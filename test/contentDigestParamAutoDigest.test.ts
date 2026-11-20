import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
} from "../src/index.js";

// Backlog #1271: `signRequest` auto-computed the `content-digest` header
// only when a covered component matched the bare string
// `"content-digest"` exactly, so `content-digest;bs` / `;sf` /
// `;key="sha-512"` — all legal value-parameter forms that still bind
// this message's header — threw `covered header field "content-digest"
// is missing from the request` instead of signing. The trigger now
// matches by component base name (the part before the first `;`,
// case-insensitively, the same idiom as the `requiredComponents`
// coverage check, backlog #1267); `;req` / `;tr` keep their existing
// fail-fast errors because they bind the associated request / a
// trailer, not this message's header, and an unknown parameter (`;zz`)
// still reports as unsupported instead of being masked by a no-body error.

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const BODY = JSON.stringify({ amount: 10630, currency: "USD" });
const { publicKey, privateKey } = generateEd25519KeyPair();

function digestOf(
  body: string | Buffer,
  alg: "sha-256" | "sha-512",
): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(buf).digest("base64")}:`;
}

function signOpts(overrides: Record<string, unknown> = {}) {
  return {
    alg: "ed25519" as const,
    key: privateKey,
    keyId: "k",
    created: CREATED,
    ...overrides,
  };
}

function verifyOpts() {
  return { key: publicKey, now: CREATED + 60 };
}

test("content-digest;bs auto-computes the digest and verifies end-to-end", () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;bs"] }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("content-digest;sf auto-computes the digest and verifies end-to-end", () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;sf"] }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test('content-digest;key="sha-512" auto-computes the digest and verifies end-to-end', () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({
      coveredComponents: ["@method", "@authority", "@path", 'content-digest;key="sha-512"'],
    }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("content-digest;tr without a trailer still fails fast (no header minted for a trailer binding)", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "POST", url: URL, headers: {}, body: BODY },
        signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;tr"] }),
      ),
    /covered trailer field "content-digest" is missing from the request/,
  );
});

test("content-digest;req without an attached request still fails fast (no header minted for the other message)", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "POST", url: URL, headers: {}, body: BODY },
        signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;req"] }),
      ),
    /no associated request was given/,
  );
});

test("content-digest;req with an attached digested request still round-trips", () => {
  const attached = {
    method: "POST",
    url: URL,
    headers: { "content-digest": digestOf(BODY, "sha-512") },
    body: BODY,
  };
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY, request: attached },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;req"] }),
  );
  // The minted header is absent: the binding reads the attached
  // request's digest, not this message's.
  assert.equal(signed.headers["content-digest"], undefined);
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("unknown parameter on content-digest still reports unsupported, not the no-body error", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "GET", url: URL, headers: {} },
        signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;zz"] }),
      ),
    /unsupported component parameter ";zz"/,
  );
});

test("bodyless request covering content-digest;bs still reports the original no-body error", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "GET", url: URL, headers: {} },
        signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;bs"] }),
      ),
    /content-digest is covered but the request has no body/,
  );
});

test('mixed-case "Content-Digest;BS" triggers the auto-compute', () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "Content-Digest;BS"] }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("tampering the body after a ;bs signing fails the digest binding", () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest;bs"] }),
  );
  const tampered = { ...signed, body: JSON.stringify({ amount: 1, currency: "USD" }) };
  const result = verifyRequest(tampered, verifyOpts());
  assert.equal(result.ok, false);
  assert.equal(result.code, "BODY_DIGEST_MISMATCH");
});

test("bare content-digest behaviour is unchanged", () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@method", "@authority", "@path", "content-digest"] }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("signResponse with content-digest;bs auto-computes and verifies", () => {
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    signOpts({ coveredComponents: ["@status", "content-digest;bs"] }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-512"));
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true);
});

test("content-digest;bs honours contentDigestAlg sha-256", () => {
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: BODY },
    signOpts({
      coveredComponents: ["@method", "@authority", "@path", "content-digest;bs"],
      contentDigestAlg: "sha-256",
    }),
  );
  assert.equal(signed.headers["content-digest"], digestOf(BODY, "sha-256"));
  const result = verifyRequest(signed, verifyOpts());
  assert.equal(result.ok, true);
});
