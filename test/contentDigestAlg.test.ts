import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  addSignature,
  assertContentDigestAlg,
  contentDigest,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type ContentDigestAlg,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const BODY = JSON.stringify({ amount: 10630, currency: "USD" });
const { publicKey, privateKey } = generateEd25519KeyPair();

function req(body: string | undefined = BODY) {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    body,
  };
}

function signOpts(overrides: Record<string, unknown> = {}) {
  return {
    alg: "ed25519" as const,
    key: privateKey,
    keyId: "merchant-key",
    created: CREATED,
    ...overrides,
  };
}

/** sha-256 of a body is 32 bytes -> 44 base64 chars (one '=' pad). */
function expectedDigest(body: string, alg: "sha-512" | "sha-256"): string {
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(body, "utf8").digest("base64")}:`;
}

test("default still emits sha-512", () => {
  const signed = signRequest(req(), signOpts());
  assert.equal(signed.headers["content-digest"], expectedDigest(BODY, "sha-512"));
  assert.equal(signed.headers["content-digest"], contentDigest(BODY));
});

test("explicit sha-256 emits the sha-256 wire shape", () => {
  const signed = signRequest(req(), signOpts({ contentDigestAlg: "sha-256" }));
  const header = signed.headers["content-digest"];
  assert.match(header, /^sha-256=:[A-Za-z0-9+/]{43}=:$/);
  assert.equal(header, expectedDigest(BODY, "sha-256"));
  assert.notEqual(header, expectedDigest(BODY, "sha-512"));
});

test("sha-256 signature verifies end-to-end", () => {
  const signed = signRequest(req(), signOpts({ contentDigestAlg: "sha-256" }));
  const result = verifyRequest(signed, { key: publicKey });
  assert.equal(result.ok, true);
  assert.equal(result.label, "sig1");
});

test("sha-256 signature: tampered body is BODY_DIGEST_MISMATCH", () => {
  const signed = signRequest(req(), signOpts({ contentDigestAlg: "sha-256" }));
  const tampered = {
    ...signed,
    body: JSON.stringify({ amount: 99999, currency: "USD" }),
  };
  const result = verifyRequest(tampered, { key: publicKey });
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.code, "BODY_DIGEST_MISMATCH");
});

test("invalid contentDigestAlg is a configuration error, not a signature", () => {
  assert.throws(
    () => signRequest(req(), signOpts({ contentDigestAlg: "sha-1" })),
    /contentDigest: "alg" must be "sha-512" or "sha-256"/,
  );
  assert.throws(
    () => signRequest(req(), signOpts({ contentDigestAlg: "" })),
    /contentDigest: "alg" must be "sha-512" or "sha-256"/,
  );
});

test("contentDigest() direct: alg selection and invalid rejection", () => {
  assert.equal(contentDigest(BODY, "sha-256"), expectedDigest(BODY, "sha-256"));
  assert.equal(contentDigest(BODY, "sha-512"), expectedDigest(BODY, "sha-512"));
  assert.equal(contentDigest(BODY), expectedDigest(BODY, "sha-512"));
  assert.throws(
    () => contentDigest(BODY, "md5" as ContentDigestAlg),
    /contentDigest: "alg" must be "sha-512" or "sha-256"/,
  );
  assert.throws(() => assertContentDigestAlg("sha-1"), /must be "sha-512" or "sha-256"/);
});

test("addSignature pins the digest alg of the existing header (sha-256)", () => {
  const merchant = signRequest(
    req(),
    signOpts({ label: "merchant", contentDigestAlg: "sha-256" }),
  );
  // Second signer passes no contentDigestAlg: the appended signature must
  // still build its base over the wire sha-256 value.
  const both = addSignature(merchant, signOpts({ label: "gateway" }));
  const results = verifyAllLabels(both, { key: publicKey });
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true);
  // The wire header keeps the first signature's value, byte for byte.
  assert.equal(
    both.headers["content-digest"],
    merchant.headers["content-digest"],
  );
  assert.ok(both.headers["content-digest"].startsWith("sha-256=:"));
});

test("addSignature: explicit contradictory contentDigestAlg is rejected", () => {
  const merchant = signRequest(
    req(),
    signOpts({ label: "merchant", contentDigestAlg: "sha-256" }),
  );
  assert.throws(
    () =>
      addSignature(
        merchant,
        signOpts({ label: "gateway", contentDigestAlg: "sha-512" }),
      ),
    /addSignature: the request already carries a content-digest header emitted with "sha-256"/,
  );
});

test("addSignature: explicit matching contentDigestAlg is accepted", () => {
  const merchant = signRequest(
    req(),
    signOpts({ label: "merchant", contentDigestAlg: "sha-256" }),
  );
  const both = addSignature(
    merchant,
    signOpts({ label: "gateway", contentDigestAlg: "sha-256" }),
  );
  const results = verifyAllLabels(both, { key: publicKey });
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true);
});

test("addSignature: existing header with an unemittable alg is rejected", () => {
  const merchant = signRequest(req(), signOpts({ label: "merchant" }));
  const foreign: typeof merchant = {
    ...merchant,
    headers: { ...merchant.headers, "content-digest": "sha-1=:abc=:" },
  };
  assert.throws(
    () => addSignature(foreign, signOpts({ label: "gateway" })),
    /addSignature: the request carries a content-digest header with a digest algorithm this library cannot emit/,
  );
});

test("sha-512 default path is unaffected by the new option", () => {
  const signed = signRequest(
    req(),
    signOpts({ contentDigestAlg: "sha-512" }),
  );
  assert.equal(signed.headers["content-digest"], expectedDigest(BODY, "sha-512"));
  assert.equal(verifyRequest(signed, { key: publicKey }).ok, true);
});
