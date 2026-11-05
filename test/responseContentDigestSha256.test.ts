import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signResponse,
  signatureInputValue,
  verifyResponse,
  type SignatureParams,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #906: the request side pins `contentDigestAlg: "sha-256"` and
// the sha-512-first / sha-256-fallback verifier rule
// (test/contentDigestAlg.test.ts, test/contentDigest.test.ts), but the
// response side had zero sha-256 cases — `grep -rl "sha-256"
// test/response*.test.ts test/nodeHttpResponse*.test.ts` was empty.
// `SignResponseOptions = SignOptions`, so sha-256 issuance already
// works through `signResponse`, and `verifyResponse` forwards the
// verify options; these cases pin that inheritance directly, plus the
// dual-algorithm header rule on the response wire.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ amount: 10630, currency: "USD" });
const OTHER_BODY = JSON.stringify({ amount: 1, currency: "USD" });
const { publicKey, privateKey } = generateEd25519KeyPair();

function digestOf(body: string | Buffer, alg: "sha-256" | "sha-512"): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(buf).digest("base64")}:`;
}

function signOpts(overrides: Record<string, unknown> = {}) {
  return {
    alg: "ed25519" as const,
    key: privateKey,
    keyId: "gateway-key",
    created: CREATED,
    ...overrides,
  };
}

function verifyOpts() {
  return { key: publicKey, now: NOW };
}

/**
 * Manually sign a response whose Content-Digest header we control
 * exactly — the response-side twin of `signedWithDigestHeader` in
 * test/contentDigest.test.ts. The signature base is built over the
 * same `RequestLike` shape `verifyResponse` constructs internally
 * (empty method, `https://response.invalid/` URL, the response
 * status), so the hand-built header is covered by the signature
 * exactly as a gateway-issued one would be.
 */
function signedResponseWithDigestHeader(
  body: string | undefined,
  digestHeader: string,
): SignedHttpResponse {
  const headers: Record<string, string> = { "content-digest": digestHeader };
  const covered = ["@status", "content-digest"];
  const params: SignatureParams = {
    created: CREATED,
    keyid: "gateway-key",
    alg: "ed25519",
  };
  const base = buildSignatureBase(
    covered,
    {
      method: "",
      url: "https://response.invalid/",
      headers,
      body,
      status: 200,
    },
    params,
  );
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  return { status: 200, headers, body };
}

test("signResponse with contentDigestAlg sha-256 emits the sha-256 wire shape", () => {
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    signOpts({ contentDigestAlg: "sha-256" }),
  );
  const header = signed.headers["content-digest"];
  assert.match(header, /^sha-256=:[A-Za-z0-9+/]{43}=:$/);
  assert.equal(header, digestOf(BODY, "sha-256"));
  assert.notEqual(header, digestOf(BODY, "sha-512"));
});

test("sha-256 response signature verifies end-to-end via verifyResponse", () => {
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    signOpts({ contentDigestAlg: "sha-256" }),
  );
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.label, "sig1");
});

test("sha-256 response: tampered body is BODY_DIGEST_MISMATCH", () => {
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    signOpts({ contentDigestAlg: "sha-256" }),
  );
  const tampered: SignedHttpResponse = { ...signed, body: OTHER_BODY };
  const result = verifyResponse(tampered, verifyOpts());
  assert.equal(result.ok, false);
  assert.equal(result.code, "BODY_DIGEST_MISMATCH");
  assert.equal(result.reason, "body does not match content-digest");
});

test("dual-alg digest header (sha-512 + sha-256) verifies", () => {
  const signed = signedResponseWithDigestHeader(
    BODY,
    `${digestOf(BODY, "sha-512")}, ${digestOf(BODY, "sha-256")}`,
  );
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true, JSON.stringify(result));
});

test("dual-alg header with tampered sha-256 entry still verifies (sha-512 wins)", () => {
  // Header offers a sha-256 of another body and a sha-512 of the real
  // body; the verifier must check against sha-512, so the response
  // verifies. If it had picked sha-256, this would fail.
  const signed = signedResponseWithDigestHeader(
    BODY,
    `${digestOf(OTHER_BODY, "sha-256")}, ${digestOf(BODY, "sha-512")}`,
  );
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true, JSON.stringify(result));
});

test("dual-alg header with tampered sha-512 entry is BODY_DIGEST_MISMATCH", () => {
  // The sha-512 entry is of another body while the sha-256 entry is
  // correct — the verifier trusts sha-512 when present, so the body
  // check must fail rather than fall back to the correct sha-256.
  const signed = signedResponseWithDigestHeader(
    BODY,
    `${digestOf(OTHER_BODY, "sha-512")}, ${digestOf(BODY, "sha-256")}`,
  );
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, false);
  assert.equal(result.code, "BODY_DIGEST_MISMATCH");
  assert.equal(result.reason, "body does not match content-digest");
});

test("sha-256-only header verifies via the sha-256 fallback", () => {
  const signed = signedResponseWithDigestHeader(
    BODY,
    digestOf(BODY, "sha-256"),
  );
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true, JSON.stringify(result));
});

test("no-body @status-only response carries no digest and verifies", () => {
  const signed = signResponse({ status: 200, headers: {} }, signOpts());
  assert.equal(signed.headers["content-digest"], undefined);
  assert.deepEqual(signed.coveredComponents, ["@status"]);
  const result = verifyResponse(signed, verifyOpts());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.label, "sig1");
});
