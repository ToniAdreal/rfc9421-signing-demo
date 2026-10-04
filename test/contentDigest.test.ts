import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  signatureInputValue,
  verifyRequest,
  type SignedHttpRequest,
  type SignatureParams,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const { publicKey, privateKey } = generateEd25519KeyPair();

function digestOf(
  body: string | Buffer,
  alg: "sha-256" | "sha-512",
): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(buf).digest("base64")}:`;
}

/** Manually sign a request whose Content-Digest header we control exactly. */
function signedWithDigestHeader(
  body: string | Buffer | undefined,
  digestHeader: string,
): SignedHttpRequest {
  const headers: Record<string, string> = { "content-digest": digestHeader };
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const params: SignatureParams = {
    created: CREATED,
    keyid: "k",
    alg: "ed25519",
  };
  const req = { method: "POST", url: URL, headers, body };
  const base = buildSignatureBase(covered, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  return { method: "POST", url: URL, headers, body };
}

function verify(signed: SignedHttpRequest) {
  return verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
}

test("multiple digests with sha-256 first: verifier uses sha-512 only", () => {
  const body = '{"amount":100}';
  const signed = signedWithDigestHeader(
    body,
    `${digestOf(body, "sha-256")}, ${digestOf(body, "sha-512")}`,
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("multiple digests with sha-512 first: verifier uses sha-512 only", () => {
  const body = '{"amount":100}';
  const signed = signedWithDigestHeader(
    body,
    `${digestOf(body, "sha-512")}, ${digestOf(body, "sha-256")}`,
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("only sha-256 present: rejected, no usable sha-512 digest", () => {
  const body = '{"amount":100}';
  const signed = signedWithDigestHeader(body, digestOf(body, "sha-256"));
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "cannot verify body: no sha-512 content-digest present");
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("tampered digest header: rejected as signature mismatch", () => {
  const { publicKey: pub, privateKey: priv } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: '{"amount":100}' },
    { keyId: "k", alg: "ed25519", key: priv, created: CREATED },
  );
  // Attacker swaps the covered Content-Digest header for another valid-looking
  // sha-512 value; the signature base changes, so crypto must fail.
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "content-digest": digestOf('{"amount":1}', "sha-512"),
    },
  };
  const res = verifyRequest(tampered, { key: pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature mismatch");
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("body swapped after signing: explicit body/digest mismatch rejection", () => {
  const { publicKey: pub, privateKey: priv } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: '{"amount":100}' },
    { keyId: "k", alg: "ed25519", key: priv, created: CREATED },
  );
  // Signature base only covers the header value, so crypto still passes;
  // the verifier's extra body-vs-digest check must catch the swap.
  const swapped: SignedHttpRequest = { ...signed, body: '{"amount":999999}' };
  const res = verifyRequest(swapped, { key: pub, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "body does not match content-digest");
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("empty body with correct digest: verifies (zero-length body binding)", () => {
  const signed = signedWithDigestHeader(undefined, digestOf(Buffer.alloc(0), "sha-512"));
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("empty body with digest of a non-empty body: rejected", () => {
  const signed = signedWithDigestHeader(
    undefined,
    digestOf('{"amount":100}', "sha-512"),
  );
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "body does not match content-digest");
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});
