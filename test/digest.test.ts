import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  digest,
  generateEd25519KeyPair,
  signRequest,
  signatureInputValue,
  verifyRequest,
  type SignedHttpRequest,
  type SignatureParams,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const BODY = '{"amount":100.00,"currency":"USD"}';
const { publicKey, privateKey } = generateEd25519KeyPair();

/** Manually sign a request whose Digest header we control exactly. */
function signedWithDigestHeader(
  body: string | Buffer | undefined,
  digestHeader: string,
  covered: string[] = ["@method", "@authority", "@path", "digest"],
): SignedHttpRequest {
  const headers: Record<string, string> = { digest: digestHeader };
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

test("digest sha-256 golden value, verbatim", () => {
  assert.equal(
    digest(BODY, "sha-256"),
    "sha-256=:qHycHWk7IkbwexRKk+xxmcx9yK3dOFd1TTawJhW6NrQ=:",
  );
});

test("digest sha-512 golden value, verbatim", () => {
  assert.equal(
    digest(BODY, "sha-512"),
    "sha-512=:IVJsvrg3bjX8PGlZxcOsH+KTlnxLh7sLadQHrbsDfwNzo9VQQRTUTKYlmcsgNzctXmo+I9vDOVyYWITDlUYzAA==:",
  );
});

test("digest of the empty body is the well-known empty sha-256", () => {
  assert.equal(
    digest("", "sha-256"),
    "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
  );
});

test("digest accepts a Buffer body and matches the string form", () => {
  assert.equal(
    digest(Buffer.from(BODY, "utf8"), "sha-256"),
    digest(BODY, "sha-256"),
  );
  assert.equal(
    digest(Buffer.from("hello world", "utf8"), "sha-512"),
    "sha-512=:MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw==:",
  );
});

test("signRequest -> verifyRequest round-trip with digest covered (sha-256)", () => {
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { digest: digest(BODY, "sha-256") },
      body: BODY,
    },
    {
      key: privateKey,
      alg: "ed25519",
      created: CREATED,
      keyId: "k",
      coveredComponents: ["@method", "@authority", "@path", "digest"],
    },
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("signRequest -> verifyRequest round-trip with digest covered (sha-512)", () => {
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { digest: digest(BODY, "sha-512") },
      body: BODY,
    },
    {
      key: privateKey,
      alg: "ed25519",
      created: CREATED,
      keyId: "k",
      coveredComponents: ["@method", "@authority", "@path", "digest"],
    },
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("tampered body with digest covered: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const res = verify({ ...signed, body: '{"amount":999999}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.equal(res.reason, "body does not match Digest");
});

test("signer emitted a Digest of another body: BODY_DIGEST_MISMATCH", () => {
  // The signature covers the Digest value as sent, so the crypto check
  // passes and the binding check is what catches the wrong digest —
  // the shape a buggy gateway produces when it digests stale bytes.
  const signed = signedWithDigestHeader(
    BODY,
    digest('{"amount":1}', "sha-256"),
  );
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.equal(res.reason, "body does not match Digest");
});

test("Digest header swapped after signing: signature mismatch", () => {
  // The signature covers the Digest value, so swapping the value after
  // signing breaks the crypto check first — same as content-digest.
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const swapped: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      digest: digest('{"amount":1}', "sha-256"),
    },
  };
  const res = verify(swapped);
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("digest and content-digest both covered: verifies", () => {
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { digest: digest(BODY, "sha-256") },
      body: BODY,
    },
    {
      key: privateKey,
      alg: "ed25519",
      created: CREATED,
      keyId: "k",
      coveredComponents: [
        "@method",
        "@authority",
        "@path",
        "content-digest",
        "digest",
      ],
    },
  );
  // signRequest emitted the content-digest header itself; the caller
  // supplied the Digest header. Both must be present and correct.
  assert.ok(signed.headers["content-digest"] !== undefined);
  assert.ok(signed.headers["digest"] !== undefined);
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("digest and content-digest both covered, body tampered: binding failure", () => {
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { digest: digest(BODY, "sha-256") },
      body: BODY,
    },
    {
      key: privateKey,
      alg: "ed25519",
      created: CREATED,
      keyId: "k",
      coveredComponents: [
        "@method",
        "@authority",
        "@path",
        "content-digest",
        "digest",
      ],
    },
  );
  const res = verify({ ...signed, body: '{"amount":999999}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("digest covered but the header is missing: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const headersWithoutDigest: Record<string, string> = {};
  for (const [k, v] of Object.entries(signed.headers))
    if (k !== "digest") headersWithoutDigest[k] = v;
  const res = verify({ ...signed, headers: headersWithoutDigest });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.match(res.reason ?? "", /no Digest header is present/);
});

test("md5 Digest fails closed: BODY_DIGEST_MISMATCH", () => {
  const md5 = `md5=:${createHash("md5").update(Buffer.from(BODY, "utf8")).digest("base64")}:`;
  const signed = signedWithDigestHeader(BODY, md5);
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.match(res.reason ?? "", /md5/);
});

test("unknown Digest algorithm fails closed: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(
    BODY,
    `sha-999=:${Buffer.from("nonsense").toString("base64")}:`,
  );
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("Digest present but not covered: no binding check, body swap verifies", () => {
  // The Digest check only runs when `digest` is covered. An uncovered
  // Digest header is opaque data the signature does not bind — same
  // scoping rule the backlog sets for this feature (unlike
  // content-digest, which is checked whenever present).
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { digest: digest(BODY, "sha-256") },
      body: BODY,
    },
    {
      key: privateKey,
      alg: "ed25519",
      created: CREATED,
      keyId: "k",
      coveredComponents: ["@method", "@authority", "@path"],
    },
  );
  const res = verify({ ...signed, body: '{"amount":999999}' });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("no-body request with digest of the empty body covered: verifies", () => {
  const signed = signedWithDigestHeader(undefined, digest("", "sha-256"));
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("no-body request, body added after signing: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(undefined, digest("", "sha-256"));
  const res = verify({ ...signed, body: '{"amount":100}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("multiple Digest entries: sha-512 preferred over sha-256", () => {
  // Header offers a sha-256 of another body and a sha-512 of this one;
  // the verifier must check against sha-512, so this body verifies.
  const other = '{"amount":1}';
  const signed = signedWithDigestHeader(
    BODY,
    `${digest(other, "sha-256")}, ${digest(BODY, "sha-512")}`,
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("digest rejects illegal body input and unsupported algorithms", () => {
  assert.throws(
    () => digest(123 as unknown as string, "sha-256"),
    /digest: "body" must be a string or a Buffer, got number/,
  );
  assert.throws(
    () => digest({} as unknown as string, "sha-256"),
    /digest: "body" must be a string or a Buffer, got object/,
  );
  assert.throws(
    () => digest(BODY, "md5" as unknown as "sha-256"),
    /digest: "alg" must be "sha-256" or "sha-512", got "md5"/,
  );
  assert.throws(
    () => digest(BODY, "sha-384" as unknown as "sha-256"),
    /digest: "alg" must be "sha-256" or "sha-512", got "sha-384"/,
  );
});
