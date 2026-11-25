import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  bodyToBuffer,
  buildSignatureBase,
  contentDigest,
  digest,
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  signatureInputValue,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #1397: the sign/verify path accepts a `Uint8Array` body and
// hashes its exact bytes, like the string (UTF-8) and `Buffer` forms.
// A `Uint8Array` is the shape a caller has when the body was read with
// `arrayBuffer()` or is binary (a protobuf settlement receipt, a PDF
// statement) — a form a UTF-8 string cannot express at all.

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const BODY = '{"amount":100}';
const BODY_BYTES = new TextEncoder().encode(BODY);
const { publicKey, privateKey } = generateEd25519KeyPair();

const COVERED = ["@method", "@authority", "@path", "content-digest"];

function sign(body: string | Buffer | Uint8Array): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: URL,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      key: privateKey,
      alg: "ed25519",
      keyId: "k",
      created: CREATED,
      coveredComponents: COVERED,
    },
  );
}

function verify(signed: SignedHttpRequest) {
  return verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
  });
}

test("bodyToBuffer normalizes string/Buffer/Uint8Array and rejects the rest", () => {
  assert.deepEqual(bodyToBuffer(BODY), Buffer.from(BODY, "utf8"));
  const buf = Buffer.from(BODY, "utf8");
  assert.equal(bodyToBuffer(buf), buf, "a Buffer passes through untouched");
  const u8 = new TextEncoder().encode(BODY);
  assert.deepEqual(bodyToBuffer(u8), buf);
  assert.ok(Buffer.isBuffer(bodyToBuffer(u8)));
  // A view over a larger backing store hashes only the viewed bytes:
  // the three leading/trailing zero bytes must not leak into the digest.
  const backing = new Uint8Array(3 + BODY_BYTES.length + 3);
  backing.set(BODY_BYTES, 3);
  const view = backing.subarray(3, 3 + BODY_BYTES.length);
  assert.equal(view.byteOffset, 3);
  assert.deepEqual(bodyToBuffer(view), buf);
  assert.throws(
    () => bodyToBuffer(123 as unknown as Uint8Array),
    /body must be a string, a Buffer, or a Uint8Array, got number/,
  );
  assert.throws(
    () => bodyToBuffer({} as unknown as Uint8Array),
    /body must be a string, a Buffer, or a Uint8Array, got object/,
  );
  assert.throws(
    () => bodyToBuffer(null as unknown as Uint8Array),
    /body must be a string, a Buffer, or a Uint8Array, got object/,
  );
});

test("contentDigest and digest accept Uint8Array, equal to string/Buffer for the same bytes", () => {
  const u8 = new TextEncoder().encode(BODY);
  assert.equal(contentDigest(u8), contentDigest(BODY));
  assert.equal(contentDigest(u8), contentDigest(Buffer.from(BODY, "utf8")));
  assert.equal(
    contentDigest(u8, "sha-256"),
    contentDigest(BODY, "sha-256"),
  );
  assert.equal(digest(u8, "sha-256"), digest(BODY, "sha-256"));
  assert.equal(
    digest(u8, "sha-512"),
    digest(Buffer.from(BODY, "utf8"), "sha-512"),
  );
});

test("a Uint8Array view hashes only its slice, not the whole backing store", () => {
  const backing = new Uint8Array(4 + BODY_BYTES.length + 4);
  backing.set(BODY_BYTES, 4);
  const view = backing.subarray(4, 4 + BODY_BYTES.length);
  assert.equal(contentDigest(view), contentDigest(BODY));
  assert.notEqual(contentDigest(backing), contentDigest(BODY));
});

test("sign/verify round-trips a Uint8Array body, digest header identical to the string form", () => {
  const u8 = new TextEncoder().encode(BODY);
  const signedU8 = sign(u8);
  const signedStr = sign(BODY);
  assert.equal(
    signedU8.headers["content-digest"],
    signedStr.headers["content-digest"],
  );
  const res = verify(signedU8);
  assert.equal(res.ok, true, JSON.stringify(res));
  // The signature itself is over the same base either way: the
  // Uint8Array-signed request verifies against the string-signed
  // headers and vice versa (same bytes, same base).
  assert.equal(verify(signedStr).ok, true);
});

test("sign and verify agree across string/Buffer/Uint8Array forms of the same bytes", () => {
  const u8 = new TextEncoder().encode(BODY);
  const buf = Buffer.from(BODY, "utf8");
  // Sign with one form, verify with each other form.
  const signedU8 = sign(u8);
  assert.equal(verify({ ...signedU8, body: buf }).ok, true);
  assert.equal(verify({ ...signedU8, body: BODY }).ok, true);
  const signedStr = sign(BODY);
  assert.equal(verify({ ...signedStr, body: u8 }).ok, true);
  const signedBuf = sign(buf);
  assert.equal(verify({ ...signedBuf, body: u8 }).ok, true);
});

test("non-UTF8 bytes round-trip: Uint8Array and Buffer agree where a string cannot", () => {
  const raw = new Uint8Array([0x00, 0xff, 0x80, 0x7f, 0x22, 0x5c, 0x01, 0xfe]);
  const buf = Buffer.from(raw);
  assert.equal(contentDigest(raw), contentDigest(buf));
  const signed = sign(raw);
  assert.equal(verify(signed).ok, true, JSON.stringify(verify(signed)));
  assert.equal(verify({ ...signed, body: buf }).ok, true);
});

test("an empty Uint8Array behaves like an empty string body", () => {
  const empty = new Uint8Array(0);
  assert.equal(contentDigest(empty), contentDigest(""));
  const signed = sign(empty);
  assert.equal(verify(signed).ok, true, JSON.stringify(verify(signed)));
});

test("flipping one byte in a Uint8Array body fails with BODY_DIGEST_MISMATCH", () => {
  const u8 = new TextEncoder().encode(BODY);
  const signed = sign(u8);
  const tampered = new Uint8Array(u8);
  tampered[2] ^= 0x01;
  const res = verify({ ...signed, body: tampered });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("sign side still throws a named error for an illegal body type", () => {
  assert.throws(
    () => contentDigest(123 as unknown as Uint8Array),
    /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got number/,
  );
  assert.throws(
    () => digest({} as unknown as Uint8Array, "sha-256"),
    /digest: "body" must be a string, a Buffer, or a Uint8Array, got object/,
  );
  assert.throws(
    () =>
      signRequest(
        { method: "POST", url: URL, headers: {}, body: 42 as unknown as string },
        {
          key: privateKey,
          alg: "ed25519",
          created: CREATED,
          coveredComponents: COVERED,
        },
      ),
    /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got number/,
  );
});

test("verify side reports an illegal body as VERIFICATION_ERROR, never a throw", () => {
  const signed = sign(BODY);
  const res = verifyRequest(
    { ...signed, body: 123 as unknown as string },
    { key: publicKey, now: CREATED },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
  assert.match(
    res.reason ?? "",
    /body must be a string, a Buffer, or a Uint8Array, got number/,
  );
});

test("verifyRequestOrThrow passes a Uint8Array body through", () => {
  const signed = sign(new TextEncoder().encode(BODY));
  const res = verifyRequestOrThrow(signed, {
    key: publicKey,
    now: CREATED,
  });
  assert.equal(res.alg, "ed25519");
  assert.equal(res.keyId, "k");
});

/** Manually sign a request whose legacy Digest header we control exactly. */
function signedWithLegacyDigestHeader(
  body: string | Buffer | Uint8Array | undefined,
  digestHeader: string,
): SignedHttpRequest {
  const headers: Record<string, string> = { digest: digestHeader };
  const covered = ["@method", "@authority", "@path", "digest"];
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

test("legacy Digest binding verifies a Uint8Array body and rejects a tampered one", () => {
  const u8 = new TextEncoder().encode(BODY);
  const signed = signedWithLegacyDigestHeader(u8, digest(u8, "sha-256"));
  assert.equal(verify(signed).ok, true, JSON.stringify(verify(signed)));
  const tampered = new Uint8Array(u8);
  tampered[0] ^= 0x01;
  const res = verify({ ...signed, body: tampered });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("response sign/verify round-trips a Uint8Array body", () => {
  const u8 = new TextEncoder().encode(BODY);
  const signedU8 = signResponse(
    { status: 200, headers: { "content-type": "application/json" }, body: u8 },
    {
      key: privateKey,
      alg: "ed25519",
      keyId: "k",
      created: CREATED,
    },
  );
  const signedStr = signResponse(
    { status: 200, headers: { "content-type": "application/json" }, body: BODY },
    {
      key: privateKey,
      alg: "ed25519",
      keyId: "k",
      created: CREATED,
    },
  );
  assert.equal(
    signedU8.headers["content-digest"],
    signedStr.headers["content-digest"],
  );
  const res = verifyResponse(signedU8, {
    key: publicKey,
    now: CREATED,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
  // Cross-form: the same signed response verifies with a Buffer body.
  const resBuf = verifyResponse(
    { ...signedU8, body: Buffer.from(BODY, "utf8") },
    { key: publicKey, now: CREATED },
  );
  assert.equal(resBuf.ok, true, JSON.stringify(resBuf));
});
