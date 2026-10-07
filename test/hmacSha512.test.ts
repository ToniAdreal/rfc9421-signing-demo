import test from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  createSecretKey,
  type KeyObject,
} from "node:crypto";
import {
  assertHmacSecretLength,
  buildSignatureBase,
  contentDigest,
  generateEd25519KeyPair,
  isVerifyError,
  MIN_HMAC_SECRET_BYTES,
  MIN_HMAC_SHA512_SECRET_BYTES,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: '{"amount":100}',
};

/** A secret KeyObject that bypasses secretKey() — what a careless caller
 *  could hand to sign/verify directly via node:crypto. */
function rawSecret(bytes: number): KeyObject {
  return createSecretKey(Buffer.alloc(bytes, 0xab));
}

function sign512(secret: KeyObject, label = "sig1"): SignedHttpRequest {
  return signRequest(REQ, {
    keyId: "hmac512-key-1",
    alg: "hmac-sha512",
    key: secret,
    created: CREATED,
    label,
  });
}

function sign256(secret: KeyObject, label = "sig1"): SignedHttpRequest {
  return signRequest(REQ, {
    keyId: "hmac256-key-1",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    label,
  });
}

/** Relabel the alg parameter in the wire signature-input (and nothing
 *  else): the crypto bytes still belong to the original algorithm, so a
 *  verifier must fail, never cross-verify. */
function swapWireAlg(req: SignedHttpRequest, from: string, to: string) {
  const sigInput = req.headers["signature-input"];
  assert.ok(sigInput.includes(`alg="${from}"`), "precondition: wire alg");
  return {
    ...req,
    headers: {
      ...req.headers,
      "signature-input": sigInput.replace(`alg="${from}"`, `alg="${to}"`),
    },
  };
}

test("MIN_HMAC_SHA512_SECRET_BYTES is 64 (RFC 2104: key ≥ hash output)", () => {
  assert.equal(MIN_HMAC_SHA512_SECRET_BYTES, 64);
  assert.equal(MIN_HMAC_SECRET_BYTES, 32);
});

test("round-trip: sign→verify with hmac-sha512 passes, reports alg hmac-sha512", () => {
  const secret = secretKey(Buffer.alloc(64, 0x42));
  const signed = sign512(secret);
  const res = verifyRequest(signed, { key: secret, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha512");
  assert.equal(res.keyId, "hmac512-key-1");
});

test("wire shape: signature-input carries alg=\"hmac-sha512\"", () => {
  const secret = secretKey(Buffer.alloc(64, 0x42));
  const signed = sign512(secret);
  assert.match(signed.headers["signature-input"], /alg="hmac-sha512"/);
  // The MAC value is a 64-byte HMAC: 88 base64 chars between colons.
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/]{86}==:$/);
});

test("assertHmacSecretLength pairs the floor with the algorithm", () => {
  const k32 = rawSecret(32);
  // Backwards compatible: the default (one-arg) call is hmac-sha256.
  assert.doesNotThrow(() => assertHmacSecretLength(k32));
  assert.doesNotThrow(() => assertHmacSecretLength(k32, "hmac-sha256"));
  assert.throws(
    () => assertHmacSecretLength(k32, "hmac-sha512"),
    /assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes.*got 32 bytes/,
  );
  assert.doesNotThrow(() => assertHmacSecretLength(rawSecret(64), "hmac-sha512"));
  assert.doesNotThrow(() => assertHmacSecretLength(rawSecret(128), "hmac-sha512"));
});

test("sign side: 63-byte secret throws a config error naming hmac-sha512", () => {
  assert.throws(
    () => sign512(rawSecret(63)),
    /assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes.*got 63 bytes/,
  );
});

test("verify side: 63-byte secret throws a config error (never a verification failure)", () => {
  const signed = sign512(secretKey(Buffer.alloc(64, 0x42)));
  assert.throws(
    () => verifyRequest(signed, { key: rawSecret(63), now: NOW }),
    /hmac-sha512 secret must be at least 64 bytes/,
  );
  // The throwing variant must surface the caller config Error, not a VerifyError.
  assert.throws(
    () => verifyRequestOrThrow(signed, { key: rawSecret(63), now: NOW }),
    (err: unknown) =>
      err instanceof Error &&
      !isVerifyError(err) &&
      /hmac-sha512 secret must be at least 64 bytes/.test(err.message),
  );
});

test("secretKey()'s 32-byte secret is rejected for hmac-sha512 on both sides", () => {
  const short = secretKey(Buffer.alloc(32, 0x42)); // valid for hmac-sha256 only
  assert.throws(() => sign512(short), /hmac-sha512 secret must be at least 64/);
  const signed = sign512(secretKey(Buffer.alloc(64, 0x42)));
  assert.throws(
    () => verifyRequest(signed, { key: short, now: NOW }),
    /hmac-sha512 secret must be at least 64/,
  );
});

test("no confusion with hmac-sha256: swapped alg param fails SIGNATURE_MISMATCH", () => {
  const secret64 = secretKey(Buffer.alloc(64, 0x42));
  const secret32 = secretKey(Buffer.alloc(32, 0x42));
  // hmac-sha512 bytes relabeled as hmac-sha256 must not cross-verify.
  const relabeled512 = swapWireAlg(sign512(secret64), "hmac-sha512", "hmac-sha256");
  const r1 = verifyRequest(relabeled512, { key: secret64, now: NOW });
  assert.equal(r1.ok, false);
  assert.equal(r1.code, "SIGNATURE_MISMATCH");
  // hmac-sha256 bytes relabeled as hmac-sha512 must not cross-verify either.
  const relabeled256 = swapWireAlg(sign256(secret32), "hmac-sha256", "hmac-sha512");
  const r2 = verifyRequest(relabeled256, { key: secret64, now: NOW });
  assert.equal(r2.ok, false);
  assert.equal(r2.code, "SIGNATURE_MISMATCH");
});

test("tampered body fails with BODY_DIGEST_MISMATCH under hmac-sha512", () => {
  const secret = secretKey(Buffer.alloc(64, 0x42));
  const signed = sign512(secret);
  const tampered = {
    ...signed,
    body: '{"amount":999}',
    headers: { ...signed.headers },
  };
  const res = verifyRequest(tampered, { key: secret, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("verifyAllLabels: hmac-sha512 + ed25519 dual labels both verify", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const secret = secretKey(Buffer.alloc(64, 0x42));
  const a = sign512(secret, "gateway");
  const b = signRequest(REQ, {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  const merged = {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
  const results = verifyAllLabels(merged, {
    keys: { gateway: secret, merchant: publicKey },
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "hmac-sha512");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "ed25519");
});

test("algFallback infer: wire alg hmac-sha512 + secret passes shape check, ed25519 key throws", () => {
  const secret = secretKey(Buffer.alloc(64, 0x42));
  const signed = sign512(secret);
  const res = verifyRequest(signed, {
    key: secret,
    now: NOW,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha512");
  const { publicKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: NOW,
        algFallback: "infer",
      }),
    /wire alg "hmac-sha512" is incompatible with the configured key/,
  );
});

test("missing alg with infer still maps secret → hmac-sha256 (backwards compatible)", () => {
  // Foreign-signer mode (see test/algFallback.test.ts): the base is built
  // with params that never carried `alg`, then MACed directly — stripping
  // the parameter from our own signer's wire header would change the base
  // and rightly fail, so that is not a valid way to build this case.
  const secret32 = secretKey(Buffer.alloc(32, 0x42));
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const signingInput: RequestLike = {
    ...REQ,
    headers: {
      "content-type": "application/json",
      "content-digest": contentDigest(REQ.body),
    },
  };
  const params = {
    created: CREATED,
    keyid: "hmac256-key-1",
    // No `alg`: RFC 9421 §2.3 leaves it optional (cf. Appendix B.2.5).
  };
  const base = buildSignatureBase(covered, signingInput, params);
  const mac = createHmac("sha256", secret32).update(base, "utf8").digest();
  const foreign: SignedHttpRequest = {
    method: REQ.method,
    url: REQ.url,
    body: REQ.body,
    headers: {
      "content-type": "application/json",
      "content-digest": contentDigest(REQ.body),
      "signature-input": signatureInputValue("sig1", covered, params),
      signature: `sig1=:${mac.toString("base64")}:`,
    },
  };
  assert.ok(!foreign.headers["signature-input"].includes("alg="));
  const res = verifyRequest(foreign, {
    key: secret32,
    now: NOW,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
});
