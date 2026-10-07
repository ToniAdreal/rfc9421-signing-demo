import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ: RequestLike = {
  method: "GET",
  url: "https://api.example.com/v1/balance",
  headers: { accept: "application/json" },
};

test("optional keyId: signature without keyId round-trips", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQ, {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });

  // RFC 9421 leaves `keyid` optional: the wire must not carry it.
  assert.ok(!signed.headers["signature-input"].includes("keyid="));
  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path"\);created=1700000000;alg="ed25519"$/,
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, undefined);
  assert.equal(res.alg, "ed25519");
});

test("optional keyId: hmac signature without keyId round-trips", () => {
  const secret = secretKey("hmac-test-secret-32-bytes-long-000");
  const signed = signRequest(REQ, {
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
  });

  assert.ok(!signed.headers["signature-input"].includes("keyid="));
  const res = verifyRequest(signed, { key: secret, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, undefined);
});

test("optional keyId: supplying keyId keeps the old wire shape", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQ, {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });

  assert.match(
    signed.headers["signature-input"],
    /^sig1=\("@method" "@authority" "@path"\);created=1700000000;keyid="merchant-key-1";alg="ed25519"$/,
  );
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "merchant-key-1");
});

test("optional keyId: keyResolver still fails a keyid-less signature", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQ, {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });

  const res = verifyRequest(signed, {
    keyResolver: () => publicKey,
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
  assert.match(res.reason ?? "", /no keyid/);
});

test("optional keyId: expectedKeyId pin still fails a keyid-less signature", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQ, {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });

  const res = verifyRequest(signed, {
    key: publicKey,
    expectedKeyId: "merchant-key-1",
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEYID_MISMATCH");
  assert.equal(res.keyId, undefined);
});
