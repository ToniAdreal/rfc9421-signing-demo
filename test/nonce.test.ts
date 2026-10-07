import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyRequest,
  verifyRequestOrThrow,
} from "../src/index.js";

const CREATED = 1700000000;

test("ed25519 nonce round-trip returns the nonce", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "replay-id-1",
    },
  );
  assert.match(signed.headers["signature-input"], /;nonce="replay-id-1"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "replay-id-1");
});

test("hmac-sha256 nonce round-trip returns the nonce", () => {
  const secret = secretKey("nonce-test-hmac-secret-32-bytes-00");
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "hmac-sha256",
      key: secret,
      created: CREATED,
      nonce: "hmac-nonce-42",
    },
  );
  const res = verifyRequest(signed, { key: secret, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "hmac-nonce-42");
});

test("missing nonce verifies fine and result.nonce is undefined", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
  );
  assert.ok(!/nonce=/.test(signed.headers["signature-input"]));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, undefined);
});

test("tampered nonce fails with SIGNATURE_MISMATCH (nonce is signed)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "original",
    },
  );
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'nonce="original"',
        'nonce="forged"',
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  // wire-seen value is still reported on failure, before authenticity is known
  assert.equal(res.nonce, "forged");
});

test("nonce survives quoting round-trip", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const tricky = 'a"b\\c d';
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: tricky,
    },
  );
  assert.match(signed.headers["signature-input"], /;nonce="a\\"b\\\\c d"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, tricky);
});

test("verifyRequestOrThrow returns nonce on success", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "throw-path",
    },
  );
  const out = verifyRequestOrThrow(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(out.nonce, "throw-path");
});

test("VerifyError carries nonce on failure", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "err-nonce",
    },
  );
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'nonce="err-nonce"',
        'nonce="evil"',
      ),
    },
  };
  assert.throws(
    () =>
      verifyRequestOrThrow(tampered, { key: publicKey, now: CREATED + 60 }),
    (e: unknown) => {
      assert.equal((e as Error).name, "VerifyError");
      assert.equal(
        (e as { code?: string }).code,
        "SIGNATURE_MISMATCH",
      );
      assert.equal((e as { nonce?: string }).nonce, "evil");
      return true;
    },
  );
});

test('empty-string nonce is rejected with a configuration error', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(
        { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, nonce: "" },
      ),
    /must not be an empty string/,
  );
});

test("normal nonce path is unaffected by the empty-string guard", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "guard-regression",
    },
  );
  assert.match(signed.headers["signature-input"], /;nonce="guard-regression"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "guard-regression");
});

test("nonce-less path is unaffected by the empty-string guard", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
  );
  assert.ok(!/nonce=/.test(signed.headers["signature-input"]));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, undefined);
});
