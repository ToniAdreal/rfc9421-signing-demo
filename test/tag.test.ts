import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
} from "../src/index.js";

const CREATED = 1700000000;
const TAG = "payment-webhook-v1";

function signEd(tag?: string) {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: "https://api.example.com/v1/webhooks", headers: {}, body: "{}" },
    {
      keyId: "k",
      alg: "ed25519",
      key: kp.privateKey,
      created: CREATED,
      ...(tag !== undefined ? { tag } : {}),
    },
  );
  return { ...kp, signed };
}

test("ed25519 tag round-trip returns the tag", () => {
  const { publicKey, signed } = signEd(TAG);
  assert.match(signed.headers["signature-input"], /;tag="payment-webhook-v1"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.tag, TAG);
});

test("hmac-sha256 tag round-trip returns the tag", () => {
  const secret = secretKey("tag-test-hmac-secret-32-bytes-0000");
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "hmac-sha256", key: secret, created: CREATED, tag: TAG },
  );
  const res = verifyRequest(signed, { key: secret, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.tag, TAG);
});

test("missing tag verifies fine and result.tag is undefined (backwards compatible)", () => {
  const { publicKey, signed } = signEd(undefined);
  assert.ok(!/;tag=/.test(signed.headers["signature-input"]));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.tag, undefined);
});

test("tampered tag fails with SIGNATURE_MISMATCH (tag is signed)", () => {
  const { publicKey, signed } = signEd(TAG);
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'tag="payment-webhook-v1"',
        'tag="admin-api-v1"',
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  // wire-seen value is still reported on failure, before authenticity is known
  assert.equal(res.tag, "admin-api-v1");
});

test("expectedTag match passes", () => {
  const { publicKey, signed } = signEd(TAG);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(res.ok, true);
  assert.equal(res.tag, TAG);
});

test("expectedTag mismatch fails with TAG_MISMATCH", () => {
  const { publicKey, signed } = signEd("admin-api-v1");
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "TAG_MISMATCH");
  assert.equal(res.tag, "admin-api-v1");
});

test("expectedTag set but signature carries no tag fails with TAG_MISMATCH", () => {
  const { publicKey, signed } = signEd(undefined);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "TAG_MISMATCH");
  assert.equal(res.tag, undefined);
});

test("forgery reports SIGNATURE_MISMATCH, not TAG_MISMATCH (crypto checked first)", () => {
  const { signed } = signEd("admin-api-v1");
  const other = generateEd25519KeyPair();
  const res = verifyRequest(signed, {
    key: other.publicKey,
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("verifyRequestOrThrow carries tag on success and TAG_MISMATCH on failure", () => {
  const { publicKey, signed } = signEd(TAG);
  const out = verifyRequestOrThrow(signed, {
    key: publicKey,
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(out.tag, TAG);
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: CREATED + 60,
        expectedTag: "admin-api-v1",
      }),
    (e: unknown) => {
      assert.equal((e as Error).name, "VerifyError");
      assert.equal((e as { code?: string }).code, "TAG_MISMATCH");
      assert.equal((e as { tag?: string }).tag, TAG);
      return true;
    },
  );
});

test("tag survives quoting round-trip", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const tricky = 'pay"ment\\v1';
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, tag: tricky },
  );
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.tag, tricky);
});

test("empty-string tag is rejected with a configuration error", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(
        { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, tag: "" },
      ),
    /must not be an empty string/,
  );
});

test("verifyAllLabels judges expectedTag per label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const req = { method: "POST", url: "https://api.example.com/v1/pay", headers: {}, body: "{}" };
  const first = signRequest(req, {
    keyId: "merchant",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "sig1",
    // no tag on the merchant label
  });
  const both = addSignature(first, {
    keyId: "gateway",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "sig2",
    tag: TAG,
  });
  const results = verifyAllLabels(both, {
    keys: { sig1: merchant.publicKey, sig2: gateway.publicKey },
    now: CREATED + 60,
    expectedTag: TAG,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "sig1");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "TAG_MISMATCH");
  assert.equal(results[1].label, "sig2");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].tag, TAG);
});
