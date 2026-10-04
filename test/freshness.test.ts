import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;

function signedEd(
  opts: { created?: number; expires?: number } = {},
): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: opts.created ?? CREATED,
      expires: opts.expires,
    },
  );
  return { signed, publicKey };
}

// ---------- expiry tolerance: default behavior is unchanged (strict) ----------

test("default: signature expired 1s ago is rejected", () => {
  const { signed, publicKey } = signedEd({ expires: CREATED + 100 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 101, // 1 second past expires
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature expired");
});

test("default: signature expiring exactly now still verifies (boundary)", () => {
  const { signed, publicKey } = signedEd({ expires: CREATED + 100 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 100, // now === expires: not past it
  });
  assert.equal(res.ok, true);
});

// ---------- expiry tolerance: custom window ----------

test("expiredToleranceSec: recently-expired signature verifies inside the window", () => {
  const { signed, publicKey } = signedEd({ expires: CREATED + 100 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 130, // 30s past expires
    expiredToleranceSec: 60,
  });
  assert.equal(res.ok, true);
});

test("expiredToleranceSec: too-small window still rejects", () => {
  const { signed, publicKey } = signedEd({ expires: CREATED + 100 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 130, // 30s past expires
    expiredToleranceSec: 20,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature expired");
});

test("expiredToleranceSec: boundary — now exactly at expires + tolerance verifies", () => {
  const { signed, publicKey } = signedEd({ expires: CREATED + 100 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 160, // exactly expires + 60
    expiredToleranceSec: 60,
  });
  assert.equal(res.ok, true);
});

// ---------- created skew: custom window ----------

test("clockSkewToleranceSec: custom window accepts a wider future skew", () => {
  const { signed, publicKey } = signedEd({ created: CREATED + 120 });
  // Default (60s) would reject this; an explicit 180s window accepts it.
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    clockSkewToleranceSec: 180,
  });
  assert.equal(res.ok, true);
});

test("clockSkewToleranceSec: custom narrow window rejects a mildly future signature", () => {
  const { signed, publicKey } = signedEd({ created: CREATED + 30 });
  // Default (60s) would accept this; a 20s window rejects it.
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    clockSkewToleranceSec: 20,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature created in the future (clock skew)");
});
