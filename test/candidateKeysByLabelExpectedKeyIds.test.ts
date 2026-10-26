import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #627: `candidateKeysByLabel` (per-label key rotation) and
// `expectedKeyIds` (per-label keyid pinning) have each been tested on
// their own, but never in combination. This file pins the orthogonal
// semantics for a dual-label gateway: the merchant label rotates
// ed25519 keys, the gateway label uses one static key, and each label's
// keyid is pinned to the keyid of the key that actually signed.
//
// The fixture is the mirror image of
// `test/candidateKeysByLabelRequireTag.test.ts` in one respect and the
// same shape in another: the merchant is again the rotating label, but
// the second axis here is keyid pinning, not tag presence. Pinning is a
// single value per label, so a rotated key is only "the pinned key"
// when its own keyid is the pinned value — the old-key test below
// therefore re-pins the merchant to the old key's keyid, proving the
// rotation list, not the pin, decides whether the crypto walk passes.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path", "content-digest"];

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

const merchantOld = generateEd25519KeyPair();
const merchantNew = generateEd25519KeyPair();
const merchantRetired = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(pair: KeyPair, keyId: string) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function signGateway(keyId = "gateway-key-1") {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId,
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// Both labels pinned to the keyid of the key that signed in the happy
// path: the merchant's new (rotated-in) key and the gateway's static key.
const OPTS = {
  now: NOW,
  candidateKeysByLabel: {
    merchant: [merchantOld.publicKey, merchantNew.publicKey],
  },
  keys: { gateway: gateway.publicKey },
  expectedKeyIds: { merchant: "merchant-key-new", gateway: "gateway-key-1" },
};

test("candidateKeysByLabel x expectedKeyIds: rotated merchant key verifies and its keyid echoes the pinned value", () => {
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-new");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
});

test("candidateKeysByLabel x expectedKeyIds: old merchant key still verifies inside the rotation window when re-pinned to its own keyid", () => {
  // The pin follows the signing key: re-pin the merchant to the old
  // key's keyid and the old key still verifies, because list
  // membership — not pin value — decides the crypto walk. Keeping
  // the new-key pin here would fail with KEYID_MISMATCH, which is
  // exactly what the next test pins.
  const dual = mergeSignatures(
    signMerchant(merchantOld, "merchant-key-old"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    ...OPTS,
    expectedKeyIds: { merchant: "merchant-key-old", gateway: "gateway-key-1" },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-old");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x expectedKeyIds: merchant keyid mismatch fails KEYID_MISMATCH, not a key-rotation error", () => {
  // The new key is in the rotation list, so the crypto walk passes;
  // the only failing check is the pin. A rotation problem would
  // surface as SIGNATURE_MISMATCH instead (see the retired-key test).
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-WRONG"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEYID_MISMATCH");
  assert.equal(by["merchant"].keyId, "merchant-key-WRONG");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x expectedKeyIds: gateway keyid mismatch fails only the gateway label", () => {
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway("gateway-key-WRONG"),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEYID_MISMATCH");
});

test("candidateKeysByLabel x expectedKeyIds: a key removed from the rotation list fails SIGNATURE_MISMATCH even when its keyid is pinned", () => {
  // Pinning the retired key's keyid cannot rescue it: the pin check
  // runs only after the crypto walk, and the walk exhausts the
  // rotation list without the retired key. This is the counterpart of
  // the mismatch tests — pin pass does not imply rotation pass.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-retired"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    ...OPTS,
    expectedKeyIds: { merchant: "merchant-key-retired", gateway: "gateway-key-1" },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("candidateKeysByLabel x expectedKeyIds: label missing from the map falls back to the global expectedKeyId", () => {
  // The gateway is not pinned per label here, so the global
  // expectedKeyId applies to it; the merchant keeps its own pin.
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchantOld.publicKey, merchantNew.publicKey],
    },
    keys: { gateway: gateway.publicKey },
    expectedKeyId: "gateway-key-1",
    expectedKeyIds: { merchant: "merchant-key-new" },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
});

test("candidateKeysByLabel x expectedKeyIds: global fallback mismatch fails only the unpinned label", () => {
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchantOld.publicKey, merchantNew.publicKey],
    },
    keys: { gateway: gateway.publicKey },
    expectedKeyId: "gateway-key-WRONG",
    expectedKeyIds: { merchant: "merchant-key-new" },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEYID_MISMATCH");
});

test("candidateKeysByLabel x expectedKeyIds: no pinning configured keeps rotation-only behavior", () => {
  // Without any pin (per-label or global), a rotated key verifies
  // whatever keyid it carries — pinning is opt-in, rotation alone
  // does not pin.
  const dual = mergeSignatures(
    signMerchant(merchantNew, "merchant-key-new"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    candidateKeysByLabel: {
      merchant: [merchantOld.publicKey, merchantNew.publicKey],
    },
    keys: { gateway: gateway.publicKey },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-new");
  assert.equal(by["gateway"].ok, true);
});
