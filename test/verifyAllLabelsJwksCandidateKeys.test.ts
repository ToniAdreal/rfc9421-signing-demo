import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  secretKey,
  signRequest,
  verifyAllLabels,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const JWKS_URL = "https://merchant.example.com/.well-known/jwks.json";
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

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function restoredMerchantStore(
  merchant: ReturnType<typeof generateEd25519KeyPair>,
  opts: {
    fetchImpl?: JwksFetchImpl;
    now?: () => number;
  } = {},
): JwksKeyStore {
  const snapshot: JwksKeyStoreSnapshot = {
    v: 1,
    fetchedAtSec: CREATED,
    keys: [{ ...exportPublicKeyJwk(merchant.publicKey), kid: "merchant-key-1" }],
  };
  return JwksKeyStore.restore(snapshot, JWKS_URL, {
    fetchImpl: noFetch,
    ttlSec: 300,
    ...opts,
  });
}

function signMerchant(
  merchant: ReturnType<typeof generateEd25519KeyPair>,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function signGateway(secret: ReturnType<typeof secretKey>): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

test("verifyAllLabels: merchant via JWKS resolver + gateway via candidateKeys both verify", () => {
  const merchant = generateEd25519KeyPair();
  const gatewayOld = secretKey(randomBytes(32));
  const gatewayNew = secretKey(randomBytes(32));
  const dual = mergeSignatures(signMerchant(merchant), signGateway(gatewayNew));
  const store = restoredMerchantStore(merchant);

  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: { merchant: store.resolve },
    candidateKeysByLabel: { gateway: [gatewayOld, gatewayNew] },
  });

  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "hmac-sha256");
});

test("verifyAllLabels: gateway still verifies with the old secret while merchant resolves via JWKS", () => {
  const merchant = generateEd25519KeyPair();
  const gatewayOld = secretKey(randomBytes(32));
  const gatewayNew = secretKey(randomBytes(32));
  const dual = mergeSignatures(signMerchant(merchant), signGateway(gatewayOld));
  const store = restoredMerchantStore(merchant);

  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: { merchant: store.resolve },
    candidateKeysByLabel: { gateway: [gatewayOld, gatewayNew] },
  });

  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("verifyAllLabels: merchant kid rotated out fails alone, gateway candidate list still verifies", async () => {
  const merchant = generateEd25519KeyPair();
  const gatewayOld = secretKey(randomBytes(32));
  const gatewayNew = secretKey(randomBytes(32));
  const dual = mergeSignatures(signMerchant(merchant), signGateway(gatewayNew));

  // The merchant rotates: its endpoint now serves only the new kid.
  const rotated = generateEd25519KeyPair();
  const rotatedFetch: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      keys: [
        { ...exportPublicKeyJwk(rotated.publicKey), kid: "merchant-key-2" },
      ],
    }),
  });
  const store = restoredMerchantStore(merchant, {
    fetchImpl: rotatedFetch,
    now: () => CREATED,
  });
  assert.notEqual(store.resolve("merchant-key-1"), undefined);
  await store.refresh();
  assert.equal(store.resolve("merchant-key-1"), undefined);
  assert.notEqual(store.resolve("merchant-key-2"), undefined);

  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: { merchant: store.resolve },
    candidateKeysByLabel: { gateway: [gatewayOld, gatewayNew] },
  });

  // Per-label isolation: the merchant failure is fail-closed for that
  // label only, never a silent fallback to the rotated key, and the
  // gateway label is untouched by the merchant's rotation.
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("verifyAllLabels: same label with both a resolver and candidateKeys throws the mutual-exclusion error", () => {
  const merchant = generateEd25519KeyPair();
  const gatewayOld = secretKey(randomBytes(32));
  const gatewayNew = secretKey(randomBytes(32));
  const dual = mergeSignatures(signMerchant(merchant), signGateway(gatewayNew));
  const store = restoredMerchantStore(merchant);

  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: NOW,
        keyResolvers: { merchant: store.resolve },
        candidateKeysByLabel: {
          merchant: [merchant.publicKey],
          gateway: [gatewayOld, gatewayNew],
        },
      }),
    /mutually exclusive/,
  );
});
