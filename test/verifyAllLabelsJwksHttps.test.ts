import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  generateEd25519KeyPair,
  generateP256KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  type JwksFetchImpl,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: ed25519. Gateway: P-256. Each party's public key lives in
// its own JWKS document, so a multi-label verification crosses two
// keystores — and the requireHttps rule must hold per store, not just
// on the single-label path jwksHttps.test.ts pins.
const CREATED = 1700000000;
const NOW = CREATED + 60;

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";
const HTTP_URL = "http://gateway.example.com/.well-known/jwks.json";
const REQUIRE_HTTPS_MSG =
  'JwksKeyStore: `requireHttps` requires https: for the JWKS endpoint, got "http:"';

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250 }),
  };
}

/**
 * Combine single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature
 * (same shape as the merge helper in verifyAllLabelsJwksKeyResolvers.test.ts).
 */
function mergeSignatures(
  ...signed: SignedHttpRequest[]
): SignedHttpRequest {
  const first = signed[0];
  return {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": signed
        .map((s) => s.headers["signature-input"])
        .join(", "),
      signature: signed.map((s) => s.headers["signature"]).join(", "),
    },
  };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  label: string,
  alg: "ed25519" | "ecdsa-p256-sha256",
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    keyId,
    alg,
    key: privateKey,
    created: CREATED,
    label,
  });
}

/** A counting fetchImpl so tests can prove exactly which URL was fetched. */
function countingFetch(body: unknown): {
  impl: JwksFetchImpl;
  calls: string[];
} {
  const calls: string[] = [];
  const impl: JwksFetchImpl = async (url: string) => {
    calls.push(url);
    return { ok: true, status: 200, json: async () => body };
  };
  return { impl, calls };
}

interface TwoParty {
  merged: SignedHttpRequest;
  merchantStore: JwksKeyStore;
  gatewayStore: JwksKeyStore;
  merchantCalls: string[];
  gatewayCalls: string[];
}

/**
 * Dual-label request (merchant ed25519 + gateway P-256) with one
 * requireHttps store per party, each fed by an injected fetch stub —
 * zero real network, by the repo's fetchImpl convention.
 */
async function twoParty(gatewayDocOverride?: unknown): Promise<TwoParty> {
  const merchant = generateEd25519KeyPair();
  const gateway = generateP256KeyPair();
  const merged = mergeSignatures(
    signAs("merchant-key-1", merchant.privateKey, "merchant", "ed25519"),
    signAs("gateway-key-1", gateway.privateKey, "gateway", "ecdsa-p256-sha256"),
  );
  const merchantDoc = {
    keys: [{ ...exportPublicKeyJwk(merchant.publicKey), kid: "merchant-key-1" }],
  };
  const gatewayDoc = gatewayDocOverride ?? {
    keys: [
      { ...exportPublicKeyJwkP256(gateway.publicKey), kid: "gateway-key-1" },
    ],
  };
  const merchantFetch = countingFetch(merchantDoc);
  const gatewayFetch = countingFetch(gatewayDoc);
  const merchantStore = new JwksKeyStore(MERCHANT_URL, {
    requireHttps: true,
    fetchImpl: merchantFetch.impl,
  });
  const gatewayStore = new JwksKeyStore(GATEWAY_URL, {
    requireHttps: true,
    fetchImpl: gatewayFetch.impl,
  });
  await merchantStore.refresh();
  await gatewayStore.refresh();
  return {
    merged,
    merchantStore,
    gatewayStore,
    merchantCalls: merchantFetch.calls,
    gatewayCalls: gatewayFetch.calls,
  };
}

test("verifyAllLabels x requireHttps: http endpoint store throws at construction, zero fetches, sibling https store unaffected", async () => {
  const { impl, calls } = countingFetch({ keys: [] });
  assert.throws(
    () => new JwksKeyStore(HTTP_URL, { requireHttps: true, fetchImpl: impl }),
    (err: unknown) =>
      err instanceof Error && err.message === REQUIRE_HTTPS_MSG,
  );
  assert.deepEqual(
    calls,
    [],
    "rejection must happen before any fetch is attempted",
  );
  // The sibling store is an independent object: the failed construction
  // neither poisons it nor shares any state with it.
  const gateway = generateP256KeyPair();
  const gatewayDoc = {
    keys: [
      { ...exportPublicKeyJwkP256(gateway.publicKey), kid: "gateway-key-1" },
    ],
  };
  const siblingFetch = countingFetch(gatewayDoc);
  const sibling = new JwksKeyStore(GATEWAY_URL, {
    requireHttps: true,
    fetchImpl: siblingFetch.impl,
  });
  await sibling.refresh();
  assert.deepEqual(siblingFetch.calls, [GATEWAY_URL]);
  assert.equal(sibling.size, 1);
  assert.notEqual(sibling.resolve("gateway-key-1"), undefined);
  assert.equal(sibling.resolve("merchant-key-1"), undefined);
});

test("verifyAllLabels x requireHttps: dual label over two https JWKS endpoints verifies both labels", async () => {
  const { merged, merchantStore, gatewayStore, merchantCalls, gatewayCalls } =
    await twoParty();
  assert.deepEqual(merchantCalls, [MERCHANT_URL]);
  assert.deepEqual(gatewayCalls, [GATEWAY_URL]);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, `merchant failed: ${JSON.stringify(results[0])}`);
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, `gateway failed: ${JSON.stringify(results[1])}`);
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.equal(results[1].alg, "ecdsa-p256-sha256");
});

test("verifyAllLabels x requireHttps: a label whose kid is missing from its https JWKS doc fails alone, the other label still passes", async () => {
  // The gateway rotates: its https endpoint now serves only the new
  // kid, so the request's old gateway kid cannot resolve — while the
  // merchant store is untouched. requireHttps stays on for both
  // stores; the failure must be per-label, not whole-request.
  const rotated = generateP256KeyPair();
  const rotatedDoc = {
    keys: [
      { ...exportPublicKeyJwkP256(rotated.publicKey), kid: "gateway-key-2" },
    ],
  };
  const { merged, merchantStore, gatewayStore } =
    await twoParty(rotatedDoc);
  assert.equal(gatewayStore.resolve("gateway-key-1"), undefined);
  assert.notEqual(gatewayStore.resolve("gateway-key-2"), undefined);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[1].keyId, "gateway-key-1");
});
