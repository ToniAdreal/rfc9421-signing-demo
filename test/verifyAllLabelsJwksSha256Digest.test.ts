import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #767: `verifyAllLabelsContentDigestJwks.test.ts` (#751)
// pins the dual-label x JWKS x content-digest combination with a
// sha-512 wire digest, and `verifyAllLabelsContentDigest.test.ts`
// (#730) pins the sha-256-only fallback without any JWKS store.
// The sha-256-only digest through per-label JWKS resolvers was
// therefore unpinned: does the sha-256 fallback (used only when
// no sha-512 entry is present) compose with independent JWKS
// resolution the same way sha-512 does, and do the two failure
// dimensions stay orthogonal when they coincide?
//
// The digest-tamper case here is a body swap with the wire header
// untouched: the signature base covers the header value, so the
// crypto check still passes and the body-vs-digest check is the
// rejection, exactly as in #730. Tampering the header value
// itself would instead fail as SIGNATURE_MISMATCH (also #730),
// so that is not the case pinned here.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. All JWKS paths are offline snapshot
// restores (or a stub fetch for the rotation case); zero real
// network.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";
const BODY_A = '{"amount":100}';
const BODY_B = '{"amount":1}';

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function baseRequest(body: string) {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    body,
  };
}

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

function snapshotFor(
  publicKey: KeyObject,
  kid: string,
): JwksKeyStoreSnapshot {
  return {
    v: 1,
    fetchedAtSec: CREATED,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid }],
  };
}

function restoredStore(
  url: string,
  publicKey: KeyObject,
  kid: string,
  opts: { fetchImpl?: JwksFetchImpl; now?: () => number } = {},
): JwksKeyStore {
  return JwksKeyStore.restore(snapshotFor(publicKey, kid), url, {
    fetchImpl: noFetch,
    ttlSec: 300,
    ...opts,
  });
}

function signAs(
  body: string,
  keyId: string,
  privateKey: KeyObject,
  label: string,
): SignedHttpRequest {
  return signRequest(baseRequest(body), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
    contentDigestAlg: "sha-256",
  });
}

/**
 * One merchant + one gateway signature on the same request, each
 * party's public key held in its own offline-restored JwksKeyStore.
 * Both labels cover content-digest by default (a body is present),
 * so the wire carries a single sha-256-only digest header.
 */
function twoParty() {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signAs(BODY_A, "merchant-key-1", merchant.privateKey, "merchant"),
    signAs(BODY_A, "gateway-key-1", gateway.privateKey, "gateway"),
  );
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
  );
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
  );
  return { merged, merchant, gateway, merchantStore, gatewayStore };
}

function verifyWithStores(
  req: SignedHttpRequest,
  merchantStore: JwksKeyStore,
  gatewayStore: JwksKeyStore,
) {
  return verifyAllLabels(req, {
    now: NOW,
    keyResolvers: {
      merchant: merchantStore.resolve,
      gateway: gatewayStore.resolve,
    },
  });
}

/** Retire the merchant kid by refreshing its store to a new kid only. */
async function retireMerchantKid(merchant: KeyObject) {
  const rotated = generateEd25519KeyPair();
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant,
    "merchant-key-1",
    {
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          keys: [
            {
              ...exportPublicKeyJwk(rotated.publicKey),
              kid: "merchant-key-2",
            },
          ],
        }),
      }),
      now: () => CREATED,
    },
  );
  await merchantStore.refresh();
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  assert.notEqual(merchantStore.resolve("merchant-key-2"), undefined);
  return merchantStore;
}

test("verifyAllLabels x JwksKeyStore x sha-256-only content-digest: dual labels each resolve via their own store and both verify over the sha-256 fallback", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const digest = merged.headers["content-digest"];
  assert.ok(
    digest?.startsWith("sha-256="),
    "wire must carry the shared sha-256 digest",
  );
  assert.ok(
    !digest?.includes("sha-512="),
    "wire must be sha-256-only, so the fallback path is exercised",
  );
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("content-digest"),
      `${r.label} must cover content-digest`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].keyId, "gateway-key-1");
});

test("verifyAllLabels x JwksKeyStore x sha-256-only content-digest: body swapped after signing fails both labels as BODY_DIGEST_MISMATCH, not SIGNATURE_MISMATCH", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const swapped = { ...merged, body: BODY_B };
  const results = verifyWithStores(swapped, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) {
    // Key resolution still succeeds for both labels (the stores
    // are untouched) and the header value is untouched, so the
    // crypto check passes and the body-vs-digest check rejects:
    // the digest dimension must surface on its own, under the
    // sha-256 fallback just as under sha-512 in #751.
    assert.equal(r.ok, false);
    assert.equal(r.code, "BODY_DIGEST_MISMATCH");
    assert.equal(r.reason, "body does not match content-digest");
  }
});

test("verifyAllLabels x JwksKeyStore x sha-256-only content-digest: retired merchant kid fails KEY_RESOLUTION_FAILED while the gateway sha-256 label still verifies", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
  const merchantStore = await retireMerchantKid(merchant.publicKey);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  // The gateway label's key still resolves and its sha-256 digest
  // still binds the same wire body: a neighbour's key failure must
  // not turn into a digest or signature failure on this label.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.ok(results[1].coveredComponents?.includes("content-digest"));
});

test("verifyAllLabels x JwksKeyStore x sha-256-only content-digest: a neighbour's key failure does not change the other label's digest failure code", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
  const merchantStore = await retireMerchantKid(merchant.publicKey);
  const swapped = { ...merged, body: BODY_B };
  const results = verifyWithStores(swapped, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  // The gateway label must report exactly the digest failure it
  // reported in the body-swap-only case: the merchant's key
  // failure must not mask, upgrade, or otherwise change it.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "BODY_DIGEST_MISMATCH");
  assert.equal(results[1].reason, "body does not match content-digest");
});
