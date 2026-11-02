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

// Backlog #817: `;key` member selection has single-label static-key
// coverage (`keyComponent.test.ts`) and dual-label adapter coverage
// (#806, static keys, dict + plain labels), `;sf` dictionary
// components have JWKS coverage (`sfComponentJwks.test.ts`), and
// `verifyAllLabels` has per-label JWKS resolvers (#751), but the
// three-way combination — each label resolved through its own
// offline-restored JwksKeyStore AND covering a `;key` dictionary
// member — has no test. The question is orthogonality: does a
// member failure, a key-rotation failure, or a stale snapshot on
// one label stay confined to that label?
//
// Honest deviation from the backlog text, recorded here rather than
// silently papered over: the backlog says both labels sign
// `x-dict;key="b"` and then asks for "selected member tampered,
// only that label fails". With identical member selection that
// outcome is impossible — tampering b breaks both signatures,
// because both bind b. Member selection is per label, so the
// "only that label fails" case is implemented with per-label
// selection: merchant binds member b, gateway binds member c.
// That is exactly the orthogonality under test (each label's
// member choice is independent), and the shared-header case —
// both labels binding the same member — is already covered by
// #806's dict + plain shape in the other direction.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. All JWKS paths are offline snapshot
// restores (or stub fetches); zero real network.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";
// Dictionary fixture in the shape gateways sign member-wise, same
// as `keyComponent.test.ts`: several members, one with parameters,
// one inner list, one bare (Boolean) key.
const DICT = "a=1, b=2;x=1;y=2, c=(a b c), d";
const BODY = '{"amount":100}';

const MERCHANT_URL = "https://merchant.example.com/.well-known/jwks.json";
const GATEWAY_URL = "https://gateway.example.com/.well-known/jwks.json";

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function baseRequest(dictValue: string = DICT) {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json", "x-dict": dictValue },
    body: BODY,
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

interface StoreOpts {
  fetchImpl?: JwksFetchImpl;
  now?: () => number;
}

function restoredStore(
  url: string,
  publicKey: KeyObject,
  kid: string,
  opts: StoreOpts = {},
): JwksKeyStore {
  return JwksKeyStore.restore(snapshotFor(publicKey, kid), url, {
    fetchImpl: noFetch,
    ttlSec: 300,
    ...opts,
  });
}

/**
 * One merchant + one gateway signature on the same request, each
 * party's public key held in its own offline-restored JwksKeyStore.
 * Merchant binds dictionary member b, gateway binds member c, so a
 * tamper aimed at one label's member cannot be confused with a
 * failure of the other label's member selection.
 */
function twoParty(opts: {
  merchantStoreOpts?: StoreOpts;
  gatewayStoreOpts?: StoreOpts;
} = {}) {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signRequest(baseRequest(), {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@method", 'x-dict;key="b"'],
    }),
    signRequest(baseRequest(), {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
      coveredComponents: ["@method", 'x-dict;key="c"'],
    }),
  );
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    opts.merchantStoreOpts,
  );
  const gatewayStore = restoredStore(
    GATEWAY_URL,
    gateway.publicKey,
    "gateway-key-1",
    opts.gatewayStoreOpts,
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

test("verifyAllLabels x ;key x JwksKeyStore: dual labels each resolve via their own store and each cover their own dictionary member", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // Store isolation first: neither store may answer for the other's kid.
  assert.equal(merchantStore.resolve("gateway-key-1"), undefined);
  assert.equal(gatewayStore.resolve("merchant-key-1"), undefined);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].keyId, "gateway-key-1");
  assert.ok(results[0].coveredComponents?.includes('x-dict;key="b"'));
  assert.ok(results[1].coveredComponents?.includes('x-dict;key="c"'));
});

test("verifyAllLabels x ;key x JwksKeyStore: tampering the merchant's selected member fails only the merchant label", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const tampered = {
    ...merged,
    headers: {
      ...merged.headers,
      "x-dict": "a=1, b=3;x=1;y=2, c=(a b c), d",
    },
  };
  const results = verifyWithStores(tampered, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  // The gateway label binds member c, which is untouched: its JWKS
  // resolution and its member check must both still succeed.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x ;key x JwksKeyStore: tampering a parameter of the merchant's selected member fails only the merchant label", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const tampered = {
    ...merged,
    headers: {
      ...merged.headers,
      "x-dict": "a=1, b=2;x=9;y=2, c=(a b c), d",
    },
  };
  const results = verifyWithStores(tampered, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x ;key x JwksKeyStore: editing only unselected members still verifies both labels", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  // a and d are bound by neither label (merchant binds b, gateway
  // binds c), so both may change freely.
  const edited = {
    ...merged,
    headers: {
      ...merged.headers,
      "x-dict": "a=99, b=2;x=1;y=2, c=(a b c), d=?0",
    },
  };
  const results = verifyWithStores(edited, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
});

test("verifyAllLabels x ;key x JwksKeyStore: deleting the merchant's selected member fails that label closed while the gateway label still verifies", () => {
  const { merged, merchantStore, gatewayStore } = twoParty();
  const deleted = {
    ...merged,
    headers: { ...merged.headers, "x-dict": "a=1, c=(a b c), d" },
  };
  const results = verifyWithStores(deleted, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(results[0].reason ?? "", /dictionary member "b" is not present/);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x ;key x JwksKeyStore: rotated-out merchant key fails KEY_RESOLUTION_FAILED while the gateway member label still verifies", async () => {
  const { merged, merchant, gatewayStore } = twoParty();
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
  const merchantStore = restoredStore(
    MERCHANT_URL,
    merchant.publicKey,
    "merchant-key-1",
    { fetchImpl: rotatedFetch, now: () => CREATED },
  );
  await merchantStore.refresh();
  assert.equal(merchantStore.resolve("merchant-key-1"), undefined);
  assert.notEqual(merchantStore.resolve("merchant-key-2"), undefined);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[0].keyId, "merchant-key-1");
  // The gateway label's key still resolves and its member c is
  // untouched: a neighbour's rotation must not turn into a member
  // or signature failure on this label.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
  assert.ok(results[1].coveredComponents?.includes('x-dict;key="c"'));
});

test("verifyAllLabels x ;key x JwksKeyStore: a stale gateway snapshot still resolves and both member labels still verify, with no fetch attempted", () => {
  const { merged, merchantStore, gatewayStore } = twoParty({
    gatewayStoreOpts: { now: () => CREATED + 1000 },
  });
  assert.equal(gatewayStore.isStale(), true);
  assert.notEqual(gatewayStore.resolve("gateway-key-1"), undefined);
  const results = verifyWithStores(merged, merchantStore, gatewayStore);
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(results[1].keyId, "gateway-key-1");
});
