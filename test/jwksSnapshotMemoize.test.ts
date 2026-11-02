import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  memoizeKeyResolver,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function signAs(keyId: string, privateKey: KeyObject): SignedHttpRequest {
  return signRequest(freshReq(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

function pem(key: KeyObject): string {
  return key.export({ format: "pem", type: "spki" }).toString();
}

function stubFetch(body: unknown): JwksFetchImpl {
  return async () => ({ ok: true, status: 200, json: async () => body });
}

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function documentFor(
  pairs: Array<{ kid: string; publicKey: KeyObject }>,
): { keys: unknown[] } {
  return {
    keys: pairs.map(({ kid, publicKey }) => ({
      ...exportPublicKeyJwk(publicKey),
      kid,
    })),
  };
}

async function snapshotFor(
  pairs: Array<{ kid: string; publicKey: KeyObject }>,
  t: number,
): Promise<JwksKeyStoreSnapshot> {
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(documentFor(pairs)),
    ttlSec: 300,
    now: () => t,
  });
  await store.refresh();
  return store.exportSnapshot();
}

/** A fresh JSON round-trip copy, as a persisted snapshot would arrive. */
function persistedCopy(snapshot: JwksKeyStoreSnapshot): unknown {
  return JSON.parse(JSON.stringify(snapshot));
}

function restoreFrom(
  snapshot: JwksKeyStoreSnapshot,
  now: () => number,
): JwksKeyStore {
  return JwksKeyStore.restore(persistedCopy(snapshot), URL, {
    fetchImpl: noFetch,
    ttlSec: 300,
    now,
  });
}

/** Wrap a store's resolve with an observable call log. */
function counted(store: JwksKeyStore): {
  resolver: (id: string) => KeyObject | undefined;
  calls: string[];
} {
  const calls: string[] = [];
  const resolver = (id: string): KeyObject | undefined => {
    calls.push(id);
    return store.resolve(id);
  };
  return { resolver, calls };
}

test("jwksSnapshotMemoize: two stores restored from one snapshot each verify the same kid through their own memoized resolver", async () => {
  const t = 1_700_000_000;
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const snapshot = await snapshotFor(
    [
      { kid: "ed-key-1", publicKey: k1.publicKey },
      { kid: "ed-key-2", publicKey: k2.publicKey },
    ],
    t,
  );
  const storeA = restoreFrom(snapshot, () => t);
  const storeB = restoreFrom(snapshot, () => t);
  assert.equal(storeA.size, 2);
  assert.equal(storeB.size, 2);

  const a = counted(storeA);
  const b = counted(storeB);
  const memoizedA = memoizeKeyResolver(a.resolver, { ttlSec: 60, now: () => t });
  const memoizedB = memoizeKeyResolver(b.resolver, { ttlSec: 60, now: () => t });

  const signed = signAs("ed-key-1", k1.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: memoizedA, now: CREATED }).ok,
    true,
  );
  assert.equal(
    verifyRequest(signed, { keyResolver: memoizedB, now: CREATED }).ok,
    true,
  );
  // Each side consulted its own store exactly once: the snapshot
  // restore gave both sides a working key, and neither side borrowed
  // the other's cache.
  assert.deepEqual(a.calls, ["ed-key-1"]);
  assert.deepEqual(b.calls, ["ed-key-1"]);
  assert.equal(pem(memoizedA("ed-key-1")!), pem(k1.publicKey));
  assert.equal(pem(memoizedB("ed-key-1")!), pem(k1.publicKey));
  assert.deepEqual(a.calls, ["ed-key-1"]);
  assert.deepEqual(b.calls, ["ed-key-1"]);
});

test("jwksSnapshotMemoize: resolving on one side does not fill the other side's memoize cache", async () => {
  const t = 1_700_000_000;
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const snapshot = await snapshotFor(
    [
      { kid: "ed-key-1", publicKey: k1.publicKey },
      { kid: "ed-key-2", publicKey: k2.publicKey },
    ],
    t,
  );
  const a = counted(restoreFrom(snapshot, () => t));
  const b = counted(restoreFrom(snapshot, () => t));
  const memoizedA = memoizeKeyResolver(a.resolver, { ttlSec: 60, now: () => t });
  const memoizedB = memoizeKeyResolver(b.resolver, { ttlSec: 60, now: () => t });

  assert.equal(pem(memoizedA("ed-key-1")!), pem(k1.publicKey));
  assert.deepEqual(a.calls, ["ed-key-1"]);
  assert.deepEqual(b.calls, []);
  // B's cache is empty despite A's fill: B still consults its store.
  assert.equal(pem(memoizedB("ed-key-1")!), pem(k1.publicKey));
  assert.deepEqual(b.calls, ["ed-key-1"]);
  // And the reverse direction, for a different kid, is independent too.
  assert.equal(pem(memoizedB("ed-key-2")!), pem(k2.publicKey));
  assert.deepEqual(b.calls, ["ed-key-1", "ed-key-2"]);
  assert.equal(pem(memoizedA("ed-key-2")!), pem(k2.publicKey));
  assert.deepEqual(a.calls, ["ed-key-1", "ed-key-2"]);
  // Repeat resolutions are cache hits on both sides.
  memoizedA("ed-key-1");
  memoizedB("ed-key-2");
  assert.deepEqual(a.calls, ["ed-key-1", "ed-key-2"]);
  assert.deepEqual(b.calls, ["ed-key-1", "ed-key-2"]);
});

test("jwksSnapshotMemoize: restoring a second store after the first is primed does not disturb the first store's memoized cache", async () => {
  const t = 1_700_000_000;
  const k1 = generateEd25519KeyPair();
  const snapshot = await snapshotFor(
    [{ kid: "ed-key-1", publicKey: k1.publicKey }],
    t,
  );
  const a = counted(restoreFrom(snapshot, () => t));
  const memoizedA = memoizeKeyResolver(a.resolver, { ttlSec: 60, now: () => t });

  const signed = signAs("ed-key-1", k1.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: memoizedA, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1"]);

  // Only now is the second store restored from the same snapshot.
  const b = counted(restoreFrom(snapshot, () => t));
  const memoizedB = memoizeKeyResolver(b.resolver, { ttlSec: 60, now: () => t });

  // A's cache still serves without a new underlying call.
  assert.equal(
    verifyRequest(signed, { keyResolver: memoizedA, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1"]);
  // B resolves independently, with its own first underlying call.
  assert.equal(
    verifyRequest(signed, { keyResolver: memoizedB, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(b.calls, ["ed-key-1"]);
});

test("jwksSnapshotMemoize: TTL expiry re-resolves through the restored store", async () => {
  let t = 1_700_000_000;
  const k1 = generateEd25519KeyPair();
  const snapshot = await snapshotFor(
    [{ kid: "ed-key-1", publicKey: k1.publicKey }],
    t,
  );
  const a = counted(restoreFrom(snapshot, () => t));
  const memoized = memoizeKeyResolver(a.resolver, { ttlSec: 10, now: () => t });
  const signed = signAs("ed-key-1", k1.privateKey);

  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1"]);
  t = 1_700_000_009; // still within TTL
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1"]);
  t = 1_700_000_010; // exactly at TTL boundary: expired
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1", "ed-key-1"]);
});

test("jwksSnapshotMemoize: an unknown kid is never cached on either side", async () => {
  const t = 1_700_000_000;
  const k1 = generateEd25519KeyPair();
  const snapshot = await snapshotFor(
    [{ kid: "ed-key-1", publicKey: k1.publicKey }],
    t,
  );
  const a = counted(restoreFrom(snapshot, () => t));
  const b = counted(restoreFrom(snapshot, () => t));
  const memoizedA = memoizeKeyResolver(a.resolver, { ttlSec: 60, now: () => t });
  const memoizedB = memoizeKeyResolver(b.resolver, { ttlSec: 60, now: () => t });
  // Sign with a real key but claim a kid neither store knows.
  const signed = signAs("ghost-key", k1.privateKey);

  for (const memoized of [memoizedA, memoizedB]) {
    for (let i = 0; i < 2; i++) {
      const r = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
      assert.equal(r.ok, false);
      assert.equal(r.code, "KEY_RESOLUTION_FAILED");
    }
  }
  // Misses are not cached on either side: each attempt re-consulted
  // its own store, and neither side's misses leaked into the other.
  assert.deepEqual(a.calls, ["ghost-key", "ghost-key"]);
  assert.deepEqual(b.calls, ["ghost-key", "ghost-key"]);
});

test("jwksSnapshotMemoize: a memoized cache survives a snapshot restore into the same store until its TTL expires", async () => {
  let t = 1_700_000_000;
  const oldPair = generateEd25519KeyPair();
  const newPair = generateEd25519KeyPair();
  const snapshotOld = await snapshotFor(
    [{ kid: "ed-key-1", publicKey: oldPair.publicKey }],
    t,
  );
  const snapshotNew = await snapshotFor(
    [{ kid: "ed-key-1", publicKey: newPair.publicKey }],
    t,
  );
  const store = restoreFrom(snapshotOld, () => t);
  const a = counted(store);
  const memoized = memoizeKeyResolver(a.resolver, { ttlSec: 10, now: () => t });
  const signedOld = signAs("ed-key-1", oldPair.privateKey);
  const signedNew = signAs("ed-key-1", newPair.privateKey);

  assert.equal(
    verifyRequest(signedOld, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.deepEqual(a.calls, ["ed-key-1"]);

  // Rotate the store's snapshot underneath the memoized wrapper.
  store.restoreSnapshot(persistedCopy(snapshotNew));
  assert.equal(store.size, 1);
  assert.equal(pem(store.resolve("ed-key-1")!), pem(newPair.publicKey));

  // The memoized wrapper still serves the pre-rotation key: its cache
  // is per-wrapper state, not the store's snapshot. No new underlying
  // call happens, the old signature still verifies, and the new one
  // does not (it is checked against the cached old key).
  assert.equal(pem(memoized("ed-key-1")!), pem(oldPair.publicKey));
  assert.deepEqual(a.calls, ["ed-key-1"]);
  assert.equal(
    verifyRequest(signedOld, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  const staleNew = verifyRequest(signedNew, {
    keyResolver: memoized,
    now: CREATED,
  });
  assert.equal(staleNew.ok, false);
  assert.equal(staleNew.code, "SIGNATURE_MISMATCH");

  // Past the TTL the wrapper re-resolves and picks up the rotated key.
  t = 1_700_000_010;
  assert.equal(pem(memoized("ed-key-1")!), pem(newPair.publicKey));
  assert.deepEqual(a.calls, ["ed-key-1", "ed-key-1"]);
  assert.equal(
    verifyRequest(signedNew, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(
    verifyRequest(signedOld, { keyResolver: memoized, now: CREATED }).ok,
    false,
  );
});
