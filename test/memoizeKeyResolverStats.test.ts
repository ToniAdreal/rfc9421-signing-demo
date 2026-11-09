import test from "node:test";
import assert from "node:assert/strict";
import { createSecretKey, type KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  memoizeKeyResolver,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

/** Cheap deterministic keys: memoization never inspects key material. */
function keyFor(id: string): KeyObject {
  return createSecretKey(Buffer.from(`memoize-stats-${id}`, "utf8"));
}

function countingStore(ids: string[]) {
  const store = new Map(ids.map((id) => [id, keyFor(id)]));
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  return { store, resolver, calls: () => calls };
}

test("memoizeKeyResolver stats: zero initial counters", () => {
  const { resolver } = countingStore(["k1"]);
  const memoized = memoizeKeyResolver(resolver, { now: () => 1_700_000_000 });
  assert.deepEqual(memoized.stats(), {
    size: 0,
    hits: 0,
    misses: 0,
    evictions: 0,
  });
});

test("memoizeKeyResolver stats: hits and misses counted, unknown keyid is a miss and stays uncached", () => {
  const { store, resolver, calls } = countingStore(["k1"]);
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  assert.equal(memoized("k1"), store.get("k1")); // miss, cached
  assert.equal(memoized("k1"), store.get("k1")); // hit
  assert.equal(memoized("k1"), store.get("k1")); // hit
  assert.equal(memoized("missing"), undefined); // miss, not cached
  assert.equal(memoized("missing"), undefined); // miss again
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 2,
    misses: 3,
    evictions: 0,
  });
  assert.equal(calls(), 3);
});

test("memoizeKeyResolver stats: expired entry is a miss and counts as an eviction", () => {
  const { store, resolver } = countingStore(["k1"]);
  let t = 1_700_000_000;
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 10,
    now: () => t,
  });
  memoized("k1"); // miss, cached until t + 10
  t += 9;
  memoized("k1"); // hit at t + 9: recency refreshed, TTL not extended
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
  t += 1; // t + 10: the original expiry, hit would not renew it
  assert.equal(memoized("k1"), store.get("k1")); // miss, expired entry reclaimed
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 2,
    evictions: 1,
  });
});

test("memoizeKeyResolver stats: LRU eviction from a full cache counts", () => {
  const { store, resolver } = countingStore(["k1", "k2", "k3"]);
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    maxEntries: 2,
    now: () => 1_700_000_000,
  });
  memoized("k1"); // miss, [k1]
  memoized("k2"); // miss, [k1, k2]
  memoized("k1"); // hit, recency refreshed -> [k2, k1]
  memoized("k3"); // miss, full: evicts LRU k2 -> [k1, k3]
  assert.deepEqual(memoized.stats(), {
    size: 2,
    hits: 1,
    misses: 3,
    evictions: 1,
  });
  assert.equal(memoized("k2"), store.get("k2")); // miss: k2 was evicted
  // Re-caching k2 evicts the new LRU (k1) from the full cache.
  assert.deepEqual(memoized.stats(), {
    size: 2,
    hits: 1,
    misses: 4,
    evictions: 2,
  });
});

test("memoizeKeyResolver stats: expired entries reclaimed while making room count as evictions", () => {
  const { store, resolver } = countingStore(["k1", "k2", "k3"]);
  let t = 1_700_000_000;
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 10,
    maxEntries: 2,
    now: () => t,
  });
  memoized("k1"); // miss, [k1]
  memoized("k2"); // miss, [k1, k2]
  t += 11; // both entries expired
  memoized("k3"); // miss: makeRoom reclaims one expired entry (enough for room), no LRU eviction
  assert.deepEqual(memoized.stats(), {
    size: 2,
    hits: 0,
    misses: 3,
    evictions: 1,
  });
  // The second expired entry is still in the cache (reclaim stops once
  // there is room); reading it reclaims it on the spot instead of
  // serving it.
  assert.equal(memoized("k2"), store.get("k2"));
  assert.deepEqual(memoized.stats(), {
    size: 2,
    hits: 0,
    misses: 4,
    evictions: 2,
  });
});

test("memoizeKeyResolver stats: clear empties the cache and resets every counter", () => {
  const { store, resolver } = countingStore(["k1", "k2", "k3"]);
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    maxEntries: 2,
    now: () => 1_700_000_000,
  });
  memoized("k1");
  memoized("k2");
  memoized("k3"); // evicts k1
  assert.deepEqual(memoized.stats(), {
    size: 2,
    hits: 0,
    misses: 3,
    evictions: 1,
  });
  memoized.clear();
  assert.deepEqual(memoized.stats(), {
    size: 0,
    hits: 0,
    misses: 0,
    evictions: 0,
  });
  assert.equal(memoized("k1"), store.get("k1")); // miss again from the empty cache
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
});

test("memoizeKeyResolver stats: the snapshot is detached", () => {
  const { resolver } = countingStore(["k1"]);
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  memoized("k1");
  const snapshot = memoized.stats();
  snapshot.hits = 999;
  snapshot.size = 999;
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
});

test("memoizeKeyResolver stats: the returned resolver still verifies as a keyResolver", () => {
  const { privateKey, publicKey } = generateEd25519KeyPair();
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return id === "merchant-key-1" ? publicKey : undefined;
  };
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed: SignedHttpRequest = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "merchant-key-1", alg: "ed25519", key: privateKey, created: 1700000000 },
  );
  for (let i = 0; i < 2; i++) {
    assert.equal(
      verifyRequest(signed, { keyResolver: memoized, now: 1700000000 }).ok,
      true,
    );
  }
  assert.equal(calls, 1);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
});
