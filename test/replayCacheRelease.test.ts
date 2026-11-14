import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

test("release: seen nonce returns true and has turns false", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.has("a"), true);
  assert.equal(cache.release("a"), true);
  assert.equal(cache.has("a"), false);
  assert.equal(cache.size, 0);
});

test("release: unseen nonce returns false and changes nothing", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  const before = cache.stats();
  assert.equal(cache.release("missing"), false);
  assert.deepEqual(cache.stats(), before);
  assert.equal(cache.has("a"), true);
});

test("release: the same nonce checks as first-seen afterwards", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("n"), false);
  assert.equal(cache.check("n"), true); // replay while tracked
  assert.equal(cache.release("n"), true);
  // The retry of the never-executed request is first-seen again.
  assert.equal(cache.check("n"), false);
  assert.equal(cache.check("n"), true);
});

test("release: expired nonce returns false (TTL boundary matches check)", () => {
  let now = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => now });
  assert.equal(cache.check("n"), false);
  now = 1000 + 3599;
  assert.equal(cache.release("n"), true);
  // Re-record, then let it expire: release must refuse and change nothing.
  assert.equal(cache.check("n"), false);
  now = 1000 + 3599 + 3600;
  assert.equal(cache.release("n"), false);
  assert.equal(cache.has("n"), false);
  // The expired entry is still in the map for the next check to reclaim,
  // exactly as a has() probe leaves it: the next recording check reclaims
  // it as a miss, not an eviction.
  assert.equal(cache.stats().evictions, 0);
  assert.equal(cache.check("n"), false);
});

test("release with an explicit now: same TTL boundary without the injected clock", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("n"), false);
  assert.equal(cache.release("n", 1000 + 3599), true);
  assert.equal(cache.check("n"), false);
  assert.equal(cache.release("n", 1000 + 3600), false);
});

test("release: counters untouched except size", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("a"), true);
  assert.equal(cache.check("b"), false);
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 2, evictions: 0 });
  assert.equal(cache.release("a"), true);
  assert.deepEqual(cache.stats(), { size: 1, hits: 1, misses: 2, evictions: 0 });
  // Releasing an unseen nonce touches nothing at all.
  assert.equal(cache.release("missing"), false);
  assert.deepEqual(cache.stats(), { size: 1, hits: 1, misses: 2, evictions: 0 });
});

test("release does not refresh the LRU recency of sibling nonces", () => {
  const cache = new ReplayCache({
    maxEntries: 3,
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.check("c"), false);
  // Releasing "b" must not move "a" to the tail: "a" stays the eviction
  // candidate when the next nonce arrives.
  assert.equal(cache.release("b"), true);
  assert.equal(cache.check("d"), false);
  assert.equal(cache.has("a"), true);
  assert.equal(cache.has("b"), false);
  assert.equal(cache.check("e"), false);
  assert.equal(cache.has("a"), false);
  assert.equal(cache.has("c"), true);
  assert.equal(cache.has("d"), true);
  assert.equal(cache.has("e"), true);
});

test("release: the exported snapshot no longer contains the released nonce", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.release("a"), true);
  const snapshot = cache.exportSnapshot();
  assert.deepEqual(snapshot, { v: 1, entries: [["b", 1000]] });
  const restored = ReplayCache.restore(snapshot, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.has("a"), false);
  assert.equal(restored.has("b"), true);
});

test("release: invalid nonce throws", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.throws(() => cache.release(""), /non-empty/);
  assert.throws(() => cache.release(123 as unknown as string), /non-empty/);
  assert.throws(() => cache.release(undefined as unknown as string), /non-empty/);
  // The failed releases recorded nothing.
  assert.equal(cache.size, 0);
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
});

test("release after clear returns false", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  cache.clear();
  assert.equal(cache.release("a"), false);
  assert.equal(cache.size, 0);
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
});

test("release: a released nonce can be re-recorded by a fresh check without touching siblings", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.release("a"), true);
  assert.equal(cache.check("a"), false);
  assert.equal(cache.has("b"), true);
  assert.equal(cache.size, 2);
});
