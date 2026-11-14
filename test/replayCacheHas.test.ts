import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

test("has: seen nonce returns true, unseen returns false", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.has("a"), true);
  assert.equal(cache.has("b"), false);
});

test("has does not record: a probed nonce is still first-seen to check", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.has("x"), false);
  assert.equal(cache.size, 0);
  // The probe left nothing behind: this is still the first sighting.
  assert.equal(cache.check("x"), false);
  assert.equal(cache.size, 1);
  assert.equal(cache.check("x"), true);
});

test("has: expired nonce returns false (TTL boundary matches check)", () => {
  let now = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => now });
  assert.equal(cache.check("n"), false);
  now = 1000 + 3599;
  assert.equal(cache.has("n"), true);
  now = 1000 + 3600;
  assert.equal(cache.has("n"), false);
});

test("has with an explicit now: same TTL boundary without the injected clock", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("n"), false);
  assert.equal(cache.has("n", 1000 + 3599), true);
  assert.equal(cache.has("n", 1000 + 3600), false);
});

test("has does not move the stats counters", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("a"), true);
  const before = cache.stats();
  assert.deepEqual(before, { size: 1, hits: 1, misses: 1, evictions: 0 });
  assert.equal(cache.has("a"), true);
  assert.equal(cache.has("missing"), false);
  assert.deepEqual(cache.stats(), before);
});

test("has: invalid nonce throws", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.throws(() => cache.has(""), /non-empty/);
  assert.throws(() => cache.has(123 as unknown as string), /non-empty/);
  assert.throws(() => cache.has(undefined as unknown as string), /non-empty/);
  // The failed probes recorded nothing.
  assert.equal(cache.size, 0);
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
});

test("has: clear makes every nonce unseen again", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.has("a"), true);
  cache.clear();
  assert.equal(cache.has("a"), false);
  assert.equal(cache.has("b"), false);
  assert.equal(cache.check("a"), false);
});

test("has does not refresh LRU recency", () => {
  const cache = new ReplayCache({
    maxEntries: 3,
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.check("c"), false);
  // Probing "a" must not move it to the tail: it stays the eviction
  // candidate when the next nonce arrives.
  assert.equal(cache.has("a"), true);
  assert.equal(cache.check("d"), false);
  assert.equal(cache.has("a"), false);
  assert.equal(cache.has("b"), true);
  assert.equal(cache.has("c"), true);
  assert.equal(cache.has("d"), true);
});

test("has on an expired nonce triggers no reclamation", () => {
  let now = 1000;
  const cache = new ReplayCache({
    maxEntries: 2,
    ttlSec: 10,
    now: () => now,
  });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  now = 1011;
  assert.equal(cache.has("a"), false);
  assert.equal(cache.has("b"), false);
  // Nothing was reclaimed by the probes: evictions stays zero until a
  // recording check has to make room.
  assert.equal(cache.stats().evictions, 0);
  assert.equal(cache.check("c"), false);
  assert.equal(cache.stats().evictions, 1);
});

test("has does not change size", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.has("unseen"), false);
  assert.equal(cache.size, 0);
  assert.equal(cache.check("seen"), false);
  assert.equal(cache.has("seen"), true);
  assert.equal(cache.size, 1);
});
