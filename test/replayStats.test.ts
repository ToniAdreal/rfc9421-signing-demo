import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;

// Fresh cache starts with zeroed counters.
test("fresh cache: stats() starts at zero", () => {
  const cache = new ReplayCache({ now: () => 1000 });
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
});

// Mixed call sequence: hits and misses are counted accurately.
test("mixed sequence: hits and misses counted accurately", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 100, ttlSec: 3600, now: () => t });

  assert.equal(cache.check("a"), false); // miss
  assert.equal(cache.check("b"), false); // miss
  assert.equal(cache.check("a"), true); // hit
  assert.equal(cache.check("c"), false); // miss
  assert.equal(cache.check("b"), true); // hit
  assert.equal(cache.check("d"), false); // miss

  assert.deepEqual(cache.stats(), { size: 4, hits: 2, misses: 4, evictions: 0 });
});

// Expired-entry reclamation inside prune() counts as evictions.
test("expired reclamation counts as evictions", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 100, now: () => t });
  cache.check("e1");
  cache.check("e2");
  assert.deepEqual(cache.stats(), { size: 2, hits: 0, misses: 2, evictions: 0 });

  t += 200; // both entries expired
  assert.equal(cache.check("e3"), false); // miss; prune reclaims e1 to make room
  // prune reclaims lazily: only one slot was needed, so only e1 was dropped.
  assert.deepEqual(cache.stats(), { size: 1, hits: 0, misses: 3, evictions: 1 });
});

// LRU eviction counts as evictions.
test("LRU eviction counts as evictions", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 3600, now: () => t });
  cache.check("a");
  cache.check("b");
  assert.equal(cache.check("c"), false); // miss; nothing expired: evict oldest (a)
  assert.deepEqual(cache.stats(), { size: 2, hits: 0, misses: 3, evictions: 1 });

  // "a" was evicted: checking it is a miss, and room is made by evicting "b".
  assert.equal(cache.check("a"), false);
  assert.deepEqual(cache.stats(), { size: 2, hits: 0, misses: 4, evictions: 2 });
  // "c" survived; "b" was evicted by the previous check.
  assert.equal(cache.check("c"), true); // hit
  assert.equal(cache.check("b"), false); // miss (evicted)
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 5, evictions: 3 });
});

// An expired nonce re-recorded by check() is a miss, not an eviction.
test("expired nonce re-record is a miss, not an eviction", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 10, ttlSec: 100, now: () => t });
  assert.equal(cache.check("a"), false); // miss
  t += 150; // expired
  // Treated as unseen: recorded fresh, returns false (not a replay).
  assert.equal(cache.check("a"), false);
  assert.deepEqual(cache.stats(), { size: 1, hits: 0, misses: 2, evictions: 0 });
});

// clear() resets the counters as well as the tracked nonces.
test("clear() resets counters", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("x");
  cache.check("x"); // hit
  assert.deepEqual(cache.stats(), { size: 1, hits: 1, misses: 1, evictions: 0 });
  cache.clear();
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
});

// stats() returns a snapshot: mutating it must not affect the cache.
test("stats() returns a detached snapshot", () => {
  const cache = new ReplayCache({ now: () => 1000 });
  cache.check("a");
  const s = cache.stats();
  s.hits = 999;
  s.misses = 999;
  s.evictions = 999;
  s.size = 999;
  const again = cache.stats();
  assert.deepEqual(again, { size: 1, hits: 0, misses: 1, evictions: 0 });
});

// End-to-end through verifyRequest: the verify path drives the counters,
// and the no-cache path is unaffected.
test("verifyRequest drives the counters; no-cache path unaffected", () => {
  const t = CREATED + 60;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 3600, now: () => t });
  const { privateKey, publicKey } = generateEd25519KeyPair();
  const signed = (nonce: string) =>
    signRequest(
      { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
      { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, nonce },
    );
  const opts = { key: publicKey, now: t, replayCache: cache } as const;
  const verify = (nonce: string) => verifyRequest(signed(nonce), opts);

  assert.equal(verify("n1").ok, true); // miss
  assert.equal(verify("n2").ok, true); // miss
  assert.equal(verify("n1").code, "NONCE_REPLAY"); // hit
  assert.equal(verify("n3").ok, true); // miss + LRU eviction of n1
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 3, evictions: 1 });

  // The no-cache path never touches any cache and verifies the same
  // nonce twice without a replay verdict (backwards compatible).
  const plainSigned = signed("no-cache-nonce");
  for (let i = 0; i < 2; i++) {
    const res = verifyRequest(plainSigned, { key: publicKey, now: t });
    assert.equal(res.ok, true);
    assert.equal(res.code, undefined);
  }
  // Counters unchanged by the no-cache verifications.
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 3, evictions: 1 });
});
