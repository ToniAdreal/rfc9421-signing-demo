import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
  type ReplayCacheSnapshot,
} from "../src/index.js";

const CREATED = 1700000000;

// A nonce seen before the export is still a replay after restore —
// the restart does not reopen the replay window. Exercised both
// directly and end-to-end through verifyRequest.
test("snapshot round-trip: seen nonce is still rejected after restore", () => {
  let t = 1000;
  const opts = { ttlSec: 3600, now: () => t };
  const cache = new ReplayCache(opts);
  assert.equal(cache.check("snap-1"), false);
  assert.equal(cache.check("snap-2"), false);

  const snap = cache.exportSnapshot();
  assert.equal(snap.v, 1);
  assert.deepEqual(snap.entries, [
    ["snap-1", 1000],
    ["snap-2", 1000],
  ]);

  const restored = ReplayCache.restore(snap, opts);
  assert.equal(restored.size, 2);
  assert.equal(restored.check("snap-1"), true); // replay
  assert.equal(restored.check("snap-2"), true); // replay
  assert.equal(restored.check("snap-3"), false); // fresh nonce still records
  // The original cache is untouched by the restore.
  assert.equal(cache.size, 2);

  // End-to-end: a signature verified before the "restart" is rejected
  // with NONCE_REPLAY by the verifier using the restored cache.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, nonce: "wire-1" },
  );
  const before = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const vopts = { key: publicKey, now: CREATED + 60 };
  assert.equal(verifyRequest(signed, { ...vopts, replayCache: before }).ok, true);
  const after = ReplayCache.restore(before.exportSnapshot(), {
    ttlSec: 3600,
    now: () => CREATED + 60,
  });
  const replayed = verifyRequest(signed, { ...vopts, replayCache: after });
  assert.equal(replayed.ok, false);
  assert.equal(replayed.code, "NONCE_REPLAY");
});

// Entries that have already expired at export time never enter the
// snapshot (they would be dead weight — and wrong: their TTL is over).
test("export excludes entries already expired at export time", () => {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 100, now: () => t });
  cache.check("old");
  t = 1050;
  cache.check("fresh");
  t = 1150; // "old" is 150s old (expired), "fresh" is exactly 100s old (expired: >= ttl)
  const snap = cache.exportSnapshot();
  assert.deepEqual(snap.entries, []);
  t = 1149; // one second earlier "fresh" (99s old) is still live, "old" is not
  assert.deepEqual(cache.exportSnapshot().entries, [["fresh", 1050]]);
});

// The TTL keeps counting from the original first-seen time: restoring
// must not grant a fresh window. If restore re-timestamped entries,
// the nonce below would still be blocked at t=1101.
test("restored TTL counts from the original seenAt, not the restore time", () => {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 100, now: () => t });
  cache.check("ttl-1"); // first seen at t=1000, expires at t=1100
  const snap = cache.exportSnapshot();

  t = 1090; // restore happens 90s later, 10s before expiry
  const restored = ReplayCache.restore(snap, { ttlSec: 100, now: () => t });
  assert.equal(restored.check("ttl-1"), true); // still within the original window

  t = 1101; // past the ORIGINAL expiry (1000 + 100), inside a would-be restored window (1090 + 100)
  assert.equal(restored.check("ttl-1"), false); // treated as unseen again
});

// Entries that expire between export and restore are dropped at load.
test("restore drops entries already expired at restore time", () => {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 100, now: () => t });
  cache.check("gone");
  const snap = cache.exportSnapshot();
  assert.equal(snap.entries.length, 1);

  t = 1200; // the entry's TTL ran out while the snapshot sat on disk
  const restored = ReplayCache.restore(snap, { ttlSec: 100, now: () => t });
  assert.equal(restored.size, 0);
  assert.equal(restored.check("gone"), false);
});

// Corrupt snapshots are configuration errors, never a silently empty
// (replay-protection-off) cache.
test("malformed snapshots throw a clear configuration error", () => {
  const bad: Array<[string, unknown, RegExp]> = [
    ["null", null, /invalid snapshot/],
    ["non-object", "snapshot", /invalid snapshot/],
    ["top-level array", [], /invalid snapshot/],
    ["wrong version", { v: 2, entries: [] }, /unsupported snapshot version 2/],
    ["string version", { v: "1", entries: [] }, /unsupported snapshot version "1"/],
    ["null version", { v: null, entries: [] }, /unsupported snapshot version null/],
    ["missing version", { entries: [] }, /unsupported snapshot version undefined/],
    ["unknown field", { v: 1, entries: [], extra: 1 }, /unknown field "extra"/],
    ["missing entries", { v: 1 }, /entries must be an array/],
    ["non-array entries", { v: 1, entries: "x" }, /entries must be an array/],
    ["entry not a pair", { v: 1, entries: ["n"] }, /entries\[0\] must be a \[nonce, seenAt\] pair/],
    ["entry too long", { v: 1, entries: [["n", 1, 2]] }, /entries\[0\] must be a \[nonce, seenAt\] pair/],
    ["non-string nonce", { v: 1, entries: [[42, 1000]] }, /entries\[0\]: nonce must be a non-empty string/],
    ["empty nonce", { v: 1, entries: [["", 1000]] }, /entries\[0\]: nonce must be a non-empty string/],
    ["non-number seenAt", { v: 1, entries: [["n", "1000"]] }, /entries\[0\]: seenAt must be a finite non-negative number/],
    ["NaN seenAt", { v: 1, entries: [["n", Number.NaN]] }, /entries\[0\]: seenAt/],
    ["infinite seenAt", { v: 1, entries: [["n", Infinity]] }, /entries\[0\]: seenAt/],
    ["negative seenAt", { v: 1, entries: [["n", -1]] }, /entries\[0\]: seenAt/],
    ["second entry bad", { v: 1, entries: [["ok", 1000], ["bad", -5]] }, /entries\[1\]: seenAt/],
  ];
  for (const [name, snapshot, pattern] of bad) {
    assert.throws(() => ReplayCache.restore(snapshot), pattern, name);
  }
  // The fromSnapshot alias validates identically.
  assert.throws(() => ReplayCache.fromSnapshot({ v: 2, entries: [] }), /unsupported snapshot version/);
  assert.equal(ReplayCache.fromSnapshot({ v: 1, entries: [["a", 1000]] }, { now: () => 1000 }).size, 1);
});

// Over-capacity restore keeps the newest entries: the oldest by
// seenAt are evicted first, and size never exceeds maxEntries.
test("over-capacity restore evicts the oldest seenAt first", () => {
  const snap: ReplayCacheSnapshot = {
    v: 1,
    entries: [
      ["n1", 1000],
      ["n2", 1001],
      ["n3", 1002],
      ["n4", 1003],
      ["n5", 1004],
    ],
  };
  const restored = ReplayCache.restore(snap, {
    maxEntries: 3,
    ttlSec: 3600,
    now: () => 1010,
  });
  assert.equal(restored.size, 3);
  assert.ok(restored.size <= 3);
  // n1/n2 (oldest seenAt) were evicted: they record as fresh.
  assert.equal(restored.check("n1", 1010), false);
  assert.equal(restored.check("n2", 1010), false);
});

// Separate assertion for the survivors, on a fresh restore: the
// newest three are all still tracked as replays.
test("over-capacity restore keeps the newest entries as replays", () => {
  const snap: ReplayCacheSnapshot = {
    v: 1,
    entries: [
      ["n1", 1000],
      ["n2", 1001],
      ["n3", 1002],
      ["n4", 1003],
      ["n5", 1004],
    ],
  };
  const restored = ReplayCache.restore(snap, {
    maxEntries: 3,
    ttlSec: 3600,
    now: () => 1010,
  });
  assert.equal(restored.check("n3", 1010), true);
  assert.equal(restored.check("n4", 1010), true);
  assert.equal(restored.check("n5", 1010), true);
});

// An empty cache snapshots and restores cleanly.
test("empty cache round-trips", () => {
  const cache = new ReplayCache({ now: () => 1000 });
  const snap = cache.exportSnapshot();
  assert.deepEqual(snap, { v: 1, entries: [] });
  const restored = ReplayCache.restore(snap, { now: () => 1000 });
  assert.equal(restored.size, 0);
  assert.deepEqual(restored.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
  assert.equal(restored.check("anything"), false);
});

// The exported snapshot is a detached copy: mutating it (entries,
// pairs, version) must not reach back into the source cache. And a
// restored cache is likewise detached from the snapshot object.
test("export and restore are detached copies", () => {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => t });
  cache.check("keep");
  const snap = cache.exportSnapshot();
  snap.entries[0][0] = "forged";
  snap.entries[0][1] = 0;
  snap.entries.push(["injected", 1000]);
  (snap as { v: number }).v = 99;

  assert.equal(cache.size, 1);
  assert.equal(cache.check("keep"), true); // original entry intact
  assert.equal(cache.check("forged"), false); // mutations never landed
  assert.equal(cache.check("injected"), false);

  const clean = cache.exportSnapshot();
  const restored = ReplayCache.restore(clean, { ttlSec: 3600, now: () => t });
  clean.entries.length = 0; // gutting the snapshot afterwards changes nothing
  assert.equal(restored.size, 3);
  assert.equal(restored.check("keep"), true);
});

// Counters are observability for one process lifetime: they are not
// serialized, and load-time expiry/truncation is not an eviction.
test("restore starts counters at zero", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 100, now: () => t });
  cache.check("a");
  cache.check("a"); // hit
  cache.check("b");
  cache.check("c"); // miss + eviction
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 3, evictions: 1 });

  const restored = ReplayCache.restore(cache.exportSnapshot(), {
    maxEntries: 2,
    ttlSec: 100,
    now: () => t,
  });
  assert.deepEqual(restored.stats(), { size: 2, hits: 0, misses: 0, evictions: 0 });
});

// The snapshot survives the actual persistence path: JSON text on
// disk, parsed back at startup.
test("snapshot survives a JSON stringify/parse round-trip", () => {
  let t = 2000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => t });
  cache.check("json-1");
  cache.check("json-2");
  const wire = JSON.stringify(cache.exportSnapshot());
  const restored = ReplayCache.restore(JSON.parse(wire), { ttlSec: 3600, now: () => t });
  assert.equal(restored.check("json-1"), true);
  assert.equal(restored.check("json-2"), true);
  assert.deepEqual(restored.exportSnapshot().entries, cache.exportSnapshot().entries);
});

// Restoring under a different (valid) configuration honors the new
// cache's own limits; invalid restore options fail like the constructor.
test("restore validates its options like the constructor", () => {
  const snap: ReplayCacheSnapshot = { v: 1, entries: [["n", 1000]] };
  assert.throws(() => ReplayCache.restore(snap, { maxEntries: 0 }), /maxEntries/);
  assert.throws(() => ReplayCache.restore(snap, { ttlSec: 0 }), /ttlSec/);
  // A shorter TTL on the new cache expires the entry at load time.
  const restored = ReplayCache.restore(snap, { ttlSec: 10, now: () => 2000 });
  assert.equal(restored.size, 0);
});
