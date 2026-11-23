import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

// Backlog #1349: `ReplayCache`'s constructor read `opts.maxEntries`
// with no guard on `opts` itself, so `new ReplayCache(null)` died as
// a bare `TypeError: Cannot read properties of null (reading
// 'maxEntries')` — while the sibling constructors (`memoizeKeyResolver`,
// `JwksKeyStore`) and `ReplayCache`'s own value checks already throw
// named configuration Errors. The signed-restore entry points had
// the same shape of gap: `restoreSignedSnapshot` read `opts.now`
// before reaching the constructor, and `restoreSignedSnapshotsByLabel`
// read `opts.expectedLabels` first. All three now fail closed with
// `ReplayCache: opts must be an object` before any field is read.

const MSG = "ReplayCache: opts must be an object";
const SECRET = "replay-cache-opts-shape-secret-for-tests";

function assertNamedError(fn: () => unknown): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, "must throw an Error");
    assert.ok(!(e instanceof TypeError), "must not be a bare TypeError");
    assert.equal(e.message, MSG);
    return true;
  });
}

function seededEnvelope() {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("nonce-a");
  return cache.exportSignedSnapshot(SECRET);
}

test("constructor: null opts throws a named error, not a TypeError", () => {
  assertNamedError(() => new ReplayCache(null as never));
});

test("constructor: string opts throws a named error", () => {
  assertNamedError(() => new ReplayCache("x" as never));
});

test("constructor: number opts throws a named error", () => {
  assertNamedError(() => new ReplayCache(42 as never));
});

test("constructor: array opts throws a named error", () => {
  assertNamedError(() => new ReplayCache([] as never));
});

test("constructor: undefined opts still means the defaults", () => {
  const cache = new ReplayCache(undefined);
  assert.equal(cache.check("n1", 1000), false);
  assert.equal(cache.check("n1", 1000), true); // replay
  // `size` reads the wall clock, so an entry stamped at t=1000 is
  // already past the default 3600s TTL there — assert through
  // `check` only, which takes the explicit clock.
  assert.equal(cache.check("n2", 1000), false);
});

test("constructor: custom maxEntries/ttlSec/injected clock unchanged", () => {
  let t = 1000;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 60, now: () => t });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("b"), false);
  assert.equal(cache.check("a"), true); // replay, still tracked
  t += 61; // past the TTL: "a" is unseen again
  assert.equal(cache.check("a"), false);
});

test("restore: null opts throws a named error", () => {
  assertNamedError(() =>
    ReplayCache.restore({ v: 1, entries: [["n", 1000]] }, null as never),
  );
});

test("fromSnapshot: null opts throws a named error (inherits the guard)", () => {
  assertNamedError(() =>
    ReplayCache.fromSnapshot({ v: 1, entries: [["n", 1000]] }, null as never),
  );
});

test("restore: valid opts still restore the snapshot", () => {
  const restored = ReplayCache.restore(
    { v: 1, entries: [["n", 1000]] },
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.size, 1);
  assert.equal(restored.check("n", 1000), true); // replay
});

test("restoreSignedSnapshot: null opts throws a named error", () => {
  const envelope = seededEnvelope();
  assertNamedError(() =>
    ReplayCache.restoreSignedSnapshot(envelope, SECRET, null as never),
  );
});

test("restoreSignedSnapshot: string opts throws a named error", () => {
  const envelope = seededEnvelope();
  assertNamedError(() =>
    ReplayCache.restoreSignedSnapshot(envelope, SECRET, "x" as never),
  );
});

test("restoreSignedSnapshot: null opts wins over a bad secret (guard is first)", () => {
  const envelope = seededEnvelope();
  assertNamedError(() =>
    ReplayCache.restoreSignedSnapshot(envelope, "wrong-secret", null as never),
  );
});

test("restoreSignedSnapshot: valid opts still restore the envelope", () => {
  const envelope = seededEnvelope();
  const restored = ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.size, 1);
  assert.equal(restored.check("nonce-a", 1000), true); // replay
});

test("restoreSignedSnapshotsByLabel: null opts throws a named error", () => {
  const envelope = seededEnvelope();
  assertNamedError(() =>
    ReplayCache.restoreSignedSnapshotsByLabel({ a: envelope }, SECRET, null as never),
  );
});

test("restoreSignedSnapshotsByLabel: valid opts still restore the map", () => {
  const envelope = seededEnvelope();
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(
    { a: envelope },
    SECRET,
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.a.size, 1);
  assert.equal(restored.a.check("nonce-a", 1000), true); // replay
});
