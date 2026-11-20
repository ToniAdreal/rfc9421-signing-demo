import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

/**
 * `check`/`has`/`release`/`size`/`exportSnapshot` used to read the
 * explicit `now` argument (or the injected clock) without any
 * finite-number check: a `NaN` reading made every `t - prev < ttlSec`
 * comparison false, so a nonce already seen looked expired and the
 * replay check silently stopped working. A bad clock now fails closed
 * with a configuration `Error` before any cache state is read or
 * changed. (backlog #1288)
 */

const NOW_MESSAGE =
  "ReplayCache: now must be a finite number of seconds since the epoch, got NaN";
const CLOCK_MESSAGE =
  "ReplayCache: clock must return a finite number of seconds since the epoch, got NaN";

function assertConfigError(fn: () => unknown, message: string): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof Error, "must throw an Error");
    assert.ok(!(err instanceof TypeError), "must be a plain Error, not a TypeError");
    assert.equal((err as Error).message, message);
    return true;
  });
}

test("check: NaN explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(() => cache.check("n1", Number.NaN), NOW_MESSAGE);
});

test("check: Infinity explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check("n1", Number.POSITIVE_INFINITY),
    "ReplayCache: now must be a finite number of seconds since the epoch, got Infinity",
  );
});

test("check: non-number explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check("n1", "x" as unknown as number),
    "ReplayCache: now must be a finite number of seconds since the epoch, got string",
  );
});

test("has: NaN explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("n1", 1000);
  assertConfigError(() => cache.has("n1", Number.NaN), NOW_MESSAGE);
});

test("release: NaN explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("n1", 1000);
  assertConfigError(() => cache.release("n1", Number.NaN), NOW_MESSAGE);
});

test("has: Infinity explicit now throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("n1", 1000);
  assertConfigError(
    () => cache.has("n1", Number.NEGATIVE_INFINITY),
    "ReplayCache: now must be a finite number of seconds since the epoch, got -Infinity",
  );
});

test("injected clock returning NaN: construction succeeds, first call throws", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => Number.NaN });
  assertConfigError(() => cache.check("n1"), CLOCK_MESSAGE);
});

test("injected clock returning a non-number: first call throws", () => {
  const cache = new ReplayCache({
    ttlSec: 3600,
    now: () => "x" as unknown as number,
  });
  assertConfigError(
    () => cache.check("n1"),
    "ReplayCache: clock must return a finite number of seconds since the epoch, got string",
  );
});

test("bad clock: cache content and counters are unchanged, no NaN residue", () => {
  let nowValue = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => nowValue });
  assert.equal(cache.check("n1", 1000), false);
  assert.equal(cache.check("n2", 1000), false);
  const statsBefore = cache.stats();
  assert.deepEqual(statsBefore, { size: 2, hits: 0, misses: 2, evictions: 0 });

  nowValue = Number.NaN;
  assertConfigError(() => cache.check("n1"), CLOCK_MESSAGE);
  assertConfigError(() => cache.has("n1"), CLOCK_MESSAGE);
  assertConfigError(() => cache.release("n1"), CLOCK_MESSAGE);

  // The failed calls recorded nothing: back on a good clock the
  // original nonces are still tracked and no new entry exists.
  nowValue = 1000;
  assert.equal(cache.has("n1", 1000), true);
  assert.equal(cache.has("n2", 1000), true);
  assert.equal(cache.check("n1", 1000), true);
  assert.deepEqual(cache.stats(), { size: 2, hits: 1, misses: 2, evictions: 0 });
});

test("size: bad injected clock throws instead of reporting 0", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => Number.NaN });
  assertConfigError(() => cache.size, CLOCK_MESSAGE);
});

test("exportSnapshot: bad injected clock throws instead of exporting empty", () => {
  let nowValue = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => nowValue });
  cache.check("n1", 1000);
  nowValue = Number.NaN;
  assertConfigError(() => cache.exportSnapshot(), CLOCK_MESSAGE);
  nowValue = 1000;
  assert.deepEqual(cache.exportSnapshot(), { v: 1, entries: [["n1", 1000]] });
});

test("legal clocks and explicit now behave exactly as before", () => {
  let nowValue = 1000;
  const cache = new ReplayCache({ ttlSec: 100, now: () => nowValue });
  assert.equal(cache.check("n1"), false);
  assert.equal(cache.check("n1"), true);
  assert.equal(cache.has("n1"), true);
  assert.equal(cache.size, 1);
  assert.equal(cache.release("n1"), true);
  assert.equal(cache.has("n1"), false);
  // Explicit now overrides the injected clock, including an earlier time.
  assert.equal(cache.check("n2", 500), false);
  assert.equal(cache.has("n2", 550), true);
  assert.equal(cache.has("n2", 600), false);
  nowValue = 2000;
  assert.equal(cache.size, 0);
  assert.deepEqual(cache.exportSnapshot(), { v: 1, entries: [] });
});
