import test from "node:test";
import assert from "node:assert/strict";
import { ReplayCache } from "../src/index.js";

/**
 * `check()` used to guard only the empty string, while `has()` and
 * `release()` reject any non-string nonce. A JS caller passing a number
 * would silently record a numeric key, so a later `check("123")` missed
 * the replay. (backlog #1286)
 */

function assertConfigError(fn: () => unknown, message: string): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof Error, "must throw an Error");
    assert.ok(!(err instanceof TypeError), "must be a plain Error, not a TypeError");
    assert.equal((err as Error).message, message);
    return true;
  });
}

test("check: number nonce throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check(123 as unknown as string),
    "ReplayCache: nonce must be a non-empty string",
  );
});

test("check: object nonce throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check({ value: "n" } as unknown as string),
    "ReplayCache: nonce must be a non-empty string",
  );
});

test("check: null nonce throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check(null as unknown as string),
    "ReplayCache: nonce must be a non-empty string",
  );
});

test("check: undefined nonce throws a configuration Error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(
    () => cache.check(undefined as unknown as string),
    "ReplayCache: nonce must be a non-empty string",
  );
});

test("check: empty string still throws the original error", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assertConfigError(() => cache.check(""), "ReplayCache: nonce must be non-empty");
});

test("check: a rejected non-string nonce leaves no residue", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.throws(() => cache.check(123 as unknown as string), /non-empty string/);
  // No numeric key was recorded: the string form is still first-seen,
  // and the failed call changed no counters.
  assert.equal(cache.size, 0);
  assert.deepEqual(cache.stats(), { size: 0, hits: 0, misses: 0, evictions: 0 });
  assert.equal(cache.has("123"), false);
  assert.equal(cache.check("123"), false);
  assert.equal(cache.check("123"), true);
});

test("check: string nonce hit/miss behavior is unchanged", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  assert.equal(cache.check("a"), false);
  assert.equal(cache.check("a"), true);
  assert.equal(cache.has("a"), true);
  assert.equal(cache.release("a"), true);
  assert.equal(cache.has("a"), false);
  assert.equal(cache.check("a"), false);
});

test("check: non-string rejection matches has/release wording", () => {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  for (const bad of [123, {}, null, undefined] as unknown as string[]) {
    assert.throws(
      () => cache.has(bad),
      { message: "ReplayCache: nonce must be a non-empty string" },
    );
    assert.throws(
      () => cache.release(bad),
      { message: "ReplayCache: nonce must be a non-empty string" },
    );
    assert.throws(
      () => cache.check(bad),
      { message: "ReplayCache: nonce must be a non-empty string" },
    );
  }
  assert.equal(cache.size, 0);
});
