import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  memoizeKeyResolver,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
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

/** A one-key store with an observable call counter behind the resolver. */
function countingStore() {
  const k1 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key-1", k1.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  return { k1, store, resolver, calls: () => calls };
}

const CLOCK_ERROR =
  "memoizeKeyResolver: clock must return a finite number of seconds since the epoch, got ";

test("memoizeKeyResolver: a NaN clock reading throws a configuration error on lookup", () => {
  const { resolver } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { now: () => NaN });
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}NaN`,
  });
});

test("memoizeKeyResolver: an Infinity clock reading throws a configuration error on lookup", () => {
  const { resolver } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { now: () => Infinity });
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}Infinity`,
  });
});

test("memoizeKeyResolver: a -Infinity clock reading throws a configuration error on lookup", () => {
  const { resolver } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { now: () => -Infinity });
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}-Infinity`,
  });
});

test("memoizeKeyResolver: a non-number clock reading throws naming the received type", () => {
  const { resolver } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    now: () => "1700000000" as unknown as number,
  });
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}string`,
  });
});

test("memoizeKeyResolver: a failed lookup leaves no residue — no call, no entry, no counters", () => {
  const { resolver, calls } = countingStore();
  let t: number = NaN;
  const memoized = memoizeKeyResolver(resolver, { now: () => t });
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}NaN`,
  });
  assert.equal(calls(), 0);
  // The counters are only readable once the clock is good again: the
  // failed call must not have left a NaN-timestamped entry behind.
  t = CREATED;
  assert.deepEqual(memoized.stats(), {
    size: 0,
    hits: 0,
    misses: 0,
    evictions: 0,
  });
  // And the next good-clock lookup is a genuine miss, not a hit on a
  // residue entry.
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 0,
    misses: 1,
    evictions: 0,
  });
});

test("memoizeKeyResolver: a cached entry survives a bad-clock episode and counters are unchanged", () => {
  const { resolver, calls } = countingStore();
  let t: number = CREATED;
  const memoized = memoizeKeyResolver(resolver, { now: () => t });
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  const before = memoized.stats();
  assert.deepEqual(before, { size: 1, hits: 0, misses: 1, evictions: 0 });

  t = NaN;
  assert.throws(() => memoized("merchant-key-1"), {
    name: "Error",
    message: `${CLOCK_ERROR}NaN`,
  });
  assert.equal(calls(), 1);

  // With a good clock again, the counters are exactly as before the
  // failed call, and the previously cached entry still resolves.
  t = CREATED;
  assert.deepEqual(memoized.stats(), before);
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
});

test("memoizeKeyResolver: stats() throws under a bad clock instead of reporting zero", () => {
  const { resolver } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => NaN,
  });
  assert.throws(() => memoized.stats(), {
    name: "Error",
    message: `${CLOCK_ERROR}NaN`,
  });
});

test("memoizeKeyResolver: clear() throws under a bad clock and does not clear the cache", () => {
  const { resolver, calls } = countingStore();
  let t: number = CREATED;
  const memoized = memoizeKeyResolver(resolver, { now: () => t });
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);

  t = NaN;
  assert.throws(() => memoized.clear(), {
    name: "Error",
    message: `${CLOCK_ERROR}NaN`,
  });

  // The entry and the counters are untouched by the failed clear.
  t = CREATED;
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
  // And a good-clock clear still works afterwards.
  memoized.clear();
  assert.deepEqual(memoized.stats(), {
    size: 0,
    hits: 0,
    misses: 0,
    evictions: 0,
  });
});

test("memoizeKeyResolver: TTL boundary behavior is unchanged under a good clock", () => {
  const { resolver, calls } = countingStore();
  let t = CREATED;
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => t,
  });
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  // One second before expiry: still a hit.
  t = CREATED + 59;
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 1);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 1,
    evictions: 0,
  });
  // Exactly at expiry: a miss that re-resolves and reclaims the entry.
  t = CREATED + 60;
  assert.notEqual(memoized("merchant-key-1"), undefined);
  assert.equal(calls(), 2);
  assert.deepEqual(memoized.stats(), {
    size: 1,
    hits: 1,
    misses: 2,
    evictions: 1,
  });
});

test("memoizeKeyResolver: verifyRequest converges a bad clock to VERIFICATION_ERROR, never a pass-through", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { now: () => NaN });
  const signed = signAs("merchant-key-1", k1.privateKey);
  const result = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
  assert.match(result.reason ?? "", /clock must return a finite number/);
  // The memoizer never reached the keystore: the failure is the clock,
  // not a key lookup.
  assert.equal(calls(), 0);
});
