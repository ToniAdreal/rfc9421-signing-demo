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

/** A two-key store with an observable call counter behind the resolver. */
function countingStore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key-1", k1.publicKey],
    ["merchant-key-2", k2.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  return { k1, k2, store, resolver, calls: () => calls };
}

test("memoizeKeyResolver: same keyid, three consecutive verifies -> one underlying call", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("merchant-key-1", k1.privateKey);
  for (let i = 0; i < 3; i++) {
    const r = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
    assert.equal(r.ok, true);
  }
  assert.equal(calls(), 1);
});

test("memoizeKeyResolver: TTL expiry re-invokes the underlying resolver", () => {
  let t = 1_700_000_000;
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { ttlSec: 10, now: () => t });
  const signed = signAs("merchant-key-1", k1.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_009; // still within TTL
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_010; // exactly at TTL boundary: expired
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 2);
});

test("memoizeKeyResolver: unknown keyid (undefined) is never cached", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  // Sign with a real key but claim a keyid the store does not know.
  const signed = signAs("ghost-key", k1.privateKey);
  for (let i = 0; i < 2; i++) {
    const r = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
    assert.equal(r.ok, false);
    assert.equal(r.code, "KEY_RESOLUTION_FAILED");
  }
  // Not cached: the store is consulted again so a rotated-in keyid is
  // discoverable on the very next verify.
  assert.equal(calls(), 2);
});

test("memoizeKeyResolver: different keyids have independent cache entries", () => {
  const { k1, k2, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const s1 = signAs("merchant-key-1", k1.privateKey);
  const s2 = signAs("merchant-key-2", k2.privateKey);
  assert.equal(
    verifyRequest(s1, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(
    verifyRequest(s2, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 2);
  assert.equal(
    verifyRequest(s1, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(
    verifyRequest(s2, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 2); // both served from their own cache entries
});

test("memoizeKeyResolver: a throwing resolver is not cached, error propagates", () => {
  const { k1 } = countingStore();
  const keys = new Map<string, KeyObject>([
    ["merchant-key-1", k1.publicKey],
  ]);
  let calls = 0;
  let broken = true;
  const flaky = (id: string): KeyObject | undefined => {
    calls++;
    if (broken) throw new Error("keystore down");
    return keys.get(id);
  };
  const memoized = memoizeKeyResolver(flaky, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("merchant-key-1", k1.privateKey);

  const r1 = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
  assert.equal(r1.ok, false);
  assert.equal(r1.code, "VERIFICATION_ERROR");
  assert.match(r1.reason ?? "", /keystore down/);
  assert.equal(calls, 1);

  // The failure was not cached: recovering the keystore is visible on the
  // next verify, and that success is then cached normally.
  broken = false;
  const r2 = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
  assert.equal(r2.ok, true);
  assert.equal(calls, 2);
  const r3 = verifyRequest(signed, { keyResolver: memoized, now: CREATED });
  assert.equal(r3.ok, true);
  assert.equal(calls, 2);
});

test("memoizeKeyResolver: default ttlSec is 300 (verified with injected clock)", () => {
  let t = 5_000_000;
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { now: () => t });
  const signed = signAs("merchant-key-1", k1.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 5_000_299;
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 1); // still cached at 299s
  t = 5_000_300; // default TTL of 300s expires here
  assert.equal(
    verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
    true,
  );
  assert.equal(calls(), 2);
});

test("memoizeKeyResolver: invalid resolver/options throw configuration errors", () => {
  const { resolver } = countingStore();
  assert.throws(
    () => memoizeKeyResolver(undefined as never),
    /`resolver` must be a function/,
  );
  assert.throws(
    () => memoizeKeyResolver(resolver, { ttlSec: 0 }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () => memoizeKeyResolver(resolver, { ttlSec: -5 }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () => memoizeKeyResolver(resolver, { ttlSec: NaN }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () => memoizeKeyResolver(resolver, { ttlSec: Infinity }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () => memoizeKeyResolver(resolver, { now: 42 as never }),
    /`now` must be a function/,
  );
});

test("memoizeKeyResolver: maxEntries cap is enforced (underlying call counts)", () => {
  const { k1 } = countingStore();
  const store = new Map<string, KeyObject>([
    ["a", k1.publicKey],
    ["b", k1.publicKey],
    ["c", k1.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    maxEntries: 2,
    now: () => 1_700_000_000,
  });
  memoized("a");
  memoized("b");
  assert.equal(calls, 2);
  memoized("a");
  memoized("b");
  assert.equal(calls, 2); // both cached
  memoized("c"); // fills beyond cap -> evicts the LRU entry (a)
  assert.equal(calls, 3);
  memoized("b");
  memoized("c");
  assert.equal(calls, 3); // b and c retained
  memoized("a");
  assert.equal(calls, 4); // a was evicted
});

test("memoizeKeyResolver: LRU eviction keeps the most recently hit entry", () => {
  const { k1 } = countingStore();
  const store = new Map<string, KeyObject>([
    ["a", k1.publicKey],
    ["b", k1.publicKey],
    ["c", k1.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    maxEntries: 2,
    now: () => 1_700_000_000,
  });
  memoized("a");
  memoized("b");
  assert.equal(calls, 2);
  memoized("a"); // hit: a becomes most recently used
  assert.equal(calls, 2);
  memoized("c"); // must evict b (LRU), not a
  assert.equal(calls, 3);
  memoized("a");
  assert.equal(calls, 3); // a retained
  memoized("c");
  assert.equal(calls, 3); // c retained
  memoized("b");
  assert.equal(calls, 4); // b was evicted
});

test("memoizeKeyResolver: expired entries are reclaimed before LRU eviction", () => {
  let t = 1_000;
  const { k1 } = countingStore();
  const store = new Map<string, KeyObject>([
    ["a", k1.publicKey],
    ["b", k1.publicKey],
    ["c", k1.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 10,
    maxEntries: 2,
    now: () => t,
  });
  memoized("a"); // expires at 1010
  t = 1_001;
  memoized("b"); // expires at 1011
  t = 1_009;
  memoized("a"); // hit: a is now MRU, but still expires at 1010
  assert.equal(calls, 2);
  t = 1_010; // a expired, b still live but is the LRU entry
  memoized("c"); // must reclaim expired a, not evict live b
  assert.equal(calls, 3);
  memoized("b");
  assert.equal(calls, 3); // b survived
  memoized("c");
  assert.equal(calls, 3);
  memoized("a");
  assert.equal(calls, 4); // a was reclaimed
});

test("memoizeKeyResolver: a hit does not extend the entry TTL", () => {
  let t = 2_000;
  const { resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { ttlSec: 10, now: () => t });
  memoized("merchant-key-1");
  assert.equal(calls(), 1);
  t = 2_009;
  memoized("merchant-key-1"); // hit just before expiry
  assert.equal(calls(), 1);
  t = 2_010; // original expiry, despite the hit at 2009
  memoized("merchant-key-1");
  assert.equal(calls(), 2);
});

test("memoizeKeyResolver: invalid maxEntries throws a configuration error", () => {
  const { resolver, calls } = countingStore();
  for (const bad of [0, -1, 1.5, NaN, Infinity]) {
    assert.throws(
      () => memoizeKeyResolver(resolver, { maxEntries: bad }),
      /`maxEntries` must be a positive integer/,
    );
  }
  // Boundary: 1 is valid and holds exactly one entry.
  const before = calls();
  const single = memoizeKeyResolver(resolver, {
    maxEntries: 1,
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  single("merchant-key-1");
  single("merchant-key-2");
  single("merchant-key-1"); // evicted by merchant-key-2, re-resolved
  assert.equal(calls(), before + 3);
});

test("memoizeKeyResolver: default maxEntries is 10000", () => {
  const { k1 } = countingStore();
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return id.startsWith("k") ? k1.publicKey : undefined;
  };
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  for (let i = 0; i < 10_001; i++) memoized(`k${i}`);
  assert.equal(calls, 10_001);
  memoized("k10000"); // newest entry retained
  assert.equal(calls, 10_001);
  memoized("k0"); // oldest entry evicted by the 10001st insert
  assert.equal(calls, 10_002);
});
