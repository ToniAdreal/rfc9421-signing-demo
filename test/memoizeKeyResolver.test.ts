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
