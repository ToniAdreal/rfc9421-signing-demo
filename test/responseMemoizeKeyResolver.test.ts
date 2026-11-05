import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  memoizeKeyResolver,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #897: `verifyResponse` inherits `VerifyOptions.keyResolver`
// from `verifyRequest`, so a gateway callback verifier can wrap its
// resolver in `memoizeKeyResolver` — but no response-side test ever
// proved the cache survives the response path. That matters because
// `verifyResponse` rebuilds a fresh internal RequestLike on every
// call: if the resolver were (wrongly) captured per-request-object
// instead of forwarded through the options, the cache would silently
// miss on every response and hammer the keystore once per callback.
// These tests pin the response side directly: the memoized resolver
// passed via `VerifyResponseOptions.keyResolver` is consulted once
// per keyid, per TTL window, exactly as on the request side
// (test/memoizeKeyResolver.test.ts).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

/** Two rotating gateway key pairs behind a `keyid`→key map. */
function countingStore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["gateway-key-1", k1.publicKey],
    ["gateway-key-2", k2.publicKey],
  ]);
  let calls = 0;
  const resolver = (id: string): KeyObject | undefined => {
    calls++;
    return store.get(id);
  };
  return { k1, k2, store, resolver, calls: () => calls };
}

function signAs(
  keyId: string | undefined,
  privateKey: KeyObject,
  overrides: Partial<HttpResponseLike> = {},
): SignedHttpResponse {
  return signResponse(response(overrides), {
    ...(keyId !== undefined ? { keyId } : {}),
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

test("response memoizeKeyResolver: same keyid verified twice -> one underlying call", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("gateway-key-1", k1.privateKey);
  for (let i = 0; i < 2; i++) {
    const result = verifyResponse(signed, { keyResolver: memoized, now: NOW });
    assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
    assert.equal(result.keyId, "gateway-key-1");
  }
  assert.equal(calls(), 1);
});

test("response memoizeKeyResolver: different keyids have independent cache entries", () => {
  const { k1, k2, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const s1 = signAs("gateway-key-1", k1.privateKey);
  const s2 = signAs("gateway-key-2", k2.privateKey);
  assert.equal(
    verifyResponse(s1, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(
    verifyResponse(s2, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 2);
  // A second round for both keyids is fully cached.
  assert.equal(
    verifyResponse(s1, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(
    verifyResponse(s2, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 2);
});

test("response memoizeKeyResolver: a throwing resolver is not cached, the retry re-invokes it", () => {
  const { k1, store } = countingStore();
  let throwCalls = 0;
  let throwOnce = true;
  const flaky = (id: string): KeyObject | undefined => {
    throwCalls++;
    if (throwOnce) {
      throwOnce = false;
      throw new Error("store is down");
    }
    return store.get(id);
  };
  const memoized = memoizeKeyResolver(flaky, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("gateway-key-1", k1.privateKey);
  const failed = verifyResponse(signed, { keyResolver: memoized, now: NOW });
  assert.equal(failed.ok, false);
  assert.equal(failed.code, "VERIFICATION_ERROR");
  assert.match(failed.reason ?? "", /key resolver threw/);
  // The failure was not cached: the retry consults the store again
  // and now verifies, instead of replaying the stale error.
  const retried = verifyResponse(signed, { keyResolver: memoized, now: NOW });
  assert.equal(retried.ok, true, `expected ok, got ${JSON.stringify(retried)}`);
  assert.equal(throwCalls, 2);
});

test("response memoizeKeyResolver: unknown keyid (undefined) is never cached", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  // Signed with a real key but claiming a keyid the store does not know.
  const signed = signAs("ghost-key", k1.privateKey);
  for (let i = 0; i < 2; i++) {
    const result = verifyResponse(signed, { keyResolver: memoized, now: NOW });
    assert.equal(result.ok, false);
    assert.equal(result.code, "KEY_RESOLUTION_FAILED");
  }
  // Not cached: the store is consulted again so a rotated-in keyid is
  // discoverable on the very next callback verify.
  assert.equal(calls(), 2);
});

test("response memoizeKeyResolver: TTL expiry re-invokes the underlying resolver", () => {
  let t = 1_700_000_000;
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { ttlSec: 10, now: () => t });
  const signed = signAs("gateway-key-1", k1.privateKey);
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_009; // still within TTL
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_010; // exactly at TTL boundary: expired
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 2);
});

test("response memoizeKeyResolver: a cache hit does not extend the TTL", () => {
  let t = 1_700_000_000;
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, { ttlSec: 10, now: () => t });
  const signed = signAs("gateway-key-1", k1.privateKey);
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_009; // hit: refreshes recency only, not expiry
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 1);
  t = 1_700_000_010; // original expiry, not hit + TTL
  assert.equal(
    verifyResponse(signed, { keyResolver: memoized, now: NOW }).ok,
    true,
  );
  assert.equal(calls(), 2);
});

test("response memoizeKeyResolver: cache-hit result matches the direct resolver result", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("gateway-key-1", k1.privateKey);
  const direct = verifyResponse(signed, { keyResolver: resolver, now: NOW });
  assert.equal(direct.ok, true);
  // The direct verify above cost one call; the memoized wrapper has
  // its own cache, so its first verify costs one more, its second none.
  const first = verifyResponse(signed, { keyResolver: memoized, now: NOW });
  const second = verifyResponse(signed, { keyResolver: memoized, now: NOW });
  assert.equal(first.ok, true);
  assert.equal(second.ok, true);
  assert.equal(first.keyId, direct.keyId);
  assert.equal(first.alg, direct.alg);
  assert.deepEqual(first.coveredComponents, direct.coveredComponents);
  assert.deepEqual(second.coveredComponents, direct.coveredComponents);
  assert.equal(calls(), 2);
});

test("response memoizeKeyResolver: body-less response (@status only) is cached the same way", () => {
  const { k1, resolver, calls } = countingStore();
  const memoized = memoizeKeyResolver(resolver, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("gateway-key-1", k1.privateKey, { body: undefined });
  for (let i = 0; i < 2; i++) {
    const result = verifyResponse(signed, { keyResolver: memoized, now: NOW });
    assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
    assert.deepEqual(result.coveredComponents, ["@status"]);
  }
  assert.equal(calls(), 1);
});
