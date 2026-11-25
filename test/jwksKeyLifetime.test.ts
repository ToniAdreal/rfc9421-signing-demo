import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportSymmetricKeyJwk,
  generateEd25519KeyPair,
  generateHmacSecret,
  JwksKeyStore,
  secretKey,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type SignedHttpRequest,
} from "../src/index.js";

// Pinned clock (unix seconds): every lifetime judgement in this file
// is made against this one instant, so the exp/nbf boundaries below
// are exact, not wall-clock races.
const NOW = 1700000000;
const CREATED = 1700000000;

function freshReq() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {} as Record<string, string>,
    body: '{"amount":100}',
  };
}

function signAs(
  keyId: string,
  alg: "ed25519" | "hmac-sha256",
  key: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), {
    keyId,
    alg,
    key,
    created: CREATED,
  });
}

/** A fetch stub that serves a fixed JSON body without any network. */
function stubFetch(body: unknown, status = 200): JwksFetchImpl {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

function storeFor(doc: unknown, now: () => number = () => NOW) {
  return new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
    now,
  });
}

const { publicKey: edPublic, privateKey: edPrivate } =
  generateEd25519KeyPair();
const edJwk = { ...exportPublicKeyJwk(edPublic), kid: "ed-key-1" };
const hmacSecret = secretKey(generateHmacSecret());
const hmacJwk = { ...exportSymmetricKeyJwk(hmacSecret), kid: "hmac-key-1" };

/**
 * Refresh `goodDoc` into a fresh store, then assert that refreshing
 * `badDoc` rejects with a message matching `pattern` and leaves size,
 * lastRefreshedAt, the resolved key and the refresh-failure counter's
 * delta exactly as they were.
 */
async function assertBadRefreshLeavesSnapshot(
  goodDoc: unknown,
  badDoc: unknown,
  kid: string,
  expectedKey: KeyObject,
  pattern: RegExp,
): Promise<void> {
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(goodDoc),
    now: () => NOW,
  });
  await store.refresh();
  const sizeBefore = store.size;
  const refreshedAtBefore = store.lastRefreshedAt;
  assert.ok(refreshedAtBefore !== null);
  assert.deepEqual(store.resolve(kid), expectedKey);
  // A store cannot swap its fetchImpl, so seed a second store with
  // the good snapshot via restoreSnapshot, then refresh it with the
  // bad document: the failure must leave the restored snapshot intact.
  const badStore = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(badDoc),
    now: () => NOW,
  });
  badStore.restoreSnapshot(store.exportSnapshot());
  await assert.rejects(badStore.refresh(), pattern);
  assert.equal(badStore.size, sizeBefore);
  assert.equal(badStore.lastRefreshedAt, refreshedAtBefore);
  assert.deepEqual(badStore.resolve(kid), expectedKey);
  assert.equal(badStore.stats().refreshFailures, 1);
}

test("expired key: refresh rejects with a named error, old snapshot untouched", async () => {
  const goodDoc = { keys: [edJwk] };
  const badDoc = { keys: [{ ...edJwk, exp: NOW - 1 }] };
  await assertBadRefreshLeavesSnapshot(
    goodDoc,
    badDoc,
    "ed-key-1",
    edPublic,
    /entry for kid "ed-key-1": key expired at 1699999999 \(now 1700000000\)/,
  );
});

test("not-yet-valid key: refresh rejects with a named error, old snapshot untouched", async () => {
  const goodDoc = { keys: [edJwk] };
  const badDoc = { keys: [{ ...edJwk, nbf: NOW + 3600 }] };
  await assertBadRefreshLeavesSnapshot(
    goodDoc,
    badDoc,
    "ed-key-1",
    edPublic,
    /entry for kid "ed-key-1": key not yet valid until 1700003600 \(now 1700000000\)/,
  );
});

test("boundary: exp exactly now is already expired", async () => {
  const store = storeFor({ keys: [{ ...edJwk, exp: NOW }] });
  await assert.rejects(
    store.refresh(),
    /entry for kid "ed-key-1": key expired at 1700000000 \(now 1700000000\)/,
  );
  assert.equal(store.size, 0);
  assert.equal(store.resolve("ed-key-1"), undefined);
});

test("boundary: nbf exactly now is already valid, round-trip verifies", async () => {
  const store = storeFor({ keys: [{ ...edJwk, nbf: NOW }] });
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("ed-key-1", "ed25519", edPrivate);
  const result = verifyRequest(signed, { keyResolver: store.resolve });
  assert.equal(result.ok, true);
});

test("key inside its lifetime window verifies end to end", async () => {
  const store = storeFor({
    keys: [{ ...edJwk, exp: NOW + 3600, nbf: NOW - 3600 }],
  });
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("ed-key-1", "ed25519", edPrivate);
  const result = verifyRequest(signed, { keyResolver: store.resolve });
  assert.equal(result.ok, true);
});

test("malformed exp (string) rejects with a named error", async () => {
  const store = storeFor({
    keys: [{ ...edJwk, exp: "1700000000" }],
  });
  await assert.rejects(
    store.refresh(),
    /entry for kid "ed-key-1": "exp" must be a finite number of seconds since the epoch when present, got string/,
  );
  assert.equal(store.size, 0);
});

test("malformed nbf (object) rejects with a named error", async () => {
  const store = storeFor({ keys: [{ ...edJwk, nbf: { t: NOW } }] });
  await assert.rejects(
    store.refresh(),
    /entry for kid "ed-key-1": "nbf" must be a finite number of seconds since the epoch when present, got object/,
  );
  assert.equal(store.size, 0);
});

test("expired key among valid siblings fails the whole refresh", async () => {
  const store = storeFor({
    keys: [
      { ...hmacJwk, exp: NOW + 3600 },
      { ...edJwk, kid: "ed-expired", exp: NOW - 60 },
    ],
  });
  await assert.rejects(
    store.refresh(),
    /entry for kid "ed-expired": key expired at 1699999940 \(now 1700000000\)/,
  );
  // Fail-closed: the valid sibling is NOT installed either.
  assert.equal(store.size, 0);
  assert.equal(store.resolve("hmac-key-1"), undefined);
  assert.equal(store.resolve("ed-expired"), undefined);
});

test("expired HMAC (oct) key rejects the same way as an asymmetric key", async () => {
  const store = storeFor({ keys: [{ ...hmacJwk, exp: NOW - 1 }] });
  await assert.rejects(
    store.refresh(),
    /entry for kid "hmac-key-1": key expired at 1699999999 \(now 1700000000\)/,
  );
  assert.equal(store.size, 0);
});

test("key with no exp/nbf is unaffected (positive control)", async () => {
  const store = storeFor({ keys: [edJwk, hmacJwk] });
  await store.refresh();
  assert.equal(store.size, 2);
  const signed = signAs("ed-key-1", "ed25519", edPrivate);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve }).ok,
    true,
  );
  const hmacSigned = signAs("hmac-key-1", "hmac-sha256", hmacSecret);
  assert.equal(
    verifyRequest(hmacSigned, { keyResolver: store.resolve }).ok,
    true,
  );
});

test("lifetime is judged against the store clock, not the wall clock", async () => {
  // The key expired an hour ago by the wall clock, but the store's
  // injected clock is pinned before the expiry, so it still verifies.
  const store = storeFor(
    { keys: [{ ...edJwk, exp: NOW - 60 }] },
    () => NOW - 3600,
  );
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("ed-key-1", "ed25519", edPrivate);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve }).ok,
    true,
  );
});
