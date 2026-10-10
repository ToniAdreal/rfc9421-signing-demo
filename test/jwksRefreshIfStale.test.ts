import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
} from "../src/index.js";

function docFor(publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"]) {
  return {
    keys: [{ ...exportPublicKeyJwk(publicKey), kid: "ed-key-1" }],
  };
}

/** Counting fetch stub serving a fixed JWKS document. */
function countingFetch(body: unknown) {
  const state = { calls: 0 };
  const fetchImpl: JwksFetchImpl = async () => {
    state.calls++;
    return { ok: true, status: 200, json: async () => body };
  };
  return { fetchImpl, state };
}

test("refreshIfStale: fresh snapshot returns false and never calls fetchImpl", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  assert.equal(state.calls, 1);

  state.calls = 0;
  t = 1_700_000_060; // well within the TTL
  assert.equal(await store.refreshIfStale(), false);
  assert.equal(state.calls, 0);
});

test("refreshIfStale: stale snapshot fetches once and returns true", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  state.calls = 0;

  t = 1_700_000_500;
  assert.equal(store.isStale(), true);
  assert.equal(await store.refreshIfStale(), true);
  assert.equal(state.calls, 1);
  assert.equal(store.isStale(), false);
  assert.equal(store.lastRefreshedAt, 1_700_000_500);

  // Immediately afterwards it is fresh again: no second fetch.
  assert.equal(await store.refreshIfStale(), false);
  assert.equal(state.calls, 1);
});

test("refreshIfStale: never-refreshed store fetches and returns true", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    now: () => 1_700_000_000,
  });
  assert.equal(store.lastRefreshedAt, null);
  assert.equal(await store.refreshIfStale(), true);
  assert.equal(state.calls, 1);
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("refreshIfStale: a failed refresh throws and the old snapshot still resolves", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let fail = false;
  let calls = 0;
  const fetchImpl: JwksFetchImpl = async () => {
    calls++;
    if (fail) return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => docFor(publicKey) };
  };
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 60,
    now: () => t,
  });
  await store.refresh();
  const before = store.resolve("ed-key-1");
  assert.ok(before !== undefined);
  const refreshedAt = store.lastRefreshedAt;

  t = 1_700_000_120; // stale
  fail = true;
  await assert.rejects(() => store.refreshIfStale(), /HTTP 500/);
  assert.equal(calls, 2);
  // Old snapshot and timestamp untouched; store is still stale so a
  // later call retries rather than believing the failure refreshed it.
  assert.equal(store.resolve("ed-key-1"), before);
  assert.equal(store.lastRefreshedAt, refreshedAt);
  assert.equal(store.isStale(), true);
});

test("refreshIfStale: TTL boundary uses the same >= semantics as isStale()", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  state.calls = 0;

  t = 1_700_000_119; // one second before the boundary: still fresh
  assert.equal(await store.refreshIfStale(), false);
  assert.equal(state.calls, 0);

  t = 1_700_000_120; // exactly at the boundary: stale (>=), so it fetches
  assert.equal(await store.refreshIfStale(), true);
  assert.equal(state.calls, 1);
  assert.equal(store.lastRefreshedAt, 1_700_000_120);
});
