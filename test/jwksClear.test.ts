import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function docFor(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  kid = "ed-key-1",
) {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

/** Fetch stub with a call counter, an optional gate, and a failure switch. */
function controlledFetch(getBody: () => unknown) {
  const state = {
    calls: 0,
    fail: false,
    gate: null as Promise<void> | null,
  };
  const fetchImpl: JwksFetchImpl = async () => {
    state.calls++;
    if (state.gate !== null) await state.gate;
    if (state.fail)
      return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => getBody() };
  };
  return { fetchImpl, state };
}

/** A manually released gate: fetches park on it until `release()`. */
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

test("JwksKeyStore.clear: drops the snapshot and the freshness timestamp", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.equal(store.isStale(), false);
  assert.ok(store.lastRefreshedAt !== null);
  assert.ok(store.resolve("ed-key-1"));

  store.clear();

  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.equal(store.isStale(), true);
  assert.equal(store.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore.clear: a previously verifiable key fails closed afterwards", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  const signed = signRequest(freshReq(), {
    keyId: "ed-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );

  store.clear();

  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
});

test("JwksKeyStore.clear: resets all four stats counters to zero", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh(); // refreshes: 1
  assert.ok(store.resolve("ed-key-1")); // hit
  assert.equal(store.resolve("unknown-kid"), undefined); // miss
  state.fail = true;
  await assert.rejects(store.refresh(), /HTTP 500/); // refreshFailures: 1
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 1,
    hits: 1,
    misses: 1,
  });

  store.clear();

  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
});

test("JwksKeyStore.clear: a refresh afterwards re-fetches and restores service", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  store.clear();
  assert.equal(state.calls, 1);

  await store.refresh();

  assert.equal(state.calls, 2);
  assert.equal(store.size, 1);
  assert.equal(store.isStale(), false);
  assert.ok(store.resolve("ed-key-1"));
  // Stats count from the clear: only the post-clear refresh is counted.
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 1,
    misses: 0,
  });
});

test("JwksKeyStore.clear: a snapshot can still be restored into the cleared store", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  let now = CREATED;
  const store = new JwksKeyStore(URL, { fetchImpl, now: () => now });
  await store.refresh();
  const snapshot = store.exportSnapshot();
  assert.equal(snapshot.fetchedAtSec, CREATED);

  store.clear();
  assert.equal(store.size, 0);

  store.restoreSnapshot(snapshot);
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, CREATED);
  assert.ok(store.resolve("ed-key-1"));
  // Staleness still counts from the snapshot's original fetch time,
  // not from the restore: fresh now, stale at the TTL boundary.
  assert.equal(store.isStale(), false);
  now = CREATED + 300;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore.clear: clearing a never-refreshed store does not throw", () => {
  const { fetchImpl } = controlledFetch(() => ({}));
  const store = new JwksKeyStore(URL, { fetchImpl });

  assert.doesNotThrow(() => store.clear());

  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.equal(store.isStale(), true);
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
});

test("JwksKeyStore.clear: exportSnapshot afterwards throws like a never-refreshed store", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.doesNotThrow(() => store.exportSnapshot());

  store.clear();

  assert.throws(
    () => store.exportSnapshot(),
    /cannot export a snapshot before a successful refresh\(\)/,
  );
});

test("JwksKeyStore.clear: resolves after the clear count as misses from zero", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.ok(store.resolve("ed-key-1")); // hit before the clear
  store.clear();

  assert.equal(store.resolve("ed-key-1"), undefined);

  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 1,
  });
});

test("JwksKeyStore.clear: an in-flight refresh still installs its snapshot when it settles", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const g = gate();
  state.gate = g.promise;
  const store = new JwksKeyStore(URL, { fetchImpl });
  const pending = store.refresh();
  // The fetch is parked on the gate: nothing has landed yet.
  store.clear();
  assert.equal(store.size, 0);
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });

  g.release();
  await pending;

  // Documented limit: clear() does not cancel an in-flight refresh —
  // the single-flight fetch keeps its contract and installs its
  // snapshot when it settles. Retire again after it lands if the
  // keys must stay retired.
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1"));
  assert.equal(store.stats().refreshes, 1);
});
