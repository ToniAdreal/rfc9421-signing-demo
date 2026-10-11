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

function docFor(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  kid = "ed-key-1",
) {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

/** A manually released gate: fetches park on it until `release()`. */
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

/**
 * Fetch stub with a call counter, an optional gate the test controls,
 * and a failure switch (same shape as jwksSingleFlight.test.ts).
 */
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

test("stats: a fresh store starts at zero", () => {
  const { fetchImpl } = controlledFetch(() => ({}));
  const store = new JwksKeyStore(URL, { fetchImpl });
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
});

test("stats: mixed refresh/resolve sequence is counted accurately", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });

  // Misses before any refresh (empty snapshot) still count as misses.
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 1,
  });

  await store.refresh(); // success
  assert.ok(store.resolve("ed-key-1")); // hit
  assert.ok(store.resolve("ed-key-1")); // hit
  assert.equal(store.resolve("unknown-kid"), undefined); // miss
  // An invalid keyid returns undefined and counts as a miss, so
  // hits + misses always equals the number of resolve() calls.
  assert.equal(store.resolve(""), undefined); // miss

  state.fail = true;
  await assert.rejects(store.refresh(), /HTTP 500/); // failure
  // The old snapshot still serves after the failure.
  assert.ok(store.resolve("ed-key-1")); // hit

  assert.equal(state.calls, 2);
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 1,
    hits: 3,
    misses: 3,
  });
});

test("stats: single-flight concurrent refresh counts once (success)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const g = gate();
  state.gate = g.promise;
  const store = new JwksKeyStore(URL, { fetchImpl });

  const pending = [store.refresh(), store.refresh(), store.refresh()];
  g.release();
  await Promise.all(pending);

  assert.equal(state.calls, 1);
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });

  // A settled refresh is not reused: the next call fetches (and counts) again.
  await store.refresh();
  assert.equal(state.calls, 2);
  assert.equal(store.stats().refreshes, 2);
});

test("stats: single-flight concurrent failure counts once, all waiters share the error", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh(); // one success first, so an old key exists

  const g = gate();
  state.gate = g.promise;
  state.fail = true;
  const pending = [store.refresh(), store.refresh(), store.refresh()];
  g.release();
  const settled = await Promise.allSettled(pending);
  assert.ok(settled.every((s) => s.status === "rejected"));
  const reasons = settled.map((s) =>
    s.status === "rejected" ? s.reason : null,
  );
  assert.ok(reasons[0] instanceof Error);
  assert.equal(reasons[1], reasons[0]); // same error object for every waiter
  assert.equal(reasons[2], reasons[0]);

  assert.equal(state.calls, 2); // 1 success + 1 merged failure
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 1,
    hits: 0,
    misses: 0,
  });
  // The failed refresh left the old key resolvable.
  assert.ok(store.resolve("ed-key-1"));
  assert.equal(store.stats().hits, 1);
});

test("stats: refreshIfStale counts only actual fetches", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl, ttlSec: 300 });

  assert.equal(await store.refreshIfStale(), true); // never refreshed -> stale -> fetch
  assert.equal(await store.refreshIfStale(), false); // fresh -> no fetch, no count
  assert.equal(state.calls, 1);
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
});

test("stats: the returned snapshot is detached from the counters", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.ok(store.resolve("ed-key-1"));

  const snapshot = store.stats();
  snapshot.refreshes = 999;
  snapshot.hits = 999;

  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 1,
    misses: 0,
  });
});

test("stats: snapshot export/restore does not reset the counters", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.ok(store.resolve("ed-key-1")); // hit
  assert.equal(store.resolve("nope"), undefined); // miss

  const exported = store.exportSnapshot();
  store.restoreSnapshot(exported); // instance restore: counters keep running
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 1,
    misses: 1,
  });
  assert.ok(store.resolve("ed-key-1"));
  assert.equal(store.stats().hits, 2);

  // The static restore path builds a NEW store, which starts at zero
  // like any fresh store; its own resolves then count from there.
  const restored = JwksKeyStore.restore(exported, URL, { fetchImpl });
  assert.deepEqual(restored.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
  assert.ok(restored.resolve("ed-key-1"));
  assert.equal(restored.stats().hits, 1);
});

test("stats: verifyRequest through store.resolve counts hits and misses", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();

  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "ed-key-1", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const ok = verifyRequest(signed, { keyResolver: store.resolve });
  assert.equal(ok.ok, true);
  assert.equal(store.stats().hits, 1);
  assert.equal(store.stats().misses, 0);

  const signedUnknown = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "retired-kid", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const failed = verifyRequest(signedUnknown, { keyResolver: store.resolve });
  assert.equal(failed.ok, false);
  if (!failed.ok) assert.equal(failed.code, "KEY_RESOLUTION_FAILED");
  assert.equal(store.stats().hits, 1);
  assert.equal(store.stats().misses, 1);
});
