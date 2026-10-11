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
 * and a failure switch. `getBody` is re-read per fetch so tests can
 * rotate the served document mid-flight.
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

test("single-flight: 3 concurrent refresh() calls share one fetch", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const g = gate();
  state.gate = g.promise;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });

  const pending = [store.refresh(), store.refresh(), store.refresh()];
  // All three calls are in flight, but only one fetch was started.
  assert.equal(state.calls, 1);
  g.release();
  await Promise.all(pending);

  assert.equal(state.calls, 1);
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("single-flight: concurrent stale refreshIfStale() calls share one fetch and all return true", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  assert.equal(state.calls, 1);

  t = 1_700_000_500; // stale
  const g = gate();
  state.gate = g.promise;
  const pending = [
    store.refreshIfStale(),
    store.refreshIfStale(),
    store.refreshIfStale(),
  ];
  assert.equal(state.calls, 2); // one new fetch for all three callers
  g.release();
  assert.deepEqual(await Promise.all(pending), [true, true, true]);
  assert.equal(state.calls, 2);
  assert.equal(store.isStale(), false);
});

test("single-flight: concurrent refresh() and refreshIfStale() join the same flight", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();

  t = 1_700_000_500; // stale
  const g = gate();
  state.gate = g.promise;
  const pRefresh = store.refresh();
  const pIfStale = store.refreshIfStale();
  const pRefresh2 = store.refresh();
  assert.equal(state.calls, 2);
  g.release();
  await pRefresh;
  assert.equal(await pIfStale, true);
  await pRefresh2;
  assert.equal(state.calls, 2);
});

test("single-flight: a failed fetch gives every concurrent waiter the same error and preserves the old snapshot", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });
  await store.refresh();
  const before = store.resolve("ed-key-1");
  assert.ok(before !== undefined);
  const refreshedAt = store.lastRefreshedAt;

  const g = gate();
  state.gate = g.promise;
  state.fail = true;
  const pending = [store.refresh(), store.refresh(), store.refresh()];
  assert.equal(state.calls, 2); // initial + one shared failing fetch
  g.release();
  const settled = await Promise.allSettled(pending);

  assert.equal(state.calls, 2);
  for (const outcome of settled) assert.equal(outcome.status, "rejected");
  const reasons = settled.map((o) =>
    o.status === "rejected" ? o.reason : null,
  );
  // The very same error object reaches every waiter: there was only
  // one underlying refresh, so there is only one failure.
  assert.ok(reasons[0] instanceof Error);
  assert.match((reasons[0] as Error).message, /HTTP 500/);
  assert.equal(reasons[1], reasons[0]);
  assert.equal(reasons[2], reasons[0]);
  // Old snapshot and freshness timestamp untouched; old key verifies.
  assert.equal(store.resolve("ed-key-1"), before);
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, refreshedAt);
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "ed-key-1", alg: "ed25519", key: privateKey, created: CREATED },
  );
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
});

test("single-flight: a failure is not cached — the next refresh() retries and can succeed", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });
  state.fail = true;
  await assert.rejects(() => store.refresh(), /HTTP 500/);
  assert.equal(state.calls, 1);
  assert.equal(store.size, 0);

  state.fail = false;
  await store.refresh();
  assert.equal(state.calls, 2);
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("single-flight: two serial refresh() calls still fetch twice (only overlapping calls merge)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = controlledFetch(() => docFor(publicKey));
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });
  await store.refresh();
  await store.refresh();
  assert.equal(state.calls, 2);
  assert.equal(store.size, 1);
});

test("single-flight: resolve() serves the old complete snapshot while a refresh is in flight", async () => {
  const oldKeys = generateEd25519KeyPair();
  const newKeys = generateEd25519KeyPair();
  let doc: unknown = docFor(oldKeys.publicKey, "ed-key-1");
  const { fetchImpl, state } = controlledFetch(() => doc);
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });
  await store.refresh();
  const oldResolved = store.resolve("ed-key-1");
  assert.ok(oldResolved !== undefined);

  // Rotation starts but is parked at the gate: nothing may change yet.
  doc = docFor(newKeys.publicKey, "ed-key-2");
  const g = gate();
  state.gate = g.promise;
  const pending = store.refresh();
  assert.equal(state.calls, 2);
  assert.equal(store.resolve("ed-key-1"), oldResolved);
  assert.equal(store.resolve("ed-key-2"), undefined);
  assert.equal(store.size, 1);

  g.release();
  await pending;
  // After the flight lands, the swap is complete and atomic.
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.ok(store.resolve("ed-key-2") !== undefined);
  assert.equal(store.size, 1);
});
