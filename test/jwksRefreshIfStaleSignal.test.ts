import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";
const ABORTED_MSG = "JwksKeyStore: JWKS refresh aborted";

function docFor(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  kid = "ed-key-1",
) {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

function okResponse(body: unknown) {
  return { ok: true, status: 200, json: async () => body };
}

/**
 * Swap in a stubbed `globalThis.fetch` (the default fetch the store
 * uses) and hand back the seen (url, init) calls plus a restore
 * function. Tests always restore in a finally block so the real
 * fetch is never left patched.
 */
function stubGlobalFetch(
  impl: (url: string, init?: RequestInit) => Promise<unknown>,
) {
  const original = globalThis.fetch;
  const seen: Array<{ url: string; init?: RequestInit | undefined }> = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push({ url, init });
    return impl(url, init);
  }) as typeof globalThis.fetch;
  return {
    seen,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

/** A stub fetch that never resolves on its own — like a hung JWKS
 * endpoint — but rejects with a DOMException AbortError when its
 * abort signal fires, exactly like Node's undici does. */
function hangingFetch() {
  return (_url: string, init?: RequestInit) =>
    new Promise<never>((_resolve, reject) => {
      const signal = init?.signal;
      const onAbort = () =>
        reject(new DOMException("This operation was aborted", "AbortError"));
      if (signal?.aborted) {
        onAbort();
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
    });
}

const sleep = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

function emptyStats() {
  return {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
    staleResolutions: 0,
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

test("jwks refreshIfStale({ signal }): a pre-aborted signal returns false and fetches nothing on a never-refreshed store", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  const controller = new AbortController();
  controller.abort();
  // Unlike refresh(), which throws on a pre-aborted signal, the
  // convenience wrapper returns: a cancelled caller asked for no
  // refresh, and false reports that none happened.
  assert.equal(await store.refreshIfStale({ signal: controller.signal }), false);
  assert.equal(state.calls, 0);
  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.deepEqual(store.stats(), emptyStats());
});

test("jwks refreshIfStale({ signal }): a pre-aborted signal returns false and leaves a seeded stale snapshot, freshness, and stats untouched", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  assert.equal(state.calls, 1);
  const refreshedAt = store.lastRefreshedAt;
  assert.notEqual(refreshedAt, null);

  t = 1_700_000_500; // stale
  assert.equal(store.isStale(), true);
  state.calls = 0;
  const controller = new AbortController();
  controller.abort();
  assert.equal(await store.refreshIfStale({ signal: controller.signal }), false);
  // No refresh was attempted: no fetch, no snapshot or freshness
  // change, and not even counted as a failure.
  assert.equal(state.calls, 0);
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, refreshedAt);
  assert.ok(store.resolve("ed-key-1")); // old snapshot still served
  assert.equal(store.isStale(), true);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshes: 1,
    hits: 1,
  });
});

test("jwks refreshIfStale({ signal }): a pre-aborted signal returns false without fetching on a fresh snapshot", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  state.calls = 0;

  t = 1_700_000_060; // well within the TTL: fresh
  const controller = new AbortController();
  controller.abort();
  assert.equal(await store.refreshIfStale({ signal: controller.signal }), false);
  assert.equal(state.calls, 0);
  assert.deepEqual(store.stats(), { ...emptyStats(), refreshes: 1 });
});

test("jwks refreshIfStale({ signal }): a non-AbortSignal signal is a configuration error and fetches nothing", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  for (const bad of [
    "signal",
    42,
    {},
    null,
    [],
    true,
  ] as unknown as AbortSignal[]) {
    // A bad signal is a fail-fast configuration error, thrown before
    // any fetch is attempted — the same check refresh() applies.
    await assert.rejects(
      () => store.refreshIfStale({ signal: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          `JwksKeyStore: refresh signal must be an AbortSignal, got ${String(bad)}`,
      `expected a configuration error for signal=${String(bad)}`,
    );
  }
  assert.equal(state.calls, 0);
  assert.deepEqual(store.stats(), emptyStats());
});

test("jwks refreshIfStale({ signal }): a non-object options value is a configuration error", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl } = countingFetch(docFor(publicKey));
  const store = new JwksKeyStore(URL, { fetchImpl });
  for (const bad of [null, "refreshIfStale", 42] as unknown as Parameters<
    JwksKeyStore["refreshIfStale"]
  >[0][]) {
    await assert.rejects(
      () => store.refreshIfStale(bad),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          `JwksKeyStore: refresh options must be an object, got ${String(bad)}`,
      `expected a configuration error for opts=${String(bad)}`,
    );
  }
  // An empty options object is the same as no options at all.
  assert.equal(await store.refreshIfStale({}), true);
  assert.equal(store.size, 1);
});

test("jwks refreshIfStale({ signal }): aborting mid-fetch rejects with the aborted error and leaves the snapshot untouched", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    let t = 1_700_000_000;
    const store = new JwksKeyStore(URL, { ttlSec: 120, now: () => t });
    await store.refresh(); // seeds a good snapshot
    assert.equal(store.size, 1);
    const refreshedAt = store.lastRefreshedAt;

    t = 1_700_000_500; // stale
    stub.restore();
    const hang = stubGlobalFetch(hangingFetch());
    try {
      const controller = new AbortController();
      const pending = store.refreshIfStale({ signal: controller.signal });
      // The endpoint never answers on its own: the only way this
      // settles is the caller signal cancelling the fetch.
      setTimeout(() => controller.abort(), 10);
      await assert.rejects(
        () => pending,
        (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
        "expected the aborted error, not a timeout (no timeout is configured)",
      );
      // The default fetch really was invoked with an AbortSignal.
      assert.equal(hang.seen.length, 1);
      assert.ok(hang.seen[0].init?.signal instanceof AbortSignal);
      // Fail-closed: keys and the freshness timestamp are exactly as before.
      assert.equal(store.size, 1);
      assert.equal(store.lastRefreshedAt, refreshedAt);
      assert.ok(store.resolve("ed-key-1")); // old snapshot still served
      assert.equal(store.isStale(), true);
      assert.deepEqual(store.stats(), {
        ...emptyStats(),
        refreshes: 1,
        refreshFailures: 1,
        hits: 1,
      });
    } finally {
      hang.restore();
    }
  } finally {
    stub.restore();
  }
});

test("jwks refreshIfStale({ signal }): abort during the retry backoff starts no new attempt", async () => {
  const fetchCalls: string[] = [];
  const sleepDelays: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl: async (url: string) => {
      fetchCalls.push(url);
      throw new Error("network down");
    },
    fetchRetries: 1,
    // A sleep that never resolves on its own: the only way out of
    // the backoff is the caller signal.
    sleepImpl: (ms: number) => {
      sleepDelays.push(ms);
      return new Promise<void>(() => {});
    },
  });
  const controller = new AbortController();
  const pending = store.refreshIfStale({ signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(
    () => pending,
    (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
  );
  assert.equal(fetchCalls.length, 1);
  assert.deepEqual(sleepDelays, [1000]);
  assert.equal(store.size, 0);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshFailures: 1,
  });
});

test("jwks refreshIfStale({ signal }): a live signal leaves the normal path untouched", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, state } = countingFetch(docFor(publicKey));
  let t = 1_700_000_000;
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    ttlSec: 120,
    now: () => t,
  });
  // Stale (never refreshed): a live signal refreshes and returns true.
  const first = new AbortController();
  assert.equal(await store.refreshIfStale({ signal: first.signal }), true);
  assert.equal(state.calls, 1);
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1"));

  // Fresh: a live signal still returns false without fetching.
  t = 1_700_000_060;
  const second = new AbortController();
  assert.equal(await store.refreshIfStale({ signal: second.signal }), false);
  assert.equal(state.calls, 1);

  // Stale again: refreshes once more and returns true.
  t = 1_700_000_500;
  const third = new AbortController();
  assert.equal(await store.refreshIfStale({ signal: third.signal }), true);
  assert.equal(state.calls, 2);
  assert.equal(store.lastRefreshedAt, 1_700_000_500);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshes: 2,
    hits: 1,
  });
});

test("jwks refreshIfStale({ signal }): a joiner's signal does not cancel the shared in-flight refresh", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let fetchCalls = 0;
  const stub = stubGlobalFetch(async () => {
    fetchCalls++;
    await sleep(80);
    return okResponse(docFor(publicKey));
  });
  try {
    const store = new JwksKeyStore(URL);
    const controller = new AbortController();
    const first = store.refreshIfStale();
    // Joins the in-flight refresh: its own signal is ignored, so
    // cancelling it must not cancel the other caller's refresh.
    const second = store.refreshIfStale({ signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    assert.equal(await first, true);
    assert.equal(await second, true);
    assert.equal(fetchCalls, 1);
    assert.equal(store.size, 1);
    assert.ok(store.resolve("ed-key-1"));
    assert.deepEqual(store.stats(), {
      ...emptyStats(),
      refreshes: 1,
      hits: 1,
    });
  } finally {
    stub.restore();
  }
});
