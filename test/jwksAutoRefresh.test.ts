import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
  type JwksSetIntervalImpl,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";

/** One ed25519 key, the JWKS document a gateway would publish for it. */
function jwksDoc(): { keys: unknown[] } {
  const { publicKey } = generateEd25519KeyPair();
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid: "ed-key-1" }] };
}

/** A fetch stub that counts calls and serves a fixed JWKS document. */
function countingFetch(
  doc: unknown,
  calls: { count: number },
): JwksFetchImpl {
  return async () => {
    calls.count++;
    return { ok: true, status: 200, json: async () => doc };
  };
}

/** A fetch stub that always fails at the network layer. */
const failingFetch: JwksFetchImpl = async () => {
  throw new Error("boom");
};

/**
 * A stub interval implementation: records the interval, counts
 * `unref()` / `clear()` calls, and fires ticks only when the test
 * says so — so no test waits on real time. `fire()` after `clear()`
 * is a no-op, exactly like a cleared real timer.
 */
function stubTimer(): {
  state: {
    callback: (() => void) | null;
    ms: number | null;
    implCalls: number;
    unrefCalls: number;
    clearCalls: number;
    cleared: boolean;
    fires: number;
  };
  impl: JwksSetIntervalImpl;
  fire: () => void;
} {
  const state = {
    callback: null as (() => void) | null,
    ms: null as number | null,
    implCalls: 0,
    unrefCalls: 0,
    clearCalls: 0,
    cleared: false,
    fires: 0,
  };
  const impl: JwksSetIntervalImpl = (callback, ms) => {
    state.implCalls++;
    state.callback = callback;
    state.ms = ms;
    return {
      unref: () => {
        state.unrefCalls++;
      },
      clear: () => {
        state.clearCalls++;
        state.cleared = true;
      },
    };
  };
  return {
    state,
    impl,
    fire(): void {
      if (state.cleared) return;
      state.fires++;
      state.callback?.();
    },
  };
}

/** Let a fired tick's async refresh settle (the stub fetch resolves in a microtask). */
const flush = (): Promise<void> =>
  new Promise<void>((resolve) => setTimeout(resolve, 5));

test("JwksKeyStore.startAutoRefresh: illegal intervalMs values are rejected before any timer is created", () => {
  const bad: unknown[] = [0, -1, -100, Number.NaN, Infinity, "60000", undefined, null];
  for (const value of bad) {
    const timer = stubTimer();
    const store = new JwksKeyStore(URL, {
      fetchImpl: countingFetch(jwksDoc(), { count: 0 }),
    });
    assert.throws(
      () => store.startAutoRefresh(value as number, { setIntervalImpl: timer.impl }),
      /`intervalMs` must be a finite number > 0/,
    );
    assert.equal(timer.state.implCalls, 0, `no timer for intervalMs ${String(value)}`);
  }
});

test("JwksKeyStore.startAutoRefresh: illegal onError / setIntervalImpl are rejected", () => {
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), { count: 0 }) });
  const timer = stubTimer();
  assert.throws(
    () =>
      store.startAutoRefresh(60_000, {
        onError: "not a function" as unknown as (err: Error) => void,
        setIntervalImpl: timer.impl,
      }),
    /`onError` must be a function/,
  );
  assert.throws(
    () =>
      store.startAutoRefresh(60_000, {
        setIntervalImpl: 42 as unknown as JwksSetIntervalImpl,
      }),
    /`setIntervalImpl` must be a function/,
  );
  assert.equal(timer.state.implCalls, 0);
});

test("JwksKeyStore.startAutoRefresh: creates one timer with the given interval and unrefs it", () => {
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), { count: 0 }) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  assert.equal(typeof stop, "function");
  assert.equal(timer.state.implCalls, 1);
  assert.equal(timer.state.ms, 60_000);
  assert.equal(timer.state.unrefCalls, 1);
  stop();
});

test("JwksKeyStore.startAutoRefresh: a tick refreshes a stale store and counts in stats", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  try {
    assert.equal(store.isStale(), true);
    timer.fire();
    await flush();
    assert.equal(calls.count, 1);
    assert.equal(store.size, 1);
    assert.equal(store.isStale(), false);
    assert.equal(store.stats().refreshes, 1);
    assert.equal(store.stats().refreshFailures, 0);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: a tick while fresh fetches nothing", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  try {
    timer.fire();
    await flush();
    timer.fire();
    await flush();
    assert.equal(calls.count, 1);
    assert.equal(store.stats().refreshes, 1);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: a failing tick reports to onError and does not throw", async () => {
  const errors: Error[] = [];
  const store = new JwksKeyStore(URL, { fetchImpl: failingFetch });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, {
    onError: (err) => {
      errors.push(err);
    },
    setIntervalImpl: timer.impl,
  });
  try {
    timer.fire();
    await flush();
    assert.equal(errors.length, 1);
    assert.match(errors[0]?.message ?? "", /boom/);
    assert.equal(store.stats().refreshFailures, 1);
    assert.equal(store.stats().refreshes, 0);
    assert.equal(store.size, 0);
    // The store is still usable after a failed tick: a later good
    // fetch would succeed (here the endpoint stays down, so the
    // next tick fails the same way — the point is no uncaught throw).
    timer.fire();
    await flush();
    assert.equal(errors.length, 2);
    assert.equal(store.stats().refreshFailures, 2);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: a failing tick without onError is silently swallowed", async () => {
  const store = new JwksKeyStore(URL, { fetchImpl: failingFetch });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  try {
    timer.fire();
    await flush();
    assert.equal(store.stats().refreshFailures, 1);
    assert.equal(store.stats().refreshes, 0);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: an onError that itself throws is swallowed", async () => {
  let onErrorCalls = 0;
  const store = new JwksKeyStore(URL, { fetchImpl: failingFetch });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, {
    onError: () => {
      onErrorCalls++;
      throw new Error("onError itself broke");
    },
    setIntervalImpl: timer.impl,
  });
  try {
    timer.fire();
    await flush();
    assert.equal(onErrorCalls, 1);
    assert.equal(store.stats().refreshFailures, 1);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: stop() prevents further refreshes", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  timer.fire();
  await flush();
  assert.equal(calls.count, 1);
  stop();
  assert.equal(timer.state.clearCalls, 1);
  timer.fire();
  await flush();
  assert.equal(calls.count, 1);
  assert.equal(store.stats().refreshes, 1);
});

test("JwksKeyStore.startAutoRefresh: stop() is idempotent", () => {
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), { count: 0 }) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  stop();
  stop();
  assert.equal(timer.state.clearCalls, 1);
});

test("JwksKeyStore.startAutoRefresh: clear() stops auto-refresh", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  timer.fire();
  await flush();
  assert.equal(calls.count, 1);
  store.clear();
  assert.equal(timer.state.clearCalls, 1);
  assert.equal(store.stats().refreshes, 0);
  timer.fire();
  await flush();
  assert.equal(calls.count, 1);
  // stop() after clear() is a safe no-op and never clears a later timer.
  stop();
  assert.equal(timer.state.clearCalls, 1);
});

test("JwksKeyStore.startAutoRefresh: a second start while running throws, and the first keeps working", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  const timer = stubTimer();
  const stop = store.startAutoRefresh(60_000, { setIntervalImpl: timer.impl });
  try {
    assert.throws(
      () => store.startAutoRefresh(30_000, { setIntervalImpl: timer.impl }),
      /auto-refresh is already running/,
    );
    assert.equal(timer.state.implCalls, 1);
    timer.fire();
    await flush();
    assert.equal(calls.count, 1);
  } finally {
    stop();
  }
});

test("JwksKeyStore.startAutoRefresh: a real short interval refreshes on its own, and stop ends it", async () => {
  const calls = { count: 0 };
  const store = new JwksKeyStore(URL, { fetchImpl: countingFetch(jwksDoc(), calls) });
  // Default implementation: the real global setInterval (unref'd, so
  // it cannot hold the test process open if stop() were forgotten).
  const stop = store.startAutoRefresh(10);
  try {
    await new Promise<void>((resolve) => setTimeout(resolve, 150));
    assert.equal(calls.count, 1);
    assert.equal(store.stats().refreshes, 1);
  } finally {
    stop();
  }
  await new Promise<void>((resolve) => setTimeout(resolve, 100));
  assert.equal(calls.count, 1);
  assert.equal(store.stats().refreshes, 1);
});
