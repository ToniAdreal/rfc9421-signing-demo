import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
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

/** Case-insensitive header lookup, mirroring the native `Headers`. */
function headersOf(record: Record<string, string>) {
  return {
    get(name: string): string | null {
      return record[name.toLowerCase()] ?? null;
    },
  };
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

test("jwks refresh({ signal }): a pre-aborted signal throws at once and fetches nothing", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl: async (url: string) => {
      calls.push(url);
      const { publicKey } = generateEd25519KeyPair();
      return okResponse(docFor(publicKey));
    },
  });
  const controller = new AbortController();
  controller.abort();
  assert.throws(
    () => store.refresh({ signal: controller.signal }),
    (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
    "expected the exact aborted error",
  );
  // No refresh was attempted: no fetch, no snapshot, no stats move.
  assert.equal(calls.length, 0);
  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.deepEqual(store.stats(), emptyStats());
});

test("jwks refresh({ signal }): a pre-aborted signal leaves a seeded snapshot, freshness, and stats untouched", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    const store = new JwksKeyStore(URL);
    await store.refresh(); // seeds a good snapshot
    assert.equal(store.size, 1);
    const refreshedAt = store.lastRefreshedAt;
    assert.notEqual(refreshedAt, null);

    const controller = new AbortController();
    controller.abort();
    // A pre-aborted signal throws synchronously from refresh()
    // (the check runs before any promise is created), so this is
    // assert.throws, not assert.rejects.
    assert.throws(
      () => store.refresh({ signal: controller.signal }),
      (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
    );
    // Fail-closed, and not even counted: the call never attempted a fetch.
    assert.equal(store.size, 1);
    assert.equal(store.lastRefreshedAt, refreshedAt);
    assert.ok(store.resolve("ed-key-1")); // old snapshot still served
    assert.deepEqual(store.stats(), {
      ...emptyStats(),
      refreshes: 1,
      hits: 1,
    });
  } finally {
    stub.restore();
  }
});

test("jwks refresh({ signal }): a non-AbortSignal signal is a configuration error and fetches nothing", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl: async (url: string) => {
      calls.push(url);
      const { publicKey } = generateEd25519KeyPair();
      return okResponse(docFor(publicKey));
    },
  });
  for (const bad of [
    "signal",
    42,
    {},
    null,
    [],
    true,
  ] as unknown as AbortSignal[]) {
    // A bad signal is a synchronous configuration error, thrown
    // before any fetch is attempted.
    assert.throws(
      () => store.refresh({ signal: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          `JwksKeyStore: refresh signal must be an AbortSignal, got ${String(bad)}`,
      `expected a configuration error for signal=${String(bad)}`,
    );
  }
  assert.equal(calls.length, 0);
  assert.deepEqual(store.stats(), emptyStats());
});

test("jwks refresh({ signal }): a non-object options value is a configuration error", async () => {
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => {
      const { publicKey } = generateEd25519KeyPair();
      return okResponse(docFor(publicKey));
    },
  });
  for (const bad of [null, "refresh", 42] as unknown as Parameters<
    JwksKeyStore["refresh"]
  >[0][]) {
    assert.throws(
      () => store.refresh(bad),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          `JwksKeyStore: refresh options must be an object, got ${String(bad)}`,
      `expected a configuration error for opts=${String(bad)}`,
    );
  }
  // An empty options object is the same as no options at all.
  await store.refresh({});
  assert.equal(store.size, 1);
});

test("jwks refresh({ signal }): aborting mid-fetch cancels the default fetch", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    const store = new JwksKeyStore(URL);
    await store.refresh(); // seeds a good snapshot
    assert.equal(store.size, 1);
    const refreshedAt = store.lastRefreshedAt;

    stub.restore();
    const hang = stubGlobalFetch(hangingFetch());
    try {
      const controller = new AbortController();
      const pending = store.refresh({ signal: controller.signal });
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

test("jwks refresh({ signal }): the caller abort wins over the fetch timeout", async () => {
  const stub = stubGlobalFetch(hangingFetch());
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 5000 });
    const controller = new AbortController();
    const pending = store.refresh({ signal: controller.signal });
    setTimeout(() => controller.abort(), 10);
    await assert.rejects(
      () => pending,
      (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
      "expected the aborted error, not the 5000ms timeout error",
    );
    assert.deepEqual(store.stats(), {
      ...emptyStats(),
      refreshFailures: 1,
    });
  } finally {
    stub.restore();
  }
});

test("jwks refresh({ signal }): abort during the retry backoff starts no new attempt", async () => {
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
  const pending = store.refresh({ signal: controller.signal });
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

test("jwks refresh({ signal }): abort during a Retry-After wait starts no new attempt", async () => {
  const fetchCalls: string[] = [];
  const sleepDelays: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl: async (url: string) => {
      fetchCalls.push(url);
      return {
        ok: false,
        status: 429,
        json: async () => ({}),
        headers: headersOf({ "retry-after": "30" }),
      };
    },
    fetchRetries: 1,
    sleepImpl: (ms: number) => {
      sleepDelays.push(ms);
      return new Promise<void>(() => {});
    },
  });
  const controller = new AbortController();
  const pending = store.refresh({ signal: controller.signal });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(
    () => pending,
    (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
  );
  assert.equal(fetchCalls.length, 1);
  assert.deepEqual(sleepDelays, [30_000]);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshFailures: 1,
  });
});

test("jwks refresh({ signal }): a custom fetchImpl in flight is not interrupted, but the abort is honoured before the swap", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let fetchCalls = 0;
  let implResolved = false;
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => {
      fetchCalls++;
      // Runs to completion: the impl never receives the signal,
      // so the abort cannot interrupt this call.
      await sleep(150);
      implResolved = true;
      return okResponse(docFor(publicKey));
    },
  });
  const controller = new AbortController();
  const pending = store.refresh({ signal: controller.signal });
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(
    () => pending,
    (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
  );
  // The in-flight call ran to completion, then the abort was
  // honoured before any state changed — no snapshot installed.
  assert.equal(implResolved, true);
  assert.equal(fetchCalls, 1);
  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshFailures: 1,
  });
});

test("jwks refresh({ signal }): an abort during body read is honoured before the swap", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let textResolved = false;
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      // json() must be present for the response shape check; text()
      // takes precedence for the body read once that check passes.
      json: async () => docFor(publicKey),
      text: async () => {
        await sleep(150);
        textResolved = true;
        return JSON.stringify(docFor(publicKey));
      },
    }),
  });
  const controller = new AbortController();
  const pending = store.refresh({ signal: controller.signal });
  setTimeout(() => controller.abort(), 20);
  await assert.rejects(
    () => pending,
    (err: unknown) => err instanceof Error && err.message === ABORTED_MSG,
  );
  assert.equal(textResolved, true);
  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.deepEqual(store.stats(), {
    ...emptyStats(),
    refreshFailures: 1,
  });
});

test("jwks refresh({ signal }): a signal that never aborts changes nothing", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    const store = new JwksKeyStore(URL);
    const controller = new AbortController();
    await store.refresh({ signal: controller.signal });
    assert.equal(store.size, 1);
    assert.ok(store.resolve("ed-key-1"));
    // The default fetch received a signal even with no timeout set.
    assert.equal(stub.seen.length, 1);
    assert.ok(stub.seen[0].init?.signal instanceof AbortSignal);
    assert.deepEqual(store.stats(), {
      ...emptyStats(),
      refreshes: 1,
      hits: 1,
    });
  } finally {
    stub.restore();
  }
});

test("jwks refresh({ signal }): a joiner's signal does not cancel the shared in-flight refresh", async () => {
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
    const first = store.refresh();
    // Joins the in-flight refresh: its own signal is ignored, so
    // cancelling it must not cancel the other caller's refresh.
    const second = store.refresh({ signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    await first;
    await second;
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
