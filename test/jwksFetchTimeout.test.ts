import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";
const TIMEOUT_MSG = (ms: number) =>
  `JwksKeyStore: JWKS fetch timed out after ${ms}ms`;

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
  const seen: Array<{ url: string; init?: RequestInit }> = [];
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

test("jwks fetchTimeoutMs: constructor rejects non-positive-integer values", () => {
  for (const bad of [0, -1, 1.5, NaN, Infinity, "100" as unknown as number]) {
    assert.throws(
      () => new JwksKeyStore(URL, { fetchTimeoutMs: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: `fetchTimeoutMs` must be a positive integer",
        ),
      `expected throw for ${String(bad)}`,
    );
  }
  // 1ms and a large value are legal; undefined is legal too.
  assert.doesNotThrow(() => new JwksKeyStore(URL, { fetchTimeoutMs: 1 }));
  assert.doesNotThrow(
    () => new JwksKeyStore(URL, { fetchTimeoutMs: 30_000 }),
  );
  assert.doesNotThrow(() => new JwksKeyStore(URL));
});

test("jwks fetchTimeoutMs: a hung default fetch throws a descriptive timeout error", async () => {
  const stub = stubGlobalFetch(hangingFetch());
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 50 });
    await assert.rejects(
      () => store.refresh(),
      (err: unknown) =>
        err instanceof Error && err.message === TIMEOUT_MSG(50),
      "expected the exact timeout error, not the generic fetch-failure wrap",
    );
    // The default fetch really was invoked with an AbortSignal.
    assert.equal(stub.seen.length, 1);
    assert.ok(stub.seen[0].init?.signal instanceof AbortSignal);
    assert.equal(stub.seen[0].url, URL);
  } finally {
    stub.restore();
  }
});

test("jwks fetchTimeoutMs: timeout leaves the previous snapshot and freshness timestamp untouched", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 50 });
    await store.refresh(); // seeds a good snapshot
    assert.equal(store.size, 1);
    const refreshedAt = store.lastRefreshedAt;
    assert.notEqual(refreshedAt, null);
    assert.ok(store.resolve("ed-key-1"));

    stub.restore();
    const hang = stubGlobalFetch(hangingFetch());
    try {
      await assert.rejects(() => store.refresh(), /timed out after 50ms/);
      // Fail-closed: keys and the freshness timestamp are exactly as before.
      assert.equal(store.size, 1);
      assert.equal(store.lastRefreshedAt, refreshedAt);
      assert.ok(store.resolve("ed-key-1")); // old snapshot still served
      assert.equal(store.resolve("unknown-kid"), undefined);
    } finally {
      hang.restore();
    }
  } finally {
    // restore() is idempotent-safe here: the first stub was already
    // restored; restoring again keeps the real fetch patched back.
    stub.restore();
  }
});

test("jwks fetchTimeoutMs: a timeout failure counts in stats().refreshFailures", async () => {
  const stub = stubGlobalFetch(hangingFetch());
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 50 });
    await assert.rejects(() => store.refresh(), /timed out after 50ms/);
    await assert.rejects(() => store.refresh(), /timed out after 50ms/);
    assert.deepEqual(store.stats(), {
      refreshes: 0,
      refreshFailures: 2,
      hits: 0,
      misses: 0,
    });
  } finally {
    stub.restore();
  }
});

test("jwks fetchTimeoutMs: a fetch that finishes within the deadline is unaffected", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => {
    await sleep(10);
    return okResponse(docFor(publicKey));
  });
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 5000 });
    await store.refresh(); // must not abort a healthy fetch
    assert.equal(store.size, 1);
    assert.ok(store.resolve("ed-key-1"));
    assert.deepEqual(store.stats(), {
      refreshes: 1,
      refreshFailures: 0,
      hits: 1,
      misses: 0,
    });
  } finally {
    stub.restore();
  }
});

test("jwks fetchTimeoutMs: without the option the default fetch receives no signal (zero drift)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const stub = stubGlobalFetch(async () => okResponse(docFor(publicKey)));
  try {
    const store = new JwksKeyStore(URL);
    await store.refresh();
    assert.equal(stub.seen.length, 1);
    assert.equal(stub.seen[0].init, undefined);
    assert.equal(store.size, 1);
  } finally {
    stub.restore();
  }
});

test("jwks fetchTimeoutMs: a custom fetchImpl is never timed out (documented exemption)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  // A slow custom implementation (120ms) with a 50ms timeout: if the
  // timeout were wrongly applied, this refresh would throw.
  const slowImpl = async (_url: string) => {
    await sleep(120);
    return okResponse(docFor(publicKey));
  };
  const store = new JwksKeyStore(URL, {
    fetchImpl: slowImpl,
    fetchTimeoutMs: 50,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1"));
});

test("jwks fetchTimeoutMs: timeout on an empty store leaves it empty (fail-closed from birth)", async () => {
  const stub = stubGlobalFetch(hangingFetch());
  try {
    const store = new JwksKeyStore(URL, { fetchTimeoutMs: 50 });
    assert.equal(store.size, 0);
    assert.equal(store.lastRefreshedAt, null);
    await assert.rejects(() => store.refresh(), /timed out after 50ms/);
    assert.equal(store.size, 0);
    assert.equal(store.lastRefreshedAt, null);
    assert.equal(store.resolve("ed-key-1"), undefined);
  } finally {
    stub.restore();
  }
});
