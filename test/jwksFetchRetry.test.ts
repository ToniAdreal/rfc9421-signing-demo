import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";

function docFor(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  kid = "ed-key-1",
) {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

function okResponse(body: unknown) {
  return { ok: true, status: 200, json: async () => body };
}

function errorResponse(status: number) {
  return { ok: false, status, json: async () => ({}) };
}

/**
 * A scripted fetchImpl: each call consumes the next scripted outcome
 * (`"ok"` body / HTTP status / thrown error); running out of scripted
 * outcomes is a test bug, not a store behavior.
 */
function scriptedFetch(
  script: Array<
    | { kind: "ok"; body: unknown }
    | { kind: "status"; status: number }
    | { kind: "throw"; message: string }
  >,
) {
  const calls: string[] = [];
  const fetchImpl = async (url: string) => {
    calls.push(url);
    const next = script.shift();
    assert.ok(next !== undefined, "scripted fetch ran out of outcomes");
    if (next.kind === "ok") return okResponse(next.body);
    if (next.kind === "status") return errorResponse(next.status);
    throw new Error(next.message);
  };
  return { fetchImpl, calls };
}

test("jwks fetchRetries: constructor rejects illegal retry/backoff/sleep values", () => {
  for (const bad of [-1, 1.5, NaN, Infinity, "2" as unknown as number]) {
    assert.throws(
      () => new JwksKeyStore(URL, { fetchRetries: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: `fetchRetries` must be a non-negative integer",
        ),
      `expected throw for fetchRetries=${String(bad)}`,
    );
  }
  for (const bad of [-1, NaN, Infinity, "100" as unknown as number]) {
    assert.throws(
      () => new JwksKeyStore(URL, { fetchBackoffMs: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: `fetchBackoffMs` must be a finite number >= 0",
        ),
      `expected throw for fetchBackoffMs=${String(bad)}`,
    );
  }
  assert.throws(
    () => new JwksKeyStore(URL, { sleepImpl: 42 as unknown as never }),
    (err: unknown) =>
      err instanceof Error &&
      err.message === "JwksKeyStore: `sleepImpl` must be a function",
  );
  // Legal values: 0 retries (the default), a positive count, and a
  // zero backoff (retry immediately) are all accepted.
  assert.doesNotThrow(() => new JwksKeyStore(URL, { fetchRetries: 0 }));
  assert.doesNotThrow(() => new JwksKeyStore(URL, { fetchRetries: 3 }));
  assert.doesNotThrow(() => new JwksKeyStore(URL, { fetchBackoffMs: 0 }));
});

test("jwks fetchRetries: 500 then 200 succeeds on the retry and swaps the snapshot", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 500 },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 2,
    fetchBackoffMs: 250,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(sleeps, [250]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().refreshes, 1);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks fetchRetries: persistent 500 exhausts retries, throws, and keeps the old snapshot", async () => {
  const { publicKey } = generateEd25519KeyPair();
  // Seed the retrying store with a good snapshot first, via a
  // separate successful refresh, so "old snapshot untouched" is real.
  const seed = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(docFor(publicKey)),
  });
  await seed.refresh();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 2,
    fetchBackoffMs: 100,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  store.restoreSnapshot(seed.exportSnapshot());
  const seededAt = store.lastRefreshedAt;
  assert.notEqual(seededAt, null);
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        `JwksKeyStore: JWKS fetch failed: HTTP 500 from ${URL}`,
  );
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [100, 100]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.lastRefreshedAt, seededAt);
  assert.equal(store.stats().refreshFailures, 1);
  assert.equal(store.stats().refreshes, 0);
});

test("jwks fetchRetries: 404 is terminal — exactly one fetch, no sleep", async () => {
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 404 },
    { kind: "status", status: 404 },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 3,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        `JwksKeyStore: JWKS fetch failed: HTTP 404 from ${URL}`,
  );
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test("jwks fetchRetries: default 0 means a single attempt and no sleep", async () => {
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await assert.rejects(() => store.refresh(), /HTTP 500/);
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test("jwks fetchRetries: network errors are retried and the last error wins on exhaustion", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "throw", message: "connection reset" },
    { kind: "throw", message: "connection reset" },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 2,
    sleepImpl: async () => {},
  });
  await store.refresh();
  assert.equal(calls.length, 3);
  assert.notEqual(store.resolve("ed-key-1"), undefined);

  const { fetchImpl: failingImpl, calls: failingCalls } = scriptedFetch([
    { kind: "throw", message: "dns failure" },
    { kind: "throw", message: "dns failure" },
  ]);
  const failing = new JwksKeyStore(URL, {
    fetchImpl: failingImpl,
    fetchRetries: 1,
    sleepImpl: async () => {},
  });
  await assert.rejects(
    () => failing.refresh(),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        `JwksKeyStore: failed to fetch JWKS from ${URL}: dns failure`,
  );
  assert.equal(failingCalls.length, 2);
  assert.equal(failing.stats().refreshFailures, 1);
});

test("jwks fetchRetries: a malformed JWKS document is terminal — not retried", async () => {
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "ok", body: { keys: "not-an-array" } },
    { kind: "ok", body: { keys: "not-an-array" } },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 3,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await assert.rejects(() => store.refresh(), /"keys" must be an array/);
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});

test("jwks fetchRetries: a fetchTimeoutMs abort is terminal — not retried", async () => {
  const original = globalThis.fetch;
  const seen: string[] = [];
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    seen.push(url);
    return new Promise<never>((_resolve, reject) => {
      const signal = init?.signal;
      const onAbort = () =>
        reject(new DOMException("This operation was aborted", "AbortError"));
      if (signal?.aborted) {
        onAbort();
        return;
      }
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }) as typeof globalThis.fetch;
  try {
    const sleeps: number[] = [];
    const store = new JwksKeyStore(URL, {
      fetchTimeoutMs: 20,
      fetchRetries: 2,
      sleepImpl: async (ms: number) => {
        sleeps.push(ms);
      },
    });
    await assert.rejects(
      () => store.refresh(),
      (err: unknown) =>
        err instanceof Error &&
        err.message === "JwksKeyStore: JWKS fetch timed out after 20ms",
    );
    assert.equal(seen.length, 1);
    assert.deepEqual(sleeps, []);
    assert.equal(store.stats().refreshFailures, 1);
  } finally {
    globalThis.fetch = original;
  }
});

test("jwks fetchRetries: retry success still counts one refresh, not one per attempt", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 503 },
    { kind: "status", status: 503 },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 5,
    fetchBackoffMs: 10,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await store.refresh();
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [10, 10]);
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
  });
});
