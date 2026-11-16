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

/** Case-insensitive header lookup, mirroring the native `Headers`. */
function headersOf(record: Record<string, string>) {
  return {
    get(name: string): string | null {
      return record[name.toLowerCase()] ?? null;
    },
  };
}

function errorResponse(status: number, retryAfter?: string) {
  return {
    ok: false,
    status,
    json: async () => ({}),
    ...(retryAfter !== undefined
      ? { headers: headersOf({ "retry-after": retryAfter }) }
      : {}),
  };
}

/**
 * A scripted fetchImpl: each call consumes the next scripted outcome
 * (`"ok"` body / HTTP status, optionally with a `Retry-After`
 * header / thrown error); running out of scripted outcomes is a
 * test bug, not a store behavior.
 */
function scriptedFetch(
  script: Array<
    | { kind: "ok"; body: unknown }
    | { kind: "status"; status: number; retryAfter?: string }
    | { kind: "throw"; message: string }
  >,
) {
  const calls: string[] = [];
  const fetchImpl = async (url: string) => {
    calls.push(url);
    const next = script.shift();
    assert.ok(next !== undefined, "scripted fetch ran out of outcomes");
    if (next.kind === "ok") return okResponse(next.body);
    if (next.kind === "status")
      return errorResponse(next.status, next.retryAfter);
    throw new Error(next.message);
  };
  return { fetchImpl, calls };
}

test("jwks Retry-After: constructor rejects illegal fetchMaxRetryDelayMs values", () => {
  for (const bad of [-1, NaN, Infinity, "5000" as unknown as number]) {
    assert.throws(
      () => new JwksKeyStore(URL, { fetchMaxRetryDelayMs: bad }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: `fetchMaxRetryDelayMs` must be a finite number >= 0",
        ),
      `expected throw for fetchMaxRetryDelayMs=${String(bad)}`,
    );
  }
  // Legal values: 0 (honour no server-requested wait at all) and
  // the 60-second default are both accepted.
  assert.doesNotThrow(() => new JwksKeyStore(URL, { fetchMaxRetryDelayMs: 0 }));
  assert.doesNotThrow(
    () => new JwksKeyStore(URL, { fetchMaxRetryDelayMs: 60_000 }),
  );
});

test("jwks Retry-After: 429 with Retry-After: 2 waits 2000ms, then retries to success", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429, retryAfter: "2" },
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
  assert.deepEqual(sleeps, [2000]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().refreshes, 1);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks Retry-After: 503 with Retry-After: 3 waits 3000ms, then retries to success", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 503, retryAfter: "3" },
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
  assert.deepEqual(sleeps, [3000]);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("jwks Retry-After: 503 with an HTTP-date waits the date-derived delay (injected clock)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const nowSec = 1_700_000_000;
  const retryDate = new Date((nowSec + 5) * 1000).toUTCString();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 503, retryAfter: retryDate },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 2,
    fetchBackoffMs: 250,
    now: () => nowSec,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(sleeps, [5000]);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("jwks Retry-After: 429 without the header falls back to the fixed backoff", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429 },
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
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("jwks Retry-After: other 4xx stay terminal even with a Retry-After header", async () => {
  for (const status of [400, 404]) {
    const { fetchImpl, calls } = scriptedFetch([
      { kind: "status", status, retryAfter: "2" },
      { kind: "status", status, retryAfter: "2" },
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
          `JwksKeyStore: JWKS fetch failed: HTTP ${status} from ${URL}`,
      `expected terminal throw for HTTP ${status}`,
    );
    assert.equal(calls.length, 1);
    assert.deepEqual(sleeps, []);
  }
});

test("jwks Retry-After: unparseable values fall back to the fixed backoff, never throw", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const nowSec = 1_700_000_000;
  const pastDate = new Date((nowSec - 60) * 1000).toUTCString();
  for (const bad of ["not-a-date", "-5", "2.5", pastDate, ""]) {
    const { fetchImpl, calls } = scriptedFetch([
      { kind: "status", status: 429, retryAfter: bad },
      { kind: "ok", body: docFor(publicKey) },
    ]);
    const sleeps: number[] = [];
    const store = new JwksKeyStore(URL, {
      fetchImpl,
      fetchRetries: 1,
      fetchBackoffMs: 125,
      now: () => nowSec,
      sleepImpl: async (ms: number) => {
        sleeps.push(ms);
      },
    });
    await store.refresh();
    assert.equal(calls.length, 2);
    assert.deepEqual(sleeps, [125], `bad Retry-After ${JSON.stringify(bad)}`);
    assert.notEqual(store.resolve("ed-key-1"), undefined);
  }
});

test("jwks Retry-After: a delay above the cap waits exactly the cap", async () => {
  const { publicKey } = generateEd25519KeyPair();
  // Explicit cap: the endpoint asks for 120s, the store waits 5s.
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429, retryAfter: "120" },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 1,
    fetchBackoffMs: 250,
    fetchMaxRetryDelayMs: 5000,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(sleeps, [5000]);
  assert.notEqual(store.resolve("ed-key-1"), undefined);

  // Default cap (60_000): the same 120s ask waits the full minute.
  const { fetchImpl: defaultImpl, calls: defaultCalls } = scriptedFetch([
    { kind: "status", status: 503, retryAfter: "120" },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const defaultSleeps: number[] = [];
  const defaultStore = new JwksKeyStore(URL, {
    fetchImpl: defaultImpl,
    fetchRetries: 1,
    fetchBackoffMs: 250,
    sleepImpl: async (ms: number) => {
      defaultSleeps.push(ms);
    },
  });
  await defaultStore.refresh();
  assert.equal(defaultCalls.length, 2);
  assert.deepEqual(defaultSleeps, [60_000]);
  assert.notEqual(defaultStore.resolve("ed-key-1"), undefined);
});

test("jwks Retry-After: persistent 429 exhausts retries, throws the original error, keeps the old snapshot", async () => {
  const { publicKey } = generateEd25519KeyPair();
  // Seed the retrying store with a good snapshot first, via a
  // separate successful refresh, so "old snapshot untouched" is real.
  const seed = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(docFor(publicKey)),
  });
  await seed.refresh();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429, retryAfter: "2" },
    { kind: "status", status: 429, retryAfter: "2" },
    { kind: "status", status: 429, retryAfter: "2" },
    { kind: "status", status: 429, retryAfter: "2" },
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
        `JwksKeyStore: JWKS fetch failed: HTTP 429 from ${URL}`,
  );
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [2000, 2000]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.lastRefreshedAt, seededAt);
  assert.equal(store.stats().refreshFailures, 1);
  assert.equal(store.stats().refreshes, 0);
});

test("jwks Retry-After: resolve still serves the old snapshot while a retry is waiting", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const seed = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(docFor(publicKey)),
  });
  await seed.refresh();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429, retryAfter: "2" },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  let store: JwksKeyStore;
  const seenDuringWait: Array<unknown> = [];
  store = new JwksKeyStore(URL, {
    fetchImpl,
    fetchRetries: 1,
    fetchBackoffMs: 100,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
      // The retry is waiting here: the old snapshot must still
      // answer, and no refresh has been counted yet.
      seenDuringWait.push(store.resolve("ed-key-1"));
      seenDuringWait.push(store.stats().refreshes);
    },
  });
  store.restoreSnapshot(seed.exportSnapshot());
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(sleeps, [2000]);
  assert.equal(seenDuringWait.length, 2);
  assert.notEqual(seenDuringWait[0], undefined);
  assert.equal(seenDuringWait[1], 0);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("jwks Retry-After: 429 with fetchRetries 0 is a single attempt — no sleep, immediate throw", async () => {
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 429, retryAfter: "2" },
    { kind: "status", status: 429, retryAfter: "2" },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        `JwksKeyStore: JWKS fetch failed: HTTP 429 from ${URL}`,
  );
  assert.equal(calls.length, 1);
  assert.deepEqual(sleeps, []);
});
