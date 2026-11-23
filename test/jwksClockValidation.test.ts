import test from "node:test";
import assert from "node:assert/strict";
import { type KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksFetchResponse,
  type JwksSignedSnapshotEnvelope,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";
const SECRET = "jwks-clock-validation-test-secret-32bytes!";
const T0 = 1_700_000_000;
const CLOCK_ERROR =
  /JwksKeyStore: clock must return a finite number of seconds since the epoch, got /;

/** One ed25519 key and the JWKS document publishing it. */
function edDoc() {
  const pair = generateEd25519KeyPair();
  return {
    pair,
    doc: { keys: [{ ...exportPublicKeyJwk(pair.publicKey), kid: "ed-key-1" }] },
  };
}

function okResponse(body: unknown): JwksFetchResponse {
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

function errorResponse(status: number, retryAfter?: string): JwksFetchResponse {
  return {
    ok: false,
    status,
    json: async () => ({}),
    ...(retryAfter !== undefined
      ? { headers: headersOf({ "retry-after": retryAfter }) }
      : {}),
  };
}

/** A 304 response whose `json()` throws if called: a 304 has no body. */
function notModifiedResponse(): JwksFetchResponse {
  return {
    ok: false,
    status: 304,
    json: async () => {
      throw new Error("json() must not be called on a 304 response");
    },
  };
}

/**
 * A scripted fetchImpl: each call consumes the next scripted response;
 * running out of scripted responses is a test bug, not store behavior.
 */
function scriptedFetch(script: JwksFetchResponse[]) {
  const calls: string[] = [];
  const fetchImpl: JwksFetchImpl = async (url) => {
    calls.push(url);
    const next = script.shift();
    assert.ok(next !== undefined, "scripted fetch ran out of responses");
    return next;
  };
  return { fetchImpl, calls };
}

/** A clock the test can move, including onto a non-finite reading. */
function mutableClock(start: number) {
  let t: unknown = start;
  return {
    now: () => t as number,
    set: (v: unknown) => {
      t = v;
    },
  };
}

test("jwks clock validation: isStale() throws under a NaN clock instead of reporting the snapshot fresh forever", async () => {
  const { pair, doc } = edDoc();
  const clock = mutableClock(T0);
  const { fetchImpl } = scriptedFetch([okResponse(doc)]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: clock.now });
  await store.refresh();
  assert.equal(store.lastRefreshedAt, T0);
  assert.equal(store.isStale(), false);

  clock.set(NaN);
  assert.throws(() => store.isStale(), CLOCK_ERROR);
  // No residue: the snapshot, the timestamp, and resolution are untouched.
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, T0);
  assert.equal(store.resolve("ed-key-1")?.equals(pair.publicKey), true);
});

test("jwks clock validation: isStale() throws under Infinity and non-number clocks, naming the bad value", async () => {
  const { doc } = edDoc();
  for (const bad of [Infinity, -Infinity, "yesterday" as unknown as number]) {
    const clock = mutableClock(T0);
    const { fetchImpl } = scriptedFetch([okResponse(doc)]);
    const store = new JwksKeyStore(URL, { fetchImpl, now: clock.now });
    await store.refresh();
    clock.set(bad);
    assert.throws(
      () => store.isStale(),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: clock must return a finite number of seconds since the epoch, got ",
        ) &&
        // The message names the bad reading: the value for numbers,
        // the typeof for a non-number return.
        err.message.includes(
          typeof bad === "number" ? String(bad) : typeof bad,
        ),
      `expected a naming throw for clock=${String(bad)}`,
    );
    assert.equal(store.lastRefreshedAt, T0);
  }
});

test("jwks clock validation: construction with a bad clock still succeeds, and isStale() before the first refresh never reads the clock", () => {
  const { doc } = edDoc();
  const { fetchImpl } = scriptedFetch([okResponse(doc)]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: () => NaN });
  // No refresh yet: trivially stale, no clock read, no throw.
  assert.equal(store.isStale(), true);
  assert.equal(store.lastRefreshedAt, null);
});

test("jwks clock validation: refreshIfStale() under a NaN clock throws and issues no fetch", async () => {
  const { doc } = edDoc();
  const clock = mutableClock(T0);
  const { fetchImpl, calls } = scriptedFetch([okResponse(doc)]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: clock.now });
  await store.refresh();
  assert.equal(calls.length, 1);

  clock.set(NaN);
  await assert.rejects(() => store.refreshIfStale(), CLOCK_ERROR);
  assert.equal(calls.length, 1, "no fetch may be issued under a bad clock");
  assert.equal(store.lastRefreshedAt, T0);
});

test("jwks clock validation: refresh() under a NaN clock rejects and stores no NaN timestamp", async () => {
  const { doc } = edDoc();
  const { fetchImpl, calls } = scriptedFetch([okResponse(doc)]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: () => NaN });
  // The fetch itself succeeds; the clock read at the swap point throws.
  await assert.rejects(() => store.refresh(), CLOCK_ERROR);
  assert.equal(calls.length, 1);
  assert.equal(store.lastRefreshedAt, null, "no NaN timestamp may be stored");
  assert.equal(store.size, 0);
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 1,
    hits: 0,
    misses: 1,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
  });
});

test("jwks clock validation: refresh() under a NaN clock keeps the previous snapshot, timestamp, and verification working", async () => {
  const { pair, doc } = edDoc();
  const clock = mutableClock(T0);
  const { fetchImpl } = scriptedFetch([okResponse(doc), okResponse(doc)]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: clock.now });
  await store.refresh();

  clock.set(NaN);
  await assert.rejects(() => store.refresh(), CLOCK_ERROR);
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, T0);
  // The kept snapshot still verifies, exactly as before the bad clock.
  const signed = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {}, body: '{"amount":100}' },
    { keyId: "ed-key-1", alg: "ed25519", key: pair.privateKey, created: T0 },
  );
  const result = verifyRequest(signed, { keyResolver: store.resolve });
  assert.equal(result.ok, true);
  assert.equal(store.stats().refreshFailures, 1);
});

test("jwks clock validation: a 304 refresh under a NaN clock rejects and leaves the freshness timestamp and counters untouched", async () => {
  const { doc } = edDoc();
  const clock = mutableClock(T0);
  const { fetchImpl, calls } = scriptedFetch([
    okResponse(doc),
    notModifiedResponse(),
  ]);
  const store = new JwksKeyStore(URL, { fetchImpl, now: clock.now });
  await store.refresh();
  assert.equal(store.lastRefreshedAt, T0);

  clock.set(NaN);
  await assert.rejects(() => store.refresh(), CLOCK_ERROR);
  assert.equal(calls.length, 2, "the 304 fetch happened; only its timestamp write failed");
  assert.equal(store.lastRefreshedAt, T0);
  assert.equal(store.size, 1);
  assert.equal(store.stats().notModified, 0, "a failed refresh is not a 304 success");
  assert.equal(store.stats().refreshFailures, 1);
});

test("jwks clock validation: a Retry-After HTTP-date under a NaN clock throws before any retry sleep or second fetch", async () => {
  const { doc } = edDoc();
  const sleeps: number[] = [];
  const { fetchImpl, calls } = scriptedFetch([
    errorResponse(429, "Wed, 21 Oct 2015 07:28:00 GMT"),
    okResponse(doc),
  ]);
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    now: () => NaN,
    fetchRetries: 1,
    fetchBackoffMs: 0,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await assert.rejects(() => store.refresh(), CLOCK_ERROR);
  assert.equal(calls.length, 1, "the retry must never be attempted");
  assert.deepEqual(sleeps, [], "no backoff may be slept under a bad clock");
  assert.equal(store.lastRefreshedAt, null);
});

test("jwks clock validation: the same Retry-After HTTP-date retries and succeeds under a good clock", async () => {
  const { doc } = edDoc();
  const sleeps: number[] = [];
  const { fetchImpl, calls } = scriptedFetch([
    errorResponse(429, "Wed, 21 Oct 2015 07:28:00 GMT"),
    okResponse(doc),
  ]);
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    now: () => T0,
    fetchRetries: 1,
    fetchBackoffMs: 0,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  // The 2015 date is in the past against T0, so the delay is unusable
  // and the fixed backoff (0) applies — the control proves the retry
  // path itself works and only the bad clock breaks it.
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(sleeps, [0]);
  assert.equal(store.lastRefreshedAt, T0);
  assert.equal(store.size, 1);
});

test("jwks clock validation: legal-clock TTL boundary behavior is unchanged", async () => {
  const { doc } = edDoc();
  const clock = mutableClock(T0);
  const { fetchImpl } = scriptedFetch([okResponse(doc), okResponse(doc)]);
  const store = new JwksKeyStore(URL, {
    fetchImpl,
    now: clock.now,
    ttlSec: 60,
  });
  await store.refresh();
  assert.equal(store.isStale(), false);
  clock.set(T0 + 59);
  assert.equal(store.isStale(), false);
  clock.set(T0 + 60);
  assert.equal(store.isStale(), true);
  await store.refresh();
  assert.equal(store.lastRefreshedAt, T0 + 60);
  assert.equal(store.isStale(), false);
});

test("jwks clock validation: restoreSignedSnapshot under a NaN store clock throws instead of installing keys", async () => {
  const { doc } = edDoc();
  const { fetchImpl } = scriptedFetch([okResponse(doc)]);
  const original = new JwksKeyStore(URL, { fetchImpl, now: () => T0 });
  await original.refresh();
  const envelope: JwksSignedSnapshotEnvelope =
    original.exportSignedSnapshot(SECRET);

  const bad = new JwksKeyStore(URL, { fetchImpl, now: () => NaN });
  assert.throws(
    () => bad.restoreSignedSnapshot(envelope, SECRET),
    CLOCK_ERROR,
  );
  assert.equal(bad.size, 0, "no keys may be installed under a bad clock");

  // Control: the same envelope restores fine under a good clock.
  const good = new JwksKeyStore(URL, { fetchImpl, now: () => T0 });
  good.restoreSignedSnapshot(envelope, SECRET);
  assert.equal(good.size, 1);
  assert.equal(good.lastRefreshedAt, T0);
});
