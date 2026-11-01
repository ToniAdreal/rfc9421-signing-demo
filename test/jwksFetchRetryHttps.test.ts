import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
} from "../src/index.js";

const HTTP_URL = "http://gateway.example.com/.well-known/jwks.json";
const HTTPS_URL = "https://gateway.example.com/.well-known/jwks.json";
const REQUIRE_HTTPS_MSG =
  'JwksKeyStore: `requireHttps` requires https: for the JWKS endpoint, got "http:"';

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
 * (`"ok"` body / HTTP status); running out of scripted outcomes is a
 * test bug, not a store behavior.
 */
function scriptedFetch(
  script: Array<{ kind: "ok"; body: unknown } | { kind: "status"; status: number }>,
) {
  const calls: string[] = [];
  const fetchImpl = async (url: string) => {
    calls.push(url);
    const next = script.shift();
    assert.ok(next !== undefined, "scripted fetch ran out of outcomes");
    if (next.kind === "ok") return okResponse(next.body);
    return errorResponse(next.status);
  };
  return { fetchImpl, calls };
}

test("jwks fetchRetry x requireHttps: http rejection is construction-time, never retried", () => {
  // Note on the backlog wording: #554 ships `requireHttps` as a
  // construction-time rejection, not a refresh-time one, so there is
  // no "first refresh attempt" to count. The combination property that
  // matters is the same: the rejection is terminal and is never
  // retried, even with fetchRetries configured. It happens before any
  // fetch is attempted (0 calls, not 1 attempt plus retries), and no
  // backoff sleep is ever requested.
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
  ]);
  const sleeps: number[] = [];
  assert.throws(
    () =>
      new JwksKeyStore(HTTP_URL, {
        requireHttps: true,
        fetchImpl,
        fetchRetries: 3,
        fetchBackoffMs: 100,
        sleepImpl: async (ms: number) => {
          sleeps.push(ms);
        },
      }),
    (err: unknown) =>
      err instanceof Error && err.message === REQUIRE_HTTPS_MSG,
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(sleeps, []);
});

test("jwks fetchRetry x requireHttps: https 500, 500, then 200 succeeds on the third fetch", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const { fetchImpl, calls } = scriptedFetch([
    { kind: "status", status: 500 },
    { kind: "status", status: 500 },
    { kind: "ok", body: docFor(publicKey) },
  ]);
  const sleeps: number[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl,
    fetchRetries: 2,
    fetchBackoffMs: 10,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  await store.refresh();
  assert.equal(calls.length, 3);
  assert.deepEqual(calls, [HTTPS_URL, HTTPS_URL, HTTPS_URL]);
  assert.deepEqual(sleeps, [10, 10]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().refreshes, 1);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks fetchRetry x requireHttps: https persistent 500 exhausts retries and keeps the old snapshot", async () => {
  const { publicKey } = generateEd25519KeyPair();
  // Seed the retrying store with a good snapshot first, via a
  // separate successful refresh, so "old snapshot untouched" is real.
  const seed = new JwksKeyStore(HTTPS_URL, {
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
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
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
        `JwksKeyStore: JWKS fetch failed: HTTP 500 from ${HTTPS_URL}`,
  );
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [100, 100]);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.lastRefreshedAt, seededAt);
  assert.equal(store.stats().refreshFailures, 1);
  assert.equal(store.stats().refreshes, 0);
});
