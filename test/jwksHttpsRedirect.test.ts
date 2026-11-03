import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
  type JwksFetchResponse,
} from "../src/index.js";

const HTTPS_URL = "https://gateway.example.com/.well-known/jwks.json";
const HTTP_FINAL_URL = "http://gateway.example.com/.well-known/jwks.json";
const REDIRECT_MSG = `JwksKeyStore: JWKS fetch redirected to insecure http: ${HTTP_FINAL_URL}`;
const REQUIRE_HTTPS_MSG =
  'JwksKeyStore: `requireHttps` requires https: for the JWKS endpoint, got "http:"';

function docFor(kid: string): { keys: unknown[] } {
  const { publicKey } = generateEd25519KeyPair();
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

/** A fetchImpl that reports a final URL, like the default fetch does. */
function implWithFinalUrl(
  body: unknown,
  finalUrl: string | undefined,
  calls: string[],
): JwksFetchImpl {
  return async (url: string): Promise<JwksFetchResponse> => {
    calls.push(url);
    const res: JwksFetchResponse = {
      ok: true,
      status: 200,
      json: async () => body,
    };
    if (finalUrl !== undefined) res.url = finalUrl;
    return res;
  };
}

test("jwks requireHttps: https-to-http redirect is rejected and the snapshot stays empty", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTP_FINAL_URL, calls),
    now: () => 1700000000,
  });
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => err instanceof Error && err.message === REDIRECT_MSG,
  );
  assert.deepEqual(calls, [HTTPS_URL]);
  assert.equal(store.size, 0);
  assert.equal(store.lastRefreshedAt, null);
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 1,
    hits: 0,
    misses: 1,
  });
});

test("jwks requireHttps: redirect failure leaves a prior good snapshot and timestamp untouched", async () => {
  const firstCalls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTPS_URL, firstCalls),
    now: () => 1700000000,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.equal(store.lastRefreshedAt, 1700000000);
  assert.ok(store.resolve("ed-key-1") !== undefined);

  // Swap the fetch to a redirecting one by building a second store
  // over the same snapshot is not possible, so instead verify the
  // failure path on a store pre-loaded via restoreSnapshot.
  const snapshot = store.exportSnapshot();
  const secondCalls: string[] = [];
  const redirected = JwksKeyStore.restore(snapshot, HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(docFor("ed-key-2"), HTTP_FINAL_URL, secondCalls),
    now: () => 1700000600,
  });
  await assert.rejects(
    () => redirected.refresh(),
    (err: unknown) => err instanceof Error && err.message === REDIRECT_MSG,
  );
  assert.equal(redirected.size, 1);
  assert.equal(redirected.lastRefreshedAt, 1700000000);
  assert.ok(redirected.resolve("ed-key-1") !== undefined);
  assert.equal(redirected.resolve("ed-key-2"), undefined);
  assert.equal(redirected.stats().refreshFailures, 1);
  assert.equal(redirected.stats().refreshes, 0);
});

test("jwks requireHttps: https final url passes and installs the keys", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTPS_URL, calls),
  });
  await store.refresh();
  assert.deepEqual(calls, [HTTPS_URL]);
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks requireHttps: custom fetchImpl with no final url passes unchecked (honest exemption)", async () => {
  // The response carries no url at all, so the redirect check has
  // nothing to verify: the refresh must succeed rather than fail
  // on a missing field, and the limitation is documented on
  // JwksFetchResponse.url, not hidden behind a fabricated check.
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), undefined, calls),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks requireHttps: http final url is not intercepted when the guard is off", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTP_FINAL_URL, calls),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  assert.equal(store.stats().refreshFailures, 0);
});

test("jwks requireHttps: http final url is not intercepted with explicit requireHttps false", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: false,
    fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTP_FINAL_URL, calls),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("jwks requireHttps: uppercase HTTP final url is intercepted too", async () => {
  const calls: string[] = [];
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: implWithFinalUrl(
      docFor("ed-key-1"),
      "HTTP://gateway.example.com/.well-known/jwks.json",
      calls,
    ),
  });
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        "JwksKeyStore: JWKS fetch redirected to insecure http: HTTP://gateway.example.com/.well-known/jwks.json",
  );
  assert.equal(store.size, 0);
  assert.equal(store.stats().refreshFailures, 1);
});

test("jwks requireHttps: construction-time http endpoint is still rejected first (regression)", () => {
  const calls: string[] = [];
  assert.throws(
    () =>
      new JwksKeyStore("http://gateway.example.com/.well-known/jwks.json", {
        requireHttps: true,
        fetchImpl: implWithFinalUrl(docFor("ed-key-1"), HTTP_FINAL_URL, calls),
      }),
    (err: unknown) =>
      err instanceof Error && err.message === REQUIRE_HTTPS_MSG,
  );
  assert.deepEqual(calls, []);
});
