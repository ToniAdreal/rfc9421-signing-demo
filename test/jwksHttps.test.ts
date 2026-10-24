import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
} from "../src/index.js";

const HTTP_URL = "http://gateway.example.com/.well-known/jwks.json";
const HTTPS_URL = "https://gateway.example.com/.well-known/jwks.json";
const REQUIRE_HTTPS_MSG =
  'JwksKeyStore: `requireHttps` requires https: for the JWKS endpoint, got "http:"';

/** A counting fetchImpl so tests can prove zero (or exactly one) fetch. */
function countingFetch(body: unknown): {
  impl: JwksFetchImpl;
  calls: string[];
} {
  const calls: string[] = [];
  const impl: JwksFetchImpl = async (url: string) => {
    calls.push(url);
    return { ok: true, status: 200, json: async () => body };
  };
  return { impl, calls };
}

test("jwks requireHttps: http endpoint allowed by default (regression)", () => {
  assert.doesNotThrow(() => new JwksKeyStore(HTTP_URL));
  // Explicit false is the same as the default.
  assert.doesNotThrow(
    () => new JwksKeyStore(HTTP_URL, { requireHttps: false }),
  );
  assert.doesNotThrow(() => new JwksKeyStore(HTTPS_URL));
});

test("jwks requireHttps: opt-in http throws at construction, zero fetches", () => {
  const { impl, calls } = countingFetch({ keys: [] });
  assert.throws(
    () => new JwksKeyStore(HTTP_URL, { requireHttps: true, fetchImpl: impl }),
    (err: unknown) =>
      err instanceof Error && err.message === REQUIRE_HTTPS_MSG,
  );
  assert.deepEqual(
    calls,
    [],
    "rejection must happen before any fetch is attempted",
  );
});

test("jwks requireHttps: uppercase HTTP: is rejected too", () => {
  const { impl, calls } = countingFetch({ keys: [] });
  assert.throws(
    () =>
      new JwksKeyStore("HTTP://gateway.example.com/jwks.json", {
        requireHttps: true,
        fetchImpl: impl,
      }),
    (err: unknown) =>
      err instanceof Error && err.message === REQUIRE_HTTPS_MSG,
  );
  assert.deepEqual(calls, []);
});

test("jwks requireHttps: https is unaffected and refreshes end to end", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const doc = { keys: [{ ...exportPublicKeyJwk(publicKey), kid: "ed-key-1" }] };
  const { impl, calls } = countingFetch(doc);
  const store = new JwksKeyStore(HTTPS_URL, {
    requireHttps: true,
    fetchImpl: impl,
  });
  await store.refresh();
  assert.deepEqual(calls, [HTTPS_URL]);
  const resolved = store.resolve("ed-key-1");
  assert.ok(resolved !== undefined);
  assert.equal(store.resolve("unknown"), undefined);
});

test("jwks requireHttps: illegal option values throw configuration errors", () => {
  for (const bad of ["yes", 1, 0, null, {}, []] as unknown[]) {
    assert.throws(
      () => new JwksKeyStore(HTTPS_URL, { requireHttps: bad as boolean }),
      (err: unknown) =>
        err instanceof Error &&
        err.message.startsWith(
          "JwksKeyStore: `requireHttps` must be a boolean",
        ),
      `expected throw for ${String(bad)}`,
    );
  }
});

test("jwks requireHttps: http refresh still works when the guard is off", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const doc = { keys: [{ ...exportPublicKeyJwk(publicKey), kid: "ed-key-1" }] };
  const { impl, calls } = countingFetch(doc);
  const store = new JwksKeyStore(HTTP_URL, { fetchImpl: impl });
  await store.refresh();
  assert.deepEqual(calls, [HTTP_URL]);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("jwks requireHttps: ftp endpoint still reports the protocol whitelist error", () => {
  // Check order: URL validity -> protocol whitelist -> https enforcement.
  assert.throws(
    () =>
      new JwksKeyStore("ftp://gateway.example.com/jwks.json", {
        requireHttps: true,
      }),
    /`url` must use http: or https:/,
  );
});

test("jwks requireHttps: invalid URL still reports URL validity first", () => {
  assert.throws(
    () => new JwksKeyStore("not a url", { requireHttps: true }),
    /`url` is not a valid URL/,
  );
});
