import test from "node:test";
import assert from "node:assert/strict";
import { type KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
  type JwksFetchResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";

/** One ed25519 key and the JWKS document publishing it. */
function edDoc(): {
  pair: { publicKey: KeyObject; privateKey: KeyObject };
  doc: { keys: unknown[] };
} {
  const pair = generateEd25519KeyPair();
  return {
    pair,
    doc: { keys: [{ ...exportPublicKeyJwk(pair.publicKey), kid: "ed-key-1" }] },
  };
}

/**
 * A stub response serving `doc` through `json()` and reporting an
 * optional `Cache-Control` header (looked up case-insensitively, like
 * the native `Headers`). No `text()`: the max-age read must work on
 * the `json()` path too, since it happens after the parse, not as
 * part of the body-limit machinery.
 */
function cacheControlResponse(
  cacheControl: string | null,
  doc: { keys: unknown[] },
): JwksFetchResponse {
  return {
    ok: true,
    status: 200,
    json: async () => doc,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "cache-control" ? cacheControl : null,
    },
  };
}

test("JwksKeyStore: max-age shorter than ttlSec makes the snapshot stale early", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () => cacheControlResponse("max-age=60", doc),
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  now = CREATED + 59;
  assert.equal(store.isStale(), false);
  now = CREATED + 60;
  assert.equal(store.isStale(), true);
  // Stale-but-serving: the key still resolves past the effective TTL.
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: max-age longer than ttlSec never extends the TTL", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () => cacheControlResponse("max-age=3600", doc),
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 300);
  now = CREATED + 299;
  assert.equal(store.isStale(), false);
  now = CREATED + 300;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: a missing Cache-Control header leaves ttlSec in force", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () => cacheControlResponse(null, doc),
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 300);
  now = CREATED + 299;
  assert.equal(store.isStale(), false);
  now = CREATED + 300;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: a malformed max-age leaves ttlSec in force", async () => {
  const { doc } = edDoc();
  for (const header of [
    "max-age=abc",
    "max-age=60abc",
    'max-age="60"',
    "max-age=",
    "no-store",
  ]) {
    let now = CREATED;
    const store = new JwksKeyStore(URL, {
      ttlSec: 300,
      now: () => now,
      fetchImpl: async () => cacheControlResponse(header, doc),
    });
    await store.refresh();
    assert.equal(store.effectiveTtlSec, 300, `header ${JSON.stringify(header)}`);
    now = CREATED + 299;
    assert.equal(store.isStale(), false, `header ${JSON.stringify(header)}`);
    now = CREATED + 300;
    assert.equal(store.isStale(), true, `header ${JSON.stringify(header)}`);
  }
});

test("JwksKeyStore: max-age=0 is stale immediately but still serves", async () => {
  const { doc } = edDoc();
  let fetchCalls = 0;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => CREATED,
    fetchImpl: (async () => {
      fetchCalls++;
      return cacheControlResponse("max-age=0", doc);
    }) as JwksFetchImpl,
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 0);
  assert.equal(store.isStale(), true);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  // refreshIfStale sees the immediate staleness and re-fetches.
  assert.equal(await store.refreshIfStale(), true);
  assert.equal(fetchCalls, 2);
});

test("JwksKeyStore: max-age is parsed out of a multi-directive Cache-Control", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () =>
      cacheControlResponse("public, max-age=60, must-revalidate", doc),
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  now = CREATED + 59;
  assert.equal(store.isStale(), false);
  now = CREATED + 60;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: max-age parsing is case-insensitive and tolerates spaces", async () => {
  const { doc } = edDoc();
  for (const header of ["MAX-AGE=60", "Max-Age=60", "max-age = 60"]) {
    const store = new JwksKeyStore(URL, {
      ttlSec: 300,
      now: () => CREATED,
      fetchImpl: async () => cacheControlResponse(header, doc),
    });
    await store.refresh();
    assert.equal(store.effectiveTtlSec, 60, `header ${JSON.stringify(header)}`);
  }
});

test("JwksKeyStore: a later refresh re-derives the effective TTL from its own header", async () => {
  const { doc } = edDoc();
  let header = "max-age=60";
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () => cacheControlResponse(header, doc),
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  header = "max-age=3600";
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 300);
  now = CREATED + 299;
  assert.equal(store.isStale(), false);
  now = CREATED + 300;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: a failed refresh never moves the effective TTL", async () => {
  const { doc } = edDoc();
  let mode: "ok" | "fail" = "ok";
  let now = CREATED;
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: (async () => {
      if (mode === "fail")
        return { ok: false, status: 500, json: async () => ({}) };
      return cacheControlResponse("max-age=60", doc);
    }) as JwksFetchImpl,
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  mode = "fail";
  await assert.rejects(store.refresh(), /HTTP 500/);
  assert.equal(store.effectiveTtlSec, 60);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  now = CREATED + 59;
  assert.equal(store.isStale(), false);
  now = CREATED + 60;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: a restored snapshot uses ttlSec, not a fetched max-age", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const fetched = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl: async () => cacheControlResponse("max-age=60", doc),
  });
  await fetched.refresh();
  assert.equal(fetched.effectiveTtlSec, 60);
  const snapshot = fetched.exportSnapshot();
  const restored = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
  });
  restored.restoreSnapshot(snapshot);
  assert.equal(restored.effectiveTtlSec, 300);
  now = CREATED + 299;
  assert.equal(restored.isStale(), false);
  now = CREATED + 300;
  assert.equal(restored.isStale(), true);
  assert.notEqual(restored.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: effectiveTtlSec is ttlSec before any refresh and after clear()", async () => {
  const { doc } = edDoc();
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => CREATED,
    fetchImpl: async () => cacheControlResponse("max-age=60", doc),
  });
  assert.equal(store.effectiveTtlSec, 300);
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  store.clear();
  assert.equal(store.effectiveTtlSec, 300);
  assert.equal(store.isStale(), true);
});
