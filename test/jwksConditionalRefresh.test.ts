import test from "node:test";
import assert from "node:assert/strict";
import { type KeyObject } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo, Socket } from "node:net";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
  type JwksFetchInit,
  type JwksFetchResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const SECRET = "conditional-refresh-test-secret-32b!";

/** One ed25519 key and the JWKS document publishing it. */
function edDoc(kid = "ed-key-1"): {
  pair: { publicKey: KeyObject; privateKey: KeyObject };
  doc: { keys: unknown[] };
} {
  const pair = generateEd25519KeyPair();
  return {
    pair,
    doc: { keys: [{ ...exportPublicKeyJwk(pair.publicKey), kid }] },
  };
}

/**
 * A stub response serving `doc` through `json()` and reporting an
 * `ETag` header (looked up case-insensitively, like the native
 * `Headers`). No `text()`: the ETag read must work on the `json()`
 * path too, since it happens after the parse, not as part of the
 * body-limit machinery.
 */
function etagResponse(
  etag: string | null,
  doc: { keys: unknown[] },
): JwksFetchResponse {
  return {
    ok: true,
    status: 200,
    json: async () => doc,
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "etag" ? etag : null,
    },
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

/** A recording fetch stub: each call logs the init it received. */
function recordingFetch(
  respond: (call: number) => JwksFetchResponse,
): { fetchImpl: JwksFetchImpl; calls: { url: string; init: JwksFetchInit | undefined }[] } {
  const calls: { url: string; init: JwksFetchInit | undefined }[] = [];
  const fetchImpl: JwksFetchImpl = async (url, init) => {
    calls.push({ url, init });
    return respond(calls.length);
  };
  return { fetchImpl, calls };
}

test("JwksKeyStore: a remembered ETag is sent as If-None-Match and a 304 keeps the snapshot but advances lastRefreshedAt", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const { fetchImpl, calls } = recordingFetch((call) =>
    call === 1 ? etagResponse('"v1"', doc) : notModifiedResponse(),
  );
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl,
  });
  await store.refresh();
  assert.equal(store.lastRefreshedAt, CREATED);
  assert.equal(store.size, 1);
  assert.deepEqual(calls[0]?.init, undefined);
  now = CREATED + 100;
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1]?.init, { headers: { "If-None-Match": '"v1"' } });
  // Same snapshot, only the freshness timestamp moved.
  assert.equal(store.size, 1);
  assert.deepEqual(store.keyIds(), ["ed-key-1"]);
  assert.equal(store.lastRefreshedAt, CREATED + 100);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: after a 304 the old key still resolves and verifies", async () => {
  const { pair, doc } = edDoc();
  let now = CREATED;
  const { fetchImpl } = recordingFetch((call) =>
    call === 1 ? etagResponse("W/\"v1\"", doc) : notModifiedResponse(),
  );
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl,
  });
  await store.refresh();
  now = CREATED + 100;
  await store.refresh();
  // Weak validators are opaque too: the same weak ETag is re-sent,
  // and the key the 304 kept is the same key material.
  const resolved = store.resolve("ed-key-1");
  assert.notEqual(resolved, undefined);
  assert.deepEqual(exportPublicKeyJwk(resolved as KeyObject), exportPublicKeyJwk(pair.publicKey));
});

test("JwksKeyStore: a changed ETag with a 200 swaps in the new snapshot", async () => {
  const first = edDoc("ed-key-1");
  const second = edDoc("ed-key-2");
  const { fetchImpl, calls } = recordingFetch((call) =>
    call === 1
      ? etagResponse('"v1"', first.doc)
      : etagResponse('"v2"', second.doc),
  );
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  assert.equal(store.resolve("ed-key-1") !== undefined, true);
  await store.refresh();
  assert.deepEqual(calls[1]?.init, { headers: { "If-None-Match": '"v1"' } });
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.notEqual(store.resolve("ed-key-2"), undefined);
  assert.deepEqual(store.stats(), {
    refreshes: 2,
    refreshFailures: 0,
    hits: 2,
    misses: 1,
    conditionalRefreshes: 1,
    notModified: 0,
    duplicateKids: 0,
  });
});

test("JwksKeyStore: a response without an ETag sends no conditional header on the next refresh", async () => {
  const { doc } = edDoc();
  const { fetchImpl, calls } = recordingFetch(() => etagResponse(null, doc));
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0]?.init, undefined);
  assert.deepEqual(calls[1]?.init, undefined);
  assert.equal(store.stats().conditionalRefreshes, 0);
});

test("JwksKeyStore: an empty ETag header is not remembered", async () => {
  const { doc } = edDoc();
  const { fetchImpl, calls } = recordingFetch(() => etagResponse("", doc));
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  await store.refresh();
  assert.deepEqual(calls[1]?.init, undefined);
  assert.equal(store.stats().conditionalRefreshes, 0);
});

test("JwksKeyStore: a 304 never calls json() and works without a json() method at all", async () => {
  const { doc } = edDoc();
  // First store: the 304 carries a json() that throws if called.
  const throwing = recordingFetch((call) =>
    call === 1 ? etagResponse('"v1"', doc) : notModifiedResponse(),
  );
  const store = new JwksKeyStore(URL, {
    now: () => CREATED,
    fetchImpl: throwing.fetchImpl,
  });
  await store.refresh();
  await store.refresh(); // would throw if json() were called on the 304
  assert.equal(store.size, 1);
  assert.equal(store.stats().notModified, 1);

  // Second store: the 304 response offers no json() method at all.
  let calls = 0;
  const bare: JwksFetchImpl = async () => {
    calls++;
    if (calls === 1) return etagResponse('"v1"', doc);
    return { ok: false, status: 304 } as JwksFetchResponse;
  };
  const bareStore = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl: bare });
  await bareStore.refresh();
  await bareStore.refresh();
  assert.equal(bareStore.size, 1);
  assert.equal(bareStore.stats().notModified, 1);
});

test("JwksKeyStore: clear() drops the remembered ETag", async () => {
  const { doc } = edDoc();
  const { fetchImpl, calls } = recordingFetch(() => etagResponse('"v1"', doc));
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  assert.equal(store.stats().conditionalRefreshes, 0);
  store.clear();
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
  });
  await store.refresh();
  assert.deepEqual(calls[1]?.init, undefined);
});

test("JwksKeyStore: restoring a snapshot drops the remembered ETag", async () => {
  const { doc } = edDoc();
  const fetched = new JwksKeyStore(URL, {
    now: () => CREATED,
    fetchImpl: async () => etagResponse('"v1"', doc),
  });
  await fetched.refresh();
  const snapshot = fetched.exportSnapshot();

  const { fetchImpl, calls } = recordingFetch(() => etagResponse('"v2"', doc));
  const restored = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  restored.restoreSnapshot(snapshot);
  await restored.refresh();
  // The restored snapshot was never fetched with a validator, so
  // the refresh after the restore is unconditional.
  assert.deepEqual(calls[0]?.init, undefined);
  assert.notEqual(restored.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: restoring a signed snapshot drops the remembered ETag", async () => {
  const { doc } = edDoc();
  const fetched = new JwksKeyStore(URL, {
    now: () => CREATED,
    fetchImpl: async () => etagResponse('"v1"', doc),
  });
  await fetched.refresh();
  const envelope = fetched.exportSignedSnapshot(SECRET);

  const { fetchImpl, calls } = recordingFetch(() => etagResponse('"v2"', doc));
  const restored = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  restored.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), SECRET);
  await restored.refresh();
  assert.deepEqual(calls[0]?.init, undefined);
  assert.notEqual(restored.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: a custom fetchImpl receives the If-None-Match header as its second argument", async () => {
  const { doc } = edDoc();
  const seen: (JwksFetchInit | undefined)[] = [];
  const fetchImpl: JwksFetchImpl = async (_url, init) => {
    seen.push(init);
    return seen.length === 1
      ? etagResponse('"v1"', doc)
      : notModifiedResponse();
  };
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  await store.refresh();
  assert.equal(seen.length, 2);
  assert.equal(seen[0], undefined);
  assert.deepEqual(seen[1], { headers: { "If-None-Match": '"v1"' } });
});

test("JwksKeyStore: a legacy single-argument fetchImpl still works", async () => {
  const { doc } = edDoc();
  let calls = 0;
  // Deliberately one parameter: the store must not require the
  // second argument to be accepted.
  const legacy = (async () => {
    calls++;
    return etagResponse('"v1"', doc);
  }) as JwksFetchImpl;
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl: legacy });
  await store.refresh();
  await store.refresh();
  assert.equal(calls, 2);
  assert.equal(store.size, 1);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
});

test("JwksKeyStore: stats() counts conditionalRefreshes and notModified", async () => {
  const { doc } = edDoc();
  const { fetchImpl } = recordingFetch((call) => {
    if (call === 1) return etagResponse('"v1"', doc);
    if (call === 2) return notModifiedResponse();
    return etagResponse('"v2"', doc);
  });
  const store = new JwksKeyStore(URL, { now: () => CREATED, fetchImpl });
  await store.refresh();
  assert.deepEqual(store.stats(), {
    refreshes: 1,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
  });
  await store.refresh(); // 304
  assert.deepEqual(store.stats(), {
    refreshes: 2,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 1,
    notModified: 1,
    duplicateKids: 0,
  });
  await store.refresh(); // 200 with a new ETag
  assert.deepEqual(store.stats(), {
    refreshes: 3,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 2,
    notModified: 1,
    duplicateKids: 0,
  });
});

test("JwksKeyStore: a 304 does not move the effective TTL", async () => {
  const { doc } = edDoc();
  let now = CREATED;
  const { fetchImpl } = recordingFetch((call) => {
    if (call === 1)
      return {
        ok: true,
        status: 200,
        json: async () => doc,
        headers: {
          get: (name: string) => {
            if (name.toLowerCase() === "etag") return '"v1"';
            if (name.toLowerCase() === "cache-control") return "max-age=60";
            return null;
          },
        },
      };
    return notModifiedResponse();
  });
  const store = new JwksKeyStore(URL, {
    ttlSec: 300,
    now: () => now,
    fetchImpl,
  });
  await store.refresh();
  assert.equal(store.effectiveTtlSec, 60);
  now = CREATED + 30;
  await store.refresh(); // 304 at +30s
  assert.equal(store.effectiveTtlSec, 60);
  assert.equal(store.isStale(), false);
  now = CREATED + 89;
  assert.equal(store.isStale(), false);
  now = CREATED + 90;
  assert.equal(store.isStale(), true);
});

test("JwksKeyStore: a 304 is a success, never retried", async () => {
  const { doc } = edDoc();
  const { fetchImpl, calls } = recordingFetch((call) =>
    call === 1 ? etagResponse('"v1"', doc) : notModifiedResponse(),
  );
  const store = new JwksKeyStore(URL, {
    now: () => CREATED,
    fetchImpl,
    fetchRetries: 2,
    fetchBackoffMs: 0,
  });
  await store.refresh();
  await store.refresh();
  assert.equal(calls.length, 2);
  assert.equal(store.stats().refreshFailures, 0);
  assert.equal(store.stats().notModified, 1);
});

test("JwksKeyStore: a 304 that landed over plaintext http is rejected under requireHttps", async () => {
  const { doc } = edDoc();
  const { fetchImpl } = recordingFetch((call) => {
    if (call === 1) return etagResponse('"v1"', doc);
    return { ...notModifiedResponse(), url: "http://gateway.example.com/.well-known/jwks.json" };
  });
  const store = new JwksKeyStore(URL, {
    now: () => CREATED,
    fetchImpl,
    requireHttps: true,
  });
  await store.refresh();
  await assert.rejects(store.refresh(), /redirected to insecure http/);
  // The rejected 304 leaves the snapshot and its freshness untouched.
  assert.equal(store.lastRefreshedAt, CREATED);
  assert.notEqual(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().notModified, 0);
});

test("JwksKeyStore: the default fetch sends If-None-Match and a loopback 304 keeps the snapshot", async () => {
  // Regression test (backlog #1184): the default fetch used to be
  // `(u) => globalThis.fetch(u)`, which dropped the init carrying
  // `If-None-Match` — so no conditional request ever went out on the
  // default path (only `fetchTimeoutMs` forwarded the header), the
  // endpoint always re-served the document, and `notModified` stayed
  // 0 while `conditionalRefreshes` still counted 1. The store now
  // forwards the init, so a real loopback endpoint sees the header
  // and answers 304.
  const { pair, doc } = edDoc("loopback-key-1");
  const etag = '"loopback-v1"';
  let requests = 0;
  const ifNoneMatchSeen: Array<string | string[] | undefined> = [];
  const sockets = new Set<Socket>();
  const server = createServer((req, res) => {
    requests++;
    ifNoneMatchSeen.push(req.headers["if-none-match"]);
    const inm = req.headers["if-none-match"];
    if (typeof inm === "string" && inm === etag) {
      res.writeHead(304, { etag });
      res.end();
      return;
    }
    res.setHeader("content-type", "application/json");
    res.setHeader("etag", etag);
    res.end(JSON.stringify(doc));
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => {
      sockets.delete(socket);
    });
  });
  try {
    const port = await new Promise<AddressInfo>((resolve, reject) => {
      server.on("error", reject);
      server.listen(0, "127.0.0.1", () => {
        resolve(server.address() as AddressInfo);
      });
    }).then((info) => info.port);
    let now = CREATED;
    const store = new JwksKeyStore(
      `http://127.0.0.1:${port}/.well-known/jwks.json`,
      { ttlSec: 300, now: () => now },
    );
    await store.refresh();
    assert.equal(requests, 1);
    assert.deepEqual(ifNoneMatchSeen, [undefined]);
    assert.deepEqual(store.keyIds(), ["loopback-key-1"]);
    assert.notEqual(store.resolve("loopback-key-1"), undefined);
    now = CREATED + 100;
    await store.refresh();
    assert.equal(requests, 2);
    assert.deepEqual(ifNoneMatchSeen, [undefined, etag]);
    // Same snapshot, only the freshness timestamp moved — and the
    // kept key is the same key material.
    assert.deepEqual(store.keyIds(), ["loopback-key-1"]);
    assert.equal(store.lastRefreshedAt, CREATED + 100);
    const resolved = store.resolve("loopback-key-1");
    assert.notEqual(resolved, undefined);
    assert.deepEqual(
      exportPublicKeyJwk(resolved as KeyObject),
      exportPublicKeyJwk(pair.publicKey),
    );
    assert.deepEqual(store.stats(), {
      refreshes: 2,
      refreshFailures: 0,
      hits: 2,
      misses: 0,
      conditionalRefreshes: 1,
      notModified: 1,
      duplicateKids: 0,
    });
  } finally {
    for (const socket of sockets) socket.destroy();
    server.close();
  }
});
