import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";

function docFor(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  kid = "ed-key-1",
) {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

function stubFetch(body: unknown): JwksFetchImpl {
  return async () => ({ ok: true, status: 200, json: async () => body });
}

test("jwks maxStaleSec: the constructor rejects a non-positive or non-finite cutoff", () => {
  for (const bad of [0, -1, -60, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () =>
        new JwksKeyStore(URL, {
          maxStaleSec: bad,
          fetchImpl: stubFetch({ keys: [] }),
        }),
      /JwksKeyStore: `maxStaleSec` must be a finite number > 0/,
    );
  }
  assert.throws(
    () =>
      new JwksKeyStore(URL, {
        // @ts-expect-error a non-number cutoff is a caller bug
        maxStaleSec: "60",
        fetchImpl: stubFetch({ keys: [] }),
      }),
    /JwksKeyStore: `maxStaleSec` must be a finite number > 0/,
  );
});

test("jwks maxStaleSec: unset, a stale snapshot still resolves (advisory staleness unchanged)", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 120,
    now: () => t,
  });
  await store.refresh();
  t = CREATED + 121; // past the TTL: isStale() flips, resolution does not
  assert.equal(store.isStale(), true);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  assert.equal(store.stats().staleResolutions, 0);
});

test("jwks maxStaleSec: set, an over-age snapshot refuses every keyid and counts the refusal", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 300,
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  assert.ok(store.resolve("ed-key-1") !== undefined);
  t = CREATED + 119;
  assert.ok(store.resolve("ed-key-1") !== undefined);
  t = CREATED + 121; // past the cutoff, still inside the 300s TTL
  assert.equal(store.isStale(), false);
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.equal(store.resolve("ed-key-1"), undefined);
  const stats = store.stats();
  assert.equal(stats.staleResolutions, 2);
  assert.equal(stats.misses, 2); // every cutoff refusal is also a miss
  assert.equal(stats.hits, 2);
  assert.equal(stats.hits + stats.misses, 4);
});

test("jwks maxStaleSec: the boundary is inclusive — exactly at the cutoff still resolves", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 300,
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  t = CREATED + 120; // exactly at the bound
  assert.ok(store.resolve("ed-key-1") !== undefined);
  t = CREATED + 121; // one second past it
  assert.equal(store.resolve("ed-key-1"), undefined);
});

test("jwks maxStaleSec: a snapshot stale by the TTL still resolves until the cutoff", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 60,
    maxStaleSec: 300,
    now: () => t,
  });
  await store.refresh();
  t = CREATED + 120; // stale by the TTL, inside the cutoff
  assert.equal(store.isStale(), true);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  t = CREATED + 301; // past the cutoff too
  assert.equal(store.resolve("ed-key-1"), undefined);
});

test("jwks maxStaleSec: a successful refresh after a refusal serves keys again", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 300,
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  assert.ok(store.resolve("ed-key-1") !== undefined);
  t = CREATED + 121;
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().staleResolutions, 1);
  await store.refresh();
  assert.equal(store.lastRefreshedAt, CREATED + 121);
  assert.ok(store.resolve("ed-key-1") !== undefined);
  // The refusal count is cumulative history, not reset by the refresh.
  assert.equal(store.stats().staleResolutions, 1);
  assert.equal(store.stats().hits, 2);
});

test("jwks maxStaleSec: an unknown keyid on an over-age snapshot counts as a stale refusal", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 300,
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  t = CREATED + 121;
  assert.equal(store.resolve("retired-key"), undefined);
  assert.equal(store.stats().staleResolutions, 1);
  assert.equal(store.stats().misses, 1);
});

test("jwks maxStaleSec: a restored snapshot is judged from its fetchedAtSec", async () => {
  const { publicKey } = generateEd25519KeyPair();
  const source = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    now: () => CREATED,
  });
  await source.refresh();
  const snapshot = source.exportSnapshot();

  const old = JwksKeyStore.restore(snapshot, URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    maxStaleSec: 120,
    now: () => CREATED + 121,
  });
  assert.equal(old.lastRefreshedAt, CREATED);
  assert.equal(old.resolve("ed-key-1"), undefined);
  assert.equal(old.stats().staleResolutions, 1);

  const fresh = JwksKeyStore.restore(snapshot, URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    maxStaleSec: 120,
    now: () => CREATED + 60,
  });
  assert.ok(fresh.resolve("ed-key-1") !== undefined);
  assert.equal(fresh.stats().staleResolutions, 0);
});

test("jwks maxStaleSec: a non-finite clock throws from resolve() while the cutoff is set, and never throws without it", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t: number = CREATED;
  const gated = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    maxStaleSec: 120,
    now: () => t,
  });
  await gated.refresh();
  const before = gated.stats();
  t = Number.NaN;
  assert.throws(
    () => gated.resolve("ed-key-1"),
    /JwksKeyStore: clock must return a finite number of seconds since the epoch/,
  );
  // The failed call leaves no residue: no counters moved.
  assert.deepEqual(gated.stats(), before);

  const ungated = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    now: () => t,
  });
  t = CREATED; // good clock again for the priming refresh
  await ungated.refresh();
  t = Number.NaN; // the clock goes bad only after a good refresh
  assert.ok(ungated.resolve("ed-key-1") !== undefined);
});

test("jwks maxStaleSec: verifyRequest fails a stale snapshot closed as KEY_RESOLUTION_FAILED", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    ttlSec: 300,
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "ed-key-1", alg: "ed25519", key: privateKey, created: CREATED },
  );
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
  t = CREATED + 121; // past the cutoff
  const failed = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(failed.ok, false);
  assert.equal(failed.code, "KEY_RESOLUTION_FAILED");
});

test("jwks maxStaleSec: clear() resets the stale-resolution count with the rest", async () => {
  const { publicKey } = generateEd25519KeyPair();
  let t = CREATED;
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(docFor(publicKey)),
    maxStaleSec: 120,
    now: () => t,
  });
  await store.refresh();
  t = CREATED + 121;
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.equal(store.stats().staleResolutions, 1);
  store.clear();
  assert.deepEqual(store.stats(), {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
    staleResolutions: 0,
  });
});
