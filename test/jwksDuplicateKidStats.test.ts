import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, type KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const SECRET = "duplicate-kid-stats-test-secret-at-least-32-bytes-long";
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function stubFetch(body: unknown): JwksFetchImpl {
  return async () => ({ ok: true, status: 200, json: async () => body });
}

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function docFor(
  entries: Array<{
    kid: string;
    publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  }>,
): { keys: unknown[] } {
  return {
    keys: entries.map(({ kid, publicKey }) => ({
      ...exportPublicKeyJwk(publicKey),
      kid,
    })),
  };
}

function signAs(keyId: string, privateKey: KeyObject): SignedHttpRequest {
  return signRequest(freshReq(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

/**
 * The same canonical-JSON shape `computeSnapshotMac` in `jwks.ts`
 * MACs (sorted keys, no whitespace), re-implemented here so the
 * test can hand-build a signed envelope carrying a duplicate kid —
 * `exportSignedSnapshot()` only ever exports the deduplicated
 * snapshot, so no library call can produce one.
 */
function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new Error(`cannot canonicalize a non-JSON value of type ${typeof value}`);
}

function signedEnvelope(snapshot: unknown): {
  v: number;
  snapshot: unknown;
  mac: string;
} {
  return {
    v: 1,
    snapshot,
    mac: createHmac("sha256", SECRET)
      .update(canonicalJson(snapshot), "utf8")
      .digest("hex"),
  };
}

function zeroStats(): Record<string, number> {
  return {
    refreshes: 0,
    refreshFailures: 0,
    hits: 0,
    misses: 0,
    conditionalRefreshes: 0,
    notModified: 0,
    duplicateKids: 0,
    staleResolutions: 0,
  };
}

test("jwks duplicateKids: a fresh store starts at zero", () => {
  const store = new JwksKeyStore(URL, { fetchImpl: stubFetch({ keys: [] }) });
  assert.deepEqual(store.stats(), zeroStats());
});

test("jwks duplicateKids: duplicate kid refresh serves the later key and counts 1", async () => {
  const oldKeys = generateEd25519KeyPair();
  const newKeys = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(
      docFor([
        { kid: "k", publicKey: oldKeys.publicKey },
        { kid: "k", publicKey: newKeys.publicKey },
      ]),
    ),
  });
  await store.refresh();

  assert.equal(store.stats().duplicateKids, 1);
  assert.equal(store.stats().refreshes, 1);
  // The later entry wins: the resolved key is the new one.
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("k")!),
    exportPublicKeyJwk(newKeys.publicKey),
  );
  // A signature under the new key verifies; one under the retired
  // first key fails against the served (new) key.
  assert.equal(
    verifyRequest(signAs("k", newKeys.privateKey), {
      keyResolver: store.resolve,
    }).ok,
    true,
  );
  const stale = verifyRequest(signAs("k", oldKeys.privateKey), {
    keyResolver: store.resolve,
  });
  assert.equal(stale.ok, false);
  if (!stale.ok) assert.equal(stale.code, "SIGNATURE_MISMATCH");
});

test("jwks duplicateKids: the same kid three times counts 2", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(
      docFor([
        { kid: "k", publicKey: a.publicKey },
        { kid: "k", publicKey: b.publicKey },
        { kid: "k", publicKey: c.publicKey },
      ]),
    ),
  });
  await store.refresh();

  assert.equal(store.stats().duplicateKids, 2);
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("k")!),
    exportPublicKeyJwk(c.publicKey),
  );
});

test("jwks duplicateKids: distinct kids count 0", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(
      docFor([
        { kid: "k1", publicKey: a.publicKey },
        { kid: "k2", publicKey: b.publicKey },
      ]),
    ),
  });
  await store.refresh();

  assert.equal(store.stats().duplicateKids, 0);
  assert.ok(store.resolve("k1"));
  assert.ok(store.resolve("k2"));
});

test("jwks duplicateKids: two kids duplicated once each count 2", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  const d = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(
      docFor([
        { kid: "k1", publicKey: a.publicKey },
        { kid: "k1", publicKey: b.publicKey },
        { kid: "k2", publicKey: c.publicKey },
        { kid: "k2", publicKey: d.publicKey },
      ]),
    ),
  });
  await store.refresh();

  assert.equal(store.stats().duplicateKids, 2);
});

test("jwks duplicateKids: counts accumulate across refreshes", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  const d = generateEd25519KeyPair();
  let doc = docFor([
    { kid: "k", publicKey: a.publicKey },
    { kid: "k", publicKey: b.publicKey },
  ]);
  // The fetch stub reads the mutable holder, so reassigning `doc`
  // changes what the next refresh fetches.
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    }),
  });
  await store.refresh();
  assert.equal(store.stats().duplicateKids, 1);

  doc = docFor([
    { kid: "k", publicKey: c.publicKey },
    { kid: "k", publicKey: d.publicKey },
  ]);
  await store.refresh();
  assert.equal(store.stats().duplicateKids, 2);
  assert.equal(store.stats().refreshes, 2);
});

test("jwks duplicateKids: snapshot restore counts duplicates the same way", () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, { fetchImpl: noFetch });
  store.restoreSnapshot({
    v: 1,
    fetchedAtSec: CREATED,
    keys: [
      { ...exportPublicKeyJwk(a.publicKey), kid: "k" },
      { ...exportPublicKeyJwk(b.publicKey), kid: "k" },
    ],
  });

  assert.equal(store.stats().duplicateKids, 1);
  assert.equal(store.stats().refreshes, 0);
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("k")!),
    exportPublicKeyJwk(b.publicKey),
  );
});

test("jwks duplicateKids: signed snapshot restore counts duplicates", () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, { fetchImpl: noFetch });
  store.restoreSignedSnapshot(
    signedEnvelope({
      v: 1,
      fetchedAtSec: CREATED,
      keys: [
        { ...exportPublicKeyJwk(a.publicKey), kid: "k" },
        { ...exportPublicKeyJwk(b.publicKey), kid: "k" },
      ],
    }),
    SECRET,
  );

  assert.equal(store.stats().duplicateKids, 1);
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("k")!),
    exportPublicKeyJwk(b.publicKey),
  );
});

test("jwks duplicateKids: an exported old snapshot still verifies after a duplicate refresh", async () => {
  const oldKeys = generateEd25519KeyPair();
  const newKeys = generateEd25519KeyPair();
  let doc = docFor([{ kid: "k", publicKey: oldKeys.publicKey }]);
  // The fetch stub reads the mutable holder, so reassigning `doc`
  // changes what the next refresh fetches.
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    }),
  });
  await store.refresh();
  const exported = store.exportSnapshot();

  // The publisher re-issues kid "k" for a new key version: the
  // first key is silently retired from the live snapshot.
  doc = docFor([
    { kid: "k", publicKey: oldKeys.publicKey },
    { kid: "k", publicKey: newKeys.publicKey },
  ]);
  await store.refresh();
  assert.equal(store.stats().duplicateKids, 1);
  assert.equal(
    verifyRequest(signAs("k", oldKeys.privateKey), {
      keyResolver: store.resolve,
    }).ok,
    false,
  );

  // The exported old snapshot restores offline and the old key
  // verifies through it again; the restore adds nothing to the
  // counter (the export is deduplicated) and does not reset it.
  store.restoreSnapshot(exported);
  assert.equal(store.stats().duplicateKids, 1);
  assert.equal(
    verifyRequest(signAs("k", oldKeys.privateKey), {
      keyResolver: store.resolve,
    }).ok,
    true,
  );
});

test("jwks duplicateKids: clear() resets the counter with the others", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(
      docFor([
        { kid: "k", publicKey: a.publicKey },
        { kid: "k", publicKey: b.publicKey },
      ]),
    ),
  });
  await store.refresh();
  assert.ok(store.resolve("k")); // a hit before the clear
  assert.equal(store.stats().duplicateKids, 1);

  store.clear();
  assert.deepEqual(store.stats(), zeroStats());
});

test("jwks duplicateKids: a failed refresh leaves the counter untouched", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  let doc: unknown = docFor([
    { kid: "k", publicKey: a.publicKey },
    { kid: "k", publicKey: b.publicKey },
  ]);
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => doc,
    }),
  });
  await store.refresh();
  assert.equal(store.stats().duplicateKids, 1);

  // A document that repeats the kid and then fails on a later
  // entry: the repeat must not count, because the refresh fails
  // before the swap.
  const c = generateEd25519KeyPair();
  doc = {
    keys: [
      { ...exportPublicKeyJwk(a.publicKey), kid: "k" },
      { ...exportPublicKeyJwk(b.publicKey), kid: "k" },
      { ...exportPublicKeyJwk(c.publicKey), kid: "bad", kty: "unknown" },
    ],
  };
  await assert.rejects(store.refresh(), /invalid JWKS/);
  assert.equal(store.stats().duplicateKids, 1);
  assert.equal(store.stats().refreshFailures, 1);
  // The old snapshot still serves the previously installed key.
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("k")!),
    exportPublicKeyJwk(b.publicKey),
  );
});
