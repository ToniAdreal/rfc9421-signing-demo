import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function keyMaterial() {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const rsa = generateRsaPssKeyPair();
  return { ed, p256, rsa };
}

type Keys = ReturnType<typeof keyMaterial>;

function jwksDocument({ ed, p256, rsa }: Keys): { keys: unknown[] } {
  return {
    keys: [
      { ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1" },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1" },
    ],
  };
}

function stubFetch(body: unknown): JwksFetchImpl {
  return async () => ({ ok: true, status: 200, json: async () => body });
}

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function signAs(
  keyId: string,
  alg: "ed25519" | "ecdsa-p256-sha256" | "rsa-pss-sha512",
  privateKey: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId, alg, key: privateKey, created: CREATED });
}

async function refreshedStore(
  keys: Keys,
  now: () => number,
  ttlSec = 300,
): Promise<JwksKeyStore> {
  const store = new JwksKeyStore(URL, {
    fetchImpl: stubFetch(jwksDocument(keys)),
    ttlSec,
    now,
  });
  await store.refresh();
  return store;
}

test("JwksKeyStore snapshot: export -> JSON round-trip -> static restore resolves offline and verifies all three key types", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const snapshot: JwksKeyStoreSnapshot = original.exportSnapshot();
  assert.equal(snapshot.v, 1);
  assert.equal(snapshot.fetchedAtSec, 1_700_000_500);
  assert.equal(snapshot.keys.length, 3);
  assert.deepEqual(
    snapshot.keys.map((k) => k.kid).sort(),
    ["ed-key-1", "p256-key-1", "rsa-key-1"],
  );
  // Only public material is exported: no entry may carry a "d".
  for (const k of snapshot.keys) assert.equal("d" in k, false);

  // Restore through the persisted (JSON) form into a store whose
  // fetch always throws: resolution and verification are fully offline.
  const persisted: unknown = JSON.parse(JSON.stringify(snapshot));
  const restored = JwksKeyStore.restore(persisted, URL, {
    fetchImpl: noFetch,
    ttlSec: 300,
    now: () => t,
  });
  assert.equal(restored.endpoint, URL);
  assert.equal(restored.size, 3);
  assert.equal(restored.lastRefreshedAt, 1_700_000_500);
  assert.equal(restored.isStale(), false);

  const cases: Array<[string, SignedHttpRequest]> = [
    ["ed-key-1", signAs("ed-key-1", "ed25519", keys.ed.privateKey)],
    ["p256-key-1", signAs("p256-key-1", "ecdsa-p256-sha256", keys.p256.privateKey)],
    ["rsa-key-1", signAs("rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey)],
  ];
  for (const [keyId, signed] of cases) {
    const res = verifyRequest(signed, { keyResolver: restored.resolve, now: CREATED });
    assert.equal(res.ok, true, keyId);
    assert.equal(res.keyId, keyId);
  }

  // The fromSnapshot alias produces an equivalent store.
  const viaAlias = JwksKeyStore.fromSnapshot(persisted, URL, {
    fetchImpl: noFetch,
    now: () => t,
  });
  assert.equal(viaAlias.size, 3);
  assert.equal(
    viaAlias.resolve("ed-key-1")?.export({ format: "pem", type: "spki" }).toString(),
    keys.ed.publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
});

test("JwksKeyStore snapshot: staleness counts from the original fetchedAtSec — restoring never renews freshness", async () => {
  const keys = keyMaterial();
  let t = 1_700_000_000;
  const original = await refreshedStore(keys, () => t, 120);
  const snapshot = original.exportSnapshot();

  // Restore at the same wall time: fresh.
  const atFetch = JwksKeyStore.restore(snapshot, URL, {
    fetchImpl: noFetch,
    ttlSec: 120,
    now: () => t,
  });
  assert.equal(atFetch.isStale(), false);

  // One second before the original TTL boundary: still fresh.
  t = 1_700_000_000 + 119;
  assert.equal(atFetch.isStale(), false);

  // Exactly at the boundary counted from the ORIGINAL fetch (not from
  // the restore, which happened 0 seconds of TTL ago at export time):
  // the restored store is stale, exactly as the original is.
  t = 1_700_000_000 + 120;
  assert.equal(original.isStale(), true);
  assert.equal(atFetch.isStale(), true);
  // Staleness is advisory, not a cutoff: the keys still resolve.
  assert.ok(atFetch.resolve("ed-key-1") !== undefined);

  // Instance restore into a store created later tells the same story.
  const late = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 120, now: () => t });
  late.restoreSnapshot(snapshot);
  assert.equal(late.lastRefreshedAt, 1_700_000_000);
  assert.equal(late.isStale(), true);
});

test("JwksKeyStore snapshot: an entry carrying private \"d\" material is rejected, and a failed instance restore leaves the old snapshot untouched", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_000;
  const store = await refreshedStore(keys, () => t);
  const good = store.exportSnapshot();
  const poisoned = {
    v: 1,
    fetchedAtSec: t,
    keys: [
      {
        ...exportPublicKeyJwk(keys.ed.publicKey),
        kid: "ed-key-1",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    ],
  };
  assert.throws(() => JwksKeyStore.restore(poisoned, URL), /private key material/);
  assert.throws(() => store.restoreSnapshot(poisoned), /private key material/);
  // Fail-closed and atomic: the previously refreshed snapshot survives.
  assert.equal(store.size, 3);
  assert.equal(store.lastRefreshedAt, t);
  assert.deepEqual(store.exportSnapshot(), good);
  const signed = signAs("rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
});

test("JwksKeyStore snapshot: unknown kty and unsupported curve are rejected", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_000;
  const base = { v: 1, fetchedAtSec: t };
  assert.throws(
    () =>
      JwksKeyStore.restore(
        { ...base, keys: [{ kty: "oct", kid: "sym-1", k: "AAAA" }] },
        URL,
      ),
    /unsupported kty/,
  );
  assert.throws(
    () =>
      JwksKeyStore.restore(
        {
          ...base,
          keys: [
            { ...exportPublicKeyJwkP256(keys.p256.publicKey), crv: "P-384", kid: "p384-1" },
          ],
        },
        URL,
      ),
    /expected crv "P-256"/,
  );
});

test("JwksKeyStore snapshot: malformed snapshots throw — bad version, non-array keys, missing kid, unknown field", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_000;
  const goodKey = { ...exportPublicKeyJwk(keys.ed.publicKey), kid: "ed-key-1" };
  const cases: Array<[string, unknown, RegExp]> = [
    ["null snapshot", null, /expected an object/],
    ["array snapshot", [], /expected an object/],
    ["unsupported version", { v: 2, fetchedAtSec: t, keys: [goodKey] }, /unsupported snapshot version 2/],
    ["missing version", { fetchedAtSec: t, keys: [goodKey] }, /unsupported snapshot version undefined/],
    ["keys not an array", { v: 1, fetchedAtSec: t, keys: { "ed-key-1": goodKey } }, /"keys" must be an array/],
    ["negative fetchedAtSec", { v: 1, fetchedAtSec: -1, keys: [goodKey] }, /fetchedAtSec must be a finite non-negative number/],
    ["NaN fetchedAtSec", { v: 1, fetchedAtSec: Number.NaN, keys: [goodKey] }, /fetchedAtSec must be a finite non-negative number/],
    ["unknown top-level field", { v: 1, fetchedAtSec: t, keys: [goodKey], extra: 1 }, /unknown field "extra"/],
    ["entry not an object", { v: 1, fetchedAtSec: t, keys: ["nope"] }, /keys\[0\] must be a JWK object/],
    // Kid-less entries are skipped by refresh() but fatal in a
    // snapshot: this store's own export format cannot legitimately
    // contain one.
    ["entry without kid", { v: 1, fetchedAtSec: t, keys: [exportPublicKeyJwk(keys.ed.publicKey)] }, /kid must be a non-empty string/],
    ["entry with empty kid", { v: 1, fetchedAtSec: t, keys: [{ ...goodKey, kid: "" }] }, /kid must be a non-empty string/],
  ];
  for (const [name, snapshot, re] of cases) {
    assert.throws(() => JwksKeyStore.restore(snapshot, URL), re, name);
    const store = new JwksKeyStore(URL, { fetchImpl: noFetch });
    assert.throws(() => store.restoreSnapshot(snapshot), re, name);
    assert.equal(store.size, 0, name);
    assert.equal(store.lastRefreshedAt, null, name);
  }
});

test("JwksKeyStore snapshot: mutating the exported object does not affect the original store", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_000;
  const store = await refreshedStore(keys, () => t);
  const snapshot = store.exportSnapshot();

  // Tamper with every layer of the exported copy.
  const first = snapshot.keys[0];
  assert.ok(first !== undefined);
  if (first.kty === "OKP") first.x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  first.kid = "tampered-kid";
  snapshot.keys.push({
    ...exportPublicKeyJwk(generateEd25519KeyPair().publicKey),
    kid: "injected-key",
  });
  snapshot.fetchedAtSec = 0;

  assert.equal(store.size, 3);
  assert.equal(store.lastRefreshedAt, t);
  assert.equal(store.resolve("tampered-kid"), undefined);
  assert.equal(store.resolve("injected-key"), undefined);
  // The real key still verifies: its exported material was a copy.
  const signed = signAs("ed-key-1", "ed25519", keys.ed.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
  // And a fresh export is unaffected by the tampered one.
  const fresh = store.exportSnapshot();
  assert.equal(fresh.fetchedAtSec, t);
  assert.deepEqual(
    fresh.keys.map((k) => k.kid).sort(),
    ["ed-key-1", "p256-key-1", "rsa-key-1"],
  );
});

test("JwksKeyStore snapshot: exporting before any successful refresh throws; a zero-key refresh exports a valid empty snapshot", async () => {
  const never = new JwksKeyStore(URL, { fetchImpl: noFetch });
  assert.throws(() => never.exportSnapshot(), /before a successful refresh/);

  // A refresh whose document carries only kid-less entries succeeds
  // and imports zero keys — that snapshot is legitimately exportable.
  const keys = keyMaterial();
  const t = 1_700_000_000;
  const empty = new JwksKeyStore(URL, {
    fetchImpl: stubFetch({ keys: [exportPublicKeyJwk(keys.ed.publicKey)] }),
    now: () => t,
  });
  await empty.refresh();
  assert.equal(empty.size, 0);
  const snapshot = empty.exportSnapshot();
  assert.deepEqual(snapshot, { v: 1, fetchedAtSec: t, keys: [] });
  const restored = JwksKeyStore.restore(snapshot, URL, {
    fetchImpl: noFetch,
    now: () => t,
  });
  assert.equal(restored.size, 0);
  assert.equal(restored.lastRefreshedAt, t);
  assert.equal(restored.isStale(), false);
});
