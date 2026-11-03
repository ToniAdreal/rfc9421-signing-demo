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
  type JwksSignedSnapshotEnvelope,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";
const SECRET = "signed-snapshot-test-secret-at-least-32-bytes-long";
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

function verifyAll(
  keys: Keys,
  restored: JwksKeyStore,
): void {
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
}

test("signed snapshot: export -> JSON round-trip -> restoreSignedSnapshot resolves offline and verifies all three key types", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope: JwksSignedSnapshotEnvelope = original.exportSignedSnapshot(SECRET);
  assert.equal(envelope.v, 1);
  assert.equal(envelope.snapshot.v, 1);
  assert.equal(envelope.snapshot.fetchedAtSec, 1_700_000_500);
  assert.equal(envelope.snapshot.keys.length, 3);
  assert.match(envelope.mac, /^[0-9a-f]{64}$/);
  // The secret is never written into the envelope.
  assert.equal(JSON.stringify(envelope).includes(SECRET), false);
  // Only public material is exported: no entry may carry a "d".
  for (const k of envelope.snapshot.keys) assert.equal("d" in k, false);

  const persisted: unknown = JSON.parse(JSON.stringify(envelope));
  const restored = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  restored.restoreSignedSnapshot(persisted, SECRET);
  assert.equal(restored.size, 3);
  assert.equal(restored.lastRefreshedAt, 1_700_000_500);
  assert.equal(restored.isStale(), false);
  verifyAll(keys, restored);
});

test("signed snapshot: Buffer secret round-trips, and key-order-insensitive canonical JSON still verifies", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const secret = Buffer.from(SECRET, "utf8");
  const envelope = original.exportSignedSnapshot(secret);
  // Rebuild the envelope with the snapshot's object keys in reverse
  // order and one JWK entry's fields reversed: canonical JSON sorts
  // keys, so the MAC must still match.
  const reordered: Record<string, unknown> = {};
  for (const key of Object.keys(envelope).reverse()) {
    if (key === "snapshot") {
      const snap = envelope.snapshot as unknown as Record<string, unknown>;
      const snapReordered: Record<string, unknown> = {};
      for (const snapKey of Object.keys(snap).reverse()) {
        if (snapKey === "keys") {
          snapReordered[snapKey] = (snap[snapKey] as unknown[]).map((entry) => {
            const entryRecord = entry as Record<string, unknown>;
            const reversed: Record<string, unknown> = {};
            for (const entryKey of Object.keys(entryRecord).reverse())
              reversed[entryKey] = entryRecord[entryKey];
            return reversed;
          });
        } else {
          snapReordered[snapKey] = snap[snapKey];
        }
      }
      reordered[key] = snapReordered;
    } else {
      reordered[key] = (envelope as unknown as Record<string, unknown>)[key];
    }
  }
  const restored = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  restored.restoreSignedSnapshot(reordered, secret);
  assert.equal(restored.size, 3);
  verifyAll(keys, restored);
});

test("signed snapshot: tampered key is rejected and the old store is untouched", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);

  // A second store holding the good snapshot, so the failed restore
  // has an old snapshot to (not) disturb.
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), SECRET);
  verifyAll(keys, target);
  // Capture stats after the good verifies, so the assertion below
  // isolates the failed restore (which must move no counter).
  const statsBefore = target.stats();

  const tampered = JSON.parse(JSON.stringify(envelope)) as {
    snapshot: { keys: Array<Record<string, unknown>> };
  };
  const edEntry = tampered.snapshot.keys.find((k) => k["kid"] === "ed-key-1");
  assert.ok(edEntry);
  edEntry["x"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  assert.throws(
    () => target.restoreSignedSnapshot(tampered, SECRET),
    /signed snapshot MAC mismatch/,
  );
  assert.equal(target.size, 3);
  assert.equal(target.lastRefreshedAt, 1_700_000_500);
  assert.deepEqual(target.stats(), statsBefore);
  verifyAll(keys, target);
});

test("signed snapshot: tampered fetchedAtSec is rejected and the old store is untouched", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);

  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), SECRET);

  const tampered = JSON.parse(JSON.stringify(envelope)) as {
    snapshot: { fetchedAtSec: number };
  };
  tampered.snapshot.fetchedAtSec = 1_600_000_000;
  assert.throws(
    () => target.restoreSignedSnapshot(tampered, SECRET),
    /signed snapshot MAC mismatch/,
  );
  assert.equal(target.size, 3);
  assert.equal(target.lastRefreshedAt, 1_700_000_500);
  verifyAll(keys, target);
});

test("signed snapshot: wrong secret is rejected and the old store is untouched", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);

  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), SECRET);
  assert.throws(
    () =>
      target.restoreSignedSnapshot(
        JSON.parse(JSON.stringify(envelope)),
        "a-different-secret-that-is-also-long-enough",
      ),
    /signed snapshot MAC mismatch/,
  );
  assert.equal(target.size, 3);
  assert.equal(target.lastRefreshedAt, 1_700_000_500);
  verifyAll(keys, target);
});

test("signed snapshot: tampered mac string is rejected", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);
  const tampered = JSON.parse(JSON.stringify(envelope)) as { mac: string };
  // Flip the last hex digit, keeping the 64-hex shape so the failure
  // is a MAC mismatch, not a malformed-mac rejection.
  tampered.mac =
    tampered.mac.slice(0, -1) + (tampered.mac.slice(-1) === "0" ? "1" : "0");
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  assert.throws(
    () => target.restoreSignedSnapshot(tampered, SECRET),
    /signed snapshot MAC mismatch/,
  );
  assert.equal(target.size, 0);
  assert.equal(target.lastRefreshedAt, null);
});

test("signed snapshot: envelope unknown fields are rejected, including a smuggled secret", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  const withExtra = { ...JSON.parse(JSON.stringify(envelope)), note: "extra" };
  assert.throws(
    () => target.restoreSignedSnapshot(withExtra, SECRET),
    /unknown field "note"/,
  );
  const withSecret = { ...JSON.parse(JSON.stringify(envelope)), secret: SECRET };
  assert.throws(
    () => target.restoreSignedSnapshot(withSecret, SECRET),
    /unknown field "secret"/,
  );
  assert.equal(target.size, 0);
});

test("signed snapshot: wrong envelope version and malformed mac are rejected", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const envelope = original.exportSignedSnapshot(SECRET);
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  const wrongVersion = { ...JSON.parse(JSON.stringify(envelope)), v: 2 };
  assert.throws(
    () => target.restoreSignedSnapshot(wrongVersion, SECRET),
    /unsupported envelope version/,
  );
  const shortMac = { ...JSON.parse(JSON.stringify(envelope)), mac: "deadbeef" };
  assert.throws(
    () => target.restoreSignedSnapshot(shortMac, SECRET),
    /mac must be a 64-character lowercase hex/,
  );
  const upperMac = {
    ...JSON.parse(JSON.stringify(envelope)),
    mac: envelope.mac.toUpperCase(),
  };
  assert.throws(
    () => target.restoreSignedSnapshot(upperMac, SECRET),
    /mac must be a 64-character lowercase hex/,
  );
  assert.equal(target.size, 0);
});

test("signed snapshot: empty secret is rejected on export and on restore", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  assert.throws(() => original.exportSignedSnapshot(""), /secret must not be empty/);
  assert.throws(
    () => original.exportSignedSnapshot(Buffer.alloc(0)),
    /secret must not be empty/,
  );
  const envelope = original.exportSignedSnapshot(SECRET);
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  assert.throws(
    () => target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), ""),
    /secret must not be empty/,
  );
  assert.throws(
    () =>
      target.restoreSignedSnapshot(
        JSON.parse(JSON.stringify(envelope)),
        Buffer.alloc(0),
      ),
    /secret must not be empty/,
  );
  assert.equal(target.size, 0);
});

test("signed snapshot: MAC-valid envelope with a malformed snapshot still fails closed", async () => {
  // Build a genuinely MAC-valid envelope over snapshot content that
  // fails snapshot validation (a kid-less entry): the MAC is
  // computed here with node:crypto over the same canonical JSON the
  // library specifies (object keys sorted recursively), so restore
  // must pass the MAC check and then fail on the snapshot check —
  // without installing anything.
  const { createHmac } = await import("node:crypto");
  const canonicalJson = (value: unknown): string => {
    if (value === null) return "null";
    if (typeof value === "number" || typeof value === "string" || typeof value === "boolean")
      return JSON.stringify(value);
    if (Array.isArray(value))
      return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
    if (typeof value === "object") {
      const record = value as Record<string, unknown>;
      return `{${Object.keys(record)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
        .join(",")}}`;
    }
    throw new Error("non-JSON value");
  };
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  const good = original.exportSignedSnapshot(SECRET);
  const badSnapshot = JSON.parse(JSON.stringify(good.snapshot)) as {
    keys: Array<Record<string, unknown>>;
  };
  delete badSnapshot.keys[0]["kid"];
  const mac = createHmac("sha256", SECRET)
    .update(canonicalJson(badSnapshot), "utf8")
    .digest("hex");
  const badEnvelope = { v: 1, snapshot: badSnapshot, mac };

  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  target.restoreSignedSnapshot(JSON.parse(JSON.stringify(good)), SECRET);
  assert.throws(
    () => target.restoreSignedSnapshot(badEnvelope, SECRET),
    /kid must be a non-empty string/,
  );
  assert.equal(target.size, 3);
  assert.equal(target.lastRefreshedAt, 1_700_000_500);
  verifyAll(keys, target);
});

test("signed snapshot: unsigned paths are unchanged, and the two forms do not cross-accept", async () => {
  const keys = keyMaterial();
  const t = 1_700_000_500;
  const original = await refreshedStore(keys, () => t);
  // Unsigned round-trip still works exactly as before.
  const snapshot = original.exportSnapshot();
  const unsignedRestored = JwksKeyStore.restore(JSON.parse(JSON.stringify(snapshot)), URL, {
    fetchImpl: noFetch,
    ttlSec: 300,
    now: () => t,
  });
  assert.equal(unsignedRestored.size, 3);
  verifyAll(keys, unsignedRestored);

  // A signed envelope is not a valid unsigned snapshot (its extra
  // fields are rejected), and an unsigned snapshot is not a valid
  // signed envelope (it has no mac).
  const envelope = original.exportSignedSnapshot(SECRET);
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => t });
  assert.throws(
    () => target.restoreSnapshot(JSON.parse(JSON.stringify(envelope))),
    /unknown field "snapshot"/,
  );
  assert.throws(
    () => target.restoreSignedSnapshot(JSON.parse(JSON.stringify(snapshot)), SECRET),
    /mac must be a 64-character lowercase hex|invalid signed snapshot envelope/,
  );
  assert.equal(target.size, 0);
});

test("signed snapshot: export before any refresh throws, and a failed signed restore counts no refresh failure", async () => {
  const empty = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => 1_700_000_500 });
  assert.throws(
    () => empty.exportSignedSnapshot(SECRET),
    /cannot export a snapshot before a successful refresh/,
  );
  const keys = keyMaterial();
  const original = await refreshedStore(keys, () => 1_700_000_500);
  const envelope = original.exportSignedSnapshot(SECRET);
  const target = new JwksKeyStore(URL, { fetchImpl: noFetch, ttlSec: 300, now: () => 1_700_000_500 });
  assert.deepEqual(target.stats(), { refreshes: 0, refreshFailures: 0, hits: 0, misses: 0 });
  assert.throws(
    () =>
      target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), "wrong-secret-long-enough"),
    /signed snapshot MAC mismatch/,
  );
  // A rejected signed restore is not a refresh, so it must not move
  // the refresh counters (unlike a failed refresh()).
  assert.deepEqual(target.stats(), { refreshes: 0, refreshFailures: 0, hits: 0, misses: 0 });
  // And a subsequent good restore still works.
  target.restoreSignedSnapshot(JSON.parse(JSON.stringify(envelope)), SECRET);
  assert.equal(target.size, 3);
  verifyAll(keys, target);
});
