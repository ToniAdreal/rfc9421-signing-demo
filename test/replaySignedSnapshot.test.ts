import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
  type ReplayCacheSignedSnapshotEnvelope,
} from "../src/index.js";

const SECRET = "replay-snapshot-signing-secret-for-tests";
const CREATED = 1700000000;

function seededCache(): { cache: ReplayCache; now: () => number } {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => t });
  cache.check("nonce-a");
  cache.check("nonce-b");
  return { cache, now: () => t };
}

// A signed snapshot survives a JSON round-trip and the restart does not
// reopen the replay window — exercised both directly and end-to-end
// through verifyRequest (NONCE_REPLAY).
test("signed snapshot round-trip: seen nonce is still a replay after restore", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.equal(envelope.v, 1);
  assert.deepEqual(envelope.snapshot, {
    v: 1,
    entries: [
      ["nonce-a", 1000],
      ["nonce-b", 1000],
    ],
  });
  assert.match(envelope.mac, /^[0-9a-f]{64}$/);

  // The envelope is plain JSON: a string round-trip must not break it.
  const wire = JSON.parse(JSON.stringify(envelope)) as ReplayCacheSignedSnapshotEnvelope;
  const restored = ReplayCache.restoreSignedSnapshot(wire, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-a"), true); // replay
  assert.equal(restored.check("nonce-b"), true); // replay
  assert.equal(restored.check("nonce-c"), false); // fresh nonce still records
  // The original cache is untouched by the restore.
  assert.equal(cache.size, 2);

  // End-to-end: a signature verified before the "restart" is rejected
  // with NONCE_REPLAY by the verifier using the restored cache.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, nonce: "wire-1" },
  );
  const before = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const vopts = { key: publicKey, now: CREATED + 60 };
  assert.equal(verifyRequest(signed, { ...vopts, replayCache: before }).ok, true);
  const signedEnvelope = before.exportSignedSnapshot(SECRET);
  const after = ReplayCache.restoreSignedSnapshot(
    JSON.parse(JSON.stringify(signedEnvelope)) as ReplayCacheSignedSnapshotEnvelope,
    SECRET,
    { ttlSec: 3600, now: () => CREATED + 60 },
  );
  const replayed = verifyRequest(signed, { ...vopts, replayCache: after });
  assert.equal(replayed.ok, false);
  assert.equal(replayed.code, "NONCE_REPLAY");
});

// The secret is caller configuration: it is never written into the
// envelope, so a persisted envelope leaks nothing about it.
test("envelope carries no secret", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.deepEqual(Object.keys(envelope).sort(), ["mac", "snapshot", "v"]);
  assert.equal(JSON.stringify(envelope).includes(SECRET), false);
  assert.equal(JSON.stringify(envelope).includes("secret"), false);
});

// Rewriting a tracked nonce without the secret is caught at restore.
test("tampered entry is rejected", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  const tampered = JSON.parse(JSON.stringify(envelope)) as ReplayCacheSignedSnapshotEnvelope;
  tampered.snapshot.entries[0][0] = "nonce-evil";
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(tampered, SECRET),
    /MAC mismatch/,
  );
});

// Rewriting a first-seen timestamp (e.g. to extend a nonce's window)
// is caught the same way.
test("tampered seenAt is rejected", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  const tampered = JSON.parse(JSON.stringify(envelope)) as ReplayCacheSignedSnapshotEnvelope;
  tampered.snapshot.entries[0][1] = 1; // pretend the nonce was seen at t=1
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(tampered, SECRET),
    /MAC mismatch/,
  );
});

// A wrong secret fails the MAC check — the same error as tampering,
// deliberately: restore cannot tell the two apart.
test("wrong secret is rejected", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(envelope, "a-different-secret"),
    /MAC mismatch/,
  );
});

// An empty secret is a caller-configuration error on both sides,
// before any cache state is touched.
test("empty secret fails fast on export and on restore", () => {
  const { cache } = seededCache();
  assert.throws(() => cache.exportSignedSnapshot(""), /must not be empty/);
  assert.throws(() => cache.exportSignedSnapshot(Buffer.alloc(0)), /must not be empty/);
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(envelope, ""),
    /must not be empty/,
  );
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(envelope, Buffer.alloc(0)),
    /must not be empty/,
  );
});

// A non-string/non-Buffer secret is a caller-configuration error too.
test("non-string secret fails fast on export and on restore", () => {
  const { cache } = seededCache();
  for (const bad of [undefined, null, 42, true, {}, ["s"]]) {
    assert.throws(
      () => cache.exportSignedSnapshot(bad as never),
      /must be a non-empty string or Buffer/,
    );
  }
  const envelope = cache.exportSignedSnapshot(SECRET);
  for (const bad of [undefined, null, 42, true, {}, ["s"]]) {
    assert.throws(
      () => ReplayCache.restoreSignedSnapshot(envelope, bad as never),
      /must be a non-empty string or Buffer/,
    );
  }
});

// The MAC covers the canonical JSON, not the wire key order: a JSON
// round-trip that reorders object keys still verifies.
test("key-reordered JSON round-trip still verifies (canonical MAC)", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  // Rebuild the envelope with keys in the opposite order, and the
  // snapshot object with its keys swapped too.
  const reordered = {
    mac: envelope.mac,
    snapshot: {
      entries: envelope.snapshot.entries,
      v: envelope.snapshot.v,
    },
    v: envelope.v,
  } as unknown as ReplayCacheSignedSnapshotEnvelope;
  const restored = ReplayCache.restoreSignedSnapshot(reordered, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-a"), true);
});

// Array order is part of the MAC: reordering entries changes the
// canonical document, so it must fail (entries carry LRU order).
test("reordered entries fail the MAC", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  const tampered = JSON.parse(JSON.stringify(envelope)) as ReplayCacheSignedSnapshotEnvelope;
  tampered.snapshot.entries.reverse();
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(tampered, SECRET),
    /MAC mismatch/,
  );
});

// A MAC-valid envelope whose snapshot is structurally bad still fails
// through the strict snapshot validation — and produces no cache.
// The MAC is computed independently here (node:crypto over the
// canonical JSON: keys sorted recursively, array order preserved),
// so the envelope genuinely passes the authenticity check and the
// failure must come from snapshot validation.
function canonicalJsonForTest(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return `[${value.map((entry) => canonicalJsonForTest(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJsonForTest(record[key])}`)
      .join(",")}}`;
  }
  throw new Error("test helper: non-JSON value");
}

test("MAC-valid but structurally broken snapshot is rejected", async () => {
  const { createHmac } = await import("node:crypto");
  const badSnapshots: Array<{ snapshot: Record<string, unknown>; pattern: RegExp }> = [
    { snapshot: { v: 2, entries: [] }, pattern: /invalid snapshot: unsupported snapshot version/ },
    { snapshot: { v: 1, entries: [["ok", 1000], ["", 1000]] }, pattern: /invalid snapshot: entries\[1\]: nonce must be a non-empty string/ },
    { snapshot: { v: 1, entries: [["ok", -5]] }, pattern: /invalid snapshot: entries\[0\]: seenAt must be a finite non-negative number/ },
    { snapshot: { v: 1 }, pattern: /invalid snapshot: entries must be an array/ },
    { snapshot: { v: 1, entries: "not-an-array" }, pattern: /invalid snapshot: entries must be an array/ },
  ];
  for (const { snapshot, pattern } of badSnapshots) {
    const mac = createHmac("sha256", SECRET)
      .update(canonicalJsonForTest(snapshot), "utf8")
      .digest("hex");
    const envelope = { v: 1, snapshot, mac } as unknown as ReplayCacheSignedSnapshotEnvelope;
    assert.throws(
      () => ReplayCache.restoreSignedSnapshot(envelope, SECRET),
      pattern,
    );
  }
});

// Envelope-shape defects are rejected before any MAC work, and a
// failed restore never produces a cache.
test("envelope shape defects are rejected", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  // Unknown envelope field: rejected before any MAC work.
  const extraField = {
    ...envelope,
    secret: SECRET,
  } as unknown as ReplayCacheSignedSnapshotEnvelope;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(extraField, SECRET),
    /unknown field "secret"/,
  );
  // Wrong envelope version.
  const badVersion = { ...envelope, v: 2 } as unknown as ReplayCacheSignedSnapshotEnvelope;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(badVersion, SECRET),
    /unsupported envelope version/,
  );
  // Malformed mac (wrong length / non-hex) is rejected as malformed,
  // not compared.
  for (const badMac of ["", "zz".repeat(32), "a".repeat(63), "A".repeat(64)]) {
    const bad = { ...envelope, mac: badMac } as unknown as ReplayCacheSignedSnapshotEnvelope;
    assert.throws(
      () => ReplayCache.restoreSignedSnapshot(bad, SECRET),
      /mac must be a 64-character lowercase hex/,
    );
  }
  // A non-object envelope and a non-object snapshot are rejected.
  for (const bad of [null, [], "envelope", 42]) {
    assert.throws(
      () => ReplayCache.restoreSignedSnapshot(bad, SECRET),
      /expected an object/,
    );
  }
  const badSnapshot = { ...envelope, snapshot: "not-an-object" } as unknown as ReplayCacheSignedSnapshotEnvelope;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshot(badSnapshot, SECRET),
    /"snapshot" must be an object/,
  );
  // The source cache is untouched by all of the above.
  assert.equal(cache.size, 2);
});

// Buffer secrets work, and a Buffer holding the same UTF-8 bytes as a
// string secret produces the same MAC (no encoding surprise).
test("Buffer secret works and matches the same string secret", () => {
  const { cache } = seededCache();
  const fromString = cache.exportSignedSnapshot(SECRET);
  const fromBuffer = cache.exportSignedSnapshot(Buffer.from(SECRET, "utf8"));
  assert.equal(fromBuffer.mac, fromString.mac);
  const restored = ReplayCache.restoreSignedSnapshot(
    fromBuffer,
    Buffer.from(SECRET, "utf8"),
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.check("nonce-a"), true);
  // Cross-form restore: string-signed envelope, Buffer secret.
  const cross = ReplayCache.restoreSignedSnapshot(fromString, Buffer.from(SECRET, "utf8"), {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(cross.check("nonce-b"), true);
});

// `fromSignedSnapshot` is the same restore under the snapshot-naming
// alias, mirroring `ReplayCache.fromSnapshot`.
test("fromSignedSnapshot alias restores identically", () => {
  const { cache } = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  const restored = ReplayCache.fromSignedSnapshot(
    JSON.parse(JSON.stringify(envelope)) as ReplayCacheSignedSnapshotEnvelope,
    SECRET,
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-b"), true);
});

// The signed envelope inherits the unsigned snapshot's expiry rule:
// entries already expired at export time never enter the snapshot,
// so they cannot be revived by a signed restore either.
test("expired entries are excluded from the signed snapshot", () => {
  let t = 1000;
  const cache = new ReplayCache({ ttlSec: 100, now: () => t });
  cache.check("old");
  t = 1050;
  cache.check("fresh");
  t = 1150; // both entries expired (fresh is exactly 100s old)
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.deepEqual(envelope.snapshot.entries, []);
  const restored = ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
    ttlSec: 100,
    now: () => 1150,
  });
  assert.equal(restored.size, 0);
  assert.equal(restored.check("fresh"), false);
});
