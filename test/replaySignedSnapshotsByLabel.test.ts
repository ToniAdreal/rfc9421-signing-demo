import test from "node:test";
import assert from "node:assert/strict";
import {
  exportSignedSnapshotsByLabel,
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  type ReplayCacheSignedSnapshotEnvelope,
  type VerifyResult,
} from "../src/index.js";

// Backlog #952: the single-cache signed envelope (#920) seals one
// `ReplayCache`; a multi-signature deployment keeps one cache per
// label in `VerifyAllOptions.replayCacheByLabel`, so persisting those
// caches needs one envelope per label. This file pins the by-label
// envelope pair: `exportSignedSnapshotsByLabel` /
// `ReplayCache.restoreSignedSnapshotsByLabel` (+ the
// `fromSignedSnapshotsByLabel` alias).

const SECRET = "replay-by-label-signing-secret-for-tests";
const CREATED = 1700000000;
const NOW = CREATED + 60;

type EnvelopesByLabel = Record<string, ReplayCacheSignedSnapshotEnvelope>;

function seededCaches(): Record<string, ReplayCache> {
  const merchant = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  merchant.check("m-nonce-1");
  merchant.check("m-nonce-2");
  const gateway = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  gateway.check("g-nonce-1");
  return { merchant, gateway };
}

function exportSeeded(): EnvelopesByLabel {
  return exportSignedSnapshotsByLabel(seededCaches(), SECRET);
}

// Two labels sign -> JSON round-trip -> restore: each label's replay
// window survives, and the namespaces stay partitioned.
test("two-label signed round-trip: per-label replay correct after restore", () => {
  const envelopes = exportSeeded();
  assert.deepEqual(Object.keys(envelopes).sort(), ["gateway", "merchant"]);
  for (const envelope of Object.values(envelopes)) {
    assert.equal(envelope.v, 1);
    assert.match(envelope.mac, /^[0-9a-f]{64}$/);
  }
  assert.deepEqual(envelopes.merchant.snapshot, {
    v: 1,
    entries: [
      ["m-nonce-1", 1000],
      ["m-nonce-2", 1000],
    ],
  });
  assert.deepEqual(envelopes.gateway.snapshot, {
    v: 1,
    entries: [["g-nonce-1", 1000]],
  });

  // The envelopes are plain JSON: a string round-trip must not break them.
  const wire = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(wire, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.deepEqual(Object.keys(restored).sort(), ["gateway", "merchant"]);
  assert.equal(restored.merchant.check("m-nonce-1"), true); // replay
  assert.equal(restored.merchant.check("m-nonce-2"), true); // replay
  assert.equal(restored.gateway.check("g-nonce-1"), true); // replay
  // Namespaces stay partitioned: a nonce seen under one label is
  // fresh under the other.
  assert.equal(restored.merchant.check("g-nonce-1"), false);
  assert.equal(restored.gateway.check("m-nonce-1"), false);
  assert.equal(restored.gateway.check("g-nonce-2"), false);
});

// Rewriting one label's entry is caught, and the whole batch is
// rejected — no partial map escapes.
test("tampered entry in one label rejects the whole batch", () => {
  const envelopes = exportSeeded();
  const before = JSON.stringify(envelopes);
  const tampered = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  tampered.gateway.snapshot.entries[0][0] = "g-nonce-evil";
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(tampered, SECRET),
    /MAC mismatch/,
  );
  // The input envelopes are untouched by the failed restore.
  assert.equal(JSON.stringify(envelopes), before);
});

// Rewriting a first-seen timestamp in one label (e.g. to extend a
// nonce's window) is caught the same way.
test("tampered seenAt in one label rejects the whole batch", () => {
  const envelopes = exportSeeded();
  const tampered = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  tampered.merchant.snapshot.entries[0][1] = 1;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(tampered, SECRET),
    /MAC mismatch/,
  );
});

// A wrong secret fails every label — the same error as tampering,
// deliberately: restore cannot tell the two apart.
test("wrong secret rejects the whole batch", () => {
  const envelopes = exportSeeded();
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshotsByLabel(
        envelopes,
        "a-different-secret",
      ),
    /MAC mismatch/,
  );
});

// An empty secret is a caller-configuration error on both sides,
// before any cache state is touched.
test("empty secret fails fast on export and on restore", () => {
  const caches = seededCaches();
  assert.throws(() => exportSignedSnapshotsByLabel(caches, ""), /must not be empty/);
  assert.throws(
    () => exportSignedSnapshotsByLabel(caches, Buffer.alloc(0)),
    /must not be empty/,
  );
  const envelopes = exportSeeded();
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(envelopes, ""),
    /must not be empty/,
  );
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(envelopes, Buffer.alloc(0)),
    /must not be empty/,
  );
});

// A non-string/non-Buffer secret is a caller-configuration error too.
test("non-string secret fails fast on export and on restore", () => {
  const caches = seededCaches();
  for (const bad of [undefined, null, 42, true, {}, ["s"]]) {
    assert.throws(
      () => exportSignedSnapshotsByLabel(caches, bad as never),
      /must be a non-empty string or Buffer/,
    );
  }
  const envelopes = exportSeeded();
  for (const bad of [undefined, null, 42, true, {}, ["s"]]) {
    assert.throws(
      () => ReplayCache.restoreSignedSnapshotsByLabel(envelopes, bad as never),
      /must be a non-empty string or Buffer/,
    );
  }
});

// An empty map is a valid batch: it round-trips to an empty map.
test("empty map round-trips to an empty map", () => {
  assert.deepEqual(exportSignedSnapshotsByLabel({}, SECRET), {});
  assert.deepEqual(
    ReplayCache.restoreSignedSnapshotsByLabel({}, SECRET),
    {},
  );
});

// Export only accepts real ReplayCache instances: a duck-typed store,
// a snapshot object, or any other value is a caller error.
test("non-ReplayCache value is rejected on export", () => {
  const real = seededCaches().merchant;
  const duckStore = { check: () => false };
  for (const bad of [null, undefined, 42, "cache", duckStore, { v: 1, entries: [] }]) {
    assert.throws(
      () =>
        exportSignedSnapshotsByLabel(
          { merchant: bad } as never,
          SECRET,
        ),
      /must be a ReplayCache/,
    );
  }
  // The good label does not rescue a bad sibling: the whole export fails.
  assert.throws(
    () =>
      exportSignedSnapshotsByLabel(
        { merchant: real, gateway: duckStore } as never,
        SECRET,
      ),
    /must be a ReplayCache/,
  );
  // A non-object map is rejected outright.
  for (const bad of [null, [], "caches", 42]) {
    assert.throws(
      () => exportSignedSnapshotsByLabel(bad as never, SECRET),
      /expects a label -> ReplayCache object/,
    );
  }
});

// `expectedLabels` pins the label set: an unknown/extra label, or a
// missing expected label, fails the whole restore. Without it, any
// label set is accepted (each label is still MAC-verified).
test("expectedLabels: extra or missing label fails the whole restore", () => {
  const envelopes = exportSeeded();
  // Exact set passes.
  const exact = ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
    expectedLabels: ["merchant", "gateway"],
  });
  assert.equal(exact.merchant.check("m-nonce-1"), true);
  // An extra label fails — including a copied envelope under a new
  // name, whose MAC still verifies (the MAC covers the snapshot,
  // not the label name).
  const extra = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  extra.stolen = extra.merchant;
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshotsByLabel(extra, SECRET, {
        expectedLabels: ["merchant", "gateway"],
      }),
    /unexpected label "stolen"/,
  );
  // A missing expected label fails too: silently dropping a label's
  // cache would reopen that label's replay window.
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
        expectedLabels: ["merchant", "gateway", "auditor"],
      }),
    /missing expected label "auditor"/,
  );
  // Without expectedLabels the same copied-label map restores (each
  // envelope is MAC-valid); the pinning is opt-in and documented.
  const unpinned = ReplayCache.restoreSignedSnapshotsByLabel(extra, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(unpinned.stolen.check("m-nonce-1"), true);
  // Malformed expectedLabels is a caller-configuration error.
  for (const bad of [null, "merchant", ["merchant", ""], ["merchant", "merchant"]]) {
    assert.throws(
      () =>
        ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
          expectedLabels: bad as never,
        }),
      /expectedLabels/,
    );
  }
});

// A non-object envelopes map is rejected before any MAC work.
test("non-object envelopes map is rejected on restore", () => {
  for (const bad of [null, [], "envelopes", 42]) {
    assert.throws(
      () => ReplayCache.restoreSignedSnapshotsByLabel(bad, SECRET),
      /expected an object mapping label -> signed snapshot envelope/,
    );
  }
});

// Envelope-shape defects in one label reject the whole batch, with
// the same errors as the single-cache restore.
test("envelope shape defect in one label rejects the whole batch", () => {
  const envelopes = exportSeeded();
  const extraField = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  (extraField.gateway as unknown as Record<string, unknown>).secret = SECRET;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(extraField, SECRET),
    /unknown field "secret"/,
  );
  const badVersion = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  (badVersion.merchant as unknown as Record<string, unknown>).v = 2;
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(badVersion, SECRET),
    /unsupported envelope version/,
  );
  const badMac = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  badMac.gateway.mac = "a".repeat(63);
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(badMac, SECRET),
    /mac must be a 64-character lowercase hex/,
  );
  const badSnapshot = JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel;
  (badSnapshot.merchant as unknown as Record<string, unknown>).snapshot =
    "not-an-object";
  assert.throws(
    () => ReplayCache.restoreSignedSnapshotsByLabel(badSnapshot, SECRET),
    /"snapshot" must be an object/,
  );
});

// An empty label is not a label: rejected on both sides.
test("empty label is rejected on export and on restore", () => {
  const cache = seededCaches().merchant;
  assert.throws(
    () => exportSignedSnapshotsByLabel({ "": cache }, SECRET),
    /label must be a non-empty string/,
  );
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshotsByLabel({ "": envelope }, SECRET),
    /label must be a non-empty string/,
  );
});

// Buffer secrets work, and a Buffer holding the same UTF-8 bytes as a
// string secret produces the same MACs (no encoding surprise).
test("Buffer secret works and matches the same string secret", () => {
  const caches = seededCaches();
  const fromString = exportSignedSnapshotsByLabel(caches, SECRET);
  const fromBuffer = exportSignedSnapshotsByLabel(
    caches,
    Buffer.from(SECRET, "utf8"),
  );
  assert.equal(fromBuffer.merchant.mac, fromString.merchant.mac);
  assert.equal(fromBuffer.gateway.mac, fromString.gateway.mac);
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(
    fromBuffer,
    Buffer.from(SECRET, "utf8"),
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.merchant.check("m-nonce-2"), true);
  // Cross-form restore: string-signed envelopes, Buffer secret.
  const cross = ReplayCache.restoreSignedSnapshotsByLabel(
    fromString,
    Buffer.from(SECRET, "utf8"),
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(cross.gateway.check("g-nonce-1"), true);
});

// The MAC covers the canonical JSON, not the wire key order: a JSON
// round-trip that reorders object keys still verifies, per label.
test("key-reordered JSON round-trip still verifies (canonical MAC)", () => {
  const envelopes = exportSeeded();
  const reordered = {
    gateway: {
      mac: envelopes.gateway.mac,
      snapshot: {
        entries: envelopes.gateway.snapshot.entries,
        v: envelopes.gateway.snapshot.v,
      },
      v: envelopes.gateway.v,
    },
    merchant: {
      mac: envelopes.merchant.mac,
      snapshot: {
        entries: envelopes.merchant.snapshot.entries,
        v: envelopes.merchant.snapshot.v,
      },
      v: envelopes.merchant.v,
    },
  } as unknown as EnvelopesByLabel;
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(reordered, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.merchant.check("m-nonce-1"), true);
  assert.equal(restored.gateway.check("g-nonce-1"), true);
});

// `fromSignedSnapshotsByLabel` is the same restore under the
// snapshot-naming alias, mirroring `ReplayCache.fromSignedSnapshot`.
test("fromSignedSnapshotsByLabel alias restores identically", () => {
  const envelopes = exportSeeded();
  const restored = ReplayCache.fromSignedSnapshotsByLabel(
    JSON.parse(JSON.stringify(envelopes)) as EnvelopesByLabel,
    SECRET,
    { ttlSec: 3600, now: () => 1000 },
  );
  assert.equal(restored.merchant.size, 2);
  assert.equal(restored.gateway.check("g-nonce-1"), true);
});

// The signed envelopes inherit the unsigned snapshot's expiry rule
// per label: entries already expired at export time never enter the
// snapshot, so they cannot be revived by a signed restore either.
test("expired entries are excluded per label", () => {
  let t = 1000;
  const merchant = new ReplayCache({ ttlSec: 100, now: () => t });
  merchant.check("m-old");
  t = 1050;
  merchant.check("m-fresh");
  // The gateway cache runs a longer TTL on its own fixed clock, so
  // its entry is still live when the merchant's entries expire.
  const gateway = new ReplayCache({ ttlSec: 3600, now: () => 1050 });
  gateway.check("g-fresh");
  t = 1150; // both merchant entries expired (fresh is exactly 100s old)
  const envelopes = exportSignedSnapshotsByLabel(
    { merchant, gateway },
    SECRET,
  );
  assert.deepEqual(envelopes.merchant.snapshot.entries, []);
  assert.deepEqual(envelopes.gateway.snapshot.entries, [["g-fresh", 1050]]);
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
    ttlSec: 100,
    now: () => 1100,
  });
  assert.equal(restored.merchant.size, 0);
  assert.equal(restored.merchant.check("m-fresh"), false);
  assert.equal(restored.gateway.check("g-fresh"), true);
});

// End-to-end: restored per-label caches plug back into
// `verifyAllLabels` via `replayCacheByLabel`, and a replayed
// dual-signed request is rejected per label.
test("restored per-label caches plug into verifyAllLabels", () => {
  const merchantKeys = generateEd25519KeyPair();
  const gatewayKeys = generateEd25519KeyPair();
  const request = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
  const signed = (label: string, pair: ReturnType<typeof generateEd25519KeyPair>, nonce: string) =>
    signRequest(request, {
      label,
      keyId: label,
      alg: "ed25519",
      key: pair.privateKey,
      created: CREATED,
      nonce,
    });
  const signedMerchant = signed("merchant", merchantKeys, "wire-m-1");
  const signedGateway = signed("gateway", gatewayKeys, "wire-g-1");
  const merged = {
    ...signedMerchant,
    headers: {
      ...signedMerchant.headers,
      "signature-input": `${signedMerchant.headers["signature-input"]}, ${signedGateway.headers["signature-input"]}`,
      signature: `${signedMerchant.headers["signature"]}, ${signedGateway.headers["signature"]}`,
    },
  };
  const keys = { merchant: merchantKeys.publicKey, gateway: gatewayKeys.publicKey };

  // First verification records both nonces into the live caches.
  const live = {
    merchant: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
    gateway: new ReplayCache({ ttlSec: 3600, now: () => NOW }),
  };
  const first = Object.fromEntries(
    verifyAllLabels(merged, { now: NOW, keys, replayCacheByLabel: live }).map(
      (r: VerifyResult) => [r.label, r],
    ),
  );
  assert.equal(first.merchant.ok, true);
  assert.equal(first.gateway.ok, true);

  // Persist across a "restart" through the signed envelopes, then
  // re-verify the same request against the restored caches.
  const restored = ReplayCache.restoreSignedSnapshotsByLabel(
    JSON.parse(
      JSON.stringify(exportSignedSnapshotsByLabel(live, SECRET)),
    ) as EnvelopesByLabel,
    SECRET,
    { ttlSec: 3600, now: () => NOW },
  );
  const second = Object.fromEntries(
    verifyAllLabels(merged, { now: NOW, keys, replayCacheByLabel: restored }).map(
      (r: VerifyResult) => [r.label, r],
    ),
  );
  assert.equal(second.merchant.ok, false);
  assert.equal(second.merchant.code, "NONCE_REPLAY");
  assert.equal(second.gateway.ok, false);
  assert.equal(second.gateway.code, "NONCE_REPLAY");
});
