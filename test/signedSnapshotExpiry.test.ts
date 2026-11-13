import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  exportSignedSnapshotsByLabel,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  JwksKeyStore,
  ReplayCache,
  type JwksFetchImpl,
  type JwksSignedSnapshotEnvelope,
  type ReplayCacheSignedSnapshotEnvelope,
} from "../src/index.js";

const SECRET = "signed-snapshot-expiry-test-secret";
const URL = "https://gateway.example.com/.well-known/jwks.json";

/** Canonical JSON mirroring the src implementations (sorted keys, array order kept). */
function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string" || typeof value === "boolean")
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
  throw new Error(`cannot canonicalize ${typeof value}`);
}

function macFor(value: unknown): string {
  return createHmac("sha256", SECRET)
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

function iso(sec: number): string {
  return new Date(sec * 1000).toISOString();
}

function seededCache(): ReplayCache {
  const cache = new ReplayCache({ ttlSec: 3600, now: () => 1000 });
  cache.check("nonce-a");
  cache.check("nonce-b");
  return cache;
}

// ---------------------------------------------------------------------------
// ReplayCache family
// ---------------------------------------------------------------------------

test("replay: no expiresAt restores exactly as before (legacy envelope)", () => {
  const cache = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET);
  assert.equal(envelope.expiresAt, undefined);
  assert.equal("expiresAt" in envelope, false);
  const restored = ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
    ttlSec: 3600,
    now: () => 1000,
  });
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-a"), true);
});

test("replay: future expiresAt round-trips and restores", () => {
  const cache = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET, {
    expiresAt: iso(2000),
  });
  assert.equal(envelope.expiresAt, iso(2000));
  const restored = ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
    ttlSec: 3600,
    now: () => 1500,
  });
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-b"), true);
});

test("replay: expired envelope rejected; restoring at exactly expiresAt still succeeds", () => {
  const cache = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET, {
    expiresAt: iso(2000),
  });
  // Boundary is inclusive: now == expiresAt restores.
  const atBoundary = ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
    ttlSec: 3600,
    now: () => 2000,
  });
  assert.equal(atBoundary.size, 2);
  // One second past expiresAt is expired.
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
        ttlSec: 3600,
        now: () => 2001,
      }),
    /signed snapshot envelope expired at 1970-01-01T00:33:20\.000Z/,
  );
});

test("replay: tampered expiresAt fails the MAC check", () => {
  const cache = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET, {
    expiresAt: iso(2000),
  });
  const tampered: ReplayCacheSignedSnapshotEnvelope = {
    ...envelope,
    expiresAt: iso(3000),
  };
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshot(tampered, SECRET, {
        ttlSec: 3600,
        now: () => 1000,
      }),
    /signed snapshot MAC mismatch/,
  );
  // Removing expiresAt from a keyed envelope also fails the MAC:
  // the MAC was computed over { expiresAt, snapshot }.
  const { expiresAt: _dropped, ...stripped } = envelope;
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshot(stripped, SECRET, {
        ttlSec: 3600,
        now: () => 1000,
      }),
    /signed snapshot MAC mismatch/,
  );
});

test("replay: illegal expiresAt at export throws before any envelope exists", () => {
  const cache = seededCache();
  for (const bad of [
    "tomorrow",
    "2026-01-01T00:00:00+00:00", // non-canonical: UTC must render with Z
    "2026-01-01T00:00:00Z", // non-canonical: missing milliseconds
    "",
    1700000000 as unknown as string, // wrong type
  ]) {
    assert.throws(
      () => cache.exportSignedSnapshot(SECRET, { expiresAt: bad }),
      /expiresAt must be a canonical ISO-8601 UTC timestamp string/,
    );
  }
});

test("replay: maxAgeMs sets expiresAt; option misuse fails fast", () => {
  const cache = seededCache();
  const envelope = cache.exportSignedSnapshot(SECRET, {
    maxAgeMs: 3_600_000,
    now: 1_700_000_000_000,
  });
  assert.equal(
    envelope.expiresAt,
    new Date(1_700_000_000_000 + 3_600_000).toISOString(),
  );
  // expiresAt and maxAgeMs are mutually exclusive.
  assert.throws(
    () =>
      cache.exportSignedSnapshot(SECRET, {
        expiresAt: iso(2000),
        maxAgeMs: 1000,
      }),
    /must not combine expiresAt and maxAgeMs/,
  );
  // now without maxAgeMs has nothing to compute.
  assert.throws(
    () => cache.exportSignedSnapshot(SECRET, { now: 1_700_000_000_000 }),
    /now is only used with maxAgeMs/,
  );
  // maxAgeMs must be a positive finite number.
  for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => cache.exportSignedSnapshot(SECRET, { maxAgeMs: bad }),
      /maxAgeMs must be a positive finite number/,
    );
  }
});

test("replay: expiry check runs before snapshot parsing (MAC-valid, expired, malformed snapshot)", () => {
  const malformedSnapshot = { v: 1, entries: "not-an-array" };
  const expiresAt = iso(2000);
  const envelope = {
    v: 1,
    snapshot: malformedSnapshot,
    expiresAt,
    mac: macFor({ expiresAt, snapshot: malformedSnapshot }),
  };
  // The MAC is valid, the snapshot is malformed, the envelope is
  // expired: the expiry error must win, not the snapshot error.
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
        ttlSec: 3600,
        now: () => 2001,
      }),
    /signed snapshot envelope expired at 1970-01-01T00:33:20\.000Z/,
  );
  // Within the window the same envelope fails on the snapshot instead.
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshot(envelope, SECRET, {
        ttlSec: 3600,
        now: () => 1500,
      }),
    /invalid snapshot: entries must be an array/,
  );
});

test("replay by-label: an expired label rejects the whole batch, the valid label is unaffected", () => {
  const merchant = seededCache();
  const gateway = seededCache();
  const envelopes = {
    merchant: merchant.exportSignedSnapshot(SECRET, {
      expiresAt: iso(2000),
    }),
    gateway: gateway.exportSignedSnapshot(SECRET, {
      expiresAt: iso(3000),
    }),
  };
  // 2500 is past the merchant expiry but inside the gateway window:
  // the batch fails atomically.
  assert.throws(
    () =>
      ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
        ttlSec: 3600,
        now: () => 2500,
      }),
    /signed snapshot envelope expired at 1970-01-01T00:33:20\.000Z/,
  );
  // The unexpired label is unaffected: it restores fine on its own.
  const restored = ReplayCache.restoreSignedSnapshot(
    envelopes.gateway,
    SECRET,
    { ttlSec: 3600, now: () => 2500 },
  );
  assert.equal(restored.size, 2);
  assert.equal(restored.check("nonce-a"), true);
  // And the same batch restores whole when the clock is inside both windows.
  const both = ReplayCache.restoreSignedSnapshotsByLabel(envelopes, SECRET, {
    ttlSec: 3600,
    now: () => 1500,
  });
  assert.equal(both.merchant.size, 2);
  assert.equal(both.gateway.size, 2);
});

// ---------------------------------------------------------------------------
// JwksKeyStore family
// ---------------------------------------------------------------------------

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

test("jwks: no expiresAt restores exactly as before (legacy envelope)", async () => {
  const keys = keyMaterial();
  const source = await refreshedStore(keys, () => 1_700_000_000);
  const envelope = source.exportSignedSnapshot(SECRET);
  assert.equal(envelope.expiresAt, undefined);
  assert.equal("expiresAt" in envelope, false);
  const target = new JwksKeyStore(URL, {
    fetchImpl: noFetch,
    now: () => 1_700_000_000,
  });
  target.restoreSignedSnapshot(envelope, SECRET);
  assert.notEqual(target.resolve("ed-key-1"), undefined);
  assert.notEqual(target.resolve("p256-key-1"), undefined);
  assert.notEqual(target.resolve("rsa-key-1"), undefined);
});

test("jwks: future expiresAt round-trips and restores", async () => {
  const keys = keyMaterial();
  const source = await refreshedStore(keys, () => 1_700_000_000);
  const envelope = source.exportSignedSnapshot(SECRET, {
    expiresAt: iso(1_700_003_600),
  });
  assert.equal(envelope.expiresAt, iso(1_700_003_600));
  const target = new JwksKeyStore(URL, {
    fetchImpl: noFetch,
    now: () => 1_700_000_000,
  });
  target.restoreSignedSnapshot(envelope, SECRET, {
    now: () => 1_700_001_800,
  });
  assert.notEqual(target.resolve("ed-key-1"), undefined);
});

test("jwks: expired envelope rejected and the current snapshot stays untouched; boundary inclusive", async () => {
  const keys = keyMaterial();
  const source = await refreshedStore(keys, () => 1_700_000_000);
  const envelope = source.exportSignedSnapshot(SECRET, {
    expiresAt: iso(1_700_003_600),
  });
  // Target already holds keys from its own refresh.
  const target = await refreshedStore(keys, () => 1_700_000_000);
  // Boundary: now == expiresAt restores.
  target.restoreSignedSnapshot(envelope, SECRET, {
    now: () => 1_700_003_600,
  });
  assert.notEqual(target.resolve("ed-key-1"), undefined);
  // One second past expiresAt is expired, and the store is untouched.
  assert.throws(
    () =>
      target.restoreSignedSnapshot(envelope, SECRET, {
        now: () => 1_700_003_601,
      }),
    /signed snapshot envelope expired at /,
  );
  assert.notEqual(target.resolve("ed-key-1"), undefined);
  assert.notEqual(target.resolve("rsa-key-1"), undefined);
});

test("jwks: tampered expiresAt fails the MAC check", async () => {
  const keys = keyMaterial();
  const source = await refreshedStore(keys, () => 1_700_000_000);
  const envelope = source.exportSignedSnapshot(SECRET, {
    expiresAt: iso(1_700_003_600),
  });
  const tampered: JwksSignedSnapshotEnvelope = {
    ...envelope,
    expiresAt: iso(1_700_007_200),
  };
  const target = new JwksKeyStore(URL, {
    fetchImpl: noFetch,
    now: () => 1_700_000_000,
  });
  assert.throws(
    () => target.restoreSignedSnapshot(tampered, SECRET),
    /signed snapshot MAC mismatch/,
  );
  assert.equal(target.resolve("ed-key-1"), undefined);
});

test("jwks: illegal expiresAt at export throws; maxAgeMs sets expiresAt", async () => {
  const keys = keyMaterial();
  const source = await refreshedStore(keys, () => 1_700_000_000);
  assert.throws(
    () => source.exportSignedSnapshot(SECRET, { expiresAt: "tomorrow" }),
    /expiresAt must be a canonical ISO-8601 UTC timestamp string/,
  );
  assert.throws(
    () =>
      source.exportSignedSnapshot(SECRET, {
        expiresAt: "2026-01-01T00:00:00+00:00",
      }),
    /expiresAt must be a canonical ISO-8601 UTC timestamp string/,
  );
  const envelope = source.exportSignedSnapshot(SECRET, {
    maxAgeMs: 3_600_000,
    now: 1_700_000_000_000,
  });
  assert.equal(
    envelope.expiresAt,
    new Date(1_700_000_000_000 + 3_600_000).toISOString(),
  );
  assert.throws(
    () =>
      source.exportSignedSnapshot(SECRET, {
        expiresAt: iso(1_700_003_600),
        maxAgeMs: 1000,
      }),
    /must not combine expiresAt and maxAgeMs/,
  );
});

test("jwks: expiry check runs before snapshot parsing (MAC-valid, expired, malformed snapshot)", () => {
  const malformedSnapshot = {
    v: 1,
    fetchedAtSec: 1_700_000_000,
    keys: "not-an-array",
  };
  const expiresAt = iso(1_700_003_600);
  const envelope = {
    v: 1,
    snapshot: malformedSnapshot,
    expiresAt,
    mac: macFor({ expiresAt, snapshot: malformedSnapshot }),
  };
  const target = new JwksKeyStore(URL, {
    fetchImpl: noFetch,
    now: () => 1_700_000_000,
  });
  // Expired: the expiry error wins over the snapshot error.
  assert.throws(
    () =>
      target.restoreSignedSnapshot(envelope, SECRET, {
        now: () => 1_700_003_601,
      }),
    /signed snapshot envelope expired at /,
  );
  // Within the window the same envelope fails on the snapshot instead.
  assert.throws(
    () =>
      target.restoreSignedSnapshot(envelope, SECRET, {
        now: () => 1_700_001_800,
      }),
    /"keys" must be an array/,
  );
  assert.equal(target.resolve("ed-key-1"), undefined);
});
