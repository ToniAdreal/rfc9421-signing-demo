import test from "node:test";
import assert from "node:assert/strict";
import { createSecretKey, type KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportSymmetricKeyJwk,
  generateEd25519KeyPair,
  importSymmetricKeyJwk,
  JwksKeyStore,
  secretKey,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksSignedSnapshotEnvelope,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

function signHmac(
  keyId: string,
  alg: "hmac-sha256" | "hmac-sha512",
  key: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId, alg, key, created: CREATED });
}

/** Deterministic fixtures: fixed bytes, no randomness. */
const SECRET_32 = secretKey(Buffer.alloc(32, 7));
const SECRET_40 = secretKey(Buffer.alloc(40, 7));
const SECRET_64 = secretKey(Buffer.alloc(64, 9));

test("export→JSON wire→import→verify round-trip passes (hmac-sha256)", () => {
  const jwk = exportSymmetricKeyJwk(SECRET_32);
  // The JWK crosses the wire as JSON text, like a webhook JWKS entry.
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importSymmetricKeyJwk(received);
  // Byte identity: the same secret bytes came back.
  const importedJwk = imported.export({ format: "jwk" }) as unknown as {
    k: string;
  };
  assert.equal(importedJwk.k, jwk.k);
  const signed = signHmac("hmac-key-1", "hmac-sha256", SECRET_32);
  const result = verifyRequest(signed, { key: imported, now: CREATED });
  assert.equal(result.ok, true);
});

test("exported JWK has the RFC 7518 oct shape", () => {
  const jwk = exportSymmetricKeyJwk(SECRET_32);
  assert.deepEqual(Object.keys(jwk).sort(), ["k", "kty"]);
  assert.equal(jwk.kty, "oct");
  assert.match(jwk.k, /^[A-Za-z0-9_-]{43}$/); // 32 bytes base64url, no padding
  assert.ok(!("d" in jwk), "oct JWKs carry the secret in k, never in d");
  assert.equal(jwk.k, Buffer.alloc(32, 7).toString("base64url"));
});

test("export is deterministic for the same key", () => {
  assert.deepEqual(
    exportSymmetricKeyJwk(SECRET_32),
    exportSymmetricKeyJwk(SECRET_32),
  );
});

test("export with HS512 + kid records alg and kid, and hmac-sha512 verifies", () => {
  const jwk = exportSymmetricKeyJwk(SECRET_64, {
    alg: "HS512",
    kid: "hs512-key",
  });
  assert.equal(jwk.alg, "HS512");
  assert.equal(jwk.kid, "hs512-key");
  const imported = importSymmetricKeyJwk(JSON.parse(JSON.stringify(jwk)));
  const signed = signHmac("hs512-key", "hmac-sha512", SECRET_64);
  assert.equal(verifyRequest(signed, { key: imported, now: CREATED }).ok, true);
});

test("exportSymmetricKeyJwk rejects non-secret keys", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportSymmetricKeyJwk(publicKey),
    /exportSymmetricKeyJwk: expected a secret \(symmetric\) KeyObject/,
  );
  assert.throws(
    () => exportSymmetricKeyJwk(privateKey),
    /exportSymmetricKeyJwk: expected a secret \(symmetric\) KeyObject/,
  );
});

test("export enforces the per-alg secret floor and validates opts", () => {
  const short = createSecretKey(Buffer.alloc(31, 7));
  assert.throws(
    () => exportSymmetricKeyJwk(short),
    /hmac-sha256 secret must be at least 32 bytes/,
  );
  // 40 bytes clears the HS256 floor but not the HS512 one.
  assert.throws(
    () => exportSymmetricKeyJwk(SECRET_40, { alg: "HS512" }),
    /hmac-sha512 secret must be at least 64 bytes/,
  );
  assert.doesNotThrow(() =>
    exportSymmetricKeyJwk(SECRET_40, { alg: "HS256" }),
  );
  assert.throws(
    () => exportSymmetricKeyJwk(SECRET_32, { alg: "HS999" as never }),
    /`alg` must be "HS256" or "HS512"/,
  );
  assert.throws(
    () => exportSymmetricKeyJwk(SECRET_32, { kid: "" }),
    /`kid` must be a non-empty string/,
  );
});

test("import rejects a too-short secret", () => {
  const k = Buffer.alloc(16, 7).toString("base64url");
  assert.throws(
    () => importSymmetricKeyJwk({ kty: "oct", k }),
    /importSymmetricKeyJwk: invalid JWK: hmac-sha256 secret must be at least 32 bytes.*got 16 bytes/,
  );
});

test("import rejects malformed k", () => {
  const good = Buffer.alloc(32, 7).toString("base64url");
  const cases: Array<[string, unknown]> = [
    ["missing k", { kty: "oct" }],
    ["empty k", { kty: "oct", k: "" }],
    ["non-string k", { kty: "oct", k: 42 }],
    ["padded k", { kty: "oct", k: `${good}=` }],
    ["non-base64url k", { kty: "oct", k: "!!!not-base64url!!!" }],
    ["length mod 4 == 1", { kty: "oct", k: "A" }],
  ];
  for (const [label, jwk] of cases)
    assert.throws(() => importSymmetricKeyJwk(jwk), /invalid JWK/, label);
  // Non-canonical trailing bits: the last char of a 32-byte encoding
  // must have its low two bits zero; bumping it by one alphabet step
  // keeps the length but changes the decoded bytes, so the re-encode
  // check must catch it.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = good.slice(-1);
  const bumped = alphabet[(alphabet.indexOf(last) + 1) % 64];
  assert.throws(
    () => importSymmetricKeyJwk({ kty: "oct", k: good.slice(0, -1) + bumped }),
    /not canonical base64url/,
  );
});

test("import rejects non-oct kty and stray private material", () => {
  const { publicKey } = generateEd25519KeyPair();
  const okp = exportPublicKeyJwk(publicKey);
  assert.throws(
    () => importSymmetricKeyJwk(okp),
    /importSymmetricKeyJwk: invalid JWK: expected kty "oct", got "OKP"/,
  );
  assert.throws(
    () => importSymmetricKeyJwk({ kty: "oct", k: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", d: "x" }),
    /unexpected "d" member/,
  );
});

test("import rejects non-object input", () => {
  for (const bad of [null, [], "oct", 42, undefined])
    assert.throws(
      () => importSymmetricKeyJwk(bad),
      /importSymmetricKeyJwk: invalid JWK: expected a JWK object/,
    );
});

test("import honors a declared HS512 alg, and rejects unknown alg values", () => {
  const k40 = Buffer.alloc(40, 7).toString("base64url");
  assert.throws(
    () => importSymmetricKeyJwk({ kty: "oct", k: k40, alg: "HS512" }),
    /hmac-sha512 secret must be at least 64 bytes/,
  );
  // Same 40 bytes are fine for HS256 use, declared or defaulted.
  assert.doesNotThrow(() =>
    importSymmetricKeyJwk({ kty: "oct", k: k40, alg: "HS256" }),
  );
  assert.doesNotThrow(() => importSymmetricKeyJwk({ kty: "oct", k: k40 }));
  assert.doesNotThrow(() =>
    importSymmetricKeyJwk({
      kty: "oct",
      k: Buffer.alloc(64, 9).toString("base64url"),
      alg: "HS512",
    }),
  );
  assert.throws(
    () => importSymmetricKeyJwk({ kty: "oct", k: k40, alg: "HS999" }),
    /unsupported "alg" "HS999" for an oct key/,
  );
});

/** Mixed JWKS document: an ed25519 key and an HMAC oct key side by side. */
function mixedDocument(): { keys: unknown[] } {
  const { publicKey } = generateEd25519KeyPair();
  return {
    keys: [
      { ...exportPublicKeyJwk(publicKey), kid: "ed-key-1" },
      { ...exportSymmetricKeyJwk(SECRET_32), kid: "hmac-key-1" },
    ],
  };
}

function stubFetch(doc: unknown): JwksFetchImpl {
  return async () => ({ ok: true, status: 200, json: async () => doc });
}

test("JwksKeyStore refresh imports an oct entry and hmac-sha256 verifies", async () => {
  const doc = mixedDocument();
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 2);
  const resolved = store.resolve("hmac-key-1");
  assert.ok(resolved !== undefined);
  assert.equal(resolved.type, "secret");
  const signed = signHmac("hmac-key-1", "hmac-sha256", SECRET_32);
  const result = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(result.ok, true);
  // The ed25519 sibling in the same document still resolves too.
  assert.ok(store.resolve("ed-key-1") !== undefined);
});

test("JwksKeyStore refresh rejects an oct entry whose alg mismatches its family", async () => {
  const doc = {
    keys: [
      {
        ...exportSymmetricKeyJwk(SECRET_32),
        kid: "hmac-key-1",
        alg: "ES256",
      },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await assert.rejects(() => store.refresh(), /does not match this key's family/);
  assert.equal(store.size, 0);
});

test("JwksKeyStore refresh rejects an oct entry below the secret floor", async () => {
  const doc = {
    keys: [
      {
        kty: "oct",
        k: Buffer.alloc(16, 7).toString("base64url"),
        kid: "weak-hmac",
      },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await assert.rejects(() => store.refresh(), /at least 32 bytes/);
  assert.equal(store.size, 0);
});

test("snapshot export/restore round-trips an oct key (unsigned and signed)", async () => {
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(mixedDocument()),
    now: () => CREATED,
  });
  await store.refresh();
  const snapshot: unknown = JSON.parse(
    JSON.stringify(store.exportSnapshot()),
  );
  const snapshotKeys = (snapshot as { keys: Array<Record<string, unknown>> })
    .keys;
  const octEntry = snapshotKeys.find((k) => k["kty"] === "oct");
  assert.ok(octEntry !== undefined, "snapshot must carry the oct entry");
  assert.equal(octEntry["kid"], "hmac-key-1");
  assert.equal(
    octEntry["k"],
    exportSymmetricKeyJwk(SECRET_32).k,
    "snapshot preserves the secret bytes",
  );

  const restored = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch({ keys: [] }),
    now: () => CREATED,
  });
  restored.restoreSnapshot(snapshot);
  assert.equal(restored.size, 2);
  const signed = signHmac("hmac-key-1", "hmac-sha256", SECRET_32);
  assert.equal(
    verifyRequest(signed, { keyResolver: restored.resolve, now: CREATED })
      .ok,
    true,
  );

  // The signed envelope covers the oct entry too: a tampered k fails
  // the MAC before any key is installed.
  const envelope: JwksSignedSnapshotEnvelope =
    store.exportSignedSnapshot("snapshot-signing-secret-for-tests-only");
  const persisted: unknown = JSON.parse(JSON.stringify(envelope));
  const signed2 = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch({ keys: [] }),
    now: () => CREATED,
  });
  signed2.restoreSignedSnapshot(
    persisted,
    "snapshot-signing-secret-for-tests-only",
  );
  assert.equal(signed2.size, 2);
  assert.equal(
    verifyRequest(signed, { keyResolver: signed2.resolve, now: CREATED })
      .ok,
    true,
  );
});
