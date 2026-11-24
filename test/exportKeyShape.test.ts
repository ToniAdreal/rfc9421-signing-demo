import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import { createSecretKey } from "node:crypto";
import {
  exportPrivateKeyJwk,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  exportSymmetricKeyJwk,
  generateEd25519KeyPair,
  generateP256KeyPair,
  importPrivateKey,
  importPrivateKeyJwk,
  importPublicKey,
  importSymmetricKeyJwk,
  secretKey,
} from "../src/index.js";

// Backlog #1377: the four remaining key exporters read a key field
// before any null check — `exportPrivateKeyJwk(null)` /
// `exportSymmetricKeyJwk(null)` escaped as bare `TypeError`s
// (`reading 'type'`), `exportPublicKeyPem(null)` /
// `exportPrivateKeyPem(null)` as bare `TypeError`s (`reading
// 'export'`), while the import side already refused a `null` JWK
// with a named error (`importPrivateKeyJwk: invalid JWK: expected a
// JWK object, got null`) and the two JWK exporters called with `42`
// already failed with their named `expected a … KeyObject` shape
// errors. The JWK exporters now guard `null` / `undefined` first,
// before the shape check; the PEM exporters guard with an
// `instanceof KeyObject` check (the `createVerifiedHandler` shape),
// so a number, string or plain object gets the same named rejection
// as `null`. These cases pin the guard wording, the guard ordering,
// and the unchanged rejection and legal paths.

function expectExactError(
  fn: () => unknown,
  message: string,
): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof Error);
    assert.ok(!(err instanceof TypeError));
    assert.equal((err as Error).message, message);
    return true;
  });
}

// --- exportPrivateKeyJwk ---

test("exportPrivateKeyJwk: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => exportPrivateKeyJwk(null as unknown as KeyObject),
    "exportPrivateKeyJwk: expected an ed25519 private KeyObject, got null",
  );
});

test("exportPrivateKeyJwk: undefined throws a named Error", () => {
  expectExactError(
    () => exportPrivateKeyJwk(undefined as unknown as KeyObject),
    "exportPrivateKeyJwk: expected an ed25519 private KeyObject, got undefined",
  );
});

test("exportPrivateKeyJwk: number input keeps the existing shape error", () => {
  // A non-null non-KeyObject still reaches the shape check: the guard
  // only covers null/undefined, it does not swallow the existing
  // rejection for other wrong types.
  assert.throws(
    () => exportPrivateKeyJwk(42 as unknown as KeyObject),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.match(
        (err as Error).message,
        /exportPrivateKeyJwk: expected an ed25519 private KeyObject, got type=undefined asymmetricKeyType=undefined/,
      );
      return true;
    },
  );
});

test("exportPrivateKeyJwk: public key keeps the existing rejection", () => {
  const { publicKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportPrivateKeyJwk(publicKey),
    /exportPrivateKeyJwk: expected an ed25519 private KeyObject, got type=public asymmetricKeyType=ed25519/,
  );
});

test("exportPrivateKeyJwk: legal ed25519 private export is unchanged", () => {
  const { privateKey } = generateEd25519KeyPair();
  const jwk = exportPrivateKeyJwk(privateKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "d", "kty", "x"]);
  assert.equal(jwk.kty, "OKP");
  assert.equal(jwk.crv, "Ed25519");
  assert.equal(jwk.x.length, 43);
  assert.equal(jwk.d.length, 43);
  // Deterministic re-export and JSON wire round-trip.
  assert.deepEqual(exportPrivateKeyJwk(privateKey), jwk);
  const back = importPrivateKeyJwk(JSON.parse(JSON.stringify(jwk)));
  assert.deepEqual(exportPrivateKeyJwk(back), jwk);
});

// --- exportPublicKeyPem ---

test("exportPublicKeyPem: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => exportPublicKeyPem(null as unknown as KeyObject),
    "exportPublicKeyPem: expected a public KeyObject, got null",
  );
});

test("exportPublicKeyPem: undefined throws a named Error", () => {
  expectExactError(
    () => exportPublicKeyPem(undefined as unknown as KeyObject),
    "exportPublicKeyPem: expected a public KeyObject, got undefined",
  );
});

test("exportPublicKeyPem: number input throws the same named Error", () => {
  expectExactError(
    () => exportPublicKeyPem(42 as unknown as KeyObject),
    "exportPublicKeyPem: expected a public KeyObject, got number",
  );
});

test("exportPublicKeyPem: string and plain-object inputs throw the named Error", () => {
  expectExactError(
    () => exportPublicKeyPem("x" as unknown as KeyObject),
    "exportPublicKeyPem: expected a public KeyObject, got string",
  );
  expectExactError(
    () => exportPublicKeyPem({} as unknown as KeyObject),
    "exportPublicKeyPem: expected a public KeyObject, got object",
  );
});

test("exportPublicKeyPem: legal ed25519 and P-256 exports are unchanged", () => {
  const { publicKey: edKey } = generateEd25519KeyPair();
  const edPem = exportPublicKeyPem(edKey);
  assert.ok(edPem.startsWith("-----BEGIN PUBLIC KEY-----"));
  assert.ok(edPem.trimEnd().endsWith("-----END PUBLIC KEY-----"));
  assert.equal(exportPublicKeyPem(importPublicKey(edPem)), edPem);
  const { publicKey: p256Key } = generateP256KeyPair();
  const p256Pem = exportPublicKeyPem(p256Key);
  assert.ok(p256Pem.startsWith("-----BEGIN PUBLIC KEY-----"));
  assert.equal(exportPublicKeyPem(importPublicKey(p256Pem)), p256Pem);
});

test("exportPublicKeyPem: private key keeps the existing node:crypto rejection", () => {
  // node:crypto refuses an spki export from a private KeyObject; the
  // guard only covers non-KeyObjects, so this error is unchanged.
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportPublicKeyPem(privateKey),
    (err: unknown) => {
      assert.ok(err instanceof TypeError);
      assert.match(
        (err as Error).message,
        /The property 'options\.type' is invalid\. Received 'spki'/,
      );
      return true;
    },
  );
});

// --- exportPrivateKeyPem ---

test("exportPrivateKeyPem: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => exportPrivateKeyPem(null as unknown as KeyObject),
    "exportPrivateKeyPem: expected a private KeyObject, got null",
  );
});

test("exportPrivateKeyPem: undefined throws a named Error", () => {
  expectExactError(
    () => exportPrivateKeyPem(undefined as unknown as KeyObject),
    "exportPrivateKeyPem: expected a private KeyObject, got undefined",
  );
});

test("exportPrivateKeyPem: number input throws the same named Error", () => {
  expectExactError(
    () => exportPrivateKeyPem(42 as unknown as KeyObject),
    "exportPrivateKeyPem: expected a private KeyObject, got number",
  );
});

test("exportPrivateKeyPem: plain-object input throws the named Error", () => {
  expectExactError(
    () => exportPrivateKeyPem({} as unknown as KeyObject),
    "exportPrivateKeyPem: expected a private KeyObject, got object",
  );
});

test("exportPrivateKeyPem: legal ed25519 and P-256 exports are unchanged", () => {
  const { privateKey: edKey } = generateEd25519KeyPair();
  const edPem = exportPrivateKeyPem(edKey);
  assert.ok(edPem.startsWith("-----BEGIN PRIVATE KEY-----"));
  assert.ok(edPem.trimEnd().endsWith("-----END PRIVATE KEY-----"));
  assert.equal(exportPrivateKeyPem(importPrivateKey(edPem)), edPem);
  const { privateKey: p256Key } = generateP256KeyPair();
  const p256Pem = exportPrivateKeyPem(p256Key);
  assert.ok(p256Pem.startsWith("-----BEGIN PRIVATE KEY-----"));
  assert.equal(exportPrivateKeyPem(importPrivateKey(p256Pem)), p256Pem);
});

test("exportPrivateKeyPem: public key keeps the existing node:crypto rejection", () => {
  // node:crypto refuses a pkcs8 export from a public KeyObject; the
  // guard only covers non-KeyObjects, so this error is unchanged.
  const { publicKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportPrivateKeyPem(publicKey),
    (err: unknown) => {
      assert.ok(err instanceof TypeError);
      assert.match(
        (err as Error).message,
        /The property 'options\.type' is invalid\. Received 'pkcs8'/,
      );
      return true;
    },
  );
});

// --- exportSymmetricKeyJwk ---

test("exportSymmetricKeyJwk: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => exportSymmetricKeyJwk(null as unknown as KeyObject),
    "exportSymmetricKeyJwk: expected a secret (symmetric) KeyObject, got null",
  );
});

test("exportSymmetricKeyJwk: undefined throws a named Error", () => {
  expectExactError(
    () => exportSymmetricKeyJwk(undefined as unknown as KeyObject),
    "exportSymmetricKeyJwk: expected a secret (symmetric) KeyObject, got undefined",
  );
});

test("exportSymmetricKeyJwk: number input keeps the existing shape error", () => {
  // A non-null non-KeyObject still reaches the shape check: the guard
  // only covers null/undefined, it does not swallow the existing
  // rejection for other wrong types.
  assert.throws(
    () => exportSymmetricKeyJwk(42 as unknown as KeyObject),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.match(
        (err as Error).message,
        /exportSymmetricKeyJwk: expected a secret \(symmetric\) KeyObject, got type=undefined asymmetricKeyType=undefined/,
      );
      return true;
    },
  );
});

test("exportSymmetricKeyJwk: null key is reported before a bad alg option", () => {
  // The null guard runs first, before the alg/kid checks below it.
  expectExactError(
    () =>
      exportSymmetricKeyJwk(null as unknown as KeyObject, {
        alg: "bogus" as "HS256",
      }),
    "exportSymmetricKeyJwk: expected a secret (symmetric) KeyObject, got null",
  );
});

test("exportSymmetricKeyJwk: legal exports are unchanged, with and without metadata", () => {
  const key = secretKey("a".repeat(32));
  const jwk = exportSymmetricKeyJwk(key);
  assert.deepEqual(jwk, {
    kty: "oct",
    k: "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE",
  });
  assert.equal(jwk.k.length, 43);
  assert.deepEqual(exportSymmetricKeyJwk(key), jwk);
  const withMeta = exportSymmetricKeyJwk(key, {
    alg: "HS256",
    kid: "gw-1",
  });
  assert.deepEqual(withMeta, { ...jwk, kid: "gw-1", alg: "HS256" });
  // JSON wire round-trip through the importer.
  const back = importSymmetricKeyJwk(JSON.parse(JSON.stringify(withMeta)));
  assert.deepEqual(exportSymmetricKeyJwk(back, { alg: "HS256", kid: "gw-1" }), withMeta);
});

test("exportSymmetricKeyJwk: short secret and public key keep the existing rejections", () => {
  // A 16-byte secret cannot be built through `secretKey` (its own
  // 32-byte floor fires first), so build it with node:crypto directly
  // to reach the exporter's per-use floor check.
  assert.throws(
    () => exportSymmetricKeyJwk(createSecretKey(Buffer.alloc(16))),
    /assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes/,
  );
  const { publicKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportSymmetricKeyJwk(publicKey),
    /exportSymmetricKeyJwk: expected a secret \(symmetric\) KeyObject, got type=public asymmetricKeyType=ed25519/,
  );
});

test("exportSymmetricKeyJwk: 64-byte secret exports under HS512", () => {
  const key = secretKey("b".repeat(64));
  const jwk = exportSymmetricKeyJwk(key, { alg: "HS512" });
  assert.equal(jwk.kty, "oct");
  assert.equal(jwk.k.length, 86);
  assert.equal(jwk.alg, "HS512");
  assert.throws(
    () => exportSymmetricKeyJwk(secretKey("b".repeat(32)), { alg: "HS512" }),
    /assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes/,
  );
});
