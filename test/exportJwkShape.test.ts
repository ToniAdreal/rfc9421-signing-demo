import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  generateP256KeyPair,
  importPublicKeyJwk,
  secretKey,
  signRequest,
  verifyRequest,
} from "../src/index.js";

// Backlog #1373: `exportPublicKeyJwk` read `key.type` before any null
// check — `exportPublicKeyJwk(null)` escaped as a bare `TypeError`
// (`reading 'type'`), while the import side (`importPublicKeyJwk`)
// already refused a `null` JWK with a named error
// (`importPublicKeyJwk: invalid JWK: expected a JWK object, got null`)
// and `exportPublicKeyJwk(42)` already failed with the named
// `expected an ed25519 public KeyObject` error. The guard now runs
// first, before the shape check, throwing a plain named `Error` for a
// `null` / `undefined` key. These cases pin the guard wording, the
// guard-before-shape ordering, and the unchanged rejection and legal
// paths.

function expectNamedNullError(value: unknown, got: string): void {
  assert.throws(
    () => exportPublicKeyJwk(value as KeyObject),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        `exportPublicKeyJwk: expected an ed25519 public KeyObject, got ${got}`,
      );
      return true;
    },
  );
}

test("exportPublicKeyJwk: null throws a named Error, not a bare TypeError", () => {
  expectNamedNullError(null, "null");
});

test("exportPublicKeyJwk: undefined throws a named Error", () => {
  expectNamedNullError(undefined, "undefined");
});

test("exportPublicKeyJwk: number input keeps the existing shape error", () => {
  // A non-null non-KeyObject still reaches the shape check: the guard
  // only covers null/undefined, it does not swallow the existing
  // rejection for other wrong types.
  assert.throws(
    () => exportPublicKeyJwk(42 as unknown as KeyObject),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.match(
        (err as Error).message,
        /exportPublicKeyJwk: expected an ed25519 public KeyObject, got type=undefined asymmetricKeyType=undefined/,
      );
      return true;
    },
  );
});

test("exportPublicKeyJwk: private key keeps the existing rejection", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportPublicKeyJwk(privateKey),
    /exportPublicKeyJwk: expected an ed25519 public KeyObject, got type=private asymmetricKeyType=ed25519/,
  );
});

test("exportPublicKeyJwk: P-256 public key keeps the existing rejection", () => {
  const { publicKey } = generateP256KeyPair();
  assert.throws(
    () => exportPublicKeyJwk(publicKey),
    /exportPublicKeyJwk: expected an ed25519 public KeyObject, got type=public asymmetricKeyType=ec/,
  );
});

test("exportPublicKeyJwk: HMAC secret keeps the existing rejection", () => {
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  assert.throws(
    () => exportPublicKeyJwk(secret),
    /exportPublicKeyJwk: expected an ed25519 public KeyObject, got type=secret/,
  );
});

test("exportPublicKeyJwk: legal ed25519 export is unchanged", () => {
  const { publicKey } = generateEd25519KeyPair();
  const jwk = exportPublicKeyJwk(publicKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x"]);
  assert.equal(jwk.kty, "OKP");
  assert.equal(jwk.crv, "Ed25519");
  assert.equal(typeof jwk.x, "string");
  assert.equal(jwk.x.length, 43);
  // Deterministic: re-exporting the same key yields the same JWK.
  assert.deepEqual(exportPublicKeyJwk(publicKey), jwk);
});

test("exportPublicKeyJwk: export → JSON wire → import → verify round-trip is unchanged", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const jwk = exportPublicKeyJwk(publicKey);
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwk(received);
  assert.equal(
    imported.export({ format: "pem", type: "spki" }).toString(),
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    { keyId: "merchant-key-1", alg: "ed25519", key: privateKey, created: 1700000000 },
  );
  const result = verifyRequest(signed, { key: imported });
  assert.equal(result.ok, true);
});
