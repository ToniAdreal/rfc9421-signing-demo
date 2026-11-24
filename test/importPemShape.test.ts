import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPrivateKeyPem,
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateP256KeyPair,
  importPrivateKey,
  importPublicKey,
} from "../src/index.js";

// Backlog #1388: the PEM importers passed their input straight through to
// `node:crypto` — `importPrivateKey(null)` escaped as a bare `TypeError`
// (`Cannot destructure property 'key' ...`), and `importPrivateKey(42)` /
// `importPublicKey({})` escaped as node:crypto `TypeError`s that never name
// the function, so a caller could not tell which importer was misused.
// The JWK importers and `secretKey` already throw named errors for the
// same shapes; the PEM pair now does the same, before `node:crypto` runs.
// These cases pin the guard shapes and the unchanged legal paths
// (string and Buffer PEMs, ed25519 + P-256 round-trips) and the unchanged
// malformed-PEM error from OpenSSL.

type PemImporter = (pem: string | Buffer) => unknown;

function expectNamedGuardError(
  fn: PemImporter,
  name: string,
  value: unknown,
  got: string,
): void {
  assert.throws(
    () => fn(value as string),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        `${name}: pem must be a string or a Buffer, got ${got}`,
      );
      return true;
    },
  );
}

for (const [name, fn] of [
  ["importPrivateKey", importPrivateKey],
  ["importPublicKey", importPublicKey],
] as const) {
  test(`${name}: null throws a named Error, not a bare TypeError`, () => {
    expectNamedGuardError(fn, name, null, "null");
  });

  test(`${name}: number input throws a named Error`, () => {
    expectNamedGuardError(fn, name, 42, "number");
  });

  test(`${name}: plain-object input throws a named Error`, () => {
    expectNamedGuardError(fn, name, {}, "object");
  });
}

test("importPrivateKey/importPublicKey: ed25519 PEM round-trip is byte-identical", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const privatePem = exportPrivateKeyPem(privateKey);
  const publicPem = exportPublicKeyPem(publicKey);
  assert.equal(exportPrivateKeyPem(importPrivateKey(privatePem)), privatePem);
  assert.equal(exportPublicKeyPem(importPublicKey(publicPem)), publicPem);
  assert.equal(
    exportPrivateKeyPem(importPrivateKey(Buffer.from(privatePem, "utf8"))),
    privatePem,
  );
  assert.equal(
    exportPublicKeyPem(importPublicKey(Buffer.from(publicPem, "utf8"))),
    publicPem,
  );
});

test("importPrivateKey/importPublicKey: P-256 PEM round-trip is byte-identical", () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const privatePem = exportPrivateKeyPem(privateKey);
  const publicPem = exportPublicKeyPem(publicKey);
  assert.equal(exportPrivateKeyPem(importPrivateKey(privatePem)), privatePem);
  assert.equal(exportPublicKeyPem(importPublicKey(publicPem)), publicPem);
});

test("importPrivateKey/importPublicKey: malformed PEM keeps the existing OpenSSL error", () => {
  // An empty string is a string, so the guard passes it through and the
  // pre-existing node:crypto/OpenSSL rejection surfaces unchanged — the
  // guard only names mistyped input, it does not re-wrap bad PEM bytes.
  for (const fn of [importPrivateKey, importPublicKey]) {
    assert.throws(
      () => fn(""),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err as Error).message.includes("must be a string or a Buffer"));
        return true;
      },
    );
  }
});
