import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  importPublicKeyJwkP256,
} from "../src/index.js";

// Backlog #1374: the four curve/RSA public-key JWK exporters read a key
// field before any null check — `exportPublicKeyJwkP256(null)` /
// `exportPublicKeyJwkP384(null)` / `exportPublicKeyJwkP521(null)` escaped
// as a bare `TypeError` (`reading 'asymmetricKeyDetails'`), and
// `exportPublicKeyJwkRsa(null)` as a bare `TypeError` (`reading 'type'`),
// while the import side (`importPublicKeyJwkP256` and friends) already
// refused a `null` JWK with a named error
// (`importPublicKeyJwkP256: invalid JWK: expected a JWK object, got null`)
// and `exportPublicKeyJwk*(42)` already failed with the named
// `expected a … public KeyObject` shape error. The guard now runs first,
// before the shape check, throwing a plain named `Error` for a `null` /
// `undefined` key. These cases pin the guard wording, the
// guard-before-shape ordering, and the unchanged rejection and legal
// paths. (The ed25519 exporter got the same guard in #1373.)

type Exporter = (key: KeyObject) => unknown;

interface ExporterCase {
  label: string;
  fnName: string;
  fn: Exporter;
  /** Exact `expected a/an … public KeyObject` phrase the guard uses. */
  expectedPhrase: string;
  /** Regex the pre-existing shape error for `42` must match. */
  shapePattern: RegExp;
  generate: () => { publicKey: KeyObject; privateKey: KeyObject };
}

const CASES: ExporterCase[] = [
  {
    label: "P-256",
    fnName: "exportPublicKeyJwkP256",
    fn: exportPublicKeyJwkP256 as Exporter,
    expectedPhrase: "a P-256 public KeyObject",
    shapePattern:
      /exportPublicKeyJwkP256: expected a P-256 public KeyObject, got type=undefined asymmetricKeyType=undefined namedCurve=undefined/,
    generate: generateP256KeyPair,
  },
  {
    label: "P-384",
    fnName: "exportPublicKeyJwkP384",
    fn: exportPublicKeyJwkP384 as Exporter,
    expectedPhrase: "a P-384 public KeyObject",
    shapePattern:
      /exportPublicKeyJwkP384: expected a P-384 public KeyObject, got type=undefined asymmetricKeyType=undefined namedCurve=undefined/,
    generate: generateP384KeyPair,
  },
  {
    label: "P-521",
    fnName: "exportPublicKeyJwkP521",
    fn: exportPublicKeyJwkP521 as Exporter,
    expectedPhrase: "a P-521 public KeyObject",
    shapePattern:
      /exportPublicKeyJwkP521: expected a P-521 public KeyObject, got type=undefined asymmetricKeyType=undefined namedCurve=undefined/,
    generate: generateP521KeyPair,
  },
  {
    label: "RSA",
    fnName: "exportPublicKeyJwkRsa",
    fn: exportPublicKeyJwkRsa as Exporter,
    expectedPhrase: "an RSA public KeyObject",
    shapePattern:
      /exportPublicKeyJwkRsa: expected an RSA public KeyObject, got type=undefined asymmetricKeyType=undefined/,
    generate: generateRsaPssKeyPair,
  },
];

function expectNamedNullError(c: ExporterCase, value: unknown, got: string): void {
  assert.throws(
    () => c.fn(value as KeyObject),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        `${c.fnName}: expected ${c.expectedPhrase}, got ${got}`,
      );
      return true;
    },
  );
}

for (const c of CASES) {
  test(`${c.fnName}: null throws a named Error, not a bare TypeError`, () => {
    expectNamedNullError(c, null, "null");
  });

  test(`${c.fnName}: undefined throws a named Error`, () => {
    expectNamedNullError(c, undefined, "undefined");
  });

  test(`${c.fnName}: number input keeps the existing shape error`, () => {
    // A non-null non-KeyObject still reaches the shape check: the guard
    // only covers null/undefined, it does not swallow the existing
    // rejection for other wrong types.
    assert.throws(
      () => c.fn(42 as unknown as KeyObject),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof TypeError));
        assert.match((err as Error).message, c.shapePattern);
        return true;
      },
    );
  });

  test(`${c.fnName}: legal public key export is unchanged`, () => {
    const { publicKey } = c.generate();
    const jwk = c.fn(publicKey) as Record<string, unknown>;
    assert.equal(typeof jwk["kty"], "string");
    // Deterministic: re-exporting the same key yields the same JWK.
    assert.deepEqual(c.fn(publicKey), jwk);
  });
}

test("exportPublicKeyJwkP384: P-256 public key keeps the existing rejection", () => {
  const { publicKey } = generateP256KeyPair();
  assert.throws(
    () => exportPublicKeyJwkP384(publicKey),
    /exportPublicKeyJwkP384: expected a P-384 public KeyObject, got type=public asymmetricKeyType=ec namedCurve=prime256v1/,
  );
});

test("exportPublicKeyJwkP256: ed25519 public key keeps the existing rejection", () => {
  const { publicKey } = generateEd25519KeyPair();
  assert.throws(
    () => exportPublicKeyJwkP256(publicKey),
    /exportPublicKeyJwkP256: expected a P-256 public KeyObject, got type=public asymmetricKeyType=ed25519 namedCurve=undefined/,
  );
});

test("exportPublicKeyJwkRsa: RSA private key keeps the existing rejection", () => {
  const { privateKey } = generateRsaPssKeyPair();
  assert.throws(
    () => exportPublicKeyJwkRsa(privateKey),
    /exportPublicKeyJwkRsa: expected an RSA public KeyObject, got type=private asymmetricKeyType=rsa/,
  );
});

test("exportPublicKeyJwkP256: export → JSON wire → import round-trip is unchanged", () => {
  const { publicKey } = generateP256KeyPair();
  const jwk = exportPublicKeyJwkP256(publicKey);
  assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.equal(typeof jwk.x, "string");
  assert.equal(typeof jwk.y, "string");
  const received = JSON.parse(JSON.stringify(jwk)) as unknown;
  const imported = importPublicKeyJwkP256(received);
  assert.equal(
    imported.export({ format: "pem", type: "spki" }).toString(),
    publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
});
