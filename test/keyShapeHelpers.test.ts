import test from "node:test";
import assert from "node:assert/strict";
import {
  createSecretKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import {
  algMatchesKeyShape,
  assertRsaModulusLength,
  describeKey,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  inferAlgFromKeyShape,
} from "../src/index.js";

// Backlog #1378: the four key-shape introspection helpers in
// `src/keys.ts` read a `KeyObject` field on their first line with no
// null guard — `describeKey(null)` / `algMatchesKeyShape("ed25519",
// null)` / `inferAlgFromKeyShape(null)` /
// `assertRsaModulusLength(null, "probe")` all escaped as bare
// `TypeError`s (`reading 'type'` / `reading 'asymmetricKeyType'`),
// while the key exporters already refused a `null` key with a named
// `expected a … KeyObject, got null` error (backlog #1377) and the
// HMAC entry point `secretKey` did the same (backlog #1372). These
// helpers are the other call surface: `algMatchesKeyShape` /
// `inferAlgFromKeyShape` are the choke point of the sign/verify
// dispatch chain, so a caller passing the wrong key should get a
// named error, not a bare `TypeError` from deep inside dispatch.
// `algMatchesKeyShape`, `inferAlgFromKeyShape` and
// `assertRsaModulusLength` guard with an `instanceof KeyObject`
// check (the exporter shape), so a number, string or plain object
// gets the same named rejection as `null`. `describeKey` is the one
// deliberate exception: it formats the error message *about* a bad
// key, so it rejects only `null` / `undefined` (the inputs that
// cannot be read at all) and stays descriptive over anything else —
// the stub case in `test/algKeyShape.test.ts` pins that tolerance.
// These cases pin the guard wording, the guard ordering, and the
// unchanged legal-path behaviour.

function expectExactError(fn: () => unknown, message: string): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof Error);
    assert.ok(!(err instanceof TypeError));
    assert.equal((err as Error).message, message);
    return true;
  });
}

const ed25519 = generateEd25519KeyPair();
const p256 = generateP256KeyPair();
const rsa = generateRsaPssKeyPair();
const rsa1024 = generateKeyPairSync("rsa", { modulusLength: 1024 });
const secret32 = createSecretKey(Buffer.alloc(32, 0x2a));

// --- describeKey ---

test("describeKey: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => describeKey(null as unknown as KeyObject),
    "describeKey: expected a KeyObject, got null",
  );
  expectExactError(
    () => describeKey(undefined as unknown as KeyObject),
    "describeKey: expected a KeyObject, got undefined",
  );
});

test("describeKey: non-KeyObject values stay descriptive, not rejected", () => {
  // Deliberate exception to the `instanceof KeyObject` guard the other
  // three helpers use: `describeKey` formats the error message *about*
  // a bad key, so it must stay total over key-like objects — a number
  // or plain object describes as an unknown asymmetric key instead of
  // throwing (the stub case in `test/algKeyShape.test.ts` pins the
  // `?? "unknown"` fallback the same way). Only `null` / `undefined`
  // cannot be read at all, and those get the named error above.
  assert.equal(
    describeKey(42 as unknown as KeyObject),
    "an asymmetric unknown key",
  );
  assert.equal(
    describeKey({} as unknown as KeyObject),
    "an asymmetric unknown key",
  );
});

test("describeKey: legal key descriptions are unchanged", () => {
  assert.equal(describeKey(ed25519.privateKey), "an asymmetric ed25519 key");
  assert.equal(describeKey(p256.publicKey), "an asymmetric ec key (prime256v1)");
  assert.equal(describeKey(secret32), "a secret (symmetric) key");
  assert.equal(describeKey(rsa.publicKey), "an asymmetric rsa key");
});

// --- algMatchesKeyShape ---

test("algMatchesKeyShape: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => algMatchesKeyShape("ed25519", null as unknown as KeyObject),
    "algMatchesKeyShape: expected a KeyObject, got null",
  );
});

test("algMatchesKeyShape: non-KeyObject inputs get the same named rejection", () => {
  expectExactError(
    () => algMatchesKeyShape("hmac-sha256", 42 as unknown as KeyObject),
    "algMatchesKeyShape: expected a KeyObject, got number",
  );
  expectExactError(
    () =>
      algMatchesKeyShape(
        "ecdsa-p256-sha256",
        "not-a-key" as unknown as KeyObject,
      ),
    "algMatchesKeyShape: expected a KeyObject, got string",
  );
});

test("algMatchesKeyShape: legal pairings are unchanged", () => {
  assert.equal(algMatchesKeyShape("ed25519", ed25519.publicKey), true);
  assert.equal(algMatchesKeyShape("ed25519", secret32), false);
  assert.equal(algMatchesKeyShape("hmac-sha256", secret32), true);
  assert.equal(
    algMatchesKeyShape("ecdsa-p256-sha256", p256.publicKey),
    true,
  );
  assert.equal(algMatchesKeyShape("rsa-pss-sha512", rsa.publicKey), true);
  assert.equal(algMatchesKeyShape("rsa-pss-sha512", p256.publicKey), false);
  assert.equal(algMatchesKeyShape("unknown-alg", ed25519.publicKey), false);
});

// --- inferAlgFromKeyShape ---

test("inferAlgFromKeyShape: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => inferAlgFromKeyShape(null as unknown as KeyObject),
    "inferAlgFromKeyShape: expected a KeyObject, got null",
  );
});

test("inferAlgFromKeyShape: non-KeyObject inputs get the same named rejection", () => {
  expectExactError(
    () => inferAlgFromKeyShape(undefined as unknown as KeyObject),
    "inferAlgFromKeyShape: expected a KeyObject, got undefined",
  );
});

test("inferAlgFromKeyShape: legal inferences are unchanged", () => {
  assert.equal(inferAlgFromKeyShape(secret32), "hmac-sha256");
  assert.equal(inferAlgFromKeyShape(ed25519.privateKey), "ed25519");
  assert.equal(inferAlgFromKeyShape(p256.publicKey), "ecdsa-p256-sha256");
  assert.equal(inferAlgFromKeyShape(rsa.publicKey), "rsa-pss-sha512");
});

// --- assertRsaModulusLength ---

test("assertRsaModulusLength: null throws a named Error, not a bare TypeError", () => {
  expectExactError(
    () => assertRsaModulusLength(null as unknown as KeyObject, "probe"),
    "probe: expected an RSA KeyObject, got null",
  );
});

test("assertRsaModulusLength: non-KeyObject inputs get the same named rejection", () => {
  expectExactError(
    () =>
      assertRsaModulusLength(42 as unknown as KeyObject, "probe"),
    "probe: expected an RSA KeyObject, got number",
  );
});

test("assertRsaModulusLength: legal RSA key passes, existing rejections unchanged", () => {
  assert.doesNotThrow(() =>
    assertRsaModulusLength(rsa.publicKey, "probe"),
  );
  // A non-RSA key still fails with the existing shape wording.
  assert.throws(
    () => assertRsaModulusLength(p256.publicKey, "probe"),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        "probe: expected an RSA key, got an asymmetric ec key",
      );
      return true;
    },
  );
  // A sub-floor RSA key still fails with the existing modulus wording.
  assert.throws(
    () => assertRsaModulusLength(rsa1024.publicKey, "probe"),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        "probe: RSA modulus must be at least 2048 bits, got 1024 bits",
      );
      return true;
    },
  );
});
