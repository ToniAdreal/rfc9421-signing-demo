import test from "node:test";
import assert from "node:assert/strict";
import {
  createSecretKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import {
  algMatchesKeyShape,
  describeKey,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
} from "../src/index.js";

// Direct unit tests for the two exported key-shape helpers in
// `src/keys.ts` (#936): `algMatchesKeyShape` is the shared fail-fast
// predicate behind the sign-side and verify-side checks, and
// `describeKey` supplies the wording of their configuration errors.
// #936's tests only reached them through `signRequest`, so a change
// to the predicate or a message branch could only turn red
// indirectly. These tests pin the truth table and the message
// branches directly.

const ed25519 = generateEd25519KeyPair();
const p256 = generateP256KeyPair();
const p384 = generateP384KeyPair();
const p521 = generateP521KeyPair();
const rsa = generateRsaPssKeyPair();
const dsa = generateKeyPairSync("dsa", {
  modulusLength: 2048,
  divisorLength: 256,
});
const secret32 = createSecretKey(Buffer.alloc(32, 0x2a));
const secret16 = createSecretKey(Buffer.alloc(16, 0x2a));

test("algMatchesKeyShape: all eight supported pairings return true", () => {
  const pairings: Array<[string, KeyObject]> = [
    ["ed25519", ed25519.publicKey],
    ["hmac-sha256", secret32],
    ["hmac-sha512", secret32],
    ["ecdsa-p256-sha256", p256.publicKey],
    ["ecdsa-p384-sha384", p384.publicKey],
    ["ecdsa-p521-sha512", p521.publicKey],
    ["rsa-pss-sha512", rsa.publicKey],
    ["rsa-v1_5-sha256", rsa.publicKey],
  ];
  for (const [alg, key] of pairings) {
    assert.equal(
      algMatchesKeyShape(alg, key),
      true,
      `${alg} should match its own key shape`,
    );
  }
});

test("algMatchesKeyShape: shape, not secret length, decides HMAC", () => {
  // The predicate only checks `key.type === "secret"`; the 32/64-byte
  // floors are a separate policy enforced by assertHmacSecretLength.
  // A 16-byte secret still "matches" hmac-sha256 here — the sign
  // path rejects it later, at the length check.
  assert.equal(algMatchesKeyShape("hmac-sha256", secret16), true);
  assert.equal(algMatchesKeyShape("hmac-sha512", secret16), true);
});

test("algMatchesKeyShape: wrong key family returns false", () => {
  const mismatches: Array<[string, KeyObject]> = [
    ["ed25519", rsa.publicKey],
    ["ed25519", secret32],
    ["hmac-sha256", p256.publicKey],
    ["hmac-sha256", rsa.publicKey],
    ["hmac-sha512", rsa.publicKey],
    ["ecdsa-p256-sha256", secret32],
    ["rsa-pss-sha512", ed25519.publicKey],
    ["rsa-pss-sha512", secret32],
    ["rsa-v1_5-sha256", ed25519.publicKey],
    ["rsa-v1_5-sha256", p521.publicKey],
  ];
  for (const [alg, key] of mismatches) {
    assert.equal(
      algMatchesKeyShape(alg, key),
      false,
      `${alg} must not match a ${key.asymmetricKeyType ?? key.type} key`,
    );
  }
});

test("algMatchesKeyShape: wrong EC curve returns false", () => {
  const mismatches: Array<[string, KeyObject]> = [
    ["ecdsa-p256-sha256", p384.publicKey],
    ["ecdsa-p256-sha256", p521.publicKey],
    ["ecdsa-p384-sha384", p256.publicKey],
    ["ecdsa-p384-sha384", p521.publicKey],
    ["ecdsa-p521-sha512", p256.publicKey],
    ["ecdsa-p521-sha512", p384.publicKey],
  ];
  for (const [alg, key] of mismatches) {
    assert.equal(
      algMatchesKeyShape(alg, key),
      false,
      `${alg} must not match a key on curve ${key.asymmetricKeyDetails?.namedCurve}`,
    );
  }
});

test("algMatchesKeyShape: unknown alg returns false instead of throwing", () => {
  // An unknown alg is not this predicate's job — the dispatch below
  // reports UNSUPPORTED_ALG / unsupported alg. The predicate must
  // stay total: no throw, just false.
  for (const alg of ["unknown-alg", "", "rsa-pss-sha256", "Ed25519"]) {
    assert.equal(
      algMatchesKeyShape(alg, ed25519.publicKey),
      false,
      `unknown alg ${JSON.stringify(alg)} must return false`,
    );
  }
  assert.equal(algMatchesKeyShape("not-an-alg", rsa.publicKey), false);
  assert.equal(algMatchesKeyShape("not-an-alg", secret32), false);
});

test("algMatchesKeyShape: private keys match the same as public keys", () => {
  // The sign side hands the predicate private keys, the verify side
  // public ones — both must see the same truth table.
  assert.equal(algMatchesKeyShape("ed25519", ed25519.privateKey), true);
  assert.equal(
    algMatchesKeyShape("ecdsa-p256-sha256", p256.privateKey),
    true,
  );
  assert.equal(
    algMatchesKeyShape("ecdsa-p384-sha384", p384.privateKey),
    true,
  );
  assert.equal(
    algMatchesKeyShape("ecdsa-p521-sha512", p521.privateKey),
    true,
  );
  assert.equal(algMatchesKeyShape("rsa-pss-sha512", rsa.privateKey), true);
  assert.equal(algMatchesKeyShape("rsa-v1_5-sha256", rsa.privateKey), true);
  assert.equal(algMatchesKeyShape("ed25519", rsa.privateKey), false);
  assert.equal(
    algMatchesKeyShape("ecdsa-p384-sha384", p256.privateKey),
    false,
  );
});

test("describeKey: secret key", () => {
  assert.equal(describeKey(secret32), "a secret (symmetric) key");
  assert.equal(describeKey(secret16), "a secret (symmetric) key");
});

test("describeKey: EC keys include the curve", () => {
  assert.equal(
    describeKey(p256.publicKey),
    "an asymmetric ec key (prime256v1)",
  );
  assert.equal(
    describeKey(p384.publicKey),
    "an asymmetric ec key (secp384r1)",
  );
  assert.equal(
    describeKey(p521.publicKey),
    "an asymmetric ec key (secp521r1)",
  );
});

test("describeKey: RSA key has no curve", () => {
  assert.equal(describeKey(rsa.publicKey), "an asymmetric rsa key");
});

test("describeKey: ed25519 key has no curve", () => {
  assert.equal(describeKey(ed25519.publicKey), "an asymmetric ed25519 key");
});

test("describeKey: other asymmetric key types are described, not rejected", () => {
  // The helper is not hard-coded to the eight supported algs: a DSA
  // key — unusable for signing here — still gets a readable
  // description in the configuration error instead of a crash.
  assert.equal(describeKey(dsa.publicKey), "an asymmetric dsa key");
});

test("describeKey: private key describes the same as its public key", () => {
  assert.equal(
    describeKey(p256.privateKey),
    describeKey(p256.publicKey),
  );
  assert.equal(
    describeKey(rsa.privateKey),
    describeKey(rsa.publicKey),
  );
  assert.equal(
    describeKey(ed25519.privateKey),
    describeKey(ed25519.publicKey),
  );
});

test("describeKey: unknown key type falls back to 'unknown'", () => {
  // node:crypto always sets asymmetricKeyType on a real asymmetric
  // key, so the `?? "unknown"` fallback is defensive only. Exercise
  // it with a minimal stub — a public key object with no type
  // metadata — rather than leaving the branch unpinned.
  const stub = { type: "public" } as unknown as KeyObject;
  assert.equal(describeKey(stub), "an asymmetric unknown key");
});
