import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  generateEd25519KeyPair,
  generateRsaPssKeyPair,
  signRequest,
  verifyRequest,
} from "../src/index.js";

// Backlog #1415: the 2048-bit RSA modulus floor (`MIN_RSA_MODULUS_BITS`,
// `assertRsaModulusLength`) was enforced on the `rsa-v1_5-sha256` sign
// and verify paths but not on `rsa-pss-sha512`, so a KeyObject passed
// directly (bypassing the JWK/JWKS import guards) could mint and verify
// sub-floor PSS signatures. A 1024-bit key only failed signing with a
// raw OpenSSL "data too large for key size" (SHA-512 + 64-byte salt
// does not fit a 128-byte modulus), and a 1536-bit key signed and
// verified cleanly — treated as exactly as trustworthy as a 2048-bit
// key. Both sides now fail fast with the named configuration error.

const CREATED = 1700000000;

const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ amount: 100, currency: "USD" }),
};

function signPss2048() {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const signed = signRequest(REQ, {
    keyId: "rsa-pss",
    alg: "rsa-pss-sha512",
    key: privateKey,
    created: CREATED,
  });
  return { publicKey, privateKey, signed };
}

test("a 1024-bit RSA key is rejected when signing rsa-pss-sha512, with the named error", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });

  // Before #1415 this threw a raw OpenSSL error ("data too large for
  // key size"); the floor guard now names the configuration error.
  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "weak",
        alg: "rsa-pss-sha512",
        key: weak.privateKey,
        created: CREATED,
      }),
    /signRequest: alg "rsa-pss-sha512": RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
});

test("a 1536-bit RSA key is rejected when signing rsa-pss-sha512 (above the OpenSSL limit, below the floor)", () => {
  const mid = generateKeyPairSync("rsa", { modulusLength: 1536 });

  // 1536 bits fits SHA-512 + 64-byte salt, so without the guard this
  // minted a signature the verifier accepted; only the floor stops it.
  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "mid",
        alg: "rsa-pss-sha512",
        key: mid.privateKey,
        created: CREATED,
      }),
    /signRequest: alg "rsa-pss-sha512": RSA modulus must be at least 2048 bits, got 1536 bits/,
  );
});

test("a 1024-bit RSA key is rejected when verifying rsa-pss-sha512, not reported as SIGNATURE_MISMATCH", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const { signed } = signPss2048();

  assert.throws(
    () => verifyRequest(signed, { key: weak.publicKey, now: CREATED + 60 }),
    /verifyRequest: alg "rsa-pss-sha512": RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
});

test("a 1536-bit RSA key is rejected when verifying rsa-pss-sha512", () => {
  const mid = generateKeyPairSync("rsa", { modulusLength: 1536 });
  const { signed } = signPss2048();

  assert.throws(
    () => verifyRequest(signed, { key: mid.publicKey, now: CREATED + 60 }),
    /verifyRequest: alg "rsa-pss-sha512": RSA modulus must be at least 2048 bits, got 1536 bits/,
  );
});

test("a 2048-bit RSA key still signs and verifies rsa-pss-sha512", () => {
  const { publicKey, signed } = signPss2048();

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("a non-RSA key paired with rsa-pss-sha512 still reports ALG_NOT_ALLOWED on verify, not a throw", () => {
  const { publicKey: edPub } = generateEd25519KeyPair();
  const { signed } = signPss2048();

  // Backlog #1410: a mismatched alg/key pairing is a verification
  // verdict, so a foreign signer cannot force an exception by
  // declaring a mismatched alg. The modulus throw only fires once the
  // key is known to be RSA, which is why this stays a verdict.
  const res = verifyRequest(signed, { key: edPub, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "ALG_NOT_ALLOWED");
});

test("a non-RSA key paired with rsa-pss-sha512 is still refused on sign with the shape error", () => {
  const { privateKey: edPriv } = generateEd25519KeyPair();

  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "ed",
        alg: "rsa-pss-sha512",
        key: edPriv,
        created: CREATED,
      }),
    /signRequest: alg "rsa-pss-sha512" is incompatible with the key \(an asymmetric ed25519 key\)/,
  );
});

test("candidateKeys: a sub-floor RSA candidate throws out of the walk instead of being silently skipped", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const { publicKey, signed } = signPss2048();

  // A misconfigured candidate is a caller bug, not a mismatch: the
  // walk throws instead of advancing to the good candidate.
  assert.throws(
    () =>
      verifyRequest(signed, {
        candidateKeys: [weak.publicKey, publicKey],
        now: CREATED + 60,
      }),
    /verifyRequest: alg "rsa-pss-sha512": RSA modulus must be at least 2048 bits, got 1024 bits/,
  );

  // The good candidate first still verifies: the weak key is never
  // reached, so the walk is unaffected.
  const res = verifyRequest(signed, {
    candidateKeys: [publicKey, weak.publicKey],
    now: CREATED + 60,
  });
  assert.equal(res.ok, true);
});

test("rsa-v1_5-sha256 behavior is unchanged: 2048-bit round-trip passes, 1024-bit still throws", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });

  const v15 = signRequest(REQ, {
    keyId: "rsa-v15",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(
    verifyRequest(v15, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );

  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "weak",
        alg: "rsa-v1_5-sha256",
        key: weak.privateKey,
        created: CREATED,
      }),
    /RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
  assert.throws(
    () => verifyRequest(v15, { key: weak.publicKey, now: CREATED + 60 }),
    /RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
});
