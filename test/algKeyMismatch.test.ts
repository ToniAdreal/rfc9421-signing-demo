import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyRequest,
  type RequestLike,
  type SignAlg,
} from "../src/index.js";

// Backlog #936: the sign side used to hand `opts.key` straight to
// node:crypto with no shape check, so an RSA key paired with
// `alg: "ed25519"` (or any other swapped pair) surfaced as a cryptic
// node:crypto error that said nothing about which of the two was
// wrong. `signRequest` now fails fast with a clear configuration
// error before the signature base is built or any crypto runs.
// `signResponse`, `addSignature`, and `addResponseSignature` inherit
// the check through `signRequest`.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function req(body?: string): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body } : {}),
  };
}

const ed = generateEd25519KeyPair();
const p256 = generateP256KeyPair();
const p384 = generateP384KeyPair();
const p521 = generateP521KeyPair();
const rsa = generateRsaPssKeyPair();
const hmac32 = secretKey("a".repeat(32));
const hmac64 = secretKey("b".repeat(64));

test("ed25519 alg + RSA key throws the exact configuration error", () => {
  assert.throws(
    () => signRequest(req(), { alg: "ed25519", key: rsa.privateKey, created: CREATED }),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'signRequest: alg "ed25519" is incompatible with the key (an asymmetric rsa key) — pass a key of the matching type for the algorithm',
  );
});

test("ed25519 alg + secret key throws, naming the key shape", () => {
  assert.throws(
    () => signRequest(req(), { alg: "ed25519", key: hmac32, created: CREATED }),
    /signRequest: alg "ed25519" is incompatible with the key \(a secret \(symmetric\) key\)/,
  );
});

test("hmac-sha256 alg + ed25519 key throws", () => {
  assert.throws(
    () => signRequest(req(), { alg: "hmac-sha256", key: ed.privateKey, created: CREATED }),
    /signRequest: alg "hmac-sha256" is incompatible with the key \(an asymmetric ed25519 key\)/,
  );
});

test("hmac-sha512 alg + P-256 key throws", () => {
  assert.throws(
    () => signRequest(req(), { alg: "hmac-sha512", key: p256.privateKey, created: CREATED }),
    /signRequest: alg "hmac-sha512" is incompatible with the key \(an asymmetric ec key \(prime256v1\)\)/,
  );
});

test("ecdsa-p256-sha256 alg + P-384 key throws (curve mismatch, not just key type)", () => {
  assert.throws(
    () => signRequest(req(), { alg: "ecdsa-p256-sha256", key: p384.privateKey, created: CREATED }),
    /signRequest: alg "ecdsa-p256-sha256" is incompatible with the key \(an asymmetric ec key \(secp384r1\)\)/,
  );
});

test("ecdsa-p384-sha384 alg + P-256 key throws", () => {
  assert.throws(
    () => signRequest(req(), { alg: "ecdsa-p384-sha384", key: p256.privateKey, created: CREATED }),
    /signRequest: alg "ecdsa-p384-sha384" is incompatible with the key \(an asymmetric ec key \(prime256v1\)\)/,
  );
});

test("ecdsa-p521-sha512 alg + RSA key throws", () => {
  assert.throws(
    () => signRequest(req(), { alg: "ecdsa-p521-sha512", key: rsa.privateKey, created: CREATED }),
    /signRequest: alg "ecdsa-p521-sha512" is incompatible with the key \(an asymmetric rsa key\)/,
  );
});

test("rsa-pss-sha512 alg + ed25519 key throws", () => {
  assert.throws(
    () => signRequest(req(), { alg: "rsa-pss-sha512", key: ed.privateKey, created: CREATED }),
    /signRequest: alg "rsa-pss-sha512" is incompatible with the key \(an asymmetric ed25519 key\)/,
  );
});

test("rsa-v1_5-sha256 alg + RSA key signs and verifies (positive control)", () => {
  const signed = signRequest(req(), {
    alg: "rsa-v1_5-sha256",
    key: rsa.privateKey,
    created: CREATED,
  });
  const result = verifyRequest(signed, { key: rsa.publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("every correct alg/key pairing signs and verifies", () => {
  const pairings: { alg: SignAlg; privateKey: unknown; publicKey: unknown }[] = [
    { alg: "ed25519", privateKey: ed.privateKey, publicKey: ed.publicKey },
    { alg: "hmac-sha256", privateKey: hmac32, publicKey: hmac32 },
    { alg: "hmac-sha512", privateKey: hmac64, publicKey: hmac64 },
    { alg: "ecdsa-p256-sha256", privateKey: p256.privateKey, publicKey: p256.publicKey },
    { alg: "ecdsa-p384-sha384", privateKey: p384.privateKey, publicKey: p384.publicKey },
    { alg: "ecdsa-p521-sha512", privateKey: p521.privateKey, publicKey: p521.publicKey },
    { alg: "rsa-pss-sha512", privateKey: rsa.privateKey, publicKey: rsa.publicKey },
    { alg: "rsa-v1_5-sha256", privateKey: rsa.privateKey, publicKey: rsa.publicKey },
  ];
  for (const { alg, privateKey, publicKey } of pairings) {
    const signed = signRequest(req(), {
      alg,
      // The loop's keys are all KeyObjects; the cast only satisfies
      // the loop's `unknown` element type, not a runtime conversion.
      key: privateKey as Parameters<typeof signRequest>[1]["key"],
      created: CREATED,
    });
    const result = verifyRequest(signed, {
      key: publicKey as KeyObject,
      now: NOW,
    });
    assert.equal(result.ok, true, `${alg} should sign and verify with its matching key`);
  }
});

test("mismatch fires before base building: it wins over a missing-body content-digest error", () => {
  // With no body and content-digest covered, a shape-correct call
  // throws the content-digest error; the mismatched call must throw
  // the shape error instead, proving the check runs before the base
  // (and the digest) is computed and before any crypto runs.
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "ed25519",
        key: rsa.privateKey,
        created: CREATED,
        coveredComponents: ["@method", "content-digest"],
      }),
    /signRequest: alg "ed25519" is incompatible with the key/,
  );
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "ed25519",
        key: ed.privateKey,
        created: CREATED,
        coveredComponents: ["@method", "content-digest"],
      }),
    /content-digest is covered but the request has no body/,
  );
});

test("signResponse inherits the check: RSA key + ed25519 alg throws", () => {
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        { alg: "ed25519", key: rsa.privateKey, created: CREATED },
      ),
    /signRequest: alg "ed25519" is incompatible with the key \(an asymmetric rsa key\)/,
  );
});

test("addSignature inherits the check: appended label with a mismatched key throws", () => {
  const first = signRequest(req(), {
    alg: "ed25519",
    key: ed.privateKey,
    created: CREATED,
  });
  assert.throws(
    () =>
      addSignature(first, {
        label: "sig2",
        alg: "hmac-sha256",
        key: ed.privateKey,
        created: CREATED,
      }),
    /signRequest: alg "hmac-sha256" is incompatible with the key \(an asymmetric ed25519 key\)/,
  );
});

test("addResponseSignature inherits the check: appended label with a mismatched key throws", () => {
  const first = signResponse(
    { status: 200, headers: {} },
    { alg: "ed25519", key: ed.privateKey, created: CREATED },
  );
  assert.throws(
    () =>
      addResponseSignature(first, {
        label: "sig2",
        alg: "ecdsa-p256-sha256",
        key: rsa.privateKey,
        created: CREATED,
      }),
    /signRequest: alg "ecdsa-p256-sha256" is incompatible with the key \(an asymmetric rsa key\)/,
  );
});
