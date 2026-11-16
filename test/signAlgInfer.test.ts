import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  addSignature,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  inferAlgFromKeyShape,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyRequest,
  verifyResponse,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Sign-side twin of the verify-side `algFallback: "infer"` coverage
// (backlog #1172): `signRequest` / `signResponse` accept
// `alg: "infer"`, deriving the algorithm from the key's shape through
// the shared `keys.inferAlgFromKeyShape` mapping — the same mapping the
// verify side applies when `signature-input` carries no `alg`. The
// inferred value is written into `signature-input` exactly as an
// explicit alg would be, so the wire shape (and `VerifyResult.alg`)
// is identical to naming the algorithm outright. Every case below was
// observed live with a probe before being written down; nothing here
// asserts a code path that was only assumed to exist.

const CREATED = 1700000000;

function demoRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100,"currency":"USD"}',
  };
}

/** The `alg="..."` value carried in a signed message's signature-input. */
function wireAlg(signed: { headers: Record<string, string> }): string {
  const input = signed.headers["signature-input"];
  const match = /;alg="([^"]+)"/.exec(input);
  assert.ok(match, `signature-input carries no alg: ${input}`);
  return match[1];
}

test('ed25519 key + alg "infer" signs as ed25519 and verifies', () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "ed25519");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ed25519");
});

test('P-256 key + alg "infer" signs as ecdsa-p256-sha256 and verifies', () => {
  const { publicKey, privateKey } = generateP256KeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "ecdsa-p256-sha256");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test('P-384 key + alg "infer" signs as ecdsa-p384-sha384 and verifies', () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "ecdsa-p384-sha384");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p384-sha384");
});

test('P-521 key + alg "infer" signs as ecdsa-p521-sha512 and verifies', () => {
  const { publicKey, privateKey } = generateP521KeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "ecdsa-p521-sha512");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p521-sha512");
});

test('RSA key + alg "infer" signs as rsa-pss-sha512 and verifies', () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "rsa-pss-sha512");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-pss-sha512");
});

test('32-byte secret + alg "infer" signs as hmac-sha256 and verifies', () => {
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: secret,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "hmac-sha256");
  const res = verifyRequest(signed, { key: secret, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
});

test("a 64-byte secret still infers hmac-sha256, never hmac-sha512", () => {
  // A secret carries no length signal that names the hash, so the
  // mapping always picks the lower floor; hmac-sha512 is only ever
  // chosen explicitly. Pin it so a future "longer secret → sha-512"
  // shortcut cannot silently change what an inferred signature is.
  const secret = secretKey("s".repeat(64));
  assert.equal(secret.symmetricKeySize, 64);
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: secret,
    created: CREATED,
  });
  assert.equal(wireAlg(signed), "hmac-sha256");
  assert.equal(
    verifyRequest(signed, { key: secret, now: CREATED + 60 }).ok,
    true,
  );
});

test("explicit alg equal to the inferred one mints byte-identical headers", () => {
  // hmac-sha256 is deterministic, so the same base + key must produce
  // the same signature bytes either way: "infer" changes nothing
  // about the wire shape, it only spares the caller naming the alg.
  const secret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const inferred = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: secret,
    created: CREATED,
  });
  const explicit = signRequest(demoRequest(), {
    keyId: "k",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
  });
  assert.equal(inferred.headers["signature-input"], explicit.headers["signature-input"]);
  assert.equal(inferred.headers["signature"], explicit.headers["signature"]);
});

test('unmappable key shape (secp256k1) + alg "infer" throws a configuration error', () => {
  const { privateKey } = generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });
  assert.throws(
    () =>
      signRequest(demoRequest(), {
        keyId: "k",
        alg: "infer",
        key: privateKey,
        created: CREATED,
      }),
    /signRequest: alg "infer" cannot infer an algorithm for an asymmetric ec key \(secp256k1\)/,
  );
});

test('signResponse + alg "infer" infers ed25519 and verifies', () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {}, body: '{"status":"settled"}' },
    { keyId: "gw", alg: "infer", key: privateKey, created: CREATED },
  );
  assert.equal(wireAlg(signed), "ed25519");
  const res = verifyResponse(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ed25519");
});

test('infer-signed signature verifies under algFallback "infer" too', () => {
  // The inferred alg is on the wire, so the verifier needs no
  // fallback to read it — but a receiver that enables the opt-in
  // (e.g. for mixed foreign signers) must still accept it, and the
  // shape check under the opt-in must agree the wire alg matches
  // the key.
  const { publicKey, privateKey } = generateP256KeyPair();
  const signed = signRequest(demoRequest(), {
    keyId: "k",
    alg: "infer",
    key: privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test('addSignature with alg "infer" appends a second label with the inferred alg', () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const first = signRequest(demoRequest(), {
    keyId: "merchant",
    label: "merchant",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  const both = addSignature(first, {
    keyId: "gateway",
    label: "gateway",
    alg: "infer",
    key: gatewaySecret,
    created: CREATED,
  });
  const results = verifyAllLabels(both, {
    keyResolver: (keyId) =>
      keyId === "merchant"
        ? merchant.publicKey
        : keyId === "gateway"
          ? gatewaySecret
          : undefined,
    now: CREATED + 60,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].alg, "hmac-sha256");
  assert.ok(results.every((r) => r.ok));
});

test("inferAlgFromKeyShape is exported and maps each shape", () => {
  // Direct unit pin of the shared mapping, so a drift between the
  // sign-side and verify-side inference surfaces here first.
  assert.equal(
    inferAlgFromKeyShape(generateEd25519KeyPair().privateKey),
    "ed25519",
  );
  assert.equal(
    inferAlgFromKeyShape(generateP256KeyPair().privateKey),
    "ecdsa-p256-sha256",
  );
  assert.equal(
    inferAlgFromKeyShape(generateP384KeyPair().privateKey),
    "ecdsa-p384-sha384",
  );
  assert.equal(
    inferAlgFromKeyShape(generateP521KeyPair().privateKey),
    "ecdsa-p521-sha512",
  );
  assert.equal(
    inferAlgFromKeyShape(generateRsaPssKeyPair().privateKey),
    "rsa-pss-sha512",
  );
  assert.equal(
    inferAlgFromKeyShape(secretKey("a-shared-hmac-secret-of-32-bytes!!")),
    "hmac-sha256",
  );
  assert.throws(
    () =>
      inferAlgFromKeyShape(
        generateKeyPairSync("ec", { namedCurve: "secp256k1" }).privateKey,
      ),
    /cannot infer an algorithm for an asymmetric ec key \(secp256k1\)/,
  );
});
