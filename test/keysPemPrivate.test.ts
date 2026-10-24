import test from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, createSecretKey, type KeyObject } from "node:crypto";
import {
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  exportPublicKeyPem,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  importPrivateKey,
  jwkThumbprint,
  secretKey,
  signRequest,
  verifyRequest,
  type SignAlg,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

interface AlgCase {
  alg: SignAlg;
  generate: () => { publicKey: KeyObject; privateKey: KeyObject };
  publicJwk: (publicKey: KeyObject) => unknown;
}

const ALGS: AlgCase[] = [
  {
    alg: "ed25519",
    generate: generateEd25519KeyPair,
    publicJwk: exportPublicKeyJwk,
  },
  {
    alg: "ecdsa-p256-sha256",
    generate: generateP256KeyPair,
    publicJwk: exportPublicKeyJwkP256,
  },
  {
    alg: "ecdsa-p384-sha384",
    generate: generateP384KeyPair,
    publicJwk: exportPublicKeyJwkP384,
  },
  {
    alg: "ecdsa-p521-sha512",
    generate: generateP521KeyPair,
    publicJwk: exportPublicKeyJwkP521,
  },
  {
    alg: "rsa-pss-sha512",
    generate: generateRsaPssKeyPair,
    publicJwk: exportPublicKeyJwkRsa,
  },
  {
    alg: "rsa-v1_5-sha256",
    generate: generateRsaPssKeyPair,
    publicJwk: exportPublicKeyJwkRsa,
  },
];

function signWith(key: KeyObject, alg: SignAlg) {
  return signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "pem-round-trip", alg, key, created: CREATED },
  );
}

for (const { alg, generate } of ALGS) {
  test(`${alg}: exportPrivateKeyPem -> importPrivateKey round-trip signs and verifies`, () => {
    const { publicKey, privateKey } = generate();
    const pem = exportPrivateKeyPem(privateKey);

    // PKCS#8, unencrypted: the first line is the same for every algorithm.
    assert.equal(pem.split("\n")[0], "-----BEGIN PRIVATE KEY-----");
    assert.match(pem, /-----END PRIVATE KEY-----\n?$/);

    const imported = importPrivateKey(pem);
    assert.equal(imported.type, "private");
    // Re-export is byte-identical: import is lossless, not a re-encode.
    assert.equal(exportPrivateKeyPem(imported), pem);
    // node:crypto exports SPKI only from public keys, so the public half
    // of the imported private key is derived via createPublicKey first.
    assert.equal(
      exportPublicKeyPem(publicKey),
      exportPublicKeyPem(createPublicKey(imported)),
    );

    const signed = signWith(imported, alg);
    const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
    assert.equal(res.ok, true);
    assert.equal(res.keyId, "pem-round-trip");
  });
}

test("private PEM export is deterministic: two exports of one key are identical", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.equal(exportPrivateKeyPem(privateKey), exportPrivateKeyPem(privateKey));
});

test("jwkThumbprint is unchanged by a private PEM round-trip (all algorithms)", () => {
  for (const { generate, publicJwk } of ALGS) {
    const { publicKey, privateKey } = generate();
    const before = jwkThumbprint(publicJwk(publicKey));
    const imported = importPrivateKey(exportPrivateKeyPem(privateKey));
    // JWK exporters here are public-key-only, so derive the public half.
    const after = jwkThumbprint(publicJwk(createPublicKey(imported)));
    assert.equal(after, before);
  }
});

test("importPrivateKey: malformed PEM shapes all throw (never a silent key)", () => {
  const { privateKey, publicKey } = generateEd25519KeyPair();
  const pem = exportPrivateKeyPem(privateKey);
  const malformed: Array<[string, string]> = [
    ["garbage text", "this is not a PEM document at all"],
    ["empty string", ""],
    [
      "truncated PKCS#8",
      pem.slice(0, Math.floor(pem.length / 2)),
    ],
    [
      "wrong PEM label",
      pem.replaceAll("PRIVATE KEY", "CERTIFICATE"),
    ],
    [
      "corrupted base64 body",
      pem.replace(/[A-Za-z0-9+/]{24}/, "!!!!!@@@@@#####$$$$$%%%%"),
    ],
    ["missing END line", pem.split("-----END")[0]],
  ];
  for (const [shape, input] of malformed) {
    assert.throws(
      () => importPrivateKey(input),
      (err: unknown) => {
        assert.ok(err instanceof Error, `${shape}: expected an Error`);
        // Honest pin: node:crypto's decoder errors carry no "private key"
        // or "PEM" keyword in their message, so the contract pinned here is
        // the stable error code, not a keyword match.
        assert.equal(
          (err as NodeJS.ErrnoException).code,
          "ERR_OSSL_UNSUPPORTED",
          `${shape}: expected ERR_OSSL_UNSUPPORTED, got ${err}`,
        );
        return true;
      },
      `${shape} must throw`,
    );
  }
  // A public SPKI PEM is not a private key either.
  assert.throws(
    () => importPrivateKey(exportPublicKeyPem(publicKey)),
    (err: unknown) => {
      assert.equal((err as NodeJS.ErrnoException).code, "ERR_OSSL_UNSUPPORTED");
      return true;
    },
    "SPKI public PEM must not import as a private key",
  );
});

test("exportPrivateKeyPem: a symmetric secret KeyObject is rejected", () => {
  const secret = secretKey(Buffer.alloc(32, 0x42));
  assert.equal(secret.type, "secret");
  assert.throws(
    () => exportPrivateKeyPem(secret),
    (err: unknown) => {
      // node:crypto cannot PEM-export secret keys at all: format "pem" is
      // not a valid export format for them.
      assert.equal((err as NodeJS.ErrnoException).code, "ERR_INVALID_ARG_VALUE");
      assert.match((err as Error).message, /options\.format/);
      return true;
    },
  );
  // The raw node:crypto secret behaves the same: this is a platform limit,
  // not a wrapper choice.
  assert.throws(() =>
    createSecretKey(Buffer.alloc(32, 0x42)).export({
      format: "pem",
      type: "pkcs8",
    }),
  );
});

test("exportPrivateKeyPem: a public KeyObject is rejected", () => {
  const { publicKey } = generateEd25519KeyPair();
  assert.equal(publicKey.type, "public");
  assert.throws(
    () => exportPrivateKeyPem(publicKey),
    (err: unknown) => {
      // PKCS#8 is a private-key container; node:crypto refuses it for
      // public keys instead of silently exporting something else.
      assert.equal((err as NodeJS.ErrnoException).code, "ERR_INVALID_ARG_VALUE");
      assert.match((err as Error).message, /pkcs8/);
      return true;
    },
  );
});

test("importPrivateKey: Buffer and string inputs are equivalent", () => {
  const { publicKey, privateKey } = generateP384KeyPair();
  const pem = exportPrivateKeyPem(privateKey);
  const fromString = importPrivateKey(pem);
  const fromBuffer = importPrivateKey(Buffer.from(pem, "utf8"));
  assert.equal(exportPrivateKeyPem(fromString), pem);
  assert.equal(exportPrivateKeyPem(fromBuffer), pem);
  // The Buffer-imported key signs a request the original public key verifies.
  const signed = signWith(fromBuffer, "ecdsa-p384-sha384");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
