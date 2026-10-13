import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  jwkThumbprint,
} from "../src/index.js";

// RFC 7638 §3.1 example JWK (RSA, with the long "n" line unwrapped) and
// its published SHA-256 thumbprint. The "n" transcription was verified
// at implementation time by recomputing the hash: only this exact
// string reproduces the published thumbprint below.
const RFC7638_EXAMPLE_JWK = {
  kty: "RSA",
  n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
  alg: "RS256",
  kid: "2011-04-29",
};
const RFC7638_EXAMPLE_THUMBPRINT =
  "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

test("RFC 7638 §3.1 official example reproduces the published thumbprint", () => {
  // The example JWK carries alg/kid members: they must not participate.
  assert.equal(jwkThumbprint(RFC7638_EXAMPLE_JWK), RFC7638_EXAMPLE_THUMBPRINT);
});

test("thumbprint is a 43-char base64url SHA-256 digest for each exported shape", () => {
  const ed = exportPublicKeyJwk(generateEd25519KeyPair().publicKey);
  const ec = exportPublicKeyJwkP256(generateP256KeyPair().publicKey);
  const rsa = exportPublicKeyJwkRsa(generateRsaPssKeyPair().publicKey);
  for (const jwk of [ed, ec, rsa]) {
    const tp = jwkThumbprint(jwk);
    assert.match(tp, /^[A-Za-z0-9_-]{43}$/);
    // Deterministic: the same JWK always yields the same thumbprint.
    assert.equal(jwkThumbprint(jwk), tp);
    // Distinct keys yield distinct thumbprints.
    assert.notEqual(tp, RFC7638_EXAMPLE_THUMBPRINT);
  }
});

test("member order and extra members do not affect the thumbprint", () => {
  const ed = exportPublicKeyJwk(generateEd25519KeyPair().publicKey);
  const ec = exportPublicKeyJwkP256(generateP256KeyPair().publicKey);
  const rsa = exportPublicKeyJwkRsa(generateRsaPssKeyPair().publicKey);
  for (const jwk of [ed, ec, rsa]) {
    const base = jwkThumbprint(jwk);
    // Same members, reversed insertion order.
    const reversed = Object.fromEntries(Object.entries(jwk).reverse());
    assert.equal(jwkThumbprint(reversed), base);
    // Extra metadata members are ignored (RFC 7638 §3.2).
    const decorated = {
      ...jwk,
      kid: "some-local-name",
      alg: "EdDSA",
      use: "sig",
      key_ops: ["verify"],
    };
    assert.equal(jwkThumbprint(decorated), base);
  }
});

test("changing any required member by one character changes the thumbprint", () => {
  const flip = (s: string): string =>
    (s.startsWith("A") ? "B" : "A") + s.slice(1);
  const ed = exportPublicKeyJwk(generateEd25519KeyPair().publicKey);
  assert.notEqual(jwkThumbprint({ ...ed, x: flip(ed.x) }), jwkThumbprint(ed));
  assert.notEqual(
    jwkThumbprint({ ...ed, crv: "Ed448" }),
    jwkThumbprint(ed),
  );
  const ec = exportPublicKeyJwkP256(generateP256KeyPair().publicKey);
  assert.notEqual(jwkThumbprint({ ...ec, y: flip(ec.y) }), jwkThumbprint(ec));
  const rsa = exportPublicKeyJwkRsa(generateRsaPssKeyPair().publicKey);
  assert.notEqual(jwkThumbprint({ ...rsa, n: flip(rsa.n) }), jwkThumbprint(rsa));
  assert.notEqual(jwkThumbprint({ ...rsa, e: "AQAC" }), jwkThumbprint(rsa));
});

test("jwkThumbprint rejects private JWKs and unknown kty values", () => {
  const ed = exportPublicKeyJwk(generateEd25519KeyPair().publicKey);
  assert.throws(
    () => jwkThumbprint({ ...ed, d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
    /private key material/,
  );
  assert.throws(() => jwkThumbprint({ ...ed, kty: "oct" }), /unsupported kty/);
  assert.throws(() => jwkThumbprint({ ...ed, kty: "OKP2" }), /unsupported kty/);
  assert.throws(() => jwkThumbprint({ x: ed.x, crv: ed.crv }), /missing "kty"/);
});

test("jwkThumbprint rejects missing, empty, or non-string required members", () => {
  const ed = exportPublicKeyJwk(generateEd25519KeyPair().publicKey);
  const ec = exportPublicKeyJwkP256(generateP256KeyPair().publicKey);
  const rsa = exportPublicKeyJwkRsa(generateRsaPssKeyPair().publicKey);
  const { x: _x, ...edNoX } = ed;
  const { y: _y, ...ecNoY } = ec;
  const { e: _e, ...rsaNoE } = rsa;
  const cases: Array<[string, unknown, RegExp]> = [
    ["OKP missing x", edNoX, /missing or empty "x"/],
    ["OKP empty crv", { ...ed, crv: "" }, /missing or empty "crv"/],
    ["OKP non-string x", { ...ed, x: 42 }, /missing or empty "x"/],
    ["EC missing y", ecNoY, /missing or empty "y"/],
    ["RSA missing e", rsaNoE, /missing or empty "e"/],
    ["RSA empty n", { ...rsa, n: "" }, /missing or empty "n"/],
  ];
  for (const [name, input, re] of cases) {
    assert.throws(() => jwkThumbprint(input), re, name);
  }
});

test("jwkThumbprint rejects non-object inputs", () => {
  for (const input of [null, undefined, "{}", 42, []]) {
    assert.throws(() => jwkThumbprint(input), /expected a JWK object/);
  }
});

test("thumbprint of an imported-then-re-exported key is stable", () => {
  // The JWKS distribution case: the verifier's copy of the key must
  // derive the same identifier as the signer's original.
  const { publicKey } = generateEd25519KeyPair();
  const original = exportPublicKeyJwk(publicKey);
  const wire = JSON.parse(JSON.stringify(original)) as unknown;
  assert.equal(jwkThumbprint(wire), jwkThumbprint(original));
});
