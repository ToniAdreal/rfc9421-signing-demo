import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import {
  buildJwksDocument,
  exportPublicKeyJwk,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
} from "../src/index.js";

const CREATED = 1700000000;

function freshReq() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {} as Record<string, string>,
    body: '{"amount":100}',
  };
}

/** One signing key pair per published JWKS key shape. */
function keyMaterial() {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const p384 = generateP384KeyPair();
  const p521 = generateP521KeyPair();
  const rsa = generateRsaPssKeyPair();
  return { ed, p256, p384, p521, rsa };
}

type Keys = ReturnType<typeof keyMaterial>;

/** The five-shape document the signer publishes for those keys. */
function publishedDocument(keys: Keys) {
  return buildJwksDocument([
    { key: keys.ed.publicKey, kid: "ed-key-1" },
    { key: keys.p256.publicKey, kid: "p256-key-1" },
    { key: keys.p384.publicKey, kid: "p384-key-1" },
    { key: keys.p521.publicKey, kid: "p521-key-1" },
    { key: keys.rsa.publicKey, kid: "rsa-key-1" },
  ]);
}

/** A store whose fetch serves `doc` (re-parsed per fetch, as over the wire). */
function storeFor(doc: unknown): JwksKeyStore {
  const fetchImpl: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => JSON.parse(JSON.stringify(doc)),
  });
  return new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    { fetchImpl },
  );
}

test("buildJwksDocument: each key shape carries its JWA alg", () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  assert.deepEqual(
    doc.keys.map((k) => [k.kid, k.alg]),
    [
      ["ed-key-1", "EdDSA"],
      ["p256-key-1", "ES256"],
      ["p384-key-1", "ES384"],
      ["p521-key-1", "ES512"],
      ["rsa-key-1", "PS512"],
    ],
  );
});

test("buildJwksDocument: the alg-labelled document verifies end to end via JwksKeyStore", async () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const store = storeFor(doc);
  // refresh() runs the store's own alg check on every entry, so a
  // successful refresh proves the emitted values are the ones the
  // verify side accepts for each family.
  await store.refresh();
  const cases: Array<[string, string, KeyObject]> = [
    ["ed-key-1", "ed25519", keys.ed.privateKey],
    ["p256-key-1", "ecdsa-p256-sha256", keys.p256.privateKey],
    ["p384-key-1", "ecdsa-p384-sha384", keys.p384.privateKey],
    ["p521-key-1", "ecdsa-p521-sha512", keys.p521.privateKey],
    ["rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey],
  ];
  for (const [keyId, alg, privateKey] of cases) {
    const signed = signRequest(freshReq(), {
      keyId,
      alg: alg as Parameters<typeof signRequest>[1]["alg"],
      key: privateKey,
      created: CREATED,
    });
    const res = verifyRequest(signed, {
      keyResolver: store.resolve,
      now: CREATED,
    });
    assert.equal(res.ok, true, `${keyId} (${alg}) should verify`);
    assert.equal(res.keyId, keyId);
    assert.equal(res.alg, alg);
  }
});

test("buildJwksDocument: the PS512-labelled RSA key still verifies rsa-v1_5-sha256", async () => {
  // The one RSA key serves both RSA algorithms: the PS512 label
  // names the library default, it does not fence the key to PSS.
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const store = storeFor(doc);
  await store.refresh();
  const signed = signRequest(freshReq(), {
    keyId: "rsa-key-1",
    alg: "rsa-v1_5-sha256",
    key: keys.rsa.privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-v1_5-sha256");
});

test("buildJwksDocument: a JSON round-trip preserves alg and still verifies", async () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const roundTripped = JSON.parse(JSON.stringify(doc)) as unknown;
  const store = storeFor(roundTripped);
  await store.refresh();
  const signed = signRequest(freshReq(), {
    keyId: "ed-key-1",
    alg: "ed25519",
    key: keys.ed.privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(
    (roundTripped as { keys: Array<{ alg: string }> }).keys[0]!.alg,
    "EdDSA",
  );
});

test("buildJwksDocument: a tampered alg is refused by the store refresh", async () => {
  // The label is not decorative: the verify side checks a declared
  // alg against the key family, so a wrong label must fail closed
  // here — which is exactly why the publisher must emit the right
  // one in the first place.
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const tampered = JSON.parse(JSON.stringify(doc)) as {
    keys: Array<Record<string, unknown>>;
  };
  tampered.keys[0]!["alg"] = "ES256";
  const store = storeFor(tampered);
  await assert.rejects(
    () => store.refresh(),
    /"alg" "ES256" does not match this key's family/,
  );
  assert.deepEqual(store.keyIds(), []);
});

test("buildJwksDocument: an unsupported key shape is still refused with a named error", () => {
  // secp256k1 is a real EC curve node:crypto supports, but no
  // exportPublicKeyJwk* helper covers it — the publisher must not
  // ship a key verifiers cannot import, and there is no alg to
  // write for it either.
  const { publicKey } = generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });
  assert.throws(
    () => buildJwksDocument([{ key: publicKey, kid: "k256-key-1" }]),
    /unsupported key shape/,
  );
});

test("buildJwksDocument: the bare exporters still emit no alg", () => {
  // Only the published document gains `alg`: the exporters are
  // also the snapshot-export shape, which stays alg-free by design.
  const keys = keyMaterial();
  assert.equal("alg" in exportPublicKeyJwk(keys.ed.publicKey), false);
  assert.equal(
    "alg" in exportPublicKeyJwkRsa(keys.rsa.publicKey),
    false,
  );
});
