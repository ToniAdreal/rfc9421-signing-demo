import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import {
  buildJwksDocument,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  JwksKeyStore,
  secretKey,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type SignedHttpRequest,
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

function signAs(
  keyId: string,
  alg:
    | "ed25519"
    | "ecdsa-p256-sha256"
    | "ecdsa-p384-sha384"
    | "ecdsa-p521-sha512"
    | "rsa-pss-sha512",
  privateKey: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), {
    keyId,
    alg,
    key: privateKey,
    created: CREATED,
  });
}

/** Every published kid signs one request; each must verify via the store. */
async function assertAllVerify(
  store: JwksKeyStore,
  keys: Keys,
): Promise<void> {
  await store.refresh();
  const cases: Array<[string, string, KeyObject]> = [
    ["ed-key-1", "ed25519", keys.ed.privateKey],
    ["p256-key-1", "ecdsa-p256-sha256", keys.p256.privateKey],
    ["p384-key-1", "ecdsa-p384-sha384", keys.p384.privateKey],
    ["p521-key-1", "ecdsa-p521-sha512", keys.p521.privateKey],
    ["rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey],
  ];
  for (const [keyId, alg, privateKey] of cases) {
    const signed = signAs(
      keyId,
      alg as Parameters<typeof signAs>[1],
      privateKey,
    );
    const res = verifyRequest(signed, {
      keyResolver: store.resolve,
      now: CREATED,
    });
    assert.equal(res.ok, true, `${keyId} (${alg}) should verify`);
    assert.equal(res.keyId, keyId);
    assert.equal(res.alg, alg);
  }
}

test("buildJwksDocument: five key shapes assemble with the right kty/crv and kid", () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  assert.equal(doc.keys.length, 5);
  assert.deepEqual(
    doc.keys.map((k) => [k.kty, "crv" in k ? k.crv : undefined, k.kid]),
    [
      ["OKP", "Ed25519", "ed-key-1"],
      ["EC", "P-256", "p256-key-1"],
      ["EC", "P-384", "p384-key-1"],
      ["EC", "P-521", "p521-key-1"],
      ["RSA", undefined, "rsa-key-1"],
    ],
  );
  // The published keys are the very keys the pairs hold.
  assert.equal(
    doc.keys[0].kty,
    "OKP",
  );
});

test("buildJwksDocument: published document verifies end to end via JwksKeyStore", async () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const store = storeFor(doc);
  await assertAllVerify(store, keys);
  assert.deepEqual(store.keyIds(), [
    "ed-key-1",
    "p256-key-1",
    "p384-key-1",
    "p521-key-1",
    "rsa-key-1",
  ]);
});

test("buildJwksDocument: empty entries give an empty key set", () => {
  assert.deepEqual(buildJwksDocument([]), { keys: [] });
});

test("buildJwksDocument: empty kid is refused", () => {
  const keys = keyMaterial();
  assert.throws(
    () => buildJwksDocument([{ key: keys.ed.publicKey, kid: "" }]),
    /non-empty string/,
  );
});

test("buildJwksDocument: missing kid is refused", () => {
  const keys = keyMaterial();
  const entry = { key: keys.ed.publicKey } as unknown as {
    key: KeyObject;
    kid: string;
  };
  assert.throws(
    () => buildJwksDocument([entry]),
    /non-empty string/,
  );
});

test("buildJwksDocument: duplicate kid is refused", () => {
  const keys = keyMaterial();
  assert.throws(
    () =>
      buildJwksDocument([
        { key: keys.ed.publicKey, kid: "same-kid" },
        { key: keys.p256.publicKey, kid: "same-kid" },
      ]),
    /duplicate kid "same-kid"/,
  );
});

test("buildJwksDocument: a symmetric secret key is refused", () => {
  const secret = secretKey(Buffer.alloc(32, 0x2a));
  assert.throws(
    () => buildJwksDocument([{ key: secret, kid: "hmac-key-1" }]),
    /symmetric secret key/,
  );
});

test("buildJwksDocument: a private key is refused — pass the public half", () => {
  const keys = keyMaterial();
  assert.throws(
    () => buildJwksDocument([{ key: keys.ed.privateKey, kid: "ed-key-1" }]),
    /is a private key/,
  );
});

test("buildJwksDocument: an unsupported key shape is refused", () => {
  // secp256k1 is a real EC curve node:crypto supports, but no
  // exportPublicKeyJwk* helper covers it — the publisher must not
  // ship a key verifiers cannot import.
  const { publicKey } = generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });
  assert.throws(
    () => buildJwksDocument([{ key: publicKey, kid: "k256-key-1" }]),
    /unsupported key shape/,
  );
});

test("buildJwksDocument: the published document never carries private material", () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  for (const entry of doc.keys) {
    assert.ok(!("d" in entry), `entry ${entry.kid} must not carry "d"`);
  }
  // The JSON text itself must not contain a "d" member either: a
  // base64url value is never exactly "d", so this only matches a
  // key named "d".
  assert.equal(JSON.stringify(doc).includes('"d"'), false);
});

test("buildJwksDocument: key order is irrelevant — a reordered document still verifies", async () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const reordered = { keys: [...doc.keys].reverse() };
  const store = storeFor(reordered);
  await assertAllVerify(store, keys);
});

test("buildJwksDocument: a JSON round-trip (stringify/parse) still verifies", async () => {
  const keys = keyMaterial();
  const doc = publishedDocument(keys);
  const roundTripped = JSON.parse(JSON.stringify(doc)) as unknown;
  const store = storeFor(roundTripped);
  await assertAllVerify(store, keys);
});

test("buildJwksDocument: a non-array entries argument is refused", () => {
  assert.throws(
    () =>
      buildJwksDocument(
        "not-an-array" as unknown as Parameters<
          typeof buildJwksDocument
        >[0],
      ),
    /must be an array/,
  );
});

test("buildJwksDocument: a non-object entry is refused", () => {
  assert.throws(
    () =>
      buildJwksDocument([
        "not-an-entry" as unknown as { key: KeyObject; kid: string },
      ]),
    /must be an object with `key` and `kid`/,
  );
});
