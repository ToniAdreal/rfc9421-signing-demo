import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
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

function signAs(
  keyId: string,
  alg:
    | "ed25519"
    | "ecdsa-p256-sha256"
    | "ecdsa-p384-sha384"
    | "ecdsa-p521-sha512"
    | "rsa-pss-sha512"
    | "rsa-v1_5-sha256",
  privateKey: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId, alg, key: privateKey, created: CREATED });
}

/** A fetch stub that serves a fixed JSON body without any network. */
function stubFetch(body: unknown, status = 200): JwksFetchImpl {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

function pem(key: KeyObject): string {
  return key.export({ format: "pem", type: "spki" }).toString();
}

/**
 * Refresh `goodDoc` into a fresh store, then assert that refreshing
 * `badDoc` rejects and leaves size, lastRefreshedAt, resolved keys
 * and the refresh-failure counter's delta exactly as they were.
 */
async function assertBadRefreshLeavesSnapshot(
  goodDoc: unknown,
  badDoc: unknown,
  kid: string,
  expectedKey: KeyObject,
): Promise<void> {
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(goodDoc),
  });
  await store.refresh();
  const sizeBefore = store.size;
  const refreshedAtBefore = store.lastRefreshedAt;
  assert.ok(refreshedAtBefore !== null);

  // A store cannot swap its fetchImpl, so replay the same scenario on
  // a store restored from the good snapshot, then refresh it with the
  // bad document: the old snapshot must survive the failed refresh.
  const snapshot = store.exportSnapshot();
  const underTest = JwksKeyStore.restore(
    snapshot,
    "https://gateway.example.com/jwks.json",
    { fetchImpl: stubFetch(badDoc) },
  );
  await assert.rejects(underTest.refresh(), /does not match|must be a string/);
  assert.equal(underTest.size, sizeBefore);
  assert.equal(underTest.lastRefreshedAt, refreshedAtBefore);
  assert.equal(pem(underTest.resolve(kid) as KeyObject), pem(expectedKey));
  assert.equal(
    underTest.stats().refreshFailures,
    1,
    "one failed refresh counts once",
  );
}

test("JwksKeyStore: correct alg for all five families refreshes and verifies", async () => {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const p384 = generateP384KeyPair();
  const p521 = generateP521KeyPair();
  const rsa = generateRsaPssKeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1", alg: "EdDSA" },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1", alg: "ES256" },
      { ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1", alg: "ES384" },
      { ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1", alg: "ES512" },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1", alg: "PS512" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 5);
  const cases: Array<[string, SignedHttpRequest, KeyObject]> = [
    ["ed-key-1", signAs("ed-key-1", "ed25519", ed.privateKey), ed.publicKey],
    ["p256-key-1", signAs("p256-key-1", "ecdsa-p256-sha256", p256.privateKey), p256.publicKey],
    ["p384-key-1", signAs("p384-key-1", "ecdsa-p384-sha384", p384.privateKey), p384.publicKey],
    ["p521-key-1", signAs("p521-key-1", "ecdsa-p521-sha512", p521.privateKey), p521.publicKey],
    ["rsa-key-1", signAs("rsa-key-1", "rsa-pss-sha512", rsa.privateKey), rsa.publicKey],
  ];
  for (const [kid, signed, publicKey] of cases) {
    assert.equal(pem(store.resolve(kid) as KeyObject), pem(publicKey));
    const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
    assert.equal(res.ok, true, kid);
  }
});

test("JwksKeyStore: RSA entry labelled RS256 is accepted (second RSA alg)", async () => {
  const rsa = generateRsaPssKeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1", alg: "RS256" }],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("rsa-key-1", "rsa-v1_5-sha256", rsa.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, true);
});

test("JwksKeyStore: ed25519 entry labelled ES256 is rejected, old snapshot untouched", async () => {
  const ed = generateEd25519KeyPair();
  const good = { keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" }] };
  const bad = {
    keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1", alg: "ES256" }],
  };
  await assertBadRefreshLeavesSnapshot(good, bad, "ed-key-1", ed.publicKey);
});

test("JwksKeyStore: P-256 entry labelled EdDSA is rejected, old snapshot untouched", async () => {
  const p256 = generateP256KeyPair();
  const good = { keys: [{ ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1" }] };
  const bad = {
    keys: [{ ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1", alg: "EdDSA" }],
  };
  await assertBadRefreshLeavesSnapshot(good, bad, "p256-key-1", p256.publicKey);
});

test("JwksKeyStore: P-384 entry labelled ES256 is rejected, old snapshot untouched", async () => {
  const p384 = generateP384KeyPair();
  const good = { keys: [{ ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1" }] };
  const bad = {
    keys: [{ ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1", alg: "ES256" }],
  };
  await assertBadRefreshLeavesSnapshot(good, bad, "p384-key-1", p384.publicKey);
});

test("JwksKeyStore: P-521 entry labelled ES384 is rejected, old snapshot untouched", async () => {
  const p521 = generateP521KeyPair();
  const good = { keys: [{ ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1" }] };
  const bad = {
    keys: [{ ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1", alg: "ES384" }],
  };
  await assertBadRefreshLeavesSnapshot(good, bad, "p521-key-1", p521.publicKey);
});

test("JwksKeyStore: RSA entry labelled ES256 is rejected, old snapshot untouched", async () => {
  const rsa = generateRsaPssKeyPair();
  const good = { keys: [{ ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1" }] };
  const bad = {
    keys: [{ ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1", alg: "ES256" }],
  };
  await assertBadRefreshLeavesSnapshot(good, bad, "rsa-key-1", rsa.publicKey);
});

test("JwksKeyStore: non-string alg is rejected, old snapshot untouched", async () => {
  const ed = generateEd25519KeyPair();
  const good = { keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" }] };
  for (const alg of [123, null]) {
    const bad = {
      keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1", alg }],
    };
    await assertBadRefreshLeavesSnapshot(good, bad, "ed-key-1", ed.publicKey);
  }
});

test("JwksKeyStore: entry without alg refreshes exactly as before", async () => {
  const ed = generateEd25519KeyPair();
  const doc = { keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" }] };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("ed-key-1", "ed25519", ed.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
});

test("JwksKeyStore: snapshot restore is unaffected by alg checking", async () => {
  const ed = generateEd25519KeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1", alg: "EdDSA" }],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  const snapshot = store.exportSnapshot();
  // The snapshot is this store's own export format: it carries no alg.
  for (const key of snapshot.keys) {
    assert.equal("alg" in key, false);
  }
  const restored = JwksKeyStore.restore(
    snapshot,
    "https://gateway.example.com/jwks.json",
  );
  assert.equal(pem(restored.resolve("ed-key-1") as KeyObject), pem(ed.publicKey));
  const signed = signAs("ed-key-1", "ed25519", ed.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: restored.resolve, now: CREATED }).ok,
    true,
  );
});

test("JwksKeyStore: kid-less entry with a mismatched alg is skipped, not fatal", async () => {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const doc = {
    keys: [
      // No kid: skipped before any alg check, per the refresh() contract.
      { ...exportPublicKeyJwk(ed.publicKey), alg: "ES256" },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1", alg: "ES256" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.equal(pem(store.resolve("p256-key-1") as KeyObject), pem(p256.publicKey));
});

test("JwksKeyStore: unknown kty still fails as unsupported, not as an alg error", async () => {
  // "AKP" is not a kty this library imports ("oct" is one since
  // #933, so it no longer serves as the unknown-kty fixture). The
  // declared alg must not shadow the kty error: expectedJwkAlgs
  // returns null for an unknown kty, so the alg check passes through
  // and the importer reports the unsupported kty.
  const doc = {
    keys: [{ kty: "AKP", k: "AAECAwQFBgcICQoLDA0ODw", kid: "sym-key-1", alg: "HS256" }],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await assert.rejects(store.refresh(), /unsupported kty/);
  assert.equal(store.size, 0);
});
