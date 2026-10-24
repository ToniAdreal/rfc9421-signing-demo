import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
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
    url: "https://api.example.com/v1/payouts",
    headers: {} as Record<string, string>,
    body: '{"payout":42}',
  };
}

function signAs(
  keyId: string,
  alg: "ed25519" | "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "ecdsa-p521-sha512" | "rsa-pss-sha512",
  privateKey: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId, alg, key: privateKey, created: CREATED });
}

/**
 * Serve `getBody()` (re-read per request, so tests can rotate the
 * document mid-test) from a local HTTP server on an ephemeral port.
 */
async function serve(
  getBody: () => string,
  status = 200,
): Promise<{ server: Server; url: string }> {
  const server = createServer((_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(getBody());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(typeof addr === "object" && addr !== null);
  return { server, url: `http://127.0.0.1:${addr.port}/.well-known/jwks.json` };
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

/** A fetch stub that serves a fixed JSON body without any network. */
function stubFetch(body: unknown, status = 200): JwksFetchImpl {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

test("JwksKeyStore: P-384 JWKS entry refresh→resolve→ecdsa-p384-sha384 verify round-trip", async () => {
  const pair = generateP384KeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwkP384(pair.publicKey), kid: "p384-key-1" }],
  };
  assert.equal(doc.keys[0].crv, "P-384");
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  const resolved = store.resolve("p384-key-1");
  assert.ok(resolved !== undefined);
  assert.equal(
    resolved.export({ format: "pem", type: "spki" }).toString(),
    pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
  );
  const signed = signAs("p384-key-1", "ecdsa-p384-sha384", pair.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "p384-key-1");
});

test("JwksKeyStore: P-521 JWKS entry refresh→resolve→ecdsa-p521-sha512 verify round-trip", async () => {
  const pair = generateP521KeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwkP521(pair.publicKey), kid: "p521-key-1" }],
  };
  assert.equal(doc.keys[0].crv, "P-521");
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 1);
  const signed = signAs("p521-key-1", "ecdsa-p521-sha512", pair.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "p521-key-1");
});

test("JwksKeyStore: P-256 EC entry still imports exactly as before (regression)", async () => {
  const pair = generateP256KeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwkP256(pair.publicKey), kid: "p256-key-1" }],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  const signed = signAs("p256-key-1", "ecdsa-p256-sha256", pair.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "p256-key-1");
});

test("JwksKeyStore: five-curve document coexists — every kid resolves and verifies with its own alg", async () => {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const p384 = generateP384KeyPair();
  const p521 = generateP521KeyPair();
  const rsa = generateRsaPssKeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1" },
      { ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1" },
      { ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1" },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  assert.equal(store.size, 5);
  const cases: Array<[string, SignedHttpRequest]> = [
    ["ed-key-1", signAs("ed-key-1", "ed25519", ed.privateKey)],
    ["p256-key-1", signAs("p256-key-1", "ecdsa-p256-sha256", p256.privateKey)],
    ["p384-key-1", signAs("p384-key-1", "ecdsa-p384-sha384", p384.privateKey)],
    ["p521-key-1", signAs("p521-key-1", "ecdsa-p521-sha512", p521.privateKey)],
    ["rsa-key-1", signAs("rsa-key-1", "rsa-pss-sha512", rsa.privateKey)],
  ];
  for (const [keyId, signed] of cases) {
    const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
    assert.equal(res.ok, true, keyId);
    assert.equal(res.keyId, keyId);
  }
});

test("JwksKeyStore: unknown EC crv (P-999) refresh throws and the old snapshot is untouched", async () => {
  const p256 = generateP256KeyPair();
  const goodBody = JSON.stringify({
    keys: [{ ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1" }],
  });
  const badJwk = { ...exportPublicKeyJwkP256(p256.publicKey), crv: "P-999", kid: "p999-key-1" };
  const badBody = JSON.stringify({ keys: [badJwk] });
  let current = goodBody;
  const { server, url } = await serve(() => current);
  try {
    const store = new JwksKeyStore(url);
    await store.refresh();
    const before = store.resolve("p256-key-1");
    assert.ok(before !== undefined);
    assert.equal(store.size, 1);

    current = badBody;
    await assert.rejects(() => store.refresh(), /unsupported EC crv "P-999"/);
    // Fail-closed: the previous snapshot — and its verification path —
    // survive the bad document.
    assert.equal(store.resolve("p256-key-1"), before);
    assert.equal(store.resolve("p999-key-1"), undefined);
    assert.equal(store.size, 1);
    const signed = signAs("p256-key-1", "ecdsa-p256-sha256", p256.privateKey);
    assert.equal(
      verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
      true,
    );
  } finally {
    await close(server);
  }
});

test("JwksKeyStore: EC entry missing crv is rejected explicitly", async () => {
  const p256 = generateP256KeyPair();
  const { crv: _dropped, ...crvless } = exportPublicKeyJwkP256(p256.publicKey);
  const doc = { keys: [{ ...crvless, kid: "crvless-key-1" }] };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await assert.rejects(() => store.refresh(), /unsupported EC crv undefined/);
  assert.equal(store.size, 0);
});

test("JwksKeyStore: exportSnapshot/restore round-trips P-384 and P-521 keys and the restored store verifies", async () => {
  const p384 = generateP384KeyPair();
  const p521 = generateP521KeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1" },
      { ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  const snapshot = store.exportSnapshot();
  // The snapshot carries the curve identity: restore must land on the
  // right importer, not on a P-256 default.
  const crvs = snapshot.keys
    .map((k) => (k as unknown as Record<string, unknown>)["crv"])
    .sort();
  assert.deepEqual(crvs, ["P-384", "P-521"]);
  const wire = JSON.parse(JSON.stringify(snapshot));
  const restored = JwksKeyStore.restore(wire, "https://gateway.example.com/jwks.json");
  for (const [kid, pair, alg] of [
    ["p384-key-1", p384, "ecdsa-p384-sha384"],
    ["p521-key-1", p521, "ecdsa-p521-sha512"],
  ] as const) {
    assert.ok(restored.resolve(kid) !== undefined);
    const signed = signAs(kid, alg, pair.privateKey);
    const res = verifyRequest(signed, {
      keyResolver: restored.resolve,
      now: CREATED,
    });
    assert.equal(res.ok, true, kid);
  }
});

test("JwksKeyStore: tampered P-384 signature is rejected (cross-curve isolation)", async () => {
  const p384 = generateP384KeyPair();
  const p521 = generateP521KeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwkP384(p384.publicKey), kid: "p384-key-1" },
      { ...exportPublicKeyJwkP521(p521.publicKey), kid: "p521-key-1" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh();
  // Sign with the P-384 key but claim the P-521 kid: the imported curves
  // must not be interchangeable.
  const signed = signAs("p521-key-1", "ecdsa-p384-sha384", p384.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, false);
});

test("JwksKeyStore: snapshot restore with an unknown EC crv throws and does not build a half-keyed store", async () => {
  const p384 = generateP384KeyPair();
  const jwk = { ...exportPublicKeyJwkP384(p384.publicKey), crv: "P-999", kid: "p999-key-1" };
  const snapshot = { v: 1, fetchedAtSec: 1700000000, keys: [jwk] };
  assert.throws(
    () => JwksKeyStore.restore(snapshot, "https://gateway.example.com/jwks.json"),
    /unsupported EC crv "P-999"/,
  );
});
