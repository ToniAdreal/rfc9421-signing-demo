import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://gateway.example.com/.well-known/jwks.json";

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function docFor(publicKey: KeyObject, kid = "ed-key-1") {
  return { keys: [{ ...exportPublicKeyJwk(publicKey), kid }] };
}

function okResponse(body: unknown) {
  return { ok: true, status: 200, json: async () => body };
}

/** A store whose fetch always returns `doc`. */
async function storeWithDoc(doc: unknown): Promise<JwksKeyStore> {
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(doc),
  });
  await store.refresh();
  return store;
}

/** Sign with no `keyId`, so the signature carries no `keyid` parameter. */
function signKeyidLess(
  privateKey: KeyObject,
  label?: string,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    ...(label !== undefined ? { label } : {}),
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

test("single-key fallback: single-key store verifies a keyid-less signature when opted in", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, undefined);
});

test("single-key fallback: opt-in off keeps the historical KEY_RESOLUTION_FAILED", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
  assert.equal(res.reason, "signature carries no keyid to resolve");
});

test("single-key fallback: a multi-key snapshot never falls back", async () => {
  const one = generateEd25519KeyPair();
  const two = generateEd25519KeyPair();
  const store = await storeWithDoc({
    keys: [
      { ...exportPublicKeyJwk(one.publicKey), kid: "ed-key-1" },
      { ...exportPublicKeyJwk(two.publicKey), kid: "ed-key-2" },
    ],
  });
  assert.equal(store.size, 2);
  const signed = signKeyidLess(one.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
});

test("single-key fallback: a store that never refreshed never falls back", async () => {
  const ed = generateEd25519KeyPair();
  const store = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(docFor(ed.publicKey)),
  });
  assert.equal(store.size, 0);
  const signed = signKeyidLess(ed.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
});

test("single-key fallback: a keyid-carrying signature is unaffected by the opt-in", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signRequest(baseRequest(), {
    keyId: "ed-key-1",
    alg: "ed25519",
    key: ed.privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "ed-key-1");
  // And an unknown kid still fails closed — the fallback is only for
  // signatures with no keyid at all, never for a kid that misses.
  const unknown = signRequest(baseRequest(), {
    keyId: "retired-key-9",
    alg: "ed25519",
    key: ed.privateKey,
    created: CREATED,
  });
  const missed = verifyRequest(unknown, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(missed.ok, false);
  assert.equal(missed.code, "KEY_RESOLUTION_FAILED");
  assert.match(
    missed.reason ?? "",
    /keyid "retired-key-9" could not be resolved to a key/,
  );
});

test("single-key fallback: the only key is actually tried, so a foreign signature mismatches", async () => {
  const ed = generateEd25519KeyPair();
  const other = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(other.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("single-key fallback: a non-JWKS resolver plus the opt-in is a configuration error", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  assert.throws(
    () =>
      verifyRequest(signed, {
        keyResolver: () => ed.publicKey,
        singleKeyFallback: store,
        now: CREATED,
      }),
    (err: unknown) =>
      err instanceof Error &&
      err.message ===
        "verifyRequest: `singleKeyFallback` requires `keyResolver` to be that store's `resolve` — a non-JWKS resolver cannot fall back to the store's only key",
  );
});

test("single-key fallback: a static key plus the opt-in is a configuration error", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: ed.publicKey,
        singleKeyFallback: store,
        now: CREATED,
      }),
    /`singleKeyFallback` requires `keyResolver` to be that store's `resolve`/,
  );
});

test("single-key fallback: candidateKeys plus the opt-in is a configuration error", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  assert.throws(
    () =>
      verifyRequest(signed, {
        candidateKeys: [ed.publicKey],
        singleKeyFallback: store,
        now: CREATED,
      }),
    /`singleKeyFallback` requires `keyResolver` to be that store's `resolve`/,
  );
});

test("single-key fallback: a non-store value is a configuration error", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  for (const bad of [
    {},
    { resolve: () => ed.publicKey },
    "https://gateway.example.com/.well-known/jwks.json",
  ]) {
    assert.throws(
      () =>
        verifyRequest(signed, {
          keyResolver: store.resolve,
          singleKeyFallback: bad as unknown as JwksKeyStore,
          now: CREATED,
        }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          "verifyRequest: `singleKeyFallback` must be a JwksKeyStore",
      `expected throw for singleKeyFallback=${JSON.stringify(bad)}`,
    );
  }
});

test("single-key fallback: a different store than the resolver's store is a configuration error", async () => {
  const ed = generateEd25519KeyPair();
  const other = generateEd25519KeyPair();
  const storeA = await storeWithDoc(docFor(ed.publicKey));
  const storeB = await storeWithDoc(docFor(other.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  assert.throws(
    () =>
      verifyRequest(signed, {
        keyResolver: storeA.resolve,
        singleKeyFallback: storeB,
        now: CREATED,
      }),
    /`singleKeyFallback` requires `keyResolver` to be that store's `resolve`/,
  );
});

test("resolveOnlyKey: single key returns it, multi/empty/cleared return undefined", async () => {
  const one = generateEd25519KeyPair();
  const two = generateEd25519KeyPair();
  const single = await storeWithDoc(docFor(one.publicKey));
  // The store holds an imported copy of the key, so compare the
  // exported JWK, not the object reference.
  assert.deepEqual(
    exportPublicKeyJwk(single.resolveOnlyKey()!),
    exportPublicKeyJwk(one.publicKey),
  );
  const multi = await storeWithDoc({
    keys: [
      { ...exportPublicKeyJwk(one.publicKey), kid: "ed-key-1" },
      { ...exportPublicKeyJwk(two.publicKey), kid: "ed-key-2" },
    ],
  });
  assert.equal(multi.resolveOnlyKey(), undefined);
  const empty = new JwksKeyStore(URL, {
    fetchImpl: async () => okResponse(docFor(one.publicKey)),
  });
  assert.equal(empty.resolveOnlyKey(), undefined);
  single.clear();
  assert.equal(single.size, 0);
  assert.equal(single.resolveOnlyKey(), undefined);
});

test("single-key fallback: a stale snapshot still falls back after a failed refresh", async () => {
  const ed = generateEd25519KeyPair();
  const script: Array<
    | { kind: "ok"; body: unknown }
    | { kind: "throw"; message: string }
  > = [
    { kind: "ok", body: docFor(ed.publicKey) },
    { kind: "throw", message: "gateway down" },
  ];
  const fetchImpl = async () => {
    const next = script.shift();
    assert.ok(next !== undefined, "scripted fetch ran out of outcomes");
    if (next.kind === "ok") return okResponse(next.body);
    throw new Error(next.message);
  };
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  await assert.rejects(() => store.refresh(), /gateway down/);
  // The failed refresh kept the old snapshot, so the fallback still
  // serves the only key — staleness degrades to the cached key, the
  // same as `resolve` serves a stale snapshot. (The store holds an
  // imported copy of the key, so compare the exported JWK.)
  assert.deepEqual(
    exportPublicKeyJwk(store.resolveOnlyKey()!),
    exportPublicKeyJwk(ed.publicKey),
  );
  const signed = signKeyidLess(ed.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.ok, true);
});

test("single-key fallback: verifyAllLabels verifies both keyid-less labels through the fallback", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = mergeSignatures(
    signKeyidLess(ed.privateKey, "sig1"),
    signKeyidLess(ed.privateKey, "sig2"),
  );
  const results = verifyAllLabels(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["sig1", true],
      ["sig2", true],
    ],
  );
});

test("single-key fallback: verifyAllLabels throws when a label uses its own non-JWKS resolver", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = mergeSignatures(
    signKeyidLess(ed.privateKey, "sig1"),
    signKeyidLess(ed.privateKey, "sig2"),
  );
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        keyResolver: store.resolve,
        keyResolvers: { sig2: () => ed.publicKey },
        singleKeyFallback: store,
        now: CREATED,
      }),
    /`singleKeyFallback` requires `keyResolver` to be that store's `resolve`/,
  );
});

test("single-key fallback: verifyRequestOrThrow succeeds through the fallback", async () => {
  const ed = generateEd25519KeyPair();
  const store = await storeWithDoc(docFor(ed.publicKey));
  const signed = signKeyidLess(ed.privateKey);
  const res = verifyRequestOrThrow(signed, {
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: CREATED,
  });
  assert.equal(res.label, "sig1");
  assert.equal(res.keyId, undefined);
});
