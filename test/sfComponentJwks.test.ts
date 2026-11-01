import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  parseSignatureInput,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksKeyStoreSnapshot,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const JWKS_URL = "https://gateway.example.com/.well-known/jwks.json";

// The dictionary the backlog item names: two members, the second
// carrying a parameter. Its strict serialization is itself — the
// combination under test is that this serialization, not the raw
// wire spacing, is what the JWKS-resolved key verifies.
const DICT = "a=1, b=2;x=1";
const SLOPPY_DICT = "a=1,   b=2;x=1";

function makeReq(value: string = DICT): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": value },
    body: "hello",
  };
}

function signSf(
  privateKey: KeyObject,
  keyId: string,
  value: string = DICT,
): SignedHttpRequest {
  return signRequest(makeReq(value), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "x-quota;sf"],
  });
}

/** A fetch that must never be called: restore paths are offline. */
const noFetch: JwksFetchImpl = async () => {
  throw new Error("fetch must not be called by snapshot restore");
};

function snapshotFor(
  publicKey: KeyObject,
  kid: string,
): JwksKeyStoreSnapshot {
  return {
    v: 1,
    fetchedAtSec: CREATED,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid }],
  };
}

interface StoreOpts {
  fetchImpl?: JwksFetchImpl;
  ttlSec?: number;
  now?: () => number;
}

function restoredStore(
  publicKey: KeyObject,
  kid: string,
  opts: StoreOpts = {},
): JwksKeyStore {
  return JwksKeyStore.restore(snapshotFor(publicKey, kid), JWKS_URL, {
    fetchImpl: noFetch,
    ttlSec: 300,
    ...opts,
  });
}

test(";sf x JwksKeyStore: a dictionary component verifies through an offline-restored store", () => {
  const keys = generateEd25519KeyPair();
  const signed = signSf(keys.privateKey, "gateway-key-1");
  assert.match(signed.headers["signature-input"], /"x-quota";sf/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", "x-quota;sf"]);

  const store = restoredStore(keys.publicKey, "gateway-key-1");
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "gateway-key-1");
  assert.equal(res.alg, "ed25519");
});

test(";sf x JwksKeyStore: re-spaced dictionary wire value still verifies (canonical serialization, not raw bytes)", () => {
  const keys = generateEd25519KeyPair();
  // Signed with sloppy spacing; presented with canonical spacing.
  const signed = signSf(keys.privateKey, "gateway-key-1", SLOPPY_DICT);
  const store = restoredStore(keys.publicKey, "gateway-key-1");
  const respaced = {
    ...signed,
    headers: { ...signed.headers, "x-quota": DICT },
  };
  assert.equal(
    verifyRequest(respaced, { keyResolver: store.resolve, now: NOW }).ok,
    true,
  );
  // And the reverse direction: signed canonical, presented sloppy.
  const signedCanonical = signSf(keys.privateKey, "gateway-key-1", DICT);
  const sloppy = {
    ...signedCanonical,
    headers: { ...signedCanonical.headers, "x-quota": SLOPPY_DICT },
  };
  assert.equal(
    verifyRequest(sloppy, { keyResolver: store.resolve, now: NOW }).ok,
    true,
  );
});

test(";sf x JwksKeyStore: tampering a dictionary member value or parameter fails with SIGNATURE_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const signed = signSf(keys.privateKey, "gateway-key-1");
  const store = restoredStore(keys.publicKey, "gateway-key-1");
  // Member value change: b=2 -> b=3.
  const valueTampered = {
    ...signed,
    headers: { ...signed.headers, "x-quota": "a=1, b=3;x=1" },
  };
  const valueRes = verifyRequest(valueTampered, {
    keyResolver: store.resolve,
    now: NOW,
  });
  assert.equal(valueRes.ok, false);
  assert.equal(valueRes.code, "SIGNATURE_MISMATCH");
  // Parameter change: x=1 -> x=2 (same member, different parameter).
  const paramTampered = {
    ...signed,
    headers: { ...signed.headers, "x-quota": "a=1, b=2;x=2" },
  };
  const paramRes = verifyRequest(paramTampered, {
    keyResolver: store.resolve,
    now: NOW,
  });
  assert.equal(paramRes.ok, false);
  assert.equal(paramRes.code, "SIGNATURE_MISMATCH");
});

test(";sf x JwksKeyStore: after a rotation refresh retires the kid, the ;sf signature fails KEY_RESOLUTION_FAILED", async () => {
  const oldKeys = generateEd25519KeyPair();
  const signed = signSf(oldKeys.privateKey, "gateway-key-1");
  // The gateway rotates: its endpoint now serves only the new kid.
  // The fetch is a stub returning the rotated document — still zero
  // real network — and refresh() is the re-pull that retires the old kid.
  const rotated = generateEd25519KeyPair();
  const rotatedFetch: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      keys: [
        { ...exportPublicKeyJwk(rotated.publicKey), kid: "gateway-key-2" },
      ],
    }),
  });
  const store = restoredStore(oldKeys.publicKey, "gateway-key-1", {
    fetchImpl: rotatedFetch,
    now: () => CREATED,
  });
  assert.notEqual(store.resolve("gateway-key-1"), undefined);
  await store.refresh();
  assert.equal(store.size, 1);
  assert.equal(store.resolve("gateway-key-1"), undefined);
  assert.notEqual(store.resolve("gateway-key-2"), undefined);
  // The request still carries the old kid, so verification fails
  // closed with KEY_RESOLUTION_FAILED — never a silent fallback to
  // the new key, and never a crypto mismatch masking the rotation.
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
  assert.equal(res.keyId, "gateway-key-1");
});

test(";sf x JwksKeyStore: a stale snapshot still resolves and verifies, with no fetch attempted", () => {
  const keys = generateEd25519KeyPair();
  const signed = signSf(keys.privateKey, "gateway-key-1");
  // The snapshot is past its 300s TTL (clock pinned at CREATED +
  // 1000) and has never been re-pulled, yet resolve keeps serving
  // the last good snapshot. The fetch counts calls and throws if
  // anything ever calls it, so a passing verify plus a zero count
  // proves no fetch ran.
  let fetchCalls = 0;
  const countingThrowingFetch: JwksFetchImpl = async () => {
    fetchCalls++;
    throw new Error("fetch must not be called by stale-snapshot verify");
  };
  const store = restoredStore(keys.publicKey, "gateway-key-1", {
    fetchImpl: countingThrowingFetch,
    now: () => CREATED + 1000,
  });
  assert.equal(store.isStale(), true);
  assert.notEqual(store.resolve("gateway-key-1"), undefined);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "gateway-key-1");
  assert.equal(fetchCalls, 0);
});
