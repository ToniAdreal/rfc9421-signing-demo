import test from "node:test";
import assert from "node:assert/strict";
import { createSecretKey, type KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
  verifyRequestAsync,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function REQT(r: typeof REQ): typeof REQ {
  return { ...r, headers: { ...r.headers } };
}

/** Two rotating key pairs behind a `keyid`→key map, like a keystore. */
function keystore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key-1", k1.publicKey],
    ["merchant-key-2", k2.publicKey],
  ]);
  return { k1, k2, store };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  extra: { label?: string; nonce?: string; expires?: number } = {},
): SignedHttpRequest {
  return signRequest(REQT(REQ), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    ...extra,
  });
}

/** Flip the last byte of the `sig1` signature value (keeps the header well-formed). */
function tamperSignature(signed: SignedHttpRequest): SignedHttpRequest {
  const field = signed.headers["signature"] as string;
  const match = /^sig1=:([A-Za-z0-9+/=]+):$/.exec(field);
  assert.ok(match, "signature header shape");
  const bytes = Buffer.from(match[1], "base64");
  bytes[bytes.length - 1] ^= 0xff;
  return {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${bytes.toString("base64")}:`,
    },
  };
}

/** An async resolver over the keystore, with a real await in the path. */
function asyncKeyResolver(store: Map<string, KeyObject>) {
  return async (keyId: string) => {
    await new Promise((resolve) => setImmediate(resolve));
    return store.get(keyId);
  };
}

test("verifyRequestAsync: async resolver round-trip (both key ids)", async () => {
  const { k1, k2, store } = keystore();
  const s1 = signAs("merchant-key-1", k1.privateKey);
  const s2 = signAs("merchant-key-2", k2.privateKey);
  const keyResolver = asyncKeyResolver(store);
  const r1 = await verifyRequestAsync(s1, { keyResolver, now: CREATED });
  const r2 = await verifyRequestAsync(s2, { keyResolver, now: CREATED });
  assert.equal(r1.ok, true);
  assert.equal(r1.keyId, "merchant-key-1");
  assert.equal(r2.ok, true);
  assert.equal(r2.keyId, "merchant-key-2");
});

test("verifyRequestAsync: a synchronous resolver still works (assignable to AsyncKeyResolver)", async () => {
  const { k1, store } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const r = await verifyRequestAsync(signed, {
    keyResolver: (id: string) => store.get(id),
    now: CREATED,
  });
  assert.equal(r.ok, true);
  assert.equal(r.keyId, "merchant-key-1");
});

test("verifyRequestAsync: unknown keyid fails with KEY_RESOLUTION_FAILED", async () => {
  const { k1, store } = keystore();
  const signed = signAs("attacker-key", k1.privateKey);
  const r = await verifyRequestAsync(signed, {
    keyResolver: asyncKeyResolver(store),
    now: CREATED,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, "KEY_RESOLUTION_FAILED");
});

test("verifyRequestAsync: resolver resolving to undefined fails with KEY_RESOLUTION_FAILED", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const r = await verifyRequestAsync(signed, {
    keyResolver: async () => undefined,
    now: CREATED,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, "KEY_RESOLUTION_FAILED");
});

test("verifyRequestAsync: resolver throw is contained to VERIFICATION_ERROR without leaking the error", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const r = await verifyRequestAsync(signed, {
    keyResolver: async () => {
      throw new Error("vault-unreachable: secret-token-abc123 at https://vault.internal:8200");
    },
    now: CREATED,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, "VERIFICATION_ERROR");
  assert.equal(r.reason, "key resolver threw an error");
  assert.ok(!r.reason?.includes("vault-unreachable"));
  assert.ok(!r.reason?.includes("secret-token-abc123"));
});

test("verifyRequestAsync: resolver returning a non-KeyObject is contained to VERIFICATION_ERROR without leaking the value", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  for (const bad of ["not-a-key", 42, {}, { type: "bogus" }] as unknown[]) {
    const r = await verifyRequestAsync(signed, {
      keyResolver: async () => bad as KeyObject,
      now: CREATED,
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, "VERIFICATION_ERROR");
    assert.ok(!r.reason?.includes("not-a-key"));
    assert.ok(!r.reason?.includes("bogus"));
  }
});

test("verifyRequestAsync: resolver is not called for a request that fails an earlier gate", async () => {
  const { store } = keystore();
  let calls = 0;
  const keyResolver = async (keyId: string) => {
    calls++;
    return store.get(keyId);
  };
  // No signature-input header at all: MISSING_SIGNATURE_INPUT, resolver untouched.
  const r = await verifyRequestAsync(REQT(REQ), { keyResolver, now: CREATED });
  assert.equal(r.ok, false);
  assert.equal(r.code, "MISSING_SIGNATURE_INPUT");
  assert.equal(calls, 0);
});

test("verifyRequestAsync: tampered signature fails SIGNATURE_MISMATCH and does not consume the nonce", async () => {
  const { k1, store } = keystore();
  const cache = new ReplayCache({ ttlSec: 3600 });
  const keyResolver = asyncKeyResolver(store);
  const signed = signAs("merchant-key-1", k1.privateKey, { nonce: "async-nonce-1" });
  // Tamper with the signature value: flip its last byte.
  const tampered = tamperSignature(signed);
  const bad = await verifyRequestAsync(tampered, {
    keyResolver,
    replayCache: cache,
    maxSignatureAgeSec: 60,
    now: CREATED,
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.has("async-nonce-1", CREATED, "merchant-key-1"), false);
  // The genuine signature with the same nonce still verifies first time.
  const good = await verifyRequestAsync(signed, {
    keyResolver,
    replayCache: cache,
    maxSignatureAgeSec: 60,
    now: CREATED,
  });
  assert.equal(good.ok, true);
  assert.equal(cache.has("async-nonce-1", CREATED, "merchant-key-1"), true);
});

test("verifyRequestAsync: replay cache rejects the second presentation of a nonce", async () => {
  const { k1, store } = keystore();
  const cache = new ReplayCache({ ttlSec: 3600 });
  const keyResolver = asyncKeyResolver(store);
  const signed = signAs("merchant-key-1", k1.privateKey, { nonce: "async-nonce-2" });
  const opts = {
    keyResolver,
    replayCache: cache,
    maxSignatureAgeSec: 60,
    now: CREATED,
  };
  assert.equal((await verifyRequestAsync(signed, opts)).ok, true);
  const replay = await verifyRequestAsync(signed, opts);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
});

test("verifyRequestAsync: candidateKeys rotation walk still works (sync keys)", async () => {
  const { k1, k2 } = keystore();
  const signed = signAs("merchant-key-2", k2.privateKey);
  // Wrong key first, right key second: first full pass wins.
  const r = await verifyRequestAsync(signed, {
    candidateKeys: [k1.publicKey, k2.publicKey],
    now: CREATED,
  });
  assert.equal(r.ok, true);
  // No candidate matches: last candidate's SIGNATURE_MISMATCH.
  const bad = await verifyRequestAsync(signed, {
    candidateKeys: [k1.publicKey],
    now: CREATED,
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "SIGNATURE_MISMATCH");
});

test("verifyRequestAsync: static key still works (no resolver involved)", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const r = await verifyRequestAsync(signed, { key: k1.publicKey, now: CREATED });
  assert.equal(r.ok, true);
});

test("verifyRequestAsync: unknown option key throws naming verifyRequestAsync", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  await assert.rejects(
    verifyRequestAsync(signed, {
      key: k1.publicKey,
      now: CREATED,
      maxSignatureAge: 60,
    } as never),
    /invalid verifyRequestAsync options: unknown option "maxSignatureAge"/,
  );
});

test("verifyRequestAsync: no key source throws a configuration error", async () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  await assert.rejects(
    verifyRequestAsync(signed, { now: CREATED }),
    /verifyRequestAsync: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
});

test("verifyRequestAsync: key + keyResolver together throw a configuration error", async () => {
  const { k1, store } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  await assert.rejects(
    verifyRequestAsync(signed, {
      key: k1.publicKey,
      keyResolver: asyncKeyResolver(store),
      now: CREATED,
    }),
    /mutually exclusive/,
  );
});

test("verifyRequestAsync: expectedKeyId pinning still applies after the async resolution", async () => {
  const { k1, store } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const r = await verifyRequestAsync(signed, {
    keyResolver: asyncKeyResolver(store),
    expectedKeyId: "other-key",
    now: CREATED,
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, "KEYID_MISMATCH");
});

test("verifyRequestAsync: hmac secret resolved asynchronously verifies", async () => {
  const secretKey = createSecretKey(Buffer.alloc(32, 7));
  const signed = signRequest(REQT(REQ), {
    keyId: "hmac-key-1",
    alg: "hmac-sha256",
    key: secretKey,
    created: CREATED,
  });
  const r = await verifyRequestAsync(signed, {
    keyResolver: async (keyId: string) => {
      await new Promise((resolve) => setImmediate(resolve));
      return keyId === "hmac-key-1" ? secretKey : undefined;
    },
    now: CREATED,
  });
  assert.equal(r.ok, true);
  assert.equal(r.alg, "hmac-sha256");
});

test("verifyRequestAsync: sync/async parity — identical verdicts for the same requests", async () => {
  const { k1, k2, store } = keystore();
  const keyResolver = (id: string) => store.get(id);
  const good = signAs("merchant-key-1", k1.privateKey);
  const tampered = tamperSignature(good);
  const expired = signAs("merchant-key-2", k2.privateKey, { expires: CREATED + 60 });
  const cases: [string, SignedHttpRequest, number][] = [
    ["good", good, CREATED],
    ["tampered", tampered, CREATED],
    ["expired", expired, CREATED + 3600],
  ];
  for (const [name, req, now] of cases) {
    const syncResult = verifyRequest(req, { keyResolver, now });
    const asyncResult = await verifyRequestAsync(req, { keyResolver, now });
    assert.deepEqual(asyncResult, syncResult, `parity failed for ${name}`);
  }
});
