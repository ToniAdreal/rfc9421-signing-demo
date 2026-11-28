import test from "node:test";
import assert from "node:assert/strict";
import { type KeyObject } from "node:crypto";
import {
  addResponseSignature,
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signResponse,
  verifyAllResponseLabels,
  verifyAllResponseLabelsAsync,
  verifyAllResponseLabelsOrThrowAsync,
  verifyResponse,
  verifyResponseAsync,
  verifyResponseOrThrowAsync,
  type HttpResponseLike,
  type RequestLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1447: the request side gained `verifyRequestAsync` /
// `verifyAllLabelsAsync` in #1439, but `src/response.ts` had only the
// synchronous entry points — a response verifier whose keys live
// behind an async lookup (remote JWKS, Vault, KMS) could not verify a
// signed response at all. These tests pin the async response twins:
// same verdicts as the sync side for the same input, async resolver
// containment per label, and the OrThrow twins.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

function triggeringRequest(): RequestLike {
  return {
    method: "POST",
    url: `${URL}?order=42`,
    headers: { "x-charge-id": "ch_42" },
  };
}

/** Two rotating key pairs behind a `keyid`→key map, like a keystore. */
function keystore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["gateway-key-1", k1.publicKey],
    ["gateway-key-2", k2.publicKey],
  ]);
  return { k1, k2, store };
}

/** An async resolver with a real await in the path. */
function asyncResolver(store: Map<string, KeyObject>) {
  return async (keyId: string) => {
    await Promise.resolve();
    return store.get(keyId);
  };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  extra: { label?: string; nonce?: string } = {},
): SignedHttpResponse {
  return signResponse(response(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    ...extra,
  });
}

/** Flip the last byte of the `sig1` signature value (keeps the header well-formed). */
function tamperSignature(signed: SignedHttpResponse): SignedHttpResponse {
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

test("async resolver round-trip: @status + content-digest verify, keyid echoed", async () => {
  const { k1, store } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(signed, {
    keyResolver: asyncResolver(store),
    now: NOW,
  });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "gateway-key-1");
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("keyid rotation: resolver serves the second key after rotation", async () => {
  const { k1, k2, store } = keystore();
  const first = await verifyResponseAsync(signAs("gateway-key-1", k1.privateKey), {
    keyResolver: asyncResolver(store),
    now: NOW,
  });
  assert.equal(first.ok, true);
  const second = await verifyResponseAsync(signAs("gateway-key-2", k2.privateKey), {
    keyResolver: asyncResolver(store),
    now: NOW,
  });
  assert.equal(second.ok, true);
  assert.equal(second.keyId, "gateway-key-2");
});

test("a synchronous resolver keeps working through the async entry point", async () => {
  const { k1, store } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(signed, {
    keyResolver: (keyId: string) => store.get(keyId),
    now: NOW,
  });
  assert.equal(result.ok, true);
});

test("unknown keyid fails with KEY_RESOLUTION_FAILED", async () => {
  const { k1 } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(signed, {
    keyResolver: async () => undefined,
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "KEY_RESOLUTION_FAILED");
});

test("resolver that throws is contained to VERIFICATION_ERROR without leaking its error", async () => {
  const { k1 } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(signed, {
    keyResolver: async () => {
      throw new Error("vault boom SECRET-DO-NOT-LEAK");
    },
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
  assert.doesNotMatch(result.reason ?? "", /SECRET-DO-NOT-LEAK/);
});

test("resolver resolving to a non-KeyObject is contained to VERIFICATION_ERROR", async () => {
  const { k1 } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(signed, {
    keyResolver: async () => "not-a-key" as unknown as KeyObject,
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "VERIFICATION_ERROR");
  assert.doesNotMatch(result.reason ?? "", /not-a-key/);
});

test("tampered status fails with SIGNATURE_MISMATCH through the async path", async () => {
  const { k1, store } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const result = await verifyResponseAsync(
    { ...signed, status: 201 },
    { keyResolver: asyncResolver(store), now: NOW },
  );
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("sync/async parity: identical verdicts on good, tampered, and too-old responses", async () => {
  const { k1, store } = keystore();
  const good = signAs("gateway-key-1", k1.privateKey);
  const tampered = tamperSignature(good);
  for (const signed of [good, tampered]) {
    const syncResult = verifyResponse(signed, { key: k1.publicKey, now: NOW });
    const asyncResult = await verifyResponseAsync(signed, {
      keyResolver: asyncResolver(store),
      now: NOW,
    });
    assert.deepEqual(
      { ok: asyncResult.ok, code: asyncResult.code, label: asyncResult.label },
      { ok: syncResult.ok, code: syncResult.code, label: syncResult.label },
    );
  }
  const syncOld = verifyResponse(good, {
    key: k1.publicKey,
    now: NOW,
    maxSignatureAgeSec: 30,
  });
  const asyncOld = await verifyResponseAsync(good, {
    keyResolver: asyncResolver(store),
    now: NOW,
    maxSignatureAgeSec: 30,
  });
  assert.equal(syncOld.code, "SIGNATURE_TOO_OLD");
  assert.equal(asyncOld.code, "SIGNATURE_TOO_OLD");
  assert.equal(asyncOld.ok, false);
});

test("resolver is never invoked when the response carries no signature-input", async () => {
  let calls = 0;
  const result = await verifyResponseAsync(response(), {
    keyResolver: async (keyId: string) => {
      calls += 1;
      return undefined;
    },
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_SIGNATURE_INPUT");
  assert.equal(calls, 0);
});

test(";req components resolve against the attached request through the async path", async () => {
  const { k1, store } = keystore();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: k1.privateKey,
      created: CREATED,
      coveredComponents: ["@status", "@method;req", "@authority;req"],
      request,
    },
  );
  const result = await verifyResponseAsync(signed, {
    keyResolver: asyncResolver(store),
    now: NOW,
    request,
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.coveredComponents, [
    "@status",
    "@method;req",
    "@authority;req",
  ]);
});

test("verify side still rejects a ;req signature with no request attached, naming verifyResponseAsync", async () => {
  const { k1 } = keystore();
  const request = triggeringRequest();
  const signed = signResponse(
    { status: 200, headers: {} },
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: k1.privateKey,
      created: CREATED,
      coveredComponents: ["@status", "@method;req"],
      request,
    },
  );
  await assert.rejects(
    () => verifyResponseAsync(signed, { key: k1.publicKey, now: NOW }),
    /verifyResponseAsync: covered component .* derives from the request.*verifyRequestAsync/,
  );
});

test("configuration errors name verifyResponseAsync: unknown option and bad status", async () => {
  const { k1, store } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  await assert.rejects(
    () =>
      verifyResponseAsync(signed, {
        keyResolver: asyncResolver(store),
        now: NOW,
        bogus: true,
      } as never),
    /invalid verifyResponseAsync options: unknown option "bogus"/,
  );
  await assert.rejects(
    () =>
      verifyResponseAsync(
        { ...signed, status: 99 },
        { keyResolver: asyncResolver(store), now: NOW },
      ),
    /verifyResponseAsync: "status" must be an integer HTTP status code/,
  );
});

test("verifyResponseOrThrowAsync returns the identity on success and throws VerifyError on failure", async () => {
  const { k1, store } = keystore();
  const signed = signAs("gateway-key-1", k1.privateKey);
  const identity = await verifyResponseOrThrowAsync(signed, {
    keyResolver: asyncResolver(store),
    now: NOW,
  });
  assert.equal(identity.label, "sig1");
  assert.equal(identity.keyId, "gateway-key-1");
  assert.equal(identity.alg, "ed25519");
  const tampered = tamperSignature(signed);
  await assert.rejects(
    () =>
      verifyResponseOrThrowAsync(tampered, {
        keyResolver: asyncResolver(store),
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal((e as { code: string }).code, "SIGNATURE_MISMATCH");
      return true;
    },
  );
});

const merchant = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function merchantThenGateway(): SignedHttpResponse {
  const merchantSigned = signResponse(
    { status: 200, headers: { "content-type": "application/json" }, body: BODY },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  return addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
}

test("dual-signed response verifies both labels via per-label async resolvers", async () => {
  const dual = merchantThenGateway();
  const results = await verifyAllResponseLabelsAsync(dual, {
    keyResolvers: {
      merchant: async (keyId: string) =>
        keyId === "merchant-key-1" ? merchant.publicKey : undefined,
      gateway: async (keyId: string) =>
        keyId === "gateway-key-7" ? gatewaySecret : undefined,
    },
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("global async keyResolver is the fallback for unmapped labels", async () => {
  const dual = merchantThenGateway();
  const results = await verifyAllResponseLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => merchant.publicKey,
    },
    keyResolver: async (keyId: string) =>
      keyId === "gateway-key-7" ? gatewaySecret : undefined,
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("per-label throw is contained to that label; the other label still verifies", async () => {
  const dual = merchantThenGateway();
  const results = await verifyAllResponseLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => {
        throw new Error("merchant vault down SECRET-DO-NOT-LEAK");
      },
      gateway: async () => gatewaySecret,
    },
    now: NOW,
  });
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "VERIFICATION_ERROR");
  assert.doesNotMatch(results[0]?.reason ?? "", /SECRET-DO-NOT-LEAK/);
  assert.equal(results[1]?.ok, true);
});

test("requiredLabels: missing label is a synthetic failure; unsigned response returns []", async () => {
  const dual = merchantThenGateway();
  const results = await verifyAllResponseLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => merchant.publicKey,
      gateway: async () => gatewaySecret,
    },
    now: NOW,
    requiredLabels: ["merchant", "gateway", "auditor"],
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok, r.code]),
    [
      ["merchant", true, undefined],
      ["gateway", true, undefined],
      ["auditor", false, "MISSING_REQUIRED_LABEL"],
    ],
  );
  const unsigned = await verifyAllResponseLabelsAsync(response(), {
    keyResolver: async () => undefined,
    now: NOW,
  });
  assert.deepEqual(unsigned, []);
});

test("sync/async parity for the multi-label path, including a tampered label", async () => {
  const dual = merchantThenGateway();
  const syncResults = verifyAllResponseLabels(dual, {
    keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
    now: NOW,
  });
  const asyncResults = await verifyAllResponseLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => merchant.publicKey,
      gateway: async () => gatewaySecret,
    },
    now: NOW,
  });
  assert.deepEqual(
    asyncResults.map((r) => ({ ok: r.ok, code: r.code, label: r.label })),
    syncResults.map((r) => ({ ok: r.ok, code: r.code, label: r.label })),
  );
  // Flip the gateway label's signature bytes: merchant still verifies.
  const tampered = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: (dual.headers["signature"] as string).replace(
        /gateway=:[A-Za-z0-9+/=]+:/,
        (m) => {
          const bytes = Buffer.from(
            m.slice("gateway=:".length, -1),
            "base64",
          );
          bytes[bytes.length - 1] ^= 0xff;
          return `gateway=:${bytes.toString("base64")}:`;
        },
      ),
    },
  };
  const tamperedResults = await verifyAllResponseLabelsAsync(tampered, {
    keyResolvers: {
      merchant: async () => merchant.publicKey,
      gateway: async () => gatewaySecret,
    },
    now: NOW,
  });
  assert.equal(tamperedResults[0]?.ok, true);
  assert.equal(tamperedResults[1]?.ok, false);
  assert.equal(tamperedResults[1]?.code, "SIGNATURE_MISMATCH");
});

test("verifyAllResponseLabelsOrThrowAsync returns all results on success and throws the first failure", async () => {
  const dual = merchantThenGateway();
  const results = await verifyAllResponseLabelsOrThrowAsync(dual, {
    keyResolvers: {
      merchant: async () => merchant.publicKey,
      gateway: async () => gatewaySecret,
    },
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.ok));
  const tampered = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: (dual.headers["signature"] as string).replace(
        /gateway=:[A-Za-z0-9+/=]+:/,
        (m) => {
          const bytes = Buffer.from(
            m.slice("gateway=:".length, -1),
            "base64",
          );
          bytes[bytes.length - 1] ^= 0xff;
          return `gateway=:${bytes.toString("base64")}:`;
        },
      ),
    },
  };
  await assert.rejects(
    () =>
      verifyAllResponseLabelsOrThrowAsync(tampered, {
        keyResolvers: {
          merchant: async () => merchant.publicKey,
          gateway: async () => gatewaySecret,
        },
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      const err = e as { code: string; label?: string; verifyResults?: unknown[] };
      assert.equal(err.code, "SIGNATURE_MISMATCH");
      assert.equal(err.label, "gateway");
      assert.equal((err.verifyResults as unknown[]).length, 2);
      return true;
    },
  );
});

test("multi-label configuration errors name verifyAllResponseLabelsAsync", async () => {
  const dual = merchantThenGateway();
  await assert.rejects(
    () =>
      verifyAllResponseLabelsAsync(dual, {
        keyResolvers: {
          merchant: async () => merchant.publicKey,
        },
        now: NOW,
        bogus: true,
      } as never),
    /invalid verifyAllResponseLabelsAsync options: unknown option "bogus"/,
  );
  await assert.rejects(
    () =>
      verifyAllResponseLabelsAsync(
        { ...dual, status: 600 },
        {
          keyResolvers: {
            merchant: async () => merchant.publicKey,
          },
          now: NOW,
        },
      ),
    /verifyAllResponseLabelsAsync: "status" must be an integer HTTP status code/,
  );
});
