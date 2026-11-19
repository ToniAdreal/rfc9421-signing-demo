import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  createVerifiedHandler,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifiedFetch,
  verifyAllLabels,
  verifyAllResponseLabels,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type CreateVerifiedHandlerOptions,
  type SignOptions,
  type VerifiedFetchOptions,
  type VerifyAllOptions,
  type VerifyOptions,
  type VerifyResponseOptions,
} from "../src/index.js";

// Backlog #1251: every sign / verify entry point is fail-closed on
// unknown option keys. A misspelled freshness key (`maxSignatureAge`
// for `maxSignatureAgeSec`, `requireNonces` for `requireNonce`) used
// to be silently ignored while the caller believed the safety check
// was on — the same footgun the constructor unknown-option rejection
// guards against, except here the dropped option is a security check,
// not ordinary configuration. Each entry point scans its own options
// object first, with its own allowlist, and throws
// `invalid <caller> options: unknown option "<key>"`.
//
// The unknown keys below are cast through `unknown`: TypeScript
// already rejects them at compile time, so the runtime check is the
// backstop for JavaScript callers (and for JSON-shaped options built
// at runtime).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ amount: 100 });

const merchant = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function paymentRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {
      host: "api.example.com",
      "content-type": "application/json",
    },
    body: BODY,
  };
}

function settlementResponse() {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: BODY,
  };
}

const signOpts: SignOptions = {
  key: merchant.privateKey,
  alg: "ed25519",
  keyId: "test-key",
  created: CREATED,
  label: "sig1",
};

const verifyOpts: VerifyOptions = {
  key: merchant.publicKey,
  now: NOW,
};

test("signRequest rejects a misspelled freshness key", () => {
  const bad = {
    ...signOpts,
    maxSignatureAge: 300,
  } as unknown as SignOptions;
  assert.throws(
    () => signRequest(paymentRequest(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid signRequest options: unknown option "maxSignatureAge"',
  );
});

test("verifyRequest rejects a misspelled require flag", () => {
  const bad = {
    ...verifyOpts,
    requireNonces: true,
  } as unknown as VerifyOptions;
  assert.throws(
    () => verifyRequest(paymentRequest(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyRequest options: unknown option "requireNonces"',
  );
});

test("verifyAllLabels rejects a misspelled resolver key", () => {
  const bad = {
    ...verifyOpts,
    keyResolverr: () => merchant.publicKey,
  } as unknown as VerifyAllOptions;
  assert.throws(
    () => verifyAllLabels(paymentRequest(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyAllLabels options: unknown option "keyResolverr"',
  );
});

test("signResponse rejects an unknown key under its own name", () => {
  const bad = {
    ...signOpts,
    maxSignatureAge: 300,
  } as unknown as SignOptions;
  assert.throws(
    () => signResponse(settlementResponse(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid signResponse options: unknown option "maxSignatureAge"',
  );
});

test("verifyResponse rejects an unknown key under its own name", () => {
  const signed = signResponse(settlementResponse(), signOpts);
  const bad = {
    ...verifyOpts,
    requireNonces: true,
  } as unknown as VerifyResponseOptions;
  assert.throws(
    () => verifyResponse(signed, bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyResponse options: unknown option "requireNonces"',
  );
});

test("verifyAllResponseLabels rejects an unknown per-label key", () => {
  const signed = signResponse(settlementResponse(), signOpts);
  const bad = {
    ...verifyOpts,
    requiredLabel: ["sig1"],
  } as unknown as VerifyResponseOptions;
  assert.throws(
    () => verifyAllResponseLabels(signed, bad as never),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyAllResponseLabels options: unknown option "requiredLabel"',
  );
});

test("verifyAllLabels rejects an unknown per-label map key", () => {
  const bad = {
    ...verifyOpts,
    keysByLabel: { sig1: merchant.publicKey },
  } as unknown as VerifyAllOptions;
  assert.throws(
    () => verifyAllLabels(paymentRequest(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyAllLabels options: unknown option "keysByLabel"',
  );
});

test("a key set to undefined still counts as present", () => {
  const bad = {
    ...signOpts,
    maxSignatureAge: undefined,
  } as unknown as SignOptions;
  assert.throws(
    () => signRequest(paymentRequest(), bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid signRequest options: unknown option "maxSignatureAge"',
  );
});

test("every known key passes: full-option round trips", () => {
  const signed = signRequest(paymentRequest(), {
    ...signOpts,
    expires: CREATED + 300,
    nonce: "nonce-1251",
    tag: "payment-initiation-v1",
    coveredComponents: ["@method", "@authority", "@path", "content-digest"],
    contentDigestAlg: "sha-256",
  });
  const result = verifyRequest(signed, {
    ...verifyOpts,
    requireNonce: true,
    requireTag: true,
    expectedKeyId: "test-key",
    expectedTag: "payment-initiation-v1",
    maxSignatureAgeSec: 600,
    allowedAlgs: ["ed25519"],
    clockSkewToleranceSec: 60,
  });
  assert.equal(result.ok, true);
  assert.equal(result.nonce, "nonce-1251");
  assert.equal(result.tag, "payment-initiation-v1");

  // Multi-label: merchant ed25519 + gateway hmac, per-label keys and
  // requiredLabels all known keys, all pass.
  const dual = addSignature(signed, {
    key: gatewaySecret,
    alg: "hmac-sha256",
    keyId: "gw-1",
    created: CREATED,
    label: "gateway",
  });
  const results = verifyAllLabels(dual, {
    keys: { sig1: merchant.publicKey, gateway: gatewaySecret },
    requiredLabels: ["sig1", "gateway"],
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["sig1", true],
      ["gateway", true],
    ],
  );
});

test("verifyRequestOrThrow inherits the rejection", () => {
  const signed = signRequest(paymentRequest(), signOpts);
  const bad = {
    ...verifyOpts,
    maxSignatureAge: 300,
  } as unknown as VerifyOptions;
  assert.throws(
    () => verifyRequestOrThrow(signed, bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifyRequest options: unknown option "maxSignatureAge"',
  );
});

test("addSignature rejects an unknown key under its own name", () => {
  const signed = signRequest(paymentRequest(), signOpts);
  const bad = {
    key: gatewaySecret,
    alg: "hmac-sha256",
    label: "gateway",
    maxSignatureAge: 300,
  } as unknown as SignOptions;
  assert.throws(
    () => addSignature(signed, bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid addSignature options: unknown option "maxSignatureAge"',
  );
});

test("verifiedFetch rejects an unknown top-level key before any network", async () => {
  let fetchCalls = 0;
  const bad = {
    sign: signOpts,
    verify: verifyOpts,
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    },
    maxBodyByte: 1024,
  } as unknown as VerifiedFetchOptions;
  await assert.rejects(
    () => verifiedFetch("https://api.example.com/v1/payments", undefined, bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid verifiedFetch options: unknown option "maxBodyByte"',
  );
  assert.equal(fetchCalls, 0);
});

test("verifiedFetch rejects an unknown nested verify key before any network", async () => {
  let fetchCalls = 0;
  const bad = {
    sign: signOpts,
    verify: { ...verifyOpts, maxSignatureAge: 300 },
    fetchImpl: async () => {
      fetchCalls += 1;
      throw new Error("fetch must not run");
    },
  } as unknown as VerifiedFetchOptions;
  await assert.rejects(
    () => verifiedFetch("https://api.example.com/v1/payments", undefined, bad),
    (e: unknown) =>
      e instanceof Error &&
      /unknown option "maxSignatureAge"/.test(e.message),
  );
  assert.equal(fetchCalls, 0);
});

test("createVerifiedHandler rejects an unknown top-level key at creation", () => {
  const bad = {
    maxBodyByte: 1024,
  } as unknown as CreateVerifiedHandlerOptions;
  assert.throws(
    () =>
      createVerifiedHandler(verifyOpts, () => {}, bad),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'invalid createVerifiedHandler options: unknown option "maxBodyByte"',
  );
});

test("createVerifiedHandler rejects an unknown nested verify key at creation", () => {
  const bad = {
    ...verifyOpts,
    maxSignatureAge: 300,
  } as unknown as VerifyOptions;
  assert.throws(
    () =>
      createVerifiedHandler(bad, () => {}),
    (e: unknown) =>
      e instanceof Error &&
      /invalid verifyOpts: invalid verifyRequest options: unknown option "maxSignatureAge"/.test(
        e.message,
      ),
  );
});
