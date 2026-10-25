import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  ReplayCache,
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequestOrThrow,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signRequest` always emits a `nonce` when given one; a real third-party
// signer may omit it. The hand-built helpers below mint such signatures
// with the public signature-base primitives, so the wire shape matches
// what a foreign implementation would send.
const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@path"];

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
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

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

function signedWithout(
  params: SignatureParams,
  label: string,
  pair: KeyPair,
): SignedHttpRequest {
  const req: RequestLike = baseRequest();
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    method: req.method,
    url: req.url,
    headers: {
      "signature-input": signatureInputValue(label, COVERED, params),
      signature: `${label}=:${sig.toString("base64")}:`,
    },
  };
}

function signedWithNonce(
  label: string,
  pair: KeyPair,
  nonce: string,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: CREATED + 600,
    nonce,
  });
}

function signedDated(label: string, pair: KeyPair): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: CREATED + 600,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// ---------- requireNonceByLabel ----------

test("requireNonceByLabel: merchant required, gateway not — independent per-label verdicts", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithNonce("gateway", gateway, "gateway-nonce-1"),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].nonce, "gateway-nonce-1");
});

test("requireNonceByLabel: a mapped true overrides a global false", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonce: false,
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("requireNonceByLabel: a mapped false relaxes a global true for that label only", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonce: true,
    requireNonceByLabel: { merchant: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_NONCE");
});

test("requireNonceByLabel: an empty-string nonce counts as missing for the mapped label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600, nonce: "" },
      "merchant",
      merchant,
    ),
    signedWithNonce("gateway", gateway, "gateway-nonce-1"),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("requireNonceByLabel: a mapped-true label carrying a nonce passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithNonce("merchant", merchant, "merchant-nonce-1"),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].nonce, "merchant-nonce-1");
  assert.equal(by["gateway"].ok, true);
});

// ---------- fallback to the global flag ----------

test("map absent entirely: the global flag decides every label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonce: true,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].code, "MISSING_NONCE");
});

// ---------- validation ----------

test("requireNonceByLabel: illegal values and malformed maps throw a configuration error naming the label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedDated("gateway", gateway),
  );
  for (const v of ["true", 1, null, undefined]) {
    assert.throws(
      () =>
        verifyAllLabels(merged, {
          now: CREATED,
          keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          requireNonceByLabel: { merchant: v as any },
        }),
      (e: unknown) =>
        e instanceof Error &&
        /requireNonceByLabel\["merchant"\].*boolean/.test(e.message),
      `expected a configuration error for ${String(v)}`,
    );
  }
  for (const v of [null, ["true"], "true"]) {
    assert.throws(
      () =>
        verifyAllLabels(merged, {
          now: CREATED,
          keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          requireNonceByLabel: v as any,
        }),
      /requireNonceByLabel.*label→boolean object/,
      `expected a configuration error for ${String(v)}`,
    );
  }
});

// ---------- check order and OrThrow stability ----------

test("requireNonceByLabel: a forgery is reported as SIGNATURE_MISMATCH, not MISSING_NONCE", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithNonce("gateway", gateway, "gateway-nonce-1"),
  );
  const forged: SignedHttpRequest = {
    ...merged,
    headers: {
      ...merged.headers,
      signature: merged.headers["signature"]!.replace("merchant=:", "merchant=:AAAA"),
    },
  };
  const results = verifyAllLabels(forged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("verifyRequestOrThrow: the global requirement still throws VerifyError with a stable code", () => {
  const merchant = generateEd25519KeyPair();
  const undated = signedWithout(
    { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
    "sig1",
    merchant,
  );
  assert.throws(
    () =>
      verifyRequestOrThrow(undated, {
        key: merchant.publicKey,
        now: CREATED,
        requireNonce: true,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_NONCE" && e instanceof Error,
  );
});

// ---------- map entries for absent labels ----------

test("map entries for labels absent from the request are ignored", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireNonceByLabel: { unknown: true },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

// ---------- replay-cache orthogonality (cf. #532) ----------

test("existence and replay stay separate: a MISSING_NONCE label never reaches the shared cache", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const cache = new ReplayCache({ now: () => CREATED });
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithNonce("gateway", gateway, "gateway-nonce-1"),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    replayCache: cache,
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
  // Only the gateway nonce was recorded: the missing-nonce failure
  // happened before the cache query, so it polluted nothing.
  assert.equal(cache.stats().size, 1);
  assert.equal(cache.stats().misses, 1);
  assert.equal(cache.stats().hits, 0);
});

test("existence and replay stay separate: a shared nonce still replays on the second label even when both pass the existence check", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const cache = new ReplayCache({ now: () => CREATED });
  const merged = mergeSignatures(
    signedWithNonce("merchant", merchant, "shared-nonce-1"),
    signedWithNonce("gateway", gateway, "shared-nonce-1"),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    replayCache: cache,
    requireNonceByLabel: { merchant: true, gateway: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  // The existence requirement passed for the gateway label too (it
  // carries a nonce); the shared store's one-nonce-per-label contract
  // from #532 is what rejects it, not the existence map.
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "NONCE_REPLAY");
});
