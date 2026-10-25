import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
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
// `signRequest` always emits a `tag` when given one; a real third-party
// signer may omit it. The hand-built helpers below mint such signatures
// with the public signature-base primitives, so the wire shape matches
// what a foreign implementation would send.
const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@path"];
const TAG = "payment-webhook-v1";

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

function signedWithTag(
  label: string,
  pair: KeyPair,
  tag: string,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: CREATED + 600,
    tag,
  });
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

// ---------- requireTagByLabel ----------

test("requireTagByLabel: merchant required, gateway not — independent per-label verdicts", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithTag("gateway", gateway, TAG),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireTagByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].tag, TAG);
});

test("requireTagByLabel: a mapped true overrides a global false", () => {
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
    requireTag: false,
    requireTagByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
});

test("requireTagByLabel: a mapped false relaxes a global true for that label only", () => {
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
    requireTag: true,
    requireTagByLabel: { merchant: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_TAG");
});

test("requireTagByLabel: an empty-string tag counts as missing for the mapped label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600, tag: "" },
      "merchant",
      merchant,
    ),
    signedWithTag("gateway", gateway, TAG),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireTagByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
});

test("requireTagByLabel: a mapped-true label carrying a tag passes and echoes it", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithTag("merchant", merchant, TAG),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireTagByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].tag, TAG);
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
    requireTag: true,
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].code, "MISSING_TAG");
});

// ---------- validation ----------

test("requireTagByLabel: illegal values and malformed maps throw a configuration error naming the label", () => {
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
          requireTagByLabel: { merchant: v as any },
        }),
      (e: unknown) =>
        e instanceof Error &&
        /requireTagByLabel\["merchant"\].*boolean/.test(e.message),
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
          requireTagByLabel: v as any,
        }),
      /requireTagByLabel.*label→boolean object/,
      `expected a configuration error for ${String(v)}`,
    );
  }
});

// ---------- check order and OrThrow stability ----------

test("requireTagByLabel: a forgery is reported as SIGNATURE_MISMATCH, not MISSING_TAG", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithTag("gateway", gateway, TAG),
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
    requireTagByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("verifyRequestOrThrow: the global requirement still throws VerifyError with a stable code", () => {
  const merchant = generateEd25519KeyPair();
  const tagLess = signedWithout(
    { keyid: "merchant", alg: "ed25519", created: CREATED, expires: CREATED + 600 },
    "sig1",
    merchant,
  );
  assert.throws(
    () =>
      verifyRequestOrThrow(tagLess, {
        key: merchant.publicKey,
        now: CREATED,
        requireTag: true,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_TAG" && e instanceof Error,
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
    requireTagByLabel: { unknown: true },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

// ---------- orthogonality with requireNonceByLabel (#581) ----------

test("requireTagByLabel and requireNonceByLabel are orthogonal: each map drives only its own check", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  // Merchant: carries a nonce but no tag. Gateway: carries a tag but
  // no nonce. Each label must fail only its own map's check.
  const merged = mergeSignatures(
    signedWithNonce("merchant", merchant, "merchant-nonce-1"),
    signedWithTag("gateway", gateway, TAG),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireTagByLabel: { merchant: true },
    requireNonceByLabel: { gateway: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_NONCE");
});
