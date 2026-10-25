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
// `signRequest` always emits `created` and `expires` when given them; a
// real third-party signer may omit either. The hand-built helpers below
// mint such signatures with the public signature-base primitives, so the
// wire shape matches what a foreign implementation would send.
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

// ---------- requireCreatedByLabel ----------

test("requireCreatedByLabel: merchant required, gateway not — independent per-label verdicts", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreatedByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].ok, true);
});

test("requireCreatedByLabel: a mapped true overrides a global false", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreated: false,
    requireCreatedByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].ok, true);
});

// ---------- requireExpiresByLabel ----------

test("requireExpiresByLabel: gateway required, merchant not — independent per-label verdicts", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", created: CREATED },
      "gateway",
      gateway,
    ),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireExpiresByLabel: { gateway: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_EXPIRES");
});

// ---------- combined maps ----------

test("both maps: merchant missing created and gateway missing expires fail with their own codes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", created: CREATED },
      "gateway",
      gateway,
    ),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreatedByLabel: { merchant: true },
    requireExpiresByLabel: { gateway: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].code, "MISSING_EXPIRES");
});

test("both maps: a label missing both parameters reports MISSING_CREATED first, like the global order", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedDated("gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreatedByLabel: { merchant: true },
    requireExpiresByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].ok, true);
});

// ---------- fallback to the global flag ----------

test("map missing a label falls back to the global flag: mapped false passes, unmapped fails", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", expires: CREATED + 600 },
      "gateway",
      gateway,
    ),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreated: true,
    requireCreatedByLabel: { merchant: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_CREATED");
});

test("map missing a label falls back to the global flag for expires too", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", created: CREATED },
      "gateway",
      gateway,
    ),
  );
  // No map entry for either label: the global requireExpires decides.
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireExpires: true,
    requireExpiresByLabel: { merchant: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_EXPIRES");
});

// ---------- validation ----------

test("requireCreatedByLabel: illegal values and malformed maps throw a configuration error naming the label", () => {
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
          requireCreatedByLabel: { merchant: v as any },
        }),
      (e: unknown) =>
        e instanceof Error &&
        /requireCreatedByLabel\["merchant"\].*boolean/.test(e.message),
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
          requireCreatedByLabel: v as any,
        }),
      /requireCreatedByLabel.*label→boolean object/,
      `expected a configuration error for ${String(v)}`,
    );
  }
});

test("requireExpiresByLabel: illegal values and malformed maps throw a configuration error naming the label", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedDated("gateway", gateway),
  );
  for (const v of [0, "false", null]) {
    assert.throws(
      () =>
        verifyAllLabels(merged, {
          now: CREATED,
          keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          requireExpiresByLabel: { gateway: v as any },
        }),
      (e: unknown) =>
        e instanceof Error &&
        /requireExpiresByLabel\["gateway"\].*boolean/.test(e.message),
      `expected a configuration error for ${String(v)}`,
    );
  }
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: CREATED,
        keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        requireExpiresByLabel: ["true"] as any,
      }),
    /requireExpiresByLabel.*label→boolean object/,
  );
});

// ---------- check order and OrThrow stability ----------

test("requireCreatedByLabel: a forgery is reported as SIGNATURE_MISMATCH, not MISSING_CREATED", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedDated("gateway", gateway),
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
    requireCreatedByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("verifyRequestOrThrow: the global requirement still throws VerifyError with a stable code", () => {
  const merchant = generateEd25519KeyPair();
  const undated = signedWithout(
    { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
    "sig1",
    merchant,
  );
  assert.throws(
    () =>
      verifyRequestOrThrow(undated, {
        key: merchant.publicKey,
        now: CREATED,
        requireCreated: true,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_CREATED" && e instanceof Error,
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
    requireCreatedByLabel: { unknown: true },
    requireExpiresByLabel: { unknown: true },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});
