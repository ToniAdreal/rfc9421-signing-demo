import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signRequest` always emits `created` (and `expires` when given it); a
// real third-party signer may omit either. The hand-built helpers below
// mint such signatures with the public signature-base primitives, so the
// wire shape matches what a foreign implementation would send.
//
// This file pins one combination the per-label freshness tests do not:
// the merchant label carries BOTH requirements
// (`requireCreatedByLabel` and `requireExpiresByLabel`) while the
// gateway label carries NEITHER. The existing
// `test/requireFreshnessByLabel.test.ts` pairs one requirement per label
// (merchant created-only, gateway expires-only); it never asserts that a
// label with both requirements fails on either missing field while an
// unmapped sibling with the same missing fields still passes.
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

// The backlog fixture: merchant both-required, gateway neither-required.
const BOTH_REQUIRED = {
  requireCreatedByLabel: { merchant: true },
  requireExpiresByLabel: { merchant: true },
};

function verifyBothRequired(merged: SignedHttpRequest, keys: Record<string, KeyPair["publicKey"]>) {
  return verifyAllLabels(merged, {
    now: CREATED,
    keys,
    ...BOTH_REQUIRED,
  });
}

test("both required on merchant, neither on gateway: merchant missing created fails, gateway missing created passes", () => {
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
  const by = byLabel(
    verifyBothRequired(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // Same missing field, unmapped label: no requirement, so it passes.
  assert.equal(by["gateway"].ok, true);
});

test("both required on merchant, neither on gateway: merchant missing expires fails, gateway missing expires passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED },
      "merchant",
      merchant,
    ),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", created: CREATED },
      "gateway",
      gateway,
    ),
  );
  const by = byLabel(
    verifyBothRequired(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_EXPIRES");
  assert.equal(by["gateway"].ok, true);
});

test("both required on merchant, neither on gateway: merchant missing both reports MISSING_CREATED first, gateway passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const by = byLabel(
    verifyBothRequired(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  // Same order as the global pair (see test/requireFreshness.test.ts):
  // the created check runs before the expires check, so a label
  // missing both reports MISSING_CREATED, not MISSING_EXPIRES.
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].ok, true);
});

test("both required on merchant, neither on gateway: fully dated merchant and fully undated gateway both pass", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const by = byLabel(
    verifyBothRequired(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
});

test("both required on merchant: a forged merchant signature missing both fields reports SIGNATURE_MISMATCH, not a presence code", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedDated("gateway", gateway),
  );
  const forged: SignedHttpRequest = {
    ...merged,
    headers: {
      ...merged.headers,
      signature: merged.headers["signature"]!.replace("merchant=:", "merchant=:AAAA"),
    },
  };
  const by = byLabel(
    verifyBothRequired(forged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  // The cryptographic check runs before the presence checks, so a
  // forgery is a signature failure even when it also violates both
  // requirements.
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("both dimensions together: global true plus mapped false on gateway leaves only the merchant checked", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const results = verifyAllLabels(merged, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreated: true,
    requireExpires: true,
    requireCreatedByLabel: { merchant: true, gateway: false },
    requireExpiresByLabel: { merchant: true, gateway: false },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // Both mapped-false entries win over the global true on both axes.
  assert.equal(by["gateway"].ok, true);
});
