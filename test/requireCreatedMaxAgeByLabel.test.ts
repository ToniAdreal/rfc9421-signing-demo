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
// `signRequest` always emits `created`; a real third-party signer may
// omit it. The hand-built helpers below mint such signatures with the
// public signature-base primitives, so the wire shape matches what a
// foreign implementation would send.
//
// This file pins one combination the per-label freshness tests do not:
// the merchant label carries BOTH time checks
// (`requireCreatedByLabel` and a narrow `maxSignatureAgeSecByLabel`
// window) while the gateway label carries NEITHER. The existing
// `test/requireCreatedExpiresByLabel.test.ts` pairs created with
// expires; this file pairs created with the age window, the other
// second time dimension on the same verification chain. The two
// checks interact in one way worth pinning: an undated signature
// bypasses the age check entirely (there is nothing to compare), so
// a merchant signature missing `created` under a narrow window must
// still report `MISSING_CREATED`, never `SIGNATURE_TOO_OLD` — and a
// signature cannot violate both dimensions at once, because the age
// check only applies to dated signatures.
const CREATED = 1700000000;
const NOW = CREATED + 3600; // both signatures are exactly 1 hour old
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

function signedDated(
  label: string,
  pair: KeyPair,
  created: number,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// The backlog fixture: merchant requireCreated + narrow window,
// gateway neither requirement.
const COMBINED = {
  requireCreatedByLabel: { merchant: true },
  maxSignatureAgeSecByLabel: { merchant: 300 },
};

function verifyCombined(merged: SignedHttpRequest, keys: Record<string, KeyPair["publicKey"]>) {
  return verifyAllLabels(merged, {
    now: NOW,
    keys,
    ...COMBINED,
  });
}

test("both time checks on merchant, neither on gateway: merchant missing created fails, gateway missing created passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const by = byLabel(
    verifyCombined(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // Same missing field, unmapped label: no requirement and no window,
  // so it passes.
  assert.equal(by["gateway"].ok, true);
});

test("both time checks on merchant, neither on gateway: stale merchant fails, same-age gateway passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant, CREATED),
    signedDated("gateway", gateway, CREATED),
  );
  const by = byLabel(
    verifyCombined(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  // 3600s old against a 300s window.
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(by["gateway"].ok, true);
});

test("both time checks on merchant: undated merchant reports MISSING_CREATED first, never SIGNATURE_TOO_OLD", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  // The merchant carries an `expires` so that `created` is the only
  // missing dimension; the narrow window is still configured. The
  // age check bypasses undated signatures and the presence check
  // runs first, so the reported code is MISSING_CREATED — the window
  // does not mask it as SIGNATURE_TOO_OLD.
  const merged = mergeSignatures(
    signedWithout(
      { keyid: "merchant", alg: "ed25519", expires: NOW + 600 },
      "merchant",
      merchant,
    ),
    signedWithout(
      { keyid: "gateway", alg: "ed25519", expires: NOW + 600 },
      "gateway",
      gateway,
    ),
  );
  const by = byLabel(
    verifyCombined(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  assert.equal(by["gateway"].ok, true);
});

test("both time checks on merchant, neither on gateway: fresh merchant and undated gateway both pass", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedDated("merchant", merchant, NOW - 60),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const by = byLabel(
    verifyCombined(merged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
});

test("both time checks on merchant: a forged merchant signature missing created reports SIGNATURE_MISMATCH, not a policy code", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signedWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedDated("gateway", gateway, NOW - 60),
  );
  const forged: SignedHttpRequest = {
    ...merged,
    headers: {
      ...merged.headers,
      signature: merged.headers["signature"]!.replace("merchant=:", "merchant=:AAAA"),
    },
  };
  const by = byLabel(
    verifyCombined(forged, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  // The cryptographic check runs before the presence checks, so a
  // forgery is a signature failure even when it also violates the
  // created requirement.
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
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requireCreated: true,
    maxSignatureAgeSec: 300,
    requireCreatedByLabel: { merchant: true, gateway: false },
    maxSignatureAgeSecByLabel: { merchant: 300 },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // The mapped-false entry wins over the global true for the created
  // requirement; the age check bypasses the undated gateway signature
  // regardless of the global window.
  assert.equal(by["gateway"].ok, true);
});

test("both time checks on merchant: window boundary is inclusive under the combination", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  // Exactly 300s old against a 300s window: the age check is
  // `now - created > maxAge`, so the boundary passes.
  const atBoundary = mergeSignatures(
    signedDated("merchant", merchant, NOW - 300),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const byBoundary = byLabel(
    verifyCombined(atBoundary, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(byBoundary["merchant"].ok, true);
  assert.equal(byBoundary["gateway"].ok, true);
  // One second past the window fails with the age code, not a
  // presence code: the signature is dated, so requireCreated is met.
  const pastBoundary = mergeSignatures(
    signedDated("merchant", merchant, NOW - 301),
    signedWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const byPast = byLabel(
    verifyCombined(pastBoundary, {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    }),
  );
  assert.equal(byPast["merchant"].ok, false);
  assert.equal(byPast["merchant"].code, "SIGNATURE_TOO_OLD");
  assert.equal(byPast["gateway"].ok, true);
});
