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

// Backlog #702: `expectedKeyIds` (per-label keyid pinning) and
// `requireNonceByLabel` (per-label nonce-existence) have each been
// tested on their own, but never in combination. This file pins the
// orthogonal semantics for a dual-label gateway: the merchant label
// is pinned to its keyid AND must carry a nonce, while the gateway
// label is pinned to its keyid but carries no nonce requirement.
//
// Combination legality was checked in `src/verify.ts` before writing
// this file, not assumed: neither map joins the
// `keys`/`keyResolver`/`candidateKeys` mutual-exclusion rules (the
// `requireNonceByLabel` doc says so explicitly, and the
// `expectedKeyIds` doc only describes the global fallback), and each
// map falls back to its global (`expectedKeyId` / `requireNonce`)
// for labels absent from the map. The nonce-less signatures below
// are hand-built with the public signature-base primitives, because
// `signRequest` always emits a `nonce` when given one — a real
// third-party signer may omit it, and that is exactly the shape the
// nonce requirement exists to catch.

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

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

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

function signMerchantWithNonce(nonce: string, keyId = "merchant-key-1") {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    expires: CREATED + 600,
    nonce,
  });
}

function signGatewayDated(keyId = "gateway-key-1") {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId,
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    expires: CREATED + 600,
  });
}

function signMerchantNonceless(keyId = "merchant-key-1") {
  return signedWithout(
    { keyid: keyId, alg: "ed25519", created: CREATED, expires: CREATED + 600 },
    "merchant",
    merchant,
  );
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// The combination under test: merchant pinned + nonce required,
// gateway pinned + no nonce requirement (no global requireNonce).
const OPTS = {
  now: CREATED,
  keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
  expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-1" },
  requireNonceByLabel: { merchant: true },
};

test("expectedKeyIds x requireNonceByLabel: pinned merchant with nonce and pinned nonce-less gateway both pass", () => {
  const dual = mergeSignatures(
    signMerchantWithNonce("merchant-nonce-1"),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(results.length, 2);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["merchant"].nonce, "merchant-nonce-1");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
});

test("expectedKeyIds x requireNonceByLabel: merchant nonce missing fails MISSING_NONCE while the pinned gateway still passes", () => {
  // The merchant keyid is exactly the pinned value, so the only
  // failing check is the nonce requirement — the pin does not
  // rescue a nonce-less signature, and the failure does not leak
  // into the gateway label.
  const dual = mergeSignatures(signMerchantNonceless(), signGatewayDated());
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireNonceByLabel: merchant keyid mismatch fails KEYID_MISMATCH while the gateway still passes", () => {
  // The merchant carries a nonce, so the only failing check is the
  // pin — the nonce requirement does not mask a key-confusion
  // failure, and the crypto walk passes (the signing key is the
  // merchant key), so the code is the keyid one, not
  // SIGNATURE_MISMATCH.
  const dual = mergeSignatures(
    signMerchantWithNonce("merchant-nonce-1", "merchant-key-WRONG"),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEYID_MISMATCH");
  assert.equal(by["merchant"].keyId, "merchant-key-WRONG");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireNonceByLabel: a merchant violating both dimensions reports the keyid code, not the nonce code", () => {
  // Check order inside `verifyRequest` is keyid pinning (before the
  // nonce-existence check): a signature that is both wrong-keyid
  // and nonce-less is rejected once, with the earlier check's code.
  // The fixture's created/expires window is valid at `now`, so no
  // window check intervenes between the two.
  const dual = mergeSignatures(
    signMerchantNonceless("merchant-key-WRONG"),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEYID_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireNonceByLabel: simultaneous per-label failures keep their own codes", () => {
  // Each label fails on a different dimension in the same call:
  // the merchant on nonce existence, the gateway on keyid pinning.
  // Neither failure blocks or rewrites the other label's verdict.
  const dual = mergeSignatures(
    signMerchantNonceless(),
    signGatewayDated("gateway-key-WRONG"),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEYID_MISMATCH");
});

test("expectedKeyIds x requireNonceByLabel: an empty-string nonce counts as missing even when the keyid is pinned correctly", () => {
  const dual = mergeSignatures(
    signedWithout(
      {
        keyid: "merchant-key-1",
        alg: "ed25519",
        created: CREATED,
        expires: CREATED + 600,
        nonce: "",
      },
      "merchant",
      merchant,
    ),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, OPTS);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("expectedKeyIds x requireNonceByLabel: a label absent from both maps falls back to the global pin with no nonce requirement", () => {
  // The gateway is in neither map here: it falls back to the global
  // `expectedKeyId` for pinning, and with no global `requireNonce`
  // set, its nonce-less signature is not held to the merchant's
  // requirement.
  const dual = mergeSignatures(
    signMerchantWithNonce("merchant-nonce-1"),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyId: "gateway-key-1",
    expectedKeyIds: { merchant: "merchant-key-1" },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
});

test("expectedKeyIds x requireNonceByLabel: a wrong global pin fails only the fallback label, not the per-label-pinned merchant", () => {
  const dual = mergeSignatures(
    signMerchantWithNonce("merchant-nonce-1"),
    signGatewayDated(),
  );
  const results = verifyAllLabels(dual, {
    now: CREATED,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyId: "gateway-key-WRONG",
    expectedKeyIds: { merchant: "merchant-key-1" },
    requireNonceByLabel: { merchant: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEYID_MISMATCH");
});
