import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #705: `keyResolvers` (per-label keystore resolution) and
// `requireTagByLabel` (per-label tag-presence requirement) have each
// been tested on their own, but never in combination. This file pins
// the orthogonal semantics for a dual-label gateway: each label
// resolves through its own keystore AND carries its own application
// tag, so a failure in one dimension must never mask, or be mistaken
// for, a failure in the other, and a failure on one label must never
// block the other label's verdict.
//
// Two tag mechanisms are in play and must not be conflated:
// - `requireTagByLabel` is a presence check: a tag-less signature
//   fails with `MISSING_TAG`.
// - `expectedTags` is a value pin: a signature carrying the wrong
//   tag fails with `TAG_MISMATCH`, and the pinning check runs before
//   the presence check, so a tag-less signature under a pin also
//   reports `TAG_MISMATCH` (the pin is the stricter claim).
// The pinned options below combine both; the presence-only case is
// covered with a separate options object that omits `expectedTags`.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const EXPIRES = CREATED + 600;
const MERCHANT_TAG = "payment-initiation-v1";
const GATEWAY_TAG = "settlement-webhook-v1";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();
const auditor = generateEd25519KeyPair();

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":250}',
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

function signMerchant(tag?: string) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    expires: EXPIRES,
    ...(tag === undefined ? {} : { tag }),
  });
}

function signGateway(tag?: string) {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    expires: EXPIRES,
    ...(tag === undefined ? {} : { tag }),
  });
}

function signAuditor() {
  // Tag-less legacy auditor shape: no tag, resolved only via the
  // global keyResolver fallback (see the fallback test below).
  return signRequest(baseRequest(), {
    label: "auditor",
    keyId: "auditor-key-1",
    alg: "ed25519",
    key: auditor.privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function store(
  entries: [string, KeyObject][],
): (id: string) => KeyObject | undefined {
  const map = new Map<string, KeyObject>(entries);
  return (id) => map.get(id);
}

// Per-label resolvers (separate keystores) + per-label tag presence
// + per-label tag pins. `keyResolvers` and `requireTagByLabel` are
// not in the same mutual-exclusion group (key selection vs. tag
// policy), so this combination must not throw a configuration error.
function pinnedOpts(
  overrides: Partial<Parameters<typeof verifyAllLabels>[1]> = {},
) {
  return {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
      gateway: store([["gateway-key-1", gateway.publicKey]]),
    },
    requireTagByLabel: { merchant: true, gateway: true },
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
    ...overrides,
  };
}

test("keyResolvers x requireTagByLabel: pinned dual passes, each label through its own keystore with its own tag", () => {
  const dual = mergeSignatures(
    signMerchant(MERCHANT_TAG),
    signGateway(GATEWAY_TAG),
  );
  const results = verifyAllLabels(dual, pinnedOpts());
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["merchant"].tag, MERCHANT_TAG);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
  assert.equal(by["gateway"].tag, GATEWAY_TAG);
});

test("keyResolvers x requireTagByLabel: merchant replaying the gateway tag fails TAG_MISMATCH, gateway unaffected", () => {
  // Cross-protocol replay: the merchant signature is cryptographically
  // valid and resolves through its own keystore, but it carries the
  // gateway's application tag — it must not verify as a merchant
  // payment-initiation signature.
  const dual = mergeSignatures(
    signMerchant(GATEWAY_TAG),
    signGateway(GATEWAY_TAG),
  );
  const results = verifyAllLabels(dual, pinnedOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "TAG_MISMATCH");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].tag, GATEWAY_TAG);
});

test("keyResolvers x requireTagByLabel: gateway replaying the merchant tag fails TAG_MISMATCH, merchant unaffected", () => {
  const dual = mergeSignatures(
    signMerchant(MERCHANT_TAG),
    signGateway(MERCHANT_TAG),
  );
  const results = verifyAllLabels(dual, pinnedOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "TAG_MISMATCH");
});

test("keyResolvers x requireTagByLabel (presence-only): tag-less merchant fails MISSING_TAG, gateway unaffected", () => {
  // Without an `expectedTags` pin, a tag-less signature reports the
  // presence failure, not a pin failure — the resolver dimension is
  // untouched: the merchant key still resolves, it is the tag rule
  // that rejects the label.
  const dual = mergeSignatures(signMerchant(), signGateway(GATEWAY_TAG));
  const results = verifyAllLabels(dual, {
    now: NOW,
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
      gateway: store([["gateway-key-1", gateway.publicKey]]),
    },
    requireTagByLabel: { merchant: true, gateway: true },
  });
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_TAG");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireTagByLabel: gateway key rotated out fails KEY_RESOLUTION_FAILED, merchant unaffected", () => {
  const dual = mergeSignatures(
    signMerchant(MERCHANT_TAG),
    signGateway(GATEWAY_TAG),
  );
  const results = verifyAllLabels(
    dual,
    pinnedOpts({
      keyResolvers: {
        merchant: store([["merchant-key-1", merchant.publicKey]]),
        gateway: store([]),
      },
    }),
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].tag, MERCHANT_TAG);
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "KEY_RESOLUTION_FAILED");
});

test("keyResolvers x requireTagByLabel: merchant key rotated out fails KEY_RESOLUTION_FAILED, gateway unaffected", () => {
  const dual = mergeSignatures(
    signMerchant(MERCHANT_TAG),
    signGateway(GATEWAY_TAG),
  );
  const results = verifyAllLabels(
    dual,
    pinnedOpts({
      keyResolvers: {
        merchant: store([]),
        gateway: store([["gateway-key-1", gateway.publicKey]]),
      },
    }),
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].tag, GATEWAY_TAG);
});

test("keyResolvers x requireTagByLabel: unmapped label falls back to the global keyResolver with no tag requirement", () => {
  // The auditor is in neither map: its key resolves only through the
  // global keyResolver, and with no `requireTagByLabel` entry (and no
  // global `requireTag`) its tag-less signature is not rejected.
  // The mapped labels keep their own resolver + tag rules.
  const triple = mergeSignatures(
    mergeSignatures(signMerchant(MERCHANT_TAG), signGateway(GATEWAY_TAG)),
    signAuditor(),
  );
  const results = verifyAllLabels(triple, {
    now: NOW,
    keyResolver: store([["auditor-key-1", auditor.publicKey]]),
    keyResolvers: {
      merchant: store([["merchant-key-1", merchant.publicKey]]),
      gateway: store([["gateway-key-1", gateway.publicKey]]),
    },
    requireTagByLabel: { merchant: true, gateway: true },
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  });
  assert.equal(results.length, 3);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["auditor"].ok, true);
  assert.equal(by["auditor"].keyId, "auditor-key-1");
  assert.equal(by["auditor"].tag, undefined);
});

test("keyResolvers x requireTagByLabel: unresolved key reports KEY_RESOLUTION_FAILED, not a tag error, when both fail", () => {
  // Key resolution precedes the tag checks: a merchant signature that
  // is both unresolvable and wrongly tagged must surface the
  // resolution failure — the tag dimension must not mask it.
  const dual = mergeSignatures(
    signMerchant(GATEWAY_TAG),
    signGateway(GATEWAY_TAG),
  );
  const results = verifyAllLabels(
    dual,
    pinnedOpts({
      keyResolvers: {
        merchant: store([]),
        gateway: store([["gateway-key-1", gateway.publicKey]]),
      },
    }),
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(by["gateway"].ok, true);
});
