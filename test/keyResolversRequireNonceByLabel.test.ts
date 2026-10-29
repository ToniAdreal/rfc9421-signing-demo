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

// Backlog #715: `keyResolvers` (per-label keystore resolution) and
// `requireNonceByLabel` (per-label nonce-presence requirement) have
// each been tested on their own, but never in combination. This file
// pins the orthogonal semantics for a dual-label gateway: the
// merchant label resolves through its own rotating keystore AND must
// carry a nonce, while the gateway label verifies against a static
// key and carries no nonce requirement. A failure in one dimension
// must never mask, or be mistaken for, a failure in the other, and a
// failure on one label must never block the other label's verdict.
//
// Check order, read from `src/verify.ts` (not assumed): key
// resolution happens after the header parses cleanly but before any
// crypto runs, while the nonce-presence check runs after the
// cryptographic check and before the replay-cache query. So:
// - a signature that is both unresolvable and nonce-less reports
//   `KEY_RESOLUTION_FAILED`, not `MISSING_NONCE`;
// - a forged (bad-signature) nonce-less signature reports
//   `SIGNATURE_MISMATCH`, not `MISSING_NONCE`.
// `keyResolvers` and `requireNonceByLabel` are not in the same
// mutual-exclusion group (key selection vs. nonce policy), so this
// combination must not throw a configuration error — but putting the
// same label in both `keys` and `keyResolvers` still must.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const EXPIRES = CREATED + 600;

const merchantOld = generateEd25519KeyPair();
const merchantCurrent = generateEd25519KeyPair();
const merchantRetired = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

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

function signMerchant(
  pair: ReturnType<typeof generateEd25519KeyPair>,
  keyId: string,
  nonce?: string,
) {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: EXPIRES,
    ...(nonce === undefined ? {} : { nonce }),
  });
}

function signGateway(nonce?: string) {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    expires: EXPIRES,
    ...(nonce === undefined ? {} : { nonce }),
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

// Merchant: rotating keystore (old + current keyids) + nonce
// required. Gateway: static key + no nonce requirement (no map
// entry, no global flag). The two key-selection mechanisms coexist
// because no label appears in both `keys` and `keyResolvers`.
function dualOpts(
  overrides: Partial<Parameters<typeof verifyAllLabels>[1]> = {},
) {
  return {
    now: NOW,
    keys: { gateway: gateway.publicKey },
    keyResolvers: {
      merchant: store([
        ["merchant-key-1", merchantOld.publicKey],
        ["merchant-key-2", merchantCurrent.publicKey],
      ]),
    },
    requireNonceByLabel: { merchant: true },
    ...overrides,
  };
}

test("keyResolvers x requireNonceByLabel: nonce-carrying merchant through the rotating keystore passes, nonce-less gateway passes", () => {
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2", "merchant-nonce-1"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, dualOpts());
  assert.equal(results.length, 2);
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-2");
  assert.equal(by["merchant"].nonce, "merchant-nonce-1");
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].keyId, "gateway-key-1");
  assert.equal(by["gateway"].nonce, undefined);
});

test("keyResolvers x requireNonceByLabel: merchant signed with the old rotation key still passes when it carries a nonce", () => {
  // Rotation is about the keyid→key lookup, not about which keyid is
  // "current": either store entry verifies, provided the nonce rule
  // for the label is also satisfied.
  const dual = mergeSignatures(
    signMerchant(merchantOld, "merchant-key-1", "merchant-nonce-2"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].keyId, "merchant-key-1");
  assert.equal(by["merchant"].nonce, "merchant-nonce-2");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireNonceByLabel: nonce-less merchant fails MISSING_NONCE, gateway unaffected", () => {
  // The merchant key resolves fine through its keystore — it is the
  // nonce rule, not resolution, that rejects the label.
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_NONCE");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireNonceByLabel: merchant key rotated out fails KEY_RESOLUTION_FAILED, gateway unaffected", () => {
  // The signature is cryptographically valid under the retired key
  // and carries a nonce, so neither the crypto check nor the nonce
  // rule is what rejects it — the keystore lookup is.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-0", "merchant-nonce-3"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireNonceByLabel: unresolvable AND nonce-less merchant reports KEY_RESOLUTION_FAILED, not MISSING_NONCE", () => {
  // Resolution precedes the nonce check: the key failure must not be
  // masked by the nonce failure, even though both apply.
  const dual = mergeSignatures(
    signMerchant(merchantRetired, "merchant-key-0"),
    signGateway(),
  );
  const results = verifyAllLabels(dual, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "KEY_RESOLUTION_FAILED");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireNonceByLabel: forged nonce-less merchant reports SIGNATURE_MISMATCH, not MISSING_NONCE", () => {
  // The cryptographic check precedes the nonce check: a forgery is
  // reported as a forgery even when the nonce rule would also fail.
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2"),
    signGateway(),
  );
  const forged: SignedHttpRequest = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: dual.headers["signature"]!.replace(
        "merchant=:",
        "merchant=:AAAA",
      ),
    },
  };
  const results = verifyAllLabels(forged, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("keyResolvers x requireNonceByLabel: a nonce on the gateway is tolerated, not rejected, when it is not required", () => {
  // "Not required" is not "forbidden": a gateway signature that
  // happens to carry a nonce still verifies, and the nonce is echoed.
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2", "merchant-nonce-4"),
    signGateway("gateway-nonce-1"),
  );
  const results = verifyAllLabels(dual, dualOpts());
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["gateway"].ok, true);
  assert.equal(by["gateway"].nonce, "gateway-nonce-1");
});

test("keyResolvers x requireNonceByLabel: a non-function resolver entry throws a configuration error naming the label", () => {
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2", "merchant-nonce-5"),
    signGateway(),
  );
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: NOW,
        keys: { gateway: gateway.publicKey },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        keyResolvers: { merchant: "not-a-function" as any },
        requireNonceByLabel: { merchant: true },
      }),
    /`keyResolvers\["merchant"\]` must be a function, got string/,
  );
});

test("keyResolvers x requireNonceByLabel: a non-boolean nonce-map entry throws a configuration error naming the label", () => {
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2", "merchant-nonce-6"),
    signGateway(),
  );
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: NOW,
        keys: { gateway: gateway.publicKey },
        keyResolvers: {
          merchant: store([["merchant-key-2", merchantCurrent.publicKey]]),
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        requireNonceByLabel: { merchant: "true" as any },
      }),
    /requireNonceByLabel\["merchant"\].*boolean/,
  );
});

test("keyResolvers x requireNonceByLabel: the same label in both keys and keyResolvers still throws the mutual-exclusion error", () => {
  const dual = mergeSignatures(
    signMerchant(merchantCurrent, "merchant-key-2", "merchant-nonce-7"),
    signGateway(),
  );
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: NOW,
        keys: {
          merchant: merchantCurrent.publicKey,
          gateway: gateway.publicKey,
        },
        keyResolvers: {
          merchant: store([["merchant-key-2", merchantCurrent.publicKey]]),
        },
        requireNonceByLabel: { merchant: true },
      }),
    /mutually exclusive with `keyResolver`\/`keyResolvers`/,
  );
});
