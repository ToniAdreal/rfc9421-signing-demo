import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: one fixed ed25519 key, tight acceptance window (300s).
// Gateway: an HMAC secret rotation window (old + new), wide acceptance
// window (7200s). Both signatures are minted at the same instant, so the
// combination under test is "which key signed it" x "how old may it be"
// per label: rotation must not widen a label's age window, and a tight
// window must not break rotation.
const CREATED = 1700000000;
const IN_WINDOW = CREATED + 60; // 60s old: inside both windows
const OUT_OF_MERCHANT_WINDOW = CREATED + 3600; // 1h old: outside 300s, inside 7200s
const COVERED = ["@method", "@authority", "@path", "content-digest"];

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
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

const merchant = generateEd25519KeyPair();
const GATEWAY_OLD = secretKey(randomBytes(32));
const GATEWAY_NEW = secretKey(randomBytes(32));
const GATEWAY_RETIRED = secretKey(randomBytes(32));

function signMerchant(): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function signGateway(secret: ReturnType<typeof secretKey>): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function candidateKeysByLabel() {
  return {
    merchant: [merchant.publicKey],
    gateway: [GATEWAY_OLD, GATEWAY_NEW],
  };
}

function windows(merchantWindow: number, gatewayWindow: number) {
  return {
    maxSignatureAgeSecByLabel: { merchant: merchantWindow, gateway: gatewayWindow },
  };
}

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: new key + in-window signatures both pass", () => {
  const results = verifyAllLabels(mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW)), {
    now: IN_WINDOW,
    candidateKeysByLabel: candidateKeysByLabel(),
    ...windows(300, 7200),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: old key still passes inside the rotation window", () => {
  const results = verifyAllLabels(mergeSignatures(signMerchant(), signGateway(GATEWAY_OLD)), {
    now: IN_WINDOW,
    candidateKeysByLabel: candidateKeysByLabel(),
    ...windows(300, 7200),
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: merchant window rejects, gateway window passes the same-age signatures", () => {
  const results = verifyAllLabels(mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW)), {
    now: OUT_OF_MERCHANT_WINDOW,
    candidateKeysByLabel: candidateKeysByLabel(),
    ...windows(300, 7200),
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: out-of-window signatures are rejected whichever rotation key signed them", () => {
  for (const secret of [GATEWAY_OLD, GATEWAY_NEW]) {
    const results = verifyAllLabels(mergeSignatures(signMerchant(), signGateway(secret)), {
      now: OUT_OF_MERCHANT_WINDOW,
      candidateKeysByLabel: candidateKeysByLabel(),
      ...windows(300, 300),
    });
    assert.equal(results[0].ok, false);
    assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
    assert.equal(results[1].ok, false);
    assert.equal(results[1].code, "SIGNATURE_TOO_OLD");
  }
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: a retired key is rejected even inside the window", () => {
  const results = verifyAllLabels(
    mergeSignatures(signMerchant(), signGateway(GATEWAY_RETIRED)),
    {
      now: IN_WINDOW,
      candidateKeysByLabel: candidateKeysByLabel(),
      ...windows(300, 7200),
    },
  );
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  // No candidate matches, so the walk returns the last candidate's
  // mismatch — the age window never gets a chance to rescue it.
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: the gateway window does not leak into the merchant label", () => {
  // Swapped windows: the merchant's wide window passes its 1h-old
  // signature while the gateway's tight window rejects its own.
  const results = verifyAllLabels(mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW)), {
    now: OUT_OF_MERCHANT_WINDOW,
    candidateKeysByLabel: candidateKeysByLabel(),
    ...windows(7200, 300),
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_TOO_OLD");
});

test("candidateKeysByLabel x maxSignatureAgeSecByLabel: illegal combination shapes throw a configuration error naming the label", () => {
  const dual = mergeSignatures(signMerchant(), signGateway(GATEWAY_NEW));
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: IN_WINDOW,
        candidateKeysByLabel: { merchant: [] },
        ...windows(300, 7200),
      }),
    /verifyAllLabels: `candidateKeysByLabel\["merchant"\]` is invalid: .*non-empty array of KeyObjects/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: IN_WINDOW,
        candidateKeysByLabel: candidateKeysByLabel(),
        maxSignatureAgeSecByLabel: { merchant: -1, gateway: 7200 },
      }),
    /maxSignatureAgeSecByLabel\["merchant"\].*non-negative finite number/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        now: IN_WINDOW,
        keys: { merchant: merchant.publicKey, gateway: GATEWAY_NEW },
        candidateKeysByLabel: candidateKeysByLabel(),
      }),
    /mutually exclusive/,
  );
});
