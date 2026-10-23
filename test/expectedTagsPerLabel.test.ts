import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const MERCHANT_TAG = "payment-initiation-v1";
const GATEWAY_TAG = "settlement-webhook-v1";

function paymentRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250, currency: "USD" }),
  };
}

/**
 * The canonical multi-party flow (see addSignature.test.ts): the
 * merchant signs the payment initiation with its ed25519 key, then the
 * gateway appends its own hmac signature for the settlement webhook.
 * Each party binds its label to its own application protocol via `tag`.
 * Pass `merchantTag: null` to mint a tagless merchant label.
 */
function taggedDual(opts: { merchantTag?: string | null; gatewayTag?: string } = {}) {
  const { gatewayTag = GATEWAY_TAG } = opts;
  const merchantTag = opts.merchantTag === undefined ? MERCHANT_TAG : opts.merchantTag;
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signRequest(paymentRequest(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
    ...(merchantTag === null ? {} : { tag: merchantTag }),
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    ...(gatewayTag === undefined ? {} : { tag: gatewayTag }),
  });
  return { dual, merchantPublic: publicKey, gatewaySecret };
}

function verifyDual(
  dual: ReturnType<typeof taggedDual>["dual"],
  merchantPublic: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  gatewaySecret: ReturnType<typeof secretKey>,
  opts: Record<string, unknown> = {},
) {
  return verifyAllLabels(dual, {
    key: merchantPublic,
    now: NOW,
    keys: { gateway: gatewaySecret },
    ...opts,
  });
}

test("per-label tags: each label pinned to its own protocol passes", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].tag, MERCHANT_TAG);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].tag, GATEWAY_TAG);
});

test("one label tag mismatch fails with TAG_MISMATCH while the other passes", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual({
    gatewayTag: "other-protocol",
  });
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "TAG_MISMATCH");
  assert.equal(results[1].tag, "other-protocol");
});

test("label absent from the map falls back to the global expectedTag — match passes", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: { gateway: GATEWAY_TAG },
    expectedTag: MERCHANT_TAG,
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("label absent from the map falls back to the global — global mismatch fails", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual({
    merchantTag: "admin-api-v1",
  });
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: { gateway: GATEWAY_TAG },
    expectedTag: MERCHANT_TAG,
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "TAG_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("with no global expectedTag, an unlisted label is unchecked", () => {
  // The merchant label carries no tag at all; only the gateway label is
  // pinned, and the global expectedTag is unset.
  const { dual, merchantPublic, gatewaySecret } = taggedDual({
    merchantTag: null,
  });
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: { gateway: GATEWAY_TAG },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].tag, undefined);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("expectedTags as an array throws a configuration error", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  assert.throws(
    () =>
      verifyDual(dual, merchantPublic, gatewaySecret, {
        expectedTags: [] as unknown as Record<string, string>,
      }),
    /verifyAllLabels: `expectedTags` must be a label→tag object/,
  );
});

test("expectedTags as null throws a configuration error", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  assert.throws(
    () =>
      verifyDual(dual, merchantPublic, gatewaySecret, {
        expectedTags: null as unknown as Record<string, string>,
      }),
    /verifyAllLabels: `expectedTags` must be a label→tag object/,
  );
});

test("expectedTags with an empty-string value throws a configuration error", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  assert.throws(
    () =>
      verifyDual(dual, merchantPublic, gatewaySecret, {
        expectedTags: { merchant: "" },
      }),
    /verifyAllLabels: `expectedTags\["merchant"\]` must be a non-empty string/,
  );
});

test("expectedTags with a non-string value throws a configuration error", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  assert.throws(
    () =>
      verifyDual(dual, merchantPublic, gatewaySecret, {
        expectedTags: { merchant: 42 as unknown as string },
      }),
    /verifyAllLabels: `expectedTags\["merchant"\]` must be a non-empty string/,
  );
});

test("forgery reports SIGNATURE_MISMATCH, not TAG_MISMATCH (crypto checked first)", () => {
  const { dual, merchantPublic } = taggedDual();
  const wrongSecret = secretKey("wrong-gateway-secret-32-bytes-000000");
  const results = verifyAllLabels(dual, {
    key: merchantPublic,
    now: NOW,
    keys: { gateway: wrongSecret },
    expectedTags: { merchant: MERCHANT_TAG, gateway: GATEWAY_TAG },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyRequest single-label path behavior is unchanged", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
    tag: MERCHANT_TAG,
  });
  const ok = verifyRequest(signed, {
    key: publicKey,
    label: "merchant",
    now: NOW,
    expectedTag: MERCHANT_TAG,
  });
  assert.equal(ok.ok, true);
  assert.equal(ok.tag, MERCHANT_TAG);
  const bad = verifyRequest(signed, {
    key: publicKey,
    label: "merchant",
    now: NOW,
    expectedTag: "admin-api-v1",
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "TAG_MISMATCH");
});

test("map entries for labels not on the wire are ignored", () => {
  const { dual, merchantPublic, gatewaySecret } = taggedDual();
  const results = verifyDual(dual, merchantPublic, gatewaySecret, {
    expectedTags: {
      merchant: MERCHANT_TAG,
      gateway: GATEWAY_TAG,
      "not-a-label": "whatever-v1",
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});
