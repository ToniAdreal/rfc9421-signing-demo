import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  listSignatureLabels,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function paymentRequest(body?: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
}

/**
 * The canonical multi-party flow: the merchant signs the payment request
 * with its ed25519 key, then the payment gateway appends its own hmac
 * signature. Both labels verify independently.
 */
function merchantThenGateway(): {
  dual: SignedHttpRequest;
  merchantPublic: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  gatewaySecret: ReturnType<typeof secretKey>;
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const body = JSON.stringify({ amount: 250, currency: "USD" });
  const merchantSigned = signRequest(paymentRequest(body), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
  return { dual, merchantPublic: publicKey, gatewaySecret };
}

test("merchant (ed25519) + gateway (hmac) double label both verify", () => {
  const { dual, merchantPublic, gatewaySecret } = merchantThenGateway();
  const results = verifyAllLabels(dual, {
    key: merchantPublic,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "hmac-sha256");
  assert.equal(results[1].keyId, "gateway-key-7");
});

test("a tampered gateway signature does not affect the merchant label", () => {
  const { dual, merchantPublic, gatewaySecret } = merchantThenGateway();
  const tampered: SignedHttpRequest = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: dual.headers["signature"].replace(
        /((?:^|,)\s*gateway\s*=:)([A-Za-z0-9+/])/,
        (_m, prefix: string, p1: string) =>
          `${prefix}${p1 === "A" ? "B" : "A"}`,
      ),
    },
  };
  const results = verifyAllLabels(tampered, {
    key: merchantPublic,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("appending to an unsigned request throws a clear error", () => {
  assert.throws(
    () =>
      addSignature(paymentRequest() as SignedHttpRequest, {
        keyId: "k",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
        label: "second",
      }),
    /addSignature: the request has no signature-input\/signature headers/,
  );
});

test("a duplicate label is rejected", () => {
  const signed = signRequest(paymentRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: generateEd25519KeyPair().privateKey,
    created: CREATED,
  }); // default label "sig1"
  assert.throws(
    () =>
      addSignature(signed, {
        keyId: "k2",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
      }),
    /addSignature: label "sig1" is already present/,
  );
});

test("an empty label is rejected", () => {
  const { dual } = merchantThenGateway();
  assert.throws(
    () =>
      addSignature(dual, {
        keyId: "k",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
        label: "",
      }),
    /addSignature: "label" must be a non-empty string/,
  );
});

test("the input request is not mutated", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(JSON.stringify({ a: 1 })), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "first",
  });
  const before = JSON.stringify(signed.headers);
  const dual = addSignature(signed, {
    keyId: "k2",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "second",
  });
  assert.equal(JSON.stringify(signed.headers), before);
  assert.notEqual(dual.headers, signed.headers);
  assert.equal(dual.body, signed.body);
});

test("wire shape: labels in order, content-digest stable", () => {
  const body = JSON.stringify({ amount: 250, currency: "USD" });
  const merchantSigned = signRequest(paymentRequest(body), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: generateEd25519KeyPair().privateKey,
    created: CREATED,
    label: "merchant",
  });
  const digestBefore = merchantSigned.headers["content-digest"];
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: secretKey("gateway-shared-secret-32-bytes-0!"),
    created: CREATED,
    label: "gateway",
  });
  assert.deepEqual(listSignatureLabels(dual.headers["signature-input"]), [
    "merchant",
    "gateway",
  ]);
  assert.equal(dual.headers["content-digest"], digestBefore);
});

test("single-label signing path is unchanged", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(JSON.stringify({ x: 1 })), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "only",
  });
  const result = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    expectedKeyId: "k",
    label: "only",
  });
  assert.equal(result.ok, true);
  assert.equal(result.label, "only");
});
