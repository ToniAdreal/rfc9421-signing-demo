import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  parseSignatureInput,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

/** A validly-signed ed25519 GET request plus its public key. */
function signedGet() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      nonce: "n-1",
    },
  );
  return { signed, publicKey };
}

/** Replace the signature-input header of a signed request, keeping the rest. */
function withSignatureInput(
  signed: SignedHttpRequest,
  value: string,
): SignedHttpRequest {
  return {
    ...signed,
    headers: { ...signed.headers, "signature-input": value },
  };
}

test("duplicate created (same value, otherwise valid signature) is rejected before crypto", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    `${signed.headers["signature-input"]};created=${CREATED}`,
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  // Not SIGNATURE_MISMATCH: the ambiguous parameter is rejected at parse time.
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate signature-input parameter ";created"/);
});

test("duplicate keyid is rejected with MALFORMED_SIGNATURE_INPUT", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    `${signed.headers["signature-input"]};keyid="k"`,
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate signature-input parameter ";keyid"/);
});

test("duplicate nonce is rejected with MALFORMED_SIGNATURE_INPUT", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    `${signed.headers["signature-input"]};nonce="n-1"`,
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
});

test("case variants are deduplicated after normalization (Created vs created)", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    signed.headers["signature-input"].replace(
      ";created=",
      `;Created=${CREATED};created=`,
    ),
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate signature-input parameter ";created"/);
});

test("parseSignatureInput throws the duplicate error directly", () => {
  assert.throws(
    () =>
      parseSignatureInput(
        `sig1=("@method");created=${CREATED};created=${CREATED + 1}`,
        "sig1",
      ),
    /duplicate signature-input parameter ";created"/,
  );
  assert.throws(
    () => parseSignatureInput(`sig1=("@method");foo="a";foo="b"`, "sig1"),
    /duplicate signature-input parameter ";foo"/,
  );
});

test("RFC 9421 B.2.5 published vector still parses (no duplicate, no regression)", () => {
  const B25 =
    `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`;
  const parsed = parseSignatureInput(B25, "sig-b25");
  assert.equal(parsed.label, "sig-b25");
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-shared-secret");
});

test("verifyAllLabels: duplicate param in one label fails that label only, never throws", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const body = JSON.stringify({ amount: 250, currency: "USD" });
  const merchantSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
  // Appending lands inside the gateway label's parameter segment (last in
  // the header), so only the gateway label becomes ambiguous.
  const tampered = withSignatureInput(
    dual,
    `${dual.headers["signature-input"]};created=${CREATED}`,
  );
  const results = verifyAllLabels(tampered, {
    key: publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true, "merchant label unaffected");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MALFORMED_SIGNATURE_INPUT");
  assert.equal(results[1].label, "gateway");
});
