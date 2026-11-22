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
const EXPIRES = 1700003600;
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
      expires: EXPIRES,
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

/** Replace only the last occurrence of `needle` (the gateway label's copy). */
function replaceLast(s: string, needle: string, replacement: string): string {
  const idx = s.lastIndexOf(needle);
  assert.notEqual(idx, -1, `needle not found: ${needle}`);
  return s.slice(0, idx) + replacement + s.slice(idx + needle.length);
}

/**
 * Assert the tampered header is rejected at parse time, before any crypto
 * runs: the code must be MALFORMED_SIGNATURE_INPUT, never the
 * SIGNATURE_MISMATCH the tampered base would produce if parsing passed.
 */
function assertMalformed(
  signed: SignedHttpRequest,
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  tamperedInput: string,
  reasonPattern: RegExp,
): void {
  const res = verifyRequest(withSignatureInput(signed, tamperedInput), {
    key: publicKey,
    now: NOW,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", reasonPattern);
}

test("decimal created is rejected before crypto, not truncated", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;created=${CREATED}`,
      `;created=${CREATED}.5`,
    ),
    /malformed signature-input parameter ";created"/,
  );
});

test("decimal expires is rejected before crypto", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;expires=${EXPIRES}`,
      `;expires=${EXPIRES}.5`,
    ),
    /malformed signature-input parameter ";expires"/,
  );
});

test("non-numeric created is rejected, not dropped", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;created=${CREATED}`,
      ";created=abc",
    ),
    /malformed signature-input parameter ";created"/,
  );
});

test("quoted integer created is rejected, not parsed as a number", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;created=${CREATED}`,
      `;created="${CREATED}"`,
    ),
    /malformed signature-input parameter ";created"/,
  );
});

test("unquoted keyid is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(';keyid="k"', ";keyid=123"),
    /malformed signature-input parameter ";keyid"/,
  );
});

test("unquoted alg is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      ';alg="ed25519"',
      ";alg=123",
    ),
    /malformed signature-input parameter ";alg"/,
  );
});

test("unquoted nonce is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(';nonce="n-1"', ";nonce=123"),
    /malformed signature-input parameter ";nonce"/,
  );
});

test("unquoted tag is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    `${signed.headers["signature-input"]};tag=123`,
    /malformed signature-input parameter ";tag"/,
  );
});

test("trailing garbage after the last parameter is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;created=${CREATED}`,
      `;created=${CREATED} garbage`,
    ),
    /malformed signature-input parameter/,
  );
});

test("created with a missing value is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    signed.headers["signature-input"].replace(
      `;created=${CREATED}`,
      ";created=",
    ),
    /malformed signature-input parameter ";created"/,
  );
});

test("bare unknown parameter without a value is rejected", () => {
  const { signed, publicKey } = signedGet();
  assertMalformed(
    signed,
    publicKey,
    `${signed.headers["signature-input"]};unknown-param`,
    /malformed signature-input parameter ";unknown-param"/,
  );
});

test("verifyAllLabels: malformed param in one label fails that label only", () => {
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
  // Tamper only the gateway label's created (last occurrence in the header).
  const tampered = withSignatureInput(
    dual,
    replaceLast(
      dual.headers["signature-input"],
      `;created=${CREATED}`,
      `;created=${CREATED}.5`,
    ),
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
  assert.match(results[1].reason ?? "", /malformed signature-input parameter/);
});

test("unknown parameters are still ignored per RFC 9421 §2.4", () => {
  const { signed, publicKey } = signedGet();
  const withUnknown = withSignatureInput(
    signed,
    `${signed.headers["signature-input"]};foo="bar";baz=1.5`,
  );
  const res = verifyRequest(withUnknown, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
});

test("parseSignatureInput throws the malformed-param error directly", () => {
  assert.throws(
    () =>
      parseSignatureInput(
        `sig1=("@method");created=${CREATED}.5`,
        "sig1",
      ),
    /malformed signature-input parameter ";created"/,
  );
  assert.throws(
    () => parseSignatureInput(`sig1=("@method");keyid=123`, "sig1"),
    /malformed signature-input parameter ";keyid"/,
  );
  assert.throws(
    () =>
      parseSignatureInput(
        `sig1=("@method");created=${CREATED} garbage`,
        "sig1",
      ),
    /malformed signature-input parameter/,
  );
});

test("well-formed shapes still parse: whitespace and case-insensitive names", () => {
  const parsed = parseSignatureInput(
    `sig1=("@method") ; CREATED = ${CREATED} ; keyid = "k"`,
    "sig1",
  );
  assert.equal(parsed.params.created, CREATED);
  assert.equal(parsed.params.keyid, "k");
  const empty = parseSignatureInput(`sig1=("@method")`, "sig1");
  assert.deepEqual(empty.params, {});
});

test("untampered signed request still verifies (no regression)", () => {
  const { signed, publicKey } = signedGet();
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
});
