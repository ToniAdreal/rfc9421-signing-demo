import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  isVerifyError,
  MAX_COVERED_COMPONENTS,
  parseSignatureInput,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
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

/** A validly-signed ed25519 POST request (with body) plus its public key. */
function signedPost() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ amount: 100, currency: "USD" }),
    },
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

/** A signature-input header covering `n` distinct header-field components. */
function manyComponentsHeader(n: number): string {
  const ids = Array.from({ length: n }, (_, k) => `"h${k}"`).join(" ");
  return `sig1=(${ids});created=${CREATED};keyid="k";alg="ed25519";nonce="n-1"`;
}

test("duplicate @method is rejected with MALFORMED_SIGNATURE_INPUT, before crypto", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    signed.headers["signature-input"].replace(
      `"@method"`,
      `"@method" "@method"`,
    ),
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  // Not SIGNATURE_MISMATCH: the duplicated covered line is rejected at parse time.
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate covered component "@method"/);
});

test("case variants of the same component are the same duplicate (@Method vs @method)", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    signed.headers["signature-input"].replace(
      `"@method"`,
      `"@method" "@METHOD"`,
    ),
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate covered component "@method"/);
});

test("duplicate parameterized component is rejected (content-digest;key twice)", () => {
  const { signed, publicKey } = signedPost();
  const tampered = withSignatureInput(
    signed,
    signed.headers["signature-input"].replace(
      `"content-digest"`,
      `"content-digest";key="sha-256" "content-digest";key="sha-256"`,
    ),
  );
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(
    res.reason ?? "",
    /duplicate covered component "content-digest;key="sha-256""/,
  );
});

test("duplicate @query-param with the same ;name is rejected", () => {
  const { publicKey } = signedGet();
  const res = verifyRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?a=1",
      headers: {
        "signature-input":
          `sig1=("@query-param";name="a" "@query-param";name="a");created=${CREATED};keyid="k";alg="ed25519";nonce="n-1"`,
        signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:",
      },
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(
    res.reason ?? "",
    /duplicate covered component "@query-param;name="a""/,
  );
});

test("parseSignatureInput throws the duplicate error directly", () => {
  assert.throws(
    () =>
      parseSignatureInput(
        `sig1=("@method" "@method");created=${CREATED}`,
        "sig1",
      ),
    /duplicate covered component "@method"/,
  );
  assert.throws(
    () =>
      parseSignatureInput(
        `sig1=("@path" "@method" "@path");created=${CREATED}`,
        "sig1",
      ),
    /duplicate covered component "@path"/,
  );
});

test(";req reroutes the binding, so @method and @method;req are NOT duplicates", () => {
  // Same base, different bindings (this message's method vs the
  // associated request's method, RFC 9421 §2.2.7) — both may be
  // covered, exactly as the sign side allows (coveredComponentKey).
  const parsed = parseSignatureInput(
    `sig1=("@method";req "@method");created=${CREATED}`,
    "sig1",
  );
  assert.deepEqual(parsed.componentIds, ["@method;req", "@method"]);
});

test("different parameter values are different components (;name a vs b)", () => {
  const parsed = parseSignatureInput(
    `sig1=("@query-param";name="a" "@query-param";name="b");created=${CREATED}`,
    "sig1",
  );
  assert.equal(parsed.componentIds.length, 2);
  assert.deepEqual(parsed.componentIds, [
    `@query-param;name="a"`,
    `@query-param;name="b"`,
  ]);
});

test("parameter order variants are distinct entries, mirroring the sign side", () => {
  // The sign side's coveredComponentKey compares parameters in listed
  // order, so `;key;tr` and `;tr;key` are distinct entries there —
  // the verifier must agree, never rejecting a signature the signer
  // could mint. (serializeComponentId still canonicalizes their
  // order when the base is rebuilt.)
  const parsed = parseSignatureInput(
    `sig1=("content-digest";key="sha-256";tr "content-digest";tr;key="sha-256");created=${CREATED}`,
    "sig1",
  );
  assert.equal(parsed.componentIds.length, 2);
  assert.deepEqual(parsed.componentIds, [
    `content-digest;key="sha-256";tr`,
    `content-digest;tr;key="sha-256"`,
  ]);
});

test("more than MAX_COVERED_COMPONENTS components is rejected at parse time", () => {
  assert.equal(MAX_COVERED_COMPONENTS, 64);
  assert.throws(
    () => parseSignatureInput(manyComponentsHeader(65), "sig1"),
    /too many covered components: 65 \(max 64\)/,
  );
  // Exactly at the cap parses fine.
  const parsed = parseSignatureInput(manyComponentsHeader(64), "sig1");
  assert.equal(parsed.componentIds.length, 64);
});

test("verifyRequest enforces the count cap with MALFORMED_SIGNATURE_INPUT", () => {
  const { signed, publicKey } = signedGet();
  const over = withSignatureInput(signed, manyComponentsHeader(65));
  const resOver = verifyRequest(over, { key: publicKey, now: NOW });
  assert.equal(resOver.ok, false);
  assert.equal(resOver.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(resOver.reason ?? "", /too many covered components: 65 \(max 64\)/);

  // Exactly at the cap gets past the parser: the failure moves to
  // base building (the synthetic h0..h63 fields are not on the
  // request), proving the cap — not the parser — is the boundary.
  const atCap = withSignatureInput(signed, manyComponentsHeader(64));
  const resAtCap = verifyRequest(atCap, { key: publicKey, now: NOW });
  assert.equal(resAtCap.ok, false);
  assert.equal(resAtCap.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("empty covered list still parses (RFC 9421 B.2.1 minimal coverage)", () => {
  const parsed = parseSignatureInput(`sig1=();created=${CREATED}`, "sig1");
  assert.deepEqual(parsed.componentIds, []);
});

test("verifyRequestOrThrow throws VerifyError(MALFORMED_SIGNATURE_INPUT) on duplicates", () => {
  const { signed, publicKey } = signedGet();
  const tampered = withSignatureInput(
    signed,
    signed.headers["signature-input"].replace(
      `"@method"`,
      `"@method" "@method"`,
    ),
  );
  assert.throws(
    () => verifyRequestOrThrow(tampered, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "MALFORMED_SIGNATURE_INPUT");
      return true;
    },
  );
});

test("verifyAllLabels: duplicate in one label fails that label only, never throws", () => {
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
  // Duplicate @method inside the gateway label's component list only.
  const tampered = withSignatureInput(
    dual,
    dual.headers["signature-input"].replace(
      `gateway=("@method"`,
      `gateway=("@method" "@method"`,
    ),
  );
  const results = verifyAllLabels(tampered, {
    key: publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true, "merchant label unaffected");
  assert.equal(results[0].label, "merchant");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MALFORMED_SIGNATURE_INPUT");
  assert.equal(results[1].label, "gateway");
});

test("sign and verify agree: the sign side refuses the same duplicate, valid signatures still verify", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(
        { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
        {
          keyId: "k",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: ["@method", "@method"],
        },
      ),
    /must not repeat a component/,
  );
  const { signed, publicKey } = signedGet();
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
});
