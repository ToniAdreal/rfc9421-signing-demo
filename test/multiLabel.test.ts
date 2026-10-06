import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  listSignatureLabels,
  secretKey,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function baseRequest(body?: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
}

/**
 * Combine two single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature.
 */
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

test("two ed25519 labels both verify, in wire order", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "gateway",
  });
  const merged = mergeSignatures(a, b);

  const results = verifyAllLabels(merged, { key: publicKey, now: NOW });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) assert.equal(r.ok, true);
  assert.equal(results[0].keyId, "merchant-key");
  assert.equal(results[1].keyId, "gateway-key");
});

test("mixed algorithms with per-label keys", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const secret = secretKey("multilabel-test-secret-32-bytes-0");
  const body = JSON.stringify({ amount: 250 });
  const a = signRequest(baseRequest(body), {
    keyId: "ed-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig-ed",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "hmac-key",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    label: "sig-hmac",
  });
  const merged = mergeSignatures(a, b);

  const results = verifyAllLabels(merged, {
    key: publicKey,
    now: NOW,
    keys: { "sig-hmac": secret },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "hmac-sha256");
});

test("a bad label does not block the good label", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "good",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "k2",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "bad",
  });
  // Flip the first base64 character of the "bad" signature's bytes,
  // leaving everything else intact.
  const merged = mergeSignatures(a, b);
  merged.headers = {
    ...merged.headers,
    signature: merged.headers["signature"].replace(
      /((?:^|,)\s*bad\s*=:)([A-Za-z0-9+/])/,
      (_m, prefix: string, p1: string) => `${prefix}${p1 === "A" ? "B" : "A"}`,
    ),
  };
  assert.notEqual(
    merged.headers["signature"],
    `${a.headers["signature"]}, ${b.headers["signature"]}`,
    "tamper must actually change the header",
  );

  const results = verifyAllLabels(merged, { key: publicKey, now: NOW });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "good");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "bad");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("label missing from the signature header fails only that label", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "present",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "k2",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "absent",
  });
  // signature-input lists both labels; signature header only has one.
  const merged = mergeSignatures(a, b);
  merged.headers = { ...merged.headers, signature: a.headers["signature"] };

  const results = verifyAllLabels(merged, { key: publicKey, now: NOW });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MALFORMED_SIGNATURE");
});

test("missing signature-input returns an empty array", () => {
  const { publicKey } = generateEd25519KeyPair();
  const results = verifyAllLabels(baseRequest(), { key: publicKey, now: NOW });
  assert.deepEqual(results, []);
});

test("duplicate labels are verified once", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig1",
  });
  const doubled = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": `${signed.headers["signature-input"]}, ${signed.headers["signature-input"]}`,
      signature: `${signed.headers["signature"]}, ${signed.headers["signature"]}`,
    },
  };
  const results = verifyAllLabels(doubled, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].label, "sig1");
  assert.equal(results[0].ok, true);
});

test("nonce is surfaced per label", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const a = signRequest(baseRequest(), {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "first",
    nonce: "nonce-first",
  });
  const b = signRequest(baseRequest(), {
    keyId: "k2",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "second",
    nonce: "nonce-second",
  });
  const merged = mergeSignatures(a, b);
  const results = verifyAllLabels(merged, { key: publicKey, now: NOW });
  assert.equal(results[0].nonce, "nonce-first");
  assert.equal(results[1].nonce, "nonce-second");
});

test("listSignatureLabels ignores commas in quoted params and parens", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "one",
    nonce: 'a,b "quoted"',
  });
  const two = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "two",
  });
  const value = `${signed.headers["signature-input"]}, ${two.headers["signature-input"]}`;
  assert.deepEqual(listSignatureLabels(value), ["one", "two"]);
});

test("listSignatureLabels throws on a malformed member", () => {
  assert.throws(() => listSignatureLabels('sig1=("@method");created=1, ,'), /malformed/);
});
