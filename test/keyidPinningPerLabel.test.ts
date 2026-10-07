import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  generateEd25519KeyPair,
  signRequest,
  signatureInputValue,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

const COVERED = ["@method", "@authority", "@path", "content-digest"];

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

/**
 * Sign one label like a foreign signer that omits the optional `keyid`
 * parameter entirely (hand-rolled or third-party signatures may do so).
 */
function signWithoutKeyid(
  req: ReturnType<typeof baseRequest>,
  opts: {
    label: string;
    key: ReturnType<typeof generateEd25519KeyPair>["privateKey"];
  },
): SignedHttpRequest {
  const headers: Record<string, string> = { ...req.headers };
  headers["content-digest"] = contentDigest(req.body);
  const params = { created: CREATED, alg: "ed25519" }; // no keyid
  const signingInput = { method: req.method, url: req.url, headers, body: req.body };
  const base = buildSignatureBase(COVERED, signingInput, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), opts.key);
  headers["signature-input"] = signatureInputValue(opts.label, COVERED, params);
  headers["signature"] = `${opts.label}=:${sig.toString("base64")}:`;
  assert.ok(
    !headers["signature-input"].includes("keyid="),
    "precondition: foreign wire must not carry keyid",
  );
  return { method: req.method, url: req.url, headers, body: req.body };
}

function twoLabels() {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const a = signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  const b = signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-7",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
  });
  return { merged: mergeSignatures(a, b), merchant, gateway };
}

test("per-label keyid pinning: both labels pinned, both pass", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-7" },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("per-label keyid pinning: wrong pin on one label fails it, other unaffected", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyIds: { merchant: "merchant-key-1", gateway: "gateway-key-OTHER" },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "KEYID_MISMATCH");
  assert.equal(results[1].label, "gateway");
});

test("per-label keyid pinning: label missing from map falls back to global expectedKeyId", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyId: "merchant-key-1",
    expectedKeyIds: { gateway: "gateway-key-7" },
  });
  // "merchant" is not pinned per-label, so the global expectedKeyId
  // applies and matches; "gateway" uses its own pin.
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("per-label keyid pinning: global fallback mismatch fails with KEYID_MISMATCH", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyId: "merchant-key-1",
    expectedKeyIds: {},
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "KEYID_MISMATCH");
});

test("per-label keyid pinning: pinned label with no keyid on the wire fails", () => {
  const gateway = generateEd25519KeyPair();
  const b = signWithoutKeyid(baseRequest(), {
    label: "gateway",
    key: gateway.privateKey,
  });
  const results = verifyAllLabels(b, {
    now: NOW,
    keys: { gateway: gateway.publicKey },
    expectedKeyIds: { gateway: "gateway-key-7" },
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEYID_MISMATCH");
  assert.equal(results[0].keyId, undefined);
});

test("per-label keyid pinning: no pinning configured keeps old behavior", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
  });
  assert.equal(results.every((r) => r.ok), true);
});

test("per-label keyid pinning: empty map behaves like no pinning", () => {
  const { merged, merchant, gateway } = twoLabels();
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    expectedKeyIds: {},
  });
  assert.equal(results.every((r) => r.ok), true);
});

test("per-label keyid pinning: empty-string value is a caller config error", () => {
  const { merged } = twoLabels();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        expectedKeyIds: { merchant: "" },
      }),
    /expectedKeyIds\["merchant"\].* must be a non-empty string/,
  );
});

test("per-label keyid pinning: non-string value is a caller config error", () => {
  const { merged } = twoLabels();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        expectedKeyIds: { merchant: 42 as unknown as string },
      }),
    /must be a non-empty string/,
  );
});

test("per-label keyid pinning: non-object map is a caller config error", () => {
  const { merged } = twoLabels();
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        now: NOW,
        expectedKeyIds: "merchant-key-1" as unknown as Record<string, string>,
      }),
    /must be a label→keyid object/,
  );
});
