import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
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

// ---------- success results ----------

test("VerifyResult carries the full covered-component list in signature-input order", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);
});

test("single-component signature reports exactly that one component", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method"],
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, ["@method"]);
});

test("verifyRequestOrThrow success return carries the covered-component list", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@path"],
    created: CREATED,
  });
  const out = verifyRequestOrThrow(signed, { key: publicKey, now: NOW });
  assert.deepEqual(out.coveredComponents, ["@method", "@path"]);
});

// ---------- failure results still report the wire list ----------

test("tampered signature: SIGNATURE_MISMATCH result still reports the original component list", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  // Rewrite the signature value without re-signing: the crypto check
  // must fail, but the reported component list is what was sent.
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: signed.headers["signature"].replace(/:([^:]+):$/, ":AAAA:"),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.deepEqual(res.coveredComponents, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);
});

test("tampered body: BODY_DIGEST_MISMATCH result still reports the component list", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const tampered: SignedHttpRequest = {
    ...signed,
    body: '{"amount":999}',
  };
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.deepEqual(res.coveredComponents, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);
});

test("required-component policy failure still reports the component list", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method"],
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.deepEqual(res.coveredComponents, ["@method"]);
});

// ---------- unparseable input: never fabricated ----------

test("missing signature-input: coveredComponents stays undefined, not fabricated", () => {
  const { publicKey } = generateEd25519KeyPair();
  const res = verifyRequest(baseRequest(), { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_SIGNATURE_INPUT");
  assert.equal(res.coveredComponents, undefined);
});

test("malformed signature-input: coveredComponents stays undefined", () => {
  const { publicKey } = generateEd25519KeyPair();
  const req = {
    ...baseRequest(),
    headers: {
      ...baseRequest().headers,
      "signature-input": 'sig1=("unclosed',
      signature: "sig1=:AAAA:",
    },
  };
  const res = verifyRequest(req, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.equal(res.coveredComponents, undefined);
});

// ---------- detachment and multi-label / rotation paths ----------

test("mutating the returned list does not affect a later verification", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const first = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(first.ok, true);
  first.coveredComponents?.push("content-digest-forged");
  const second = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(second.ok, true);
  assert.deepEqual(second.coveredComponents, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);
});

test("verifyAllLabels reports each label's own component list, in wire order", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const a = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@path"],
    created: CREATED,
    label: "merchant",
  });
  const b = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method"],
    created: CREATED,
    label: "gateway",
  });
  const results = verifyAllLabels(mergeSignatures(a, b), {
    key: publicKey,
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.deepEqual(results[0].coveredComponents, ["@method", "@path"]);
  assert.equal(results[1].ok, true);
  assert.deepEqual(results[1].coveredComponents, ["@method"]);
});

test("candidateKeys rotation success carries the covered-component list", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const wrong = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    coveredComponents: ["@method", "@authority"],
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    candidateKeys: [wrong.publicKey, publicKey],
    now: NOW,
  });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, ["@method", "@authority"]);
});
