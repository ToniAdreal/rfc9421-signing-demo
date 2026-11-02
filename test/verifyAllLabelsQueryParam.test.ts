import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/pay?order=42&amount=100&currency=USD";

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

/**
 * One request signed by two labels: "qp" binds a single named query
 * parameter, "plain" covers only method + content-type and never touches
 * the query string. The two labels share one keypair so that any
 * difference in outcome is attributable to coverage, not key selection.
 */
function signDual() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
  };
  const qp = signRequest(req, {
    keyId: "qp-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "qp",
    coveredComponents: ["@method", '@query-param;name="amount"'],
  });
  const plain = signRequest(req, {
    keyId: "plain-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "plain",
    coveredComponents: ["@method", "content-type"],
  });
  return { publicKey, merged: mergeSignatures(qp, plain) };
}

function byLabel(results: ReturnType<typeof verifyAllLabels>) {
  const qp = results.find((r) => r.label === "qp");
  const plain = results.find((r) => r.label === "plain");
  assert.ok(qp, "qp label must be reported");
  assert.ok(plain, "plain label must be reported");
  return { qp, plain };
}

test("dual-label round-trip: both labels verify, qp label reports its binding", () => {
  const { publicKey, merged } = signDual();
  const results = verifyAllLabels(merged, { key: publicKey, now: NOW });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["qp", "plain"],
  );
  const { qp, plain } = byLabel(results);
  assert.equal(qp.ok, true);
  assert.equal(plain.ok, true);
  assert.ok(qp.coveredComponents?.includes('@query-param;name="amount"'));
  assert.ok(!plain.coveredComponents?.some((c) => c.startsWith("@query")));
});

test("tampering the bound parameter breaks only the qp label", () => {
  const { publicKey, merged } = signDual();
  const tampered = {
    ...merged,
    url: "https://api.example.com/pay?order=42&amount=999&currency=USD",
  };
  const { qp, plain } = byLabel(
    verifyAllLabels(tampered, { key: publicKey, now: NOW }),
  );
  assert.equal(qp.ok, false);
  assert.equal(qp.code, "SIGNATURE_MISMATCH");
  assert.equal(plain.ok, true);
});

test("unbound parameters may be added, removed, or reordered without breaking either label", () => {
  const { publicKey, merged } = signDual();
  for (const url of [
    "https://api.example.com/pay?currency=USD&amount=100&order=42", // reordered
    "https://api.example.com/pay?order=42&amount=100&currency=USD&utm=x", // added
    "https://api.example.com/pay?amount=100", // unbound ones removed
    "https://api.example.com/pay?order=43&amount=100", // unbound value changed
  ]) {
    const { qp, plain } = byLabel(
      verifyAllLabels({ ...merged, url }, { key: publicKey, now: NOW }),
    );
    assert.equal(qp.ok, true, url);
    assert.equal(plain.ok, true, url);
  }
});

test("removing the bound parameter fails the qp label closed, plain label unaffected", () => {
  const { publicKey, merged } = signDual();
  const stripped = {
    ...merged,
    url: "https://api.example.com/pay?order=42&currency=USD",
  };
  const { qp, plain } = byLabel(
    verifyAllLabels(stripped, { key: publicKey, now: NOW }),
  );
  assert.equal(qp.ok, false);
  assert.equal(qp.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(plain.ok, true);
});

test("a repeated bound parameter name is rejected by the qp label only", () => {
  const { publicKey, merged } = signDual();
  const duplicated = {
    ...merged,
    url: "https://api.example.com/pay?order=42&amount=100&amount=100&currency=USD",
  };
  const { qp, plain } = byLabel(
    verifyAllLabels(duplicated, { key: publicKey, now: NOW }),
  );
  assert.equal(qp.ok, false);
  assert.equal(qp.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(qp.reason ?? "", /occurs 2 times/);
  assert.equal(plain.ok, true);
});

test("a qp label stripped of its ;name fails closed without throwing, plain label still reports", () => {
  const { publicKey, merged } = signDual();
  const forged = {
    ...merged,
    headers: {
      ...merged.headers,
      "signature-input": merged.headers["signature-input"].replace(
        '"@query-param";name="amount"',
        '"@query-param"',
      ),
    },
  };
  assert.notEqual(
    forged.headers["signature-input"],
    merged.headers["signature-input"],
    "the ;name strip must actually change the header",
  );
  let results: ReturnType<typeof verifyAllLabels>;
  assert.doesNotThrow(() => {
    results = verifyAllLabels(forged, { key: publicKey, now: NOW });
  });
  const { qp, plain } = byLabel(results!);
  assert.equal(qp.ok, false);
  assert.equal(qp.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(plain.ok, true);
});

test("tampering the plain label's covered header breaks only the plain label", () => {
  const { publicKey, merged } = signDual();
  const tampered = {
    ...merged,
    headers: { ...merged.headers, "content-type": "text/plain" },
  };
  const { qp, plain } = byLabel(
    verifyAllLabels(tampered, { key: publicKey, now: NOW }),
  );
  assert.equal(plain.ok, false);
  assert.equal(plain.code, "SIGNATURE_MISMATCH");
  assert.equal(qp.ok, true);
});
