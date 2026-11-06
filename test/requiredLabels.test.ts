import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyAllLabelsOrThrow,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
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

// Merchant: one fixed ed25519 key. Gateway: an HMAC secret.
const merchant = generateEd25519KeyPair();
const GATEWAY = secretKey(randomBytes(32));
const GATEWAY_WRONG = secretKey(randomBytes(32));

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

function dual(): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway(GATEWAY));
}

function dualWithBadGateway(): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway(GATEWAY_WRONG));
}

const KEYS = { merchant: merchant.publicKey, gateway: GATEWAY };

test("requiredLabels: both labels present, no synthetic entries", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["merchant", "gateway"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results.every((r) => r.ok), true);
});

test("requiredLabels: stripped gateway label is a synthetic MISSING_REQUIRED_LABEL failure, merchant still reported", () => {
  const results = verifyAllLabels(signMerchant(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["merchant", "gateway"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MISSING_REQUIRED_LABEL");
  assert.match(results[1].reason ?? "", /gateway/);
  assert.equal(results.every((r) => r.ok), false);
});

test("requiredLabels: unsigned request returns failure entries, not []", () => {
  const results = verifyAllLabels(baseRequest(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["gateway"],
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].label, "gateway");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "MISSING_REQUIRED_LABEL");
  assert.equal(results.every((r) => r.ok), false);
});

test("requiredLabels: empty list means no check", () => {
  assert.deepEqual(
    verifyAllLabels(baseRequest(), { now: NOW, keys: KEYS, requiredLabels: [] }),
    [],
  );
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: [],
  });
  assert.equal(results.length, 2);
  assert.equal(results.every((r) => r.ok), true);
});

test("requiredLabels: duplicate entries are a configuration error", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: KEYS,
        requiredLabels: ["gateway", "merchant", "gateway"],
      }),
    /requiredLabels.*must not repeat.*gateway/,
  );
});

test("requiredLabels: duplicate entries throw even for an unsigned request", () => {
  assert.throws(
    () =>
      verifyAllLabels(baseRequest(), {
        now: NOW,
        keys: KEYS,
        requiredLabels: ["gateway", "gateway"],
      }),
    /requiredLabels.*must not repeat/,
  );
});

test("requiredLabels: empty-string entries are a configuration error", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: KEYS,
        requiredLabels: ["merchant", ""],
      }),
    /requiredLabels.*non-empty strings/,
  );
});

test("requiredLabels: non-array and non-string entries are configuration errors", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: KEYS,
        // @ts-expect-error deliberate misuse: non-array requiredLabels
        requiredLabels: "gateway",
      }),
    /requiredLabels.*must be an array/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        now: NOW,
        keys: KEYS,
        // @ts-expect-error deliberate misuse: non-string entry
        requiredLabels: ["merchant", 42],
      }),
    /requiredLabels.*non-empty strings/,
  );
});

test("requiredLabels: a present-but-failing label gets its real failure, no synthetic entry", () => {
  const results = verifyAllLabels(dualWithBadGateway(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["merchant", "gateway"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("requiredLabels: synthetic entries follow requiredLabels order after wire-order results", () => {
  const results = verifyAllLabels(signMerchant(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["gateway", "merchant"],
  });
  assert.equal(results.length, 2);
  // Wire-order result first, synthetic entries after, in
  // requiredLabels order (gateway is the only missing one).
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].code, "MISSING_REQUIRED_LABEL");
});

test("requiredLabels: the single-label verifyRequest path is unaffected", () => {
  // verifyRequest never learned about requiredLabels: an unsigned
  // request still reports its own single failure, unchanged.
  const result = verifyRequest(baseRequest(), {
    now: NOW,
    key: merchant.publicKey,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "MISSING_SIGNATURE_INPUT");
});

test("requiredLabels: verifyAllLabelsOrThrow throws MISSING_REQUIRED_LABEL on an unsigned request", () => {
  assert.throws(
    () =>
      verifyAllLabelsOrThrow(baseRequest(), {
        now: NOW,
        keys: KEYS,
        requiredLabels: ["gateway"],
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_REQUIRED_LABEL" && e.label === "gateway",
  );
  const results = verifyAllLabelsOrThrow(dual(), {
    now: NOW,
    keys: KEYS,
    requiredLabels: ["merchant", "gateway"],
  });
  assert.equal(results.length, 2);
  assert.equal(results.every((r) => r.ok), true);
});
