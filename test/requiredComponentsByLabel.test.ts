import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  verifyAllLabels,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant signs the payment initiation; gateway signs the same
// request when forwarding it. Both signatures cover the same body,
// so a single global coverage list cannot express "the merchant must
// bind the body, the gateway must bind the query string": the
// per-label map is what splits them.
function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments?ref=abc",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  // Union the headers (so a content-digest header produced by either
  // signer survives), then combine the two signature dictionaries.
  return {
    ...a,
    headers: {
      ...a.headers,
      ...b.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function signMerchant(coveredComponents: string[]): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    coveredComponents,
  });
}

function signGateway(coveredComponents: string[]): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "ed25519",
    key: gateway.privateKey,
    coveredComponents,
  });
}

function dual(
  merchantCovered: string[],
  gatewayCovered: string[],
): SignedHttpRequest {
  return mergeSignatures(
    signMerchant(merchantCovered),
    signGateway(gatewayCovered),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

const MAP = {
  merchant: ["content-digest"],
  gateway: ["@query"],
};

test("requiredComponentsByLabel: merchant missing content-digest fails, gateway covering @query passes", () => {
  const results = verifyAllLabels(
    dual(["@method", "@path"], ["@method", "@path", "@query"]),
    { keys: keys(), requiredComponentsByLabel: MAP },
  );
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[0].reason ?? "", /content-digest/);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("requiredComponentsByLabel: gateway missing @query fails, merchant covering content-digest passes", () => {
  const results = verifyAllLabels(
    dual(
      ["@method", "@path", "content-digest"],
      ["@method", "@path"],
    ),
    { keys: keys(), requiredComponentsByLabel: MAP },
  );
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[1].reason ?? "", /@query/);
});

test("requiredComponentsByLabel: comparison is case-insensitive, like the global check", () => {
  const results = verifyAllLabels(
    dual(
      ["@method", "@path", "content-digest"],
      ["@method", "@path", "@query"],
    ),
    {
      keys: keys(),
      requiredComponentsByLabel: {
        merchant: ["Content-Digest"],
        gateway: ["@QUERY"],
      },
    },
  );
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("requiredComponentsByLabel: unmapped label falls back to the global list", () => {
  // Only the merchant is mapped (to "@method", which it covers); the
  // gateway falls back to the global content-digest requirement and
  // fails, because neither signature covers the digest here.
  const results = verifyAllLabels(dual(["@method", "@path"], ["@method", "@path"]), {
    keys: keys(),
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { merchant: ["@method"] },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "MISSING_REQUIRED_COMPONENT");
  assert.match(results[1].reason ?? "", /content-digest/);
});

test("requiredComponentsByLabel: a mapped list replaces the global list, it is not unioned with it", () => {
  // The merchant is mapped to "@method" only: it passes even though
  // the global list also demands content-digest, which it does not
  // cover. Mapping to [] disables the check for that label outright.
  const mapped = verifyAllLabels(dual(["@method", "@path"], ["@method", "@path"]), {
    keys: keys(),
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { merchant: ["@method"] },
  });
  assert.equal(mapped[0].ok, true);

  const emptied = verifyAllLabels(dual(["@method", "@path"], ["@method", "@path"]), {
    keys: keys(),
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { merchant: [] },
  });
  assert.equal(emptied[0].ok, true);
  // The unmapped gateway still falls back to the global list.
  assert.equal(emptied[1].ok, false);
  assert.equal(emptied[1].code, "MISSING_REQUIRED_COMPONENT");
});

test("requiredComponentsByLabel: without the map the global list applies to both labels", () => {
  const results = verifyAllLabels(
    dual(["@method", "@path"], ["@method", "@path", "@query"]),
    { keys: keys(), requiredComponents: ["content-digest"] },
  );
  assert.deepEqual(
    results.map((r) => r.code),
    ["MISSING_REQUIRED_COMPONENT", "MISSING_REQUIRED_COMPONENT"],
  );
});

test("requiredComponentsByLabel: malformed map or list fails fast with a configuration error", () => {
  assert.throws(
    () =>
      verifyAllLabels(dual(["@method"], ["@method"]), {
        keys: keys(),
        requiredComponentsByLabel: [] as never,
      }),
    /requiredComponentsByLabel.*must be a label→component-list object/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dual(["@method"], ["@method"]), {
        keys: keys(),
        requiredComponentsByLabel: { merchant: "content-digest" as never },
      }),
    /requiredComponentsByLabel.*merchant.*is invalid/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dual(["@method"], ["@method"]), {
        keys: keys(),
        requiredComponentsByLabel: { merchant: ["@method", ""] },
      }),
    /requiredComponentsByLabel.*merchant.*is invalid/,
  );
});

test("requiredComponentsByLabel: single-label verifyRequest global path is unchanged", () => {
  const narrow = signMerchant(["@method"]);
  const rejected = verifyRequest(narrow, {
    label: "merchant",
    key: merchant.publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, "MISSING_REQUIRED_COMPONENT");

  const covered = signMerchant(["@method", "@path", "content-digest"]);
  const accepted = verifyRequest(covered, {
    label: "merchant",
    key: merchant.publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(accepted.ok, true);
});
