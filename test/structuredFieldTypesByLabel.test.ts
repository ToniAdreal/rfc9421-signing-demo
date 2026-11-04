import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type SignedHttpRequest,
  type StructuredFieldType,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

// A Dictionary-shaped value: the default trial order (Dictionary →
// List → Item) parses it as a Dictionary, while a List registry
// rejects it outright — so the registry a label is verified with
// decides the outcome, not the wire value alone.
function dictRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": "a=1" },
  };
}

function twoFieldRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": "a=1", "x-other": '"a", "b"' },
  };
}

// A lone token serializes identically as a Dictionary, a List, and
// an Item, so both registries can sign and verify the same value.
function tokenRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": "a" },
  };
}

function signLabel(
  req: ReturnType<typeof dictRequest>,
  label: string,
  keys: ReturnType<typeof generateEd25519KeyPair>,
  covered: string[],
  registry?: Record<string, StructuredFieldType>,
): SignedHttpRequest {
  return signRequest(req, {
    label,
    keyId: `${label}-key-1`,
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
    ...(registry !== undefined ? { structuredFieldTypes: registry } : {}),
  });
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

function dualDict(
  merchantRegistry?: Record<string, StructuredFieldType>,
  gatewayRegistry?: Record<string, StructuredFieldType>,
): SignedHttpRequest {
  return mergeSignatures(
    signLabel(dictRequest(), "merchant", merchant, ["@method", "x-quota;sf"], merchantRegistry),
    signLabel(dictRequest(), "gateway", gateway, ["@method", "x-quota;sf"], gatewayRegistry),
  );
}

const KEYS = {
  merchant: merchant.publicKey,
  gateway: gateway.publicKey,
};

test("structuredFieldTypesByLabel: same field, merchant dictionary passes while gateway list fails", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypesByLabel: {
      merchant: { "x-quota": "dictionary" },
      gateway: { "x-quota": "list" },
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("structuredFieldTypesByLabel: reversed mapping reverses the outcomes", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypesByLabel: {
      merchant: { "x-quota": "list" },
      gateway: { "x-quota": "dictionary" },
    },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(results[1].ok, true);
});

test("structuredFieldTypesByLabel: each label verifies under its own registry and both pass", () => {
  const dual = mergeSignatures(
    signLabel(tokenRequest(), "merchant", merchant, ["@method", "x-quota;sf"], {
      "x-quota": "dictionary",
    }),
    signLabel(tokenRequest(), "gateway", gateway, ["@method", "x-quota;sf"], {
      "x-quota": "list",
    }),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: KEYS,
    structuredFieldTypesByLabel: {
      merchant: { "x-quota": "dictionary" },
      gateway: { "x-quota": "list" },
    },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("structuredFieldTypesByLabel: unmapped label falls back to the global registry", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypes: { "x-quota": "list" },
    structuredFieldTypesByLabel: {
      merchant: { "x-quota": "dictionary" },
    },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("structuredFieldTypesByLabel: a mapped registry replaces the global one, it is not merged", () => {
  // Global pins x-quota as a List and x-other as a Dictionary. The
  // merchant map pins only x-quota as a Dictionary: under replacement
  // semantics x-other falls back to the trial order (List, which the
  // wire value parses as) and the merchant passes; under union
  // semantics the global x-other Dictionary pin would fail it.
  const dual = mergeSignatures(
    signLabel(twoFieldRequest(), "merchant", merchant, [
      "@method",
      "x-quota;sf",
      "x-other;sf",
    ]),
    signLabel(twoFieldRequest(), "gateway", gateway, [
      "@method",
      "x-quota;sf",
      "x-other;sf",
    ]),
  );
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: KEYS,
    structuredFieldTypes: { "x-quota": "list", "x-other": "dictionary" },
    structuredFieldTypesByLabel: {
      merchant: { "x-quota": "dictionary" },
    },
  });
  assert.equal(results[0].ok, true);
  // The unmapped gateway still gets the full global registry, so its
  // Dictionary-shaped x-quota fails the global List pin.
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("structuredFieldTypesByLabel: mapping a label to an empty registry clears the global pins for it", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypes: { "x-quota": "list" },
    structuredFieldTypesByLabel: { merchant: {} },
  });
  // Merchant: empty registry means the trial order, which parses
  // "a=1" as a Dictionary — the same base the signer produced.
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("structuredFieldTypesByLabel: no map keeps the global registry for every label", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("structuredFieldTypesByLabel: a map entry for an absent label changes nothing", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypesByLabel: {
      nonexistent: { "x-quota": "list" },
    },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});

test("structuredFieldTypesByLabel: field names match case-insensitively", () => {
  const results = verifyAllLabels(dualDict(), {
    now: NOW,
    keys: KEYS,
    structuredFieldTypesByLabel: {
      // Upper-case field name must still pin the lower-case header;
      // if the lookup missed, the trial order would pass the merchant.
      merchant: { "X-QUOTA": "list" },
    },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(results[1].ok, true);
});

test("structuredFieldTypesByLabel: a malformed map throws a configuration error", () => {
  for (const bad of [[], null, "merchant"] as unknown[]) {
    assert.throws(
      () =>
        verifyAllLabels(dualDict(), {
          now: NOW,
          keys: KEYS,
          structuredFieldTypesByLabel:
            bad as Record<string, Record<string, StructuredFieldType>>,
        }),
      /structuredFieldTypesByLabel.*must be a label→registry object/,
    );
  }
});

test("structuredFieldTypesByLabel: a malformed per-label registry throws naming the label", () => {
  assert.throws(
    () =>
      verifyAllLabels(dualDict(), {
        now: NOW,
        keys: KEYS,
        structuredFieldTypesByLabel: {
          merchant: { "x-quota": "set" as unknown as StructuredFieldType },
        },
      }),
    /structuredFieldTypesByLabel\["merchant"\]/,
  );
  assert.throws(
    () =>
      verifyAllLabels(dualDict(), {
        now: NOW,
        keys: KEYS,
        structuredFieldTypesByLabel: {
          gateway: "dictionary" as unknown as Record<
            string,
            StructuredFieldType
          >,
        },
      }),
    /structuredFieldTypesByLabel\["gateway"\]/,
  );
});

test("structuredFieldTypesByLabel: case-duplicate field names in one registry throw", () => {
  assert.throws(
    () =>
      verifyAllLabels(dualDict(), {
        now: NOW,
        keys: KEYS,
        structuredFieldTypesByLabel: {
          merchant: {
            "x-quota": "dictionary",
            "X-QUOTA": "list",
          },
        },
      }),
    /maps field .* twice/,
  );
});
