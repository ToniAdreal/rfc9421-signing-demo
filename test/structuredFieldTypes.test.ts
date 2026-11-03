import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  canonicalizeStructuredFieldValueAs,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
  type StructuredFieldType,
} from "../src/index.js";

const CREATED = 1700000000;

function makeReq(headers: Record<string, string>): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers,
  };
}

function sign(
  req: RequestLike,
  covered: string[],
  registry?: Record<string, StructuredFieldType>,
) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "sf-types-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
    ...(registry !== undefined ? { structuredFieldTypes: registry } : {}),
  });
  return { ...keys, signed };
}

test("canonicalizeStructuredFieldValueAs parses exactly the registered type", () => {
  assert.equal(
    canonicalizeStructuredFieldValueAs("a=1,  b=2", "dictionary"),
    "a=1, b=2",
  );
  assert.equal(
    canonicalizeStructuredFieldValueAs('"a" ,  "b"', "list"),
    '"a", "b"',
  );
  assert.equal(canonicalizeStructuredFieldValueAs("1.5", "item"), "1.500");
  // A Dictionary-shaped value is not a List, and a List-shaped value
  // is not an Item — the single-type parser does not rescue either.
  assert.throws(
    () => canonicalizeStructuredFieldValueAs("a=1", "list"),
    /not a valid List Structured Field value/,
  );
  assert.throws(
    () => canonicalizeStructuredFieldValueAs("(1 2), 3", "item"),
    /not a valid Item Structured Field value/,
  );
});

test("registered dictionary: sign→verify round-trip", () => {
  const { publicKey, signed } = sign(
    makeReq({ "x-quota": "limit=1500, remaining=99" }),
    ["@method", "x-quota;sf"],
    { "x-quota": "dictionary" },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  assert.equal(res.ok, true);
});

test("registered list rejects a Dictionary-shaped value on the sign side", () => {
  // Default trial order would rescue "a=1" via Dictionary; the
  // registry must not: a field known to be a List is not a Dictionary.
  assert.equal(
    canonicalizeStructuredFieldValue("a=1"),
    "a=1",
  );
  assert.throws(
    () =>
      sign(makeReq({ "x-quota": "a=1" }), ["x-quota;sf"], {
        "x-quota": "list",
      }),
    /cannot be serialized with ";sf"/,
  );
});

test("registered list mismatch fails closed on the verify side", () => {
  // Minted without a registry (Dictionary trial wins); verified with
  // a List registry: the base cannot be rebuilt under the registered
  // type, so verification fails with the base-build code, not by
  // falling back to the trial order and reporting a mismatch.
  const { publicKey, signed } = sign(makeReq({ "x-quota": "a=1" }), [
    "x-quota;sf",
  ]);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-quota": "list" },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("registered item rejects a List-shaped value on both sides", () => {
  const req = makeReq({ "x-list": "(1 2), 3" });
  // Default trial order parses it as a List.
  assert.equal(
    buildSignatureBase(["x-list;sf"], req, {}),
    `"x-list";sf: (1 2), 3\n"@signature-params": ("x-list";sf)`,
  );
  assert.throws(
    () => sign(req, ["x-list;sf"], { "x-list": "item" }),
    /cannot be serialized with ";sf"/,
  );
  const { publicKey, signed } = sign(req, ["x-list;sf"]);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-list": "item" },
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("registered list parses a single-member list value", () => {
  const { publicKey, signed } = sign(
    makeReq({ "x-list": "tok" }),
    ["x-list;sf"],
    { "x-list": "list" },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-list": "list" },
  });
  assert.equal(res.ok, true);
});

test("unregistered fields keep the trial order alongside a registered field", () => {
  const { publicKey, signed } = sign(
    makeReq({ "x-quota": "a=1", "x-other": '"x",  "y"' }),
    ["x-quota;sf", "x-other;sf"],
    { "x-quota": "dictionary" },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  assert.equal(res.ok, true);
});

test("field names match case-insensitively", () => {
  const { publicKey, signed } = sign(
    makeReq({ "x-quota": "a=1" }),
    ["x-quota;sf"],
    { "X-Quota": "dictionary" },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "X-QUOTA": "dictionary" },
  });
  assert.equal(res.ok, true);
  // And the case-folded key still pins the type: a List registry
  // under a different case still rejects the Dictionary value.
  assert.throws(
    () =>
      sign(makeReq({ "x-quota": "a=1" }), ["x-quota;sf"], {
        "X-Quota": "list",
      }),
    /cannot be serialized with ";sf"/,
  );
});

test("illegal registry values fail fast on both sides, even for uncovered fields", () => {
  const badType = { "x-quota": "set" } as unknown as Record<
    string,
    StructuredFieldType
  >;
  const emptyField = { "": "list" } as Record<string, StructuredFieldType>;
  const caseDuplicate = {
    "x-quota": "dictionary",
    "X-Quota": "list",
  } as Record<string, StructuredFieldType>;
  for (const registry of [badType, emptyField, caseDuplicate]) {
    // Sign side: throws even when the registered field is not covered.
    assert.throws(
      () => sign(makeReq({ "x-quota": "a=1" }), ["@method"], registry),
      /structuredFieldTypes/,
    );
    // Verify side: a caller configuration error, thrown, not a result.
    const { publicKey, signed } = sign(makeReq({ "x-quota": "a=1" }), [
      "x-quota;sf",
    ]);
    assert.throws(
      () =>
        verifyRequest(signed, {
          key: publicKey,
          now: CREATED + 60,
          structuredFieldTypes: registry,
        }),
      /structuredFieldTypes/,
    );
  }
});

test("registry applies through ;req;sf and ;tr;sf combinations", () => {
  // ;req: the field lives on the associated request.
  const associated: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": "a=1" },
  };
  const reqWithAssociated: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: {},
    request: associated,
  };
  const { publicKey, signed } = sign(
    reqWithAssociated,
    ["x-quota;req;sf"],
    { "x-quota": "dictionary" },
  );
  assert.equal(
    verifyRequest(signed, {
      key: publicKey,
      now: CREATED + 60,
      structuredFieldTypes: { "x-quota": "dictionary" },
    }).ok,
    true,
  );
  // A List registry on the same ;req field fails the sign side.
  assert.throws(
    () =>
      sign(reqWithAssociated, ["x-quota;req;sf"], { "x-quota": "list" }),
    /cannot be serialized with ";sf"/,
  );

  // ;tr: the field lives in the trailers.
  const reqWithTrailers: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: {},
    trailers: { "x-quota": "a=1, b=2" },
  };
  const second = sign(reqWithTrailers, ["x-quota;tr;sf"], {
    "x-quota": "dictionary",
  });
  assert.equal(
    verifyRequest(second.signed, {
      key: second.publicKey,
      now: CREATED + 60,
      structuredFieldTypes: { "x-quota": "dictionary" },
    }).ok,
    true,
  );
});

test("registry does not change ;key or ;bs paths for the same field", () => {
  // ;key selects one Dictionary member by its own rule, ;bs binds raw
  // bytes: a registry entry for the field changes neither, and both
  // still round-trip. ;sf combined with either still fails closed.
  const req = makeReq({ "x-dict": "a=1, b=2" });
  const keyed = sign(req, ['x-dict;key="b"'], { "x-dict": "dictionary" });
  assert.equal(
    verifyRequest(keyed.signed, {
      key: keyed.publicKey,
      now: CREATED + 60,
      structuredFieldTypes: { "x-dict": "dictionary" },
    }).ok,
    true,
  );
  const raw = sign(req, ["x-dict;bs"], { "x-dict": "dictionary" });
  assert.equal(
    verifyRequest(raw.signed, {
      key: raw.publicKey,
      now: CREATED + 60,
      structuredFieldTypes: { "x-dict": "dictionary" },
    }).ok,
    true,
  );
  assert.throws(
    () => sign(req, ["x-dict;sf;bs"], { "x-dict": "dictionary" }),
    /not compatible/,
  );
  assert.throws(
    () => sign(req, ['x-dict;sf;key="b"'], { "x-dict": "dictionary" }),
    /not compatible/,
  );
});

test("verifyAllLabels reports each label independently under a registry", () => {
  const keys1 = generateEd25519KeyPair();
  const keys2 = generateEd25519KeyPair();
  const first = signRequest(makeReq({ "x-quota": "a=1" }), {
    keyId: "sf-types-1",
    alg: "ed25519",
    key: keys1.privateKey,
    created: CREATED,
    coveredComponents: ["x-quota;sf"],
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  const both = addSignature(first, {
    label: "sig2",
    keyId: "sf-types-2",
    alg: "ed25519",
    key: keys2.privateKey,
    created: CREATED,
    coveredComponents: ["x-quota;sf"],
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  const results = verifyAllLabels(both, {
    keys: { sig1: keys1.publicKey, sig2: keys2.publicKey },
    now: CREATED + 60,
    structuredFieldTypes: { "x-quota": "dictionary" },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["sig1", true],
      ["sig2", true],
    ],
  );

  // Minted without a registry, verified with a mismatched one: the
  // first label's failure does not block the second label's report.
  const plainFirst = signRequest(makeReq({ "x-quota": "a=1" }), {
    keyId: "sf-types-1",
    alg: "ed25519",
    key: keys1.privateKey,
    created: CREATED,
    coveredComponents: ["x-quota;sf"],
  });
  const plainBoth = addSignature(plainFirst, {
    label: "sig2",
    keyId: "sf-types-2",
    alg: "ed25519",
    key: keys2.privateKey,
    created: CREATED,
    coveredComponents: ["x-quota;sf"],
  });
  const mismatched = verifyAllLabels(plainBoth, {
    keys: { sig1: keys1.publicKey, sig2: keys2.publicKey },
    now: CREATED + 60,
    structuredFieldTypes: { "x-quota": "list" },
  });
  assert.deepEqual(
    mismatched.map((r) => [r.label, r.ok, r.code]),
    [
      ["sig1", false, "SIGNATURE_BASE_BUILD_FAILED"],
      ["sig2", false, "SIGNATURE_BASE_BUILD_FAILED"],
    ],
  );
});

test("buildSignatureBase honors the registry option directly", () => {
  const req = makeReq({ "x-quota": "a=1" });
  assert.equal(
    buildSignatureBase(["x-quota;sf"], req, {}),
    `"x-quota";sf: a=1\n"@signature-params": ("x-quota";sf)`,
  );
  assert.throws(
    () =>
      buildSignatureBase(["x-quota;sf"], req, {}, {
        structuredFieldTypes: { "x-quota": "list" },
      }),
    /cannot be serialized with ";sf"/,
  );
});

test("registry is caller configuration, never wire data", () => {
  const { signed } = sign(
    makeReq({ "x-quota": "a=1" }),
    ["x-quota;sf"],
    { "x-quota": "dictionary" },
  );
  assert.doesNotMatch(
    signed.headers["signature-input"],
    /structuredFieldTypes|dictionary/,
  );
});
