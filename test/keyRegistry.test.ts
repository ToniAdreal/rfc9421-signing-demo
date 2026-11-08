import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type RequestLike,
  type SignedHttpRequest,
  type StructuredFieldType,
} from "../src/index.js";

// Backlog #985: `;key` consults the `structuredFieldTypes` registry,
// the same registry `;sf` uses — so the two parameters agree on what
// type a field is, instead of `;key` always parsing as a Dictionary.

const CREATED = 1700000000;
const NOW = CREATED + 60;
// Dictionary fixture in the shape gateways sign member-wise.
const DICT = "a=1, b=2;x=1;y=2, c=(a b c), d";
// A genuine List value: two strings, no `=` anywhere.
const LIST = '"a", "b"';

function makeReq(value: string = DICT, field = "x-dict"): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { [field]: value },
    body: "hello",
  };
}

function signKey(
  covered: string[] = ["@method", 'x-dict;key="b"'],
  value?: string,
  registry?: Record<string, StructuredFieldType>,
) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(value), {
    keyId: "key-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
    ...(registry !== undefined ? { structuredFieldTypes: registry } : {}),
  });
  return { ...keys, signed };
}

function verifySigned(
  signed: SignedHttpRequest,
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  registry?: Record<string, StructuredFieldType>,
) {
  return verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    ...(registry !== undefined ? { structuredFieldTypes: registry } : {}),
  });
}

test("registered dictionary: ;key extracts the same member as unregistered", () => {
  const registry = { "x-dict": "dictionary" } as const;
  const base = buildSignatureBase(['x-dict;key="b"'], makeReq(), {}, {
    structuredFieldTypes: registry,
  });
  // Identical bytes to the unregistered golden in keyComponent.test.ts.
  assert.equal(
    base,
    `"x-dict";key="b": 2;x=1;y=2\n"@signature-params": ("x-dict";key="b")`,
  );
  const { publicKey, signed } = signKey(
    ["@method", 'x-dict;key="b"'],
    undefined,
    registry,
  );
  assert.equal(verifySigned(signed, publicKey, registry).ok, true);
});

test("registered list: sign side throws and names the registered type", () => {
  // DICT is a perfectly valid Dictionary — without the registry check
  // `;key` would silently sign member b. The registry must refuse.
  assert.throws(
    () =>
      signKey(["@method", 'x-dict;key="b"'], undefined, {
        "x-dict": "list",
      }),
    /registered as a "list" Structured Field/,
  );
  assert.throws(
    () =>
      signKey(["@method", 'x-dict;key="b"'], undefined, {
        "x-dict": "list",
      }),
    /cannot be serialized with ";key="b"/,
  );
});

test("registered list: verify side returns SIGNATURE_BASE_BUILD_FAILED, never throws", () => {
  const { publicKey, signed } = signKey();
  let res;
  assert.doesNotThrow(() => {
    res = verifySigned(signed, publicKey, { "x-dict": "list" });
  });
  assert.equal(res!.ok, false);
  assert.equal(res!.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(res!.reason ?? "", /registered as a "list" Structured Field/);
});

test("registered item: sign side throws and names the registered type", () => {
  assert.throws(
    () =>
      signKey(["@method", 'x-dict;key="b"'], undefined, {
        "x-dict": "item",
      }),
    /registered as a "item" Structured Field/,
  );
});

test("registered item: verify side returns SIGNATURE_BASE_BUILD_FAILED, never throws", () => {
  const { publicKey, signed } = signKey();
  let res;
  assert.doesNotThrow(() => {
    res = verifySigned(signed, publicKey, { "x-dict": "item" });
  });
  assert.equal(res!.ok, false);
  assert.equal(res!.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(res!.reason ?? "", /registered as a "item" Structured Field/);
});

test("unregistered field: ;key behavior is unchanged", () => {
  const base = buildSignatureBase(['x-dict;key="b"'], makeReq(), {});
  assert.equal(
    base,
    `"x-dict";key="b": 2;x=1;y=2\n"@signature-params": ("x-dict";key="b")`,
  );
  const { publicKey, signed } = signKey();
  assert.equal(verifySigned(signed, publicKey).ok, true);
});

test(";sf and ;key agree on a list-registered field", () => {
  const registry = { "x-list": "list" } as const;
  // `;sf` serializes the field as the List it is registered as.
  assert.equal(
    buildSignatureBase(["x-list;sf"], makeReq(LIST, "x-list"), {}, {
      structuredFieldTypes: registry,
    }).split("\n")[0],
    `"x-list";sf: "a", "b"`,
  );
  const keys = generateEd25519KeyPair();
  const sfSigned = signRequest(makeReq(LIST, "x-list"), {
    keyId: "key-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: ["x-list;sf"],
    structuredFieldTypes: registry,
  });
  assert.equal(
    verifyRequest(sfSigned, {
      key: keys.publicKey,
      now: NOW,
      structuredFieldTypes: registry,
    }).ok,
    true,
  );
  // `;key` on the very same registered field fails closed instead of
  // parsing the List value as a Dictionary.
  assert.throws(
    () =>
      signRequest(makeReq(LIST, "x-list"), {
        keyId: "key-1",
        alg: "ed25519",
        key: keys.privateKey,
        created: CREATED,
        coveredComponents: ['x-list;key="a"'],
        structuredFieldTypes: registry,
      }),
    /registered as a "list" Structured Field/,
  );
});

test(";sf and ;key agree on a dictionary-registered field", () => {
  const registry = { "x-dict": "dictionary" } as const;
  // `;sf` canonicalizes the field as a Dictionary …
  assert.equal(
    buildSignatureBase(["x-dict;sf"], makeReq(), {}, {
      structuredFieldTypes: registry,
    }).split("\n")[0],
    `"x-dict";sf: a=1, b=2;x=1;y=2, c=(a b c), d`,
  );
  // … and `;key` extracts a member of that same Dictionary.
  assert.equal(
    buildSignatureBase(['x-dict;key="b"'], makeReq(), {}, {
      structuredFieldTypes: registry,
    }).split("\n")[0],
    `"x-dict";key="b": 2;x=1;y=2`,
  );
});

test("registry lookup is case-insensitive for ;key", () => {
  // Header field names are case-insensitive, so a registry entry
  // spelled "X-Dict" still gates the "x-dict" header.
  assert.throws(
    () =>
      signKey(["@method", 'x-dict;key="b"'], undefined, {
        "X-Dict": "list",
      }),
    /registered as a "list" Structured Field/,
  );
});

test("verifyRequestOrThrow raises VerifyError with SIGNATURE_BASE_BUILD_FAILED", () => {
  const { publicKey, signed } = signKey();
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: NOW,
        structuredFieldTypes: { "x-dict": "list" },
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "SIGNATURE_BASE_BUILD_FAILED",
  );
});

test("verifyAllLabels: per-label registry gates ;key for that label only", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const signLabel = (
    label: string,
    keys: ReturnType<typeof generateEd25519KeyPair>,
    covered: string[],
  ) =>
    signRequest(makeReq(), {
      label,
      keyId: `${label}-key-1`,
      alg: "ed25519",
      key: keys.privateKey,
      created: CREATED,
      coveredComponents: covered,
    });
  const merchantSigned = signLabel("merchant", merchant, [
    "@method",
    'x-dict;key="b"',
  ]);
  const gatewaySigned = signLabel("gateway", gateway, ["@method"]);
  const dual: SignedHttpRequest = {
    ...merchantSigned,
    headers: {
      ...merchantSigned.headers,
      "signature-input": `${merchantSigned.headers["signature-input"]}, ${gatewaySigned.headers["signature-input"]}`,
      signature: `${merchantSigned.headers["signature"]}, ${gatewaySigned.headers["signature"]}`,
    },
  };
  const results = verifyAllLabels(dual, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    structuredFieldTypesByLabel: {
      merchant: { "x-dict": "list" },
    },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  // The gateway label has no per-label registry, so it falls back to
  // the (unset) global registry and verifies normally.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});
