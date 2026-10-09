import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  generateEd25519KeyPair,
  parseSignatureInput,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
// Dictionary value with sloppy (but Structured-Field-valid) spacing:
// the strict serialization collapses it to the canonical form below.
const SLOPPY_DICT = "a=1,  b=2;x=1;  y=2, c=(a   b  c)";
const CANONICAL_DICT = "a=1, b=2;x=1;y=2, c=(a b c)";

function makeReq(value: string = "limit=1500, remaining=99"): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": value },
    body: "hello",
  };
}

function signSf(covered: string[] = ["@method", "x-quota;sf"], value?: string) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(value), {
    keyId: "sf-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("golden: ;sf line is the RFC 8941 strict serialization of the dictionary", () => {
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "example-dict": SLOPPY_DICT },
  };
  const base = buildSignatureBase(["example-dict;sf"], req, {});
  assert.equal(
    base,
    `"example-dict";sf: ${CANONICAL_DICT}\n"@signature-params": ("example-dict";sf)`,
  );
});

test("canonicalizeStructuredFieldValue: decimal, list, byte-sequence and boolean forms", () => {
  // Decimals serialize with exactly three fractional digits.
  assert.equal(
    canonicalizeStructuredFieldValue("limit=1500, remaining=1.5"),
    "limit=1500, remaining=1.500",
  );
  assert.equal(canonicalizeStructuredFieldValue("1.5"), "1.500");
  assert.equal(canonicalizeStructuredFieldValue("007"), "7");
  // A List of strings: member separator collapses to ", ".
  assert.equal(canonicalizeStructuredFieldValue('"a" ,  "b"'), '"a", "b"');
  // Byte sequence member with a Boolean parameter.
  assert.equal(
    canonicalizeStructuredFieldValue("sig=:aGVsbG8=:;x=?0"),
    "sig=:aGVsbG8=:;x=?0",
  );
  // A bare dictionary key is a Boolean-true member and stays bare.
  assert.equal(canonicalizeStructuredFieldValue("a, b=2"), "a, b=2");
});

test("sign→verify round-trip: dictionary header verifies under ;sf", () => {
  const { publicKey, signed } = signSf();
  assert.match(signed.headers["signature-input"], /"x-quota";sf/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", "x-quota;sf"]);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("whitespace equivalence: re-spaced wire value still verifies under ;sf (plain component does not)", () => {
  const { publicKey, signed } = signSf(["@method", "x-quota;sf"], "limit=1500,   remaining=99");
  const respaced = {
    ...signed,
    headers: { ...signed.headers, "x-quota": "limit=1500, remaining=99" },
  };
  assert.equal(verifyRequest(respaced, { key: publicKey, now: CREATED + 60 }).ok, true);
  // Contrast: without ;sf the internal spacing is part of the signed
  // bytes (only leading/trailing whitespace is normalized), so the
  // same re-spacing is a signature mismatch.
  const keys = generateEd25519KeyPair();
  const plain = signRequest(makeReq("limit=1500,   remaining=99"), {
    keyId: "sf-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@method", "x-quota"],
  });
  const plainRespaced = {
    ...plain,
    headers: { ...plain.headers, "x-quota": "limit=1500, remaining=99" },
  };
  const res = verifyRequest(plainRespaced, { key: keys.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampering a ;sf member value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signSf();
  const tampered = {
    ...signed,
    headers: { ...signed.headers, "x-quota": "limit=1500, remaining=98" },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test('";sf" on a derived component is rejected on the sign side', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq(), {
      keyId: "sf-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["@method;sf"],
    }),
    /";sf" is only supported on header field components/,
  );
});

test('";sf" on a derived component fails closed (not throws) on the verify side', () => {
  const { publicKey, signed } = signSf(["@method", "x-quota"]);
  const forged = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace('"@method"', '"@method";sf'),
    },
  };
  const res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test(";sf combines with ;req: the associated request's field is strictly serialized", () => {
  const keys = generateEd25519KeyPair();
  const associated: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-quota": "limit=1500,   remaining=99" },
  };
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: associated,
  };
  // Caller wrote ;sf before ;req; the canonical wire form is ;req;sf.
  const signed = signRequest(response, {
    keyId: "sf-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@status", "x-quota;sf;req"],
  });
  assert.match(signed.headers["signature-input"], /"x-quota";req;sf/);
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  // Re-spacing the associated request's field still verifies…
  const respaced = {
    ...signed,
    request: { ...associated, headers: { "x-quota": "limit=1500, remaining=99" } },
  };
  assert.equal(verifyRequest(respaced, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  // …but changing a member value does not.
  const tampered = {
    ...signed,
    request: { ...associated, headers: { "x-quota": "limit=1500, remaining=98" } },
  };
  const res = verifyRequest(tampered, { key: keys.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test(";bs and ;sf together are rejected on the sign side and fail closed on verify", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq(), {
      keyId: "sf-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-quota;bs;sf"],
    }),
    /";bs" and ";sf" are not compatible/,
  );
  const { publicKey, signed } = signSf();
  const forged = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace('"x-quota";sf', '"x-quota";bs;sf'),
    },
  };
  let res;
  assert.doesNotThrow(() => { res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 }); });
  assert.equal(res!.ok, false);
});

test("a field value that is not a valid Structured Field fails closed on both sides", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq("a b c"), {
      keyId: "sf-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-quota;sf"],
    }),
    /covered header field "x-quota" cannot be serialized with ";sf"/,
  );
  assert.throws(() => canonicalizeStructuredFieldValue("a b c"), /not a valid Structured Field value/);
  assert.throws(() => canonicalizeStructuredFieldValue(""), /empty value/);
  // RFC 9651 Date is a Structured Field extension this library does not do.
  assert.throws(() => canonicalizeStructuredFieldValue("@1700000000"), /not a valid Structured Field value/);
  const { publicKey, signed } = signSf();
  const broken = {
    ...signed,
    headers: { ...signed.headers, "x-quota": "a b c" },
  };
  const res = verifyRequest(broken, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test(";sf on a missing header fails fast on sign", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest({ method: "GET", url: "https://api.example.com/", headers: {} }, {
      keyId: "sf-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-absent;sf"],
    }),
    /covered header field "x-absent" is missing/,
  );
});

test("multi-value field combines into one structure before ;sf serialization", () => {
  const req: RequestLike = {
    method: "GET",
    url: "https://api.example.com/",
    headers: { "x-list": ['"a"', '"b"'] },
  };
  const base = buildSignatureBase(["x-list;sf"], req, {});
  assert.match(base, /^"x-list";sf: "a", "b"$/m);
  const keys = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "sf-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["x-list;sf"],
  });
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
});

test("malformed/unsupported ;sf forms never throw out of verifyRequest (fuzz-style)", () => {
  const { publicKey, signed } = signSf();
  for (const bad of ['"x-quota";sf=1', '"x-quota";sf;sf', '"x-quota";sf;key="a"', '"x-quota";sf;tr']) {
    const forged = {
      ...signed,
      headers: {
        ...signed.headers,
        "signature-input": signed.headers["signature-input"].replace('"x-quota";sf', bad),
      },
    };
    let res;
    assert.doesNotThrow(() => { res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 }); });
    assert.equal(res!.ok, false, bad);
  }
});
