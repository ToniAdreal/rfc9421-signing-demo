import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  parseSignatureInput,
  serializeDictionaryMemberValue,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
// Dictionary fixture in the shape gateways sign member-wise: several
// members, one with parameters, one inner list, one bare (Boolean) key.
const DICT = "a=1, b=2;x=1;y=2, c=(a b c), d";

function makeReq(value: string = DICT): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-dict": value },
    body: "hello",
  };
}

function signKey(covered: string[] = ["@method", 'x-dict;key="b"'], value?: string) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(value), {
    keyId: "key-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("golden: ;key line contains only the selected member's strict serialization", () => {
  const base = buildSignatureBase(['x-dict;key="b"'], makeReq(), {});
  assert.equal(
    base,
    `"x-dict";key="b": 2;x=1;y=2\n"@signature-params": ("x-dict";key="b")`,
  );
});

test("golden variants: item, bare key, and inner-list members serialize per RFC 8941 §4.1.2", () => {
  assert.equal(
    buildSignatureBase(['x-dict;key="a"'], makeReq(), {}).split("\n")[0],
    `"x-dict";key="a": 1`,
  );
  // A bare dictionary key is a Boolean-true member: ?1, key not included.
  assert.equal(
    buildSignatureBase(['x-dict;key="d"'], makeReq(), {}).split("\n")[0],
    `"x-dict";key="d": ?1`,
  );
  assert.equal(
    buildSignatureBase(['x-dict;key="c"'], makeReq(), {}).split("\n")[0],
    `"x-dict";key="c": (a b c)`,
  );
});

test("serializeDictionaryMemberValue: direct member extraction", () => {
  assert.equal(serializeDictionaryMemberValue(DICT, "b"), "2;x=1;y=2");
  assert.equal(serializeDictionaryMemberValue("n=1.5", "n"), "1.500");
  assert.throws(() => serializeDictionaryMemberValue(DICT, "zzz"), /not present/);
  assert.throws(() => serializeDictionaryMemberValue("hello world", "a"), /not a valid Dictionary/);
});

test("sign→verify round-trip: dictionary member verifies under ;key", () => {
  const { publicKey, signed } = signKey();
  assert.match(signed.headers["signature-input"], /"x-dict";key="b"/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", 'x-dict;key="b"']);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("unselected members may change: signature over ;key=\"b\" survives edits to a, c and d", () => {
  const { publicKey, signed } = signKey();
  const edited = {
    ...signed,
    headers: { ...signed.headers, "x-dict": "a=99, b=2;x=1;y=2, c=(x y), d=?0" },
  };
  // This is the entire point of ;key: only member b is bound.
  assert.equal(verifyRequest(edited, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("selected member tampered: verification fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signKey();
  const tampered = {
    ...signed,
    headers: { ...signed.headers, "x-dict": "a=1, b=3;x=1;y=2, c=(a b c), d" },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  // A parameter of the selected member is part of its value too.
  const paramTampered = {
    ...signed,
    headers: { ...signed.headers, "x-dict": "a=1, b=2;x=9;y=2, c=(a b c), d" },
  };
  assert.equal(
    verifyRequest(paramTampered, { key: publicKey, now: CREATED + 60 }).code,
    "SIGNATURE_MISMATCH",
  );
});

test("selected member deleted: verification fails closed (signature base cannot be rebuilt)", () => {
  const { publicKey, signed } = signKey();
  const deleted = {
    ...signed,
    headers: { ...signed.headers, "x-dict": "a=1, c=(a b c), d" },
  };
  const res = verifyRequest(deleted, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(res.reason ?? "", /dictionary member "b" is not present/);
});

test("member missing at sign time throws a clear error (no empty-string signing)", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq(), {
        keyId: "key-1", alg: "ed25519", key: privateKey, created: CREATED,
        coveredComponents: ['x-dict;key="zzz"'],
      }),
    /dictionary member "zzz" is not present/,
  );
});

test("malformed ;key forms are rejected on the sign side", () => {
  const { privateKey } = generateEd25519KeyPair();
  for (const bad of [
    "x-dict;key", // no value
    "x-dict;key=b", // unquoted token, not a string
    "x-dict;key=123", // non-string value
    'x-dict;key=""', // empty name
    'x-dict;key="B"', // uppercase: not a valid Dictionary key
    'x-dict;key="a b"', // space: not a valid Dictionary key
    'x-dict;key="a";key="b"', // duplicate parameter
  ]) {
    assert.throws(
      () =>
        signRequest(makeReq(), {
          keyId: "key-1", alg: "ed25519", key: privateKey, created: CREATED,
          coveredComponents: [bad],
        }),
      /;key|duplicate component parameter/,
      bad,
    );
  }
});

test("malformed ;key forms never throw out of verifyRequest (fuzz-style)", () => {
  const { publicKey, signed } = signKey();
  for (const bad of ['"x-dict";key', '"x-dict";key=b', '"x-dict";key="B"', '"x-dict";key="zzz"']) {
    const forged = {
      ...signed,
      headers: {
        ...signed.headers,
        "signature-input": signed.headers["signature-input"].replace('"x-dict";key="b"', bad),
      },
    };
    let res;
    assert.doesNotThrow(() => { res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 }); });
    assert.equal(res!.ok, false, bad);
  }
});

test('";key" on a derived component is rejected on the sign side', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq(), {
        keyId: "key-1", alg: "ed25519", key: privateKey, created: CREATED,
        coveredComponents: ['@method;key="a"'],
      }),
    /";key" is only supported on header field components/,
  );
});

test('";key" combined with ";bs" or ";sf" is rejected on the sign side', () => {
  const { privateKey } = generateEd25519KeyPair();
  for (const bad of ['x-dict;key="a";bs', 'x-dict;sf;key="a"', 'x-dict;key="a";sf']) {
    assert.throws(
      () =>
        signRequest(makeReq(), {
          keyId: "key-1", alg: "ed25519", key: privateKey, created: CREATED,
          coveredComponents: [bad],
        }),
      /are not compatible/,
      bad,
    );
  }
});

test('";key" combines with ";req": response signature binds a request dictionary member', () => {
  const keys = generateEd25519KeyPair();
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: {
      method: "POST",
      url: "https://api.example.com/v1/charge",
      headers: { "x-dict": DICT },
    },
  };
  const signed = signRequest(response, {
    keyId: "key-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@status", 'x-dict;req;key="b"'],
  });
  // Canonical wire order is ;req before ;key, regardless of input order.
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@status", 'x-dict;req;key="b"']);
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  const tampered = {
    ...signed,
    request: { ...signed.request!, headers: { "x-dict": "a=1, b=7;x=1;y=2, c=(a b c), d" } },
  };
  assert.equal(
    verifyRequest(tampered, { key: keys.publicKey, now: CREATED + 60 }).code,
    "SIGNATURE_MISMATCH",
  );
});

test("two ;key components in one signature bind two members independently of dictionary order", () => {
  const { publicKey, signed } = signKey(['x-dict;key="b"', 'x-dict;key="a"']);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
  const reordered = {
    ...signed,
    headers: { ...signed.headers, "x-dict": "d, c=(a b c), b=2;x=1;y=2, a=1" },
  };
  assert.equal(verifyRequest(reordered, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("non-dictionary field value fails closed with ;key on both sides", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq("just-a-plain-value"), {
        keyId: "key-1", alg: "ed25519", key: privateKey, created: CREATED,
        coveredComponents: ['x-dict;key="a"'],
      }),
    /cannot be serialized with ";key/,
  );
  const { publicKey, signed } = signKey();
  const forged = { ...signed, headers: { ...signed.headers, "x-dict": "just-a-plain-value" } };
  const res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("member re-spacing canonicalizes: sloppy member spacing still verifies under ;key", () => {
  const { publicKey, signed } = signKey(["@method", 'x-dict;key="b"'], "a=1,  b=2;x=1;   y=2, c=(a   b  c), d");
  const respaced = {
    ...signed,
    headers: { ...signed.headers, "x-dict": DICT },
  };
  assert.equal(verifyRequest(respaced, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("multi-value field combines into one dictionary before member selection", () => {
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-dict": ["a=1", "b=2;x=1;y=2"] },
  };
  const base = buildSignatureBase(['x-dict;key="b"'], req, {});
  assert.match(base, /^"x-dict";key="b": 2;x=1;y=2$/m);
  const keys = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "key-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ['x-dict;key="b"'],
  });
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
});
