import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  parseSignatureInput,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
// Trailing space + embedded comma: exactly the bytes plain field-value
// normalization would erase or make ambiguous.
const RAW_VALUE = "ch_42, settled ";

function makeReq(value: string = RAW_VALUE): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-charge-ref": value },
    body: "hello",
  };
}

function signBs(covered: string[] = ["@method", "x-charge-ref;bs"], value = RAW_VALUE) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(value), {
    keyId: "bs-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("golden: ;bs line is the raw value as a :base64: byte sequence", () => {
  const base = buildSignatureBase(["x-charge-ref;bs"], makeReq(), {});
  const expectedB64 = Buffer.from(RAW_VALUE, "utf8").toString("base64");
  assert.equal(
    base,
    `"x-charge-ref";bs: :${expectedB64}:\n"@signature-params": ("x-charge-ref";bs)`,
  );
});

test("sign→verify round-trip: header with trailing whitespace and a comma verifies under ;bs", () => {
  const { publicKey, signed } = signBs();
  assert.match(signed.headers["signature-input"], /"x-charge-ref";bs/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", "x-charge-ref;bs"]);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("ambiguity contrast: without ;bs a stripped trailing space still verifies; with ;bs it fails", () => {
  // Plain component: normalizeFieldValue strips the trailing space, so
  // "… " and "…" canonicalize identically — the ambiguity ;bs removes.
  const keys = generateEd25519KeyPair();
  const plain = signRequest(makeReq(), {
    keyId: "bs-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@method", "x-charge-ref"],
  });
  const plainStripped = { ...plain, headers: { ...plain.headers, "x-charge-ref": RAW_VALUE.trimEnd() } };
  assert.equal(verifyRequest(plainStripped, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  // ;bs component: the raw bytes are bound, so the same strip is a tamper.
  const { publicKey, signed } = signBs();
  const bsStripped = { ...signed, headers: { ...signed.headers, "x-charge-ref": RAW_VALUE.trimEnd() } };
  const res = verifyRequest(bsStripped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampering one byte of a ;bs header value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signBs();
  const tampered = { ...signed, headers: { ...signed.headers, "x-charge-ref": "ch_43, settled " } };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test('";bs" on a derived component is rejected on the sign side', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq(), {
      keyId: "bs-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["@method;bs"],
    }),
    /";bs" is only supported on header field components/,
  );
});

test('";bs" on a derived component fails closed (not throws) on the verify side', () => {
  const { publicKey, signed } = signBs(["@method", "x-charge-ref"]);
  const forged = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace('"@method"', '"@method";bs'),
    },
  };
  const res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test(";bs coexists with ordinary and derived components in one signature", () => {
  const { publicKey, signed } = signBs(["@method", "@path", "x-charge-ref;bs", "content-digest"]);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test(";bs combines with ;req (either order): raw bytes of the associated request header are bound", () => {
  const keys = generateEd25519KeyPair();
  const associated: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-charge-ref": RAW_VALUE },
  };
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: associated,
  };
  // Caller wrote ;bs before ;req; the canonical wire form is ;req;bs.
  const signed = signRequest(response, {
    keyId: "bs-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@status", "x-charge-ref;bs;req"],
  });
  assert.match(signed.headers["signature-input"], /"x-charge-ref";req;bs/);
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  const tampered = {
    ...signed,
    request: { ...associated, headers: { "x-charge-ref": RAW_VALUE.trimEnd() } },
  };
  const res = verifyRequest(tampered, { key: keys.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("malformed/unsupported ;bs forms never throw out of verifyRequest (fuzz-style)", () => {
  const { publicKey, signed } = signBs();
  for (const bad of ['"x-charge-ref";bs=1', '"x-charge-ref";bs;bs', '"x-charge-ref";bs;sf', '"x-charge-ref";bs;req;req']) {
    const forged = {
      ...signed,
      headers: {
        ...signed.headers,
        "signature-input": signed.headers["signature-input"].replace('"x-charge-ref";bs', bad),
      },
    };
    let res;
    assert.doesNotThrow(() => { res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 }); });
    assert.equal(res!.ok, false, bad);
  }
});

test(";bs on a missing header fails fast on sign and fails closed on verify", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest({ method: "GET", url: "https://api.example.com/", headers: {} }, {
      keyId: "bs-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-absent;bs"],
    }),
    /covered header field "x-absent" is missing/,
  );
  const { publicKey, signed } = signBs();
  const { "x-charge-ref": _dropped, ...restHeaders } = signed.headers;
  const res = verifyRequest({ ...signed, headers: restHeaders }, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});
