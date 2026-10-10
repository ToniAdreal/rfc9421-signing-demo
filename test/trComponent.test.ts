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

function makeReq(overrides: Partial<RequestLike> = {}): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-checksum": "header-value", "content-type": "application/json" },
    trailers: { "x-checksum": "trailer-value" },
    body: "hello",
    ...overrides,
  };
}

function signTr(covered: string[] = ["@method", "x-checksum;tr"], req: RequestLike = makeReq()) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(req, {
    keyId: "tr-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("golden: ;tr line resolves from trailers, not headers", () => {
  const base = buildSignatureBase(["x-checksum;tr"], makeReq(), {});
  assert.equal(
    base,
    `"x-checksum";tr: trailer-value\n"@signature-params": ("x-checksum";tr)`,
  );
});

test("sign→verify round-trip: trailer field verifies under ;tr", () => {
  const { publicKey, signed } = signTr();
  assert.match(signed.headers["signature-input"], /"x-checksum";tr/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", "x-checksum;tr"]);
  assert.deepEqual(signed.trailers, { "x-checksum": "trailer-value" });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("trailer value tampered: verification fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signTr();
  const tampered = { ...signed, trailers: { "x-checksum": "forged-value" } };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("header/trailer isolation: changing only the same-name header does not affect a ;tr signature, and vice versa", () => {
  const { publicKey, signed } = signTr();
  const headerChanged = {
    ...signed,
    headers: { ...signed.headers, "x-checksum": "completely-different" },
  };
  assert.equal(verifyRequest(headerChanged, { key: publicKey, now: CREATED + 60 }).ok, true);
  // Vice versa: a plain header signature ignores trailers entirely.
  const keys = generateEd25519KeyPair();
  const plain = signRequest(makeReq(), {
    keyId: "tr-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@method", "x-checksum"],
  });
  const trailerChanged = { ...plain, trailers: { "x-checksum": "completely-different" } };
  assert.equal(verifyRequest(trailerChanged, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  // A plain component and its ;tr twin coexist and bind different values.
  const both = signTr(["x-checksum", "x-checksum;tr"]);
  assert.equal(verifyRequest(both.signed, { key: both.publicKey, now: CREATED + 60 }).ok, true);
});

test("multi-value trailers join and normalize like headers", () => {
  const req = makeReq({ trailers: { "x-checksum": ["  alpha  ", "beta "] } });
  const base = buildSignatureBase(["x-checksum;tr"], req, {});
  assert.match(base, /^"x-checksum";tr: alpha, beta$/m);
  const { publicKey, signed } = signTr(["@method", "x-checksum;tr"], req);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("missing trailer field fails fast on sign and fails closed on verify", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq({ trailers: {} }), {
      keyId: "tr-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-checksum;tr"],
    }),
    /covered trailer field "x-checksum" is missing/,
  );
  // No trailers at all is the same failure — never an empty string.
  assert.throws(
    () => signRequest(makeReq({ trailers: undefined }), {
      keyId: "tr-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["x-checksum;tr"],
    }),
    /covered trailer field "x-checksum" is missing/,
  );
  const { publicKey, signed } = signTr();
  const dropped = { ...signed, trailers: {} };
  const res = verifyRequest(dropped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(res.reason ?? "", /trailer field/);
});

test('";tr" on a derived component is rejected on both sides', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => signRequest(makeReq(), {
      keyId: "tr-1", alg: "ed25519", key: privateKey, created: CREATED,
      coveredComponents: ["@method;tr"],
    }),
    /";tr" is only supported on header field components/,
  );
  const { publicKey, signed } = signTr(["@method", "x-checksum"]);
  const forged = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace('"@method"', '"@method";tr'),
    },
  };
  const res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("rejected combinations and malformed ;tr forms fail closed on both sides", () => {
  const { privateKey } = generateEd25519KeyPair();
  for (const bad of ["x-checksum;tr;bs;sf", 'x-checksum;tr;key="a";bs', "x-checksum;tr=1", "x-checksum;tr;tr"]) {
    assert.throws(
      () => signRequest(makeReq(), {
        keyId: "tr-1", alg: "ed25519", key: privateKey, created: CREATED,
        coveredComponents: [bad],
      }),
      /not compatible|does not take a value|duplicate component parameter/,
      bad,
    );
  }
  const { publicKey, signed } = signTr();
  for (const badWire of ['"x-checksum";tr;bs;sf', '"x-checksum";tr=1', '"x-checksum";tr;tr']) {
    const forged = {
      ...signed,
      headers: {
        ...signed.headers,
        "signature-input": signed.headers["signature-input"].replace('"x-checksum";tr', badWire),
      },
    };
    let res;
    assert.doesNotThrow(() => { res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 }); });
    assert.equal(res!.ok, false, badWire);
  }
});

test(";tr combines with ;req (either order): the associated request's trailer is bound, canonical form ;req;tr", () => {
  const keys = generateEd25519KeyPair();
  const associated: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers: { "x-checksum": "req-header" },
    trailers: { "x-checksum": "req-trailer" },
  };
  const response: RequestLike = {
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    headers: {},
    status: 200,
    request: associated,
  };
  const signed = signRequest(response, {
    keyId: "tr-1", alg: "ed25519", key: keys.privateKey, created: CREATED,
    coveredComponents: ["@status", "x-checksum;tr;req"],
  });
  assert.match(signed.headers["signature-input"], /"x-checksum";req;tr/);
  assert.equal(verifyRequest(signed, { key: keys.publicKey, now: CREATED + 60 }).ok, true);
  const tampered = {
    ...signed,
    request: { ...associated, trailers: { "x-checksum": "forged" } },
  };
  const res = verifyRequest(tampered, { key: keys.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test(";tr combines with ;bs: raw trailer bytes are bound", () => {
  const req = makeReq({ trailers: { "x-checksum": "abc " } });
  const { publicKey, signed } = signTr(["@method", "x-checksum;tr;bs"], req);
  assert.match(signed.headers["signature-input"], /"x-checksum";tr;bs/);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
  const stripped = { ...signed, trailers: { "x-checksum": "abc" } };
  assert.equal(verifyRequest(stripped, { key: publicKey, now: CREATED + 60 }).code, "SIGNATURE_MISMATCH");
});

test(";tr combines with ;sf and ;key on trailer values", () => {
  const sfReq = makeReq({ trailers: { "x-quota": "limit=1500,   remaining=99" } });
  const sf = signTr(["@method", "x-quota;tr;sf"], sfReq);
  assert.equal(verifyRequest(sf.signed, { key: sf.publicKey, now: CREATED + 60 }).ok, true);

  const keyReq = makeReq({ trailers: { "x-dict": "a=1, b=2" } });
  const k = signTr(["@method", 'x-dict;tr;key="b"'], keyReq);
  assert.match(k.signed.headers["signature-input"], /"x-dict";tr;key="b"/);
  assert.equal(verifyRequest(k.signed, { key: k.publicKey, now: CREATED + 60 }).ok, true);
  const unselectedChanged = { ...k.signed, trailers: { "x-dict": "a=99, b=2" } };
  assert.equal(verifyRequest(unselectedChanged, { key: k.publicKey, now: CREATED + 60 }).ok, true);
  const selectedChanged = { ...k.signed, trailers: { "x-dict": "a=1, b=3" } };
  assert.equal(verifyRequest(selectedChanged, { key: k.publicKey, now: CREATED + 60 }).code, "SIGNATURE_MISMATCH");
});

test("case-insensitive trailer lookup: Trailer field name case does not matter", () => {
  const req = makeReq({ trailers: { "X-Checksum": "trailer-value" } });
  const { publicKey, signed } = signTr(["@method", "x-checksum;tr"], req);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
});
