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

function makeReq(url: string): RequestLike {
  return { method: "GET", url, headers: {} };
}

function signQP(url: string, covered: string[]) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(url), {
    keyId: "qp-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("golden: @query-param line binds only the named parameter's value", () => {
  const base = buildSignatureBase(
    ['@query-param;name="amount"'],
    makeReq("https://api.example.com/pay?order=42&amount=100"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@query-param";name="amount": 100\n` +
      `"@signature-params": ("@query-param";name="amount");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("golden: RFC 9421 §2.2.8 example — baz, empty qux, param", () => {
  // The RFC's own example request and component values (an empty
  // valueString yields an empty component value, so the qux line ends
  // with the separator space and nothing after it).
  const base = buildSignatureBase(
    ['@query-param;name="baz"', '@query-param;name="qux"', '@query-param;name="param"'],
    makeReq("https://www.example.com/path?param=value&foo=bar&baz=batman&qux="),
    {},
  );
  assert.equal(
    base,
    `"@query-param";name="baz": batman\n` +
      `"@query-param";name="qux": \n` +
      `"@query-param";name="param": value\n` +
      `"@signature-params": ("@query-param";name="baz" "@query-param";name="qux" "@query-param";name="param")`,
  );
});

test("sign→verify round-trip with a single bound parameter", () => {
  const { publicKey, signed } = signQP(
    "https://api.example.com/pay?order=42&amount=100&currency=USD",
    ["@method", '@query-param;name="amount"'],
  );
  assert.match(signed.headers["signature-input"], /"@query-param";name="amount"/);
  const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
  assert.deepEqual(parsed.componentIds, ["@method", '@query-param;name="amount"']);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("tampering the bound parameter's value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signQP(
    "https://api.example.com/pay?order=42&amount=100",
    ["@method", '@query-param;name="amount"'],
  );
  const tampered = { ...signed, url: "https://api.example.com/pay?order=42&amount=999" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("unbound parameters may be reordered, added, or removed without breaking verification", () => {
  const { publicKey, signed } = signQP(
    "https://api.example.com/pay?order=42&amount=100&currency=USD",
    ["@method", '@query-param;name="amount"'],
  );
  for (const url of [
    "https://api.example.com/pay?currency=USD&amount=100&order=42", // reordered
    "https://api.example.com/pay?order=42&amount=100&currency=USD&utm=x", // added
    "https://api.example.com/pay?amount=100", // unbound ones removed
  ]) {
    const res = verifyRequest({ ...signed, url }, { key: publicKey, now: CREATED + 60 });
    assert.equal(res.ok, true, url);
  }
});

test("missing named parameter fails fast on the sign side", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq("https://api.example.com/pay?order=42"), {
        keyId: "qp-1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ['@query-param;name="amount"'],
      }),
    /covered query parameter "amount" does not occur/,
  );
});

test("missing named parameter fails closed on the verify side", () => {
  const { publicKey, signed } = signQP(
    "https://api.example.com/pay?order=42&amount=100",
    ["@method", '@query-param;name="amount"'],
  );
  const stripped = { ...signed, url: "https://api.example.com/pay?order=42" };
  const res = verifyRequest(stripped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("parameter with no value binds the empty string (?flag and ?flag= agree)", () => {
  for (const url of [
    "https://api.example.com/x?flag&x=1",
    "https://api.example.com/x?flag=&x=1",
  ]) {
    const base = buildSignatureBase(['@query-param;name="flag"'], makeReq(url), {});
    assert.equal(base.split("\n")[0], `"@query-param";name="flag": `);
  }
  const { publicKey, signed } = signQP("https://api.example.com/x?flag&x=1", [
    '@query-param;name="flag"',
  ]);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
  // Giving the flag a value afterwards changes the bound component.
  const tampered = { ...signed, url: "https://api.example.com/x?flag=1&x=1" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("a repeated parameter name must not be covered (sign throws, verify fails closed)", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeReq("https://api.example.com/pay?amount=1&amount=2"), {
        keyId: "qp-1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ['@query-param;name="amount"'],
      }),
    /occurs 2 times.*must not be covered/,
  );
  const { publicKey, signed } = signQP("https://api.example.com/pay?amount=1", [
    '@query-param;name="amount"',
  ]);
  const duplicated = { ...signed, url: "https://api.example.com/pay?amount=1&amount=1" };
  const res = verifyRequest(duplicated, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("golden: RFC 9421 §2.2.8 encoding example — decoded values are percent-encoded after encoding", () => {
  const req = makeReq(
    "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace",
  );
  assert.equal(
    buildSignatureBase(['@query-param;name="var"'], req, {}).split("\n")[0],
    `"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value`,
  );
  // `+` in the wire value decodes to a space and re-encodes as %20.
  assert.equal(
    buildSignatureBase(['@query-param;name="bar"'], req, {}).split("\n")[0],
    `"@query-param";name="bar": with%20plus%20whitespace`,
  );
});

test("equivalent encodings of the bound value verify interchangeably (%20 vs +)", () => {
  const { publicKey, signed } = signQP("https://api.example.com/search?q=hello%20world", [
    '@query-param;name="q"',
  ]);
  const respelled = { ...signed, url: "https://api.example.com/search?q=hello+world" };
  assert.equal(verifyRequest(respelled, { key: publicKey, now: CREATED + 60 }).ok, true);
  const changed = { ...signed, url: "https://api.example.com/search?q=hello%20there" };
  const res = verifyRequest(changed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("percent-encoded parameter names are addressed by their encoded form", () => {
  // RFC 9421 §2.2.8 example name: the decoded name is `façade": ` and
  // its encoded form — the ;name value — is fa%C3%A7ade%22%3A%20.
  const url = "https://www.example.com/parameters?fa%C3%A7ade%22%3A%20=something";
  const base = buildSignatureBase(['@query-param;name="fa%C3%A7ade%22%3A%20"'], makeReq(url), {});
  assert.equal(base.split("\n")[0], `"@query-param";name="fa%C3%A7ade%22%3A%20": something`);
  const { publicKey, signed } = signQP(url, ['@query-param;name="fa%C3%A7ade%22%3A%20"']);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("several named parameters may be covered in any order", () => {
  const { publicKey, signed } = signQP(
    "https://api.example.com/pay?order=42&amount=100&currency=USD",
    ['@query-param;name="currency"', '@query-param;name="order"'],
  );
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
  const tampered = { ...signed, url: "https://api.example.com/pay?order=43&amount=100&currency=USD" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test(";req combination: a response signature can bind one parameter of its request", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/pay?order=42&amount=100",
    headers: {},
  };
  const response: RequestLike = {
    method: "GET",
    url: "https://api.example.com/callback",
    headers: {},
    status: 200,
    request,
  };
  const signed = signRequest(response, {
    keyId: "qp-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@status", '@query-param;req;name="order"'],
  });
  // Canonical wire form puts ;req before ;name regardless of input order.
  assert.match(signed.headers["signature-input"], /"@query-param";req;name="order"/);
  assert.equal(verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok, true);
  const transplanted = {
    ...signed,
    request: { ...request, url: "https://api.example.com/pay?order=99&amount=100" },
  };
  const res = verifyRequest(transplanted, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("malformed ;name usage fails closed on both sides", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const url = "https://api.example.com/pay?amount=100";
  const badCovered: [string[], RegExp][] = [
    [["@query-param"], /requires the ";name" component parameter/],
    [['@query-param;name=""'], /not a non-empty percent-encoded query parameter name/],
    [["@query-param;name=amount"], /requires a quoted string value/],
    [['@query-param;name="a";name="b"'], /duplicate component parameter/],
    [['@method;name="amount"'], /only supported on the "@query-param" derived component/],
    [['x-note;name="amount"'], /only supported on the "@query-param" derived component/],
    [['@query-param;name="amount";bs'], /";name" and ";bs" are not compatible/],
    [['@query-param;name="amount";sf'], /";name" and ";sf" are not compatible/],
    [['@query-param;name="amount";key="a"'], /";name" and ";key" are not compatible/],
    [['@query-param;name="amount";tr'], /";name" and ";tr" are not compatible/],
  ];
  for (const [covered, pattern] of badCovered) {
    assert.throws(
      () =>
        signRequest(makeReq(url), {
          keyId: "qp-1",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: covered,
        }),
      pattern,
      covered.join(" "),
    );
  }
  // Verify side: a wire identifier stripped of its ;name must not be
  // silently rebuilt — base construction fails closed.
  const { signed } = signQP(url, ['@query-param;name="amount"']);
  const forged = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        '"@query-param";name="amount"',
        '"@query-param"',
      ),
    },
  };
  const res = verifyRequest(forged, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});
