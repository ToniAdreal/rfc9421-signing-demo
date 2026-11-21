import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  serializeSignatureParams,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;

test("empty component list with no params serializes to ()", () => {
  assert.equal(serializeSignatureParams([], {}), "()");
});

test("empty component list with params keeps only the params", () => {
  // Same case the demo corpus pins (backlog #320): no covered
  // components, created + keyid + nonce, hand-pinned here.
  assert.equal(
    serializeSignatureParams([], {
      created: 1618884473,
      keyid: "test-key-rsa-pss",
      nonce: "b3k2pp5k7z-50gnwp.yemd",
    }),
    '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
  );
});

test("single @method with no params", () => {
  assert.equal(serializeSignatureParams(["@method"], {}), '("@method")');
});

test(";bs parameter position on @query", () => {
  assert.equal(serializeSignatureParams(["@query;bs"], {}), '("@query";bs)');
});

test(";sf parameter position on a header field; ;name position on @query-param", () => {
  assert.equal(
    serializeSignatureParams(["x-charge-ref;sf"], {}),
    '("x-charge-ref";sf)',
  );
  assert.equal(
    serializeSignatureParams(['@query-param;name="a"'], {}),
    '("@query-param";name="a")',
  );
  // ;name and ;sf are incompatible by design: ;name selects one query
  // parameter of the request target, ;sf transforms an HTTP field
  // value — the serializer fails closed instead of emitting a wire
  // form no verifier would accept.
  assert.throws(
    () => serializeSignatureParams(['@query-param;name="a";sf'], {}),
    /";name" and ";sf" are not compatible/,
  );
});

test("parameter values escape double quotes and backslashes", () => {
  // keyid value ke"y\1: the backslash doubles first, then the quote
  // is escaped — the wire form never carries a raw quote.
  assert.equal(
    serializeSignatureParams(["@method"], { keyid: 'ke"y\\1' }),
    '("@method");keyid="ke\\"y\\\\1"',
  );
});

test("nonce carrying a quote and a backslash escapes both", () => {
  // Same escaped case the demo corpus pins (backlog #320).
  assert.equal(
    serializeSignatureParams(["@method"], {
      created: CREATED,
      keyid: "k",
      alg: "ed25519",
      nonce: 'a"b\\c d',
    }),
    '("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
  );
});

test("two components keep the caller's order", () => {
  assert.equal(
    serializeSignatureParams(["@path", "@method"], {}),
    '("@path" "@method")',
  );
  assert.equal(
    serializeSignatureParams(["@method", "@path"], {}),
    '("@method" "@path")',
  );
});

test("per-component parameters canonicalize regardless of input order", () => {
  // ;name precedes ;sf and ;req precedes ;tr on the wire even when
  // the caller wrote them the other way round. (;name never co-occurs
  // with ;sf — the two are incompatible by design — so the ;name
  // reorder case pairs it with ;req instead.)
  assert.equal(
    serializeSignatureParams(['@query-param;name="a";req'], {}),
    '("@query-param";req;name="a")',
  );
  assert.equal(
    serializeSignatureParams(["@method;tr;req"], {}),
    '("@method";req;tr)',
  );
});

test("all six signature parameters serialize in fixed order", () => {
  // Object keys are deliberately scrambled: the wire order is always
  // created, expires, keyid, alg, nonce, tag.
  assert.equal(
    serializeSignatureParams(["@method", "@authority", "@path", "content-digest"], {
      tag: "payment-webhook-v1",
      nonce: "demo-nonce-001",
      alg: "ed25519",
      keyid: "demo-key-1",
      expires: 1700000300,
      created: CREATED,
    }),
    '("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"',
  );
});

test(";bs and ;sf serialize distinctly", () => {
  assert.equal(serializeSignatureParams(["@method;bs"], {}), '("@method";bs)');
  assert.equal(serializeSignatureParams(["@method;sf"], {}), '("@method";sf)');
  assert.notEqual(
    serializeSignatureParams(["@method;bs"], {}),
    serializeSignatureParams(["@method;sf"], {}),
  );
});

test("cross-check: buildSignatureBase @signature-params line matches the serializer", () => {
  const req: RequestLike = {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {},
  };
  const componentIds = ["@method"];
  const params = { created: CREATED, keyid: "k1" };
  const base = buildSignatureBase(componentIds, req, params);
  assert.equal(
    base,
    `"@method": GET\n"@signature-params": ${serializeSignatureParams(componentIds, params)}`,
  );
  assert.equal(
    base,
    '"@method": GET\n"@signature-params": ("@method");created=1700000000;keyid="k1"',
  );
});
