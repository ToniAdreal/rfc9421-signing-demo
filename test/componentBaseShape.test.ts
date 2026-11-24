import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  getHeader,
  getHeaderRaw,
  joinHeaderValues,
  parseSignatureField,
  resolveComponent,
  serializeSignatureParams,
  signatureInputValue,
} from "../src/index.js";

// Backlog #1385: the signature-base construction chain in
// `src/components.ts` dereferenced its arguments on the first line
// with no shape guard, so a direct caller passing `null` got a bare
// `TypeError` (`reading 'map'`, `reading 'trim'`, `reading
// 'headers'`, …) instead of a configuration error in the function's
// own words — and `signatureInputValue(null, [], {})` silently cast
// the label into a `"null=()"` field value, the same silent-accept
// shape backlog #1380 removed from the sign-option `label`. The
// tests below pin the guards and the unchanged legal behavior,
// including the deliberate `params` tolerance in `resolveComponent`:
// only `@created` / `@expires` read `params`, so a `null` `params`
// is still tolerated for components that do not read it.

const URL = "https://api.example.com/v1";

function paymentRequest() {
  return {
    method: "GET",
    url: URL,
    headers: {
      "content-type": "application/json",
      "x-multi": ["  a  ", "b "],
    },
  };
}

function namedError(message: string) {
  return (err: unknown) => {
    assert.ok(err instanceof Error);
    assert.ok(!(err instanceof TypeError));
    assert.equal((err as Error).message, message);
    return true;
  };
}

test("joinHeaderValues rejects null with a named error, not a TypeError", () => {
  assert.throws(
    () => joinHeaderValues(null as never),
    namedError(
      'joinHeaderValues: "values" must be an array of strings, got null',
    ),
  );
});

test("joinHeaderValues rejects non-array values with the received type named", () => {
  for (const [bad, got] of [
    ["x", "string"],
    [42, "number"],
    [{}, "object"],
    [undefined, "undefined"],
  ] as const) {
    assert.throws(
      () => joinHeaderValues(bad as never),
      namedError(
        `joinHeaderValues: "values" must be an array of strings, got ${got}`,
      ),
    );
  }
});

test("joinHeaderValues rejects non-string elements with the index named", () => {
  for (const [bad, index, got] of [
    [[null], 0, "null"],
    [[42], 0, "number"],
    [["a", null], 1, "null"],
    [["a", {}], 1, "object"],
  ] as const) {
    assert.throws(
      () => joinHeaderValues(bad as never),
      namedError(
        `joinHeaderValues: "values[${index}]" must be a string, got ${got}`,
      ),
    );
  }
});

test("joinHeaderValues still combines legal multi-value headers", () => {
  assert.equal(joinHeaderValues(["  a  ", "b "]), "a, b");
  assert.equal(joinHeaderValues(["a"]), "a");
  assert.equal(joinHeaderValues([]), "");
});

test("serializeSignatureParams rejects a null component list with a named error", () => {
  assert.throws(
    () => serializeSignatureParams(null as never, {}),
    namedError(
      'serializeSignatureParams: "componentIds" must be an array of strings, got null',
    ),
  );
});

test("serializeSignatureParams rejects null params with a named error", () => {
  assert.throws(
    () => serializeSignatureParams(["@method"], null as never),
    namedError("serializeSignatureParams: params must be an object"),
  );
});

test("serializeSignatureParams rejects non-string component entries with the index named", () => {
  assert.throws(
    () => serializeSignatureParams([null] as never, {}),
    namedError(
      'serializeSignatureParams: "componentIds[0]" must be a string, got null',
    ),
  );
  assert.throws(
    () => serializeSignatureParams(["@method", 42] as never, {}),
    namedError(
      'serializeSignatureParams: "componentIds[1]" must be a string, got number',
    ),
  );
});

test("serializeSignatureParams still serializes legal parameters byte-exactly", () => {
  assert.equal(
    serializeSignatureParams(["@method", "@path"], {
      created: 1700000000,
      expires: 1700000300,
      keyid: "test-key",
      alg: "ed25519",
      nonce: "n1",
      tag: "t1",
    }),
    '("@method" "@path");created=1700000000;expires=1700000300;keyid="test-key";alg="ed25519";nonce="n1";tag="t1"',
  );
  assert.equal(serializeSignatureParams([], {}), "()");
});

test("signatureInputValue rejects a null label with a named error, no longer casting it to \"null=()\"", () => {
  assert.throws(
    () => signatureInputValue(null as never, [], {}),
    namedError(
      'signatureInputValue: "label" must be a string, got null',
    ),
  );
});

test("signatureInputValue rejects null component list and null params through the shared guards", () => {
  assert.throws(
    () => signatureInputValue("sig1", null as never, {}),
    namedError(
      'serializeSignatureParams: "componentIds" must be an array of strings, got null',
    ),
  );
  assert.throws(
    () => signatureInputValue("sig1", [], null as never),
    namedError("serializeSignatureParams: params must be an object"),
  );
});

test("signatureInputValue still builds the legal field value", () => {
  assert.equal(
    signatureInputValue("sig1", ["@method"], { created: 1700000000 }),
    'sig1=("@method");created=1700000000',
  );
});

test("buildSignatureBase rejects a null component list, null request, and null params with named errors", () => {
  const req = paymentRequest();
  assert.throws(
    () => buildSignatureBase(null as never, req, {}),
    namedError(
      'buildSignatureBase: "componentIds" must be an array of strings, got null',
    ),
  );
  assert.throws(
    () => buildSignatureBase(["@method"], null as never, {}),
    namedError("buildSignatureBase: req must be an object"),
  );
  assert.throws(
    () => buildSignatureBase(["@method"], req, null as never),
    namedError("buildSignatureBase: params must be an object"),
  );
  assert.throws(
    () => buildSignatureBase([null] as never, req, {}),
    namedError(
      'buildSignatureBase: "componentIds[0]" must be a string, got null',
    ),
  );
});

test("buildSignatureBase still builds the legal @method base byte-exactly", () => {
  const req = paymentRequest();
  assert.equal(
    buildSignatureBase(["@method"], req, {}),
    '"@method": GET\n"@signature-params": ("@method")',
  );
  assert.equal(
    buildSignatureBase(["@method", "@path", "content-type"], req, {
      created: 1700000000,
    }),
    '"@method": GET\n"@path": /v1\n"content-type": application/json\n"@signature-params": ("@method" "@path" "content-type");created=1700000000',
  );
});

test("resolveComponent rejects a null id and a null request with named errors", () => {
  const req = paymentRequest();
  assert.throws(
    () => resolveComponent(null as never, req, {}),
    namedError('resolveComponent: "id" must be a string, got null'),
  );
  assert.throws(
    () => resolveComponent("@method", null as never, {}),
    namedError("resolveComponent: req must be an object"),
  );
});

test("resolveComponent still tolerates null params for components that do not read it", () => {
  // Deliberate ordering pin (backlog #1385): only `@created` /
  // `@expires` read `params`, so a `null` `params` is the
  // pre-existing tolerated semantic for `@method` — not tightened.
  const req = paymentRequest();
  assert.equal(resolveComponent("@method", req, null as never), "GET");
});

test("resolveComponent still resolves legal derived and header components", () => {
  const req = paymentRequest();
  assert.equal(resolveComponent("@method", req, {}), "GET");
  assert.equal(resolveComponent("@path", req, {}), "/v1");
  assert.equal(resolveComponent("content-type", req, {}), "application/json");
});

test("getHeader and getHeaderRaw reject a null name with a named error", () => {
  const headers = { a: "b" };
  assert.throws(
    () => getHeader(headers, null as never),
    namedError('getHeader: "name" must be a string, got null'),
  );
  assert.throws(
    () => getHeaderRaw(headers, null as never),
    namedError('getHeaderRaw: "name" must be a string, got null'),
  );
});

test("getHeader and getHeaderRaw still look up case-insensitively", () => {
  const req = paymentRequest();
  assert.equal(getHeader(req.headers, "CONTENT-TYPE"), "application/json");
  assert.equal(getHeader(req.headers, "x-multi"), "a, b");
  assert.equal(getHeaderRaw(req.headers, "x-multi"), "  a  , b ");
  assert.equal(getHeader(req.headers, "missing"), undefined);
  assert.equal(getHeaderRaw(req.headers, "missing"), undefined);
});

test("parseSignatureField rejects null fieldValue and null label with named errors", () => {
  assert.throws(
    () => parseSignatureField(null as never, "sig1"),
    namedError(
      'parseSignatureField: "fieldValue" must be a string, got null',
    ),
  );
  assert.throws(
    () => parseSignatureField("sig1=:aGVsbG8=:", null as never),
    namedError('parseSignatureField: "label" must be a string, got null'),
  );
});

test("parseSignatureField still reports a truly missing label as \"not present\"", () => {
  assert.throws(
    () => parseSignatureField("sig1=:aGVsbG8=:", "sig2"),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        'signature "sig2" not present in Signature field',
      );
      return true;
    },
  );
});

test("parseSignatureField still extracts the legal signature bytes", () => {
  assert.equal(
    parseSignatureField("sig1=:aGVsbG8=:, other=:d29ybGQ=:", "other").toString(
      "utf8",
    ),
    "world",
  );
  assert.equal(
    parseSignatureField("sig1=:aGVsbG8=:", "sig1").toString("utf8"),
    "hello",
  );
});
