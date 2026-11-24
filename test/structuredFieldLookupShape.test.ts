import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  secretKey,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";
import { lookupStructuredFieldType } from "../src/structuredFields.js";

// Backlog #1391: `lookupStructuredFieldType` in
// `src/structuredFields.ts` dereferenced its arguments with no shape
// guard, so a `null` registry escaped as a bare `TypeError` (`Cannot
// convert undefined or null to object`), a `null` field name as
// `reading 'toLowerCase'`, and a non-object registry such as `42` was
// silently treated as "no registry" — while the sign/verify entry
// points already refuse a `null` registry through
// `assertStructuredFieldTypes`. The lookup now guards first (registry
// wording follows `assertStructuredFieldTypes`, field wording follows
// the shared `assertStringParam`), so only a caller that imports the
// helper — or `buildSignatureBase` / `resolveComponent` — directly
// can reach it.

/** The error must be a plain named `Error` with the exact message — never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, message: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, `must throw an Error: ${String(e)}`);
    assert.ok(
      !(e instanceof TypeError),
      `must be a named Error, not a bare TypeError: ${e}`,
    );
    assert.equal(e.name, "Error");
    assert.equal(e.message, message);
    return true;
  });
}

const REGISTRY_MSG =
  "lookupStructuredFieldType: `structuredFieldTypes` must be a field-name → type object";

test("null registry throws a named error, not a bare TypeError", () => {
  assertNamedError(
    () => lookupStructuredFieldType(null as never, "x-custom"),
    `${REGISTRY_MSG}, got null`,
  );
});

test("array and non-object registries throw a named error", () => {
  assertNamedError(
    () => lookupStructuredFieldType([] as never, "x-custom"),
    `${REGISTRY_MSG}, got an array`,
  );
  assertNamedError(
    () => lookupStructuredFieldType(42 as never, "x-custom"),
    `${REGISTRY_MSG}, got number`,
  );
  assertNamedError(
    () => lookupStructuredFieldType("dictionary" as never, "x-custom"),
    `${REGISTRY_MSG}, got string`,
  );
});

test("null / non-string field name throws a named error", () => {
  assertNamedError(
    () => lookupStructuredFieldType({}, null as never),
    `lookupStructuredFieldType: "field" must be a string, got null`,
  );
  assertNamedError(
    () => lookupStructuredFieldType({}, 42 as never),
    `lookupStructuredFieldType: "field" must be a string, got number`,
  );
  assertNamedError(
    () => lookupStructuredFieldType({}, undefined as never),
    `lookupStructuredFieldType: "field" must be a string, got undefined`,
  );
});

test("undefined registry still returns undefined (no registry)", () => {
  assert.equal(lookupStructuredFieldType(undefined, "x-custom"), undefined);
});

test("legal lookups are unchanged: case-insensitive, unregistered is undefined", () => {
  const registry = {
    "X-Quota": "dictionary",
    "x-list": "list",
    "X-Item": "item",
  } as const;
  assert.equal(lookupStructuredFieldType(registry, "x-quota"), "dictionary");
  assert.equal(lookupStructuredFieldType(registry, "X-QUOTA"), "dictionary");
  assert.equal(lookupStructuredFieldType(registry, "X-List"), "list");
  assert.equal(lookupStructuredFieldType(registry, "x-item"), "item");
  assert.equal(lookupStructuredFieldType(registry, "x-other"), undefined);
  assert.equal(lookupStructuredFieldType({}, "x-quota"), undefined);
});

test("an invalid registered type still throws the existing error", () => {
  assert.throws(
    () =>
      lookupStructuredFieldType(
        { "x-quota": "bogus" } as never,
        "x-quota",
      ),
    /structuredFieldTypes: field "x-quota" must be "dictionary" \| "list" \| "item", got "bogus"/,
  );
  // An invalid entry for another field is never consulted.
  assert.equal(
    lookupStructuredFieldType({ "x-other": "bogus" } as never, "x-quota"),
    undefined,
  );
});

function sfReq(): RequestLike {
  return {
    method: "GET",
    url: "https://api.example.com/v1",
    headers: { "x-custom": "a=1, b=2" },
  };
}

test("buildSignatureBase with ;sf and a null registry reports the named lookup error", () => {
  assert.throws(
    () =>
      buildSignatureBase(["x-custom;sf"], sfReq(), { created: 1700000000 }, {
        structuredFieldTypes: null as never,
      }),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /covered header field "x-custom" cannot be serialized with ";sf": lookupStructuredFieldType: `structuredFieldTypes` must be a field-name → type object, got null/,
      );
      return true;
    },
  );
});

test("buildSignatureBase with ;key and a null registry reports the named lookup error", () => {
  assert.throws(
    () =>
      buildSignatureBase(
        ['x-custom;key="a"'],
        sfReq(),
        { created: 1700000000 },
        { structuredFieldTypes: null as never },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /cannot be serialized with ";key="a"": lookupStructuredFieldType: `structuredFieldTypes` must be a field-name → type object, got null/,
      );
      return true;
    },
  );
});

test("ordering: signRequest with a null registry still reports the options assert, not the lookup guard", () => {
  assert.throws(
    () =>
      signRequest(sfReq(), {
        key: secretKey("test-secret-0123456789abcdefghij"),
        alg: "hmac-sha256",
        coveredComponents: ["x-custom;sf"],
        structuredFieldTypes: null as never,
      }),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.equal(
        e.message,
        "signRequest: `structuredFieldTypes` must be a field-name → type object, got null",
      );
      return true;
    },
  );
});

test("legal ;sf signing with a registered dictionary still verifies", () => {
  const signed = signRequest(sfReq(), {
    key: secretKey("test-secret-0123456789abcdefghij"),
    alg: "hmac-sha256",
    coveredComponents: ["@method", "x-custom;sf"],
    structuredFieldTypes: { "x-custom": "dictionary" },
  });
  const result = verifyRequest(signed, {
    key: secretKey("test-secret-0123456789abcdefghij"),
    structuredFieldTypes: { "x-custom": "dictionary" },
  });
  assert.equal(result.ok, true);
});
