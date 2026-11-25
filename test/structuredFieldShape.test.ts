import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalizeStructuredFieldValue,
  canonicalizeStructuredFieldValueAs,
  serializeDictionaryMemberValue,
} from "../src/index.js";

// Backlog #1379: the three string helpers in `src/structuredFields.ts`
// dereferenced `value` with no shape guard, so a `null` input escaped
// as a bare `TypeError` (`reading 'replace'`) instead of the library's
// named configuration error — while the `digest` / `contentDigest`
// entry points already refused a non-string body with a named
// `"body" must be a string, a Buffer, or a Uint8Array, got …` error. The helpers now
// guard first (same `"value" must be a string, got …` family, with
// `null` named explicitly instead of reporting `typeof null`).

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

function asValue(value: unknown): string {
  return value as string;
}

const BAD_VALUES: unknown[] = [null, undefined, 42, {}, []];

// --- serializeDictionaryMemberValue: value shape ---------------------------

for (const bad of BAD_VALUES) {
  test(`serializeDictionaryMemberValue rejects ${JSON.stringify(bad) ?? String(bad)} value with a named error`, () => {
    assertNamedError(
      () => serializeDictionaryMemberValue(asValue(bad), "b"),
      `serializeDictionaryMemberValue: "value" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

// --- canonicalizeStructuredFieldValue: value shape -------------------------

for (const bad of BAD_VALUES) {
  test(`canonicalizeStructuredFieldValue rejects ${JSON.stringify(bad) ?? String(bad)} value with a named error`, () => {
    assertNamedError(
      () => canonicalizeStructuredFieldValue(asValue(bad)),
      `canonicalizeStructuredFieldValue: "value" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

// --- canonicalizeStructuredFieldValueAs: value shape -----------------------

for (const bad of BAD_VALUES) {
  test(`canonicalizeStructuredFieldValueAs rejects ${JSON.stringify(bad) ?? String(bad)} value with a named error`, () => {
    assertNamedError(
      () => canonicalizeStructuredFieldValueAs(asValue(bad), "item"),
      `canonicalizeStructuredFieldValueAs: "value" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

// --- valid inputs: canonicalization output unchanged -----------------------

test("serializeDictionaryMemberValue still serializes the selected member", () => {
  assert.equal(serializeDictionaryMemberValue("a=1, b=2;x=1", "b"), "2;x=1");
  assert.equal(serializeDictionaryMemberValue("a=1, d", "d"), "?1");
  assert.equal(
    serializeDictionaryMemberValue("a=1, c=(a b c)", "c"),
    "(a b c)",
  );
});

test("canonicalizeStructuredFieldValue still canonicalizes each type", () => {
  assert.equal(canonicalizeStructuredFieldValue("a=1, b=2"), "a=1, b=2");
  assert.equal(canonicalizeStructuredFieldValue("007"), "7");
  assert.equal(canonicalizeStructuredFieldValue('"hello"'), '"hello"');
  assert.equal(canonicalizeStructuredFieldValue("  a=1 ,  b=2  "), "a=1, b=2");
});

test("canonicalizeStructuredFieldValueAs still pins the requested type", () => {
  assert.equal(
    canonicalizeStructuredFieldValueAs("a=1, b=2", "dictionary"),
    "a=1, b=2",
  );
  assert.equal(canonicalizeStructuredFieldValueAs("1, 2", "list"), "1, 2");
  assert.equal(
    canonicalizeStructuredFieldValueAs('"hello"', "item"),
    '"hello"',
  );
});

// --- existing descriptive errors unchanged ---------------------------------

test("empty value still throws the existing descriptive error", () => {
  assert.throws(
    () => serializeDictionaryMemberValue("", "a"),
    /empty value is not a valid Dictionary Structured Field/,
  );
  assert.throws(
    () => canonicalizeStructuredFieldValue("   "),
    /empty value is not a valid Structured Field/,
  );
  assert.throws(
    () => canonicalizeStructuredFieldValueAs("", "item"),
    /empty value is not a valid Structured Field/,
  );
});

test("invalid Structured Field value still throws the existing descriptive error", () => {
  assert.throws(
    () => canonicalizeStructuredFieldValue("a b c"),
    /not a valid Structured Field value/,
  );
  assert.throws(
    () => canonicalizeStructuredFieldValueAs("a b c", "dictionary"),
    /not a valid Dictionary Structured Field value/,
  );
  assert.throws(
    () => serializeDictionaryMemberValue("not a dictionary", "a"),
    /not a valid Dictionary Structured Field value/,
  );
});
