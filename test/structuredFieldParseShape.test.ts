import test from "node:test";
import assert from "node:assert/strict";
import {
  assertStringParam,
  listSignatureLabels,
  parseSignatureInput,
} from "../src/index.js";

// Backlog #1354: the two exported structured-field parse helpers
// dereferenced their arguments with no shape guard, so a `null`
// field value / label escaped as a bare `TypeError` (`reading
// 'length'` in `listSignatureLabels`, `reading 'replace'` in
// `escapeRegExp` for `parseSignatureInput`) instead of the library's
// named configuration error — and a `null` field value in
// `parseSignatureInput` was even misreported as `"not present"`,
// because `RegExp.exec` coerces it to the string `"null"`. The shared
// `assertStringParam` guard now runs first in both functions (same
// `contentDigest` / `digest` `"must be a string, got …"` family, with
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

function asFieldValue(value: unknown): string {
  return value as string;
}
function asLabel(value: unknown): string {
  return value as string;
}

// A dual-signed Signature-Input wire value, hand-written (no signing
// involved — the parse helpers only read the field text).
const DUAL_INPUT =
  'sig1=("@method" "@path");created=1618884473;keyid="test-key-1";alg="ed25519", ' +
  'sig2=("@authority" "@query");created=1618884474;keyid="test-key-2";alg="hmac-sha256"';
const SINGLE_INPUT =
  'sig1=("@method" "@path");created=1618884473;keyid="test-key-1";alg="ed25519";nonce="abc123"';

// --- listSignatureLabels: fieldValue shape ----------------------------------

for (const bad of [null, undefined, 42, {}, []]) {
  test(`listSignatureLabels rejects ${JSON.stringify(bad) ?? String(bad)} fieldValue with a named error`, () => {
    assertNamedError(
      () => listSignatureLabels(asFieldValue(bad)),
      `listSignatureLabels: "fieldValue" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

test("listSignatureLabels rejects a non-string fieldValue that is a String object", () => {
  // A boxed String is an object, not a string primitive — still a caller bug.
  assertNamedError(
    () => listSignatureLabels(new String(DUAL_INPUT) as unknown as string),
    'listSignatureLabels: "fieldValue" must be a string, got object',
  );
});

// --- parseSignatureInput: fieldValue / label shape --------------------------

for (const bad of [null, undefined, 42, {}, []]) {
  test(`parseSignatureInput rejects ${JSON.stringify(bad) ?? String(bad)} fieldValue with a named error`, () => {
    assertNamedError(
      () => parseSignatureInput(asFieldValue(bad), "sig1"),
      `parseSignatureInput: "fieldValue" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

for (const bad of [null, undefined, 42, {}, []]) {
  test(`parseSignatureInput rejects ${JSON.stringify(bad) ?? String(bad)} label with a named error`, () => {
    assertNamedError(
      () => parseSignatureInput(DUAL_INPUT, asLabel(bad)),
      `parseSignatureInput: "label" must be a string, got ${bad === null ? "null" : typeof bad}`,
    );
  });
}

test("parseSignatureInput rejects a null fieldValue with the guard, not the old misleading 'not present'", () => {
  // Before the guard, RegExp.exec coerced null to "null" and the
  // caller got `signature "sig1" not present in Signature-Input` —
  // a lie about a label that is plainly present in the wire value.
  assertNamedError(
    () => parseSignatureInput(asFieldValue(null), "sig1"),
    'parseSignatureInput: "fieldValue" must be a string, got null',
  );
});

// --- legal behavior unchanged -----------------------------------------------

test("listSignatureLabels still lists both labels in wire order, duplicates once", () => {
  assert.deepEqual(listSignatureLabels(DUAL_INPUT), ["sig1", "sig2"]);
  assert.deepEqual(
    listSignatureLabels(`${DUAL_INPUT}, sig1=("@status");created=1618884475`),
    ["sig1", "sig2"],
  );
  assert.deepEqual(listSignatureLabels(SINGLE_INPUT), ["sig1"]);
});

test("parseSignatureInput still parses both labels with components and params", () => {
  const first = parseSignatureInput(DUAL_INPUT, "sig1");
  assert.equal(first.label, "sig1");
  assert.deepEqual(first.componentIds, ["@method", "@path"]);
  assert.equal(first.params.created, 1618884473);
  assert.equal(first.params.keyid, "test-key-1");
  assert.equal(first.params.alg, "ed25519");
  const second = parseSignatureInput(DUAL_INPUT, "sig2");
  assert.equal(second.label, "sig2");
  assert.deepEqual(second.componentIds, ["@authority", "@query"]);
  assert.equal(second.params.alg, "hmac-sha256");
  const single = parseSignatureInput(SINGLE_INPUT, "sig1");
  assert.equal(single.params.nonce, "abc123");
});

test("parseSignatureInput still reports a genuinely absent label as 'not present'", () => {
  assert.throws(
    () => parseSignatureInput(DUAL_INPUT, "sig9"),
    (e: unknown) => {
      assert.ok(e instanceof Error && !(e instanceof TypeError));
      assert.equal(
        e.message,
        'signature "sig9" not present in Signature-Input',
      );
      return true;
    },
  );
});

test("listSignatureLabels still rejects a malformed member with its own error", () => {
  assert.throws(
    () => listSignatureLabels("not-a-member"),
    (e: unknown) => {
      assert.ok(e instanceof Error && !(e instanceof TypeError));
      assert.match(e.message, /malformed Signature-Input member/);
      return true;
    },
  );
});

// --- shared helper, pinned directly -----------------------------------------

test("assertStringParam accepts a string and rejects null/non-strings with the caller-named message", () => {
  assertStringParam("listSignatureLabels", "fieldValue", DUAL_INPUT);
  assertNamedError(
    () => assertStringParam("listSignatureLabels", "fieldValue", null),
    'listSignatureLabels: "fieldValue" must be a string, got null',
  );
  assertNamedError(
    () => assertStringParam("parseSignatureInput", "label", 42),
    'parseSignatureInput: "label" must be a string, got number',
  );
});
