import test from "node:test";
import assert from "node:assert/strict";
import {
  assertCoveredComponentsShape,
  assertLabelShape,
  assertNoDuplicateCoveredComponents,
  assertNoUnknownOptions,
  coveredComponentKey,
} from "../src/index.js";

// Backlog #1321: the five input-guard helpers exported from `src/index.ts`
// (`assertCoveredComponentsShape`, `assertLabelShape`,
// `assertNoDuplicateCoveredComponents`, `assertNoUnknownOptions`,
// `coveredComponentKey`) were only covered indirectly, through the
// `signRequest` / `verifyRequest` entry points. A regression in a guard's
// wording, caller attribution, or parameter normalization would only
// surface sideways. These tests pin each helper directly, including the
// exact error text and the `coveredComponentKey` identity the duplicate
// guard and the verify-side parser share.

// --- assertCoveredComponentsShape -------------------------------------------

test("assertCoveredComponentsShape rejects a non-array covered list", () => {
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", "content-digest"),
    /signRequest: "coveredComponents" must be an array of component identifiers$/,
  );
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", null),
    /must be an array of component identifiers/,
  );
  assert.throws(
    () => assertCoveredComponentsShape("signResponse", { 0: "@method" }),
    /signResponse: "coveredComponents" must be an array of component identifiers$/,
  );
});

test("assertCoveredComponentsShape rejects non-string and empty entries, naming the index", () => {
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", [123]),
    /signRequest: coveredComponents\[0\] must be a non-empty string, got number$/,
  );
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", ["@method", null]),
    /signRequest: coveredComponents\[1\] must be a non-empty string, got object$/,
  );
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", [""]),
    /signRequest: coveredComponents\[0\] must be a non-empty string, got string$/,
  );
  assert.throws(
    () => assertCoveredComponentsShape("signRequest", [undefined]),
    /coveredComponents\[0\] must be a non-empty string, got undefined/,
  );
});

test("assertCoveredComponentsShape accepts a valid list and an empty list", () => {
  assert.doesNotThrow(() =>
    assertCoveredComponentsShape("signRequest", [
      "@method",
      "@authority",
      "content-digest;key=\"sha-512\"",
    ]),
  );
  assert.doesNotThrow(() =>
    assertCoveredComponentsShape("signResponse", []),
  );
});

// --- assertLabelShape --------------------------------------------------------

test("assertLabelShape accepts RFC 9421 token labels", () => {
  for (const label of ["sig1", "merchant-1", "gateway.key_sig", "a", "Z9-_.~"]) {
    assert.doesNotThrow(() => assertLabelShape(label), label);
  }
});

test("assertLabelShape rejects commas, spaces, colons, slashes, and non-letter starts", () => {
  for (const label of ["sig,1", "sig 1", "sig:1", "sig/1", "1sig", "", "*sig"]) {
    assert.throws(
      () => assertLabelShape(label),
      /signRequest: "label" must be an RFC 9421 token \(start with a letter/,
      label,
    );
  }
  // The rejected value is quoted in the message, so a regression that
  // drops the value is caught too.
  assert.throws(
    () => assertLabelShape("bad label"),
    /got "bad label"$/,
  );
});

test("assertLabelShape names the caller entry point in the message", () => {
  assert.throws(
    () => assertLabelShape("bad label", "addSignature"),
    /addSignature: "label" must be an RFC 9421 token/,
  );
  assert.throws(
    () => assertLabelShape("bad label", "addResponseSignature"),
    /addResponseSignature: "label" must be an RFC 9421 token/,
  );
});

// --- assertNoDuplicateCoveredComponents -------------------------------------

test("assertNoDuplicateCoveredComponents rejects exact, case, and quoting repeats", () => {
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", ["@method", "@method"]),
    /signRequest: coveredComponents must not repeat a component, got "@method" twice$/,
  );
  // Component ids are case-insensitive (RFC 9421 §2.1).
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", ["@method", "@METHOD"]),
    /got "@METHOD" twice$/,
  );
  // Quoting is not identity either.
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", ['"@method"', "@method"]),
    /got "@method" twice$/,
  );
  // Parameter names are case-insensitive too.
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", [
        "@method;req",
        "@METHOD;REQ",
      ]),
    /got "@METHOD;REQ" twice$/,
  );
});

test("assertNoDuplicateCoveredComponents accepts ;req as distinct from the bare component", () => {
  // `;req` reroutes the binding to the associated request (RFC 9421
  // §2.2.7), so covering both is legitimate.
  assert.doesNotThrow(() =>
    assertNoDuplicateCoveredComponents("signRequest", ["@method", "@method;req"]),
  );
  assert.doesNotThrow(() =>
    assertNoDuplicateCoveredComponents("signResponse", ["@status", "@status;req"]),
  );
});

test("assertNoDuplicateCoveredComponents accepts different parameter values and orders", () => {
  // Parameter values are kept verbatim: different dictionary keys name
  // different components.
  assert.doesNotThrow(() =>
    assertNoDuplicateCoveredComponents("signRequest", [
      'content-digest;key="sha-512"',
      'content-digest;key="sha-256"',
    ]),
  );
  // Parameters are compared in listed order, so a reordering is a
  // different key.
  assert.doesNotThrow(() =>
    assertNoDuplicateCoveredComponents("signRequest", [
      'content-digest;key="sha-512";bs',
      'content-digest;bs;key="sha-512"',
    ]),
  );
});

test("assertNoDuplicateCoveredComponents names the signResponse caller", () => {
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signResponse", ["@status", "@status"]),
    /signResponse: coveredComponents must not repeat a component, got "@status" twice$/,
  );
});

// --- assertNoUnknownOptions --------------------------------------------------

test("assertNoUnknownOptions rejects a misspelled freshness key by name", () => {
  assert.throws(
    () =>
      assertNoUnknownOptions(
        { maxSignatureAge: 300 },
        ["maxSignatureAgeSec"],
        "verifyRequest",
      ),
    /invalid verifyRequest options: unknown option "maxSignatureAge"$/,
  );
  assert.throws(
    () =>
      assertNoUnknownOptions(
        { requireNonces: true },
        ["requireNonce"],
        "verifyRequest",
      ),
    /unknown option "requireNonces"/,
  );
});

test("assertNoUnknownOptions passes empty and fully-known option objects", () => {
  assert.doesNotThrow(() => assertNoUnknownOptions({}, ["keyId"], "signRequest"));
  assert.doesNotThrow(() =>
    assertNoUnknownOptions({ keyId: "k", alg: "ed25519" }, ["keyId", "alg"], "signRequest"),
  );
});

test("assertNoUnknownOptions counts an undefined-valued key as present but ignores inherited keys", () => {
  // A caller that typed the key meant it, even with no value.
  assert.throws(
    () => assertNoUnknownOptions({ typo: undefined }, ["keyId"], "signRequest"),
    /unknown option "typo"/,
  );
  // Only the object's own enumerable keys are read.
  assert.doesNotThrow(() =>
    assertNoUnknownOptions(Object.create({ typo: 1 }), ["keyId"], "signRequest"),
  );
});

// --- coveredComponentKey ------------------------------------------------------

test("coveredComponentKey folds base case, strips quotes, and trims whitespace", () => {
  assert.equal(coveredComponentKey("@method"), "@method");
  assert.equal(coveredComponentKey("@METHOD"), "@method");
  assert.equal(coveredComponentKey('"@method"'), "@method");
  assert.equal(coveredComponentKey("  @method  "), "@method");
  assert.equal(coveredComponentKey('"@PATH"'), "@path");
});

test("coveredComponentKey treats ;req as a different component and folds parameter names", () => {
  assert.notEqual(coveredComponentKey("@method;req"), coveredComponentKey("@method"));
  assert.equal(coveredComponentKey("@method;req"), coveredComponentKey("@METHOD;REQ"));
  assert.equal(coveredComponentKey("content-digest;BS"), "content-digest;bs");
  assert.equal(coveredComponentKey("@path;req"), "@path;req");
});

test("coveredComponentKey keeps parameter values verbatim and parameters in listed order", () => {
  assert.notEqual(
    coveredComponentKey('content-digest;key="sha-512"'),
    coveredComponentKey('content-digest;key="sha-256"'),
  );
  assert.notEqual(
    coveredComponentKey('content-digest;key="sha-512";bs'),
    coveredComponentKey('content-digest;bs;key="sha-512"'),
  );
  assert.equal(
    coveredComponentKey('content-digest;key="sha-512"'),
    coveredComponentKey('content-digest;KEY="sha-512"'),
  );
});
