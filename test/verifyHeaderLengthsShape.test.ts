import test from "node:test";
import assert from "node:assert/strict";
import {
  checkSignatureHeaderLengths,
  DEFAULT_MAX_SIGNATURE_INPUT_LENGTH,
  DEFAULT_MAX_SIGNATURE_LENGTH,
} from "../src/verify.js";

// Backlog #1394: `checkSignatureHeaderLengths` in `src/verify.ts`
// read `opts.maxSignatureInputLength` with no shape guard, so a
// `null` `opts` escaped as a bare `TypeError` (`Cannot read
// properties of null (reading 'maxSignatureInputLength')`). The
// function is a module-level export (not on the package entry
// point), and the package entry points (`verifyRequest`,
// `verifyAllLabels`, the response side) already guard their own
// `opts` — so only a caller that imports this helper directly
// could reach the bare `TypeError`. It now guards `opts` first
// with the shared `assertObjectParam`, the same guard the entry
// points use. The `sigInput` / `sigField` `undefined` tolerance
// (a missing header is skipped here) is unchanged.

/** The error must be a plain named `Error` with the exact message — never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, message: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, `must throw an Error: ${String(e)}`);
    assert.ok(
      !(e instanceof TypeError),
      `must not be a bare TypeError: ${(e as Error).message}`,
    );
    assert.equal((e as Error).message, message);
    return true;
  });
}

const NAMED = "checkSignatureHeaderLengths: opts must be an object";

test("null opts throws a named Error, not a bare TypeError", () => {
  assertNamedError(
    () =>
      checkSignatureHeaderLengths(
        null as unknown as string,
        null as unknown as string,
        null as unknown as Parameters<typeof checkSignatureHeaderLengths>[2],
        "sig1",
      ),
    NAMED,
  );
});

test("undefined opts throws the same named Error", () => {
  assertNamedError(
    () =>
      checkSignatureHeaderLengths(
        "sig-input",
        "sig",
        undefined as unknown as Parameters<typeof checkSignatureHeaderLengths>[2],
        "sig1",
      ),
    NAMED,
  );
});

test("array and non-object opts throw the same named Error", () => {
  for (const bad of [[], "opts", 42, true]) {
    assertNamedError(
      () =>
        checkSignatureHeaderLengths(
          "sig-input",
          "sig",
          bad as unknown as Parameters<typeof checkSignatureHeaderLengths>[2],
          "sig1",
        ),
      NAMED,
    );
  }
});

test("{} opts with both headers undefined returns undefined", () => {
  assert.equal(
    checkSignatureHeaderLengths(undefined, undefined, {}, "sig1"),
    undefined,
  );
});

test("over-limit signature-input still returns SIGNATURE_INPUT_TOO_LARGE", () => {
  const over = "x".repeat(DEFAULT_MAX_SIGNATURE_INPUT_LENGTH + 1);
  const result = checkSignatureHeaderLengths(over, undefined, {}, "sig1");
  assert.ok(result);
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_INPUT_TOO_LARGE");
  assert.equal(result.label, "sig1");
});

test("over-limit signature still returns SIGNATURE_TOO_LARGE", () => {
  const over = "y".repeat(DEFAULT_MAX_SIGNATURE_LENGTH + 1);
  const result = checkSignatureHeaderLengths(undefined, over, {}, "sig1");
  assert.ok(result);
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_TOO_LARGE");
  assert.equal(result.label, "sig1");
});

test("in-bounds headers with a custom limit return undefined", () => {
  assert.equal(
    checkSignatureHeaderLengths("sig-input", "sig", { maxSignatureInputLength: 16 }, "sig1"),
    undefined,
  );
  const overCustom = checkSignatureHeaderLengths(
    "12345678901234567",
    undefined,
    { maxSignatureInputLength: 16 },
    "sig1",
  );
  assert.ok(overCustom);
  assert.equal(overCustom.code, "SIGNATURE_INPUT_TOO_LARGE");
});

test("illegal limit configuration error is unchanged", () => {
  assert.throws(
    () =>
      checkSignatureHeaderLengths(undefined, undefined, { maxSignatureInputLength: 0 }, "sig1"),
    (e: unknown) =>
      e instanceof Error &&
      !(e instanceof TypeError) &&
      e.message ===
        "verifyRequest: `maxSignatureInputLength` must be a positive integer (bytes), got 0",
  );
  assert.throws(
    () =>
      checkSignatureHeaderLengths(undefined, undefined, { maxSignatureLength: -5 }, "sig1"),
    (e: unknown) =>
      e instanceof Error &&
      !(e instanceof TypeError) &&
      e.message ===
        "verifyRequest: `maxSignatureLength` must be a positive integer (bytes), got -5",
  );
});

test("guard runs before the limit checks", () => {
  // A null opts must report the shape error even when the headers
  // would also be over any limit — the guard is first.
  assertNamedError(
    () =>
      checkSignatureHeaderLengths(
        "x".repeat(DEFAULT_MAX_SIGNATURE_INPUT_LENGTH + 1),
        "y".repeat(DEFAULT_MAX_SIGNATURE_LENGTH + 1),
        null as unknown as Parameters<typeof checkSignatureHeaderLengths>[2],
        "sig1",
      ),
    NAMED,
  );
});
