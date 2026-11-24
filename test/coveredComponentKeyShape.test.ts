import test from "node:test";
import assert from "node:assert/strict";
import {
  assertNoDuplicateCoveredComponents,
  coveredComponentKey,
  generateEd25519KeyPair,
  signRequest,
} from "../src/index.js";

// Backlog #1381: `coveredComponentKey` dereferenced its argument on
// the first line (`entry.trim()`) with no shape guard, so a direct
// caller passing `null` got a bare `TypeError: Cannot read properties
// of null (reading 'trim')` instead of a configuration error in the
// helper's own words. The sign entry points were already safe —
// `assertCoveredComponentsShape` refuses a non-string list entry
// before the duplicate check runs — so this guard only fires for a
// caller that imports the helper directly (or for
// `assertNoDuplicateCoveredComponents`, which assumes the list shape
// was checked first). The tests below pin both the guard and that
// ordering.

const CREATED = 1700000000;
const URL = "https://api.example.com/v1";

function paymentRequest() {
  return { method: "GET", url: URL, headers: {} };
}

test("coveredComponentKey rejects null with a named error, not a TypeError", () => {
  assert.throws(
    () => coveredComponentKey(null),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        'coveredComponentKey: "entry" must be a string, got null',
      );
      return true;
    },
  );
});

test("coveredComponentKey rejects non-string entries with the received type named", () => {
  for (const [bad, got] of [
    [42, "number"],
    [{}, "object"],
    [[], "object"],
    [undefined, "undefined"],
    [true, "boolean"],
  ] as const) {
    assert.throws(
      () => coveredComponentKey(bad),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof TypeError));
        assert.equal(
          (err as Error).message,
          `coveredComponentKey: "entry" must be a string, got ${got}`,
        );
        return true;
      },
    );
  }
});

test("coveredComponentKey still normalizes legal keys (case, quotes, whitespace, parameters)", () => {
  assert.equal(coveredComponentKey("@method"), "@method");
  assert.equal(coveredComponentKey("@METHOD"), "@method");
  assert.equal(coveredComponentKey('"@method"'), "@method");
  assert.equal(coveredComponentKey("  @method  "), "@method");
  assert.equal(coveredComponentKey('"@PATH"'), "@path");
  assert.equal(coveredComponentKey("@method;req"), "@method;req");
  assert.equal(coveredComponentKey("@METHOD;REQ"), "@method;req");
  assert.equal(coveredComponentKey("content-digest;BS"), "content-digest;bs");
  assert.equal(
    coveredComponentKey('content-digest;key="sha-512"'),
    'content-digest;key="sha-512"',
  );
  assert.equal(
    coveredComponentKey('content-digest;KEY="sha-512"'),
    'content-digest;key="sha-512"',
  );
});

test("assertNoDuplicateCoveredComponents surfaces the helper's named error on a null entry", () => {
  // The duplicate guard assumes the list shape was checked first, so
  // a direct call with a null entry used to escape as the same bare
  // TypeError from inside coveredComponentKey.
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", [null] as never),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        'coveredComponentKey: "entry" must be a string, got null',
      );
      return true;
    },
  );
  // The duplicate check itself is unchanged for legal entries.
  assert.throws(
    () =>
      assertNoDuplicateCoveredComponents("signRequest", [
        "@method",
        "@METHOD",
      ]),
    /coveredComponents must not repeat a component, got "@METHOD" twice/,
  );
  assert.doesNotThrow(() =>
    assertNoDuplicateCoveredComponents("signRequest", [
      "@method",
      "@method;req",
    ]),
  );
});

test("signRequest still reports a null covered entry as the list-shape error, before the helper", () => {
  // Ordering pin: the entry point's own list guard runs first, so a
  // caller going through signRequest never sees the helper's error —
  // and never a bare TypeError.
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        coveredComponents: [null] as never,
      }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        'signRequest: coveredComponents[0] must be a non-empty string, got object',
      );
      return true;
    },
  );
});

test("signRequest still signs normally with legal covered components", () => {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
    coveredComponents: ["@method", "@authority", "@path"],
  });
  assert.match(signed.headers["signature-input"], /sig1=/);
  assert.match(signed.headers["signature-input"], /"@method"/);
  assert.deepEqual(signed.coveredComponents, [
    "@method",
    "@authority",
    "@path",
  ]);
});
