import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyRequest,
  type SignOptions,
} from "../src/index.js";

// Backlog #1264: `signRequest` only checked that `coveredComponents`
// was non-empty, short, and duplicate-free — it never checked the
// shape. A JS caller passing `"content-digest"` (not an array) or
// `[123]` / `[null]` crashed `covered.map((c) => c.toLowerCase())`
// (or the duplicate guard's `entry.trim()`) with a bare
// `TypeError`, not a configuration error in the entry point's own
// words. `signResponse` inherits the guard through delegation, but
// its own duplicate check runs first, so it gets the same guard
// with its own caller name.

const CREATED = 1700000000;

function signed(opts: Partial<SignOptions>) {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const s = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
    },
    {
      keyId: "covered-shape-fixture",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      ...opts,
    },
  );
  return { signed: s, publicKey };
}

function shapeError(opts: Partial<SignOptions>): Error {
  try {
    signed(opts);
  } catch (err) {
    assert.ok(err instanceof Error);
    return err;
  }
  assert.fail("expected signRequest to throw");
}

test("non-array coveredComponents (string) is rejected as a configuration error", () => {
  const err = shapeError({
    coveredComponents: "content-digest" as unknown as string[],
  });
  assert.equal(
    err.message,
    'signRequest: "coveredComponents" must be an array of component identifiers',
  );
  assert.equal(err instanceof TypeError, false);
});

test("non-array coveredComponents (object) is rejected as a configuration error", () => {
  const err = shapeError({
    coveredComponents: { "content-digest": true } as unknown as string[],
  });
  assert.equal(
    err.message,
    'signRequest: "coveredComponents" must be an array of component identifiers',
  );
});

test("non-array coveredComponents (null) is rejected as a configuration error", () => {
  const err = shapeError({
    coveredComponents: null as unknown as string[],
  });
  assert.equal(
    err.message,
    'signRequest: "coveredComponents" must be an array of component identifiers',
  );
});

test("numeric coveredComponents entry is rejected with its index", () => {
  const err = shapeError({ coveredComponents: [123] as unknown as string[] });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[0] must be a non-empty string, got number",
  );
  assert.equal(err instanceof TypeError, false);
});

test("null coveredComponents entry is rejected with its index", () => {
  const err = shapeError({
    coveredComponents: [null] as unknown as string[],
  });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[0] must be a non-empty string, got object",
  );
});

test("undefined coveredComponents entry is rejected with its index", () => {
  const err = shapeError({
    coveredComponents: [undefined] as unknown as string[],
  });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[0] must be a non-empty string, got undefined",
  );
});

test("object coveredComponents entry is rejected with its index", () => {
  const err = shapeError({
    coveredComponents: [{ "@method": true }] as unknown as string[],
  });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[0] must be a non-empty string, got object",
  );
});

test("empty-string coveredComponents entry is rejected", () => {
  const err = shapeError({ coveredComponents: [""] });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[0] must be a non-empty string, got string",
  );
});

test("bad entry after a good one names the bad index", () => {
  const err = shapeError({
    coveredComponents: ["@method", 123] as unknown as string[],
  });
  assert.equal(
    err.message,
    "signRequest: coveredComponents[1] must be a non-empty string, got number",
  );
});

test("shape error is thrown before any base is built or crypto runs", () => {
  const { privateKey } = generateEd25519KeyPair();
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  };
  const before = JSON.stringify(req);
  assert.throws(
    () =>
      signRequest(req, {
        keyId: "covered-shape-fixture",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: [123] as unknown as string[],
      }),
    (err: unknown) =>
      err instanceof Error &&
      err instanceof TypeError === false &&
      /coveredComponents\[0\] must be a non-empty string, got number/.test(
        err.message,
      ),
  );
  // The input request is untouched: no header was added, no field
  // was rewritten, nothing was built.
  assert.equal(JSON.stringify(req), before);
});

test("duplicate entries still report the duplicate error, not the shape error", () => {
  const err = shapeError({ coveredComponents: ["@method", "@method"] });
  assert.match(
    err.message,
    /signRequest: coveredComponents must not repeat a component, got "@method" twice/,
  );
});

test("legal parameterized list round-trips, including ;bs", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const withBody = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "x-custom": "abc" },
      body: JSON.stringify({ amount: 100 }),
    },
    {
      keyId: "covered-shape-fixture",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@path", "x-custom;bs"],
    },
  );
  const res = verifyRequest(withBody, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, [
    "@method",
    "@path",
    "x-custom;bs",
  ]);
});

test("legal ;req list round-trips with the triggering request attached", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const triggering = {
    method: "DELETE",
    url: "https://api.example.com/v1/payments/pi_1",
    headers: { "x-charge-id": "ch_99" },
  };
  const s = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      request: triggering,
    },
    {
      keyId: "covered-shape-fixture",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@method;req"],
    },
  );
  const res = verifyRequest(s, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("signResponse rejects a non-array coveredComponents in its own words", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {}, body: JSON.stringify({ settled: true }) },
        {
          keyId: "covered-shape-fixture",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: "content-digest" as unknown as string[],
        },
      ),
    (err: unknown) =>
      err instanceof Error &&
      err instanceof TypeError === false &&
      err.message ===
        'signResponse: "coveredComponents" must be an array of component identifiers',
  );
});

test("signResponse rejects a non-string entry before its duplicate guard", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {}, body: JSON.stringify({ settled: true }) },
        {
          keyId: "covered-shape-fixture",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: [123] as unknown as string[],
        },
      ),
    (err: unknown) =>
      err instanceof Error &&
      err instanceof TypeError === false &&
      err.message ===
        "signResponse: coveredComponents[0] must be a non-empty string, got number",
  );
});

test("signResponse rejects an explicit null coveredComponents", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {}, body: JSON.stringify({ settled: true }) },
        {
          keyId: "covered-shape-fixture",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: null as unknown as string[],
        },
      ),
    (err: unknown) =>
      err instanceof Error &&
      err instanceof TypeError === false &&
      err.message ===
        'signResponse: "coveredComponents" must be an array of component identifiers',
  );
});
