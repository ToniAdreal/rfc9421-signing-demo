import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type SignOptions,
} from "../src/index.js";

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
      keyId: "guard-fixture",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      ...opts,
    },
  );
  return { signed: s, publicKey };
}

test("expires earlier than created is rejected", () => {
  assert.throws(
    () => signed({ expires: CREATED - 1 }),
    (err: unknown) =>
      err instanceof Error &&
      /"expires" \(1699999999\) must not be earlier than "created" \(1700000000\)/.test(
        err.message,
      ) &&
      /expired at birth/.test(err.message),
  );
});

test("expires equal to created is allowed", () => {
  const { signed: s, publicKey } = signed({ expires: CREATED });
  assert.match(s.headers["signature-input"], /;expires=1700000000;/);
  // A zero-window signature verifies at exactly `created`, before `expires`.
  const res = verifyRequest(s, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("empty coveredComponents is rejected", () => {
  assert.throws(
    () => signed({ coveredComponents: [] }),
    (err: unknown) =>
      err instanceof Error &&
      /"coveredComponents" must cover at least one component/.test(err.message),
  );
});

test("fractional created is rejected (verifier would silently truncate it)", () => {
  assert.throws(
    () => signed({ created: CREATED + 0.5 }),
    (err: unknown) =>
      err instanceof Error &&
      /"created" must be an integer number of Unix seconds, got 1700000000\.5/.test(
        err.message,
      ),
  );
});

test("fractional expires is rejected", () => {
  assert.throws(
    () => signed({ expires: CREATED + 100.25 }),
    (err: unknown) =>
      err instanceof Error &&
      /"expires" must be an integer number of Unix seconds, got 1700000100\.25/.test(
        err.message,
      ),
  );
});

test("NaN and Infinity timestamps are rejected", () => {
  assert.throws(() => signed({ created: Number.NaN }), /"created" must be an integer number of Unix seconds/);
  assert.throws(
    () => signed({ expires: Number.POSITIVE_INFINITY }),
    /"expires" must be an integer number of Unix seconds/,
  );
});

test("single-component coverage still works (non-empty list is accepted)", () => {
  const { signed: s, publicKey } = signed({ coveredComponents: ["@method"] });
  assert.match(
    s.headers["signature-input"],
    /^sig1=\("@method"\);created=1700000000;/,
  );
  const res = verifyRequest(s, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("valid created+expires pair signs and verifies normally", () => {
  const { signed: s, publicKey } = signed({ expires: CREATED + 3600 });
  assert.match(s.headers["signature-input"], /;expires=1700003600;/);
  const res = verifyRequest(s, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
