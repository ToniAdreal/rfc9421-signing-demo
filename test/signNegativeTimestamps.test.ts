import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #1258: `assertTimestamp` only checked `Number.isInteger`, so
// `signRequest({ created: -100 })` minted a signature with
// `created=-100` on the wire. The verifier's freshness checks never
// fire on a negative `created` without an `expires` (the age check only
// runs when `maxSignatureAgeSec` is set), so the signature verified as
// one that never expires — and `expires: -5` with `created: -5` slipped
// past the `expires < created` guard as equal. Unix seconds are
// non-negative by definition, so the signer rejects negatives
// fail-fast, before any crypto runs.

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";

function signedEd(opts: {
  created?: number;
  expires?: number;
  expiresInSec?: number;
}): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      ...(opts.created !== undefined ? { created: opts.created } : {}),
      ...(opts.expires !== undefined ? { expires: opts.expires } : {}),
      ...(opts.expiresInSec !== undefined
        ? { expiresInSec: opts.expiresInSec }
        : {}),
    },
  );
  return { signed, publicKey };
}

// ---------- negative timestamps are rejected ----------

test("created: -1 is rejected with a configuration error", () => {
  assert.throws(
    () => signedEd({ created: -1 }),
    /signRequest: "created" must be a non-negative integer number of Unix seconds, got -1/,
  );
});

test("created: -100 is rejected", () => {
  assert.throws(
    () => signedEd({ created: -100 }),
    /signRequest: "created" must be a non-negative integer number of Unix seconds, got -100/,
  );
});

test("expires: -5 with a normal created is rejected", () => {
  assert.throws(
    () => signedEd({ created: CREATED, expires: -5 }),
    /signRequest: "expires" must be a non-negative integer number of Unix seconds, got -5/,
  );
});

test("created: -5 with expires: -5 is rejected (the equal pair no longer slips past)", () => {
  assert.throws(
    () => signedEd({ created: -5, expires: -5 }),
    /signRequest: "created" must be a non-negative integer number of Unix seconds, got -5/,
  );
});

test("expiresInSec with a negative created is rejected", () => {
  assert.throws(
    () => signedEd({ created: -1, expiresInSec: 300 }),
    /signRequest: "created" must be a non-negative integer number of Unix seconds, got -1/,
  );
});

test("the negative-timestamp error is a plain Error, not a TypeError", () => {
  assert.throws(
    () => signedEd({ created: -1 }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(err instanceof TypeError, false);
      return true;
    },
  );
});

test("the error message names the field and the offending value", () => {
  for (const [opts, field, value] of [
    [{ created: -7 }, "created", -7],
    [{ created: CREATED, expires: -3 }, "expires", -3],
  ] as const) {
    assert.throws(
      () => signedEd(opts),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.match(err.message, new RegExp(`"${field}"`));
        assert.match(err.message, new RegExp(`got ${value}`));
        return true;
      },
    );
  }
});

// ---------- the boundary and the old paths are unaffected ----------

test("created: 0 (the Unix epoch) is legal: it signs and verifies", () => {
  const { signed, publicKey } = signedEd({ created: 0 });
  const res = verifyRequest(signed, { key: publicKey, now: 0 });
  assert.equal(res.ok, true);
  assert.equal(res.created, 0);
});

test("normal timestamps still round-trip", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expires: CREATED + 300,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, CREATED + 300);
});

test("expires earlier than created still reports the original error", () => {
  assert.throws(
    () => signedEd({ created: CREATED, expires: CREATED - 1 }),
    /must not be earlier than "created"/,
  );
});
