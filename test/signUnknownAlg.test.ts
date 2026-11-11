import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  generateRsaPssKeyPair,
  secretKey,
  signRequest,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #1058: the verify side already pins unknown wire algs
// (`test/negative.test.ts`: `alg="ed448"` → `UNSUPPORTED_ALG`), but
// the sign side had no equivalent test — and its error was wrong.
// `signRequest` rejected unknown algs through the key-shape predicate,
// so `alg: "none"` was misreported as "incompatible with the key",
// and the `unsupported alg` branch at the end of the crypto dispatch
// could never be reached by an unknown value. `signRequest` now guards
// unknown algs up front with `unsupported alg` (that branch stays only
// as the exhaustiveness guard), and these tests pin both sides,
// including the classic downgrade value `"none"` and the
// case-sensitivity of algorithm names (neither side folds case — a
// miscased `"ED25519"` is unsupported, not ed25519).

const CREATED = 1700000000;

function req(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function signedEd(): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(req(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  return { signed, publicKey, privateKey };
}

function tamperAlg(
  signed: SignedHttpRequest,
  alg: string,
): SignedHttpRequest {
  return {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'alg="ed25519"',
        `alg="${alg}"`,
      ),
    },
  };
}

test('signing with alg "none" throws unsupported alg, input untouched', () => {
  const { privateKey } = generateEd25519KeyPair();
  const input = req();
  const before = JSON.stringify(input);
  assert.throws(
    () =>
      signRequest(input, {
        alg: "none" as never,
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message === 'signRequest: unsupported alg "none"',
  );
  // No signature was minted and the caller's request was not mutated:
  // the failure happens before the base is built or any header written.
  assert.equal(JSON.stringify(input), before);
  assert.equal("signature" in input.headers, false);
  assert.equal("signature-input" in input.headers, false);
});

test('signing with alg "ed448" throws unsupported alg, input untouched', () => {
  const { privateKey } = generateEd25519KeyPair();
  const input = req();
  const before = JSON.stringify(input);
  assert.throws(
    () =>
      signRequest(input, {
        alg: "ed448" as never,
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message === 'signRequest: unsupported alg "ed448"',
  );
  assert.equal(JSON.stringify(input), before);
});

test('signing with alg "none" and an HMAC key still reports unsupported alg', () => {
  // The guard runs before the shape check: with any other key the old
  // code would have said "incompatible with the key" instead.
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "none" as never,
        key: secretKey("a".repeat(32)),
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message === 'signRequest: unsupported alg "none"',
  );
});

test('signing with miscased alg "ED25519" throws unsupported alg', () => {
  // Algorithm names are matched exactly on both sides — no case
  // folding, so a miscased name is unknown, not ed25519.
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "ED25519" as never,
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message === 'signRequest: unsupported alg "ED25519"',
  );
});

test("signing with an empty alg throws unsupported alg", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "" as never,
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error && e.message === 'signRequest: unsupported alg ""',
  );
});

test("known alg with a mismatched key still reports incompatible, not unsupported", () => {
  // The guard must not swallow the shape check: a real algorithm
  // paired with the wrong key shape keeps the key-mismatch wording.
  const { privateKey } = generateRsaPssKeyPair();
  assert.throws(
    () =>
      signRequest(req(), {
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message ===
        'signRequest: alg "ed25519" is incompatible with the key (an asymmetric rsa key) — pass a key of the matching type for the algorithm',
  );
});

test("addSignature inherits the unknown-alg guard", () => {
  // addSignature requires an already-signed request (it appends a
  // second label); the guard is reached through its inner signRequest.
  const { signed, privateKey } = signedEd();
  assert.throws(
    () =>
      addSignature(signed, {
        label: "sig2",
        alg: "none" as never,
        key: privateKey,
        created: CREATED,
      }),
    (e: unknown) =>
      e instanceof Error &&
      e.message === 'signRequest: unsupported alg "none"',
  );
});

test("positive control: a known alg still signs and verifies", () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test('verifying a signature-input with alg "none" returns UNSUPPORTED_ALG', () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(tamperAlg(signed, "none"), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "UNSUPPORTED_ALG");
  assert.equal(res.reason, 'unsupported alg "none"');
});

test('verifying a signature-input with miscased alg "ED25519" returns UNSUPPORTED_ALG', () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(tamperAlg(signed, "ED25519"), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "UNSUPPORTED_ALG");
  assert.equal(res.reason, 'unsupported alg "ED25519"');
});
