import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  secretKey,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
} from "../src/index.js";

// Backlog #873: `verifyResponse` inherits `VerifyOptions.allowedAlgs`
// from `verifyRequest` (backlog #851), but no response-side test ever
// proved it — the request side has hit/miss coverage
// (test/allowedAlgs.test.ts) plus a bench row (#860), while a gateway
// callback signed with a non-whitelisted algorithm was rejected on
// the response side only by inheritance assumption. These tests pin
// the response side directly: the whitelist gates `verifyResponse`
// exactly as it gates `verifyRequest`, and the sign side never
// filters (there is no whitelist option on `SignResponseOptions`).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

function signEd(keys: ReturnType<typeof generateEd25519KeyPair>) {
  return signResponse(response(), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
  });
}

function signHmac(secret: ReturnType<typeof secretKey>) {
  return signResponse(response(), {
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
  });
}

test("ed25519 response verifies under allowedAlgs [\"ed25519\"]", () => {
  const keys = generateEd25519KeyPair();
  const result = verifyResponse(signEd(keys), {
    key: keys.publicKey,
    now: NOW,
    allowedAlgs: ["ed25519"],
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "ed25519");
  assert.deepEqual(result.coveredComponents, ["@status", "content-digest"]);
});

test("ed25519 response under [\"hmac-sha256\"] fails verbatim ALG_NOT_ALLOWED", () => {
  const keys = generateEd25519KeyPair();
  const result = verifyResponse(signEd(keys), {
    key: keys.publicKey,
    now: NOW,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "ALG_NOT_ALLOWED");
  assert.equal(result.alg, "ed25519");
  assert.equal(result.label, "sig1");
});

test("hmac-sha256 response verifies under allowedAlgs [\"hmac-sha256\"]", () => {
  const secret = secretKey("gateway-shared-secret-at-least-32-bytes!!");
  const result = verifyResponse(signHmac(secret), {
    key: secret,
    now: NOW,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.alg, "hmac-sha256");
});

test("hmac-sha256 response under [\"ed25519\"] fails verbatim ALG_NOT_ALLOWED", () => {
  const secret = secretKey("gateway-shared-secret-at-least-32-bytes!!");
  const result = verifyResponse(signHmac(secret), {
    key: secret,
    now: NOW,
    allowedAlgs: ["ed25519"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "ALG_NOT_ALLOWED");
  assert.equal(result.alg, "hmac-sha256");
});

test("multi-alg whitelist accepts either member on the response side", () => {
  const keys = generateEd25519KeyPair();
  const result = verifyResponse(signEd(keys), {
    key: keys.publicKey,
    now: NOW,
    allowedAlgs: ["hmac-sha256", "ed25519"],
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("no whitelist (default) leaves response verification unchanged", () => {
  const keys = generateEd25519KeyPair();
  const result = verifyResponse(signEd(keys), {
    key: keys.publicKey,
    now: NOW,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("sign side is unaffected: minted signature carries alg, whitelist decides only at verify", () => {
  const keys = generateEd25519KeyPair();
  // `signResponse` takes no whitelist option at all: the minted
  // signature-input still carries alg="ed25519", and the very same
  // signature verifies under a matching whitelist but is rejected
  // under a non-matching one — the filter lives on the verify side.
  const signed = signEd(keys);
  assert.match(
    signed.headers["signature-input"] as string,
    /alg="ed25519"/,
  );
  assert.equal(
    verifyResponse(signed, {
      key: keys.publicKey,
      now: NOW,
      allowedAlgs: ["ed25519"],
    }).ok,
    true,
  );
  const denied = verifyResponse(signed, {
    key: keys.publicKey,
    now: NOW,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "ALG_NOT_ALLOWED");
});

test("whitelist gate runs before crypto: wrong key still reports ALG_NOT_ALLOWED, not SIGNATURE_MISMATCH", () => {
  const keys = generateEd25519KeyPair();
  const wrongKeys = generateEd25519KeyPair();
  const result = verifyResponse(signEd(keys), {
    key: wrongKeys.publicKey,
    now: NOW,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "ALG_NOT_ALLOWED");
});

test("body-less response (@status only) is gated the same way", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response({ body: undefined }), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
  });
  assert.equal(
    verifyResponse(signed, {
      key: keys.publicKey,
      now: NOW,
      allowedAlgs: ["ed25519"],
    }).ok,
    true,
  );
  const denied = verifyResponse(signed, {
    key: keys.publicKey,
    now: NOW,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "ALG_NOT_ALLOWED");
  assert.equal(denied.alg, "ed25519");
});
