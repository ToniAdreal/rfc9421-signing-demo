import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  ReplayCache,
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type RequestLike,
  type SignedHttpResponse,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path"];
const URL = "https://api.example.com/v1/payments";

function paymentRequest(): RequestLike {
  return { method: "POST", url: URL, headers: {} };
}

function handMintedSigned(params: {
  nonce?: string;
  keyid?: string;
}) {
  const kp = generateEd25519KeyPair();
  const req = paymentRequest();
  const fullParams = { created: CREATED, alg: "ed25519", ...params };
  const base = buildSignatureBase(COVERED, req, fullParams);
  const sig = edSign(null, Buffer.from(base, "utf8"), kp.privateKey);
  const signed = {
    ...req,
    headers: {
      ...req.headers,
      "signature-input": signatureInputValue("sig1", COVERED, fullParams),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  return { ...kp, signed };
}

test("a 257-character nonce fails with NONCE_TOO_LONG", () => {
  const nonce = "n".repeat(257);
  const { publicKey, signed } = handMintedSigned({ nonce });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "NONCE_TOO_LONG");
  assert.equal(
    res.reason,
    "nonce is too long: at most 256 characters, got 257",
  );
  assert.equal(res.nonce, nonce);
});

test("a 300-character nonce fails with NONCE_TOO_LONG", () => {
  const nonce = "n".repeat(300);
  const { publicKey, signed } = handMintedSigned({ nonce });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "NONCE_TOO_LONG");
});

test("a 256-character nonce still verifies (at the limit)", () => {
  const nonce = "n".repeat(256);
  const { publicKey, signed } = handMintedSigned({ nonce });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, nonce);
});

test("a legal short nonce verifies exactly as before", () => {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(), {
    alg: "ed25519",
    key: kp.privateKey,
    created: CREATED,
    nonce: "0196b2c0-0000-4000-8000-000000000000",
  });
  const res = verifyRequest(signed, { key: kp.publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "0196b2c0-0000-4000-8000-000000000000");
});

test("an over-long nonce is rejected before the replay cache, never recorded", () => {
  // The cache clock is pinned to the verifier's `now`: `verifyRequest`
  // records the nonce at the verifier's time, and `stats().size`
  // counts entries live against the cache clock — with the wall clock
  // a 2023-dated nonce would look expired immediately.
  const cache = new ReplayCache({ now: () => NOW });
  const { publicKey, signed } = handMintedSigned({
    nonce: "n".repeat(257),
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "NONCE_TOO_LONG");
  assert.deepEqual(cache.stats(), {
    size: 0,
    hits: 0,
    misses: 0,
    evictions: 0,
  });
  // The cache still works for a legal nonce afterwards.
  const kp = generateEd25519KeyPair();
  const legal = signRequest(paymentRequest(), {
    alg: "ed25519",
    key: kp.privateKey,
    created: CREATED,
    nonce: "legal-nonce-after-rejection",
  });
  const ok = verifyRequest(legal, {
    key: kp.publicKey,
    now: NOW,
    replayCache: cache,
    // Backlog #1411: the nonce-carrying signature needs a lifetime
    // bounded within the cache TTL (3600s).
    maxSignatureAgeSec: 3600,
  });
  assert.equal(ok.ok, true);
  assert.equal(cache.stats().misses, 1);
  assert.equal(cache.stats().size, 1);
});

test("an over-long nonce verified twice reports NONCE_TOO_LONG, never NONCE_REPLAY", () => {
  const cache = new ReplayCache({ now: () => NOW });
  const { publicKey, signed } = handMintedSigned({
    nonce: "n".repeat(257),
  });
  for (let i = 0; i < 2; i++) {
    const res = verifyRequest(signed, {
      key: publicKey,
      now: NOW,
      replayCache: cache,
    });
    assert.equal(res.ok, false);
    assert.equal(res.code, "NONCE_TOO_LONG");
  }
  assert.equal(cache.stats().size, 0);
});

test("verifyRequestOrThrow throws a VerifyError with code NONCE_TOO_LONG", () => {
  const { publicKey, signed } = handMintedSigned({
    nonce: "n".repeat(257),
  });
  assert.throws(
    () => verifyRequestOrThrow(signed, { key: publicKey, now: NOW }),
    (e: unknown) => {
      if (!isVerifyError(e)) return false;
      assert.equal(e.code, "NONCE_TOO_LONG");
      assert.match(e.message, /at most 256 characters, got 257/);
      return true;
    },
  );
});

test("verifyAllLabels rejects only the over-long-nonce label", () => {
  const kp1 = generateEd25519KeyPair();
  const kp2 = generateEd25519KeyPair();
  const req = paymentRequest();
  const p1 = {
    created: CREATED,
    alg: "ed25519",
    keyid: "k1",
    nonce: "merchant-nonce",
  };
  const p2 = {
    created: CREATED,
    alg: "ed25519",
    keyid: "k2",
    nonce: "n".repeat(257),
  };
  const sig1 = edSign(
    null,
    Buffer.from(buildSignatureBase(COVERED, req, p1), "utf8"),
    kp1.privateKey,
  );
  const sig2 = edSign(
    null,
    Buffer.from(buildSignatureBase(COVERED, req, p2), "utf8"),
    kp2.privateKey,
  );
  const signed = {
    ...req,
    headers: {
      "signature-input": `${signatureInputValue("sig1", COVERED, p1)}, ${signatureInputValue("sig2", COVERED, p2)}`,
      signature: `sig1=:${sig1.toString("base64")}:, sig2=:${sig2.toString("base64")}:`,
    },
  };
  const results = verifyAllLabels(signed, {
    keyResolver: (kid) =>
      kid === "k1" ? kp1.publicKey : kid === "k2" ? kp2.publicKey : undefined,
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.ok, true);
  assert.equal(results[1]?.ok, false);
  assert.equal(results[1]?.code, "NONCE_TOO_LONG");
});

// --- Response side: `verifyResponse` delegates to `verifyRequest`, so
// the cap holds there too. The response is hand-minted (see
// test/responseRequireFreshness.test.ts): `signResponse` always emits
// a legal nonce, so an over-long one has to come from a foreign signer.

function responseRequestLike(): RequestLike {
  return {
    method: "",
    url: "https://response.invalid/",
    headers: {},
    status: 200,
  };
}

function signedResponseWithNonce(
  nonce: string,
): { signed: SignedHttpResponse; publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"] } {
  const pair = generateEd25519KeyPair();
  const req = responseRequestLike();
  const params = { created: CREATED, alg: "ed25519", nonce };
  const base = buildSignatureBase(["@status"], req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    signed: {
      status: 200,
      headers: {
        "signature-input": signatureInputValue("sig1", ["@status"], params),
        signature: `sig1=:${sig.toString("base64")}:`,
      },
    },
    publicKey: pair.publicKey,
  };
}

test("verifyResponse rejects an over-long nonce with NONCE_TOO_LONG", () => {
  const { signed, publicKey } = signedResponseWithNonce("n".repeat(257));
  const res = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "NONCE_TOO_LONG");
});
