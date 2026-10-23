import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  ReplayCache,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

// >= 32-byte HMAC secrets: the library enforces the RFC 2104 floor on
// both the sign and verify sides.
const OLD_SECRET = secretKey("old-signing-secret-32-bytes-long!");
const NEW_SECRET = secretKey("new-signing-secret-32-bytes-long!");
const WRONG_SECRET = secretKey("wrong-signing-secret-32-bytes-lng");

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

function signHmac(
  secret: KeyObject,
  opts: {
    keyId?: string;
    nonce?: string;
    created?: number;
    expires?: number;
    label?: string;
  } = {},
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    alg: "hmac-sha256",
    key: secret,
    keyId: opts.keyId,
    nonce: opts.nonce,
    created: opts.created ?? CREATED,
    expires: opts.expires,
    label: opts.label ?? "sig1",
  });
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

test("candidateKeys: signature minted with the old secret verifies against [new, old]", () => {
  const signed = signHmac(OLD_SECRET, { keyId: "secret-2024" });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [NEW_SECRET, OLD_SECRET],
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
  assert.equal(res.keyId, "secret-2024");
});

test("candidateKeys: signature minted with the new secret verifies against [new, old]", () => {
  const signed = signHmac(NEW_SECRET, { keyId: "secret-2025" });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [NEW_SECRET, OLD_SECRET],
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "secret-2025");
});

test("candidateKeys: single `key` behavior is unchanged", () => {
  const signed = signHmac(NEW_SECRET);
  const res = verifyRequest(signed, { now: NOW, key: NEW_SECRET });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
});

test("candidateKeys: `key` + `candidateKeys` is a caller config error", () => {
  const signed = signHmac(NEW_SECRET);
  assert.throws(
    () =>
      verifyRequest(signed, {
        now: NOW,
        key: NEW_SECRET,
        candidateKeys: [NEW_SECRET],
      }),
    /mutually exclusive/,
  );
});

test("candidateKeys: `keyResolver` + `candidateKeys` is a caller config error", () => {
  const signed = signHmac(NEW_SECRET);
  assert.throws(
    () =>
      verifyRequest(signed, {
        now: NOW,
        keyResolver: () => NEW_SECRET,
        candidateKeys: [NEW_SECRET],
      }),
    /mutually exclusive/,
  );
});

test("candidateKeys: all three key sources is a caller config error", () => {
  const signed = signHmac(NEW_SECRET);
  assert.throws(
    () =>
      verifyRequest(signed, {
        now: NOW,
        key: NEW_SECRET,
        keyResolver: () => NEW_SECRET,
        candidateKeys: [NEW_SECRET],
      }),
    /mutually exclusive/,
  );
});

test("candidateKeys: empty array is a caller config error", () => {
  const signed = signHmac(NEW_SECRET);
  assert.throws(
    () => verifyRequest(signed, { now: NOW, candidateKeys: [] }),
    /non-empty array/,
  );
});

test("candidateKeys: non-KeyObject entries are caller config errors", () => {
  const signed = signHmac(NEW_SECRET);
  assert.throws(
    () =>
      verifyRequest(signed, {
        now: NOW,
        candidateKeys: ["not-a-key" as unknown as KeyObject],
      }),
    /candidateKeys\[0\].*must be a KeyObject/,
  );
  assert.throws(
    () =>
      verifyRequest(signed, {
        now: NOW,
        candidateKeys: [NEW_SECRET, null as unknown as KeyObject],
      }),
    /candidateKeys\[1\].*must be a KeyObject/,
  );
});

test("candidateKeys: second-candidate hit returns ok with alg and keyId", () => {
  const signed = signHmac(NEW_SECRET, { keyId: "secret-2025" });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [WRONG_SECRET, NEW_SECRET],
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "hmac-sha256");
  assert.equal(res.keyId, "secret-2025");
});

test("candidateKeys: all candidates mismatch returns the last SIGNATURE_MISMATCH", () => {
  const signed = signHmac(NEW_SECRET);
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [OLD_SECRET, WRONG_SECRET],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("candidateKeys: EXPIRED short-circuits the walk even when a later candidate would match", () => {
  const signed = signHmac(OLD_SECRET, {
    created: CREATED - 7200,
    expires: CREATED - 3600,
  });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [WRONG_SECRET, OLD_SECRET],
  });
  // WRONG mismatches, OLD passes crypto, then the freshness verdict
  // returns immediately — rotation never relaxes expiry.
  assert.equal(res.ok, false);
  assert.equal(res.code, "EXPIRED");
});

test("candidateKeys: MISSING_NONCE short-circuits the walk", () => {
  const signed = signHmac(NEW_SECRET); // no nonce
  const res = verifyRequest(signed, {
    now: NOW,
    requireNonce: true,
    candidateKeys: [WRONG_SECRET, NEW_SECRET],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_NONCE");
});

test("candidateKeys: NONCE_REPLAY short-circuits the walk", () => {
  const cache = new ReplayCache();
  const signed = signHmac(NEW_SECRET, { nonce: "rotation-nonce-1" });
  const opts = {
    now: NOW,
    candidateKeys: [NEW_SECRET, WRONG_SECRET],
    replayCache: cache,
  };
  const first = verifyRequest(signed, opts);
  assert.equal(first.ok, true);
  const second = verifyRequest(signed, opts);
  // If the walk continued past the replay verdict it would try
  // WRONG_SECRET next and report SIGNATURE_MISMATCH.
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
});

test("candidateKeys: failed crypto attempts never pollute the replay cache", () => {
  const cache = new ReplayCache();
  const signed = signHmac(NEW_SECRET, { nonce: "rotation-nonce-2" });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [WRONG_SECRET],
    replayCache: cache,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.stats().size, 0);
  assert.equal(cache.stats().misses, 0);
});

test("candidateKeys: verifyAllLabels walks candidates independently per label", () => {
  const a = signHmac(OLD_SECRET, { label: "merchant", keyId: "old" });
  const b = signHmac(NEW_SECRET, { label: "gateway", keyId: "new" });
  const merged = mergeSignatures(a, b);
  const results = verifyAllLabels(merged, {
    now: NOW,
    candidateKeys: [NEW_SECRET, OLD_SECRET],
  });
  assert.equal(results.length, 2);
  // merchant: NEW_SECRET mismatches, OLD_SECRET hits.
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "old");
  // gateway: NEW_SECRET hits on the first candidate.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].keyId, "new");
});

test("candidateKeys: ed25519 key rotation, new key wins when listed second", () => {
  const oldPair = generateEd25519KeyPair();
  const newPair = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: newPair.privateKey,
    keyId: "ed-2025",
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    now: NOW,
    candidateKeys: [oldPair.publicKey, newPair.publicKey],
  });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "ed25519");
  assert.equal(res.keyId, "ed-2025");
});
