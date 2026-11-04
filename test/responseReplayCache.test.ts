import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signResponse,
  verifyResponse,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #883: the response side inherits `replayCache` / `nonce`
// through `VerifyResponseOptions = VerifyOptions` and the thin
// `verifyResponse` -> `verifyRequest` delegation, but no response-side
// test pinned that inheritance. These cases pin it directly.
//
// Note on the backlog item's "OrThrow" clause: checked at execution
// time, there is NO `verifyResponseOrThrow` — the response API is
// documented to return wire failures, never throw them (only caller
// configuration errors throw). The throwing-variant case is therefore
// covered by its result-code equivalent: the second verification
// returns `NONCE_REPLAY` instead of throwing.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function signedResponse(
  key: ReturnType<typeof generateEd25519KeyPair>,
  nonce?: string,
): SignedHttpResponse {
  return signResponse(
    { status: 200, headers: {} },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: key.privateKey,
      created: CREATED,
      ...(nonce === undefined ? {} : { nonce }),
    },
  );
}

function verifyOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return { key: key.publicKey, now: NOW };
}

test("signed response nonce: first verify passes and records the nonce", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-replay-1");
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const first = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(first.ok, true);
  assert.equal(first.nonce, "resp-replay-1");
  assert.equal(first.label, "sig1");
  assert.equal(cache.size, 1);
});

test("same response nonce verified twice: second rejected with NONCE_REPLAY", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-replay-2");
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const first = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(first.ok, true);

  const second = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
  assert.match(second.reason ?? "", /replay/);
  assert.equal(second.nonce, "resp-replay-2");
  assert.equal(second.label, "sig1");
  // the replay itself does not add a second entry
  assert.equal(cache.size, 1);
});

test("failed verification (tampered status) does not pollute the cache", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-poison-status");
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const tampered = verifyResponse(
    { ...signed, status: 500 },
    { ...verifyOpts(keys), replayCache: cache },
  );
  assert.equal(tampered.ok, false);
  assert.equal(tampered.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.size, 0);

  // the same nonce, now on the untampered response, is still first-seen
  const corrected = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(corrected.ok, true);
  assert.equal(cache.size, 1);
  const replay = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(replay.code, "NONCE_REPLAY");
});

test("failed verification (wrong key) does not pollute the cache", () => {
  const keys = generateEd25519KeyPair();
  const other = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-poison-key");
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const wrongKey = verifyResponse(signed, {
    key: other.publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(wrongKey.ok, false);
  assert.equal(wrongKey.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.size, 0);

  const correct = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
  assert.equal(correct.ok, true);
  assert.equal(cache.size, 1);
});

test("response without nonce bypasses the cache entirely", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys);
  const cache = new ReplayCache();
  for (let i = 0; i < 2; i++) {
    const res = verifyResponse(signed, { ...verifyOpts(keys), replayCache: cache });
    assert.equal(res.ok, true);
    assert.equal(res.nonce, undefined);
  }
  assert.equal(cache.size, 0);
});

test("no cache configured: same response nonce verifies twice (backwards compatible)", () => {
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-no-cache-nonce");
  for (let i = 0; i < 2; i++) {
    const res = verifyResponse(signed, verifyOpts(keys));
    assert.equal(res.ok, true);
    assert.equal(res.nonce, "resp-no-cache-nonce");
  }
});

test("a distinct nonce passes while another nonce is already recorded", () => {
  const keys = generateEd25519KeyPair();
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const first = verifyResponse(signedResponse(keys, "resp-nonce-a"), {
    ...verifyOpts(keys),
    replayCache: cache,
  });
  assert.equal(first.ok, true);
  const second = verifyResponse(signedResponse(keys, "resp-nonce-b"), {
    ...verifyOpts(keys),
    replayCache: cache,
  });
  assert.equal(second.ok, true);
  assert.equal(cache.size, 2);
  const replay = verifyResponse(signedResponse(keys, "resp-nonce-a"), {
    ...verifyOpts(keys),
    replayCache: cache,
  });
  assert.equal(replay.code, "NONCE_REPLAY");
});

test("response nonce is reusable after the TTL expires (fake clock)", () => {
  let t = NOW;
  const cache = new ReplayCache({ ttlSec: 300, now: () => t });
  const keys = generateEd25519KeyPair();
  const signed = signedResponse(keys, "resp-ttl-nonce");
  const at = (now: number) =>
    verifyResponse(signed, { key: keys.publicKey, now, replayCache: cache });

  assert.equal(at(t).ok, true);
  assert.equal(at(t).code, "NONCE_REPLAY");
  assert.equal(cache.size, 1);

  t += 301; // past the TTL
  assert.equal(at(t).ok, true); // re-recorded with a fresh timestamp
  assert.equal(cache.size, 1);
  assert.equal(at(t).code, "NONCE_REPLAY");
});
