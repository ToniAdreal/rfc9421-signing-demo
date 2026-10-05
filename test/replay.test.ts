import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;

function signedReq(nonce?: string) {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      ...(nonce === undefined ? {} : { nonce }),
    },
  );
  return { signed, publicKey };
}

test("same nonce verified twice: second rejected with NONCE_REPLAY", () => {
  const { signed, publicKey } = signedReq("replay-1");
  // the cache clock matches the verification clock (see `size` docs)
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const first = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(first.ok, true);
  assert.equal(first.nonce, "replay-1");
  assert.equal(cache.size, 1);

  const second = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
  assert.match(second.reason ?? "", /replay/);
  assert.equal(second.nonce, "replay-1");
  assert.equal(second.label, "sig1");
  // the replay itself does not add a second entry
  assert.equal(cache.size, 1);
});

test("no cache configured: same nonce verifies twice (backwards compatible)", () => {
  const { signed, publicKey } = signedReq("no-cache-nonce");
  for (let i = 0; i < 2; i++) {
    const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
    assert.equal(res.ok, true);
    assert.equal(res.nonce, "no-cache-nonce");
  }
});

test("signature without nonce bypasses the cache entirely", () => {
  const { signed, publicKey } = signedReq();
  const cache = new ReplayCache();
  for (let i = 0; i < 2; i++) {
    const res = verifyRequest(signed, {
      key: publicKey,
      now: CREATED + 60,
      replayCache: cache,
    });
    assert.equal(res.ok, true);
  }
  assert.equal(cache.size, 0);
});

test("nonce is reusable after the TTL expires (fake clock)", () => {
  let t = CREATED + 60;
  const cache = new ReplayCache({ ttlSec: 300, now: () => t });
  const { signed, publicKey } = signedReq("ttl-nonce");
  const at = (now: number) =>
    verifyRequest(signed, { key: publicKey, now, replayCache: cache });

  assert.equal(at(t).ok, true);
  assert.equal(at(t).code, "NONCE_REPLAY");
  assert.equal(cache.size, 1);

  t += 301; // past the TTL
  assert.equal(at(t).ok, true); // re-recorded with a fresh timestamp
  assert.equal(cache.size, 1);
  assert.equal(at(t).code, "NONCE_REPLAY");
});

test("capacity cap evicts the least-recently-seen nonce (LRU)", () => {
  const t = CREATED + 60;
  const cache = new ReplayCache({ maxEntries: 3, ttlSec: 3600, now: () => t });
  const check = (nonce: string) => {
    const { signed, publicKey } = signedReq(nonce);
    return verifyRequest(signed, { key: publicKey, now: t, replayCache: cache });
  };

  for (const n of ["n1", "n2", "n3"]) assert.equal(check(n).ok, true);
  assert.equal(cache.size, 3);

  // n1 is a replay now; the hit also refreshes its recency.
  assert.equal(check("n1").code, "NONCE_REPLAY");

  // n4 has no room: the untouched oldest (n2) is evicted, not the
  // recently re-seen n1.
  assert.equal(check("n4").ok, true);
  assert.equal(cache.size, 3);
  assert.equal(check("n1").code, "NONCE_REPLAY"); // still cached
  assert.equal(check("n3").code, "NONCE_REPLAY"); // still cached
  assert.equal(check("n2").ok, true); // was evicted: accepted again
});

test("expired entries are reclaimed before LRU eviction", () => {
  let t = CREATED + 60;
  const cache = new ReplayCache({ maxEntries: 2, ttlSec: 100, now: () => t });
  const check = (nonce: string) => {
    const { signed, publicKey } = signedReq(nonce);
    return verifyRequest(signed, { key: publicKey, now: t, replayCache: cache });
  };
  assert.equal(check("e1").ok, true);
  assert.equal(check("e2").ok, true);
  assert.equal(cache.size, 2);

  t += 200; // both entries expired
  // e3 must fit via expiry reclamation, not by evicting a live entry.
  assert.equal(check("e3").ok, true);
  assert.equal(cache.size, 1);
  // e1/e2 expired long ago: accepted as fresh, not replayed.
  assert.equal(check("e1").ok, true);
});

test("failed verification never pollutes the cache", () => {
  const { signed, publicKey } = signedReq("poison-nonce");
  const { publicKey: wrongKey } = generateEd25519KeyPair();
  const cache = new ReplayCache({ now: () => CREATED + 60 });

  const bad = verifyRequest(signed, {
    key: wrongKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.size, 0);

  // the nonce is still unseen: the genuine request verifies fine
  const good = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(good.ok, true);
  assert.equal(cache.size, 1);
});

test("verifyRequestOrThrow raises VerifyError(NONCE_REPLAY)", () => {
  const { signed, publicKey } = signedReq("throw-nonce");
  const cache = new ReplayCache();
  const opts = { key: publicKey, now: CREATED + 60, replayCache: cache };
  const out = verifyRequestOrThrow(signed, opts);
  assert.equal(out.nonce, "throw-nonce");
  assert.throws(
    () => verifyRequestOrThrow(signed, opts),
    (e: unknown) => {
      assert.equal((e as Error).name, "VerifyError");
      assert.ok((e as Error) instanceof Error);
      assert.equal((e as { code?: string }).code, "NONCE_REPLAY");
      assert.equal((e as { nonce?: string }).nonce, "throw-nonce");
      return true;
    },
  );
});

test("clear() drops all tracked nonces", () => {
  const { signed, publicKey } = signedReq("clear-nonce");
  const cache = new ReplayCache();
  const opts = { key: publicKey, now: CREATED + 60, replayCache: cache };
  assert.equal(verifyRequest(signed, opts).ok, true);
  assert.equal(verifyRequest(signed, opts).code, "NONCE_REPLAY");
  cache.clear();
  assert.equal(cache.size, 0);
  assert.equal(verifyRequest(signed, opts).ok, true);
});

test("constructor validates options", () => {
  assert.throws(() => new ReplayCache({ maxEntries: 0 }), /maxEntries/);
  assert.throws(() => new ReplayCache({ maxEntries: 1.5 }), /maxEntries/);
  assert.throws(() => new ReplayCache({ ttlSec: 0 }), /ttlSec/);
  assert.throws(() => new ReplayCache({ ttlSec: -5 }), /ttlSec/);
  assert.throws(() => new ReplayCache().check(""), /non-empty/);
  // sane minimum works
  assert.equal(new ReplayCache({ maxEntries: 1, ttlSec: 1 }).size, 0);
});

test("verifyAllLabels: a replayed label does not block the other label", () => {
  const body = JSON.stringify({ amount: 100 });
  const req = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const a = signRequest(req, {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
    nonce: "multi-nonce-a",
  });
  const b = signRequest(req, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "gateway",
    nonce: "multi-nonce-b",
  });
  const merged: SignedHttpRequest = {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
  const cache = new ReplayCache();
  const first = verifyAllLabels(merged, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.deepEqual(
    first.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
  // Second pass: both labels' nonces are now seen. Each label is
  // reported independently — the merchant replay does not block the
  // gateway result.
  const second = verifyAllLabels(merged, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.deepEqual(
    second.map((r) => [r.label, r.ok, r.code]),
    [
      ["merchant", false, "NONCE_REPLAY"],
      ["gateway", false, "NONCE_REPLAY"],
    ],
  );
  assert.equal(second[0].nonce, "multi-nonce-a");
  assert.equal(second[1].nonce, "multi-nonce-b");
});
