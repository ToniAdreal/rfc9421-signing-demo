import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyRequest,
  verifyRequestOrThrow,
} from "../src/index.js";

// Backlog #1444: a failed single-label verification must not consume
// the nonce. The verify order is crypto first, nonce recording second:
// only a signature that actually verifies earns its nonce a cache
// entry. If a forgery consumed the nonce, the genuine request carrying
// it would then be rejected as a replay — the attacker would have
// turned one bad signature into a denial of service on the real one.
// `has()` probes use the wire keyid scope: `verifyRequest` records the
// nonce under the signature's keyid (backlog #1412), so an unscoped
// probe would never see the entry.
const CREATED = 1700000000;
const NOW = CREATED + 60;
const NONCE = "nonce-not-consumed-1";

function cache() {
  return new ReplayCache({ ttlSec: 3600, now: () => NOW });
}

function signed(
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"],
  nonce = NONCE,
) {
  return signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED, nonce },
  );
}

function opts(
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"],
  c: ReplayCache,
) {
  return { key: publicKey, now: NOW, replayCache: c, maxSignatureAgeSec: 3600 };
}

// Flip one byte of the signature bytes so the signature no longer
// matches the signed base, without touching the nonce or the
// signature-input line.
function tamperSignature(
  signedReq: ReturnType<typeof signRequest>,
) {
  const raw = Buffer.from(
    signedReq.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  raw[raw.length - 1] ^= 0x01;
  return {
    ...signedReq,
    headers: {
      ...signedReq.headers,
      signature: `sig1=:${raw.toString("base64")}:`,
    },
  };
}

test("tampered signature fails SIGNATURE_MISMATCH and leaves the nonce unrecorded", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const c = cache();
  const res = verifyRequest(tamperSignature(signed(privateKey)), opts(publicKey, c));
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  // The wire nonce is still reported on failure, but it was never
  // recorded: the cache is empty.
  assert.equal(res.nonce, NONCE);
  assert.equal(c.has(NONCE, NOW, "k"), false);
  assert.equal(c.size, 0);
  assert.deepEqual(c.exportSnapshot(), { v: 2, entries: [] });
});

test("the same nonce verifies after the failed attempt, then replays", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const c = cache();
  const good = signed(privateKey);

  const failed = verifyRequest(tamperSignature(good), opts(publicKey, c));
  assert.equal(failed.ok, false);
  assert.equal(failed.code, "SIGNATURE_MISMATCH");
  assert.equal(c.size, 0);

  // The genuine request is not punished for the earlier forgery.
  const first = verifyRequest(good, opts(publicKey, c));
  assert.equal(first.ok, true);
  assert.equal(first.nonce, NONCE);
  assert.equal(c.has(NONCE, NOW, "k"), true);
  assert.equal(c.size, 1);

  // And the second genuine presentation is a replay, as usual.
  const replayed = verifyRequest(good, opts(publicKey, c));
  assert.equal(replayed.ok, false);
  assert.equal(replayed.code, "NONCE_REPLAY");
  assert.equal(c.size, 1);
});

test("repeated failures never turn into a replay", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const c = cache();
  const good = signed(privateKey);

  // Two differently-tampered presentations of the same nonce: both
  // must fail as signature mismatches, never as replays, because no
  // failed attempt recorded anything.
  for (const tampered of [tamperSignature(good), tamperSignature(good)]) {
    const res = verifyRequest(tampered, opts(publicKey, c));
    assert.equal(res.ok, false);
    assert.equal(res.code, "SIGNATURE_MISMATCH");
  }
  assert.equal(c.has(NONCE, NOW, "k"), false);
  assert.equal(c.size, 0);

  // The genuine request still verifies afterwards.
  assert.equal(verifyRequest(good, opts(publicKey, c)).ok, true);
});

test("verifyRequestOrThrow: a thrown failure does not consume the nonce", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const c = cache();
  const good = signed(privateKey);

  assert.throws(
    () => verifyRequestOrThrow(tamperSignature(good), opts(publicKey, c)),
    (e: unknown) => {
      assert.equal((e as Error).name, "VerifyError");
      assert.equal((e as { code?: string }).code, "SIGNATURE_MISMATCH");
      assert.equal((e as { nonce?: string }).nonce, NONCE);
      return true;
    },
  );
  assert.equal(c.has(NONCE, NOW, "k"), false);
  assert.equal(c.size, 0);

  const out = verifyRequestOrThrow(good, opts(publicKey, c));
  assert.equal(out.nonce, NONCE);
  assert.equal(c.has(NONCE, NOW, "k"), true);

  assert.throws(
    () => verifyRequestOrThrow(good, opts(publicKey, c)),
    (e: unknown) => {
      assert.equal((e as Error).name, "VerifyError");
      assert.equal((e as { code?: string }).code, "NONCE_REPLAY");
      return true;
    },
  );
});

test("a forged nonce on a failed attempt is not recorded either", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const c = cache();
  const good = signed(privateKey, "original");
  // Rewrite the nonce parameter the way nonce.test.ts does: the wire
  // nonce becomes "forged", the signature no longer matches.
  const forged = {
    ...good,
    headers: {
      ...good.headers,
      "signature-input": good.headers["signature-input"].replace(
        'nonce="original"',
        'nonce="forged"',
      ),
    },
  };
  const res = verifyRequest(forged, opts(publicKey, c));
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.nonce, "forged");
  assert.equal(c.has("forged", NOW, "k"), false);
  assert.equal(c.has("original", NOW, "k"), false);
  assert.equal(c.size, 0);

  // A genuine request carrying the "forged" nonce string still
  // verifies — the failed attempt never consumed it.
  const genuineForged = signed(privateKey, "forged");
  assert.equal(verifyRequest(genuineForged, opts(publicKey, c)).ok, true);
  assert.equal(c.has("forged", NOW, "k"), true);
});
