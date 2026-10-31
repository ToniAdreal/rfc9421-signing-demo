import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #775: `verifyAllLabels` x `replayCacheByLabel` and
// `verifyAllLabels` x content-digest each had their own coverage,
// but the orthogonal combination was unpinned: a dual-signed
// message whose two labels share one sha-512 Content-Digest header
// while each label holds its own replay cache. Do the digest
// failure and the replay failure stay per-label and independent —
// does a digest failure pollute either cache, and does one label's
// replay drag the other label down?
//
// The digest-tamper case here is a body swap with the wire header
// untouched: the signature base covers the header value, so the
// crypto check still passes and the body-vs-digest check is the
// rejection, exactly as in #730/#767. Tampering the header value
// itself would instead fail as SIGNATURE_MISMATCH (also #730),
// so that is not the case pinned here.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. Zero real network.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY_A = '{"amount":100}';
const BODY_B = '{"amount":1}';

function baseRequest(body: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
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

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

function signLabel(
  pair: KeyPair,
  label: string,
  nonce: string,
  body: string = BODY_A,
) {
  return signRequest(baseRequest(body), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    nonce,
  });
}

/** Fresh keypairs, a dual-signed request, and fresh per-label caches. */
function twoParty(nonce: string) {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeSignatures(
    signLabel(merchant, "merchant", nonce),
    signLabel(gateway, "gateway", nonce),
  );
  const merchantCache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const gatewayCache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  return { merged, merchant, gateway, merchantCache, gatewayCache };
}

function verifyDual(
  req: SignedHttpRequest,
  merchant: KeyPair,
  gateway: KeyPair,
  merchantCache: ReplayCache,
  gatewayCache: ReplayCache,
) {
  return verifyAllLabels(req, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
  });
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

test("verifyAllLabels x replayCacheByLabel x content-digest: dual labels share one sha-512 digest and each records the nonce in its own store", () => {
  const { merged, merchant, gateway, merchantCache, gatewayCache } =
    twoParty("shared-nonce-775-a");
  const digest = merged.headers["content-digest"];
  assert.ok(
    digest?.startsWith("sha-512="),
    "wire must carry the shared sha-512 digest",
  );
  assert.ok(
    !digest?.includes("sha-256="),
    "wire must be sha-512-only, not the sha-256 fallback",
  );
  const first = byLabel(
    verifyDual(merged, merchant, gateway, merchantCache, gatewayCache),
  );
  for (const label of ["merchant", "gateway"]) {
    assert.equal(first[label].ok, true, JSON.stringify(first[label]));
    assert.ok(
      first[label].coveredComponents?.includes("content-digest"),
      `${label} must cover content-digest`,
    );
    assert.equal(first[label].nonce, "shared-nonce-775-a");
  }
  // Recording really happened in both stores (nothing was bypassed):
  // a second verification of the same request replays in each.
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
  const second = byLabel(
    verifyDual(merged, merchant, gateway, merchantCache, gatewayCache),
  );
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, false);
  assert.equal(second["gateway"].code, "NONCE_REPLAY");
});

test("verifyAllLabels x replayCacheByLabel x content-digest: body swapped after signing fails both labels as BODY_DIGEST_MISMATCH and records nothing", () => {
  const { merged, merchant, gateway, merchantCache, gatewayCache } =
    twoParty("shared-nonce-775-b");
  const swapped = { ...merged, body: BODY_B };
  const results = byLabel(
    verifyDual(swapped, merchant, gateway, merchantCache, gatewayCache),
  );
  for (const label of ["merchant", "gateway"]) {
    // The header value is untouched, so the crypto check passes and
    // the body-vs-digest check rejects: the digest dimension must
    // surface on its own, not as SIGNATURE_MISMATCH, on both labels.
    assert.equal(results[label].ok, false);
    assert.equal(results[label].code, "BODY_DIGEST_MISMATCH");
    assert.equal(results[label].reason, "body does not match content-digest");
  }
  // A failed verification must never pollute either replay store:
  // the digest check runs before the cache is consulted.
  assert.equal(merchantCache.size, 0);
  assert.equal(gatewayCache.size, 0);
});

test("verifyAllLabels x replayCacheByLabel x content-digest: one label's replay does not drag the other label down", () => {
  const { merged, merchant, gateway, merchantCache, gatewayCache } =
    twoParty("shared-nonce-775-c");
  // Pre-seed only the merchant store, via a single-label
  // verification of the merchant's signature with the same nonce.
  const merchantOnly = signLabel(merchant, "merchant", "shared-nonce-775-c");
  assert.equal(
    verifyRequest(merchantOnly, {
      label: "merchant",
      key: merchant.publicKey,
      now: NOW,
      replayCache: merchantCache,
    }).ok,
    true,
  );
  const results = byLabel(
    verifyDual(merged, merchant, gateway, merchantCache, gatewayCache),
  );
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "NONCE_REPLAY");
  // The gateway label's digest still binds the same wire body and
  // its store has never seen this nonce: a neighbour's replay must
  // not turn into any failure on this label.
  assert.equal(results["gateway"].ok, true, JSON.stringify(results["gateway"]));
  assert.ok(
    results["gateway"].coveredComponents?.includes("content-digest"),
  );
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
});

test("verifyAllLabels x replayCacheByLabel x content-digest: after a digest failure the true message still verifies and records both nonces", () => {
  const { merged, merchant, gateway, merchantCache, gatewayCache } =
    twoParty("shared-nonce-775-d");
  const swapped = { ...merged, body: BODY_B };
  const failed = byLabel(
    verifyDual(swapped, merchant, gateway, merchantCache, gatewayCache),
  );
  assert.equal(failed["merchant"].code, "BODY_DIGEST_MISMATCH");
  assert.equal(failed["gateway"].code, "BODY_DIGEST_MISMATCH");
  assert.equal(merchantCache.size, 0);
  assert.equal(gatewayCache.size, 0);
  // The digest failure left no trace in either store, so resending
  // the true message verifies and records both nonces normally.
  const retried = byLabel(
    verifyDual(merged, merchant, gateway, merchantCache, gatewayCache),
  );
  assert.equal(retried["merchant"].ok, true, JSON.stringify(retried["merchant"]));
  assert.equal(retried["gateway"].ok, true, JSON.stringify(retried["gateway"]));
  assert.equal(merchantCache.size, 1);
  assert.equal(gatewayCache.size, 1);
});
