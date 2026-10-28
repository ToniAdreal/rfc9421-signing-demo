import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  ReplayCache,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #662: `replayCacheByLabel` and `requireNonceByLabel` are
// orthogonal maps, but their interaction was unpinned. A per-label
// cache is only meaningful for a label that is required to carry a
// nonce — yet the two checks live at different stages of the
// verification chain (crypto first, then the nonce-existence check,
// then the cache query; see `src/verify.ts`), so which code fires
// when a label violates both, and whether one map leaks into the
// other label, needs a test of its own rather than an assumption.
// This file pins the combination with the fixture the backlog
// names: the merchant label gets its own cache and a nonce
// requirement, the gateway label gets neither.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path"];

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
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

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();
const merchantWrong = generateEd25519KeyPair();

function signLabel(label: string, pair: KeyPair, nonce?: string) {
  const opts: Parameters<typeof signRequest>[1] = {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: CREATED + 600,
  };
  if (nonce !== undefined) opts.nonce = nonce;
  return signRequest(baseRequest(), opts);
}

function dual(merchantNonce?: string, gatewayNonce?: string) {
  return mergeSignatures(
    signLabel("merchant", merchant, merchantNonce),
    signLabel("gateway", gateway, gatewayNonce),
  );
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function cache() {
  return new ReplayCache({ ttlSec: 3600, now: () => NOW });
}

// The backlog fixture: merchant mapped in both maps, gateway in
// neither, no global cache and no global requirement to fall back to.
function fixtureOpts(merchantCache: ReplayCache) {
  return {
    now: NOW,
    keys: keys(),
    replayCacheByLabel: { merchant: merchantCache },
    requireNonceByLabel: { merchant: true },
  };
}

// Hand-built merchant signature carrying an empty-string nonce:
// `signRequest` refuses to mint one, so only a third-party wire
// shape can carry it (same helper shape as
// `test/requireNonceByLabel.test.ts`).
function signedEmptyNonceMerchant(): SignedHttpRequest {
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const params: SignatureParams = {
    keyid: "merchant",
    alg: "ed25519",
    created: CREATED,
    expires: CREATED + 600,
    nonce: "",
  };
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), merchant.privateKey);
  return {
    method: req.method,
    url: req.url,
    headers: {
      "signature-input": signatureInputValue("merchant", COVERED, params),
      signature: `merchant=:${sig.toString("base64")}:`,
    },
  };
}

test("replayCacheByLabel x requireNonceByLabel: same nonce passes both labels first, then only the merchant replays", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);
  const req = dual("shared-nonce-1", "shared-nonce-1");

  const first = byLabel(verifyAllLabels(req, opts));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["merchant"].nonce, "shared-nonce-1");
  assert.equal(first["gateway"].ok, true);
  assert.equal(first["gateway"].nonce, "shared-nonce-1");
  // Only the merchant label recorded anything: the gateway label
  // has no store at all, so its nonce is not warehoused anywhere.
  assert.equal(merchantCache.size, 1);

  for (let i = 0; i < 2; i++) {
    const again = byLabel(verifyAllLabels(req, opts));
    assert.equal(again["merchant"].ok, false);
    assert.equal(again["merchant"].code, "NONCE_REPLAY");
    assert.equal(
      again["merchant"].reason,
      'nonce replay detected: "shared-nonce-1" was already seen',
    );
    // The gateway label is neither required to carry a nonce nor
    // replay-checked, so repeating the same nonce is not a failure
    // for it — the merchant's requirement and store do not leak.
    assert.equal(again["gateway"].ok, true);
  }
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel x requireNonceByLabel: the gateway's nonce reuse never pollutes the merchant store", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // The gateway presents "gateway-shared-1" while the merchant
  // presents a different nonce: only the merchant nonce is recorded.
  const first = byLabel(
    verifyAllLabels(dual("merchant-first-1", "gateway-shared-1"), opts),
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  // Now the merchant presents "gateway-shared-1" for the first time.
  // The gateway's earlier presentations never entered the merchant
  // store, so this is a fresh nonce for the merchant, not a replay —
  // even though the gateway label repeats it in the same request.
  const second = byLabel(
    verifyAllLabels(dual("gateway-shared-1", "gateway-shared-1"), opts),
  );
  assert.equal(second["merchant"].ok, true);
  assert.equal(second["gateway"].ok, true);
  assert.equal(merchantCache.size, 2);

  const third = byLabel(
    verifyAllLabels(dual("gateway-shared-1", "gateway-shared-1"), opts),
  );
  assert.equal(third["merchant"].ok, false);
  assert.equal(third["merchant"].code, "NONCE_REPLAY");
  assert.equal(third["gateway"].ok, true);
});

test("replayCacheByLabel x requireNonceByLabel: a nonce-less merchant reports MISSING_NONCE, pollutes nothing, and the gateway still passes", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // Both labels nonce-less: the merchant requirement fires, the
  // gateway label — required by nobody, cached by nobody — passes.
  for (let i = 0; i < 2; i++) {
    const results = byLabel(verifyAllLabels(dual(undefined, undefined), opts));
    assert.equal(results["merchant"].ok, false);
    assert.equal(results["merchant"].code, "MISSING_NONCE");
    assert.equal(results["gateway"].ok, true);
  }
  // The existence failure happened before the cache query, so the
  // store is still empty: a missing nonce is not a recorded nonce.
  assert.equal(merchantCache.size, 0);

  // A later, well-formed merchant nonce passes: the earlier
  // missing-nonce failures consumed nothing and blocked nothing.
  const valid = byLabel(
    verifyAllLabels(dual("fresh-after-missing-1", undefined), opts),
  );
  assert.equal(valid["merchant"].ok, true);
  assert.equal(valid["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  // And only now does the merchant replay: the gateway's repeated
  // nonce-less presentations still pass alongside it.
  const replay = byLabel(
    verifyAllLabels(dual("fresh-after-missing-1", undefined), opts),
  );
  assert.equal(replay["merchant"].ok, false);
  assert.equal(replay["merchant"].code, "NONCE_REPLAY");
  assert.equal(replay["gateway"].ok, true);
});

test("replayCacheByLabel x requireNonceByLabel: a nonce-less merchant can never also be a replay", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // Missing and replayed cannot co-fire for one label: there is no
  // nonce string to look up, so the existence check is the only code
  // a nonce-less signature can ever produce — no matter how often
  // it is re-presented, it never graduates to NONCE_REPLAY.
  for (let i = 0; i < 3; i++) {
    const results = byLabel(verifyAllLabels(dual(undefined, "gateway-nonce-1"), opts));
    assert.equal(results["merchant"].ok, false);
    assert.equal(results["merchant"].code, "MISSING_NONCE");
    assert.equal(results["gateway"].ok, true);
  }
  assert.equal(merchantCache.size, 0);
  assert.equal(merchantCache.stats().hits, 0);
  assert.equal(merchantCache.stats().misses, 0);
});

test("replayCacheByLabel x requireNonceByLabel: an empty-string nonce counts as missing, not as a replay", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  const merged = mergeSignatures(
    signedEmptyNonceMerchant(),
    signRequest(
      {
        method: "POST",
        url: "https://api.example.com/v1/payments",
        headers: {},
      },
      {
        label: "gateway",
        keyId: "gateway",
        alg: "ed25519",
        key: gateway.privateKey,
        created: CREATED,
        expires: CREATED + 600,
        nonce: "gateway-nonce-1",
      },
    ),
  );
  const results = byLabel(verifyAllLabels(merged, opts));
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "MISSING_NONCE");
  assert.equal(results["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // The empty nonce left no trace: a real nonce afterwards passes.
  const valid = byLabel(
    verifyAllLabels(dual("after-empty-1", "gateway-nonce-1"), opts),
  );
  assert.equal(valid["merchant"].ok, true);
  assert.equal(valid["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel x requireNonceByLabel: a forgery beats both checks and pollutes neither outcome", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // Forged merchant signature (wrong key) carrying a nonce: the
  // cryptographic check runs before the existence check and before
  // the cache query, so the verdict is SIGNATURE_MISMATCH — not
  // MISSING_NONCE, not NONCE_REPLAY — and the store stays empty.
  const forged = mergeSignatures(
    signLabel("merchant", merchantWrong, "forgery-nonce-1"),
    signLabel("gateway", gateway, "forgery-nonce-1"),
  );
  const forgedResults = byLabel(verifyAllLabels(forged, opts));
  assert.equal(forgedResults["merchant"].ok, false);
  assert.equal(forgedResults["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(forgedResults["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // Forged merchant signature carrying no nonce at all: still
  // SIGNATURE_MISMATCH, not MISSING_NONCE — crypto first, even
  // when the existence check would also fail.
  const forgedNoNonce = mergeSignatures(
    signLabel("merchant", merchantWrong, undefined),
    signLabel("gateway", gateway, "forgery-nonce-1"),
  );
  const forgedNoNonceResults = byLabel(verifyAllLabels(forgedNoNonce, opts));
  assert.equal(forgedNoNonceResults["merchant"].ok, false);
  assert.equal(forgedNoNonceResults["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(forgedNoNonceResults["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // The correctly signed merchant nonce passes afterwards: neither
  // forgery recorded it, so the first genuine presentation is fresh.
  const genuine = byLabel(verifyAllLabels(dual("forgery-nonce-1", "forgery-nonce-1"), opts));
  assert.equal(genuine["merchant"].ok, true);
  assert.equal(genuine["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel x requireNonceByLabel: a mapped false relaxes a global requirement for the gateway only", () => {
  const merchantCache = cache();
  // Global requirement on, gateway explicitly relaxed; the
  // merchant store map still binds the merchant label. The two
  // maps compose independently: relaxing the requirement for one
  // label does not relax its store, and mapping a store for one
  // label does not impose a requirement on the other.
  const opts = {
    now: NOW,
    keys: keys(),
    requireNonce: true,
    requireNonceByLabel: { gateway: false },
    replayCacheByLabel: { merchant: merchantCache },
  };

  const noNonce = byLabel(verifyAllLabels(dual(undefined, undefined), opts));
  assert.equal(noNonce["merchant"].ok, false);
  assert.equal(noNonce["merchant"].code, "MISSING_NONCE");
  assert.equal(noNonce["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  const req = dual("relaxed-global-1", undefined);
  const first = byLabel(verifyAllLabels(req, opts));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  const second = byLabel(verifyAllLabels(req, opts));
  assert.equal(second["merchant"].ok, false);
  assert.equal(second["merchant"].code, "NONCE_REPLAY");
  assert.equal(second["gateway"].ok, true);
});
