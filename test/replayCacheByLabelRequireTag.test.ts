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

// Backlog #718: `replayCacheByLabel` and `requireTagByLabel` are
// orthogonal maps, but their interaction was unpinned. The two
// checks live at different stages of the verification chain
// (crypto first, then the tag-existence check, then the window
// checks, then the replay cache; see `src/verify.ts`), so which
// code fires when a label violates the tag requirement, whether a
// tag failure pollutes the cache, and whether one label's store
// leaks into the other label, needs a test of its own rather than
// an assumption. This file pins the combination with the fixture
// the backlog names: the merchant label gets its own cache and a
// tag requirement, the gateway label gets neither.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path"];
const TAG = "payment-webhook-v1";

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
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

function signLabel(label: string, pair: KeyPair, nonce: string, tag?: string) {
  const opts: Parameters<typeof signRequest>[1] = {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
    expires: CREATED + 600,
    nonce,
  };
  if (tag !== undefined) opts.tag = tag;
  return signRequest(baseRequest(), opts);
}

function dual(merchantNonce: string, gatewayNonce: string, merchantTag?: string) {
  return mergeSignatures(
    signLabel("merchant", merchant, merchantNonce, merchantTag),
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
    requireTagByLabel: { merchant: true },
  };
}

// Hand-built merchant signature carrying an empty-string tag:
// `signRequest` refuses to mint one, so only a third-party wire
// shape can carry it (same helper shape as
// `test/requireTagByLabel.test.ts`).
function signedEmptyTagMerchant(nonce: string): SignedHttpRequest {
  const req: RequestLike = baseRequest();
  const params: SignatureParams = {
    keyid: "merchant",
    alg: "ed25519",
    created: CREATED,
    expires: CREATED + 600,
    nonce,
    tag: "",
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

test("replayCacheByLabel x requireTagByLabel: tagged first-seen nonce passes both, replay fails even though the tag is present", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);
  const req = dual("shared-nonce-1", "shared-nonce-1", TAG);

  const first = byLabel(verifyAllLabels(req, opts));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["merchant"].nonce, "shared-nonce-1");
  assert.equal(first["merchant"].tag, TAG);
  assert.equal(first["gateway"].ok, true);
  assert.equal(first["gateway"].nonce, "shared-nonce-1");
  // The gateway label carries no tag and no store, so it echoes no
  // tag and records nothing; only the merchant nonce is warehoused.
  assert.equal(first["gateway"].tag, undefined);
  assert.equal(merchantCache.size, 1);

  for (let i = 0; i < 2; i++) {
    const again = byLabel(verifyAllLabels(req, opts));
    // The replayed merchant signature still carries its tag, so the
    // tag-existence check passes and the verdict comes from the
    // cache — a complete tag does not rescue a seen nonce.
    assert.equal(again["merchant"].ok, false);
    assert.equal(again["merchant"].code, "NONCE_REPLAY");
    assert.equal(
      again["merchant"].reason,
      'nonce replay detected: "shared-nonce-1" was already seen',
    );
    // The gateway label is neither required to carry a tag nor
    // replay-checked, so repeating the same nonce is not a failure
    // for it — the merchant's requirement and store do not leak.
    assert.equal(again["gateway"].ok, true);
  }
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel x requireTagByLabel: a tag-less merchant reports MISSING_TAG, pollutes nothing, and the same nonce passes once tagged", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // Tag-less merchant, tag-less gateway, fresh nonce: the merchant
  // requirement fires, the gateway label — required by nobody,
  // cached by nobody — passes.
  for (let i = 0; i < 2; i++) {
    const results = byLabel(verifyAllLabels(dual("fresh-nonce-1", "fresh-nonce-1"), opts));
    assert.equal(results["merchant"].ok, false);
    assert.equal(results["merchant"].code, "MISSING_TAG");
    assert.equal(
      results["merchant"].reason,
      "signature carries no `tag` but requireTag is set",
    );
    assert.equal(results["gateway"].ok, true);
  }
  // The existence failure happened before the cache query, so the
  // store is still empty: a missing tag is not a recorded nonce,
  // and a tag-less presentation never graduates to NONCE_REPLAY.
  assert.equal(merchantCache.size, 0);
  assert.equal(merchantCache.stats().hits, 0);
  assert.equal(merchantCache.stats().misses, 0);

  // The same nonce, now carrying its tag, passes: the earlier
  // tag failures consumed nothing and blocked nothing.
  const valid = byLabel(verifyAllLabels(dual("fresh-nonce-1", "fresh-nonce-1", TAG), opts));
  assert.equal(valid["merchant"].ok, true);
  assert.equal(valid["merchant"].tag, TAG);
  assert.equal(valid["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  // And only now does the merchant replay: the gateway's repeated
  // tag-less presentations still pass alongside it.
  const replay = byLabel(verifyAllLabels(dual("fresh-nonce-1", "fresh-nonce-1", TAG), opts));
  assert.equal(replay["merchant"].ok, false);
  assert.equal(replay["merchant"].code, "NONCE_REPLAY");
  assert.equal(replay["gateway"].ok, true);
});

test("replayCacheByLabel x requireTagByLabel: an empty-string tag counts as missing, not as a replay, and leaves no cache trace", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  const merged = mergeSignatures(
    signedEmptyTagMerchant("after-empty-1"),
    signLabel("gateway", gateway, "gateway-nonce-1"),
  );
  const results = byLabel(verifyAllLabels(merged, opts));
  assert.equal(results["merchant"].ok, false);
  assert.equal(results["merchant"].code, "MISSING_TAG");
  assert.equal(results["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // The empty tag left no trace: the same nonce with a real tag
  // afterwards passes.
  const valid = byLabel(verifyAllLabels(dual("after-empty-1", "gateway-nonce-1", TAG), opts));
  assert.equal(valid["merchant"].ok, true);
  assert.equal(valid["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
});

test("replayCacheByLabel x requireTagByLabel: the gateway reusing the merchant's nonce is unaffected by the merchant store", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // The merchant records "shared-nonce-1" with its tag; the gateway
  // presents the same nonce tag-less in the same request and passes.
  const first = byLabel(verifyAllLabels(dual("shared-nonce-1", "shared-nonce-1", TAG), opts));
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  // The gateway keeps presenting that nonce, tag-less, request
  // after request: with no store of its own it can never replay.
  // The merchant presents a fresh nonce each time, so its own
  // verdicts stay green while the gateway repeats.
  for (const merchantNonce of ["other-nonce-1", "other-nonce-2"]) {
    const results = byLabel(
      verifyAllLabels(dual(merchantNonce, "shared-nonce-1", TAG), opts),
    );
    assert.equal(results["merchant"].ok, true);
    assert.equal(results["gateway"].ok, true);
  }
  // Only merchant presentations entered the merchant store: the
  // initial nonce plus the two fresh ones.
  assert.equal(merchantCache.size, 3);

  const merchantReplay = byLabel(
    verifyAllLabels(dual("shared-nonce-1", "shared-nonce-1", TAG), opts),
  );
  assert.equal(merchantReplay["merchant"].ok, false);
  assert.equal(merchantReplay["merchant"].code, "NONCE_REPLAY");
  assert.equal(merchantReplay["gateway"].ok, true);
});

test("replayCacheByLabel x requireTagByLabel: the gateway's nonce reuse never pollutes the merchant store", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // The gateway presents "gateway-shared-1" while the merchant
  // presents a different nonce: only the merchant nonce is recorded.
  const first = byLabel(
    verifyAllLabels(dual("merchant-first-1", "gateway-shared-1", TAG), opts),
  );
  assert.equal(first["merchant"].ok, true);
  assert.equal(first["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);

  // Now the merchant presents "gateway-shared-1" for the first time,
  // tagged. The gateway's earlier presentations never entered the
  // merchant store, so this is a fresh nonce for the merchant, not
  // a replay — even though the gateway label repeats it in the same
  // request.
  const second = byLabel(
    verifyAllLabels(dual("gateway-shared-1", "gateway-shared-1", TAG), opts),
  );
  assert.equal(second["merchant"].ok, true);
  assert.equal(second["gateway"].ok, true);
  assert.equal(merchantCache.size, 2);

  const third = byLabel(
    verifyAllLabels(dual("gateway-shared-1", "gateway-shared-1", TAG), opts),
  );
  assert.equal(third["merchant"].ok, false);
  assert.equal(third["merchant"].code, "NONCE_REPLAY");
  assert.equal(third["gateway"].ok, true);
});

test("replayCacheByLabel x requireTagByLabel: a forgery beats both checks and pollutes neither outcome", () => {
  const merchantCache = cache();
  const opts = fixtureOpts(merchantCache);

  // Forged merchant signature (wrong key) carrying a tag and a
  // nonce: the cryptographic check runs before the existence check
  // and before the cache query, so the verdict is
  // SIGNATURE_MISMATCH — not MISSING_TAG, not NONCE_REPLAY — and
  // the store stays empty.
  const forged = mergeSignatures(
    signLabel("merchant", merchantWrong, "forgery-nonce-1", TAG),
    signLabel("gateway", gateway, "forgery-nonce-1"),
  );
  const forgedResults = byLabel(verifyAllLabels(forged, opts));
  assert.equal(forgedResults["merchant"].ok, false);
  assert.equal(forgedResults["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(forgedResults["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // Forged merchant signature carrying a nonce but no tag at all:
  // still SIGNATURE_MISMATCH, not MISSING_TAG — crypto first, even
  // when the existence check would also fail.
  const forgedNoTag = mergeSignatures(
    signLabel("merchant", merchantWrong, "forgery-nonce-1"),
    signLabel("gateway", gateway, "forgery-nonce-1"),
  );
  const forgedNoTagResults = byLabel(verifyAllLabels(forgedNoTag, opts));
  assert.equal(forgedNoTagResults["merchant"].ok, false);
  assert.equal(forgedNoTagResults["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(forgedNoTagResults["gateway"].ok, true);
  assert.equal(merchantCache.size, 0);

  // The correctly signed merchant nonce passes afterwards: neither
  // forgery recorded it, so the first genuine presentation is fresh.
  const genuine = byLabel(
    verifyAllLabels(dual("forgery-nonce-1", "forgery-nonce-1", TAG), opts),
  );
  assert.equal(genuine["merchant"].ok, true);
  assert.equal(genuine["gateway"].ok, true);
  assert.equal(merchantCache.size, 1);
});
