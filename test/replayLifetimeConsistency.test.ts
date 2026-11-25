import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  signatureInputValue,
  verifyAllLabels,
  verifyRequest,
  type NonceStore,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signRequest` always emits `created`; a real third-party signer may omit
// it. `signedWithout` builds such signatures by hand using the public
// signature-base primitives (same pattern as test/requireFreshness.test.ts),
// so the wire shape matches what a foreign implementation would send.
const COVERED = ["@method", "@authority", "@path"];
const CREATED = 1700000000;

function signedReq(opts: {
  nonce?: string;
  expiresInSec?: number;
  created?: number;
} = {}): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: opts.created ?? CREATED,
      ...(opts.nonce === undefined ? {} : { nonce: opts.nonce }),
      ...(opts.expiresInSec === undefined
        ? {}
        : { expiresInSec: opts.expiresInSec }),
    },
  );
  return { signed, publicKey };
}

function signedWithout(params: SignatureParams): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const signed: SignedHttpRequest = {
    method: req.method,
    url: req.url,
    headers: {
      "signature-input": signatureInputValue("sig1", COVERED, params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  return { signed, publicKey };
}

/** A minimal custom store with a 1-day window that exposes no `ttlSec`. */
class MapNonceStore implements NonceStore {
  private readonly seen = new Map<string, number>();
  check(nonce: string, now?: number): boolean {
    const t = now ?? Math.floor(Date.now() / 1000);
    const prev = this.seen.get(nonce);
    if (prev !== undefined && t - prev < 86_400) return true;
    this.seen.set(nonce, t);
    return false;
  }
}

// ---------- unbounded / over-long lifetime is a configuration error ----------

test("unbounded lifetime + replayCache throws a configuration Error, records nothing", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-unbounded" });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: cache,
      }),
    (e: unknown) =>
      e instanceof Error &&
      /signature lifetime is unbounded/.test(e.message) &&
      /maxSignatureAgeSec/.test(e.message),
  );
  // The rejected verification never touches the cache: the same nonce
  // still verifies once the caller bounds the lifetime.
  assert.equal(cache.size, 0);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
    maxSignatureAgeSec: 3600,
  });
  assert.equal(res.ok, true);
  assert.equal(cache.size, 1);
});

test("long-lived signature (expires = created + 1 year) + default TTL throws", () => {
  const { signed, publicKey } = signedReq({
    nonce: "n-year",
    expiresInSec: 365 * 24 * 3600,
  });
  const cache = new ReplayCache({ now: () => CREATED + 60 });
  assert.equal(cache.ttlSec, 3600);
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: cache,
      }),
    (e: unknown) =>
      e instanceof Error &&
      /shorter than the signature lifetime/.test(e.message),
  );
  assert.equal(cache.size, 0);
});

test("expires longer than the TTL throws even when a maxAge is set but longer too", () => {
  const { signed, publicKey } = signedReq({
    nonce: "n-long",
    expiresInSec: 7200,
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: cache,
        maxSignatureAgeSec: 7200,
      }),
    /shorter than the signature lifetime/,
  );
});

// ---------- bounded within the TTL verifies ----------

test("maxSignatureAgeSec <= ttlSec verifies; replay inside the TTL is NONCE_REPLAY", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-bounded" });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const opts = {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
    maxSignatureAgeSec: 300,
  };
  assert.equal(verifyRequest(signed, opts).ok, true);
  const replay = verifyRequest(signed, opts);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
});

test("maxSignatureAgeSec equal to the TTL verifies (boundary is inclusive)", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-boundary" });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
    maxSignatureAgeSec: 3600,
  });
  assert.equal(res.ok, true);
});

test("expires shorter than the TTL verifies; the tighter of expires/maxAge governs", () => {
  // expires (60s) is tighter than maxAge (7200s): the effective lifetime
  // is 60s, inside the 3600s TTL.
  const { signed, publicKey } = signedReq({
    nonce: "n-short-expires",
    expiresInSec: 60,
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 30 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 30,
    replayCache: cache,
    maxSignatureAgeSec: 7200,
  });
  assert.equal(res.ok, true);
  // And the mirror image: a short maxAge rescues a long expires.
  const { signed: signed2, publicKey: publicKey2 } = signedReq({
    nonce: "n-short-maxage",
    expiresInSec: 7200,
  });
  const res2 = verifyRequest(signed2, {
    key: publicKey2,
    now: CREATED + 30,
    replayCache: cache,
    maxSignatureAgeSec: 60,
  });
  assert.equal(res2.ok, true);
});

test("replay after the TTL is still blocked: SIGNATURE_TOO_OLD when maxAge caps the lifetime", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-old" });
  let t = CREATED + 60;
  const cache = new ReplayCache({ ttlSec: 3600, now: () => t });
  const at = (now: number) =>
    verifyRequest(signed, {
      key: publicKey,
      now,
      replayCache: cache,
      maxSignatureAgeSec: 300,
    });
  assert.equal(at(t).ok, true);
  assert.equal(at(t).code, "NONCE_REPLAY");
  t = CREATED + 3601; // past both the 300s age cap and the 3600s TTL
  const late = at(t);
  assert.equal(late.ok, false);
  assert.equal(late.code, "SIGNATURE_TOO_OLD");
});

// ---------- no `created`: lifetime cannot be anchored ----------

test("no-created signature + replayCache throws (pinned: lifetime unanchorable)", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    nonce: "n-undated",
    expires: CREATED + 600,
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: cache,
      }),
    (e: unknown) =>
      e instanceof Error && /no `created`/.test(e.message),
  );
  assert.equal(cache.size, 0);
});

test("no-created signature without expires + replayCache also throws", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    nonce: "n-undated-noexp",
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: cache,
      }),
    /no `created`/,
  );
});

test("no-created + requireCreated reports MISSING_CREATED, not the consistency throw", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    nonce: "n-undated-req",
    expires: CREATED + 600,
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
    requireCreated: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

// ---------- the check does not apply where the cache is not consulted ----------

test("nonce-less signature + replayCache verifies: no nonce, no consistency check", () => {
  const { signed, publicKey } = signedReq();
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(res.ok, true);
  assert.equal(cache.size, 0);
});

test("no cache configured: unbounded signature still verifies (backwards compatible)", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-nocache" });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("forgery still reports SIGNATURE_MISMATCH, not the consistency throw", () => {
  const { signed, publicKey } = signedReq({ nonce: "n-forged" });
  // Corrupt the signature value itself (the body is digest-bound, so
  // tampering it would trip BODY_DIGEST_MISMATCH first): the crypto
  // check must still report the forgery instead of the config throw.
  const sig = signed.headers["signature"] as string;
  const b64 = sig.slice(sig.indexOf("=:") + 2, sig.lastIndexOf(":"));
  const corruptedB64 = (b64[0] === "A" ? "B" : "A") + b64.slice(1);
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${corruptedB64}:`,
    },
  };
  const cache = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const res = verifyRequest(tampered, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: cache,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(cache.size, 0);
});

// ---------- custom stores without an exposed TTL ----------

test("custom store without ttlSec: unbounded lifetime still throws; bounded-but-long verifies", () => {
  const store = new MapNonceStore();
  const { signed, publicKey } = signedReq({ nonce: "n-custom-unbounded" });
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: CREATED + 60,
        replayCache: store,
      }),
    /signature lifetime is unbounded/,
  );
  // A bounded lifetime the store cannot be compared against is allowed:
  // the window is unknown, so the length comparison is skipped.
  const { signed: signed2, publicKey: publicKey2 } = signedReq({
    nonce: "n-custom-long",
    expiresInSec: 7200,
  });
  const res = verifyRequest(signed2, {
    key: publicKey2,
    now: CREATED + 60,
    replayCache: store,
  });
  assert.equal(res.ok, true);
});

// ---------- per-label consistency ----------

test("verifyAllLabels: a label whose TTL cannot cover the lifetime throws; per-label maxAge fixes it", () => {
  const { publicKey: merchantKey, privateKey: merchantPriv } =
    generateEd25519KeyPair();
  const { publicKey: gatewayKey, privateKey: gatewayPriv } =
    generateEd25519KeyPair();
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
  const merchantSigned = signRequest(req, {
    keyId: "m",
    alg: "ed25519",
    key: merchantPriv,
    label: "merchant",
    created: CREATED,
    nonce: "n-dual",
  });
  const gatewaySigned = signRequest(req, {
    keyId: "g",
    alg: "ed25519",
    key: gatewayPriv,
    label: "gateway",
    created: CREATED,
    nonce: "n-dual",
  });
  const dual: SignedHttpRequest = {
    ...merchantSigned,
    headers: {
      ...merchantSigned.headers,
      "signature-input": `${merchantSigned.headers["signature-input"]}, ${gatewaySigned.headers["signature-input"]}`,
      signature: `${merchantSigned.headers["signature"]}, ${gatewaySigned.headers["signature"]}`,
    },
  };
  const merchantCache = new ReplayCache({
    ttlSec: 3600,
    now: () => CREATED + 60,
  });
  const gatewayCache = new ReplayCache({
    ttlSec: 60,
    now: () => CREATED + 60,
  });
  // Merchant is bounded by its per-label maxAge (3600 == its TTL);
  // gateway is unbounded, so its label throws out of verifyAllLabels.
  assert.throws(
    () =>
      verifyAllLabels(dual, {
        keys: { merchant: merchantKey, gateway: gatewayKey },
        now: CREATED + 60,
        replayCacheByLabel: {
          merchant: merchantCache,
          gateway: gatewayCache,
        },
        maxSignatureAgeSecByLabel: { merchant: 3600 },
      }),
    /signature lifetime is unbounded/,
  );
  // Bounding the gateway label to its own 60s TTL lets both verify.
  // Fresh caches: the throwing call above already recorded the merchant
  // nonce in merchantCache.
  const merchantCache2 = new ReplayCache({
    ttlSec: 3600,
    now: () => CREATED + 60,
  });
  const gatewayCache2 = new ReplayCache({
    ttlSec: 60,
    now: () => CREATED + 60,
  });
  const results = verifyAllLabels(dual, {
    keys: { merchant: merchantKey, gateway: gatewayKey },
    now: CREATED + 60,
    replayCacheByLabel: {
      merchant: merchantCache2,
      gateway: gatewayCache2,
    },
    maxSignatureAgeSecByLabel: { merchant: 3600, gateway: 60 },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

// ---------- ReplayCache ttlSec accessor ----------

test("ReplayCache exposes its configured TTL read-only; restore keeps the TTL it is given", () => {
  const cache = new ReplayCache({ ttlSec: 123, now: () => CREATED });
  assert.equal(cache.ttlSec, 123);
  assert.equal(new ReplayCache({ now: () => CREATED }).ttlSec, 3600);
  cache.check("n-ttl", CREATED);
  const snapshot = cache.exportSnapshot();
  const restored = ReplayCache.restore(snapshot, {
    ttlSec: 123,
    now: () => CREATED,
  });
  assert.equal(restored.ttlSec, 123);
  assert.equal(restored.has("n-ttl"), true);
});
