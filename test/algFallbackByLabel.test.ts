import test from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  createSign,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  generateP256KeyPair,
  secretKey,
  signatureInputValue,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: a P-256 signer that omits the optional `alg` parameter
// (a foreign signer, same shape as test/algFallback.test.ts).
// Gateway: an HMAC signer that also omits `alg`. Both signatures are
// on the same request, so a single global `algFallback` cannot express
// "infer the merchant's algorithm, keep the gateway strict": the
// per-label map is what splits them.
//
// The merchant is deliberately P-256, not ed25519: the legacy default
// for a missing `alg` already IS "ed25519", so an ed25519 merchant
// wire would pass under `false` too and could never show the split.
// A P-256 wire passes only under `"infer"` and fails under `false`,
// which makes both directions of the split observable.
const BODY = '{"amount":100}';

function baseRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: BODY,
  };
}

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (mirroring src/sign.ts's crypto
 * choices: P-256 raw r||s per RFC 9421 §3.3.4, hmac-sha256).
 */
function signWithoutAlg(
  req: RequestLike,
  opts: { keyId: string; key: KeyObject; label: string },
): SignedHttpRequest {
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  headers["content-digest"] = contentDigest(BODY);
  const params = { created: Math.floor(Date.now() / 1000), keyid: opts.keyId }; // no alg, ever
  const base = buildSignatureBase(covered, { ...req, headers }, params);
  const key = opts.key;
  let sig: Buffer;
  if (key.type === "secret") {
    sig = createHmac("sha256", key).update(base, "utf8").digest();
  } else {
    // A spec-conformant foreign P-256 signer emits the raw r||s value
    // RFC 9421 §3.3.4 defines (node:crypto's ieee-p1363 encoding),
    // never DER.
    sig = createSign("sha256")
      .update(base, "utf8")
      .sign({ key, dsaEncoding: "ieee-p1363" });
  }
  headers["signature-input"] = signatureInputValue(
    opts.label,
    covered,
    params,
  );
  headers["signature"] = `${opts.label}=:${sig.toString("base64")}:`;
  assert.ok(
    !headers["signature-input"].includes("alg="),
    "precondition: foreign wire must not carry alg",
  );
  return { method: req.method, url: req.url, headers, body: req.body };
}

const merchant = generateP256KeyPair();
const GATEWAY = secretKey(randomBytes(32));

function signMerchant(): SignedHttpRequest {
  return signWithoutAlg(baseRequest(), {
    keyId: "merchant-key-1",
    key: merchant.privateKey,
    label: "merchant",
  });
}

function signGateway(): SignedHttpRequest {
  return signWithoutAlg(baseRequest(), {
    keyId: "gateway-key-9",
    key: GATEWAY,
    label: "gateway",
  });
}

function dual(): SignedHttpRequest {
  const a = signMerchant();
  const b = signGateway();
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

function keys() {
  return { merchant: merchant.publicKey, gateway: GATEWAY };
}

test("algFallbackByLabel: merchant infer passes, gateway false is rejected", () => {
  const results = verifyAllLabels(dual(), {
    keys: keys(),
    algFallbackByLabel: { merchant: "infer", gateway: false },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, `merchant failed: ${JSON.stringify(results[0])}`);
  assert.equal(results[0].alg, "ecdsa-p256-sha256");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  // Legacy default: a missing alg means "ed25519", which the crypto
  // layer rejects against a secret key.
  assert.equal(results[1].code, "VERIFICATION_ERROR");
});

test("algFallbackByLabel: reversed split — merchant false rejected, gateway infer passes", () => {
  const results = verifyAllLabels(dual(), {
    keys: keys(),
    algFallbackByLabel: { merchant: false, gateway: "infer" },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  // Legacy default: a missing alg means "ed25519", and the ed25519
  // attempt against a P-256 key fails as a plain mismatch (the crypto
  // layer returns false for the wrong key type) — unlike the secret-key
  // case, where the shape error surfaces as VERIFICATION_ERROR.
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, `gateway failed: ${JSON.stringify(results[1])}`);
  assert.equal(results[1].alg, "hmac-sha256");
});

test("algFallbackByLabel: unmapped label falls back to the global strategy", () => {
  // Only the merchant is pinned strict; the gateway falls back to the
  // global "infer" and passes.
  const gatewayInferred = verifyAllLabels(dual(), {
    keys: keys(),
    algFallback: "infer",
    algFallbackByLabel: { merchant: false },
  });
  assert.equal(gatewayInferred[0].ok, false);
  assert.equal(gatewayInferred[0].code, "SIGNATURE_MISMATCH");
  assert.equal(gatewayInferred[1].ok, true);
  assert.equal(gatewayInferred[1].alg, "hmac-sha256");

  // Only the merchant is pinned to infer; the gateway falls back to
  // the global unset (legacy default) and fails.
  const merchantInferred = verifyAllLabels(dual(), {
    keys: keys(),
    algFallbackByLabel: { merchant: "infer" },
  });
  assert.equal(merchantInferred[0].ok, true);
  assert.equal(merchantInferred[0].alg, "ecdsa-p256-sha256");
  assert.equal(merchantInferred[1].ok, false);
  assert.equal(merchantInferred[1].code, "VERIFICATION_ERROR");
});

test("algFallbackByLabel: without the map the global strategy applies to both labels", () => {
  const inferred = verifyAllLabels(dual(), {
    keys: keys(),
    algFallback: "infer",
  });
  assert.deepEqual(
    inferred.map((r) => r.ok),
    [true, true],
  );
  assert.deepEqual(
    inferred.map((r) => r.alg),
    ["ecdsa-p256-sha256", "hmac-sha256"],
  );

  const legacy = verifyAllLabels(dual(), {
    keys: keys(),
  });
  // Merchant (P-256 key) fails as a plain mismatch under the ed25519
  // default; gateway (secret key) fails as VERIFICATION_ERROR.
  assert.deepEqual(
    legacy.map((r) => r.code),
    ["SIGNATURE_MISMATCH", "VERIFICATION_ERROR"],
  );
});

test("algFallbackByLabel: non-\"infer\"/false values and non-object maps fail fast", () => {
  for (const bad of ["auto", "ed25519", true, 1, null, undefined]) {
    assert.throws(
      () =>
        verifyAllLabels(dual(), {
          keys: keys(),
          algFallbackByLabel: { merchant: bad as never },
        }),
      /algFallbackByLabel/,
    );
  }
  assert.throws(
    () =>
      verifyAllLabels(dual(), {
        keys: keys(),
        algFallbackByLabel: [] as never,
      }),
    /algFallbackByLabel/,
  );
  // A mapped `false` is a valid strict choice, not a malformed value:
  // it must not throw — it rejects (SIGNATURE_MISMATCH for the P-256
  // merchant, VERIFICATION_ERROR for the secret-key gateway), as the
  // split tests above show.
  const strict = verifyAllLabels(dual(), {
    keys: keys(),
    algFallback: "infer",
    algFallbackByLabel: { merchant: false, gateway: false },
  });
  assert.deepEqual(
    strict.map((r) => r.code),
    ["SIGNATURE_MISMATCH", "VERIFICATION_ERROR"],
  );
});

test("algFallbackByLabel: single-label verifyRequest global path is unchanged", () => {
  // The gateway's HMAC wire is the discriminating case: under the
  // legacy ed25519 default it fails (an ed25519 merchant wire would
  // pass under the default too, so it cannot show the difference).
  const gatewayOnly = signGateway();
  const inferred = verifyRequest(gatewayOnly, {
    label: "gateway",
    key: GATEWAY,
    algFallback: "infer",
  });
  assert.equal(inferred.ok, true);
  assert.equal(inferred.alg, "hmac-sha256");

  const legacy = verifyRequest(gatewayOnly, {
    label: "gateway",
    key: GATEWAY,
  });
  assert.equal(legacy.ok, false);
  assert.equal(legacy.code, "VERIFICATION_ERROR");
});
