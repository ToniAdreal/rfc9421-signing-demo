import test from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  createSign,
  randomBytes,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  generateEd25519KeyPair,
  generateP256KeyPair,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  type RequestLike,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

// Backlog #690: `algFallbackByLabel` (per-label algorithm fallback for
// wires that omit `alg`) and `candidateKeysByLabel` (per-label key
// rotation) have each been tested on their own, but never in
// combination. The open questions are whether the fallback is applied
// per candidate inside the rotation walk (rather than once for the
// whole label), and whether the two dimensions' exhaustion failures
// are distinguishable. Both are answered here by measurement, not by
// assumption: the fallback strategy is resolved per label, then the
// rotation walk in src/verify.ts repeats the whole verify-with-key
// unit per candidate — including its own fallback inference — and
// only SIGNATURE_MISMATCH advances the walk; any other code returns
// immediately, so a mis-shaped early candidate can stop the walk
// before the right key is ever tried.
//
// Fixture shape, mirroring test/algFallbackByLabel.test.ts: the
// merchant is a foreign signer that never emits the optional `alg`
// parameter, so the fallback dimension is actually exercised (an
// ed25519 wire carrying `alg` would pass under either strategy and
// could never show the split). The gateway is a domestic signer with
// an explicit `alg` and one static key, mapped to neither map — the
// control group that must stay green whatever the merchant does.

const BODY = '{"amount":100}';
const CREATED = 1700000000;

function baseRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: BODY,
  };
}

/**
 * Sign like a foreign signer that never emits `alg`: build the
 * signature base with params that carry no `alg`, then sign with
 * node:crypto directly (mirroring src/sign.ts's crypto choices:
 * P-256 raw r||s per RFC 9421 §3.3.4, ed25519, hmac-sha256).
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
  const params = { created: CREATED, keyid: opts.keyId }; // no alg, ever
  const base = buildSignatureBase(covered, { ...req, headers }, params);
  const key = opts.key;
  let sig: Buffer;
  if (key.type === "secret") {
    sig = createHmac("sha256", key).update(base, "utf8").digest();
  } else if (key.asymmetricKeyType === "ed25519") {
    // node:crypto's ed25519 path takes a null algorithm (same call
    // src/sign.ts makes); createSign("sha256") rejects the key.
    sig = edSign(null, Buffer.from(base, "utf8"), key);
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

const merchantOld = generateEd25519KeyPair();
const merchantNew = generateP256KeyPair();
const merchantRetired = generateP256KeyPair();
const merchantRealEd = generateEd25519KeyPair();
const wrongSecret = secretKey(randomBytes(32));
const gateway = generateEd25519KeyPair();

function signMerchant(pairKey: KeyObject, keyId: string) {
  return signWithoutAlg(baseRequest(), {
    keyId,
    key: pairKey,
    label: "merchant",
  });
}

function signGateway() {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@authority", "@path", "content-digest"],
  });
}

function dual(merchant: SignedHttpRequest): SignedHttpRequest {
  const g = signGateway();
  return {
    ...merchant,
    headers: {
      ...merchant.headers,
      "signature-input": `${merchant.headers["signature-input"]}, ${g.headers["signature-input"]}`,
      signature: `${merchant.headers["signature"]}, ${g.headers["signature"]}`,
    },
  };
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

// Merchant: infer fallback + rotation [old ed25519, new P-256].
// Gateway: static key, mapped to neither map.
const INFER_OPTS = {
  candidateKeysByLabel: {
    merchant: [merchantOld.publicKey, merchantNew.publicKey],
  },
  keys: { gateway: gateway.publicKey },
  algFallbackByLabel: { merchant: "infer" as const },
};

test("algFallbackByLabel x candidateKeysByLabel: fallback is inferred per candidate — a P-256 wire passes on the second candidate after the ed25519 candidate mismatches", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantNew.privateKey, "merchant-key-new")),
    INFER_OPTS,
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  // The winning candidate is the P-256 key, so the inferred
  // algorithm is ecdsa-p256-sha256 — not the ed25519 default the
  // first candidate was tried under.
  assert.equal(by["merchant"].alg, "ecdsa-p256-sha256");
  assert.equal(by["gateway"].ok, true);
});

test("algFallbackByLabel x candidateKeysByLabel: rotation order is respected — the same wire passes on the first candidate when the list is reversed", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantNew.privateKey, "merchant-key-new")),
    {
      ...INFER_OPTS,
      candidateKeysByLabel: {
        merchant: [merchantNew.publicKey, merchantOld.publicKey],
      },
    },
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].alg, "ecdsa-p256-sha256");
  assert.equal(by["gateway"].ok, true);
});

test("algFallbackByLabel x candidateKeysByLabel: fallback and candidates both exhausted — a retired P-256 wire reports SIGNATURE_MISMATCH and the gateway still passes", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantRetired.privateKey, "merchant-key-retired")),
    INFER_OPTS,
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("algFallbackByLabel x candidateKeysByLabel: strict merchant never infers — the same new-key P-256 wire fails against every candidate under the ed25519 default", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantNew.privateKey, "merchant-key-new")),
    {
      ...INFER_OPTS,
      algFallbackByLabel: { merchant: false },
    },
  );
  const by = byLabel(results);
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "SIGNATURE_MISMATCH");
  assert.equal(by["gateway"].ok, true);
});

test("algFallbackByLabel x candidateKeysByLabel: infer walks past a mismatching secret candidate to the real ed25519 key", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantRealEd.privateKey, "merchant-key-ed")),
    {
      candidateKeysByLabel: {
        merchant: [wrongSecret, merchantRealEd.publicKey],
      },
      keys: { gateway: gateway.publicKey },
      algFallbackByLabel: { merchant: "infer" as const },
    },
  );
  const by = byLabel(results);
  // The secret candidate infers hmac-sha256, mismatches, and the
  // walk advances; the ed25519 candidate then verifies.
  assert.equal(by["merchant"].ok, true);
  assert.equal(by["merchant"].alg, "ed25519");
  assert.equal(by["gateway"].ok, true);
});

test("algFallbackByLabel x candidateKeysByLabel: strict walks stop at a non-mismatch code — the same list under false reports VERIFICATION_ERROR and never tries the real key", () => {
  const results = verifyAllLabels(
    dual(signMerchant(merchantRealEd.privateKey, "merchant-key-ed")),
    {
      candidateKeysByLabel: {
        merchant: [wrongSecret, merchantRealEd.publicKey],
      },
      keys: { gateway: gateway.publicKey },
      algFallbackByLabel: { merchant: false },
    },
  );
  const by = byLabel(results);
  // Under the legacy ed25519 default, the secret candidate is not
  // a mismatch but a shape error (VERIFICATION_ERROR), and only
  // SIGNATURE_MISMATCH advances the walk — so the correct second
  // candidate is never reached. This is the documented walk
  // semantics in src/verify.ts, pinned here so a future change to
  // "advance on any failure" cannot slip in silently.
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "VERIFICATION_ERROR");
  assert.equal(by["gateway"].ok, true);
});
