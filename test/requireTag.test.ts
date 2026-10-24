import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  addSignature,
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signRequest,
  signatureInputValue,
  buildSignatureBase,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signRequest` refuses an empty-string tag and makes the tag optional,
// so a tag-less (or empty-tag) third-party signature is built by hand
// using the public signature-base primitives, matching the wire shape a
// foreign implementation would send.
const COVERED = ["@method", "@authority", "@path"];
const CREATED = 1700000000;
const TAG = "payment-webhook-v1";

function signedWith(
  params: SignatureParams,
  label = "sig1",
): {
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
      "signature-input": signatureInputValue(label, COVERED, params),
      signature: `${label}=:${sig.toString("base64")}:`,
    },
  };
  return { signed, publicKey };
}

function tagLess() {
  return signedWith({ keyid: "k", alg: "ed25519", created: CREATED });
}

// ---------- requireTag ----------

test("requireTag: signature without tag fails with MISSING_TAG", () => {
  const { signed, publicKey } = tagLess();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_TAG");
  assert.equal(res.reason, "signature carries no `tag` but requireTag is set");
});

test("requireTag: empty-string tag is treated as missing", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
    tag: "",
  });
  assert.match(signed.headers["signature-input"], /;tag=""/);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_TAG");
});

test("requireTag: forgery is reported as SIGNATURE_MISMATCH, not MISSING_TAG", () => {
  const { signed, publicKey } = tagLess();
  const sigHeader = signed.headers["signature"]!;
  const tampered = sigHeader.replace(/^sig1=:/, "sig1=:AAAA");
  const forged: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers, signature: tampered },
  };
  const res = verifyRequest(forged, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("requireTag: signature carrying a tag passes and echoes it", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      tag: TAG,
    },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
  });
  assert.equal(res.ok, true);
  assert.equal(res.tag, TAG);
});

test("requireTag: missing tag checked before the window checks (expired + tag-less reports MISSING_TAG)", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
    expires: CREATED + 60,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 3600,
    requireTag: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_TAG");
});

test("requireTag: pinned expectedTag still reports TAG_MISMATCH for a missing tag", () => {
  const { signed, publicKey } = tagLess();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
    expectedTag: TAG,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "TAG_MISMATCH");
});

test("requireTag: matching pinned tag passes with requireTag set", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      tag: TAG,
    },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireTag: true,
    expectedTag: TAG,
  });
  assert.equal(res.ok, true);
});

// ---------- default behaviour unchanged ----------

test("requireTag off (default): tag-less signature still verifies", () => {
  const { signed, publicKey } = tagLess();
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
  assert.equal(res.tag, undefined);
});

// ---------- verifyRequestOrThrow ----------

test("requireTag: OrThrow throws VerifyError with code MISSING_TAG, and passes with a tag", () => {
  const { signed, publicKey } = tagLess();
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: CREATED,
        requireTag: true,
      }),
    (e: unknown) => isVerifyError(e) && e.code === "MISSING_TAG",
  );
  const { publicKey: pk2, privateKey } = generateEd25519KeyPair();
  const tagged = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      tag: TAG,
    },
  );
  const ok = verifyRequestOrThrow(tagged, {
    key: pk2,
    now: CREATED,
    requireTag: true,
  });
  assert.equal(ok.tag, TAG);
});

// ---------- verifyAllLabels ----------

test("requireTag: verifyAllLabels reports a tag-less label independently of a tagged one", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ amount: 250, currency: "USD" }),
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    tag: "settlement-webhook-v1",
  });
  const results = verifyAllLabels(dual, {
    key: publicKey,
    now: CREATED + 60,
    keys: { gateway: gatewaySecret },
    requireTag: true,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "MISSING_TAG");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].tag, "settlement-webhook-v1");
});
