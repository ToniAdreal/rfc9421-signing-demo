import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  ReplayCache,
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  signatureInputValue,
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
// `signRequest` refuses an empty-string nonce and makes the nonce optional,
// so a nonce-less (or empty-nonce) third-party signature is built by hand
// using the public signature-base primitives, matching the wire shape a
// foreign implementation would send.
const COVERED = ["@method", "@authority", "@path"];

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

const CREATED = 1700000000;

function nonceLess() {
  return signedWith({ keyid: "k", alg: "ed25519", created: CREATED });
}

// ---------- requireNonce ----------

test("requireNonce: signature without nonce fails with MISSING_NONCE", () => {
  const { signed, publicKey } = nonceLess();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_NONCE");
});

test("requireNonce: empty-string nonce is treated as missing", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
    nonce: "",
  });
  assert.match(signed.headers["signature-input"], /;nonce=""/);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_NONCE");
});

test("requireNonce: forgery is reported as SIGNATURE_MISMATCH, not MISSING_NONCE", () => {
  const { signed, publicKey } = nonceLess();
  const sigHeader = signed.headers["signature"]!;
  const tampered = sigHeader.replace(/^sig1=:/, "sig1=:AAAA");
  const forged: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers, signature: tampered },
  };
  const res = verifyRequest(forged, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("requireNonce: signature carrying a nonce passes", () => {
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
      nonce: "replay-id-1",
    },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
  });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "replay-id-1");
});

// ---------- default behaviour unchanged ----------

test("requireNonce off (default): nonce-less signature still verifies, twice with a cache (bypass unchanged)", () => {
  const { signed, publicKey } = nonceLess();
  const cache = new ReplayCache();
  const first = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    replayCache: cache,
  });
  const second = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    replayCache: cache,
  });
  assert.equal(first.ok, true);
  // Without requireNonce the nonce-less signature bypasses the store
  // entirely, so re-verifying it is not reported as a replay.
  assert.equal(second.ok, true);
});

// ---------- interaction with replayCache ----------

test("requireNonce + replayCache: nonce-less signature fails with MISSING_NONCE instead of silently bypassing the cache", () => {
  const { signed, publicKey } = nonceLess();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
    replayCache: new ReplayCache(),
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_NONCE");
});

test("requireNonce + replayCache: present nonce passes once, then NONCE_REPLAY (require check precedes the store)", () => {
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
      nonce: "once-only",
    },
  );
  const cache = new ReplayCache();
  const opts = {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
    replayCache: cache,
  };
  const first = verifyRequest(signed, opts);
  assert.equal(first.ok, true);
  const second = verifyRequest(signed, opts);
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
});

// ---------- verifyRequestOrThrow ----------

test("verifyRequestOrThrow: missing nonce throws VerifyError with stable MISSING_NONCE code", () => {
  const { signed, publicKey } = nonceLess();
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: CREATED,
        requireNonce: true,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_NONCE" && e instanceof Error,
  );
});

// ---------- verifyAllLabels ----------

test("verifyAllLabels: requireNonce applies per label; the nonce-less label fails without blocking the other", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // Label "gw": carries a nonce, goes through signRequest.
  const gw = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
    },
    {
      keyId: "gw",
      alg: "ed25519",
      key: privateKey,
      label: "gw",
      created: CREATED,
      nonce: "gw-nonce",
    },
  );
  // Label "merchant": hand-crafted, no nonce param.
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const mParams: SignatureParams = {
    keyid: "merchant",
    alg: "ed25519",
    created: CREATED,
  };
  const base = buildSignatureBase(COVERED, req, mParams);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const merged: SignedHttpRequest = {
    method: "POST",
    url: req.url,
    headers: {
      "signature-input": `${gw.headers["signature-input"]}, ${signatureInputValue("merchant", COVERED, mParams)}`,
      signature: `${gw.headers["signature"]}, merchant=:${sig.toString("base64")}:`,
    },
  };
  const results = verifyAllLabels(merged, {
    key: publicKey,
    now: CREATED,
    requireNonce: true,
  });
  assert.equal(results.length, 2);
  const byLabel = Object.fromEntries(results.map((r) => [r.label, r]));
  assert.equal(byLabel["gw"].ok, true);
  assert.equal(byLabel["merchant"].ok, false);
  assert.equal(byLabel["merchant"].code, "MISSING_NONCE");
});
