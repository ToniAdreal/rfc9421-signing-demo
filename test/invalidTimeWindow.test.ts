import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
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
// `signRequest` refuses to mint a signature whose `expires` is earlier
// than its `created` (signing-side guard), so a contradictory window can
// only arrive from a third-party / hand-built signer. This helper builds
// such signatures by hand using the public signature-base primitives, so
// the wire shape matches what a foreign implementation would send.
const COVERED = ["@method", "@authority", "@path"];

function signedWith(
  params: SignatureParams,
  label = "sig1",
): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"];
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
  return { signed, publicKey, privateKey };
}

const CREATED = 1700000000;

// ---------- the vulnerability: born-expired signature passed ----------

test("created > expires inside wide tolerances fails with INVALID_TIME_WINDOW", () => {
  // created = CREATED+100, expires = CREATED. At now = CREATED+50 the
  // individual checks both pass under wide tolerances: not expired
  // (CREATED+50 <= CREATED + 120 tolerance) and not in the future
  // (CREATED+100 <= CREATED+50 + 60 skew). Before this fix the result
  // was ok:true for a signature that was expired at birth.
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED + 100,
    expires: CREATED,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 50,
    expiredToleranceSec: 120,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "INVALID_TIME_WINDOW");
});

test("created > expires by one second fails even with default tolerances at a passing instant", () => {
  // now === expires: not past expiry; created is 1s in the future,
  // inside the default 60s skew — only the window check can reject it.
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED + 1,
    expires: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, false);
  assert.equal(res.code, "INVALID_TIME_WINDOW");
});

// ---------- boundary: expires === created stays legal ----------

test("expires === created still verifies (mirrors the signing side)", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
    expires: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

// ---------- missing timestamps never trigger the check ----------

test("missing created (expires only) does not trigger INVALID_TIME_WINDOW", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    expires: CREATED + 600,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("missing expires (created only) does not trigger INVALID_TIME_WINDOW", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("missing both timestamps does not trigger INVALID_TIME_WINDOW", () => {
  const { signed, publicKey } = signedWith({ keyid: "k", alg: "ed25519" });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

// ---------- forgeries report their true failure mode first ----------

test("forged contradictory signature reports SIGNATURE_MISMATCH, not INVALID_TIME_WINDOW", () => {
  const { signed } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED + 100,
    expires: CREATED,
  });
  // Verify against a *different* keypair's public key: the cryptographic
  // check must fire before the window check.
  const { publicKey: wrongKey } = generateEd25519KeyPair();
  const res = verifyRequest(signed, {
    key: wrongKey,
    now: CREATED + 50,
    expiredToleranceSec: 120,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

// ---------- verifyRequestOrThrow ----------

test("verifyRequestOrThrow: contradictory window throws VerifyError with stable INVALID_TIME_WINDOW code", () => {
  const { signed, publicKey } = signedWith({
    keyid: "k",
    alg: "ed25519",
    created: CREATED + 100,
    expires: CREATED,
  });
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: CREATED + 50,
        expiredToleranceSec: 120,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "INVALID_TIME_WINDOW" && e instanceof Error,
  );
});

// ---------- verifyAllLabels: per-label independence ----------

test("verifyAllLabels: contradictory label fails with INVALID_TIME_WINDOW, good label still verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // Label "gw": fully consistent window, goes through signRequest.
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
      expires: CREATED + 600,
    },
  );
  // Label "merchant": hand-crafted contradictory window, signed with the
  // same private key (build the base by hand, as a foreign signer would).
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const mParams: SignatureParams = {
    keyid: "merchant",
    alg: "ed25519",
    created: CREATED + 100,
    expires: CREATED,
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
    now: CREATED + 50,
    expiredToleranceSec: 120,
  });
  assert.equal(results.length, 2);
  const byLabel = Object.fromEntries(results.map((r) => [r.label, r]));
  assert.equal(byLabel["gw"].ok, true);
  assert.equal(byLabel["merchant"].ok, false);
  assert.equal(byLabel["merchant"].code, "INVALID_TIME_WINDOW");
});
