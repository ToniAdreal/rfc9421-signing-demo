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
// `signRequest` always emits `created`; a real third-party signer may omit
// it. This helper builds such signatures by hand using the public
// signature-base primitives, so the wire shape matches what a foreign
// implementation would send.
const COVERED = ["@method", "@authority", "@path"];

function signedWithoutCreated(
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

const NOW = 1700000000;

function agedSignature(created: number): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "webhook-signer",
      alg: "ed25519",
      key: privateKey,
      created,
    },
  );
  return { signed, publicKey };
}

// ---------- core behavior ----------

test("maxSignatureAgeSec: 6-hour-old signature without expires is rejected", () => {
  const { signed, publicKey } = agedSignature(NOW - 6 * 3600);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_OLD");
});

test("maxSignatureAgeSec: age exactly at the limit passes (strict >)", () => {
  const { signed, publicKey } = agedSignature(NOW - 300);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, true);
});

test("maxSignatureAgeSec: fresh signature passes", () => {
  const { signed, publicKey } = agedSignature(NOW);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, true);
});

test("maxSignatureAgeSec unset (default): old signature still verifies — backwards compatible", () => {
  const { signed, publicKey } = agedSignature(NOW - 6 * 3600);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
});

test("maxSignatureAgeSec: signature without created is not killed by the age check", () => {
  const { signed, publicKey } = signedWithoutCreated({
    keyid: "k",
    alg: "ed25519",
    expires: NOW + 600,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, true);
});

test("maxSignatureAgeSec + requireCreated: undated signature reports MISSING_CREATED, not SIGNATURE_TOO_OLD", () => {
  const { signed, publicKey } = signedWithoutCreated({
    keyid: "k",
    alg: "ed25519",
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireCreated: true,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

test("maxSignatureAgeSec: slightly-future created within skew passes the age check", () => {
  // now - created is negative, so the > comparison never fires — a future
  // created still goes through the normal CREATED_IN_FUTURE path.
  const { signed, publicKey } = agedSignature(NOW + 30);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, true);
});

test("maxSignatureAgeSec: forgery is still reported as SIGNATURE_MISMATCH", () => {
  const { signed, publicKey } = agedSignature(NOW - 6 * 3600);
  const tampered = signed.headers["signature"]!.replace(/^sig1=:/, "sig1=:AAAA");
  const forged: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers, signature: tampered },
  };
  const res = verifyRequest(forged, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

// ---------- configuration errors ----------

test("maxSignatureAgeSec: negative, NaN, Infinity, non-number all throw a configuration error", () => {
  const req: RequestLike = { method: "GET", url: "https://a.example/", headers: {} };
  const bad = [-1, Number.NaN, Number.POSITIVE_INFINITY, "300", null];
  for (const v of bad) {
    assert.throws(
      () =>
        verifyRequest(req, {
          key: generateEd25519KeyPair().publicKey,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          maxSignatureAgeSec: v as any,
        }),
      (e: unknown) =>
        e instanceof Error &&
        /maxSignatureAgeSec.*non-negative finite number/.test(e.message),
      `expected a configuration error for ${String(v)}`,
    );
  }
});

test("maxSignatureAgeSec: zero is a legal window (anything with created <= now fails)", () => {
  const { signed, publicKey } = agedSignature(NOW - 1);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 0,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_OLD");
});

// ---------- verifyRequestOrThrow / verifyAllLabels ----------

test("verifyRequestOrThrow: old signature throws VerifyError with code SIGNATURE_TOO_OLD", () => {
  const { signed, publicKey } = agedSignature(NOW - 6 * 3600);
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: NOW,
        maxSignatureAgeSec: 300,
      }),
    (e: unknown) =>
      isVerifyError(e) &&
      e.code === "SIGNATURE_TOO_OLD" &&
      e instanceof Error,
  );
});

test("verifyAllLabels: age check applies per label; one stale label does not block others", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const fresh = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      keyId: "fresh",
      alg: "ed25519",
      key: privateKey,
      label: "fresh",
      created: NOW,
    },
  );
  const staleReq: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const staleParams: SignatureParams = {
    keyid: "stale",
    alg: "ed25519",
    created: NOW - 6 * 3600,
  };
  const staleBase = buildSignatureBase(COVERED, staleReq, staleParams);
  const staleSig = edSign(null, Buffer.from(staleBase, "utf8"), privateKey);
  const merged: SignedHttpRequest = {
    method: "POST",
    url: staleReq.url,
    headers: {
      "signature-input": `${fresh.headers["signature-input"]}, ${signatureInputValue("stale", COVERED, staleParams)}`,
      signature: `${fresh.headers["signature"]}, stale=:${staleSig.toString("base64")}:`,
    },
  };
  const results = verifyAllLabels(merged, {
    key: publicKey,
    now: NOW,
    maxSignatureAgeSec: 300,
  });
  assert.equal(results.length, 2);
  const byLabel = Object.fromEntries(results.map((r) => [r.label, r]));
  assert.equal(byLabel["fresh"].ok, true);
  assert.equal(byLabel["stale"].ok, false);
  assert.equal(byLabel["stale"].code, "SIGNATURE_TOO_OLD");
});
