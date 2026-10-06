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

function signedWithout(
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

// ---------- requireCreated ----------

test("requireCreated: signature without created fails with MISSING_CREATED", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    expires: CREATED + 600,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireCreated: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

test("requireCreated off (default): undated signature still verifies", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    expires: CREATED + 600,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("requireCreated: forgery is reported as SIGNATURE_MISMATCH, not MISSING_CREATED", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    expires: CREATED + 600,
  });
  // Tamper with the signature bytes: authenticity check must fire first.
  const sigHeader = signed.headers["signature"]!;
  const tampered = sigHeader.replace(/^sig1=:/, "sig1=:AAAA");
  const forged: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers, signature: tampered },
  };
  const res = verifyRequest(forged, {
    key: publicKey,
    now: CREATED,
    requireCreated: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

// ---------- requireExpires ----------

test("requireExpires: signature without expires fails with MISSING_EXPIRES", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireExpires: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_EXPIRES");
});

test("requireExpires off (default): signature without expires still verifies", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

// ---------- combined ----------

test("both required: missing created is reported before missing expires", () => {
  const { signed, publicKey } = signedWithout({ keyid: "k", alg: "ed25519" });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireCreated: true,
    requireExpires: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

test("fully-dated signature passes both requirements", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      expires: CREATED + 600,
    },
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED,
    requireCreated: true,
    requireExpires: true,
  });
  assert.equal(res.ok, true);
});

// ---------- verifyRequestOrThrow ----------

test("verifyRequestOrThrow: missing created throws VerifyError with stable code", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    expires: CREATED + 600,
  });
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: CREATED,
        requireCreated: true,
      }),
    (e: unknown) =>
      isVerifyError(e) &&
      e.code === "MISSING_CREATED" &&
      e instanceof Error,
  );
});

test("verifyRequestOrThrow: dated signature does not throw when required", () => {
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
      expires: CREATED + 600,
    },
  );
  const res = verifyRequestOrThrow(signed, {
    key: publicKey,
    now: CREATED,
    requireCreated: true,
    requireExpires: true,
  });
  assert.equal(res.label, "sig1");
});

// ---------- verifyAllLabels ----------

test("verifyAllLabels: requirements apply per label; one bad label does not block others", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  // Label "gw": fully dated, goes through signRequest.
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
  // Label "merchant": hand-crafted, no `created` param.
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const mParams: SignatureParams = {
    keyid: "merchant",
    alg: "ed25519",
    expires: CREATED + 600,
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
    requireCreated: true,
  });
  assert.equal(results.length, 2);
  const byLabel = Object.fromEntries(results.map((r) => [r.label, r]));
  assert.equal(byLabel["gw"].ok, true);
  assert.equal(byLabel["merchant"].ok, false);
  assert.equal(byLabel["merchant"].code, "MISSING_CREATED");
});
