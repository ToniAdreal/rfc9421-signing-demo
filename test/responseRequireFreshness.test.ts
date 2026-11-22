import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signatureInputValue,
  signResponse,
  verifyAllResponseLabels,
  verifyResponse,
  verifyResponseOrThrow,
  type HttpResponseLike,
  type RequestLike,
  type SignatureParams,
  type SignedHttpResponse,
  type VerifyResult,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signResponse` always emits `created`; a real third-party signer (a
// gateway answering a settlement callback) may omit it. The helpers
// below mint such signatures by hand using the public signature-base
// primitives, so the wire shape matches what a foreign implementation
// would send. The base is built over the exact `RequestLike` shape
// `verifyResponse` synthesizes internally (see `responseToRequestLike`
// in `src/response.ts`): empty method, the reserved `.invalid` URL,
// and the response `status` — `@status` is what the response
// signature binds, so the base must be built against it, not against
// a fabricated request method/URL.
//
// Backlog #1331: `verifyResponse` / `verifyAllResponseLabels` forward
// the whole `VerifyOptions` / `VerifyAllOptions` object to
// `verifyRequest` / `verifyAllLabels`, so the freshness-presence
// gates (`requireCreated` / `requireExpires`, per-label maps) should
// hold on the response side — but no test pinned that. The request
// side has the same coverage in `test/requireFreshness.test.ts` and
// `test/requireCreatedExpiresByLabel.test.ts`; this file is the
// response-side twin.
const CREATED = 1700000000;
const COVERED = ["@status"];

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

function responseRequestLike(): RequestLike {
  return {
    method: "",
    url: "https://response.invalid/",
    headers: {},
    status: 200,
  };
}

function signedResponseWithout(
  params: SignatureParams,
  label: string,
  pair: KeyPair,
): SignedHttpResponse {
  const req = responseRequestLike();
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    status: 200,
    headers: {
      "signature-input": signatureInputValue(label, COVERED, params),
      signature: `${label}=:${sig.toString("base64")}:`,
    },
  };
}

function signedResponseDated(label: string, pair: KeyPair): SignedHttpResponse {
  return signResponse(
    { status: 200, headers: { "content-type": "application/json" } },
    {
      label,
      keyId: label,
      alg: "ed25519",
      key: pair.privateKey,
      created: CREATED,
      expires: CREATED + 600,
    },
  );
}

function mergeResponseSignatures(
  a: SignedHttpResponse,
  b: SignedHttpResponse,
): SignedHttpResponse {
  return {
    status: a.status,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

function byLabel(results: VerifyResult[]) {
  return Object.fromEntries(results.map((r) => [r.label, r]));
}

function asResponse(signed: SignedHttpResponse): HttpResponseLike {
  return { status: signed.status, headers: signed.headers };
}

// ---------- verifyResponse: requireCreated ----------

test("requireCreated: response signature without created fails with MISSING_CREATED", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", expires: CREATED + 600 },
    "sig1",
    pair,
  );
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
    requireCreated: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

test("requireCreated off (default): undated response signature still verifies", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", expires: CREATED + 600 },
    "sig1",
    pair,
  );
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
  });
  assert.equal(res.ok, true);
});

test("requireCreated: forgery is reported as SIGNATURE_MISMATCH, not MISSING_CREATED", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", expires: CREATED + 600 },
    "sig1",
    pair,
  );
  // Tamper with the signature bytes: authenticity check must fire first.
  const sigHeader = signed.headers["signature"]!;
  const tampered = sigHeader.replace(/^sig1=:/, "sig1=:AAAA");
  const forged: SignedHttpResponse = {
    ...signed,
    headers: { ...signed.headers, signature: tampered },
  };
  const res = verifyResponse(asResponse(forged), {
    key: pair.publicKey,
    now: CREATED,
    requireCreated: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

// ---------- verifyResponse: requireExpires ----------

test("requireExpires: response signature without expires fails with MISSING_EXPIRES", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", created: CREATED },
    "sig1",
    pair,
  );
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
    requireExpires: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_EXPIRES");
});

test("requireExpires off (default): response signature without expires still verifies", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", created: CREATED },
    "sig1",
    pair,
  );
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
  });
  assert.equal(res.ok, true);
});

// ---------- verifyResponse: combined ----------

test("both required: missing created is reported before missing expires", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout({ keyid: "k", alg: "ed25519" }, "sig1", pair);
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
    requireCreated: true,
    requireExpires: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CREATED");
});

test("fully-dated response signature passes both requirements", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseDated("sig1", pair);
  const res = verifyResponse(asResponse(signed), {
    key: pair.publicKey,
    now: CREATED,
    requireCreated: true,
    requireExpires: true,
  });
  assert.equal(res.ok, true);
});

// ---------- verifyResponseOrThrow ----------

test("verifyResponseOrThrow: missing created throws VerifyError with stable code", () => {
  const pair = generateEd25519KeyPair();
  const signed = signedResponseWithout(
    { keyid: "k", alg: "ed25519", expires: CREATED + 600 },
    "sig1",
    pair,
  );
  assert.throws(
    () =>
      verifyResponseOrThrow(asResponse(signed), {
        key: pair.publicKey,
        now: CREATED,
        requireCreated: true,
      }),
    (e: unknown) =>
      isVerifyError(e) &&
      e.code === "MISSING_CREATED" &&
      e instanceof Error,
  );
});

// ---------- verifyAllResponseLabels: per-label maps ----------

test("merchant gated on created, gateway ungated: merchant missing created fails, gateway passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeResponseSignatures(
    signedResponseWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedResponseWithout(
      { keyid: "gateway", alg: "ed25519", expires: CREATED + 600 },
      "gateway",
      gateway,
    ),
  );
  const by = byLabel(
    verifyAllResponseLabels(asResponse(merged), {
      now: CREATED,
      keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
      requireCreatedByLabel: { merchant: true },
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // Same missing field, unmapped label: no requirement, so it passes.
  assert.equal(by["gateway"].ok, true);
});

test("merchant gated on expires, gateway ungated: merchant missing expires fails, gateway passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeResponseSignatures(
    signedResponseWithout(
      { keyid: "merchant", alg: "ed25519", created: CREATED },
      "merchant",
      merchant,
    ),
    signedResponseWithout(
      { keyid: "gateway", alg: "ed25519", created: CREATED },
      "gateway",
      gateway,
    ),
  );
  const by = byLabel(
    verifyAllResponseLabels(asResponse(merged), {
      now: CREATED,
      keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
      requireExpiresByLabel: { merchant: true },
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_EXPIRES");
  assert.equal(by["gateway"].ok, true);
});

test("global requireCreated true plus map false: mapped label exempt, unmapped label still gated", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeResponseSignatures(
    signedResponseWithout(
      { keyid: "merchant", alg: "ed25519", expires: CREATED + 600 },
      "merchant",
      merchant,
    ),
    signedResponseWithout(
      { keyid: "gateway", alg: "ed25519", expires: CREATED + 600 },
      "gateway",
      gateway,
    ),
  );
  const by = byLabel(
    verifyAllResponseLabels(asResponse(merged), {
      now: CREATED,
      keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
      requireCreated: true,
      requireCreatedByLabel: { merchant: false },
    }),
  );
  // The map wins over the global: merchant is explicitly exempt.
  assert.equal(by["merchant"].ok, true);
  // Gateway is unmapped, so it falls back to the global requirement.
  assert.equal(by["gateway"].ok, false);
  assert.equal(by["gateway"].code, "MISSING_CREATED");
});

test("both maps on merchant, neither on gateway: merchant missing both fails on created, gateway passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const merged = mergeResponseSignatures(
    signedResponseWithout({ keyid: "merchant", alg: "ed25519" }, "merchant", merchant),
    signedResponseWithout({ keyid: "gateway", alg: "ed25519" }, "gateway", gateway),
  );
  const by = byLabel(
    verifyAllResponseLabels(asResponse(merged), {
      now: CREATED,
      keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
      requireCreatedByLabel: { merchant: true },
      requireExpiresByLabel: { merchant: true },
    }),
  );
  assert.equal(by["merchant"].ok, false);
  assert.equal(by["merchant"].code, "MISSING_CREATED");
  // Same missing fields, unmapped label: no requirement, so it passes.
  assert.equal(by["gateway"].ok, true);
});
