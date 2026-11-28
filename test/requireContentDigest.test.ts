import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  digest,
  generateEd25519KeyPair,
  isVerifyError,
  signResponse,
  signatureInputValue,
  verifyAllLabels,
  verifyAllLabelsAsync,
  verifyAllResponseLabels,
  verifyRequest,
  verifyRequestAsync,
  verifyRequestOrThrow,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
  type SignatureParams,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// Backlog #1457: the body-digest check only runs when a
// `content-digest` header is present, so a signed request with a body
// and no digest at all verifies against headers alone. The hand-built
// helpers below mint such signatures with the public signature-base
// primitives, so the wire shape matches what a foreign implementation
// would send — `signRequest` always emits the digest when the body is
// covered, and cannot mint a digest-less body at all.
const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";
const BODY = '{"amount":10630,"currency":"USD"}';
const COVERED = ["@method", "@authority", "@path"];

const { publicKey, privateKey } = generateEd25519KeyPair();
const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function digestOf(body: string | Buffer, alg: "sha-256" | "sha-512"): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(buf).digest("base64")}:`;
}

/** Sign `body` over COVERED with no `content-digest` header anywhere. */
function signedWithBody(
  body: string | Buffer | Uint8Array | undefined,
  label = "sig1",
  pair: { publicKey: typeof publicKey; privateKey: typeof privateKey } = {
    publicKey,
    privateKey,
  },
): SignedHttpRequest {
  const params: SignatureParams = {
    keyid: "k",
    alg: "ed25519",
    created: CREATED,
  };
  const req = { method: "POST", url: URL, headers: {}, body };
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  const signed: SignedHttpRequest = {
    method: "POST",
    url: URL,
    headers: {
      "signature-input": signatureInputValue(label, COVERED, params),
      signature: `${label}=:${sig.toString("base64")}:`,
    },
    body,
  };
  assert.equal(signed.headers["content-digest"], undefined);
  return signed;
}

/** Sign `body` covering `content-digest` with the correct digest. */
function signedWithDigestHeader(body: string | Buffer): SignedHttpRequest {
  const headers: Record<string, string> = {
    "content-digest": digestOf(body, "sha-512"),
  };
  const covered = [...COVERED, "content-digest"];
  const params: SignatureParams = {
    created: CREATED,
    keyid: "k",
    alg: "ed25519",
  };
  const req = { method: "POST", url: URL, headers, body };
  const base = buildSignatureBase(covered, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  headers["signature-input"] = signatureInputValue("sig1", covered, params);
  headers["signature"] = `sig1=:${sig.toString("base64")}:`;
  return { method: "POST", url: URL, headers, body };
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

/** Dual-sign `body` (no `content-digest` header) under two labels. */
function dualSignedWithBody(body: string): SignedHttpRequest {
  const merchantSigned = signedWithBody(body, "merchant", merchant);
  const gatewaySigned = signedWithBody(body, "gateway", gateway);
  return mergeSignatures(merchantSigned, gatewaySigned);
}

function dualKeys() {
  return {
    keys: {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    },
    now: NOW,
  };
}

/** Flip the last base64 character of the signature: a forgery. */
function forged(signed: SignedHttpRequest): SignedHttpRequest {
  const sig = signed.headers["signature"] as string;
  const flipped = sig.slice(0, -2) + (sig.endsWith("A:") ? "B:" : "A:");
  return { ...signed, headers: { ...signed.headers, signature: flipped } };
}

// ---------- requireContentDigest: single label ----------

test("requireContentDigest: string body without content-digest fails with MISSING_CONTENT_DIGEST", () => {
  const signed = signedWithBody(BODY);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("requireContentDigest: Buffer body without content-digest fails", () => {
  const signed = signedWithBody(Buffer.from(BODY, "utf8"));
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("requireContentDigest: Uint8Array body without content-digest fails", () => {
  const signed = signedWithBody(new TextEncoder().encode(BODY));
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("requireContentDigest: header present and matching still verifies (existing digest path)", () => {
  const signed = signedWithDigestHeader(BODY);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: header present but body tampered still fails with BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY);
  const tampered = { ...signed, body: '{"amount":1,"currency":"USD"}' };
  const res = verifyRequest(tampered, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("requireContentDigest: empty string body passes (nothing to bind)", () => {
  const signed = signedWithBody("");
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: empty Buffer body passes", () => {
  const signed = signedWithBody(Buffer.alloc(0));
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: absent body passes", () => {
  const signed = signedWithBody(undefined);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: unset (default) leaves a digest-less body verifying", () => {
  const signed = signedWithBody(BODY);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: explicit false behaves like unset", () => {
  const signed = signedWithBody(BODY);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: false,
  });
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("requireContentDigest: forged signature on a digest-less body reports MISSING_CONTENT_DIGEST (pre-crypto policy gate)", () => {
  const signed = forged(signedWithBody(BODY));
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("requireContentDigest: a legacy Digest header does not satisfy the requirement", () => {
  const signed = signedWithBody(BODY);
  const withLegacyDigest: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      digest: digest(BODY, "sha-256"),
    },
  };
  const res = verifyRequest(withLegacyDigest, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("requireContentDigest: verifyRequestOrThrow throws VerifyError with the code", () => {
  const signed = signedWithBody(BODY);
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        now: NOW,
        requireContentDigest: true,
      }),
    (e: unknown) =>
      isVerifyError(e) && e.code === "MISSING_CONTENT_DIGEST",
  );
});

test("requireContentDigest: verifyRequestAsync honors the gate", async () => {
  const signed = signedWithBody(BODY);
  const res = await verifyRequestAsync(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
  const withHeader = signedWithDigestHeader(BODY);
  const ok = await verifyRequestAsync(withHeader, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(ok.ok, true, JSON.stringify(ok));
});

test("requireContentDigest: misspelled option key throws (fail-closed unknown-option check)", () => {
  const signed = signedWithBody(BODY);
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        now: NOW,
        requireContentDigests: true,
      } as never),
    /unknown option.*requireContentDigests/,
  );
});

// ---------- requireContentDigestByLabel ----------

test("requireContentDigestByLabel: per-label isolation (merchant strict, gateway lenient)", () => {
  const signed = dualSignedWithBody(BODY);
  const results = verifyAllLabels(signed, {
    ...dualKeys(),
    requireContentDigestByLabel: { merchant: true },
  });
  assert.equal(results.length, 2);
  const byLabel = new Map(results.map((r) => [r.label, r]));
  assert.equal(byLabel.get("merchant")?.ok, false);
  assert.equal(byLabel.get("merchant")?.code, "MISSING_CONTENT_DIGEST");
  assert.equal(byLabel.get("gateway")?.ok, true, JSON.stringify(results));
});

test("requireContentDigestByLabel: global true applies to every label without a map entry", () => {
  const signed = dualSignedWithBody(BODY);
  const results = verifyAllLabels(signed, {
    ...dualKeys(),
    requireContentDigest: true,
  });
  assert.equal(results.length, 2);
  for (const r of results) {
    assert.equal(r.ok, false);
    assert.equal(r.code, "MISSING_CONTENT_DIGEST");
  }
});

test("requireContentDigestByLabel: per-label false overrides the global true", () => {
  const signed = dualSignedWithBody(BODY);
  const results = verifyAllLabels(signed, {
    ...dualKeys(),
    requireContentDigest: true,
    requireContentDigestByLabel: { gateway: false },
  });
  assert.equal(results.length, 2);
  const byLabel = new Map(results.map((r) => [r.label, r]));
  assert.equal(byLabel.get("merchant")?.ok, false);
  assert.equal(byLabel.get("merchant")?.code, "MISSING_CONTENT_DIGEST");
  assert.equal(byLabel.get("gateway")?.ok, true, JSON.stringify(results));
});

test("requireContentDigestByLabel: non-boolean map value is a configuration error", () => {
  const signed = dualSignedWithBody(BODY);
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        ...dualKeys(),
        requireContentDigestByLabel: { merchant: "yes" as never },
      }),
    /requireContentDigestByLabel\["merchant"\]` must be a boolean/,
  );
});

test("requireContentDigestByLabel: verifyAllLabelsAsync isolates per label", async () => {
  const signed = dualSignedWithBody(BODY);
  const results = await verifyAllLabelsAsync(signed, {
    ...dualKeys(),
    requireContentDigestByLabel: { merchant: true },
  });
  assert.equal(results.length, 2);
  const byLabel = new Map(results.map((r) => [r.label, r]));
  assert.equal(byLabel.get("merchant")?.ok, false);
  assert.equal(byLabel.get("merchant")?.code, "MISSING_CONTENT_DIGEST");
  assert.equal(byLabel.get("gateway")?.ok, true, JSON.stringify(results));
});

// ---------- response side inherits through the shared path ----------

test("requireContentDigest: verifyResponse inherits the gate for signed responses", () => {
  const res = { status: 200, headers: {}, body: BODY };
  const signed: SignedHttpResponse = signResponse(res, {
    key: privateKey,
    keyId: "k",
    alg: "ed25519",
    created: CREATED,
    coveredComponents: ["@status"],
  });
  assert.equal(signed.headers["content-digest"], undefined);
  const rejected = verifyResponse(signed, {
    key: publicKey,
    now: NOW,
    requireContentDigest: true,
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, "MISSING_CONTENT_DIGEST");
  const accepted = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
});

test("requireContentDigest: verifyAllResponseLabels inherits the per-label gate", () => {
  const merchantRes = signResponse(
    { status: 200, headers: {}, body: BODY },
    {
      label: "merchant",
      key: merchant.privateKey,
      keyId: "merchant-key",
      alg: "ed25519",
      created: CREATED,
      coveredComponents: ["@status"],
    },
  );
  const gatewayRes = signResponse(
    { status: 200, headers: {}, body: BODY },
    {
      label: "gateway",
      key: gateway.privateKey,
      keyId: "gateway-key",
      alg: "ed25519",
      created: CREATED,
      coveredComponents: ["@status"],
    },
  );
  const dual: SignedHttpResponse = {
    ...merchantRes,
    headers: {
      ...merchantRes.headers,
      "signature-input": `${merchantRes.headers["signature-input"]}, ${gatewayRes.headers["signature-input"]}`,
      signature: `${merchantRes.headers["signature"]}, ${gatewayRes.headers["signature"]}`,
    },
  };
  assert.equal(dual.headers["content-digest"], undefined);
  const results = verifyAllResponseLabels(dual, {
    keys: {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    },
    now: NOW,
    requireContentDigestByLabel: { merchant: true },
  });
  assert.equal(results.length, 2);
  const byLabel = new Map(results.map((r) => [r.label, r]));
  assert.equal(byLabel.get("merchant")?.ok, false);
  assert.equal(byLabel.get("merchant")?.code, "MISSING_CONTENT_DIGEST");
  assert.equal(byLabel.get("gateway")?.ok, true, JSON.stringify(results));
});
