import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #976: the verify entry points parsed the `signature-input` /
// `signature` headers with no size bound anywhere — a hostile peer
// could send megabytes of header and the parser would chew through
// all of it before failing at the semantic layer. `VerifyOptions`
// gains `maxSignatureInputLength` / `maxSignatureLength` (each
// defaulting to 64 KiB), enforced fail-closed before any parsing;
// `VerifyAllOptions` gains the per-label maps, and `verifyResponse`
// gates before its own guard parse too.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function signedEd(): {
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
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  return { signed, publicKey };
}

function dualSignedEd(): {
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
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  // Both labels share one key pair (different keyIds): the test is
  // about length limits, not key separation, so a single `key` must
  // verify both labels.
  const dual = addSignature(signed, {
    keyId: "gw",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig2",
  });
  return { signed: dual, publicKey };
}

function signedSettlementResponse(): {
  signed: SignedHttpResponse;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: '{"settled":true}',
    },
    {
      keyId: "gw",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  return { signed, publicKey };
}

function asResponseRequest(signed: SignedHttpResponse): {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: string | Buffer;
} {
  return {
    status: signed.status,
    headers: { ...signed.headers },
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  };
}

// ---------- request side: over-limit headers ----------

test("request: oversized signature-input is rejected before parsing", () => {
  const { publicKey } = signedEd();
  // 200 KB of garbage: without the gate this would surface as
  // MALFORMED_SIGNATURE_INPUT — the too-large code proves the gate
  // fires before the parser ever runs.
  const res = verifyRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {
        "signature-input": "x".repeat(200_000),
        signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
      },
      body: '{"amount":100}',
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
  assert.match(res.reason ?? "", /200000 bytes/);
});

test("request: oversized signature header is rejected before parsing", () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(
    {
      ...signed,
      headers: { ...signed.headers, signature: "sig1=:" + "A".repeat(70_000) + ":," },
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_LARGE");
  assert.match(res.reason ?? "", /maxSignatureLength=65536/);
});

test("request: default limit applies with no options set", () => {
  const { signed, publicKey } = signedEd();
  // A valid request still verifies under the default 64 KiB bound.
  assert.equal(verifyRequest(signed, { key: publicKey, now: NOW }).ok, true);
  // 65,537 bytes of input header trips the default.
  const res = verifyRequest(
    {
      ...signed,
      headers: { ...signed.headers, "signature-input": "x".repeat(65_537) },
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
});

// ---------- request side: boundary and custom limits ----------

test("request: signature-input exactly at a custom limit verifies", () => {
  const { signed, publicKey } = signedEd();
  const inputBytes = Buffer.byteLength(
    signed.headers["signature-input"] as string,
    "utf8",
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureInputLength: inputBytes,
  });
  assert.equal(res.ok, true);
});

test("request: signature-input one byte over a custom limit fails", () => {
  const { signed, publicKey } = signedEd();
  const inputBytes = Buffer.byteLength(
    signed.headers["signature-input"] as string,
    "utf8",
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureInputLength: inputBytes - 1,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
});

test("request: signature exactly at a custom limit verifies, one byte under fails", () => {
  const { signed, publicKey } = signedEd();
  const sigBytes = Buffer.byteLength(
    signed.headers["signature"] as string,
    "utf8",
  );
  assert.equal(
    verifyRequest(signed, {
      key: publicKey,
      now: NOW,
      maxSignatureLength: sigBytes,
    }).ok,
    true,
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLength: sigBytes - 1,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_LARGE");
});

test("request: custom small limit rejects a valid signed request", () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureInputLength: 50,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
  assert.match(res.reason ?? "", /maxSignatureInputLength=50/);
});

// ---------- request side: measurement and config errors ----------

test("request: multi-value signature-input is measured after joining", () => {
  const { signed, publicKey } = signedEd();
  const res = verifyRequest(
    {
      ...signed,
      headers: {
        ...signed.headers,
        "signature-input": [
          signed.headers["signature-input"] as string,
          "x".repeat(70_000),
        ],
      } as Record<string, string | string[]>,
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
});

test("request: non-ASCII headers are measured in bytes, not characters", () => {
  const { publicKey } = signedEd();
  const base = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    body: '{"amount":100}',
  };
  // "é" is 2 UTF-8 bytes: 400 chars = 800 bytes > 700-byte limit.
  const tooLarge = verifyRequest(
    { ...base, headers: { "signature-input": "é".repeat(400), signature: "sig1=:AA==:" } },
    { key: publicKey, now: NOW, maxSignatureInputLength: 700 },
  );
  assert.equal(tooLarge.ok, false);
  assert.equal(tooLarge.code, "SIGNATURE_INPUT_TOO_LARGE");
  // 300 chars = 600 bytes <= 700: the gate passes and the parser
  // reports the garbage as malformed instead.
  const malformed = verifyRequest(
    { ...base, headers: { "signature-input": "é".repeat(300), signature: "sig1=:AA==:" } },
    { key: publicKey, now: NOW, maxSignatureInputLength: 700 },
  );
  assert.equal(malformed.ok, false);
  assert.equal(malformed.code, "MALFORMED_SIGNATURE_INPUT");
});

test("request: invalid length limits throw a configuration error", () => {
  const { signed, publicKey } = signedEd();
  for (const bad of [0, -1, 1.5, Number.NaN, "100"]) {
    assert.throws(
      () =>
        verifyRequest(signed, {
          key: publicKey,
          now: NOW,
          maxSignatureInputLength: bad as never,
        }),
      /maxSignatureInputLength.*must be a positive integer/,
    );
    assert.throws(
      () =>
        verifyRequest(signed, {
          key: publicKey,
          now: NOW,
          maxSignatureLength: bad as never,
        }),
      /maxSignatureLength.*must be a positive integer/,
    );
  }
});

test("request: verifyRequestOrThrow raises a VerifyError with the limit code", () => {
  const { signed, publicKey } = signedEd();
  try {
    verifyRequestOrThrow(signed, {
      key: publicKey,
      now: NOW,
      maxSignatureInputLength: 50,
    });
    assert.fail("expected a throw");
  } catch (e) {
    assert.equal(isVerifyError(e), true);
    assert.equal((e as { code: string }).code, "SIGNATURE_INPUT_TOO_LARGE");
  }
});

// ---------- response side ----------

test("response: oversized signature-input is rejected before the guard parses it", () => {
  const { publicKey } = signedSettlementResponse();
  // Garbage input: without the response-side gate, verifyResponse's
  // guard would parse this first and report MALFORMED instead.
  const res = verifyResponse(
    {
      status: 200,
      headers: {
        "signature-input": "x".repeat(200_000),
        signature: "sig1=:AA==:",
      },
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_INPUT_TOO_LARGE");
});

test("response: oversized signature header is rejected", () => {
  const { signed, publicKey } = signedSettlementResponse();
  const res = verifyResponse(
    {
      ...asResponseRequest(signed),
      headers: { ...signed.headers, signature: "sig1=:" + "A".repeat(70_000) + ":" },
    },
    { key: publicKey, now: NOW },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_LARGE");
});

test("response: valid response verifies at exact custom limits", () => {
  const { signed, publicKey } = signedSettlementResponse();
  const inputBytes = Buffer.byteLength(
    signed.headers["signature-input"] as string,
    "utf8",
  );
  const sigBytes = Buffer.byteLength(
    signed.headers["signature"] as string,
    "utf8",
  );
  const res = verifyResponse(asResponseRequest(signed), {
    key: publicKey,
    now: NOW,
    maxSignatureInputLength: inputBytes,
    maxSignatureLength: sigBytes,
  });
  assert.equal(res.ok, true);
});

// ---------- multi-label ----------

test("verifyAllLabels: pre-parse gate rejects an oversized header as one result", () => {
  const { publicKey } = signedEd();
  const results = verifyAllLabels(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {
        "signature-input": "x".repeat(200_000),
        signature: "sig1=:AA==:",
      },
      body: '{"amount":100}',
    },
    { key: publicKey, now: NOW },
  );
  // The header is never split into labels: one synthetic result,
  // same shape as the unparseable-header case (label "").
  assert.equal(results.length, 1);
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "SIGNATURE_INPUT_TOO_LARGE");
  assert.equal(results[0]?.label, "");
});

test("verifyAllLabels: per-label limit fails only its label, the other still verifies", () => {
  const { signed, publicKey } = dualSignedEd();
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    // The shared signature-input header (~198 bytes) exceeds 50 for
    // sig1 only; sig2 falls back to the 64 KiB default.
    maxSignatureInputLengthByLabel: { sig1: 50 },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.label, "sig1");
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "SIGNATURE_INPUT_TOO_LARGE");
  assert.equal(results[1]?.label, "sig2");
  assert.equal(results[1]?.ok, true);
});

test("verifyAllLabels: invalid per-label limit throws a configuration error", () => {
  const { signed, publicKey } = dualSignedEd();
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        key: publicKey,
        now: NOW,
        maxSignatureInputLengthByLabel: { sig1: 0 },
      }),
    /maxSignatureInputLengthByLabel\["sig1"\]/,
  );
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        key: publicKey,
        now: NOW,
        maxSignatureLengthByLabel: { sig2: 1.5 },
      }),
    /maxSignatureLengthByLabel\["sig2"\]/,
  );
});
