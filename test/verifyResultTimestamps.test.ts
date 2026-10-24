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
// one or both timestamps. This helper builds such signatures by hand using
// the public signature-base primitives, so the wire shape matches what a
// foreign implementation would send (same pattern as requireFreshness).
const COVERED = ["@method", "@authority", "@path"];
const CREATED = 1700000000;
const EXPIRES = CREATED + 600;
const NOW = CREATED + 60;

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

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
  };
}

/**
 * Combine two single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature.
 */
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

// ---------- success round-trip ----------

test("VerifyResult carries created and expires from a signed request", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, EXPIRES);
});

test("VerifyResult carries created and leaves expires undefined when the signer sent no expires", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, undefined);
});

test("hand-built signature with expires only: created undefined, expires exact", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
    expires: EXPIRES,
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.created, undefined);
  assert.equal(res.expires, EXPIRES);
});

test("hand-built signature with neither timestamp: both undefined, still verifies", () => {
  const { signed, publicKey } = signedWithout({
    keyid: "k",
    alg: "ed25519",
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.created, undefined);
  assert.equal(res.expires, undefined);
});

test("verifyRequestOrThrow success return carries created and expires", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const out = verifyRequestOrThrow(signed, { key: publicKey, now: NOW });
  assert.equal(out.created, CREATED);
  assert.equal(out.expires, EXPIRES);
});

// ---------- failure results still report the wire values ----------

test("tampered created: SIGNATURE_MISMATCH result still reports the tampered wire value", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  // Rewrite only the wire timestamp, without re-signing: the signature
  // base no longer matches, so verification must fail — but the result
  // still reports what was actually sent, not the original value.
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        `created=${CREATED}`,
        `created=${CREATED + 30}`,
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.created, CREATED + 30);
  assert.equal(res.expires, EXPIRES);
});

test("tampered expires: SIGNATURE_MISMATCH result still reports the tampered wire value", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        `expires=${EXPIRES}`,
        `expires=${EXPIRES + 300}`,
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, EXPIRES + 300);
});

test("EXPIRED failure result carries created and expires", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const res = verifyRequest(signed, { key: publicKey, now: EXPIRES + 10 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EXPIRED");
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, EXPIRES);
});

test("MISSING_REQUIRED_COMPONENT failure result carries created and expires", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, EXPIRES);
});

test("verifyRequestOrThrow failure carries created and expires on the VerifyError", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        `created=${CREATED}`,
        `created=${CREATED + 30}`,
      ),
    },
  };
  assert.throws(
    () => verifyRequestOrThrow(tampered, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.equal(isVerifyError(e), true);
      if (isVerifyError(e)) {
        assert.equal(e.code, "SIGNATURE_MISMATCH");
        assert.equal(e.created, CREATED + 30);
        assert.equal(e.expires, EXPIRES);
      }
      return true;
    },
  );
});

// ---------- multi-label and rotation paths ----------

test("verifyAllLabels reports each label's own created and expires, in wire order", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const a = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
    label: "merchant",
  });
  const b = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED + 100,
    expires: EXPIRES + 100,
    label: "gateway",
  });
  const results = verifyAllLabels(mergeSignatures(a, b), {
    key: publicKey,
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].created, CREATED);
  assert.equal(results[0].expires, EXPIRES);
  assert.equal(results[1].ok, true);
  assert.equal(results[1].created, CREATED + 100);
  assert.equal(results[1].expires, EXPIRES + 100);
});

test("candidateKeys rotation success carries created and expires", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const wrong = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: EXPIRES,
  });
  const res = verifyRequest(signed, {
    candidateKeys: [wrong.publicKey, publicKey],
    now: NOW,
  });
  assert.equal(res.ok, true);
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, EXPIRES);
});
