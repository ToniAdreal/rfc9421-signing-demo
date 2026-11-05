import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signResponse,
  signatureInputValue,
  verifyResponse,
  type HttpResponseLike,
  type SignatureParams,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #898: `verifyResponse` inherits `VerifyOptions.maxSignatureAgeSec`
// from `verifyRequest`, so a gateway callback verifier can cap how old a
// response signature's `created` may be — but no response-side test ever
// proved the cap survives the response path. That matters because the
// response signature's `created` comes from the response's own
// `signature-input` header, not from any request header: the request-side
// age tests (test/signatureMaxAge.test.ts) cannot prove the response
// forwarder reads the response's timestamp, passes the injected `now`
// through, or reports `SIGNATURE_TOO_OLD` on the response shape. These
// tests pin the response side directly, mirroring the request-side
// semantics one for one: within the cap verifies, exactly at the cap
// verifies (the check is a strict `>`), one second past it fails with
// `SIGNATURE_TOO_OLD`, a signature with no `created` bypasses the check
// entirely, and a bogus window is a caller configuration error.

const CREATED = 1700000000;
const MAX_AGE_SEC = 300;
const BODY = JSON.stringify({ settled: true, amount: 100 });

function response(overrides: Partial<HttpResponseLike> = {}): HttpResponseLike {
  return { status: 200, headers: {}, body: BODY, ...overrides };
}

function signAged(
  created: number,
  overrides: Partial<HttpResponseLike> = {},
): {
  signed: SignedHttpResponse;
  publicKey: KeyObject;
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(response(overrides), {
    keyId: "gateway-key-1",
    alg: "ed25519",
    key: privateKey,
    created,
  });
  return { signed, publicKey };
}

// `signResponse` always emits `created`; a real third-party signer may
// omit it. This helper builds such a response signature by hand using
// the public signature-base primitives, over the same internal shape
// `verifyResponse` rebuilds (method "", url "https://response.invalid/",
// the response's own status), covering `@status` only.
function signedWithoutCreated(): {
  signed: SignedHttpResponse;
  publicKey: KeyObject;
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const params: SignatureParams = {
    keyid: "gateway-key-1",
    alg: "ed25519",
    // Still valid at the far-future verify instant: the bypass under
    // test is about the missing `created`, not an expired signature.
    expires: CREATED + 7200,
  };
  const covered = ["@status"];
  const req = {
    method: "",
    url: "https://response.invalid/",
    headers: {},
    status: 200,
  };
  const base = buildSignatureBase(covered, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const signed: SignedHttpResponse = {
    status: 200,
    headers: {
      "signature-input": signatureInputValue("sig1", covered, params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  return { signed, publicKey };
}

test("response maxSignatureAgeSec: signature inside the cap verifies", () => {
  const { signed, publicKey } = signAged(CREATED);
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-1");
  assert.equal(result.alg, "ed25519");
  assert.equal(result.created, CREATED);
});

test("response maxSignatureAgeSec: signature one second past the cap fails with SIGNATURE_TOO_OLD", () => {
  const { signed, publicKey } = signAged(CREATED);
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + MAX_AGE_SEC + 1,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_TOO_OLD");
  assert.match(
    result.reason ?? "",
    /created 301s ago, older than maxSignatureAgeSec=300/,
  );
  assert.equal(result.created, CREATED);
});

test("response maxSignatureAgeSec: age exactly at the cap verifies (strict >)", () => {
  const { signed, publicKey } = signAged(CREATED);
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + MAX_AGE_SEC,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("response maxSignatureAgeSec: signature without created bypasses the age check", () => {
  const { signed, publicKey } = signedWithoutCreated();
  // 3600s past the would-be `created` and far beyond the 300s cap —
  // with no `created` on the wire the check has nothing to measure.
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 3600,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.created, undefined);
});

test("response maxSignatureAgeSec: negative, NaN, Infinity, non-number all throw a configuration error", () => {
  const { signed, publicKey } = signAged(CREATED);
  const bad = [-1, Number.NaN, Number.POSITIVE_INFINITY, "300", null];
  for (const v of bad) {
    assert.throws(
      () =>
        verifyResponse(signed, {
          key: publicKey,
          now: CREATED + 60,
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

test("response maxSignatureAgeSec: forgery is still reported as SIGNATURE_MISMATCH, not SIGNATURE_TOO_OLD", () => {
  const { signed, publicKey } = signAged(CREATED);
  const tampered: SignedHttpResponse = {
    ...signed,
    headers: {
      ...signed.headers,
      signature: (signed.headers["signature"] as string).replace(
        /^sig1=:/,
        "sig1=:AAAA",
      ),
    },
  };
  // Old enough to be too old (3600s > 300s) AND forged: the crypto
  // check runs first, so the true failure mode is reported.
  const result = verifyResponse(tampered, {
    key: publicKey,
    now: CREATED + 3600,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response maxSignatureAgeSec: body-less (@status-only) response is aged the same way", () => {
  const { signed, publicKey } = signAged(CREATED, { body: undefined });
  const tooOld = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + MAX_AGE_SEC + 1,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(tooOld.ok, false);
  assert.equal(tooOld.code, "SIGNATURE_TOO_OLD");
  assert.deepEqual(tooOld.coveredComponents, ["@status"]);
  const fresh = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  assert.equal(fresh.ok, true);
});

test("response maxSignatureAgeSec unset (default): old response signature still verifies — backwards compatible", () => {
  const { signed, publicKey } = signAged(CREATED);
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 6 * 3600,
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});
