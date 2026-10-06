import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signRequest,
  VerifyError,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
  type VerifyFailureCode,
} from "../src/index.js";

const CREATED = 1700000000;

interface Keys {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
}

function signedEd(body = '{"amount":100}'): Keys {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "x-request-id": "req-123" },
      body,
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@authority", "@path", "content-digest"],
    },
  );
  return { signed, publicKey };
}

function strip(signed: SignedHttpRequest, header: string): SignedHttpRequest {
  const headers = { ...signed.headers };
  delete headers[header];
  return { ...signed, headers };
}

/** Flip a byte in the signature value so the cryptography genuinely fails. */
function tamperSignature(signed: SignedHttpRequest): SignedHttpRequest {
  const sigHeader = signed.headers["signature"];
  const tamperedSig = sigHeader.replace(
    /:([A-Za-z0-9+/=]+):/,
    (_m, b64: string) => {
      const buf = Buffer.from(b64, "base64");
      buf[0] ^= 0xff;
      return `:${buf.toString("base64")}:`;
    },
  );
  assert.notEqual(tamperedSig, sigHeader);
  return { ...signed, headers: { ...signed.headers, signature: tamperedSig } };
}

// Every VerifyResult failure carries a stable machine-readable code.
// Each case builds its own request + matching verifier key.
const cases: Array<{
  code: VerifyFailureCode;
  reason: string;
  build: () => Keys;
  now: number;
}> = [
  {
    code: "MISSING_SIGNATURE_INPUT",
    reason: "missing signature-input header",
    build: () => {
      const { signed, publicKey } = signedEd();
      return { signed: strip(signed, "signature-input"), publicKey };
    },
    now: CREATED + 60,
  },
  {
    code: "MISSING_SIGNATURE",
    reason: "missing signature header",
    build: () => {
      const { signed, publicKey } = signedEd();
      return { signed: strip(signed, "signature"), publicKey };
    },
    now: CREATED + 60,
  },
  {
    code: "MALFORMED_SIGNATURE_INPUT",
    reason: "bad signature-input",
    build: () => {
      const { signed, publicKey } = signedEd();
      return {
        signed: {
          ...signed,
          headers: {
            ...signed.headers,
            "signature-input": "sig1=not-a-valid(inner",
          },
        },
        publicKey,
      };
    },
    now: CREATED + 60,
  },
  {
    code: "SIGNATURE_BASE_BUILD_FAILED",
    reason: "cannot rebuild signature base",
    // content-digest is a covered component here; deleting it breaks the base.
    build: () => {
      const { signed, publicKey } = signedEd();
      return { signed: strip(signed, "content-digest"), publicKey };
    },
    now: CREATED + 60,
  },
  {
    code: "MALFORMED_SIGNATURE",
    reason: "bad signature field",
    build: () => {
      const { signed, publicKey } = signedEd();
      return {
        signed: {
          ...signed,
          headers: { ...signed.headers, signature: "sig1=:!!!:" },
        },
        publicKey,
      };
    },
    now: CREATED + 60,
  },
  {
    code: "UNSUPPORTED_ALG",
    reason: 'unsupported alg "rsa-pss-sha512"',
    build: () => {
      const { signed, publicKey } = signedEd();
      return {
        signed: {
          ...signed,
          headers: {
            ...signed.headers,
            "signature-input": signed.headers["signature-input"].replace(
              'alg="ed25519"',
              'alg="rsa-pss-sha512"',
            ),
          },
        },
        publicKey,
      };
    },
    now: CREATED + 60,
  },
  {
    code: "SIGNATURE_MISMATCH",
    reason: "signature mismatch",
    // Flip a byte of the signature itself: the base still rebuilds, but
    // the cryptography fails.
    build: () => {
      const { signed, publicKey } = signedEd();
      return { signed: tamperSignature(signed), publicKey };
    },
    now: CREATED + 60,
  },
  {
    code: "BODY_DIGEST_MISMATCH",
    reason: "body does not match content-digest",
    // Sign under hmac with the digest covered, then swap the body and
    // recompute nothing: crypto passes (hmac recomputed by the verifier
    // from the *signed* base, which covers the old digest header), the
    // digest check compares body vs header and fails.
    build: () => {
      const body = '{"amount":100}';
      const key = secretKey("s3cret-replacement-hmac-secret-32b");
      const signed = signRequest(
        {
          method: "POST",
          url: "https://api.example.com/v1/payments",
          headers: {},
          body,
        },
        {
          keyId: "k",
          alg: "hmac-sha256",
          key,
          created: CREATED,
          coveredComponents: ["@method", "@authority", "@path", "content-digest"],
        },
      );
      return { signed: { ...signed, body: '{"amount":999999}' }, publicKey: key };
    },
    now: CREATED + 60,
  },
  {
    code: "MISSING_CONTENT_DIGEST",
    reason: "cannot verify body: no sha-512 or sha-256 content-digest present",
    build: () => {
      // Sign with content-digest NOT covered, then present a sha-1-only
      // header: crypto still verifies, but the body binding cannot.
      const { publicKey, privateKey } = generateEd25519KeyPair();
      const body = '{"amount":100}';
      const signed = signRequest(
        {
          method: "POST",
          url: "https://api.example.com/v1/payments",
          headers: {},
          body,
        },
        {
          keyId: "k",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: ["@method", "@authority", "@path"],
        },
      );
      const sha1 = createHash("sha1").update(body, "utf8").digest("base64");
      return {
        signed: {
          ...signed,
          headers: {
            ...signed.headers,
            "content-digest": `sha-1=:${sha1}:`,
          },
        },
        publicKey,
      };
    },
    now: CREATED + 60,
  },
  {
    code: "EXPIRED",
    reason: "signature expired",
    build: () => {
      const { publicKey, privateKey } = generateEd25519KeyPair();
      const signed = signRequest(
        { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
        {
          keyId: "k",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          expires: CREATED + 300,
          coveredComponents: ["@method", "@authority", "@path"],
        },
      );
      return { signed, publicKey };
    },
    now: CREATED + 301,
  },
  {
    code: "CREATED_IN_FUTURE",
    reason: "signature created in the future (clock skew)",
    build: () => {
      const { publicKey, privateKey } = generateEd25519KeyPair();
      const signed = signRequest(
        { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
        {
          keyId: "k",
          alg: "ed25519",
          key: privateKey,
          created: CREATED + 600,
          coveredComponents: ["@method", "@authority", "@path"],
        },
      );
      return { signed, publicKey };
    },
    now: CREATED,
  },
];

for (const { code, reason, build, now } of cases) {
  test(`VerifyResult carries code ${code}`, () => {
    const { signed, publicKey } = build();
    const res = verifyRequest(signed, { key: publicKey, now });
    assert.equal(res.ok, false);
    assert.equal(res.code, code);
    assert.match(
      res.reason ?? "",
      new RegExp(reason.replace(/[()"]/g, "\\$&")),
    );
  });

  test(`verifyRequestOrThrow throws ${code}`, () => {
    const { signed, publicKey } = build();
    assert.throws(
      () => verifyRequestOrThrow(signed, { key: publicKey, now }),
      (e: unknown) => {
        assert.ok(e instanceof Error, "must remain an Error subclass");
        assert.ok(isVerifyError(e));
        assert.equal(e.code, code);
        return true;
      },
    );
  });
}

test("verifyRequestOrThrow returns identity info on success", () => {
  const { signed, publicKey } = signedEd();
  const out = verifyRequestOrThrow(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(out.label, "sig1");
  assert.equal(out.keyId, "k");
  assert.equal(out.alg, "ed25519");
});

test("thrown error propagates keyId and alg", () => {
  const { signed, publicKey } = signedEd();
  const tampered = tamperSignature(signed);
  assert.throws(
    () => verifyRequestOrThrow(tampered, { key: publicKey, now: CREATED + 60 }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "SIGNATURE_MISMATCH");
      assert.equal(e.keyId, "k");
      assert.equal(e.alg, "ed25519");
      return true;
    },
  );
});

test("isVerifyError rejects non-VerifyError values", () => {
  assert.equal(isVerifyError(new Error("boom")), false);
  assert.equal(isVerifyError({ code: "EXPIRED" }), false);
  assert.equal(isVerifyError(null), false);
});
