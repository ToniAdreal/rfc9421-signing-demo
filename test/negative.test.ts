import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;

function signedEd(
  body: string,
  opts: { created?: number; coveredComponents?: string[] } = {},
): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
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
      created: opts.created ?? CREATED,
      coveredComponents: opts.coveredComponents,
    },
  );
  return { signed, publicKey };
}

test("created beyond clock skew tolerance is rejected", () => {
  const { signed, publicKey } = signedEd('{"amount":100}', {
    created: CREATED + 600,
  });
  // Default tolerance is 60s; a signature stamped 10 minutes in the
  // future must be rejected even though the cryptography checks out.
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature created in the future (clock skew)");
  assert.equal(res.code, "CREATED_IN_FUTURE");
});

test("created within clock skew tolerance still verifies", () => {
  const { signed, publicKey } = signedEd('{"amount":100}', {
    created: CREATED + 30,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

test("missing covered header fails cleanly", () => {
  const { signed, publicKey } = signedEd('{"amount":100}', {
    coveredComponents: ["@method", "@authority", "@path", "x-request-id"],
  });
  const stripped: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers },
  };
  delete stripped.headers["x-request-id"];
  const res = verifyRequest(stripped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /cannot rebuild signature base/);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("wrong hmac secret fails verification", () => {
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
    {
      keyId: "k",
      alg: "hmac-sha256",
      key: secretKey("correct-hmac-secret-correct-hmac-01"),
      created: CREATED,
    },
  );
  const res = verifyRequest(signed, {
    key: secretKey("wrong-hmac-secret-wrong-hmac-0002"),
    now: CREATED + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature mismatch");
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("unsupported alg in signature-input is rejected", () => {
  const { signed, publicKey } = signedEd('{"amount":100}');
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        'alg="ed25519"',
        'alg="rsa-pss-sha512"',
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, 'unsupported alg "rsa-pss-sha512"');
  assert.equal(res.code, "UNSUPPORTED_ALG");
});

test("content-digest without sha-512 cannot be body-verified", () => {
  // The verifier only knows how to check sha-512 body bindings. A
  // content-digest header offering only sha-256 must fail cleanly
  // instead of silently skipping the body check.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = '{"amount":100}';
  const signed = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      // content-digest deliberately NOT covered: the header below is
      // added after signing and only sha-256 is offered.
      coveredComponents: ["@method", "@authority", "@path"],
    },
  );
  const sha256 = createHash("sha256").update(body, "utf8").digest("base64");
  const withDigest: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers, "content-digest": `sha-256=:${sha256}:` },
    body,
  };
  const res = verifyRequest(withDigest, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "cannot verify body: no sha-512 content-digest present");
  assert.equal(res.code, "MISSING_CONTENT_DIGEST");
});

test("documents: body swap is undetected when content-digest is not covered", () => {
  // This is a security footgun, not a bug: RFC 9421 only binds the body
  // when content-digest is among the covered components. This test pins
  // the behavior so future refactors notice if it changes.
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
      coveredComponents: ["@method", "@authority", "@path"],
    },
  );
  const swapped: SignedHttpRequest = { ...signed, body: '{"amount":999999}' };
  const res = verifyRequest(swapped, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
