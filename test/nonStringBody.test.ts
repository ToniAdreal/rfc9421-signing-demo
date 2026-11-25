import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  contentDigest,
  contentDigestAlgOf,
  digest,
  generateEd25519KeyPair,
  signRequest,
  signatureInputValue,
  verifyRequest,
  verifyRequestOrThrow,
  VerifyError,
  type SignedHttpRequest,
  type SignatureParams,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";
const BODY = '{"amount":100}';
const { publicKey, privateKey } = generateEd25519KeyPair();

function digestOf(body: string | Buffer, alg: "sha-256" | "sha-512"): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(buf).digest("base64")}:`;
}

/** Manually sign a request whose Content-Digest header we control exactly. */
function signedWithContentDigestHeader(
  body: string | Buffer | undefined,
  digestHeader: string,
): SignedHttpRequest {
  const headers: Record<string, string> = { "content-digest": digestHeader };
  const covered = ["@method", "@authority", "@path", "content-digest"];
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

/** Manually sign a request whose legacy Digest header we control exactly. */
function signedWithLegacyDigestHeader(
  body: string | Buffer | undefined,
  digestHeader: string,
): SignedHttpRequest {
  const headers: Record<string, string> = { digest: digestHeader };
  const covered = ["@method", "@authority", "@path", "digest"];
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

function verify(signed: SignedHttpRequest) {
  return verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
}

// ---------- signing side: fail-closed configuration error, never TypeError ----------

test("signRequest with a number body throws a configuration error, not TypeError", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "POST", url: URL, headers: {}, body: 123 as unknown as string },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError), `must not be a bare TypeError: ${e}`);
      assert.match(
        e.message,
        /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got number/,
      );
      return true;
    },
  );
});

test("signRequest with a boolean body throws a configuration error", () => {
  assert.throws(
    () =>
      signRequest(
        { method: "POST", url: URL, headers: {}, body: true as unknown as string },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got boolean/,
      );
      return true;
    },
  );
});

test("signRequest with an object body throws a configuration error", () => {
  assert.throws(
    () =>
      signRequest(
        {
          method: "POST",
          url: URL,
          headers: {},
          body: { amount: 100 } as unknown as string,
        },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got object/,
      );
      return true;
    },
  );
});

test("signRequest with an array body throws a configuration error", () => {
  assert.throws(
    () =>
      signRequest(
        {
          method: "POST",
          url: URL,
          headers: {},
          body: [1, 2, 3] as unknown as string,
        },
        { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got object/,
      );
      return true;
    },
  );
});

test("contentDigest with a number body throws a configuration error", () => {
  assert.throws(
    () => contentDigest(123 as unknown as string),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /contentDigest: "body" must be a string, a Buffer, or a Uint8Array, got number/,
      );
      return true;
    },
  );
});

test("contentDigestAlgOf with a non-string value throws a configuration error", () => {
  assert.throws(
    () => contentDigestAlgOf(123 as unknown as string),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof TypeError));
      assert.match(
        e.message,
        /contentDigestAlgOf: "value" must be a string, got number/,
      );
      return true;
    },
  );
});

// ---------- verify side: failure result, never a throw ----------

test("verifyRequest with a number body and content-digest returns VERIFICATION_ERROR, never throws", () => {
  const signed = signedWithContentDigestHeader(BODY, digestOf(BODY, "sha-512"));
  const swapped = { ...signed, body: 123 as unknown as string };
  let res!: ReturnType<typeof verifyRequest>;
  assert.doesNotThrow(() => {
    res = verify(swapped);
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
  assert.ok(res.reason);
  assert.match(res.reason, /body must be a string, a Buffer, or a Uint8Array, got number/);
});

test("verifyRequest with a boolean body and legacy Digest returns VERIFICATION_ERROR, never throws", () => {
  const signed = signedWithLegacyDigestHeader(BODY, digest(BODY, "sha-256"));
  const swapped = { ...signed, body: true as unknown as string };
  let res!: ReturnType<typeof verifyRequest>;
  assert.doesNotThrow(() => {
    res = verify(swapped);
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
  assert.ok(res.reason);
  assert.match(res.reason, /body must be a string, a Buffer, or a Uint8Array, got boolean/);
});

test("verifyRequestOrThrow with a number body throws VerifyError with code VERIFICATION_ERROR", () => {
  const signed = signedWithContentDigestHeader(BODY, digestOf(BODY, "sha-512"));
  const swapped = { ...signed, body: 123 as unknown as string };
  assert.throws(
    () => verifyRequestOrThrow(swapped, { key: publicKey, now: CREATED + 60 }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "VERIFICATION_ERROR");
      assert.match(e.message, /body must be a string, a Buffer, or a Uint8Array, got number/);
      return true;
    },
  );
});

// ---------- unchanged behaviour for valid bodies ----------

test("string body still verifies", () => {
  const signed = signedWithContentDigestHeader(BODY, digestOf(BODY, "sha-512"));
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("Buffer body still verifies", () => {
  const signed = signedWithContentDigestHeader(
    Buffer.from(BODY, "utf8"),
    digestOf(BODY, "sha-512"),
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test("undefined body with an empty-body digest still verifies", () => {
  const signed = signedWithContentDigestHeader(
    undefined,
    digestOf(Buffer.alloc(0), "sha-512"),
  );
  const res = verify(signed);
  assert.equal(res.ok, true, JSON.stringify(res));
});
