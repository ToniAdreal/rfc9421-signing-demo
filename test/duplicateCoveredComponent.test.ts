import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  addSignature,
  buildSignatureBase,
  generateEd25519KeyPair,
  signatureInputValue,
  signRequest,
  signResponse,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function makeRequest(overrides: Partial<RequestLike> = {}): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { "x-charge-id": "ch_42" },
    ...overrides,
  };
}

/**
 * A duplicated covered component is a silent non-standard
 * signature: `buildSignatureBase` expands the list as written, so
 * `["@method", "@method"]` mints a base with the `@method` line
 * twice, and the verifier rebuilds the identical base and accepts
 * it. The sign side must fail fast instead (backlog #939).
 */
test("exact duplicate covered component is rejected", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeRequest(), {
        keyId: "k1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@method", "@method"],
      }),
    /signRequest: coveredComponents must not repeat a component, got "@method" twice/,
  );
});

test("case-variant duplicate covered component is rejected", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeRequest(), {
        keyId: "k1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@method", "@METHOD"],
      }),
    /signRequest: coveredComponents must not repeat a component, got "@METHOD" twice/,
  );
});

test("quoted vs unquoted spelling of the same component is rejected", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(makeRequest(), {
        keyId: "k1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ['"@method"', "@method"],
      }),
    /signRequest: coveredComponents must not repeat a component, got "@method" twice/,
  );
});

test("same base with the same parameter, differing only in case, is rejected", () => {
  const { privateKey } = generateEd25519KeyPair();
  const req = makeRequest({
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    status: 200,
    request: makeRequest(),
  });
  assert.throws(
    () =>
      signRequest(req, {
        keyId: "resp-1",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@method;req", "@METHOD;REQ"],
      }),
    /signRequest: coveredComponents must not repeat a component, got "@METHOD;REQ" twice/,
  );
});

/**
 * `;req` is part of the component's identity, not decoration:
 * `"@method"` binds this message's method while `"@method";req`
 * binds the associated request's method (RFC 9421 §2.2.7), so the
 * two are distinct components with different base lines and
 * covering both stays legal — the coexistence the
 * `reqComponent.test.ts` "same base" test pins. The guard compares
 * the full entry (base + parameters), never the base alone.
 */
test("same base with a different parameter suffix is NOT a duplicate", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeRequest({
    method: "GET",
    url: "https://callbacks.example.com/v1/result",
    status: 200,
    request: makeRequest(),
  });
  const signed = signRequest(req, {
    keyId: "resp-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@method;req"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
});

test("a list with no repeated component still signs and verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeRequest(), {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@authority", "@path"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
});

test("addSignature inherits the duplicate guard", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeRequest(), {
    keyId: "merchant",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@authority", "@path"],
  });
  assert.throws(
    () =>
      addSignature(signed, {
        keyId: "gateway",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        label: "sig2",
        coveredComponents: ["@method", "@method"],
      }),
    /signRequest: coveredComponents must not repeat a component, got "@method" twice/,
  );
});

test("signResponse rejects a duplicate with its own caller name", () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(
        { status: 200, headers: {} },
        {
          keyId: "gw",
          alg: "ed25519",
          key: privateKey,
          created: CREATED,
          coveredComponents: ["@status", "@status"],
        },
      ),
    /signResponse: coveredComponents must not repeat a component, got "@status" twice/,
  );
});

/**
 * Backlog #1001 reversed the sign-side-only guard: a foreign signer
 * that minted a signature over a duplicated component list is now
 * rejected at parse time with MALFORMED_SIGNATURE_INPUT, before any
 * crypto runs — the duplicated line made the signature base
 * ambiguous about what was signed. The signature below is
 * cryptographically valid over the duplicated base (the base
 * assertion proves it), so the rejection is a parser policy
 * decision, not a crypto failure. The sign side still refuses to
 * mint such signatures; the two sides now agree, and pre-existing
 * wire traffic carrying duplicates is rejected rather than silently
 * verified.
 */
test("verify side rejects a foreign signature over duplicate components", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeRequest();
  const covered = ["@method", "@method"];
  const params = { created: CREATED, keyid: "foreign-1", alg: "ed25519" as const };
  const base = buildSignatureBase(covered, req, params);
  assert.match(base, /"@method": POST/g);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const wire: RequestLike = {
    ...req,
    headers: {
      ...req.headers,
      "signature-input": signatureInputValue("sig1", covered, params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  const res = verifyRequest(wire, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
  assert.match(res.reason ?? "", /duplicate covered component "@method"/);
});
