import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type HttpResponseLike,
  type SignedHttpResponse,
  type StructuredFieldType,
} from "../src/index.js";

// Backlog #900: `verifyResponse` inherits `VerifyOptions.structuredFieldTypes`
// from `verifyRequest`, so a gateway callback verifier can pin the
// Structured Field type of a response header covered with `;sf` — but no
// response-side test ever proved the registry survives the response path.
// That matters because the response signature covers a different
// component set than a request signature (`@status` plus named response
// headers, never `@method`/`@authority`/`@path`): the request-side `;sf`
// tests (test/structuredFieldTypes.test.ts, backlog #886) cannot prove
// the response forwarder passes the registry through, canonicalizes a
// response header under the registered type on both sides, or rejects a
// mismatched registry on the response shape. These tests pin the
// response side directly, mirroring the request-side semantics one for
// one: a registered type round-trips, a registry that disagrees with the
// wire type fails closed (sign side throws, verify side reports
// SIGNATURE_BASE_BUILD_FAILED), an unregistered field keeps the default
// trial order, and a malformed registry is a caller configuration error.

const CREATED = 1700000000;
const LIST_SCOPES = '"read", "write"';
const DICT_SCOPES = "scope=read, level=2";

function response(
  headers: Record<string, string> = {},
  body?: string,
): HttpResponseLike {
  return {
    status: 200,
    headers: { "x-scopes": LIST_SCOPES, ...headers },
    ...(body !== undefined ? { body } : {}),
  };
}

function signScopes(
  covered: string[],
  registry?: Record<string, StructuredFieldType>,
  overrides: Partial<HttpResponseLike> = {},
): { signed: SignedHttpResponse; publicKey: KeyObject } {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { ...response(undefined, JSON.stringify({ settled: true })), ...overrides },
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: covered,
      ...(registry !== undefined ? { structuredFieldTypes: registry } : {}),
    },
  );
  return { signed, publicKey };
}

test("response structuredFieldTypes: registered list round-trips through signResponse/verifyResponse", () => {
  const { signed, publicKey } = signScopes(["@status", "x-scopes;sf"], {
    "x-scopes": "list",
  });
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "list" },
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.equal(result.keyId, "gateway-key-1");
  assert.deepEqual(result.coveredComponents, ["@status", "x-scopes;sf"]);
});

test("response structuredFieldTypes: registered dictionary round-trips", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    response({ "x-scopes": DICT_SCOPES }, JSON.stringify({ settled: true })),
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-scopes;sf"],
      structuredFieldTypes: { "x-scopes": "dictionary" },
    },
  );
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "dictionary" },
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("response structuredFieldTypes: sign side rejects a Dictionary-shaped value under a list registry", () => {
  // The default trial order would rescue "scope=read, level=2" via
  // Dictionary; the registry must not: a field known to be a List is
  // not a Dictionary.
  assert.throws(
    () =>
      signScopes(["@status", "x-scopes;sf"], { "x-scopes": "list" }, {
        headers: { "x-scopes": DICT_SCOPES },
      }),
    /cannot be serialized with ";sf"/,
  );
});

test("response structuredFieldTypes: verify side fails closed with SIGNATURE_BASE_BUILD_FAILED on a mismatched registry", () => {
  // Minted without a registry (Dictionary trial wins for the
  // Dictionary-shaped value); verified with a List registry: the base
  // cannot be rebuilt under the registered type, so verification fails
  // with the base-build code, not by falling back to the trial order
  // and reporting a mismatch.
  const { signed, publicKey } = signScopes(["@status", "x-scopes;sf"], undefined, {
    headers: { "x-scopes": DICT_SCOPES },
  });
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "list" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("response structuredFieldTypes: unregistered fields keep the default trial order alongside a registered field", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    response(
      { "x-scopes": LIST_SCOPES, "x-quota": "limit=1500, remaining=99" },
      JSON.stringify({ settled: true }),
    ),
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-scopes;sf", "x-quota;sf"],
      structuredFieldTypes: { "x-scopes": "list" },
    },
  );
  // x-quota is unregistered: the default trial order still parses its
  // Dictionary-shaped value, exactly as on the request side.
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "list" },
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("response structuredFieldTypes: field names match case-insensitively", () => {
  const { signed, publicKey } = signScopes(["@status", "x-scopes;sf"], {
    "X-Scopes": "list",
  });
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "X-SCOPES": "list" },
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
});

test("response structuredFieldTypes: malformed registry is a configuration error on both sides", () => {
  const unknownType = { "x-scopes": "set" } as unknown as Record<
    string,
    StructuredFieldType
  >;
  const nonObject = "list" as unknown as Record<string, StructuredFieldType>;
  const emptyField = { "": "list" } as Record<string, StructuredFieldType>;
  for (const registry of [unknownType, nonObject, emptyField]) {
    // Sign side: throws even when the registered field is not covered.
    assert.throws(
      () => signScopes(["@status"], registry),
      /structuredFieldTypes/,
    );
    // Verify side: a caller configuration error, thrown, not a result.
    const { signed, publicKey } = signScopes(["@status", "x-scopes;sf"], {
      "x-scopes": "list",
    });
    assert.throws(
      () =>
        verifyResponse(signed, {
          key: publicKey,
          now: CREATED + 60,
          structuredFieldTypes: registry,
        }),
      /structuredFieldTypes/,
    );
  }
});

test("response structuredFieldTypes: registry does not mask a forgery", () => {
  const { signed, publicKey } = signScopes(["@status", "x-scopes;sf"], {
    "x-scopes": "list",
  });
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
  const result = verifyResponse(tampered, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "list" },
  });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("response structuredFieldTypes: body-less (@status-only) response with a ;sf header verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: { "x-scopes": LIST_SCOPES } },
    {
      keyId: "gateway-key-1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-scopes;sf"],
      structuredFieldTypes: { "x-scopes": "list" },
    },
  );
  const result = verifyResponse(signed, {
    key: publicKey,
    now: CREATED + 60,
    structuredFieldTypes: { "x-scopes": "list" },
  });
  assert.equal(result.ok, true, `expected ok, got ${JSON.stringify(result)}`);
  assert.deepEqual(result.coveredComponents, ["@status", "x-scopes;sf"]);
});
