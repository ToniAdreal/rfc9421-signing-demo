import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyRequest,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1380: the sign-side string options used to mishandle
// `null` two different ways. `label: null` was coerced —
// `opts.label ?? "sig1"` swallowed it and the signature went out
// under the default label with no signal at all (and
// `LABEL_TOKEN_RE.test(null)` would have passed anyway, because
// `null` coerces to the token-shaped string `"null"`). `tag` /
// `nonce` / `keyId: null` threw a bare `TypeError` from
// `assertSignParamLength` reading `.length` off `null`. Both are now
// named configuration errors; `signResponse` / `addSignature` /
// `addResponseSignature` share the core, so they are covered too.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1";

function paymentRequest() {
  return { method: "GET", url: URL, headers: {} };
}

function settlementResponse() {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ settled: true }),
  };
}

function merchantSignedRequest(): SignedHttpRequest {
  const kp = generateEd25519KeyPair();
  return signRequest(paymentRequest(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
    label: "merchant",
  });
}

function merchantSignedResponse(): SignedHttpResponse {
  const kp = generateEd25519KeyPair();
  return signResponse(settlementResponse(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
  });
}

test("signRequest: label null is rejected with a named token error, not silently signed as sig1", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: null as unknown as string,
      }),
    /signRequest: "label" must be an RFC 9421 token.*got "null"/,
  );
});

test("signRequest: tag null is rejected with a named string error, not a bare TypeError", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        tag: null as unknown as string,
      }),
    /signRequest: "tag" must be a string, got null/,
  );
});

test("signRequest: nonce null is rejected with a named string error, not a bare TypeError", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        nonce: null as unknown as string,
      }),
    /signRequest: "nonce" must be a string, got null/,
  );
});

test("signRequest: keyId null is rejected with a named string error, not a bare TypeError", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        keyId: null as unknown as string,
      }),
    /signRequest: "keyId" must be a string, got null/,
  );
});

test("signRequest: label 42 keeps the existing token error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: 42 as unknown as string,
      }),
    /signRequest: "label" must be an RFC 9421 token.*got "42"/,
  );
});

test("signRequest: non-string tag/nonce/keyId values are rejected with a named string error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        tag: 42 as unknown as string,
      }),
    /signRequest: "tag" must be a string, got number/,
  );
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        nonce: {} as unknown as string,
      }),
    /signRequest: "nonce" must be a string, got object/,
  );
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        keyId: true as unknown as string,
      }),
    /signRequest: "keyId" must be a string, got boolean/,
  );
});

test("signRequest: a legal custom label/tag/nonce/keyId still signs and verifies", () => {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
    label: "merchant",
    tag: "settlement",
    nonce: "nonce-1380",
    keyId: "merchant-key-1",
  });
  assert.match(
    signed.headers["signature-input"],
    /^merchant=\(/,
  );
  const result = verifyRequest(signed, {
    key: kp.publicKey,
    now: NOW,
    label: "merchant",
  });
  assert.equal(result.ok, true);
  assert.equal(result.label, "merchant");
  assert.equal(result.tag, "settlement");
  assert.equal(result.nonce, "nonce-1380");
  assert.equal(result.keyId, "merchant-key-1");
});

test("signRequest: omitting label still defaults to sig1", () => {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(paymentRequest(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
  });
  const result = verifyRequest(signed, { key: kp.publicKey, now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.label, "sig1");
});

test("signResponse: label null is rejected with the named token error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(settlementResponse(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: null as unknown as string,
        coveredComponents: ["@status"],
      }),
    /"label" must be an RFC 9421 token.*got "null"/,
  );
});

test("signResponse: tag null is rejected with a named string error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      signResponse(settlementResponse(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        tag: null as unknown as string,
        coveredComponents: ["@status"],
      }),
    /signRequest: "tag" must be a string, got null/,
  );
});

test("signResponse: a legal custom label still signs and verifies", () => {
  const kp = generateEd25519KeyPair();
  const signed = signResponse(settlementResponse(), {
    key: kp.privateKey,
    alg: "ed25519",
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
  const result = verifyResponse(signed, {
    key: kp.publicKey,
    now: NOW,
    label: "gateway",
  });
  assert.equal(result.ok, true);
  assert.equal(result.label, "gateway");
});

test("addSignature: label null is rejected with a named token error, not the duplicate-label error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      addSignature(merchantSignedRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: null as unknown as string,
      }),
    /addSignature: "label" must be an RFC 9421 token.*got "null"/,
  );
});

test("addResponseSignature: label null is rejected with a named token error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      addResponseSignature(merchantSignedResponse(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: null as unknown as string,
        coveredComponents: ["@status"],
      }),
    /addResponseSignature: "label" must be an RFC 9421 token.*got "null"/,
  );
});

test("addSignature: an empty-string label keeps its non-empty-string error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      addSignature(merchantSignedRequest(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: "",
      }),
    /addSignature: "label" must be a non-empty string/,
  );
});

test("addResponseSignature: an empty-string label keeps its non-empty-string error", () => {
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      addResponseSignature(merchantSignedResponse(), {
        key: kp.privateKey,
        alg: "ed25519",
        created: CREATED,
        label: "",
        coveredComponents: ["@status"],
      }),
    /addResponseSignature: "label" must be a non-empty string/,
  );
});
