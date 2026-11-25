import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  parseSignatureInput,
  ReplayCache,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  verifyResponse,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// `signRequest` refuses to mint an empty covered-component list (it
// throws), so an empty-list signature can only arrive from a foreign
// signer. The helpers below mint one by hand using the public
// signature-base primitives, so the wire shape matches what such a
// signer would send: the base is just the `"@signature-params"` line.
// Backlog #1409.
const CREATED = 1700000000;
const NOW = CREATED + 60;

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

function emptyParams(nonce: string): SignatureParams {
  return { keyid: "k", alg: "ed25519", created: CREATED, nonce };
}

/** A cryptographically valid ed25519 GET request covering nothing. */
function signedEmptyList(pair: KeyPair, nonce = "n-1"): SignedHttpRequest {
  const req: RequestLike = {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {},
  };
  const params = emptyParams(nonce);
  const base = buildSignatureBase([], req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {
      "signature-input": signatureInputValue("sig1", [], params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
}

/** A cryptographically valid ed25519 GET request covering only `@method`. */
function signedMethodOnly(pair: KeyPair, nonce = "n-2"): SignedHttpRequest {
  const req: RequestLike = {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {},
  };
  const params = emptyParams(nonce);
  const base = buildSignatureBase(["@method"], req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {
      "signature-input": signatureInputValue("sig1", ["@method"], params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
}

/** A dual-signed request: `sig1` covers nothing, `sig2` covers `@method`. */
function signedDualEmptyAndMethod(pair: KeyPair): SignedHttpRequest {
  const req: RequestLike = {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {},
  };
  const params1 = emptyParams("n-1");
  const params2 = emptyParams("n-2");
  const base1 = buildSignatureBase([], req, params1);
  const base2 = buildSignatureBase(["@method"], req, params2);
  const sig1 = edSign(null, Buffer.from(base1, "utf8"), pair.privateKey);
  const sig2 = edSign(null, Buffer.from(base2, "utf8"), pair.privateKey);
  return {
    method: "GET",
    url: "https://api.example.com/v1/status",
    headers: {
      "signature-input": [
        signatureInputValue("sig1", [], params1),
        signatureInputValue("sig2", ["@method"], params2),
      ].join(", "),
      signature: [
        `sig1=:${sig1.toString("base64")}:`,
        `sig2=:${sig2.toString("base64")}:`,
      ].join(", "),
    },
  };
}

// The exact `RequestLike` shape `verifyResponse` synthesizes
// internally (see `responseToRequestLike` in `src/response.ts`):
// empty method, the reserved `.invalid` URL, and the response
// `status` — `@status` is what a response signature binds, so the
// base must be built against it, not against a fabricated request
// method/URL. (Same shape as `test/responseRequireFreshness.test.ts`.)
function responseRequestLike(): RequestLike {
  return {
    method: "",
    url: "https://response.invalid/",
    headers: {},
    status: 200,
  };
}

/** A cryptographically valid ed25519 200 response covering nothing. */
function signedEmptyResponse(pair: KeyPair): SignedHttpResponse {
  const req = responseRequestLike();
  const params = emptyParams("n-1");
  const base = buildSignatureBase([], req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  return {
    status: 200,
    headers: {
      "signature-input": signatureInputValue("sig1", [], params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
}

const EMPTY_REASON =
  "signature covers no components: an empty covered-component list binds nothing";

test("empty covered list fails with EMPTY_COVERED_COMPONENTS (single label)", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyRequest(signedEmptyList(pair), {
    key: pair.publicKey,
    now: NOW,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EMPTY_COVERED_COMPONENTS");
  assert.equal(res.reason, EMPTY_REASON);
  assert.deepEqual(res.coveredComponents, []);
  assert.equal(res.nonce, "n-1");
});

test("empty covered list fails only its own label in verifyAllLabels", () => {
  const pair = generateEd25519KeyPair();
  const results = verifyAllLabels(signedDualEmptyAndMethod(pair), {
    key: pair.publicKey,
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.label, "sig1");
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "EMPTY_COVERED_COMPONENTS");
  assert.equal(results[1]?.label, "sig2");
  assert.equal(results[1]?.ok, true);
});

test("empty covered list fails on the response side", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyResponse(signedEmptyResponse(pair), {
    key: pair.publicKey,
    now: NOW,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EMPTY_COVERED_COMPONENTS");
  assert.equal(res.reason, EMPTY_REASON);
});

test("a single covered component still verifies (control)", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyRequest(signedMethodOnly(pair), {
    key: pair.publicKey,
    now: NOW,
  });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, ["@method"]);
});

test("parser still returns [] for an empty list (parser layer unchanged)", () => {
  const parsed = parseSignatureInput(`sig1=();created=${CREATED}`, "sig1");
  assert.deepEqual(parsed.componentIds, []);
});

test("empty-list rejection never records the nonce in the replay cache", () => {
  const pair = generateEd25519KeyPair();
  const cache = new ReplayCache({ ttlSec: 600 });
  const empty = signedEmptyList(pair, "n-1");
  const rejected = verifyRequest(empty, {
    key: pair.publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(rejected.ok, false);
  assert.equal(rejected.code, "EMPTY_COVERED_COMPONENTS");
  // The same nonce, now in a legal signature, must still be fresh:
  // the rejected attempt never reached (or polluted) the cache.
  // (No `stats().size` assertion here: size is computed against the
  // cache's own wall clock, while the test pins `now` at CREATED+60,
  // so a recorded entry would read as expired — the freshness
  // re-verification below is the clock-proof assertion.)
  const legal = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: pair.privateKey,
      created: CREATED,
      nonce: "n-1",
      coveredComponents: ["@method"],
    },
  );
  const ok = verifyRequest(legal, {
    key: pair.publicKey,
    now: NOW,
    replayCache: cache,
    // Backlog #1411: the nonce-carrying signature needs a lifetime
    // bounded within the cache TTL (600s).
    maxSignatureAgeSec: 600,
  });
  assert.equal(ok.ok, true);
  // And the legal presentation did record the nonce: presenting it
  // again is a replay.
  const replay = verifyRequest(legal, {
    key: pair.publicKey,
    now: NOW,
    replayCache: cache,
    maxSignatureAgeSec: 600,
  });
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
  // A second presentation of the empty signature reports the same
  // code, not NONCE_REPLAY: the empty check runs before the cache.
  const again = verifyRequest(empty, {
    key: pair.publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(again.ok, false);
  assert.equal(again.code, "EMPTY_COVERED_COMPONENTS");
});

test("allowEmptyCoveredComponents opts out of the rejection", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyRequest(signedEmptyList(pair), {
    key: pair.publicKey,
    now: NOW,
    allowEmptyCoveredComponents: true,
  });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, []);
  // The opt-in flows into verifyAllLabels through the shared option
  // scan: the empty label verifies alongside the `@method` label.
  const results = verifyAllLabels(signedDualEmptyAndMethod(pair), {
    key: pair.publicKey,
    now: NOW,
    allowEmptyCoveredComponents: true,
  });
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.ok));
});

test("a non-boolean allowEmptyCoveredComponents throws a configuration error", () => {
  const pair = generateEd25519KeyPair();
  for (const bad of ["yes", 1, null]) {
    assert.throws(
      () =>
        verifyRequest(signedEmptyList(pair), {
          key: pair.publicKey,
          now: NOW,
          allowEmptyCoveredComponents: bad as unknown as boolean,
        }),
      (e: unknown) =>
        e instanceof Error &&
        /`allowEmptyCoveredComponents` must be a boolean/.test(e.message),
    );
  }
});

test("verifyRequestOrThrow throws VerifyError(EMPTY_COVERED_COMPONENTS)", () => {
  const pair = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequestOrThrow(signedEmptyList(pair), {
        key: pair.publicKey,
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "EMPTY_COVERED_COMPONENTS");
      assert.equal(e.reason, EMPTY_REASON);
      return true;
    },
  );
});

test("empty list reports EMPTY_COVERED_COMPONENTS even with requiredComponents set", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyRequest(signedEmptyList(pair), {
    key: pair.publicKey,
    now: NOW,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EMPTY_COVERED_COMPONENTS");
});
