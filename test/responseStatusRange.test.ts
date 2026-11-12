import test from "node:test";
import assert from "node:assert/strict";
import {
  fromFetchResponse,
  fromNodeResponse,
  generateEd25519KeyPair,
  signResponse,
  verifyAllResponseLabels,
  verifyResponse,
  type FetchResponseLike,
  type HttpResponseLike,
  type IncomingResponseLike,
} from "../src/index.js";

// Backlog #1080: `assertStatus` used to check only that the status was
// an integer, so 0, 99, 600 and 999 could be signed and verified and
// `@status` bound a meaningless value. The registered HTTP status-code
// range is 100-599 (RFC 9110 §15); 600-999 are undefined codes, so the
// sign/verify entry points and both response adapters now reject them
// with the range named in the error.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

const OUT_OF_RANGE = [0, 99, 600, 999];
const BOUNDARY = [100, 599];

function signOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return {
    keyId: "gateway-key",
    alg: "ed25519" as const,
    key: key.privateKey,
    created: CREATED,
  };
}

function verifyOpts(key: ReturnType<typeof generateEd25519KeyPair>) {
  return { key: key.publicKey, now: NOW };
}

function response(status: number): HttpResponseLike {
  return { status, headers: {}, body: BODY };
}

function incomingResponse(
  statusCode: number,
): IncomingResponseLike {
  return { statusCode, headers: {} };
}

function fetchResponse(status: number): FetchResponseLike {
  return { status, headers: [] as Iterable<[string, string]> };
}

test("signResponse rejects out-of-range statuses and names the range", () => {
  const keys = generateEd25519KeyPair();
  for (const status of OUT_OF_RANGE) {
    assert.throws(
      () => signResponse(response(status), signOpts(keys)),
      new RegExp(
        `signResponse: "status" must be an integer HTTP status code, got ${status} \\(expected 100-599\\)`,
      ),
    );
  }
});

test("verifyResponse rejects out-of-range statuses before any crypto", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(200), signOpts(keys));
  for (const status of OUT_OF_RANGE) {
    assert.throws(
      () =>
        verifyResponse(
          { ...signed, status } as unknown as HttpResponseLike,
          verifyOpts(keys),
        ),
      new RegExp(
        `verifyResponse: "status" must be an integer HTTP status code, got ${status} \\(expected 100-599\\)`,
      ),
    );
  }
});

test("verifyAllResponseLabels rejects out-of-range statuses", () => {
  const keys = generateEd25519KeyPair();
  const signed = signResponse(response(200), signOpts(keys));
  for (const status of OUT_OF_RANGE) {
    assert.throws(
      () =>
        verifyAllResponseLabels(
          { ...signed, status } as unknown as HttpResponseLike,
          { keys: { sig1: keys.publicKey }, now: NOW },
        ),
      new RegExp(
        `verifyAllResponseLabels: "status" must be an integer HTTP status code, got ${status} \\(expected 100-599\\)`,
      ),
    );
  }
});

test("fromNodeResponse rejects out-of-range statusCodes at the boundary", () => {
  for (const statusCode of OUT_OF_RANGE) {
    assert.throws(
      () =>
        fromNodeResponse(incomingResponse(statusCode), BODY, {
          method: "GET",
          url: URL,
        }),
      new RegExp(
        `fromNodeResponse: res\\.statusCode must be an integer HTTP status code, got ${statusCode} \\(expected 100-599\\)`,
      ),
    );
  }
});

test("fromFetchResponse rejects out-of-range statuses at the boundary", () => {
  for (const status of OUT_OF_RANGE) {
    assert.throws(
      () =>
        fromFetchResponse(fetchResponse(status), BODY, {
          method: "GET",
          url: URL,
        }),
      new RegExp(
        `fromFetchResponse: res\\.status must be an integer HTTP status code, got ${status} \\(expected 100-599\\)`,
      ),
    );
  }
});

test("boundary 100 and 599 sign and verify end-to-end", () => {
  const keys = generateEd25519KeyPair();
  for (const status of BOUNDARY) {
    const signed = signResponse(response(status), signOpts(keys));
    assert.equal(signed.status, status);
    assert.equal(verifyResponse(signed, verifyOpts(keys)).ok, true);
    const results = verifyAllResponseLabels(signed, {
      keys: { sig1: keys.publicKey },
      now: NOW,
    });
    assert.equal(results.length, 1);
    assert.equal(results[0].ok, true);
  }
});

test("boundary 100 and 599 pass through both response adapters", () => {
  for (const status of BOUNDARY) {
    const fromNode = fromNodeResponse(incomingResponse(status), BODY, {
      method: "GET",
      url: URL,
    });
    assert.equal(fromNode.status, status);
    const fromFetch = fromFetchResponse(fetchResponse(status), BODY, {
      method: "GET",
      url: URL,
    });
    assert.equal(fromFetch.status, status);
  }
});
