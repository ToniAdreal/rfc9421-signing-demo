import test from "node:test";
import assert from "node:assert/strict";
import {
  fromFetchResponse,
  fromNodeResponse,
  generateEd25519KeyPair,
  signResponse,
  verifyResponse,
  type FetchResponseLike,
  type HttpResponseLike,
  type IncomingResponseLike,
  type RequestLike,
} from "../src/index.js";

// Backlog #1376: the two response adapters only checked the explicit
// `opts.method` / `opts.url` pair for presence, not for type — a
// non-string value (e.g. `method: 42`) slipped silently into
// `RequestLike.method` / `.url`, and the sign/verify side would only
// fail later with an unrelated message. The shared
// `assertMethodOrUrlString` guard now rejects a non-string pair value
// with a named error at the adapter boundary, mirroring the integer
// rule the adapters already enforce on `status` / `statusCode`
// (#1352). A bound `opts.request` is deliberately NOT re-checked:
// its method/url walk the `RequestLike` contract of the
// caller-supplied request, and the explicit pair is ignored entirely
// when a request is bound — these tests pin that precedence, so a
// future guard does not silently change it. An empty string keeps its
// existing named error (the "cannot determine the request" check),
// pinned by `test/nodeHttpFetchResponse.test.ts`.

const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";
const CREATED = 1700000000;
const NOW = CREATED + 60;

function asNodeRes(value: unknown): IncomingResponseLike {
  return value as IncomingResponseLike;
}
function asFetchRes(value: unknown): FetchResponseLike {
  return value as FetchResponseLike;
}

/** The error must be a plain named `Error` with the exact message — never a bare `TypeError`. */
function assertNamedError(fn: () => unknown, message: string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof Error, `must throw an Error: ${String(e)}`);
    assert.ok(
      !(e instanceof TypeError),
      `must be a named Error, not a bare TypeError: ${e}`,
    );
    assert.equal(e.name, "Error");
    assert.equal(e.message, message);
    return true;
  });
}

const nodeRes: IncomingResponseLike = {
  statusCode: 200,
  headers: { "content-type": "application/json" },
};
const fetchRes: FetchResponseLike = {
  status: 200,
  headers: new Headers({ "content-type": "application/json" }),
};
const boundRequest: RequestLike = {
  method: "GET",
  url: URL,
  headers: { host: "api.example.com" },
};
const cannotDetermine =
  "cannot determine the request this response answers — " +
  "pass opts.request, or the opts.method + opts.url pair";

// --- fromNodeResponse: explicit-pair type guard ---------------------------

for (const bad of [42, {}, null, true]) {
  test(`fromNodeResponse rejects opts.method ${String(bad)} with a named error`, () => {
    assertNamedError(
      () =>
        fromNodeResponse(nodeRes, BODY, {
          method: bad as never,
          url: URL,
        }),
      `fromNodeResponse: opts.method must be a non-empty string, got ${String(bad)}`,
    );
  });
  test(`fromNodeResponse rejects opts.url ${String(bad)} with a named error`, () => {
    assertNamedError(
      () =>
        fromNodeResponse(nodeRes, BODY, {
          method: "GET",
          url: bad as never,
        }),
      `fromNodeResponse: opts.url must be a non-empty string, got ${String(bad)}`,
    );
  });
}

test("fromNodeResponse: an empty method still reports the cannot-determine error", () => {
  assertNamedError(
    () => fromNodeResponse(nodeRes, BODY, { method: "", url: URL }),
    `fromNodeResponse: ${cannotDetermine}`,
  );
});

test("fromNodeResponse: an empty url still reports the cannot-determine error", () => {
  assertNamedError(
    () => fromNodeResponse(nodeRes, BODY, { method: "GET", url: "" }),
    `fromNodeResponse: ${cannotDetermine}`,
  );
});

test("fromNodeResponse: a legal method+url pair lands in the result unchanged", () => {
  const adapted = fromNodeResponse(nodeRes, BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.status, 200);
  assert.equal(adapted.body, BODY);
});

test("fromNodeResponse: a bound opts.request wins over a bad explicit pair", () => {
  const adapted = fromNodeResponse(nodeRes, BODY, {
    request: boundRequest,
    method: 42 as never,
    url: 42 as never,
  });
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.request, boundRequest);
});

test("fromNodeResponse: sign -> adapt with an explicit pair -> verify round-trips", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status"],
    },
  );
  const adapted = fromNodeResponse(
    asNodeRes({
      statusCode: 200,
      headers: {
        "signature-input": signed.headers["signature-input"],
        signature: signed.headers["signature"],
      },
    }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.equal(
    verifyResponse(adapted as HttpResponseLike, { key: publicKey, now: NOW }).ok,
    true,
  );
});

// --- fromFetchResponse: explicit-pair type guard --------------------------

for (const bad of [42, {}, null, true]) {
  test(`fromFetchResponse rejects opts.method ${String(bad)} with a named error`, () => {
    assertNamedError(
      () =>
        fromFetchResponse(fetchRes, BODY, {
          method: bad as never,
          url: URL,
        }),
      `fromFetchResponse: opts.method must be a non-empty string, got ${String(bad)}`,
    );
  });
  test(`fromFetchResponse rejects opts.url ${String(bad)} with a named error`, () => {
    assertNamedError(
      () =>
        fromFetchResponse(fetchRes, BODY, {
          method: "GET",
          url: bad as never,
        }),
      `fromFetchResponse: opts.url must be a non-empty string, got ${String(bad)}`,
    );
  });
}

test("fromFetchResponse: an empty method still reports the cannot-determine error", () => {
  assertNamedError(
    () => fromFetchResponse(fetchRes, BODY, { method: "", url: URL }),
    `fromFetchResponse: ${cannotDetermine}`,
  );
});

test("fromFetchResponse: an empty url still reports the cannot-determine error", () => {
  assertNamedError(
    () => fromFetchResponse(fetchRes, BODY, { method: "GET", url: "" }),
    `fromFetchResponse: ${cannotDetermine}`,
  );
});

test("fromFetchResponse: a legal method+url pair lands in the result unchanged", () => {
  const adapted = fromFetchResponse(fetchRes, BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.status, 200);
  assert.equal(adapted.body, BODY);
});

test("fromFetchResponse: a bound opts.request wins over a bad explicit pair", () => {
  const adapted = fromFetchResponse(fetchRes, BODY, {
    request: boundRequest,
    method: 42 as never,
    url: 42 as never,
  });
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.request, boundRequest);
});

test("fromFetchResponse: sign -> adapt with an explicit pair -> verify round-trips", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status"],
    },
  );
  const adapted = fromFetchResponse(
    asFetchRes({
      status: 200,
      headers: new Headers({
        "signature-input": signed.headers["signature-input"] as string,
        signature: signed.headers["signature"] as string,
      }),
    }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.equal(
    verifyResponse(adapted as HttpResponseLike, { key: publicKey, now: NOW }).ok,
    true,
  );
});
