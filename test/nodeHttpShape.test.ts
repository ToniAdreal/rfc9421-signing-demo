import test from "node:test";
import assert from "node:assert/strict";
import {
  fromNodeRequest,
  fromNodeResponse,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type IncomingRequestLike,
  type IncomingResponseLike,
} from "../src/index.js";

// Backlog #1352: the two Node HTTP adapters dereferenced their message
// argument with no shape guard, so a `null` request/response escaped
// as a bare `TypeError` (`reading 'method'` / `reading 'statusCode'`)
// instead of the library's named configuration error — the same gap
// #1344 closed on the five sign/verify entry points. The shared
// `assertObjectParam` guard now runs first in both adapters (before
// the `method` / `statusCode` fail-fast checks), with entry-named
// `headers` and `trailers` guards for the maps `normalizeHeaders` /
// `normalizeTrailers` would otherwise dereference, and an
// `opts.request` guard on the response side (a `null` bound request
// used to throw `reading 'method'`). `opts` itself is deliberately
// left unguarded: every `opts` read is optional-chained, so `null`
// opts behaves exactly like omitted opts — these tests pin that, so
// a future guard does not silently change it.

const BODY = JSON.stringify({ amount: 100, currency: "USD" });

function asReq(value: unknown): IncomingRequestLike {
  return value as IncomingRequestLike;
}
function asRes(value: unknown): IncomingResponseLike {
  return value as IncomingResponseLike;
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

const goodReq: IncomingRequestLike = {
  method: "POST",
  url: "/v1/charge",
  headers: { host: "api.example.com", "content-type": "application/json" },
  socket: null,
};
const goodRes: IncomingResponseLike = {
  statusCode: 200,
  headers: { "content-type": "application/json" },
};
const reqOpts = { method: "GET", url: "http://api.example.com/v1/charge" };

// --- fromNodeRequest: message shape ---------------------------------------

for (const bad of [null, undefined, "x", 42, []]) {
  test(`fromNodeRequest rejects ${JSON.stringify(bad) ?? String(bad)} req with a named error`, () => {
    assertNamedError(
      () => fromNodeRequest(asReq(bad)),
      "fromNodeRequest: req must be an object",
    );
  });
}

test("fromNodeRequest rejects a null headers map with a named error", () => {
  assertNamedError(
    () =>
      fromNodeRequest(
        asReq({ method: "POST", url: "/v1/charge", headers: null }),
      ),
    "fromNodeRequest: headers must be an object",
  );
});

test("fromNodeRequest rejects a null trailers map with a named error", () => {
  assertNamedError(
    () =>
      fromNodeRequest(
        asReq({
          method: "POST",
          url: "/v1/charge",
          headers: { host: "api.example.com" },
          trailers: null,
        }),
      ),
    "fromNodeRequest: trailers must be an object",
  );
});

test("fromNodeRequest: null opts behaves exactly like omitted opts", () => {
  const withNull = fromNodeRequest(goodReq, BODY, null as never);
  const omitted = fromNodeRequest(goodReq, BODY);
  assert.deepEqual(withNull, omitted);
  assert.equal(withNull.url, "http://api.example.com/v1/charge");
});

test("fromNodeRequest: missing method still reports the existing error", () => {
  assertNamedError(
    () =>
      fromNodeRequest(
        asReq({ url: "/v1/charge", headers: { host: "api.example.com" } }),
      ),
    "fromNodeRequest: req.method is missing",
  );
});

// --- fromNodeResponse: message shape --------------------------------------

for (const bad of [null, undefined, "x", 42, []]) {
  test(`fromNodeResponse rejects ${JSON.stringify(bad) ?? String(bad)} res with a named error`, () => {
    assertNamedError(
      () => fromNodeResponse(asRes(bad), "", reqOpts),
      "fromNodeResponse: res must be an object",
    );
  });
}

test("fromNodeResponse rejects a null headers map with a named error", () => {
  assertNamedError(
    () => fromNodeResponse(asRes({ statusCode: 200, headers: null }), "", reqOpts),
    "fromNodeResponse: headers must be an object",
  );
});

test("fromNodeResponse rejects a null trailers map with a named error", () => {
  assertNamedError(
    () =>
      fromNodeResponse(
        asRes({
          statusCode: 200,
          headers: { "content-type": "application/json" },
          trailers: null,
        }),
        "",
        reqOpts,
      ),
    "fromNodeResponse: trailers must be an object",
  );
});

test("fromNodeResponse rejects a null opts.request with a named error", () => {
  assertNamedError(
    () => fromNodeResponse(goodRes, "", { request: null as never }),
    "fromNodeResponse: opts.request must be an object",
  );
});

test("fromNodeResponse: a non-object opts.request is rejected the same way", () => {
  for (const bad of ["x", 42, []]) {
    assertNamedError(
      () => fromNodeResponse(goodRes, "", { request: bad as never }),
      "fromNodeResponse: opts.request must be an object",
    );
  }
});

test("fromNodeResponse: null opts behaves exactly like omitted opts", () => {
  assertNamedError(
    () => fromNodeResponse(goodRes, "", null as never),
    "fromNodeResponse: cannot determine the request this response answers — " +
      "pass opts.request, or the opts.method + opts.url pair",
  );
});

test("fromNodeResponse: missing statusCode still reports the existing error", () => {
  assertNamedError(
    () => fromNodeResponse(asRes({ headers: {} }), "", reqOpts),
    "fromNodeResponse: res.statusCode is missing — @status verification needs the response status",
  );
});

// --- legal adaptation unchanged -------------------------------------------

test("fromNodeRequest adapts a legal request exactly as before", () => {
  const adapted = fromNodeRequest(goodReq, BODY);
  assert.equal(adapted.method, "POST");
  assert.equal(adapted.url, "http://api.example.com/v1/charge");
  assert.deepEqual(adapted.headers, {
    host: "api.example.com",
    "content-type": "application/json",
  });
  assert.equal(adapted.body, BODY);
  assert.equal("trailers" in adapted, false);
});

test("fromNodeResponse adapts a legal response exactly as before", () => {
  const adapted = fromNodeResponse(goodRes, BODY, reqOpts);
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, "http://api.example.com/v1/charge");
  assert.equal(adapted.status, 200);
  assert.deepEqual(adapted.headers, { "content-type": "application/json" });
  assert.equal(adapted.body, BODY);
  assert.equal("trailers" in adapted, false);
});

test("sign -> fromNodeRequest -> verify round-trip still passes", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook?event=push",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "webhook-key", alg: "ed25519", key: privateKey, created: 1700000000 },
  );
  const adapted = fromNodeRequest(
    {
      method: "POST",
      url: "/webhook?event=push",
      headers: {
        Host: "hooks.example.com",
        "Content-Type": "application/json",
        "Signature-Input": signed.headers["signature-input"],
        Signature: signed.headers["signature"],
        "Content-Digest": signed.headers["content-digest"],
      },
      socket: { encrypted: true },
    },
    BODY,
  );
  const result = verifyRequest(adapted, { key: publicKey, now: 1700000060 });
  assert.equal(result.ok, true);
});
