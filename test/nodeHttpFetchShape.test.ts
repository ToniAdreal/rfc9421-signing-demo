import test from "node:test";
import assert from "node:assert/strict";
import {
  fromFetchRequest,
  fromFetchResponse,
  generateEd25519KeyPair,
  signRequest,
  signResponse,
  verifyRequest,
  type FetchRequestLike,
  type FetchResponseLike,
  type RequestLike,
} from "../src/index.js";

// Backlog #1375: the two fetch HTTP adapters dereferenced their message
// argument with no shape guard, so a `null` request/response escaped
// as a bare `TypeError` (`reading 'method'` / `reading 'status'`)
// instead of the library's named configuration error — the same gap
// #1352 closed on the two Node adapters. The shared
// `assertObjectParam` guard now runs first in both adapters (before
// the `method` / `status` fail-fast checks), with an `opts.request`
// guard on the response side (a `null` bound request used to throw
// `reading 'method'`), and a fetch-flavoured headers guard: fetch
// headers are an iterable of `[name, value]` pairs (a real `Headers`,
// an array of pairs, any iterable), so the Node side's
// `assertObjectParam` does not fit — it rejects arrays, which are
// valid fetch headers — and a `null` / missing / record headers value
// now throws a named error instead of the bare `TypeError`
// (`"headers is not iterable"`) the `for...of` in
// `normalizeFetchHeaders` used to throw. `opts` itself is deliberately
// left unguarded: every `opts` read is optional-chained, so `null`
// opts behaves exactly like omitted opts — these tests pin that, so
// a future guard does not silently change it.

const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";
const CREATED = 1700000000;
const NOW = CREATED + 60;

function asRes(value: unknown): FetchResponseLike {
  return value as FetchResponseLike;
}
function asReq(value: unknown): FetchRequestLike {
  return value as FetchRequestLike;
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

const goodRes: FetchResponseLike = {
  status: 200,
  headers: new Headers({ "content-type": "application/json" }),
};
const goodReq: FetchRequestLike = {
  method: "POST",
  url: URL,
  headers: new Headers({ "content-type": "application/json" }),
};
const reqOpts = { method: "GET", url: URL };

// --- fromFetchResponse: message shape -------------------------------------

for (const bad of [null, undefined, "x", 42, []]) {
  test(`fromFetchResponse rejects ${JSON.stringify(bad) ?? String(bad)} res with a named error`, () => {
    assertNamedError(
      () => fromFetchResponse(asRes(bad), BODY, reqOpts),
      "fromFetchResponse: res must be an object",
    );
  });
}

for (const bad of [null, undefined, { host: "api.example.com" }, "x"]) {
  test(`fromFetchResponse rejects ${JSON.stringify(bad) ?? String(bad)} headers with a named error`, () => {
    assertNamedError(
      () =>
        fromFetchResponse(
          asRes({ status: 200, headers: bad }),
          BODY,
          reqOpts,
        ),
      "fromFetchResponse: headers must be an iterable of [name, value] pairs",
    );
  });
}

test("fromFetchResponse rejects a null opts.request with a named error", () => {
  assertNamedError(
    () => fromFetchResponse(goodRes, BODY, { request: null as never }),
    "fromFetchResponse: opts.request must be an object",
  );
});

test("fromFetchResponse: a non-object opts.request is rejected the same way", () => {
  for (const bad of ["x", 42, []]) {
    assertNamedError(
      () => fromFetchResponse(goodRes, BODY, { request: bad as never }),
      "fromFetchResponse: opts.request must be an object",
    );
  }
});

test("fromFetchResponse: null opts behaves exactly like omitted opts", () => {
  // `null` opts supplies neither a bound request nor the method+url
  // pair, so both calls must fail the same way — and the failure must
  // be the named configuration error, not a TypeError.
  const message =
    "fromFetchResponse: cannot determine the request this response answers — " +
    "pass opts.request, or the opts.method + opts.url pair";
  assertNamedError(() => fromFetchResponse(goodRes, BODY, null as never), message);
  assertNamedError(() => fromFetchResponse(goodRes, BODY), message);
});

test("fromFetchResponse: missing status still reports the existing error", () => {
  assertNamedError(
    () =>
      fromFetchResponse(
        asRes({ headers: new Headers() }),
        BODY,
        reqOpts,
      ),
    "fromFetchResponse: res.status is missing — @status verification needs the response status",
  );
});

test("fromFetchResponse: a string status still reports the existing error", () => {
  assertNamedError(
    () =>
      fromFetchResponse(
        asRes({ status: "200", headers: new Headers() }),
        BODY,
        reqOpts,
      ),
    "fromFetchResponse: res.status must be an integer HTTP status code, got 200 (expected 100-599)",
  );
});

// --- fromFetchRequest: message shape --------------------------------------

for (const bad of [null, undefined, "x", 42, []]) {
  test(`fromFetchRequest rejects ${JSON.stringify(bad) ?? String(bad)} req with a named error`, () => {
    assertNamedError(
      () => fromFetchRequest(asReq(bad), BODY),
      "fromFetchRequest: req must be an object",
    );
  });
}

for (const bad of [null, undefined, { host: "api.example.com" }, "x"]) {
  test(`fromFetchRequest rejects ${JSON.stringify(bad) ?? String(bad)} headers with a named error`, () => {
    assertNamedError(
      () =>
        fromFetchRequest(
          asReq({ method: "POST", url: URL, headers: bad }),
          BODY,
        ),
      "fromFetchRequest: headers must be an iterable of [name, value] pairs",
    );
  });
}

test("fromFetchRequest: missing method still reports the existing error", () => {
  assertNamedError(
    () =>
      fromFetchRequest(
        asReq({ url: URL, headers: [] as [string, string][] }),
        BODY,
      ),
    "fromFetchRequest: req.method is missing",
  );
});

test("fromFetchRequest: missing url still reports the existing error", () => {
  assertNamedError(
    () =>
      fromFetchRequest(
        asReq({ method: "POST", headers: [] as [string, string][] }),
        BODY,
      ),
    "fromFetchRequest: req.url is missing",
  );
});

// --- legal adaptation unchanged -------------------------------------------

test("fromFetchResponse adapts a legal response exactly as before", () => {
  const request: RequestLike = {
    method: "GET",
    url: URL,
    headers: { host: "api.example.com" },
  };
  const adapted = fromFetchResponse(goodRes, BODY, { request });
  assert.equal(adapted.method, "GET");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.status, 200);
  assert.deepEqual(adapted.headers, { "content-type": "application/json" });
  assert.equal(adapted.body, BODY);
  assert.equal(adapted.request, request);
  assert.equal("trailers" in adapted, false);
});

test("fromFetchResponse adapts a literal pairs-array headers value", () => {
  const adapted = fromFetchResponse(
    { status: 200, headers: [["X-Multi", "a"], ["x-multi", "b"]] },
    BODY,
    reqOpts,
  );
  assert.equal(adapted.headers["x-multi"], "a, b");
});

test("fromFetchRequest adapts a legal request exactly as before", () => {
  const adapted = fromFetchRequest(goodReq, BODY);
  assert.equal(adapted.method, "POST");
  assert.equal(adapted.url, URL);
  assert.deepEqual(adapted.headers, { "content-type": "application/json" });
  assert.equal(adapted.body, BODY);
  assert.equal("trailers" in adapted, false);
});

test("fromFetchRequest adapts a literal pairs-array headers value", () => {
  const adapted = fromFetchRequest(
    { method: "POST", url: URL, headers: [["X-Multi", "a"], ["x-multi", "b"]] },
    BODY,
  );
  assert.equal(adapted.headers["x-multi"], "a, b");
});

test("sign -> real fetch Response -> fromFetchResponse -> verify round-trip still passes", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signResponse(
    { status: 200, headers: {}, body: BODY },
    { keyId: "gateway-key", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const headers = new Headers();
  for (const [name, value] of Object.entries(signed.headers)) {
    if (value !== undefined) headers.set(name, value);
  }
  const res = new Response(BODY, { status: 200, headers });
  const adapted = fromFetchResponse(res, BODY, { method: "GET", url: URL });
  assert.equal(adapted.status, 200);
  const result = verifyRequest(adapted, {
    key: publicKey,
    now: NOW,
    requiredComponents: ["@status"],
  });
  assert.equal(result.ok, true);
});

test("sign -> real fetch Request -> fromFetchRequest -> verify round-trip still passes", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "webhook-key", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const headers = new Headers();
  for (const [name, value] of Object.entries(signed.headers)) {
    if (value !== undefined) headers.set(name, value);
  }
  const req = new Request(URL, { method: "POST", headers, body: BODY });
  const body = Buffer.from(await req.arrayBuffer());
  const adapted = fromFetchRequest(req, body);
  assert.equal(adapted.method, "POST");
  assert.equal(adapted.url, URL);
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});
