import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import {
  fromFetchResponse,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type FetchResponseLike,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

/** A test double shaped like the fields of a fetch Response. */
function fetchResponse(
  overrides: Partial<FetchResponseLike> & {
    headers: Iterable<[string, string]>;
  },
): FetchResponseLike {
  return { status: 200, ...overrides };
}

/** A real fetch Response carrying a signed message's wire headers. */
function signedResponse(
  status: number,
  signed: SignedHttpRequest,
  body: string,
): Response {
  const headers = new Headers();
  for (const [name, value] of Object.entries(signed.headers)) {
    if (value !== undefined) headers.set(name, value);
  }
  return new Response(body, { status, headers });
}

function signedStatusResponse(key: Parameters<typeof signRequest>[1]) {
  return signRequest(
    { method: "GET", url: URL, headers: {}, body: BODY, status: 200 },
    { ...key, coveredComponents: ["@status"] },
  );
}

test("loopback: a real http server signs an @status response; a fetch() client verifies end-to-end", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const server = createServer((req, res) => {
    const signed = signRequest(
      {
        method: "GET",
        url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/settle`,
        headers: {},
        body: BODY,
        status: 200,
      },
      {
        keyId: "gateway-key",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@status"],
      },
    );
    res.writeHead(200, {
      "content-type": "application/json",
      "signature-input": signed.headers["signature-input"] as string,
      signature: signed.headers["signature"] as string,
    });
    res.end(BODY);
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", async () => {
      const port = (server.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/settle`;
      const request: RequestLike = {
        method: "GET",
        url,
        headers: { host: `127.0.0.1:${port}` },
      };
      try {
        const res = await fetch(url);
        // The caller reads the body first — the adapter never touches
        // res.body, so the bytes it verifies are the exact wire bytes.
        const body = Buffer.from(await res.arrayBuffer());
        const reqLike = fromFetchResponse(res, body, { request });
        assert.equal(reqLike.status, 200);
        assert.equal(reqLike.body, body);
        const result = verifyRequest(reqLike, {
          key: publicKey,
          now: NOW,
          requiredComponents: ["@status"],
        });
        assert.equal(result.ok, true);
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        server.close();
      }
    });
  });
});

test("the adapter never consumes res.body", () => {
  const { privateKey } = generateEd25519KeyPair();
  const signed = signedStatusResponse({
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const res = signedResponse(200, signed, BODY);
  assert.equal(res.bodyUsed, false);
  fromFetchResponse(res, BODY, { method: "GET", url: URL });
  assert.equal(res.bodyUsed, false);
});

test("missing status fails fast", () => {
  assert.throws(
    () =>
      fromFetchResponse({ headers: new Headers() }, "body", {
        method: "GET",
        url: URL,
      }),
    /fromFetchResponse: res\.status is missing/,
  );
});

// A string "200" used to slip through the Node adapter and verify as
// status 200 (@status resolution stringifies whatever it is given),
// while signResponse/verifyResponse reject non-integer statuses
// outright — the fetch adapter enforces the same integer rule at the
// boundary.
test("a string status fails fast instead of verifying as 200", () => {
  assert.throws(
    () =>
      fromFetchResponse(
        fetchResponse({
          status: "200" as unknown as number,
          headers: new Headers(),
        }),
        "body",
        { method: "GET", url: URL },
      ),
    /fromFetchResponse: res\.status must be an integer HTTP status code, got 200/,
  );
});

test("a float status fails fast", () => {
  assert.throws(
    () =>
      fromFetchResponse(
        fetchResponse({ status: 200.5, headers: new Headers() }),
        "body",
        { method: "GET", url: URL },
      ),
    /fromFetchResponse: res\.status must be an integer HTTP status code, got 200\.5/,
  );
});

test("neither opts.request nor the explicit method+url pair fails fast", () => {
  assert.throws(
    () => fromFetchResponse(fetchResponse({ headers: new Headers() }), "body"),
    /opts\.request, or the opts\.method \+ opts\.url pair/,
  );
  assert.throws(
    () =>
      fromFetchResponse(fetchResponse({ headers: new Headers() }), "body", {
        method: "GET",
      }),
    /opts\.method \+ opts\.url pair/,
  );
  assert.throws(
    () =>
      fromFetchResponse(fetchResponse({ headers: new Headers() }), "body", {
        url: URL,
      }),
    /opts\.method \+ opts\.url pair/,
  );
});

test("an empty method or url fails fast", () => {
  assert.throws(
    () =>
      fromFetchResponse(fetchResponse({ headers: new Headers() }), "body", {
        method: "",
        url: URL,
      }),
    /opts\.method \+ opts\.url pair/,
  );
  assert.throws(
    () =>
      fromFetchResponse(fetchResponse({ headers: new Headers() }), "body", {
        method: "GET",
        url: "",
      }),
    /opts\.method \+ opts\.url pair/,
  );
});

test("explicit method+url verifies without a bound request", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signedStatusResponse({
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const reqLike = fromFetchResponse(signedResponse(200, signed, BODY), BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(reqLike.status, 200);
  assert.equal(reqLike.request, undefined);
  // A fetch Response carries no trailers, so the adapter never sets
  // the field — a ;tr component has nothing to resolve against.
  assert.equal(reqLike.trailers, undefined);
  const result = verifyRequest(reqLike, {
    key: publicKey,
    now: NOW,
    requiredComponents: ["@status"],
  });
  assert.equal(result.ok, true);
});

test("opts.request is attached as RequestLike.request so a ;req component binds", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com", "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  };
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
      request,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "@method;req"],
    },
  );
  const reqLike = fromFetchResponse(signedResponse(200, signed, BODY), BODY, {
    request,
  });
  // Same reference — the response signature binds this exact request.
  assert.equal(reqLike.request, request);
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("a different bound request breaks the ;req binding", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com" },
  };
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
      request,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "@method;req"],
    },
  );
  // The response cannot be transplanted onto a request with a different
  // method: "@method";req resolves "get" instead of the signed "post".
  const transplanted = fromFetchResponse(signedResponse(200, signed, BODY), BODY, {
    request: { ...request, method: "GET" },
  });
  const result = verifyRequest(transplanted, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("opts.request takes precedence over the explicit method+url pair", () => {
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com" },
  };
  const reqLike = fromFetchResponse(
    fetchResponse({ headers: new Headers() }),
    BODY,
    { request, method: "GET", url: "https://other.example/" },
  );
  assert.equal(reqLike.method, "POST");
  assert.equal(reqLike.url, "https://api.example.com/v1/charge?order=42");
  assert.equal(reqLike.request, request);
});

test("a tampered @status fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signedStatusResponse({
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  // Signed as 200; the received response claims 500.
  const reqLike = fromFetchResponse(signedResponse(500, signed, BODY), BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(reqLike.status, 500);
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("Headers multi-values join with ', ' like the Node adapter", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: { "x-multi": ["a", "b"] },
      body: BODY,
      status: 200,
    },
    {
      keyId: "k1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-multi"],
    },
  );
  const headers = new Headers();
  headers.set("signature-input", signed.headers["signature-input"] as string);
  headers.set("signature", signed.headers["signature"] as string);
  headers.append("x-multi", "a");
  headers.append("x-multi", "b");
  const reqLike = fromFetchResponse({ status: 200, headers }, BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(reqLike.headers["x-multi"], "a, b");
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("a literal pairs array groups repeated names and lowercases them", () => {
  const reqLike = fromFetchResponse(
    {
      status: 201,
      headers: [
        ["Content-Type", "application/json"],
        ["X-Multi", "a "],
        ["x-multi", " b"],
      ],
    },
    "{}",
    { method: "POST", url: "https://x.example/" },
  );
  assert.equal(reqLike.status, 201);
  assert.deepEqual(reqLike.headers, {
    "content-type": "application/json",
    "x-multi": "a, b",
  });
  assert.equal(reqLike.body?.toString(), "{}");
});

test("Buffer and Uint8Array bodies verify identically", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      body: BODY,
      status: 200,
    },
    {
      keyId: "k1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "content-digest"],
    },
  );
  const bytes = new Uint8Array(Buffer.from(BODY, "utf8"));
  const fromBuffer = fromFetchResponse(signedResponse(200, signed, BODY), Buffer.from(BODY, "utf8"), {
    method: "GET",
    url: URL,
  });
  const fromUint8 = fromFetchResponse(signedResponse(200, signed, BODY), bytes, {
    method: "GET",
    url: URL,
  });
  assert.ok(Buffer.isBuffer(fromBuffer.body));
  assert.ok(Buffer.isBuffer(fromUint8.body));
  assert.deepEqual(fromUint8.body, fromBuffer.body);
  assert.equal(verifyRequest(fromBuffer, { key: publicKey, now: NOW }).ok, true);
  assert.equal(verifyRequest(fromUint8, { key: publicKey, now: NOW }).ok, true);
});

test("a Uint8Array body is copied, so later mutation of the source cannot rewrite it", () => {
  const bytes = new Uint8Array(Buffer.from(BODY, "utf8"));
  const reqLike = fromFetchResponse(
    fetchResponse({ headers: new Headers() }),
    bytes,
    { method: "GET", url: URL },
  );
  bytes[0] = 0x58; // 'X' — must not leak into the stored body.
  assert.equal(reqLike.body?.toString(), BODY);
});

test("a string body passes through untouched", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signedStatusResponse({
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  const reqLike = fromFetchResponse(signedResponse(200, signed, BODY), BODY, {
    method: "GET",
    url: URL,
  });
  assert.equal(reqLike.body, BODY);
  const result = verifyRequest(reqLike, {
    key: publicKey,
    now: NOW,
    requiredComponents: ["@status"],
  });
  assert.equal(result.ok, true);
});
