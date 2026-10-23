import test from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import {
  fromNodeResponse,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

/** Wire-style headers carrying a signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

function signedStatusResponse(key: Parameters<typeof signRequest>[1]) {
  return signRequest(
    { method: "GET", url: URL, headers: {}, body: BODY, status: 200 },
    { ...key, coveredComponents: ["@status"] },
  );
}

test("loopback: a real http server signs an @status response; http.get client verifies end-to-end", async () => {
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
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/settle`;
      const request: RequestLike = {
        method: "GET",
        url,
        headers: { host: `127.0.0.1:${port}` },
      };
      get(url, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          try {
            const reqLike = fromNodeResponse(res, Buffer.concat(chunks), {
              request,
            });
            assert.equal(reqLike.status, 200);
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
        res.on("error", reject);
      }).on("error", reject);
    });
  });
});

test("missing statusCode fails fast", () => {
  assert.throws(
    () => fromNodeResponse({ headers: {} }, "body"),
    /fromNodeResponse: res\.statusCode is missing/,
  );
});

test("neither opts.request nor the explicit method+url pair fails fast", () => {
  assert.throws(
    () => fromNodeResponse(incomingResponse({ headers: {} }), "body"),
    /opts\.request, or the opts\.method \+ opts\.url pair/,
  );
  assert.throws(
    () =>
      fromNodeResponse(incomingResponse({ headers: {} }), "body", {
        method: "GET",
      }),
    /opts\.method \+ opts\.url pair/,
  );
  assert.throws(
    () =>
      fromNodeResponse(incomingResponse({ headers: {} }), "body", {
        url: URL,
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
  const reqLike = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed) }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.equal(reqLike.status, 200);
  assert.equal(reqLike.request, undefined);
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
  const reqLike = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed) }),
    BODY,
    { request },
  );
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
  const transplanted = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(signed) }),
    BODY,
    { request: { ...request, method: "GET" } },
  );
  const result = verifyRequest(transplanted, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("rawTrailers verify a ;tr covered response component", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      trailers: { "x-settlement-id": "stl_42" },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-settlement-id;tr"],
    },
  );
  const reqLike = fromNodeResponse(
    incomingResponse({
      headers: wireHeaders(signed),
      // Mixed-case name exercises the adapter's lowercasing — the same
      // convention it applies to headers and to parsed trailers.
      rawTrailers: ["X-Settlement-Id", "stl_42"],
    }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.deepEqual(reqLike.trailers, { "x-settlement-id": "stl_42" });
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("a tampered trailer fails verification", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      trailers: { "x-settlement-id": "stl_42" },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-settlement-id;tr"],
    },
  );
  const reqLike = fromNodeResponse(
    incomingResponse({
      headers: wireHeaders(signed),
      rawTrailers: ["x-settlement-id", "stl_99"],
    }),
    BODY,
    { method: "GET", url: URL },
  );
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
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
  const reqLike = fromNodeResponse(
    incomingResponse({ statusCode: 500, headers: wireHeaders(signed) }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.equal(reqLike.status, 500);
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("headers are lowercased and multi-values joined, like the request adapter", () => {
  const reqLike = fromNodeResponse(
    incomingResponse({
      statusCode: 201,
      headers: { "Content-Type": "application/json", "X-Multi": ["a ", " b"] },
    }),
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

test("parsed trailers object verifies a ;tr component when rawTrailers is absent", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      trailers: { "x-settlement-id": "stl_42" },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", "x-settlement-id;tr"],
    },
  );
  const reqLike = fromNodeResponse(
    incomingResponse({
      headers: wireHeaders(signed),
      trailers: { "x-settlement-id": "stl_42" },
    }),
    BODY,
    { method: "GET", url: URL },
  );
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});
