import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signResponse,
  verifiedFetch,
  type SignedHttpResponse,
  type VerifiedFetchResponse,
  type VerifiedFetchSignOptions,
  type VerifiedFetchVerifyOptions,
} from "../src/index.js";

// Backlog #1087: the client side had no one-call helper for the
// "sign request → fetch → verify response" round-trip — callers
// hand-rolled signRequest + fetch + fromFetchResponse +
// verifyResponse, and a missed step let an unverified response in.
// These cases pin `verifiedFetch` end to end over a loopback server,
// plus the injected-fetchImpl doubles (zero network) and the
// fail-fast configuration errors (which must throw before fetch).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ_BODY = JSON.stringify({ amount: 100, currency: "USD" });
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });
const RES_BODY_TAMPERED = JSON.stringify({ status: "settled", amount: 10001 });

const clientKeys = generateEd25519KeyPair();
const gatewayKeys = generateEd25519KeyPair();
const otherKeys = generateEd25519KeyPair();

async function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendSigned(
  res: ServerResponse,
  signed: SignedHttpResponse,
  body: string,
): void {  res.writeHead(signed.status, {
    "content-type": "application/json",
    ...(signed.headers["content-digest"] !== undefined
      ? { "content-digest": signed.headers["content-digest"] }
      : {}),
    ...(signed.headers["signature-input"] !== undefined
      ? { "signature-input": signed.headers["signature-input"] }
      : {}),
    ...(signed.headers["signature"] !== undefined
      ? { signature: signed.headers["signature"] }
      : {}),
  });
  res.end(body);
}

function signGatewayResponse(
  body?: string,
  status = 200,
  extra?: { coveredComponents?: string[]; request?: Parameters<typeof signResponse>[1]["request"] },
): SignedHttpResponse {
  return signResponse(
    {
      status,
      headers: { "content-type": "application/json" },
      ...(body !== undefined ? { body } : {}),
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gatewayKeys.privateKey,
      created: CREATED,
      ...(extra?.coveredComponents !== undefined
        ? { coveredComponents: extra.coveredComponents }
        : {}),
      ...(extra?.request !== undefined ? { request: extra.request } : {}),
    },
  );
}

test("verifiedFetch: POST round-trip signs the request and verifies the response", async () => {
  const seen: { signatureInput?: string | undefined; body?: string } = {};
  const { baseUrl, close } = await listen(async (req, res) => {
    const body = await readRequestBody(req);
    const sigInput = req.headers["signature-input"];
    seen.signatureInput = Array.isArray(sigInput)
      ? sigInput.join(", ")
      : sigInput;
    seen.body = body.toString("utf8");
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/echo`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: REQ_BODY,
      },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
      },
    );
    assert.equal(result.response.status, 200);
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
    assert.equal(result.verifyResult.label, "sig1");
    assert.equal(result.verifyResult.keyId, "gateway-key");
    assert.equal(result.verifyResult.alg, "ed25519");
    assert.deepEqual(result.verifyResult.coveredComponents, [
      "@status",
      "content-digest",
    ]);
    // The request that went out was signed: the server saw the
    // signature-input header and the exact body that was covered.
    assert.match(seen.signatureInput ?? "", /sig1=\(/);
    assert.equal(seen.body, REQ_BODY);
  } finally {
    await close();
  }
});

test("verifiedFetch: GET with no body round-trips, covered [@status] only", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    sendSigned(res, signGatewayResponse(undefined, 200), "");
  });
  try {
    const result = await verifiedFetch(`${baseUrl}/status`, undefined, {
      sign: {
        keyId: "client-key",
        alg: "ed25519",
        key: clientKeys.privateKey,
        created: CREATED,
      },
      verify: { key: gatewayKeys.publicKey, now: NOW },
    });
    assert.equal(result.body, "");
    assert.equal(result.verifyResult.ok, true);
    assert.deepEqual(result.verifyResult.coveredComponents, ["@status"]);
  } finally {
    await close();
  }
});

test("verifiedFetch: response covering @method;req binds to the request just sent", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    const triggering = {
      method: req.method ?? "",
      url: `http://${req.headers.host}${req.url ?? ""}`,
      headers: req.headers,
    };
    sendSigned(
      res,
      signGatewayResponse(RES_BODY, 200, {
        coveredComponents: ["@status", "content-digest", "@method;req"],
        request: triggering,
      }),
      RES_BODY,
    );
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/echo`,
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
      },
    );
    assert.equal(result.verifyResult.ok, true);
    assert.deepEqual(result.verifyResult.coveredComponents, [
      "@status",
      "content-digest",
      "@method;req",
    ]);
  } finally {
    await close();
  }
});

test("verifiedFetch: tampered response body throws VerifyError BODY_DIGEST_MISMATCH", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    // Signed over the true body, tampered bytes on the wire.
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY_TAMPERED);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/echo`,
        { method: "POST", body: REQ_BODY },
        {
          sign: {
            keyId: "client-key",
            alg: "ed25519",
            key: clientKeys.privateKey,
            created: CREATED,
          },
          verify: { key: gatewayKeys.publicKey, now: NOW },
        },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "BODY_DIGEST_MISMATCH");
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch: wrong verify key throws VerifyError SIGNATURE_MISMATCH", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/echo`,
        { method: "POST", body: REQ_BODY },
        {
          sign: {
            keyId: "client-key",
            alg: "ed25519",
            key: clientKeys.privateKey,
            created: CREATED,
          },
          verify: { key: otherKeys.publicKey, now: NOW },
        },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "SIGNATURE_MISMATCH");
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch: unsigned response throws VerifyError MISSING_SIGNATURE_INPUT", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(RES_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/echo`,
        { method: "POST", body: REQ_BODY },
        {
          sign: {
            keyId: "client-key",
            alg: "ed25519",
            key: clientKeys.privateKey,
            created: CREATED,
          },
          verify: { key: gatewayKeys.publicKey, now: NOW },
        },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "MISSING_SIGNATURE_INPUT");
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch: non-2xx signed response is still verified and returned", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    sendSigned(res, signGatewayResponse(RES_BODY, 404), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/echo`,
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
      },
    );
    assert.equal(result.response.status, 404);
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
  } finally {
    await close();
  }
});

test("verifiedFetch: oversized body over the stream is rejected and the reader is cancelled at the cap", async () => {
  let pulls = 0;
  const stream: ReadableStream<Uint8Array<ArrayBuffer>> =
    new ReadableStream<Uint8Array<ArrayBuffer>>({
      pull(controller) {
        pulls++;
        controller.enqueue(new TextEncoder().encode("12345678"));
      },
    });
  let sentInit: { headers: Record<string, string> } | undefined;
  const fetchImpl = async (
    _url: string,
    init: { method: string; headers: Record<string, string>; body?: string | Buffer },
  ): Promise<VerifiedFetchResponse> => {
    sentInit = init;
    return {
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      arrayBuffer: async () => new ArrayBuffer(0),
      body: stream,
    };
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
        fetchImpl,
        maxBodyBytes: 10,
      },
    ),
    /response body exceeds maxBodyBytes \(10 bytes\)/,
  );
  // The request was signed before the fetch, and the reader was
  // cancelled as soon as the accumulated size passed the cap: the
  // first 8-byte chunk fits, the second pushes past 10, and no
  // third chunk is ever read. `pulls` is 3, not 2: a pull-based
  // stream refills after every dequeue, so the third pull fires
  // when the second chunk is dequeued — that chunk is enqueued but
  // never read, because the reader is cancelled before a third
  // read. (An implementation that kept reading would pull forever
  // on this never-ending stream instead of rejecting.)
  assert.match(sentInit?.headers["signature-input"] ?? "", /sig1=\(/);
  assert.equal(pulls, 3);
});

test("verifiedFetch: oversized body over the arrayBuffer fallback is rejected", async () => {
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => ({
    status: 200,
    headers: new Headers({}),
    arrayBuffer: async () => {
      const buf = Buffer.from("12345678901234567890");
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
    body: null,
  });
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
        fetchImpl,
        maxBodyBytes: 10,
      },
    ),
    /response body exceeds maxBodyBytes \(10 bytes\)/,
  );
});

test("verifiedFetch: injected fetchImpl round-trips with zero network", async () => {
  const signed = signGatewayResponse(RES_BODY);
  const fetchImpl = async (
    _url: string,
    init: { method: string; headers: Record<string, string>; body?: string | Buffer },
  ): Promise<VerifiedFetchResponse> => {
    assert.equal(init.method, "POST");
    assert.match(init.headers["signature-input"] ?? "", /sig1=\(/);
    assert.equal(init.body, REQ_BODY);
    return {
      status: 200,
      headers: new Headers(signed.headers),
      arrayBuffer: async () => {
        const buf = Buffer.from(RES_BODY);
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
      },
      body: null,
    };
  };
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    {
      method: "POST",
      headers: new Headers({ "content-type": "application/json" }),
      body: REQ_BODY,
    },
    {
      sign: {
        keyId: "client-key",
        alg: "ed25519",
        key: clientKeys.privateKey,
        created: CREATED,
      },
      verify: { key: gatewayKeys.publicKey, now: NOW },
      fetchImpl,
    },
  );
  assert.equal(result.body, RES_BODY);
  assert.equal(result.verifyResult.ok, true);
  assert.equal(result.verifyResult.keyId, "gateway-key");
});

test("verifiedFetch: illegal sign config throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          // An HMAC secret cannot sign ed25519: alg/key mismatch is
          // a configuration error, caught before any network.
          key: secretKey("a-shared-hmac-secret-of-32-bytes!!"),
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
        fetchImpl,
      },
    ),
    /incompatible with the key/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: illegal verify config throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  const sign: VerifiedFetchSignOptions = {
    keyId: "client-key",
    alg: "ed25519",
    key: clientKeys.privateKey,
    created: CREATED,
  };
  // No key source at all.
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      { sign, verify: {} as VerifiedFetchVerifyOptions, fetchImpl },
    ),
    /invalid verify options: verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
  // Key and resolver together are mutually exclusive.
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign,
        verify: {
          key: gatewayKeys.publicKey,
          keyResolver: () => gatewayKeys.publicKey,
          now: NOW,
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyRequest: `key`, `keyResolver`, and `candidateKeys` are mutually exclusive/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: caller-supplied verify.request throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: {
          key: gatewayKeys.publicKey,
          now: NOW,
          request: { method: "POST", url: "http://example.invalid/", headers: {} },
        } as unknown as VerifiedFetchVerifyOptions,
        fetchImpl,
      },
    ),
    /"verify\.request" is managed by verifiedFetch/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: non-positive maxBodyBytes throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY },
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: { key: gatewayKeys.publicKey, now: NOW },
        fetchImpl,
        maxBodyBytes: 0,
      },
    ),
    /maxBodyBytes must be a positive integer/,
  );
  assert.equal(calls, 0);
});
