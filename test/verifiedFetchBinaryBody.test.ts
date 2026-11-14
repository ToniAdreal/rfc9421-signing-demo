import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addResponseSignature,
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signResponse,
  verifiedFetch,
  type SignedHttpResponse,
  type VerifiedFetchVerifyOptions,
} from "../src/index.js";

// Backlog #1141: `verifiedFetch` decoded every response body as
// UTF-8 — a signed binary receipt (a PDF statement, a protobuf
// settlement credential) came back mangled, because the decode
// replaced invalid sequences, even though verification itself ran
// over the exact raw bytes. `responseBody: "bytes"` returns the raw
// `Buffer` instead, byte-for-byte. These cases pin it end to end
// over a loopback server: the full 0x00–0xFF body, tamper rejection,
// the default text mode unchanged, a Buffer request body, the byte
// cap in bytes mode, the empty body, the fail-fast on an illegal
// mode, and the multi-label return path.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ_BODY = JSON.stringify({ amount: 100, currency: "USD" });
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });

// Every byte value once: a UTF-8 decode of this body replaces the
// lone continuation bytes and the truncated sequences, so a
// string round-trip could never come back byte-equal.
const BINARY_BODY = Buffer.from(
  Array.from({ length: 256 }, (_, i) => i),
);
const TAMPERED_BODY = Buffer.from(BINARY_BODY);
TAMPERED_BODY[100] = (TAMPERED_BODY[100] as number) ^ 0xff;

const clientKeys = generateEd25519KeyPair();
const gatewayKeys = generateEd25519KeyPair();
const merchantKeys = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

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
  body: string | Buffer,
): void {
  res.writeHead(signed.status, {
    "content-type": "application/octet-stream",
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

function signGatewayResponse(body: string | Buffer): SignedHttpResponse {
  return signResponse(
    {
      status: 200,
      headers: { "content-type": "application/octet-stream" },
      body,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gatewayKeys.privateKey,
      created: CREATED,
    },
  );
}

function signOpts() {
  return {
    keyId: "client-key",
    alg: "ed25519" as const,
    key: clientKeys.privateKey,
    created: CREATED,
  };
}

function verifyOpts(): VerifiedFetchVerifyOptions {
  return { key: gatewayKeys.publicKey, now: NOW };
}

test("verifiedFetch bytes: full 0x00-0xFF binary response round-trips byte-exact", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signGatewayResponse(BINARY_BODY), BINARY_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/receipt`,
      { method: "GET" },
      { sign: signOpts(), verify: verifyOpts(), responseBody: "bytes" },
    );
    assert.equal(Buffer.isBuffer(result.body), true);
    assert.deepEqual(result.body, BINARY_BODY);
    assert.equal(result.body.length, 256);
    assert.equal(result.verifyResult.ok, true);
    assert.equal(result.verifyResult.label, "sig1");
    assert.equal(result.verifyResult.keyId, "gateway-key");
    assert.equal(result.verifyResult.alg, "ed25519");
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: one tampered byte fails the digest before the body is returned", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    // Signed over the original bytes, sent tampered: the digest is
    // covered by default, so the mismatch fires first.
    sendSigned(res, signGatewayResponse(BINARY_BODY), TAMPERED_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/receipt`,
        { method: "GET" },
        { sign: signOpts(), verify: verifyOpts(), responseBody: "bytes" },
      ),
      (e: unknown) => isVerifyError(e) && e.code === "BODY_DIGEST_MISMATCH",
    );
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: default text mode still returns the string, unchanged", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/settlement`,
      { method: "GET" },
      { sign: signOpts(), verify: verifyOpts() },
    );
    assert.equal(typeof result.body, "string");
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: explicit text mode returns the string too", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/settlement`,
      { method: "GET" },
      { sign: signOpts(), verify: verifyOpts(), responseBody: "text" },
    );
    assert.equal(typeof result.body, "string");
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: Buffer request body plus binary response in one call", async () => {
  const seen: { body?: Buffer } = {};
  const { baseUrl, close } = await listen(async (req, res) => {
    seen.body = await readRequestBody(req);
    sendSigned(res, signGatewayResponse(BINARY_BODY), BINARY_BODY);
  });
  try {
    const reqBody = Buffer.from(REQ_BODY, "utf8");
    const result = await verifiedFetch(
      `${baseUrl}/receipt`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: reqBody,
      },
      { sign: signOpts(), verify: verifyOpts(), responseBody: "bytes" },
    );
    assert.deepEqual(seen.body, reqBody);
    assert.equal(Buffer.isBuffer(result.body), true);
    assert.deepEqual(result.body, BINARY_BODY);
    assert.equal(result.verifyResult.ok, true);
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: maxBodyBytes still caps on raw byte count", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signGatewayResponse(BINARY_BODY), BINARY_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/receipt`,
        { method: "GET" },
        {
          sign: signOpts(),
          verify: verifyOpts(),
          responseBody: "bytes",
          maxBodyBytes: 32,
        },
      ),
      /verifiedFetch: response body exceeds maxBodyBytes \(32 bytes\)/,
    );
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: empty binary body round-trips as an empty Buffer", async () => {
  const empty = Buffer.alloc(0);
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signGatewayResponse(empty), empty);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/receipt`,
      { method: "GET" },
      { sign: signOpts(), verify: verifyOpts(), responseBody: "bytes" },
    );
    assert.equal(Buffer.isBuffer(result.body), true);
    assert.deepEqual(result.body, empty);
    assert.equal(result.body.length, 0);
    assert.equal(result.verifyResult.ok, true);
  } finally {
    await close();
  }
});

test("verifiedFetch bytes: illegal responseBody fails fast before any network", async () => {
  let fetchCalls = 0;
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/receipt",
      { method: "GET" },
      {
        sign: signOpts(),
        verify: verifyOpts(),
        responseBody: "yaml" as never,
        fetchImpl: async () => {
          fetchCalls += 1;
          throw new Error("must not be called");
        },
      },
    ),
    /verifiedFetch: responseBody must be "text" or "bytes", got yaml/,
  );
  assert.equal(fetchCalls, 0);
});

test("verifiedFetch bytes: multi-label mode returns the raw Buffer too", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    const merchantSigned = signResponse(
      {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
        body: BINARY_BODY,
      },
      {
        keyId: "merchant-key-1",
        alg: "ed25519",
        key: merchantKeys.privateKey,
        created: CREATED,
        label: "merchant",
      },
    );
    const dual = addResponseSignature(merchantSigned, {
      keyId: "gateway-key-7",
      alg: "hmac-sha256",
      key: gatewaySecret,
      created: CREATED,
      label: "gateway",
    });
    sendSigned(res, dual, BINARY_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/receipt`,
      { method: "GET" },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: {
            keys: { merchant: merchantKeys.publicKey, gateway: gatewaySecret },
            requiredLabels: ["merchant", "gateway"],
            now: NOW,
          },
        },
        responseBody: "bytes",
      },
    );
    assert.equal(Buffer.isBuffer(result.body), true);
    assert.deepEqual(result.body, BINARY_BODY);
    assert.equal(result.verifyResult.ok, true);
    assert.deepEqual(
      result.verifyResults?.map((r) => r.label),
      ["merchant", "gateway"],
    );
    assert.deepEqual(
      result.verifyResults?.map((r) => r.ok),
      [true, true],
    );
  } finally {
    await close();
  }
});
