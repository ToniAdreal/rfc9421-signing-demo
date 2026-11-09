import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createVerifiedHandler,
  generateEd25519KeyPair,
  signRequest,
  type SignedHttpRequest,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1016: `src/nodeHttp.ts` only had adapters —
// `fromNodeRequest` / `fromNodeResponse` / `fromFetchResponse` — and
// no `RequestListener` / middleware shape, so every webhook receiver
// hand-rolled "buffer the body, adapt, verify, answer 401", and one
// missed step let an unverified request into the business handler.
// `createVerifiedHandler` closes that loop in one place.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });

const gateway = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a client would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Content-Type": "application/json",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
    "Content-Digest": signed.headers["content-digest"] as string,
  };
}

/** Sign a POST to the exact loopback URL the server rebuilds. */
function signedPost(
  port: number,
  body: string = BODY,
  overrides: {
    key?: typeof gateway.privateKey;
    created?: number;
    expires?: number;
  } = {},
): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: overrides.key ?? gateway.privateKey,
      created: overrides.created ?? CREATED,
      ...(overrides.expires !== undefined
        ? { expires: overrides.expires }
        : {}),
    },
  );
}

/** Minimal POST client: returns the status and the raw response body. */
function post(
  port: number,
  headers: Record<string, string | undefined>,
  body: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: "/webhook",
        method: "POST",
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

interface Harness {
  port: number;
  /** VerifyResults the business handler received, in arrival order. */
  calls: VerifyResult[];
  /** Raw request lines the business handler saw, in arrival order. */
  seen: { method: string | undefined; url: string | undefined }[];
  close: () => Promise<void>;
}

async function startServer(
  verifyOpts: VerifyOptions,
  handlerOpts?: { maxBodyBytes?: number },
): Promise<Harness> {
  const calls: VerifyResult[] = [];
  const seen: { method: string | undefined; url: string | undefined }[] =
    [];
  const server = createServer(
    createVerifiedHandler(
      verifyOpts,
      (req, res, result) => {
        calls.push(result);
        seen.push({ method: req.method, url: req.url });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, keyId: result.keyId ?? null }));
      },
      handlerOpts,
    ),
  );
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", resolve),
  );
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    calls,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function verifyOpts(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { key: gateway.publicKey, now: NOW, ...overrides };
}

test("loopback: a signed POST passes and the handler receives the VerifyResult", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    assert.equal(h.calls.length, 1);
    const result = h.calls[0] as VerifyResult;
    assert.equal(result.ok, true);
    assert.equal(result.keyId, "gateway-key");
    assert.equal(result.alg, "ed25519");
    // The handler gets the raw Node request alongside the result.
    assert.deepEqual(h.seen, [{ method: "POST", url: "/webhook" }]);
  } finally {
    await h.close();
  }
});

test("an unsigned request is answered 401 and the handler is never called", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(
      h.port,
      { "Content-Type": "application/json" },
      BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "MISSING_SIGNATURE_INPUT",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("a tampered body is answered 401 and the handler is never called", async () => {
  const h = await startServer(verifyOpts());
  try {
    // Signed over BODY, sent with a different body: the wire
    // content-digest still matches the signature, but the body no
    // longer matches the digest.
    const res = await post(
      h.port,
      wireHeaders(signedPost(h.port)),
      TAMPERED_BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "BODY_DIGEST_MISMATCH",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("a wrong key is answered 401 and the handler is never called", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(
      h.port,
      wireHeaders(signedPost(h.port, BODY, { key: wrongKey.privateKey })),
      BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("an expired signature is answered 401 and the handler is never called", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(
      h.port,
      wireHeaders(signedPost(h.port, BODY, { expires: NOW - 10 })),
      BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "EXPIRED",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("the 401 body carries only error and code — no reason, no stack", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(
      h.port,
      wireHeaders(signedPost(h.port)),
      TAMPERED_BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(Object.keys(JSON.parse(res.body)).sort(), [
      "code",
      "error",
    ]);
    assert.equal(res.body.includes("reason"), false);
    assert.equal(res.body.includes("stack"), false);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("an oversized body is answered 413 and the key resolver is never called", async () => {
  let resolverCalls = 0;
  const h = await startServer(
    {
      keyResolver: (keyId: string) => {
        resolverCalls++;
        return keyId === "gateway-key" ? gateway.publicKey : undefined;
      },
      now: NOW,
    },
    { maxBodyBytes: 32 },
  );
  try {
    // A properly signed 64-byte body: even a valid signature must not
    // be verified once the body is over the cap.
    const bigBody = JSON.stringify({ settled: true, amount: 100, pad: "x".repeat(32) });
    assert.ok(Buffer.byteLength(bigBody) > 32);
    const res = await post(
      h.port,
      wireHeaders(signedPost(h.port, bigBody)),
      bigBody,
    );
    assert.equal(res.status, 413);
    assert.deepEqual(JSON.parse(res.body), {
      error: "request body too large",
      code: "BODY_TOO_LARGE",
    });
    assert.equal(resolverCalls, 0);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("a body exactly at maxBodyBytes still verifies", async () => {
  const h = await startServer(verifyOpts(), {
    maxBodyBytes: Buffer.byteLength(BODY),
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.equal(h.calls.length, 1);
  } finally {
    await h.close();
  }
});

test("a non-positive or non-integer maxBodyBytes throws at creation time", () => {
  const handler = () => {};
  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () =>
        createVerifiedHandler(
          { key: gateway.publicKey },
          handler,
          { maxBodyBytes: bad },
        ),
      /createVerifiedHandler: maxBodyBytes must be a positive integer/,
    );
  }
});

test("a signature-input header without a signature is answered 401 MISSING_SIGNATURE", async () => {
  const h = await startServer(verifyOpts());
  try {
    const signed = signedPost(h.port);
    const headers = wireHeaders(signed);
    delete headers["Signature"];
    const res = await post(h.port, headers, BODY);
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "MISSING_SIGNATURE",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});
