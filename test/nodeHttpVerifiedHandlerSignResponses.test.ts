import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createVerifiedHandler,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllResponseLabels,
  verifyResponse,
  type CreateVerifiedHandlerOptions,
  type SignedHttpRequest,
  type VerifiedHandlerSignResponseOptions,
  type VerifiedRequestHandler,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1121: `createVerifiedHandler` verified multi-label requests
// (#1090, `verifyAllLabels` opt-in) but could only *sign* a response
// with one label — a dual-signed settlement response (merchant ed25519
// plus gateway hmac on the same response) could not be produced by
// the handler: the caller had to turn response signing off and
// hand-roll `signResponse` + `addResponseSignature` after the handler,
// the same gap #1090 closed on the verify side. The opt-in
// `CreateVerifiedHandlerOptions.signResponses` closes it: the wrapper
// signs the first entry with `signResponse` and appends each later
// entry with `addResponseSignature`, in array order, all bound to the
// request it just verified.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

const gateway = generateEd25519KeyPair();
const merchant = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

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
      key: gateway.privateKey,
      created: CREATED,
    },
  );
}

/** The triggering request, as the response verifier sees it. */
function triggeringRequest(
  port: number,
  overrides: { method?: string; path?: string } = {},
): {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
} {
  return {
    method: overrides.method ?? "POST",
    url: `http://127.0.0.1:${port}${overrides.path ?? "/webhook"}`,
    headers: { "content-type": "application/json" },
    body: BODY,
  };
}

interface FullResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/** Minimal POST client: returns the status, headers and raw body. */
function post(
  port: number,
  headers: Record<string, string | undefined>,
  body: string,
): Promise<FullResponse> {
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
            headers: res.headers,
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
  close: () => Promise<void>;
}

async function startServer(
  verifyOpts: VerifyOptions,
  handlerOpts?: CreateVerifiedHandlerOptions,
  business?: VerifiedRequestHandler,
): Promise<Harness> {
  const calls: VerifyResult[] = [];
  const server = createServer(
    createVerifiedHandler(
      verifyOpts,
      business ??
        ((_req, res, result) => {
          calls.push(result);
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, keyId: result.keyId ?? null }));
        }),
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

/** Default dual-label response-signing options: merchant ed25519, then gateway hmac. */
function signResponsesOpts(
  overrides: Partial<CreateVerifiedHandlerOptions> = {},
): CreateVerifiedHandlerOptions {
  return {
    signResponses: [
      {
        key: merchant.privateKey,
        alg: "ed25519",
        keyId: "merchant-key",
        label: "merchant",
        created: CREATED,
      },
      {
        key: gatewaySecret,
        alg: "hmac-sha256",
        keyId: "gateway-key",
        label: "gateway",
        created: CREATED,
      },
    ],
    ...overrides,
  };
}

test("loopback: a dual-label handler response verifies via verifyAllResponseLabels (both labels, wire order)", async () => {
  const h = await startServer(verifyOpts(), signResponsesOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    assert.equal(h.calls.length, 1);
    // Both labels are on the wire, merchant first (array order).
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok((sigInput as string).startsWith("merchant="));
    assert.ok((sigInput as string).includes(", gateway="));
    assert.ok((sigInput as string).includes('keyid="merchant-key"'));
    assert.ok((sigInput as string).includes('keyid="gateway-key"'));
    assert.equal(typeof res.headers["signature"], "string");
    assert.equal(typeof res.headers["content-digest"], "string");
    const results = verifyAllResponseLabels(
      { status: res.status, headers: res.headers, body: res.body },
      {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        request: triggeringRequest(h.port),
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      },
    );
    assert.equal(results.length, 2);
    assert.equal(results[0].ok, true);
    assert.equal(results[0].label, "merchant");
    assert.equal(results[0].keyId, "merchant-key");
    assert.equal(results[0].alg, "ed25519");
    assert.equal(results[1].ok, true);
    assert.equal(results[1].label, "gateway");
    assert.equal(results[1].keyId, "gateway-key");
    assert.equal(results[1].alg, "hmac-sha256");
  } finally {
    await h.close();
  }
});

test("a ;req-bound merchant label fails verification against a different request while the gateway label still passes", async () => {
  const h = await startServer(
    verifyOpts(),
    signResponsesOpts({
      signResponses: [
        {
          key: merchant.privateKey,
          alg: "ed25519",
          keyId: "merchant-key",
          label: "merchant",
          created: CREATED,
          coveredComponents: ["@status", "@method;req"],
        },
        {
          key: gatewaySecret,
          alg: "hmac-sha256",
          keyId: "gateway-key",
          label: "gateway",
          created: CREATED,
        },
      ],
    }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    // Bound to the POST that triggered it: both labels verify as sent.
    const asSent = verifyAllResponseLabels(
      { status: res.status, headers: res.headers, body: res.body },
      {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        request: triggeringRequest(h.port),
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      },
    );
    assert.deepEqual(
      asSent.map((r) => r.ok),
      [true, true],
    );
    // The same response transplanted onto a GET: the merchant label
    // is bound to the POST and fails, the gateway label (no ;req
    // coverage) still passes — per-label independence, not one
    // verdict for the whole response.
    const asGet = verifyAllResponseLabels(
      { status: res.status, headers: res.headers, body: res.body },
      {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        request: triggeringRequest(h.port, { method: "GET" }),
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      },
    );
    assert.equal(asGet[0].ok, false);
    assert.equal(asGet[0].code, "SIGNATURE_MISMATCH");
    assert.equal(asGet[1].ok, true);
  } finally {
    await h.close();
  }
});

test("single-label signResponse still signs exactly one label (regression #1025)", async () => {
  const h = await startServer(verifyOpts(), {
    signResponse: {
      key: merchant.privateKey,
      alg: "ed25519",
      keyId: "merchant-key",
      created: CREATED,
    },
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok((sigInput as string).startsWith("sig1="));
    assert.ok(!(sigInput as string).includes(","));
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.keyId, "merchant-key");
  } finally {
    await h.close();
  }
});

test("a 401 rejection carries no signature headers with signResponses set", async () => {
  const h = await startServer(verifyOpts(), signResponsesOpts());
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
    assert.equal(res.headers["signature-input"], undefined);
    assert.equal(res.headers["signature"], undefined);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("a signing failure in the second label answers 500 with no signature headers and no bytes", async () => {
  const h = await startServer(
    verifyOpts(),
    signResponsesOpts({
      signResponses: [
        {
          key: merchant.privateKey,
          alg: "ed25519",
          keyId: "merchant-key",
          label: "merchant",
          created: CREATED,
        },
        {
          // The handler never sets x-request-id, so the gateway
          // label cannot be signed as configured — the whole flush
          // aborts, including the merchant label that signed fine.
          key: gatewaySecret,
          alg: "hmac-sha256",
          keyId: "gateway-key",
          label: "gateway",
          created: CREATED,
          coveredComponents: ["@status", "x-request-id"],
        },
      ],
    }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 500);
    assert.deepEqual(JSON.parse(res.body), {
      error: "internal error",
      code: "INTERNAL_ERROR",
    });
    assert.equal(res.headers["signature-input"], undefined);
    assert.equal(res.headers["signature"], undefined);
    assert.equal(res.headers["content-digest"], undefined);
  } finally {
    await h.close();
  }
});

test("signResponse and signResponses together throw at creation", () => {
  const handler = () => {};
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponse: {
          key: merchant.privateKey,
          alg: "ed25519",
        },
        signResponses: [
          { key: merchant.privateKey, alg: "ed25519", label: "merchant" },
        ],
      }),
    /createVerifiedHandler: signResponse and signResponses are mutually exclusive/,
  );
});

test("an empty signResponses array throws at creation", () => {
  const handler = () => {};
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [],
      }),
    /createVerifiedHandler: signResponses must not be empty/,
  );
});

test("a repeated label throws at creation (explicit duplicate, and labelless colliding with sig1)", () => {
  const handler = () => {};
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [
          { key: merchant.privateKey, alg: "ed25519", label: "merchant" },
          { key: gatewaySecret, alg: "hmac-sha256", label: "merchant" },
        ],
      }),
    /createVerifiedHandler: signResponses: duplicate label "merchant"/,
  );
  // An omitted label counts as "sig1", so it collides with an
  // explicit "sig1" entry.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [
          { key: merchant.privateKey, alg: "ed25519" },
          { key: gatewaySecret, alg: "hmac-sha256", label: "sig1" },
        ],
      }),
    /createVerifiedHandler: signResponses: duplicate label "sig1"/,
  );
});

test("an invalid entry throws at creation, naming its index", () => {
  const handler = () => {};
  // A string is not a KeyObject at all — in the second entry.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [
          { key: merchant.privateKey, alg: "ed25519", label: "merchant" },
          {
            key: "not-a-key",
            alg: "hmac-sha256",
            label: "gateway",
          } as unknown as VerifiedHandlerSignResponseOptions,
        ],
      }),
    /createVerifiedHandler: signResponses\[1\]\.key must be a KeyObject/,
  );
  // An unknown alg in the first entry is rejected by the dry run.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [
          {
            key: merchant.privateKey,
            alg: "rsa-md5-sha1",
            label: "merchant",
          } as unknown as VerifiedHandlerSignResponseOptions,
          { key: gatewaySecret, alg: "hmac-sha256", label: "gateway" },
        ],
      }),
    /createVerifiedHandler: invalid signResponses\[0\] options: signRequest: unsupported alg "rsa-md5-sha1"/,
  );
  // A public key cannot sign — still at creation, never on a live request.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponses: [
          {
            key: merchant.publicKey,
            alg: "ed25519",
            label: "merchant",
          } as VerifiedHandlerSignResponseOptions,
        ],
      }),
    /createVerifiedHandler: invalid signResponses\[0\] options: Invalid key object type public, expected private\./,
  );
});

test("a tampered dual-label response body fails with BODY_DIGEST_MISMATCH on both labels", async () => {
  const h = await startServer(verifyOpts(), signResponsesOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const tampered = JSON.stringify({ settled: true, amount: 999 });
    const results = verifyAllResponseLabels(
      { status: res.status, headers: res.headers, body: tampered },
      {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        request: triggeringRequest(h.port),
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      },
    );
    assert.deepEqual(
      results.map((r) => r.ok),
      [false, false],
    );
    assert.deepEqual(
      results.map((r) => r.code),
      ["BODY_DIGEST_MISMATCH", "BODY_DIGEST_MISMATCH"],
    );
  } finally {
    await h.close();
  }
});

test("a wrong key for one label fails only that label", async () => {
  const h = await startServer(verifyOpts(), signResponsesOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const results = verifyAllResponseLabels(
      { status: res.status, headers: res.headers, body: res.body },
      {
        keys: { merchant: wrongKey.publicKey, gateway: gatewaySecret },
        request: triggeringRequest(h.port),
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      },
    );
    assert.equal(results[0].ok, false);
    assert.equal(results[0].code, "SIGNATURE_MISMATCH");
    assert.equal(results[1].ok, true);
  } finally {
    await h.close();
  }
});
