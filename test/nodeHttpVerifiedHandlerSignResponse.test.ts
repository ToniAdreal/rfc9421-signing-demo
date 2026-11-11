import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createVerifiedHandler,
  generateEd25519KeyPair,
  generateRsaPssKeyPair,
  secretKey,
  signRequest,
  verifyResponse,
  type CreateVerifiedHandlerOptions,
  type SignedHttpRequest,
  type VerifiedHandlerSignResponseOptions,
  type VerifiedRequestHandler,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1025: `createVerifiedHandler` (#1016) only verified the
// request side — a webhook receiver that wanted to sign its response
// (the other half of mutual authentication) had to hand-roll
// `signResponse` / `addResponseSignature` after the handler, which is
// the same "four hand-written steps, one missed step" gap the handler
// was built to close. The opt-in `CreateVerifiedHandlerOptions
// .signResponse` closes it: the wrapper buffers the business
// handler's response, signs it with the request it just verified
// attached (so covered `;req` components bind the signature to that
// request), and flushes the signed response in one go.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });

const gateway = generateEd25519KeyPair();
const merchant = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();
const hmacSecret = secretKey("settlement-webhook-shared-secret-0123456789");

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

/** Default response-signing options: ed25519, pinned creation time. */
function signOpts(
  overrides: Partial<CreateVerifiedHandlerOptions["signResponse"]> = {},
): CreateVerifiedHandlerOptions {
  return {
    signResponse: {
      key: merchant.privateKey,
      alg: "ed25519",
      keyId: "merchant-key",
      created: CREATED,
      ...overrides,
    },
  };
}

test("loopback: a signed handler response verifies via verifyResponse (label/keyid/alg pinned)", async () => {
  const h = await startServer(verifyOpts(), signOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    assert.equal(h.calls.length, 1);
    // The response carries a full signature: label sig1, the
    // merchant keyid, and a content-digest over the body.
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok((sigInput as string).startsWith('sig1='));
    assert.ok((sigInput as string).includes('keyid="merchant-key"'));
    assert.ok((sigInput as string).includes('"@status"'));
    assert.ok((sigInput as string).includes('"content-digest"'));
    assert.equal(typeof res.headers["signature"], "string");
    assert.equal(typeof res.headers["content-digest"], "string");
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
    assert.equal(result.alg, "ed25519");
    assert.equal(result.created, CREATED);
  } finally {
    await h.close();
  }
});

test("a ;req-bound response signature fails verification against a different request method", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts({
      coveredComponents: ["@status", "@method;req", "@path;req"],
    }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    // Bound to the POST that triggered it: verifies as sent.
    const asSent = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(asSent.ok, true);
    // The same response transplanted onto a GET: the ;req binding
    // no longer matches, so verification fails.
    const asGet = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port, { method: "GET" }),
        now: NOW,
      },
    );
    assert.equal(asGet.ok, false);
    assert.equal(asGet.code, "SIGNATURE_MISMATCH");
    // Same for a different path: the signature is bound to this
    // request, not to any request the key holder once signed.
    const otherPath = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port, { path: "/other" }),
        now: NOW,
      },
    );
    assert.equal(otherPath.ok, false);
    assert.equal(otherPath.code, "SIGNATURE_MISMATCH");
  } finally {
    await h.close();
  }
});

test("without signResponse the response carries no signature headers (regression #1016)", async () => {
  const h = await startServer(verifyOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    assert.equal(res.headers["signature-input"], undefined);
    assert.equal(res.headers["signature"], undefined);
    assert.equal(res.headers["content-digest"], undefined);
    assert.equal(h.calls.length, 1);
  } finally {
    await h.close();
  }
});

test("a 401 rejection carries no signature headers", async () => {
  const h = await startServer(verifyOpts(), signOpts());
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

test("a 413 rejection carries no signature headers", async () => {
  const h = await startServer(verifyOpts(), {
    ...signOpts(),
    maxBodyBytes: 32,
  });
  try {
    const bigBody = JSON.stringify({
      settled: true,
      amount: 100,
      pad: "x".repeat(32),
    });
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
    assert.equal(res.headers["signature-input"], undefined);
    assert.equal(res.headers["signature"], undefined);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("a public key, a non-KeyObject key, or an unknown alg as signResponse throws at creation", () => {
  const handler = () => {};
  // A public key cannot sign: the shape check passes (a public
  // ed25519 key has the same asymmetricKeyType), but the dry-run
  // sign fails in node:crypto — still at creation time, never on a
  // live request.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponse: {
          key: merchant.publicKey,
          alg: "ed25519",
        } as VerifiedHandlerSignResponseOptions,
      }),
    /createVerifiedHandler: invalid signResponse options: Invalid key object type public, expected private\./,
  );
  // A string is not a KeyObject at all.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponse: {
          key: "not-a-key",
          alg: "ed25519",
        } as unknown as VerifiedHandlerSignResponseOptions,
      }),
    /createVerifiedHandler: signResponse\.key must be a KeyObject/,
  );
  // An unknown alg is rejected as unsupported, not as a key mismatch
  // (backlog #1058): no key of any shape can sign "rsa-md5-sha1".
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponse: {
          key: merchant.privateKey,
          alg: "rsa-md5-sha1",
        } as unknown as VerifiedHandlerSignResponseOptions,
      }),
    /createVerifiedHandler: invalid signResponse options: signRequest: unsupported alg "rsa-md5-sha1"/,
  );
  // An RSA key paired with ed25519 is the same swapped-pair failure.
  assert.throws(
    () =>
      createVerifiedHandler({ key: gateway.publicKey }, handler, {
        signResponse: {
          key: generateRsaPssKeyPair().privateKey,
          alg: "ed25519",
        },
      }),
    /createVerifiedHandler: invalid signResponse options: signRequest: alg "ed25519" is incompatible/,
  );
});

test("an illegal label throws at creation", () => {
  const handler = () => {};
  for (const badLabel of ["bad label", "a,b", ""]) {
    assert.throws(
      () =>
        createVerifiedHandler({ key: gateway.publicKey }, handler, {
          signResponse: {
            key: merchant.privateKey,
            alg: "ed25519",
            label: badLabel,
          },
        }),
      /createVerifiedHandler: invalid signResponse options: signRequest: "label" must be an RFC 9421 token/,
    );
  }
});

test("a custom label and coveredComponents take effect", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts({
      label: "resp-sig",
      coveredComponents: ["@status", "content-type"],
    }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    // The explicit list wins: the label is resp-sig, content-type
    // is covered, and no content-digest is minted.
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok((sigInput as string).startsWith('resp-sig='));
    assert.ok((sigInput as string).includes('"content-type"'));
    assert.ok(!(sigInput as string).includes("content-digest"));
    assert.equal(res.headers["content-digest"], undefined);
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        label: "resp-sig",
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.keyId, "merchant-key");
    assert.equal(result.alg, "ed25519");
  } finally {
    await h.close();
  }
});

test("an explicit coveredComponents list without content-digest signs no digest", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts({ coveredComponents: ["@status"] }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.equal(res.headers["content-digest"], undefined);
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok(!(sigInput as string).includes("content-digest"));
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, true);
  } finally {
    await h.close();
  }
});

test("an hmac-sha256 response signature verifies", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts({
      key: hmacSecret,
      alg: "hmac-sha256",
      keyId: "merchant-hmac",
    }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const sigInput = res.headers["signature-input"];
    assert.equal(typeof sigInput, "string");
    assert.ok((sigInput as string).includes('keyid="merchant-hmac"'));
    assert.ok((sigInput as string).includes('alg="hmac-sha256"'));
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: hmacSecret,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, true);
    assert.equal(result.keyId, "merchant-hmac");
    assert.equal(result.alg, "hmac-sha256");
  } finally {
    await h.close();
  }
});

test("a handler that streams with write() still gets a signed response", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts(),
    (_req, res, _result) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"ok":true,');
      res.write('"keyId":"gateway-key"}');
      res.end();
    },
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, true);
  } finally {
    await h.close();
  }
});

test("a covered header the handler never sets answers 500, not an unsigned response", async () => {
  const h = await startServer(
    verifyOpts(),
    signOpts({ coveredComponents: ["@status", "x-request-id"] }),
  );
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    // The handler never sets x-request-id, so the response cannot be
    // signed as configured — fail closed with 500, nothing unsigned
    // on the wire.
    assert.equal(res.status, 500);
    assert.deepEqual(JSON.parse(res.body), {
      error: "internal error",
      code: "INTERNAL_ERROR",
    });
    assert.equal(res.headers["signature-input"], undefined);
    assert.equal(res.headers["signature"], undefined);
  } finally {
    await h.close();
  }
});

test("a tampered response body fails verifyResponse with BODY_DIGEST_MISMATCH", async () => {
  const h = await startServer(verifyOpts(), signOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: TAMPERED_BODY },
      {
        key: merchant.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.code, "BODY_DIGEST_MISMATCH");
  } finally {
    await h.close();
  }
});

test("a wrong response key fails verifyResponse with SIGNATURE_MISMATCH", async () => {
  const h = await startServer(verifyOpts(), signOpts());
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    const result = verifyResponse(
      { status: res.status, headers: res.headers, body: res.body },
      {
        key: wrongKey.publicKey,
        request: triggeringRequest(h.port),
        now: NOW,
      },
    );
    assert.equal(result.ok, false);
    assert.equal(result.code, "SIGNATURE_MISMATCH");
  } finally {
    await h.close();
  }
});
