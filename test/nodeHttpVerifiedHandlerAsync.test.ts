import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addSignature,
  createVerifiedHandler,
  createVerifiedHandlerAsync,
  generateEd25519KeyPair,
  signRequest,
  type AsyncKeyResolver,
  type CreateVerifiedHandlerOptionsAsync,
  type SignedHttpRequest,
  type VerifyOptionsAsync,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1451: `createVerifiedHandler` only accepted a synchronous
// `key` / `keyResolver` / `candidateKeys` — a service whose keys live
// behind an async lookup (a JWKS endpoint fetched on demand, a Vault,
// a KMS) could not reuse the handler and had to hand-roll
// `verifyRequestAsync` + body cap + freshness, one missed step away
// from letting an unverified request in. `createVerifiedHandlerAsync`
// is the same buffer→adapt→verify→401 loop with the lookup awaited.
// This file pins the async twin and its parity with the sync one.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });

const gateway = generateEd25519KeyPair();
const merchant = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a client would send them. Absent signature headers are omitted, not sent as "undefined". */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  const headers: Record<string, string | undefined> = {
    "Content-Type": "application/json",
  };
  const sigInput = signed.headers["signature-input"] as string | undefined;
  const sig = signed.headers["signature"] as string | undefined;
  const digest = signed.headers["content-digest"] as string | undefined;
  if (sigInput !== undefined) headers["Signature-Input"] = sigInput;
  if (sig !== undefined) headers["Signature"] = sig;
  if (digest !== undefined) headers["Content-Digest"] = digest;
  return headers;
}

/** Sign a POST to the exact loopback URL the server rebuilds. */
function signedPost(
  port: number,
  body: string = BODY,
  overrides: {
    key?: typeof gateway.privateKey;
    created?: number;
    expires?: number;
    coveredComponents?: string[];
    label?: string;
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
      ...(overrides.coveredComponents !== undefined
        ? { coveredComponents: overrides.coveredComponents }
        : {}),
      ...(overrides.label !== undefined ? { label: overrides.label } : {}),
    },
  );
}

/** A dual-signed POST: merchant first, gateway appended. */
function dualSignedPost(port: number, body: string = BODY): SignedHttpRequest {
  const merchantSigned = signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  return addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
  });
}

/** Flip the first base64 character of one label's signature value. */
function tamperLabelSignature(
  signed: SignedHttpRequest,
  label: string,
): SignedHttpRequest {
  const raw = signed.headers["signature"] as string;
  const entries = raw.split(", ");
  const tampered = entries.map((entry) => {
    if (!entry.startsWith(`${label}=:`)) return entry;
    const inner = entry.slice(label.length + 2, -1);
    const flipped = (inner[0] === "A" ? "B" : "A") + inner.slice(1);
    return `${label}=:${flipped}:`;
  });
  return {
    ...signed,
    headers: { ...signed.headers, signature: tampered.join(", ") },
  };
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
  close: () => Promise<void>;
}

async function startAsyncServer(
  verifyOpts: VerifyOptionsAsync,
  handlerOpts?: CreateVerifiedHandlerOptionsAsync,
): Promise<Harness> {
  const calls: VerifyResult[] = [];
  const server = createServer(
    createVerifiedHandlerAsync(
      verifyOpts,
      (_req, res, result) => {
        calls.push(result);
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
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** An async resolver with a real await in the path: one tick, then the key. */
function tickingResolver(
  calls: { count: number },
  keyFor: (keyId: string) => typeof gateway.publicKey | undefined,
): AsyncKeyResolver {
  return async (keyId: string) => {
    calls.count++;
    await new Promise<void>((resolve) => setImmediate(resolve));
    return keyFor(keyId);
  };
}

test("an async resolver hit verifies and the handler receives the VerifyResult", async () => {
  const resolverCalls = { count: 0 };
  const h = await startAsyncServer({
    keyResolver: tickingResolver(resolverCalls, (keyId) =>
      keyId === "gateway-key" ? gateway.publicKey : undefined,
    ),
    now: NOW,
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body), {
      ok: true,
      keyId: "gateway-key",
    });
    assert.equal(resolverCalls.count, 1);
    assert.equal(h.calls.length, 1);
    assert.equal(h.calls[0]?.ok, true);
    assert.equal(h.calls[0]?.keyId, "gateway-key");
  } finally {
    await h.close();
  }
});

test("a synchronous resolver keeps working through the async handler", async () => {
  const h = await startAsyncServer({
    keyResolver: (keyId: string) =>
      keyId === "gateway-key" ? gateway.publicKey : undefined,
    now: NOW,
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.equal(h.calls.length, 1);
  } finally {
    await h.close();
  }
});

test("a throwing async resolver is answered 401 VERIFICATION_ERROR with no leak", async () => {
  const h = await startAsyncServer({
    keyResolver: async () => {
      await new Promise<void>((resolve) => setImmediate(resolve));
      throw new Error("vault exploded: secret-token-123");
    },
    now: NOW,
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "VERIFICATION_ERROR",
    });
    assert.equal(res.body.includes("vault exploded"), false);
    assert.equal(res.body.includes("secret-token-123"), false);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("an unknown keyid through the async resolver is answered 401 KEY_RESOLUTION_FAILED", async () => {
  const h = await startAsyncServer({
    keyResolver: tickingResolver({ count: 0 }, () => undefined),
    now: NOW,
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "KEY_RESOLUTION_FAILED",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("an async resolver that returns the wrong key is answered 401 SIGNATURE_MISMATCH", async () => {
  // The awaited value is actually used: resolving to a different key
  // must fail the crypto check, not pass on the keyid claim alone.
  const h = await startAsyncServer({
    keyResolver: tickingResolver({ count: 0 }, () => wrongKey.publicKey),
    now: NOW,
  });
  try {
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
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

test("an oversized body is answered 413 and the async resolver is never called", async () => {
  const resolverCalls = { count: 0 };
  const h = await startAsyncServer(
    {
      keyResolver: tickingResolver(resolverCalls, (keyId) =>
        keyId === "gateway-key" ? gateway.publicKey : undefined,
      ),
      now: NOW,
    },
    { maxBodyBytes: 32 },
  );
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
    assert.equal(resolverCalls.count, 0);
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("an expired signature through the async handler is answered 401 EXPIRED", async () => {
  const h = await startAsyncServer({
    keyResolver: tickingResolver({ count: 0 }, (keyId) =>
      keyId === "gateway-key" ? gateway.publicKey : undefined,
    ),
    now: NOW,
  });
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

test("a signature missing a required component is answered 401 MISSING_REQUIRED_COMPONENT", async () => {
  const h = await startAsyncServer({
    keyResolver: tickingResolver({ count: 0 }, (keyId) =>
      keyId === "gateway-key" ? gateway.publicKey : undefined,
    ),
    now: NOW,
    requiredComponents: ["content-digest"],
  });
  try {
    // Signed covering only @method: the required content-digest is
    // not covered, so the freshness-gated policy fails before crypto.
    const res = await post(
      h.port,
      wireHeaders(
        signedPost(h.port, BODY, { coveredComponents: ["@method"] }),
      ),
      BODY,
    );
    assert.equal(res.status, 401);
    assert.deepEqual(JSON.parse(res.body), {
      error: "signature verification failed",
      code: "MISSING_REQUIRED_COMPONENT",
    });
    assert.equal(h.calls.length, 0);
  } finally {
    await h.close();
  }
});

test("sync and async handlers agree on the same inputs, good and tampered", async () => {
  const syncCalls: VerifyResult[] = [];
  const syncServer = createServer(
    createVerifiedHandler(
      { key: gateway.publicKey, now: NOW },
      (_req, res, result) => {
        syncCalls.push(result);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, keyId: result.keyId ?? null }));
      },
    ),
  );
  await new Promise<void>((resolve) =>
    syncServer.listen(0, "127.0.0.1", resolve),
  );
  const syncPort = (syncServer.address() as AddressInfo).port;
  const asyncH = await startAsyncServer({
    keyResolver: tickingResolver({ count: 0 }, (keyId) =>
      keyId === "gateway-key" ? gateway.publicKey : undefined,
    ),
    now: NOW,
  });
  try {
    for (const body of [BODY, TAMPERED_BODY]) {
      const signed = signedPost(syncPort, BODY);
      const headers = wireHeaders(signed);
      // The signature binds the URL, so sign once per port.
      const asyncSigned = signedPost(asyncH.port, BODY);
      const syncRes = await post(syncPort, headers, body);
      const asyncRes = await post(
        asyncH.port,
        wireHeaders(asyncSigned),
        body,
      );
      assert.equal(asyncRes.status, syncRes.status);
      assert.equal(asyncRes.body, syncRes.body);
    }
    assert.equal(syncCalls.length, 1);
    assert.equal(asyncH.calls.length, 1);
  } finally {
    await asyncH.close();
    await new Promise<void>((resolve) => {
      syncServer.closeAllConnections();
      syncServer.close(() => resolve());
    });
  }
});

test("a verifier with no key source throws at creation time, naming the async factory", () => {
  assert.throws(
    () =>
      createVerifiedHandlerAsync({} as VerifyOptionsAsync, () => {}),
    /createVerifiedHandlerAsync: invalid verifyOpts: verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
});

test("a non-positive maxBodyBytes throws at creation time, naming the async factory", () => {
  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () =>
        createVerifiedHandlerAsync(
          { key: gateway.publicKey },
          () => {},
          { maxBodyBytes: bad },
        ),
      /createVerifiedHandlerAsync: maxBodyBytes must be a positive integer/,
    );
  }
});

test("an unknown handler option throws at creation time, naming the async factory", () => {
  assert.throws(
    () =>
      createVerifiedHandlerAsync(
        { key: gateway.publicKey },
        () => {},
        { bogus: true } as unknown as CreateVerifiedHandlerOptionsAsync,
      ),
    /invalid createVerifiedHandlerAsync options: unknown option "bogus"/,
  );
});

test("dual-signed requests verify through per-label async resolvers, one bad label fails closed", async () => {
  const resolverCalls = { count: 0 };
  const h = await startAsyncServer(
    {
      key: gateway.publicKey,
      now: NOW,
    },
    {
      verifyAllLabels: {
        keyResolvers: {
          merchant: tickingResolver(resolverCalls, (keyId) =>
            keyId === "merchant-key" ? merchant.publicKey : undefined,
          ),
          gateway: tickingResolver(resolverCalls, (keyId) =>
            keyId === "gateway-key" ? gateway.publicKey : undefined,
          ),
        },
        requiredLabels: ["merchant", "gateway"],
      },
    },
  );
  try {
    const good = await post(
      h.port,
      wireHeaders(dualSignedPost(h.port)),
      BODY,
    );
    assert.equal(good.status, 200);
    assert.equal(h.calls.length, 1);
    const aggregate = h.calls[0] as VerifyResult;
    assert.equal(aggregate.ok, true);
    assert.equal(aggregate.label, "");
    assert.equal(aggregate.perLabelResults?.length, 2);
    assert.deepEqual(
      aggregate.perLabelResults?.map((r) => r.keyId).sort(),
      ["gateway-key", "merchant-key"],
    );
    assert.equal(resolverCalls.count, 2);

    const tampered = await post(
      h.port,
      wireHeaders(tamperLabelSignature(dualSignedPost(h.port), "gateway")),
      BODY,
    );
    assert.equal(tampered.status, 401);
    assert.deepEqual(JSON.parse(tampered.body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(h.calls.length, 1);
  } finally {
    await h.close();
  }
});
