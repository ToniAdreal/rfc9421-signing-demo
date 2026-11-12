import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import type { KeyObject } from "node:crypto";
import {
  createVerifiedHandler,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  type SignedHttpRequest,
  type VerifyOptions,
} from "../src/index.js";

// Backlog #1077: `createVerifiedHandler` validated `maxBodyBytes` and
// (via a dry-run sign) `signResponse` at creation time, but `verifyOpts`
// went verbatim into the per-request closure — a misconfigured verifier
// (no key source, `key` + `keyResolver`, a bad freshness window, ...)
// only surfaced as a 500 `INTERNAL_ERROR` on the first live request.
// The handler now dry-runs `verifyRequest` over a synthetic unsigned
// request at creation time and wraps any configuration error as
// `createVerifiedHandler: invalid verifyOpts: …`.
//
// Honest scope note: the per-label maps the acceptance draft mentions
// (`VerifyAllOptions`: `keyResolvers`, `candidateKeysByLabel`,
// `clockSkewToleranceSecByLabel`, ...) are NOT covered here — they
// belong to `verifyAllLabels`, which this handler never calls, and
// `VerifyOptions` carries no per-label map to validate. The dry run
// covers every configuration assertion `verifyRequest` itself performs
// before its header checks (key selection, candidate lists, freshness
// windows, header limits, required components, allowed algorithms,
// Structured Field types, clock options), plus the one check the
// unsigned dry run cannot reach (no key source at all, which
// `verifyRequest` only throws after a signature header parses).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });

const gateway = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();
const noop = (): void => {};

function baseOpts(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { key: gateway.publicKey, now: NOW, ...overrides };
}

/** A misconfiguration must fail at handler creation, never per request. */
function assertCreationThrows(
  opts: VerifyOptions,
  pattern: RegExp,
): void {
  assert.throws(() => createVerifiedHandler(opts, noop), pattern);
}

test("no key source at all throws at creation time", () => {
  assertCreationThrows(
    { now: NOW },
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
});

test("key + keyResolver throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ keyResolver: () => gateway.publicKey }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `key`, `keyResolver`, and `candidateKeys` are mutually exclusive/,
  );
});

test("key + candidateKeys throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ candidateKeys: [gateway.publicKey] }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `key`, `keyResolver`, and `candidateKeys` are mutually exclusive/,
  );
});

test("keyResolver + candidateKeys throws at creation time", () => {
  assertCreationThrows(
    {
      keyResolver: () => gateway.publicKey,
      candidateKeys: [gateway.publicKey],
      now: NOW,
    },
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `key`, `keyResolver`, and `candidateKeys` are mutually exclusive/,
  );
});

test("an empty candidateKeys list throws at creation time", () => {
  assertCreationThrows(
    { candidateKeys: [], now: NOW },
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `candidateKeys` must be a non-empty array of KeyObjects/,
  );
});

test("a non-KeyObject candidateKeys entry throws at creation time", () => {
  assertCreationThrows(
    {
      candidateKeys: [gateway.publicKey, "not-a-key" as unknown as KeyObject],
      now: NOW,
    },
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `candidateKeys\[1\]` must be a KeyObject/,
  );
});

test("a bad maxSignatureAgeSec throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ maxSignatureAgeSec: -1 }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `maxSignatureAgeSec` must be a non-negative finite number/,
  );
});

test("a bad maxSignatureInputLength throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ maxSignatureInputLength: 0 }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `maxSignatureInputLength` must be a positive integer/,
  );
});

test("a bad maxSignatureLength throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ maxSignatureLength: Number.NaN }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `maxSignatureLength` must be a positive integer/,
  );
});

test("a bad now throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ now: Number.NaN }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `now` must be a non-negative integer number of Unix seconds/,
  );
});

test("a bad clockSkewToleranceSec throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ clockSkewToleranceSec: 0 }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `clockSkewToleranceSec` must be a positive finite number/,
  );
});

test("a bad expiredToleranceSec throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ expiredToleranceSec: -1 }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `expiredToleranceSec` must be a non-negative finite number/,
  );
});

test("a bad requiredComponents entry throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ requiredComponents: ["@method", ""] }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `requiredComponents` entries must be non-empty strings/,
  );
});

test("an unknown allowedAlgs entry throws at creation time", () => {
  assertCreationThrows(
    baseOpts({ allowedAlgs: ["ed448" as never] }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `allowedAlgs` entries must name an implemented algorithm/,
  );
});

test("a bad structuredFieldTypes entry throws at creation time", () => {
  assertCreationThrows(
    baseOpts({
      structuredFieldTypes: { "x-foo": "bogus" as never },
    }),
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `structuredFieldTypes\["x-foo"\]` must be "dictionary" \| "list" \| "item"/,
  );
});

test("a singleKeyFallback paired with a foreign resolver throws at creation time", () => {
  const store = new JwksKeyStore(
    "https://keys.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        throw new Error("fetch must not run during handler creation");
      },
    },
  );
  assertCreationThrows(
    {
      keyResolver: () => gateway.publicKey,
      singleKeyFallback: store,
      now: NOW,
    },
    /createVerifiedHandler: invalid verifyOpts: verifyRequest: `singleKeyFallback` requires `keyResolver` to be that store's `resolve`/,
  );
});

test("a non-object verifyOpts throws at creation time", () => {
  assert.throws(
    () => createVerifiedHandler(null as unknown as VerifyOptions, noop),
    /createVerifiedHandler: invalid verifyOpts: verifyOpts must be an object, got null/,
  );
});

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
  key: KeyObject = gateway.privateKey,
): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    { keyId: "gateway-key", alg: "ed25519", key, created: CREATED },
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
      { host: "127.0.0.1", port, path: "/webhook", method: "POST", headers },
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

async function startServer(verifyOpts: VerifyOptions): Promise<{
  port: number;
  calls: number;
  close: () => Promise<void>;
}> {
  let calls = 0;
  const server = createServer(
    createVerifiedHandler(verifyOpts, (_req, res) => {
      calls++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    }),
  );
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", resolve),
  );
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    get calls() {
      return calls;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

test("the dry run never calls the key resolver — the resolver runs only per request", async () => {
  let resolverCalls = 0;
  const opts: VerifyOptions = {
    keyResolver: (keyId: string) => {
      resolverCalls++;
      return keyId === "gateway-key" ? gateway.publicKey : undefined;
    },
    now: NOW,
  };
  const h = await startServer(opts);
  try {
    // Creation (and its dry run) must not resolve any key.
    assert.equal(resolverCalls, 0);
    const res = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(res.status, 200);
    assert.equal(resolverCalls, 1);
    assert.equal(h.calls, 1);
  } finally {
    await h.close();
  }
});

test("the dry run never fetches — a JWKS store stays untouched at creation", async () => {
  let fetchCalls = 0;
  const store = new JwksKeyStore(
    "https://keys.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        fetchCalls++;
        throw new Error("fetch must not run during handler creation");
      },
    },
  );
  const h = await startServer({
    keyResolver: store.resolve,
    singleKeyFallback: store,
    now: NOW,
  });
  try {
    // Creation (and its dry run) must not refresh the store.
    assert.equal(fetchCalls, 0);
    // An unsigned request still answers 401 before any resolution.
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
    assert.equal(fetchCalls, 0);
    assert.equal(h.calls, 0);
  } finally {
    await h.close();
  }
});

test("legal verifyOpts build a handler whose 200/401/401 loopback behavior is unchanged", async () => {
  const h = await startServer(baseOpts());
  try {
    const ok = await post(h.port, wireHeaders(signedPost(h.port)), BODY);
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { ok: true });
    const tampered = await post(
      h.port,
      wireHeaders(signedPost(h.port)),
      TAMPERED_BODY,
    );
    assert.equal(tampered.status, 401);
    assert.deepEqual(JSON.parse(tampered.body), {
      error: "signature verification failed",
      code: "BODY_DIGEST_MISMATCH",
    });
    const unsigned = await post(
      h.port,
      { "Content-Type": "application/json" },
      BODY,
    );
    assert.equal(unsigned.status, 401);
    assert.deepEqual(JSON.parse(unsigned.body), {
      error: "signature verification failed",
      code: "MISSING_SIGNATURE_INPUT",
    });
    // Only the signed request reached the business handler.
    assert.equal(h.calls, 1);
    // A wrong key still fails the same way (the dry run changed
    // nothing about request-time verification).
    const wrong = await post(
      h.port,
      wireHeaders(signedPost(h.port, BODY, wrongKey.privateKey)),
      BODY,
    );
    assert.equal(wrong.status, 401);
    assert.deepEqual(JSON.parse(wrong.body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(h.calls, 1);
  } finally {
    await h.close();
  }
});
