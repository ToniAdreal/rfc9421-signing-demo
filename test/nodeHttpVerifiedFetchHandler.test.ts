import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  createVerifiedFetchHandler,
  generateEd25519KeyPair,
  signRequest,
  verifyAllResponseLabels,
  verifyResponse,
  type CreateVerifiedFetchHandlerOptions,
  type HttpResponseLike,
  type RequestLike,
  type SignedHttpRequest,
  type VerifiedFetchHandler,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1136: `createVerifiedHandler` (#1016) only returns a Node
// `http.RequestListener` — `src/nodeHttp.ts` has no fetch-shape handler,
// so a WinterCG / edge webhook receiver (undici `Request` / `Response`)
// still hand-rolls "read the body, adapt with `fromFetchRequest`,
// verify, answer 401". `fromFetchRequest` (#1125) gave the inbound
// adapter, but the closed loop was missing on the server side (the
// client `verifiedFetch` and the Node handler already exist).
// `createVerifiedFetchHandler` closes it: the same buffer→adapt→
// verify→401 loop, returning `(req: Request) => Promise<Response>`.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });
const URL = "http://127.0.0.1/webhook";

const gateway = generateEd25519KeyPair();
const merchant = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();

/** Sign a POST to the exact URL the fetch `Request` will carry. */
function signedPost(
  body: string = BODY,
  overrides: {
    key?: typeof gateway.privateKey;
    created?: number;
    expires?: number;
    label?: string;
  } = {},
): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: URL,
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
      ...(overrides.label !== undefined
        ? { label: overrides.label }
        : {}),
    },
  );
}

/** A dual-signed request: merchant first, gateway appended. */
function dualSignedPost(body: string = BODY): SignedHttpRequest {
  const merchantSigned = signRequest(
    {
      method: "POST",
      url: URL,
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

/** Build a real fetch `Request` from a signed request. */
function fetchRequest(signed: SignedHttpRequest, body: string = BODY): Request {
  return new Request(URL, {
    method: "POST",
    headers: signed.headers as Record<string, string>,
    body,
  });
}

function verifyOpts(overrides: Partial<VerifyOptions> = {}): VerifyOptions {
  return { key: gateway.publicKey, now: NOW, ...overrides };
}

interface Harness {
  /** VerifyResults the business handler received, in arrival order. */
  calls: VerifyResult[];
  /** Raw request lines the business handler saw, in arrival order. */
  seen: { method: string | undefined; url: string | undefined }[];
  fetchHandler: (req: Request) => Promise<Response>;
}

function makeHandler(
  opts: VerifyOptions,
  handlerOpts?: CreateVerifiedFetchHandlerOptions,
  business?: VerifiedFetchHandler,
): Harness {
  const calls: VerifyResult[] = [];
  const seen: { method: string | undefined; url: string | undefined }[] = [];
  const fetchHandler = createVerifiedFetchHandler(
    opts,
    business ??
      ((req, result) => {
        calls.push(result);
        seen.push({ method: req.method, url: req.url });
        return new Response(
          JSON.stringify({ ok: true, keyId: result.keyId ?? null }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        );
      }),
    handlerOpts,
  );
  return { calls, seen, fetchHandler };
}

/** The triggering request, as a response verifier sees it. */
function triggeringRequest(body: string = BODY): RequestLike {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    body,
  };
}

/** A fetch `Response` as the `HttpResponseLike` `verifyResponse` takes. */
function responseLike(res: Response, body: string): HttpResponseLike {
  const headers: Record<string, string> = {};
  res.headers.forEach((value, name) => {
    headers[name] = value;
  });
  return { status: res.status, headers, body };
}

test("a signed POST passes and the handler receives the VerifyResult", async () => {
  const h = makeHandler(verifyOpts());
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(await res.text()), {
    ok: true,
    keyId: "gateway-key",
  });
  assert.equal(h.calls.length, 1);
  const result = h.calls[0] as VerifyResult;
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "gateway-key");
  assert.equal(result.alg, "ed25519");
  // The handler gets the received Request alongside the result.
  assert.deepEqual(h.seen, [{ method: "POST", url: URL }]);
});

test("an unsigned request is answered 401 and the handler is never called", async () => {
  const h = makeHandler(verifyOpts());
  const req = new Request(URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: BODY,
  });
  const res = await h.fetchHandler(req);
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "signature verification failed",
    code: "MISSING_SIGNATURE_INPUT",
  });
  assert.equal(h.calls.length, 0);
});

test("a tampered body is answered 401 and the handler is never called", async () => {
  const h = makeHandler(verifyOpts());
  // Signed over BODY, sent with a different body: the wire
  // content-digest still matches the signature, but the body no
  // longer matches the digest.
  const res = await h.fetchHandler(
    fetchRequest(signedPost(), TAMPERED_BODY),
  );
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "signature verification failed",
    code: "BODY_DIGEST_MISMATCH",
  });
  assert.equal(h.calls.length, 0);
});

test("a wrong key is answered 401 SIGNATURE_MISMATCH", async () => {
  const h = makeHandler(verifyOpts());
  const res = await h.fetchHandler(
    fetchRequest(signedPost(BODY, { key: wrongKey.privateKey })),
  );
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "signature verification failed",
    code: "SIGNATURE_MISMATCH",
  });
  assert.equal(h.calls.length, 0);
});

test("an expired signature is answered 401 EXPIRED", async () => {
  const h = makeHandler(verifyOpts());
  const res = await h.fetchHandler(
    fetchRequest(signedPost(BODY, { expires: NOW - 10 })),
  );
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "signature verification failed",
    code: "EXPIRED",
  });
  assert.equal(h.calls.length, 0);
});

test("a 401 body carries only error and code — no reason, no stack", async () => {
  const h = makeHandler(verifyOpts());
  const req = new Request(URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: BODY,
  });
  const res = await h.fetchHandler(req);
  assert.equal(res.status, 401);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), {
    error: "signature verification failed",
    code: "MISSING_SIGNATURE_INPUT",
  });
  assert.equal(text.includes("reason"), false);
  assert.equal(text.includes("stack"), false);
  assert.equal(res.headers.get("content-type"), "application/json");
});

test("an over-cap body is answered 413 and the key resolver is never called", async () => {
  let resolverCalls = 0;
  const h = makeHandler(
    {
      keyResolver: (keyId) => {
        resolverCalls++;
        assert.equal(keyId, "gateway-key");
        return gateway.publicKey;
      },
      now: NOW,
    },
    { maxBodyBytes: 10 },
  );
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 413);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "request body too large",
    code: "BODY_TOO_LARGE",
  });
  assert.equal(resolverCalls, 0);
  assert.equal(h.calls.length, 0);
});

test("a body exactly at the cap still verifies", async () => {
  const h = makeHandler(verifyOpts(), {
    maxBodyBytes: Buffer.byteLength(BODY),
  });
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 200);
  assert.equal(h.calls.length, 1);
});

test("creation-time maxBodyBytes validation rejects non-positive integers", () => {
  for (const bad of [0, -1, 1.5, Number.NaN]) {
    assert.throws(
      () =>
        createVerifiedFetchHandler(
          verifyOpts(),
          () => new Response("ok"),
          { maxBodyBytes: bad },
        ),
      /createVerifiedFetchHandler: maxBodyBytes must be a positive integer/,
    );
  }
});

test("creation-time verifyOpts validation names the fetch handler", () => {
  assert.throws(
    () =>
      createVerifiedFetchHandler({} as VerifyOptions, () =>
        new Response("ok"),
      ),
    /createVerifiedFetchHandler: invalid verifyOpts: verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
});

test("creation-time signResponse and signResponses are mutually exclusive", () => {
  assert.throws(
    () =>
      createVerifiedFetchHandler(
        verifyOpts(),
        () => new Response("ok"),
        {
          signResponse: { key: merchant.privateKey, alg: "ed25519" },
          signResponses: [{ key: merchant.privateKey, alg: "ed25519" }],
        },
      ),
    /createVerifiedFetchHandler: signResponse and signResponses are mutually exclusive/,
  );
  assert.throws(
    () =>
      createVerifiedFetchHandler(verifyOpts(), () => new Response("ok"), {
        signResponses: [],
      }),
    /createVerifiedFetchHandler: signResponses must not be empty/,
  );
  assert.throws(
    () =>
      createVerifiedFetchHandler(
        verifyOpts(),
        () => new Response("ok"),
        {
          // A key source must be present to reach the requiredLabels
          // check — without one the key-source error fires first.
          verifyAllLabels: {
            key: gateway.publicKey,
            requiredLabels: [],
          },
        },
      ),
    /createVerifiedFetchHandler: invalid verifyAllLabels: verifyAllLabels: `requiredLabels` must not be empty/,
  );
});

test("opt-in signResponse: the response carries a verifiable signature", async () => {
  const h = makeHandler(
    verifyOpts(),
    {
      signResponse: {
        key: merchant.privateKey,
        alg: "ed25519",
        keyId: "merchant-key",
        // Pinned so the response verifies against the same fixed
        // clock as the request (NOW), like the Node handler tests.
        created: CREATED,
        coveredComponents: ["@status", "@method;req"],
      },
    },
    (_req, result) =>
      new Response(JSON.stringify({ ok: true, keyId: result.keyId ?? null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 200);
  assert.ok(res.headers.get("signature-input") !== null);
  assert.ok(res.headers.get("signature") !== null);
  const body = await res.text();
  const verified = verifyResponse(responseLike(res, body), {
    key: merchant.publicKey,
    request: triggeringRequest(),
    now: NOW,
    requiredComponents: ["@status"],
  });
  assert.equal(verified.ok, true);
  assert.deepEqual(JSON.parse(body), { ok: true, keyId: "gateway-key" });
});

test("opt-in signResponses: a dual-label response verifies via verifyAllResponseLabels", async () => {
  const h = makeHandler(
    verifyOpts(),
    {
      signResponses: [
        {
          key: merchant.privateKey,
          alg: "ed25519",
          keyId: "merchant-key",
          label: "merchant",
          // Pinned so both labels verify against the same fixed
          // clock as the request (NOW), like the Node handler tests.
          created: CREATED,
        },
        {
          key: gateway.privateKey,
          alg: "ed25519",
          keyId: "gateway-key",
          label: "gateway",
          created: CREATED,
        },
      ],
    },
    () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 200);
  const body = await res.text();
  const results = verifyAllResponseLabels(responseLike(res, body), {
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    requiredLabels: ["merchant", "gateway"],
    now: NOW,
    request: triggeringRequest(),
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("opt-in verifyAllLabels: a dual-signed request passes with an aggregate result", async () => {
  const h = makeHandler(
    verifyOpts(),
    {
      verifyAllLabels: {
        keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
        requiredLabels: ["merchant", "gateway"],
      },
    },
  );
  const res = await h.fetchHandler(fetchRequest(dualSignedPost()));
  assert.equal(res.status, 200);
  assert.equal(h.calls.length, 1);
  const result = h.calls[0] as VerifyResult;
  assert.equal(result.ok, true);
  // The aggregate has no single owner label; each label's own result
  // rides in perLabelResults, in wire order.
  assert.equal(result.label, "");
  assert.equal(result.perLabelResults?.length, 2);
  assert.deepEqual(
    result.perLabelResults?.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("opt-in verifyAllLabels: a stripped co-signature is answered 401", async () => {
  const h = makeHandler(
    verifyOpts(),
    {
      verifyAllLabels: {
        keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
        requiredLabels: ["merchant", "gateway"],
      },
    },
  );
  // Merchant-only signature: the required gateway label is missing.
  const merchantOnly = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  const res = await h.fetchHandler(fetchRequest(merchantOnly));
  assert.equal(res.status, 401);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "signature verification failed",
    code: "MISSING_REQUIRED_LABEL",
  });
  assert.equal(h.calls.length, 0);
});

test("a business handler that throws is answered 500 and nothing leaks", async () => {
  const h = makeHandler(
    verifyOpts(),
    undefined,
    () => {
      throw new Error("database is down");
    },
  );
  const res = await h.fetchHandler(fetchRequest(signedPost()));
  assert.equal(res.status, 500);
  const text = await res.text();
  assert.deepEqual(JSON.parse(text), {
    error: "internal error",
    code: "INTERNAL_ERROR",
  });
  assert.equal(text.includes("database is down"), false);
});

test("a request that cannot be adapted is answered 400", async () => {
  const h = makeHandler(verifyOpts());
  // A test double shaped like a fetch Request but with no method:
  // `fromFetchRequest` fails fast instead of silently defaulting.
  const malformed = {
    method: "",
    url: URL,
    headers: new Headers({ "content-type": "application/json" }),
    body: null,
  } as unknown as Request;
  const res = await h.fetchHandler(malformed);
  assert.equal(res.status, 400);
  assert.deepEqual(JSON.parse(await res.text()), {
    error: "malformed request",
    code: "MALFORMED_REQUEST",
  });
  assert.equal(h.calls.length, 0);
});

test("the handler receives the same Request object it was given", async () => {
  const h = makeHandler(verifyOpts());
  const req = fetchRequest(signedPost());
  const res = await h.fetchHandler(req);
  assert.equal(res.status, 200);
  // The body stream was consumed by verification, so the handler
  // cannot re-read it — the documented limit, pinned here so a
  // future change to the contract fails loudly instead of silently.
  assert.deepEqual(h.seen, [{ method: "POST", url: URL }]);
  assert.equal(req.bodyUsed, true);
});
