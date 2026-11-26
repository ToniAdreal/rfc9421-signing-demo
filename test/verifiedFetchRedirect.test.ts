import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  fromFetchResponse,
  generateEd25519KeyPair,
  isVerifyError,
  signResponse,
  verifiedFetch,
  verifyRequest,
  type RequestLike,
  type SignedHttpResponse,
  type VerifiedFetchResponse,
} from "../src/index.js";

// Backlog #1413: `verifiedFetch` used to follow redirects silently —
// the default fetch's `redirect: "follow"` was never overridden, and
// a caller-supplied `init.redirect` was never read, so the signed
// request headers rode along to whatever origin the 3xx pointed at
// while the response was still verified against the original request.
// These cases pin the fix: the default is `redirect: "error"`, the
// policy is an `opts` field (an `init.redirect` is a configuration
// error, never silently dropped), a followed redirect that lands on
// a different origin is refused unless explicitly allowed, and the
// result exposes the final URL. The `fromFetchResponse` half pins
// the new `finalUrl` override: the adapted message records where the
// response came from while `;req` still binds to the request sent.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });
const RES_BODY_TAMPERED = JSON.stringify({ status: "settled", amount: 10001 });

const clientKeys = generateEd25519KeyPair();
const gatewayKeys = generateEd25519KeyPair();

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

function sendSigned(
  res: ServerResponse,
  signed: SignedHttpResponse,
  body: string,
): void {
  res.writeHead(signed.status, {
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

function signGatewayResponse(body?: string, status = 200): SignedHttpResponse {
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
    },
  );
}

function signedDouble(
  body: string,
  extra?: { url?: string; status?: number; signBody?: string },
): VerifiedFetchResponse {
  const signed = signGatewayResponse(extra?.signBody ?? body, extra?.status ?? 200);
  return {
    status: extra?.status ?? 200,
    headers: new Headers(signed.headers),
    arrayBuffer: async () => {
      const buf = Buffer.from(body);
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
    body: null,
    ...(extra?.url !== undefined ? { url: extra.url } : {}),
  };
}

const signOpts = {
  keyId: "client-key",
  alg: "ed25519",
  key: clientKeys.privateKey,
  created: CREATED,
} as const;
const verifyOpts = { key: gatewayKeys.publicKey, now: NOW };

test("verifiedFetch: default redirect is error — the default fetchImpl receives redirect error", async () => {
  let seenRedirect: unknown;
  const fetchImpl = async (
    _url: string,
    init: { redirect?: string },
  ): Promise<VerifiedFetchResponse> => {
    seenRedirect = init.redirect;
    return signedDouble(RES_BODY);
  };
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "GET" },
    { sign: signOpts, verify: verifyOpts, fetchImpl },
  );
  assert.equal(seenRedirect, "error");
  assert.equal(result.body, RES_BODY);
  assert.equal(result.finalUrl, "https://gateway.example/v1/settlement");
});

test("verifiedFetch: explicit redirect follow reaches the fetchImpl", async () => {
  let seenRedirect: unknown;
  const fetchImpl = async (
    _url: string,
    init: { redirect?: string },
  ): Promise<VerifiedFetchResponse> => {
    seenRedirect = init.redirect;
    return signedDouble(RES_BODY);
  };
  await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "GET" },
    { sign: signOpts, verify: verifyOpts, fetchImpl, redirect: "follow" },
  );
  assert.equal(seenRedirect, "follow");
});

test("verifiedFetch: default opts never follow a loopback 302 — the redirect target is never hit", async () => {
  let targetHits = 0;
  const { baseUrl, close } = await listen((req, res) => {
    if (req.url === "/old") {
      res.writeHead(302, { location: "/target" });
      res.end();
      return;
    }
    targetHits++;
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    // The global fetch rejects on the redirect (a fetch-layer
    // error, passed through untouched) — the signed request is
    // never carried to /target.
    await assert.rejects(
      verifiedFetch(`${baseUrl}/old`, undefined, {
        sign: signOpts,
        verify: verifyOpts,
      }),
      (e: unknown) => e instanceof TypeError && /fetch failed/.test(e.message),
    );
    assert.equal(targetHits, 0);
  } finally {
    await close();
  }
});

test("verifiedFetch: redirect follow follows a same-origin loopback 302 and exposes the final URL", async () => {
  const { baseUrl, close } = await listen((req, res) => {
    if (req.url === "/old") {
      res.writeHead(302, { location: "/target" });
      res.end();
      return;
    }
    sendSigned(res, signGatewayResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(`${baseUrl}/old`, undefined, {
      sign: signOpts,
      verify: verifyOpts,
      redirect: "follow",
    });
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
    assert.equal(result.finalUrl, `${baseUrl}/target`);
  } finally {
    await close();
  }
});

test("verifiedFetch: redirect manual returns the 302 itself for verification", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    res.writeHead(302, { location: "/target" });
    res.end();
  });
  try {
    await assert.rejects(
      verifiedFetch(`${baseUrl}/old`, undefined, {
        sign: signOpts,
        verify: verifyOpts,
        redirect: "manual",
      }),
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

test("verifiedFetch: a cross-origin final URL is refused before verification", async () => {
  // The double returns a TAMPERED body under a signature for the
  // untampered one: if the refusal ran after verification, this
  // would report SIGNATURE_MISMATCH instead.
  const fetchImpl = async (): Promise<VerifiedFetchResponse> =>
    signedDouble(RES_BODY_TAMPERED, {
      url: "https://other.example.com/v1/settlement",
      signBody: RES_BODY,
    });
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      { method: "GET" },
      {
        sign: signOpts,
        verify: verifyOpts,
        fetchImpl,
        redirect: "follow",
      },
    ),
    /verifiedFetch: cross-origin redirect to https:\/\/other\.example\.com\/v1\/settlement refused/,
  );
});

test("verifiedFetch: cross-origin redirect is accepted with the explicit opt-in", async () => {
  const fetchImpl = async (): Promise<VerifiedFetchResponse> =>
    signedDouble(RES_BODY, {
      url: "https://other.example.com/v1/settlement",
    });
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "GET" },
    {
      sign: signOpts,
      verify: verifyOpts,
      fetchImpl,
      redirect: "follow",
      allowCrossOriginRedirect: true,
    },
  );
  assert.equal(result.body, RES_BODY);
  assert.equal(result.verifyResult.ok, true);
  assert.equal(result.finalUrl, "https://other.example.com/v1/settlement");
});

test("verifiedFetch: a different port is a different origin", async () => {
  const fetchImpl = async (): Promise<VerifiedFetchResponse> =>
    signedDouble(RES_BODY, { url: "http://127.0.0.1:9090/v1/settlement" });
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:8080/v1/settlement",
      { method: "GET" },
      {
        sign: signOpts,
        verify: verifyOpts,
        fetchImpl,
        redirect: "follow",
      },
    ),
    /cross-origin redirect to http:\/\/127\.0\.0\.1:9090\/v1\/settlement refused/,
  );
});

test("verifiedFetch: a same-origin redirect to another path passes and exposes the final URL", async () => {
  const fetchImpl = async (): Promise<VerifiedFetchResponse> =>
    signedDouble(RES_BODY, {
      url: "https://gateway.example/v1/settlement/final",
    });
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "GET" },
    {
      sign: signOpts,
      verify: verifyOpts,
      fetchImpl,
      redirect: "follow",
    },
  );
  assert.equal(result.body, RES_BODY);
  assert.equal(result.finalUrl, "https://gateway.example/v1/settlement/final");
});

test("verifiedFetch: no redirect — the result echoes the requested URL as finalUrl", async () => {
  const fetchImpl = async (): Promise<VerifiedFetchResponse> =>
    signedDouble(RES_BODY);
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "GET" },
    { sign: signOpts, verify: verifyOpts, fetchImpl },
  );
  assert.equal(result.finalUrl, "https://gateway.example/v1/settlement");
});

test("verifiedFetch: init.redirect is a configuration error, thrown before any network", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      { method: "GET", redirect: "follow" } as never,
      { sign: signOpts, verify: verifyOpts, fetchImpl },
    ),
    /init\.redirect is managed by opts\.redirect/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: an illegal opts.redirect throws before any network", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      { method: "GET" },
      {
        sign: signOpts,
        verify: verifyOpts,
        fetchImpl,
        redirect: "sometimes" as never,
      },
    ),
    /opts\.redirect must be "follow", "error", or "manual"/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: a non-boolean allowCrossOriginRedirect throws before any network", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      { method: "GET" },
      {
        sign: signOpts,
        verify: verifyOpts,
        fetchImpl,
        allowCrossOriginRedirect: "yes" as never,
      },
    ),
    /opts\.allowCrossOriginRedirect must be a boolean/,
  );
  assert.equal(calls, 0);
});

test("fromFetchResponse: finalUrl override records the landing URL while ;req stays bound to the sent request", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com", "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  };
  const signed = signResponse(
    { status: 200, headers: {}, body: RES_BODY },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      request,
      coveredComponents: ["@status", "@method;req"],
    },
  );
  const res = {
    status: 200,
    headers: new Headers(signed.headers),
  };
  const reqLike = fromFetchResponse(res, RES_BODY, {
    request,
    finalUrl: "https://api.example.com/v1/charge/final",
  });
  assert.equal(reqLike.url, "https://api.example.com/v1/charge/final");
  assert.equal(reqLike.request, request);
  // The ;req component still resolves against the request that was
  // actually sent (the original URL), not the landing URL.
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("fromFetchResponse: a non-string finalUrl throws the named error", () => {
  const res = { status: 200, headers: new Headers({}) };
  assert.throws(
    () =>
      fromFetchResponse(res, "body", {
        method: "GET",
        url: "https://api.example.com/v1/charge",
        finalUrl: 42 as never,
      }),
    /fromFetchResponse: opts\.finalUrl must be a non-empty string, got 42/,
  );
});

test("fromFetchResponse: an empty finalUrl falls through to the cannot-determine check", () => {
  const res = { status: 200, headers: new Headers({}) };
  assert.throws(
    () =>
      fromFetchResponse(res, "body", {
        method: "GET",
        url: "https://api.example.com/v1/charge",
        finalUrl: "",
      }),
    /cannot determine the request this response answers/,
  );
});
