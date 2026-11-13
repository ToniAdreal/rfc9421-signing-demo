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
  type VerifiedFetchResponse,
  type VerifiedFetchVerifyOptions,
} from "../src/index.js";

// Backlog #1105: `verifiedFetch` only verified a single response label
// (`verifyResponse`), while `verifyAllResponseLabels` already existed
// for the dual-sign settlement flow (merchant ed25519 signs, gateway
// hmac appends) — a client verifying both labels had to hand-roll
// `signRequest` + `fetch` + `fromFetchResponse` +
// `verifyAllResponseLabels`, the same "four hand-written steps, easy
// to skip one" shape #1087 removed for the single-label case.
// These cases pin `verify.verifyAllLabels` end to end over a loopback
// server: fail-closed per-label results, the other label staying
// visible on failure, and illegal label policies throwing before any
// network happens.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ_BODY = JSON.stringify({ amount: 100, currency: "USD" });
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });

const clientKeys = generateEd25519KeyPair();
const merchantKeys = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
const wrongGatewaySecret = secretKey("wrong-gateway-secret-32-bytes-00");

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

function signDualResponse(
  body: string,
  extra?: {
    gatewayKey?: ReturnType<typeof secretKey>;
    coveredComponents?: string[];
    request?: Parameters<typeof signResponse>[1]["request"];
  },
): SignedHttpResponse {
  const merchantSigned = signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchantKeys.privateKey,
      created: CREATED,
      label: "merchant",
      ...(extra?.coveredComponents !== undefined
        ? { coveredComponents: extra.coveredComponents }
        : {}),
      ...(extra?.request !== undefined ? { request: extra.request } : {}),
    },
  );
  return addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: extra?.gatewayKey ?? gatewaySecret,
    created: CREATED,
    label: "gateway",
    ...(extra?.coveredComponents !== undefined
      ? { coveredComponents: extra.coveredComponents }
      : {}),
    ...(extra?.request !== undefined ? { request: extra.request } : {}),
  });
}

function signMerchantOnlyResponse(body: string): SignedHttpResponse {
  return signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchantKeys.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
}

function multiLabelVerify(): VerifiedFetchVerifyOptions {
  return {
    verifyAllLabels: {
      keys: { merchant: merchantKeys.publicKey, gateway: gatewaySecret },
      requiredLabels: ["merchant", "gateway"],
      now: NOW,
    },
  };
}

function signOpts() {
  return {
    keyId: "client-key",
    alg: "ed25519" as const,
    key: clientKeys.privateKey,
    created: CREATED,
  };
}

test("verifiedFetch multi-label: loopback dual-sign round-trip verifies both labels", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signDualResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/charge`,
      { method: "POST", body: REQ_BODY },
      { sign: signOpts(), verify: multiLabelVerify() },
    );
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
    // Aggregate result: no single label owns it, per-label results
    // ride on `perLabelResults` (the createVerifiedHandler shape).
    assert.equal(result.verifyResult.label, "");
    assert.deepEqual(
      result.verifyResult.perLabelResults?.map((r) => r.label),
      ["merchant", "gateway"],
    );
    assert.deepEqual(
      result.verifyResult.perLabelResults?.map((r) => r.ok),
      [true, true],
    );
    assert.deepEqual(
      result.verifyResults?.map((r) => r.label),
      ["merchant", "gateway"],
    );
    assert.equal(result.verifyResults?.[0]?.keyId, "merchant-key-1");
    assert.equal(result.verifyResults?.[0]?.alg, "ed25519");
    assert.equal(result.verifyResults?.[1]?.keyId, "gateway-key-7");
    assert.equal(result.verifyResults?.[1]?.alg, "hmac-sha256");
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: one bad label fails the whole call but the other label's result stays visible", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    // Gateway signs with the wrong secret: its label fails, the
    // merchant label still verifies.
    sendSigned(
      res,
      signDualResponse(RES_BODY, { gatewayKey: wrongGatewaySecret }),
      RES_BODY,
    );
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/charge`,
        { method: "POST", body: REQ_BODY },
        { sign: signOpts(), verify: multiLabelVerify() },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "SIGNATURE_MISMATCH");
        assert.equal(e.label, "gateway");
        assert.equal(e.verifyResults?.length, 2);
        assert.equal(e.verifyResults?.[0]?.label, "merchant");
        assert.equal(e.verifyResults?.[0]?.ok, true);
        assert.equal(e.verifyResults?.[1]?.label, "gateway");
        assert.equal(e.verifyResults?.[1]?.ok, false);
        assert.equal(e.verifyResults?.[1]?.code, "SIGNATURE_MISMATCH");
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: missing required label fails with MISSING_REQUIRED_LABEL", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    // Merchant only: the gateway co-signature was stripped.
    sendSigned(res, signMerchantOnlyResponse(RES_BODY), RES_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/charge`,
        { method: "POST", body: REQ_BODY },
        { sign: signOpts(), verify: multiLabelVerify() },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "MISSING_REQUIRED_LABEL");
        assert.equal(e.label, "gateway");
        assert.equal(e.verifyResults?.length, 2);
        assert.equal(e.verifyResults?.[0]?.label, "merchant");
        assert.equal(e.verifyResults?.[0]?.ok, true);
        assert.equal(e.verifyResults?.[1]?.label, "gateway");
        assert.equal(e.verifyResults?.[1]?.ok, false);
        assert.equal(e.verifyResults?.[1]?.code, "MISSING_REQUIRED_LABEL");
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: unsigned response throws MISSING_SIGNATURE_INPUT, never passes vacuously", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(RES_BODY);
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/charge`,
        { method: "POST", body: REQ_BODY },
        {
          sign: signOpts(),
          // No requiredLabels: an unsigned response yields an empty
          // result set, which must not pass an `every` check
          // vacuously.
          verify: {
            verifyAllLabels: {
              keys: {
                merchant: merchantKeys.publicKey,
                gateway: gatewaySecret,
              },
              now: NOW,
            },
          },
        },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "MISSING_SIGNATURE_INPUT");
        assert.deepEqual(e.verifyResults, []);
        return true;
      },
    );
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: without verifyAllLabels the single-label behavior is unchanged", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    sendSigned(res, signDualResponse(RES_BODY), RES_BODY);
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/charge`,
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: { key: merchantKeys.publicKey, label: "merchant", now: NOW },
      },
    );
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
    assert.equal(result.verifyResult.label, "merchant");
    assert.equal(result.verifyResult.keyId, "merchant-key-1");
    assert.equal(result.verifyResults, undefined);
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: empty requiredLabels throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/charge",
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: {
            keys: {
              merchant: merchantKeys.publicKey,
              gateway: gatewaySecret,
            },
            requiredLabels: [],
            now: NOW,
          },
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyAllLabels: `requiredLabels` must not be empty/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch multi-label: duplicate or non-string requiredLabels throw before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  const base = {
    keys: { merchant: merchantKeys.publicKey, gateway: gatewaySecret },
    now: NOW,
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/charge",
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: {
            ...base,
            requiredLabels: ["merchant", "merchant"],
          },
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyAllLabels: `requiredLabels` must not repeat a label/,
  );
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/charge",
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: {
            ...base,
            requiredLabels: ["merchant", 7 as unknown as string],
          },
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyAllLabels: `requiredLabels` entries must be non-empty strings/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch multi-label: no key source at all throws before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/charge",
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: { requiredLabels: ["merchant"], now: NOW },
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch multi-label: outer verify options alongside verifyAllLabels throw before fetch", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/charge",
      { method: "POST", body: REQ_BODY },
      {
        sign: signOpts(),
        verify: {
          // A `key` here would be silently ignored in multi-label
          // mode, so it is a configuration error, not an override.
          key: merchantKeys.publicKey,
          verifyAllLabels: {
            keys: {
              merchant: merchantKeys.publicKey,
              gateway: gatewaySecret,
            },
            requiredLabels: ["merchant", "gateway"],
            now: NOW,
          },
        },
        fetchImpl,
      },
    ),
    /invalid verify options: verifyAllLabels is set: pass every verification option inside verifyAllLabels/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch multi-label: ;req binding anchors both labels to the request just sent", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    const triggering = {
      method: req.method ?? "",
      url: `http://${req.headers.host}${req.url ?? ""}`,
      headers: req.headers,
    };
    sendSigned(
      res,
      signDualResponse(RES_BODY, {
        coveredComponents: ["@status", "content-digest", "@method;req"],
        request: triggering,
      }),
      RES_BODY,
    );
  });
  try {
    const result = await verifiedFetch(
      `${baseUrl}/charge`,
      { method: "POST", body: REQ_BODY },
      { sign: signOpts(), verify: multiLabelVerify() },
    );
    assert.equal(result.verifyResult.ok, true);
    assert.deepEqual(
      result.verifyResults?.map((r) => r.coveredComponents),
      [
        ["@status", "content-digest", "@method;req"],
        ["@status", "content-digest", "@method;req"],
      ],
    );
  } finally {
    await close();
  }
});

test("verifiedFetch multi-label: ;req bound to a different request fails both labels", async () => {
  const { baseUrl, close } = await listen(async (req, res) => {
    await readRequestBody(req);
    // The peer binds ;req to a GET it never received; the client
    // actually sent a POST, so both signatures fail the base check.
    const triggering = {
      method: "GET",
      url: `http://${req.headers.host}${req.url ?? ""}`,
      headers: req.headers,
    };
    sendSigned(
      res,
      signDualResponse(RES_BODY, {
        coveredComponents: ["@status", "content-digest", "@method;req"],
        request: triggering,
      }),
      RES_BODY,
    );
  });
  try {
    await assert.rejects(
      verifiedFetch(
        `${baseUrl}/charge`,
        { method: "POST", body: REQ_BODY },
        { sign: signOpts(), verify: multiLabelVerify() },
      ),
      (e: unknown) => {
        assert.ok(isVerifyError(e), "must throw VerifyError");
        assert.equal(e.code, "SIGNATURE_MISMATCH");
        assert.equal(e.verifyResults?.length, 2);
        assert.deepEqual(
          e.verifyResults?.map((r) => r.ok),
          [false, false],
        );
        return true;
      },
    );
  } finally {
    await close();
  }
});
