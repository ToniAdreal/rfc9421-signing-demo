import test from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addSignature,
  fromNodeResponse,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #737: `test/nodeHttpResponse.test.ts` never mentions
// `verifyAllLabels` — every case there walks the single-label
// `verifyRequest` path. A client verifying a gateway's dual-signed
// settlement response through `fromNodeResponse` therefore had no
// backing: whether each label's own key is honoured through the
// adapter, and whether one label's failure is reported per label
// instead of failing the whole response, was unpinned.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// the wire signature headers verbatim and attaches the bound
// request, and `verifyAllLabels` already reports per label.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

function response(status = 200, request?: RequestLike) {
  return request === undefined
    ? { method: "GET", url: URL, headers: {}, body: BODY, status }
    : { method: "GET", url: URL, headers: {}, body: BODY, status, request };
}

/** A dual-signed response: merchant first, gateway appended. */
function dualSigned(status = 200): SignedHttpRequest {
  const merchantSigned = signRequest(response(status), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
  });
  return addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
}

/** Merge two independently signed responses into one wire header set. */
function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

function adaptedDual(signed: SignedHttpRequest): RequestLike {
  return fromNodeResponse(incomingResponse({ headers: wireHeaders(signed) }), BODY, {
    method: "GET",
    url: URL,
  });
}

test("verifyAllLabels x fromNodeResponse: a dual-signed response verifies both labels through the adapter", () => {
  const results = verifyAllLabels(adaptedDual(dualSigned()), {
    now: NOW,
    keys: keys(),
    requiredComponents: ["@status"],
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("@status"),
      `${r.label} must cover @status`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key");
  assert.equal(results[1].keyId, "gateway-key");
});

test("verifyAllLabels x fromNodeResponse: a real loopback server dual-signs a response; http.get client verifies both labels", async () => {
  const server = createServer((req, res) => {
    const port = (server.address() as AddressInfo).port;
    const url = `http://127.0.0.1:${port}/settle`;
    const merchantSigned = signRequest(
      { method: "GET", url, headers: {}, body: BODY, status: 200 },
      {
        keyId: "merchant-key",
        alg: "ed25519",
        key: merchant.privateKey,
        created: CREATED,
        label: "merchant",
        coveredComponents: ["@status"],
      },
    );
    const dual = addSignature(merchantSigned, {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
      coveredComponents: ["@status"],
    });
    res.writeHead(200, {
      "content-type": "application/json",
      "signature-input": dual.headers["signature-input"] as string,
      signature: dual.headers["signature"] as string,
    });
    res.end(BODY);
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/settle`;
      const request: RequestLike = {
        method: "GET",
        url,
        headers: { host: `127.0.0.1:${port}` },
      };
      get(url, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          try {
            const reqLike = fromNodeResponse(res, Buffer.concat(chunks), {
              request,
            });
            assert.equal(reqLike.status, 200);
            const results = verifyAllLabels(reqLike, {
              now: NOW,
              keys: keys(),
              requiredComponents: ["@status"],
            });
            assert.deepEqual(
              results.map((r) => [r.label, r.ok, r.keyId]),
              [
                ["merchant", true, "merchant-key"],
                ["gateway", true, "gateway-key"],
              ],
            );
            resolve();
          } catch (e) {
            reject(e);
          } finally {
            server.close();
          }
        });
        res.on("error", reject);
      }).on("error", reject);
    });
  });
});

test("verifyAllLabels x fromNodeResponse: a label signed over a different status fails alone, the other label still verifies", () => {
  // The wire status is single, so per-label divergence can only come
  // from signing history (same pattern as the #730 content-digest
  // divergence case): the gateway label is minted over status 500
  // while the wire carries status 200.
  const divergent = mergeSignatures(
    signRequest(response(200), {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@status"],
    }),
    signRequest(response(500), {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
      coveredComponents: ["@status"],
    }),
  );
  const results = verifyAllLabels(adaptedDual(divergent), {
    now: NOW,
    keys: keys(),
    requiredComponents: ["@status"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeResponse: each label is checked against its own key through the adapter", () => {
  const stranger = generateEd25519KeyPair();
  const results = verifyAllLabels(adaptedDual(dualSigned()), {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: stranger.publicKey },
    requiredComponents: ["@status"],
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeResponse: a bound request is attached and a ;req component binds for both labels", () => {
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com", "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  };
  const merchantSigned = signRequest(response(200, request), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status", "@method;req"],
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status", "@method;req"],
  });
  const reqLike = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(dual) }),
    BODY,
    { request },
  );
  // Same reference — the response signature binds this exact request.
  assert.equal(reqLike.request, request);
  const results = verifyAllLabels(reqLike, { now: NOW, keys: keys() });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("verifyAllLabels x fromNodeResponse: a dual-signed response without a status still fails fast in the adapter", () => {
  assert.throws(
    () =>
      fromNodeResponse(
        incomingResponse({
          statusCode: undefined,
          headers: wireHeaders(dualSigned()),
        }),
        BODY,
        { method: "GET", url: URL },
      ),
    /fromNodeResponse: res\.statusCode is missing/,
  );
});
