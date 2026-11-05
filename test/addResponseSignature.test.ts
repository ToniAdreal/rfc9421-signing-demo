import test from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addResponseSignature,
  fromNodeResponse,
  generateEd25519KeyPair,
  listSignatureLabels,
  secretKey,
  signResponse,
  verifyAllLabels,
  verifyResponse,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #904: the request side has had `addSignature` since the
// multi-party flow landed, but the response side had no counterpart —
// a gateway appending its own label to a merchant-signed settlement
// response had to hand-merge dictionaries, with no guard against a
// label collision or a content-digest algorithm mismatch.
// `addResponseSignature` mirrors `addSignature` exactly: the second
// base is built over the unsigned response, the label must be unique,
// and the wire content-digest algorithm wins over
// `opts.contentDigestAlg`.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();
const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

function settlementResponse(body?: string): {
  status: number;
  headers: Record<string, string>;
  body?: string;
} {
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body } : {}),
  };
}

/**
 * The canonical multi-party flow: the merchant signs the settlement
 * response with its ed25519 key, then the payment gateway appends its
 * own hmac signature. Both labels verify independently.
 */
function merchantThenGateway(): {
  dual: SignedHttpResponse;
  merchantSigned: SignedHttpResponse;
} {
  const merchantSigned = signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
  return { dual, merchantSigned };
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gatewaySecret };
}

/** Wire-style headers carrying a signature, as a server would send them. */
function wireHeaders(
  signed: SignedHttpResponse,
): Record<string, string | undefined> {
  return {
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
    ...(signed.headers["content-digest"] !== undefined
      ? { "Content-Digest": signed.headers["content-digest"] as string }
      : {}),
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

function adaptedDual(signed: SignedHttpResponse): RequestLike {
  return fromNodeResponse(incomingResponse({ headers: wireHeaders(signed) }), BODY, {
    method: "GET",
    url: URL,
  });
}

test("merchant (ed25519) + gateway (hmac) double label both verify via verifyResponse per label", () => {
  const { dual } = merchantThenGateway();
  const merchantResult = verifyResponse(dual, {
    key: merchant.publicKey,
    now: NOW,
    label: "merchant",
  });
  assert.equal(merchantResult.ok, true, JSON.stringify(merchantResult));
  assert.equal(merchantResult.label, "merchant");
  assert.equal(merchantResult.alg, "ed25519");
  assert.equal(merchantResult.keyId, "merchant-key-1");
  assert.ok(merchantResult.coveredComponents?.includes("@status"));
  assert.ok(merchantResult.coveredComponents?.includes("content-digest"));

  const gatewayResult = verifyResponse(dual, {
    key: gatewaySecret,
    now: NOW,
    label: "gateway",
  });
  assert.equal(gatewayResult.ok, true, JSON.stringify(gatewayResult));
  assert.equal(gatewayResult.label, "gateway");
  assert.equal(gatewayResult.alg, "hmac-sha256");
  assert.equal(gatewayResult.keyId, "gateway-key-7");
});

test("verifyAllLabels x fromNodeResponse: a dual-signed response verifies both labels through the adapter", () => {
  const { dual } = merchantThenGateway();
  const results = verifyAllLabels(adaptedDual(dual), {
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
    assert.ok(r.coveredComponents?.includes("@status"));
  }
  assert.equal(results[0].keyId, "merchant-key-1");
  assert.equal(results[1].keyId, "gateway-key-7");
});

test("verifyAllLabels x fromNodeResponse: a real loopback server dual-signs a response; http.get client verifies both labels", async () => {
  const server = createServer((_req, res) => {
    const merchantSigned = signResponse(settlementResponse(BODY), {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    });
    const dual = addResponseSignature(merchantSigned, {
      keyId: "gateway-key-7",
      alg: "hmac-sha256",
      key: gatewaySecret,
      created: CREATED,
      label: "gateway",
    });
    res.writeHead(200, {
      "content-type": "application/json",
      "signature-input": dual.headers["signature-input"] as string,
      signature: dual.headers["signature"] as string,
      "content-digest": dual.headers["content-digest"] as string,
    });
    res.end(BODY);
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/settle`;
      get(url, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          try {
            const reqLike = fromNodeResponse(res, Buffer.concat(chunks), {
              method: "GET",
              url,
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
                ["merchant", true, "merchant-key-1"],
                ["gateway", true, "gateway-key-7"],
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

test("appending to an unsigned response throws a clear error", () => {
  assert.throws(
    () =>
      addResponseSignature(settlementResponse(BODY) as SignedHttpResponse, {
        keyId: "k",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
        label: "second",
      }),
    /addResponseSignature: the response has no signature-input\/signature headers/,
  );
});

test("a duplicate label is rejected", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "k",
    alg: "ed25519",
    key: generateEd25519KeyPair().privateKey,
    created: CREATED,
  }); // default label "sig1"
  assert.throws(
    () =>
      addResponseSignature(signed, {
        keyId: "k2",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
      }),
    /addResponseSignature: label "sig1" is already present/,
  );
});

test("an empty label is rejected", () => {
  const { dual } = merchantThenGateway();
  assert.throws(
    () =>
      addResponseSignature(dual, {
        keyId: "k",
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
        label: "",
      }),
    /addResponseSignature: "label" must be a non-empty string/,
  );
});

test("a contradictory content-digest algorithm is rejected; a matching one is pinned to the wire value", () => {
  const merchantSigned = signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    contentDigestAlg: "sha-256",
  });
  assert.ok(merchantSigned.headers["content-digest"]?.startsWith("sha-256="));
  assert.throws(
    () =>
      addResponseSignature(merchantSigned, {
        keyId: "gateway-key-7",
        alg: "hmac-sha256",
        key: gatewaySecret,
        created: CREATED,
        label: "gateway",
        contentDigestAlg: "sha-512",
      }),
    /addResponseSignature: the response already carries a content-digest header emitted with "sha-256"/,
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    contentDigestAlg: "sha-256",
  });
  assert.ok(dual.headers["content-digest"]?.startsWith("sha-256="));
  assert.equal(
    dual.headers["content-digest"],
    merchantSigned.headers["content-digest"],
  );
});

test("a content-digest algorithm this library cannot emit is rejected", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "k",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  const tampered: SignedHttpResponse = {
    ...signed,
    headers: { ...signed.headers, "content-digest": "sha-999=:AAAA:" },
  };
  assert.throws(
    () =>
      addResponseSignature(tampered, {
        keyId: "k2",
        alg: "hmac-sha256",
        key: gatewaySecret,
        created: CREATED,
        label: "gateway",
      }),
    /addResponseSignature: the response carries a content-digest header with a digest algorithm this library cannot emit/,
  );
});

test("a tampered gateway signature does not affect the merchant label", () => {
  const { dual } = merchantThenGateway();
  const tampered: SignedHttpResponse = {
    ...dual,
    headers: {
      ...dual.headers,
      signature: dual.headers["signature"].replace(
        /((?:^|,)\s*gateway\s*=:)([A-Za-z0-9+/])/,
        (_m, prefix: string, p1: string) =>
          `${prefix}${p1 === "A" ? "B" : "A"}`,
      ),
    },
  };
  const results = verifyAllLabels(adaptedDual(tampered), {
    now: NOW,
    keys: keys(),
    requiredComponents: ["@status"],
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("@status-covered double signing round-trips without a body; tampering the status fails both labels", () => {
  const merchantSigned = signResponse(settlementResponse(), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status"],
  });
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status"],
  });
  for (const [label, key] of [
    ["merchant", merchant.publicKey],
    ["gateway", gatewaySecret],
  ] as const) {
    const result = verifyResponse(dual, { key, now: NOW, label });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(result.coveredComponents, ["@status"]);
  }
  const tampered: SignedHttpResponse = { ...dual, status: 500 };
  for (const [label, key] of [
    ["merchant", merchant.publicKey],
    ["gateway", gatewaySecret],
  ] as const) {
    const result = verifyResponse(tampered, { key, now: NOW, label });
    assert.equal(result.ok, false);
    assert.equal(result.code, "SIGNATURE_MISMATCH");
  }
});

test("the input response is not mutated", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "k",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "first",
  });
  const before = JSON.stringify(signed.headers);
  const dual = addResponseSignature(signed, {
    keyId: "k2",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "second",
  });
  assert.equal(JSON.stringify(signed.headers), before);
  assert.notEqual(dual.headers, signed.headers);
  assert.equal(dual.body, signed.body);
  assert.equal(dual.status, signed.status);
});

test("wire shape: labels in order, content-digest stable", () => {
  const { dual, merchantSigned } = merchantThenGateway();
  assert.deepEqual(listSignatureLabels(dual.headers["signature-input"]), [
    "merchant",
    "gateway",
  ]);
  assert.equal(
    dual.headers["content-digest"],
    merchantSigned.headers["content-digest"],
  );
  // The appended signature's own covered list, not a merge.
  assert.deepEqual(dual.coveredComponents, ["@status", "content-digest"]);
});

test(";req binding: both response labels bind the triggering request, and a swapped request fails both", () => {
  const request: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { host: "api.example.com", "content-type": "application/json" },
    body: JSON.stringify({ amount: 100 }),
  };
  const merchantSigned = signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
    coveredComponents: ["@status", "@method;req"],
    request,
  });
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status", "@method;req"],
    request,
  });
  const reqLike = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(dual) }),
    BODY,
    { request },
  );
  assert.equal(reqLike.request, request);
  const results = verifyAllLabels(reqLike, { now: NOW, keys: keys() });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );

  const swapped: RequestLike = { ...request, method: "GET" };
  const swappedLike = fromNodeResponse(
    incomingResponse({ headers: wireHeaders(dual) }),
    BODY,
    { request: swapped },
  );
  const swappedResults = verifyAllLabels(swappedLike, {
    now: NOW,
    keys: keys(),
  });
  assert.deepEqual(
    swappedResults.map((r) => [r.label, r.ok, r.code]),
    [
      ["merchant", false, "SIGNATURE_MISMATCH"],
      ["gateway", false, "SIGNATURE_MISMATCH"],
    ],
  );
});
