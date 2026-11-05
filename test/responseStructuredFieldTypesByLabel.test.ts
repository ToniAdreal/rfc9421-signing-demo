import test from "node:test";
import assert from "node:assert/strict";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addResponseSignature,
  fromNodeResponse,
  generateEd25519KeyPair,
  signResponse,
  verifyAllLabels,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpResponse,
  type StructuredFieldType,
  type VerifyAllOptions,
} from "../src/index.js";

// Backlog #911: `VerifyAllOptions.structuredFieldTypesByLabel`
// (`src/verify.ts:1680`) had no response-side coverage at all —
// `grep -rl "structuredFieldTypesByLabel"
// test/nodeHttpResponse*.test.ts test/response*.test.ts` was empty.
// The request-side twin (test/structuredFieldTypesByLabel.test.ts,
// backlog #886) pins the per-label semantics on requests, and the
// single-label response registry (test/responseStructuredFieldTypes.
// test.ts, backlog #900) pins the global registry on responses, but
// neither proves the combination: a dual-signed settlement response
// adapted with `fromNodeResponse`, where the merchant label treats a
// shared header as one Structured Field type and the gateway label
// treats the same header differently. That matters because the
// response signature covers a different component set (`@status` plus
// named response headers, never `@method`/`@authority`/`@path`), so
// the request-side proof cannot stand in for the response path.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `signResponse` forwards the registry
// to `signRequest`, `addResponseSignature` appends the second label
// over the same content, `fromNodeResponse` carries the wire headers
// verbatim, and `verifyAllLabels` resolves each label's registry
// (per-label, else global, else the trial order) before delegating
// to `verifyRequest`.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";
const LIST_SCOPES = '"read", "write"';
const DICT_SCOPES = "scope=read, level=2";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

const KEYS = {
  merchant: merchant.publicKey,
  gateway: gateway.publicKey,
};

/** A test double shaped like the fields of a client's IncomingMessage. */
function incomingResponse(
  overrides: Partial<IncomingResponseLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingResponseLike {
  return { statusCode: 200, ...overrides };
}

/**
 * A dual-signed settlement response: the merchant signs first, the
 * gateway appends its label over the same status, headers, and body.
 * Each party may pin its own `;sf` registry for `x-scopes`.
 */
function dualSignedResponse(
  scopesValue: string,
  merchantRegistry?: Record<string, StructuredFieldType>,
  gatewayRegistry?: Record<string, StructuredFieldType>,
): SignedHttpResponse {
  const merchantSigned = signResponse(
    { status: 200, headers: { "x-scopes": scopesValue }, body: BODY },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
      coveredComponents: ["@status", "x-scopes;sf"],
      ...(merchantRegistry !== undefined
        ? { structuredFieldTypes: merchantRegistry }
        : {}),
    },
  );
  return addResponseSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
    coveredComponents: ["@status", "x-scopes;sf"],
    ...(gatewayRegistry !== undefined
      ? { structuredFieldTypes: gatewayRegistry }
      : {}),
  });
}

function adapted(signed: SignedHttpResponse): RequestLike {
  return fromNodeResponse(
    incomingResponse({ headers: { ...signed.headers } }),
    BODY,
    { method: "GET", url: URL },
  );
}

function verify(
  signed: SignedHttpResponse,
  extra: Omit<VerifyAllOptions, "now" | "keys" | "requiredComponents">,
) {
  return verifyAllLabels(adapted(signed), {
    now: NOW,
    keys: KEYS,
    requiredComponents: ["@status"],
    ...extra,
  });
}

test("response structuredFieldTypesByLabel: merchant list registry and gateway default both pass", () => {
  // The List-shaped value parses as a List under the merchant's
  // registry and under the gateway's default trial order (the
  // Dictionary trial fails on the quoted bare items first), so both
  // bases are the same canonical List.
  const results = verify(
    dualSignedResponse(LIST_SCOPES, { "x-scopes": "list" }),
    { structuredFieldTypesByLabel: { merchant: { "x-scopes": "list" } } },
  );
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => [r.label, r.ok, r.keyId]),
    [
      ["merchant", true, "merchant-key"],
      ["gateway", true, "gateway-key"],
    ],
  );
  for (const r of results) {
    assert.ok(
      r.coveredComponents?.includes("x-scopes;sf"),
      `${r.label} must cover x-scopes;sf`,
    );
  }
});

test("response structuredFieldTypesByLabel: merchant dictionary registry and gateway default both pass", () => {
  const results = verify(
    dualSignedResponse(DICT_SCOPES, { "x-scopes": "dictionary" }),
    {
      structuredFieldTypesByLabel: {
        merchant: { "x-scopes": "dictionary" },
      },
    },
  );
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("response structuredFieldTypesByLabel: a registry that disagrees with the wire type fails only that label", () => {
  // Both labels minted without a registry over the Dictionary-shaped
  // value (the trial order builds both bases as a Dictionary).
  // Verifying the merchant under a List registry cannot rebuild its
  // base, while the gateway keeps the trial order and passes.
  const results = verify(dualSignedResponse(DICT_SCOPES), {
    structuredFieldTypesByLabel: { merchant: { "x-scopes": "list" } },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("response structuredFieldTypesByLabel: unmapped label falls back to the global registry", () => {
  const results = verify(dualSignedResponse(DICT_SCOPES), {
    structuredFieldTypes: { "x-scopes": "list" },
    structuredFieldTypesByLabel: {
      merchant: { "x-scopes": "dictionary" },
    },
  });
  // The merchant's own registry replaces the global List pin, so it
  // passes; the gateway is not in the map, so the global List pin
  // applies to it and its base cannot be rebuilt.
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("response structuredFieldTypesByLabel: mapping a label to an empty registry clears the global pins for it", () => {
  const results = verify(dualSignedResponse(DICT_SCOPES), {
    structuredFieldTypes: { "x-scopes": "list" },
    structuredFieldTypesByLabel: { merchant: {} },
  });
  // Merchant: an empty registry means the trial order, which parses
  // the Dictionary-shaped value as a Dictionary — the same base the
  // signer produced. Gateway: the global List pin still applies.
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("response structuredFieldTypesByLabel: a malformed map throws a configuration error", () => {
  const dual = dualSignedResponse(DICT_SCOPES);
  for (const bad of [[], null, "merchant"] as unknown[]) {
    assert.throws(
      () =>
        verify(dual, {
          structuredFieldTypesByLabel:
            bad as Record<string, Record<string, StructuredFieldType>>,
        }),
      /structuredFieldTypesByLabel.*must be a label→registry object/,
    );
  }
});

test("response structuredFieldTypesByLabel: a malformed per-label registry throws naming the label", () => {
  const dual = dualSignedResponse(DICT_SCOPES);
  assert.throws(
    () =>
      verify(dual, {
        structuredFieldTypesByLabel: {
          merchant: { "x-scopes": "set" } as unknown as Record<
            string,
            StructuredFieldType
          >,
        },
      }),
    /structuredFieldTypesByLabel\["merchant"\].*is invalid/,
  );
  assert.throws(
    () =>
      verify(dual, {
        structuredFieldTypesByLabel: {
          merchant: { "": "list" },
        },
      }),
    /field names must be non-empty strings/,
  );
});

test("response structuredFieldTypesByLabel: a real loopback server dual-signs a response; http.get client verifies both labels with per-label registries", async () => {
  const server = createServer((req, res) => {
    const dual = dualSignedResponse(LIST_SCOPES, { "x-scopes": "list" });
    res.writeHead(200, {
      "content-type": "application/json",
      "x-scopes": LIST_SCOPES,
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
              keys: KEYS,
              requiredComponents: ["@status"],
              structuredFieldTypesByLabel: {
                merchant: { "x-scopes": "list" },
              },
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
