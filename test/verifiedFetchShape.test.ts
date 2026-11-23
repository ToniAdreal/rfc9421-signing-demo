import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signResponse,
  verifiedFetch,
  type VerifiedFetchResponse,
} from "../src/index.js";

// Backlog #1355: `verifiedFetch` guarded `opts` / `opts.sign` /
// `opts.verify` with named errors, but `input: string | URL` had no
// guard — a `null` input escaped as a bare `TypeError` from
// `input.toString()` in the request build. The input guard must fire
// first (before the `opts` guards), as a plain named `Error`, and
// never reach the network. These cases pin the guard shapes, the
// guard ordering, and the unchanged legal round-trips (string and
// `URL` inputs over an injected fetchImpl, zero network).

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ_BODY = JSON.stringify({ amount: 100, currency: "USD" });
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });

const clientKeys = generateEd25519KeyPair();
const gatewayKeys = generateEd25519KeyPair();

function validOpts(fetchImpl?: (url: string) => Promise<VerifiedFetchResponse>) {
  return {
    sign: {
      keyId: "client-key",
      alg: "ed25519" as const,
      key: clientKeys.privateKey,
      created: CREATED,
    },
    verify: { key: gatewayKeys.publicKey, now: NOW },
    ...(fetchImpl !== undefined ? { fetchImpl } : {}),
  };
}

function stubFetchImpl(): (url: string) => Promise<VerifiedFetchResponse> {
  const signed = signResponse(
    {
      status: 200,
      headers: { "content-type": "application/json" },
      body: RES_BODY,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gatewayKeys.privateKey,
      created: CREATED,
    },
  );
  return async (
    _url: string,
  ): Promise<VerifiedFetchResponse> => ({
    status: 200,
    headers: new Headers(signed.headers),
    arrayBuffer: async () => {
      const buf = Buffer.from(RES_BODY);
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
    body: null,
  });
}

test("verifiedFetch: null input throws a named Error, not a bare TypeError", async () => {
  let calls = 0;
  const fetchImpl = async (): Promise<VerifiedFetchResponse> => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  await assert.rejects(
    verifiedFetch(
      null as unknown as string,
      undefined,
      validOpts(fetchImpl),
    ),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        "verifiedFetch: input must be a string or URL, got null",
      );
      return true;
    },
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: non-string non-URL inputs throw the named input error", async () => {
  const badInputs: Array<{ input: unknown; got: string }> = [
    { input: 42, got: "number" },
    { input: {}, got: "object" },
    { input: undefined, got: "undefined" },
    { input: true, got: "boolean" },
    { input: Symbol("x"), got: "symbol" },
  ];
  for (const { input, got } of badInputs) {
    await assert.rejects(
      verifiedFetch(
        input as unknown as string,
        undefined,
        validOpts(),
      ),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof TypeError));
        assert.equal(
          (err as Error).message,
          `verifiedFetch: input must be a string or URL, got ${got}`,
        );
        return true;
      },
    );
  }
});

test("verifiedFetch: input guard fires before the opts guard", async () => {
  await assert.rejects(
    verifiedFetch(
      null as unknown as string,
      undefined,
      null as unknown as Parameters<typeof verifiedFetch>[2],
    ),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        "verifiedFetch: input must be a string or URL, got null",
      );
      return true;
    },
  );
});

test("verifiedFetch: existing opts/sign/verify named errors are unchanged", async () => {
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      undefined,
      null as unknown as Parameters<typeof verifiedFetch>[2],
    ),
    /verifiedFetch: opts must be an object, got null/,
  );
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      undefined,
      {
        sign: null,
        verify: { key: gatewayKeys.publicKey, now: NOW },
      } as unknown as Parameters<typeof verifiedFetch>[2],
    ),
    /verifiedFetch: opts\.sign \(SignOptions\) is required, got null/,
  );
  await assert.rejects(
    verifiedFetch(
      "https://gateway.example/v1/settlement",
      undefined,
      {
        sign: {
          keyId: "client-key",
          alg: "ed25519",
          key: clientKeys.privateKey,
          created: CREATED,
        },
        verify: null,
      } as unknown as Parameters<typeof verifiedFetch>[2],
    ),
    /verifiedFetch: opts\.verify \(VerifyResponseOptions\) is required, got null/,
  );
});

test("verifiedFetch: legal string input round-trips over an injected fetchImpl", async () => {
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "POST", body: REQ_BODY },
    validOpts(stubFetchImpl()),
  );
  assert.equal(result.body, RES_BODY);
  assert.equal(result.verifyResult.ok, true);
  assert.equal(result.verifyResult.keyId, "gateway-key");
});

test("verifiedFetch: legal URL input round-trips over an injected fetchImpl", async () => {
  let fetchedUrl: string | undefined;
  const fetchImpl = stubFetchImpl();
  const result = await verifiedFetch(
    new URL("https://gateway.example/v1/settlement"),
    { method: "POST", body: REQ_BODY },
    validOpts(async (url: string) => {
      fetchedUrl = url;
      return fetchImpl(url);
    }),
  );
  assert.equal(fetchedUrl, "https://gateway.example/v1/settlement");
  assert.equal(result.body, RES_BODY);
  assert.equal(result.verifyResult.ok, true);
});
