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
  verifyRequest,
  type IncomingResponseLike,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #806: `test/nodeHttpResponse.test.ts` pins `fromNodeResponse`
// for `@status` and `;tr` responses, and `test/keyComponent.test.ts`
// pins `;key` member selection on hand-built `RequestLike` values —
// but `grep -rl fromNodeResponse test | xargs grep -l ';key'` was
// 0 files. Whether a real Node response, normalized by
// `fromNodeResponse`, still binds only the selected Dictionary member
// (and lets the unselected members move) had no backing. A
// gateway-signed settlement response whose per-member values travel
// as a Dictionary header — and, symmetrically, as a Dictionary
// trailer — is exactly that case.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeResponse` already carries
// headers and trailers through the same lowercasing/joining
// normalization the signer applies, and `;key` already resolves
// against whichever field source (`;tr` or not) the component names.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com/v1/charge";
// Dictionary fixture in the shape gateways sign member-wise: several
// members, one with parameters, one inner list, one bare (Boolean) key.
const DICT = "a=1, b=2;x=1;y=2, c=(a b c), d";
const TRAILER_DICT = "p=10, q=20;r=3, s=(x y)";

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

/** A response signed over `@status` plus the `b` member of `x-dict`. */
function signedDictResponse(
  privateKey: ReturnType<typeof generateEd25519KeyPair>["privateKey"],
  label?: string,
): SignedHttpRequest {
  return signRequest(
    {
      method: "GET",
      url: URL,
      headers: { "x-dict": DICT },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      ...(label !== undefined ? { label } : {}),
      coveredComponents: ["@status", 'x-dict;key="b"'],
    },
  );
}

/** Adapt a signed response through `fromNodeResponse`, as a client would. */
function adapted(
  signed: SignedHttpRequest,
  dictValue: string = DICT,
  extra: Partial<IncomingResponseLike> = {},
): RequestLike {
  return fromNodeResponse(
    incomingResponse({
      headers: { ...wireHeaders(signed), "x-dict": dictValue },
      ...extra,
    }),
    BODY,
    { method: "GET", url: URL },
  );
}

test("fromNodeResponse x ;key: a signed dictionary header verifies through the adapter", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const reqLike = adapted(signedDictResponse(privateKey));
  assert.equal(reqLike.status, 200);
  assert.equal(reqLike.headers["x-dict"], DICT);
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(result.coveredComponents?.includes("@status"));
  assert.ok(result.coveredComponents?.includes('x-dict;key="b"'));
});

test("fromNodeResponse x ;key: changing the selected member value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const reqLike = adapted(
    signedDictResponse(privateKey),
    "a=1, b=3;x=1;y=2, c=(a b c), d",
  );
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("fromNodeResponse x ;key: changing a parameter of the selected member fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const reqLike = adapted(
    signedDictResponse(privateKey),
    "a=1, b=2;x=9;y=2, c=(a b c), d",
  );
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});

test("fromNodeResponse x ;key: changing only unselected members still verifies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const reqLike = adapted(
    signedDictResponse(privateKey),
    "a=99, b=2;x=1;y=2, c=(x y), d=?0",
  );
  // This is the entire point of ;key: only member b is bound, so the
  // adapter must not let unrelated member edits break the signature.
  assert.equal(
    verifyRequest(reqLike, { key: publicKey, now: NOW }).ok,
    true,
  );
});

test("fromNodeResponse x ;key: deleting the selected member fails closed (signature base cannot be rebuilt)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const reqLike = adapted(signedDictResponse(privateKey), "a=1, c=(a b c), d");
  const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(result.reason ?? "", /dictionary member "b" is not present/);
});

test("verifyAllLabels x fromNodeResponse x ;key: a dual-signed response verifies both labels through the adapter", () => {
  const dict = generateEd25519KeyPair();
  const plain = generateEd25519KeyPair();
  const first = signedDictResponse(dict.privateKey, "dict");
  const signed = addSignature(first, {
    keyId: "plain-key",
    alg: "ed25519",
    key: plain.privateKey,
    created: CREATED,
    label: "plain",
    coveredComponents: ["@status"],
  });
  const reqLike = adapted(signed);
  const results = verifyAllLabels(reqLike, {
    now: NOW,
    keys: { dict: dict.publicKey, plain: plain.publicKey },
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["dict", "plain"],
  );
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("verifyAllLabels x fromNodeResponse x ;key: tampering the selected member fails only the ;key label", () => {
  const dict = generateEd25519KeyPair();
  const plain = generateEd25519KeyPair();
  const first = signedDictResponse(dict.privateKey, "dict");
  const signed = addSignature(first, {
    keyId: "plain-key",
    alg: "ed25519",
    key: plain.privateKey,
    created: CREATED,
    label: "plain",
    coveredComponents: ["@status"],
  });
  const reqLike = adapted(signed, "a=1, b=7;x=1;y=2, c=(a b c), d");
  const results = verifyAllLabels(reqLike, {
    now: NOW,
    keys: { dict: dict.publicKey, plain: plain.publicKey },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "dict");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
  assert.equal(results[1].label, "plain");
  assert.equal(results[1].ok, true, JSON.stringify(results[1]));
});

test("fromNodeResponse x ;tr;key: a dictionary trailer member verifies through the adapter", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      trailers: { "x-tdict": TRAILER_DICT },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", 'x-tdict;tr;key="q"'],
    },
  );
  const reqLike = fromNodeResponse(
    incomingResponse({
      headers: wireHeaders(signed),
      trailers: { "x-tdict": TRAILER_DICT },
    }),
    BODY,
    { method: "GET", url: URL },
  );
  assert.deepEqual(reqLike.trailers, { "x-tdict": TRAILER_DICT });
  assert.equal(
    verifyRequest(reqLike, { key: publicKey, now: NOW }).ok,
    true,
  );
});

test("fromNodeResponse x ;tr;key: tampering the trailer member fails, moving unselected trailer members passes", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: URL,
      headers: {},
      trailers: { "x-tdict": TRAILER_DICT },
      body: BODY,
      status: 200,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@status", 'x-tdict;tr;key="q"'],
    },
  );
  const adaptedTrailer = (value: string) =>
    fromNodeResponse(
      incomingResponse({
        headers: wireHeaders(signed),
        trailers: { "x-tdict": value },
      }),
      BODY,
      { method: "GET", url: URL },
    );
  const tampered = adaptedTrailer("p=10, q=21;r=3, s=(x y)");
  assert.equal(
    verifyRequest(tampered, { key: publicKey, now: NOW }).code,
    "SIGNATURE_MISMATCH",
  );
  const moved = adaptedTrailer("p=11, q=20;r=3, s=(z)");
  assert.equal(
    verifyRequest(moved, { key: publicKey, now: NOW }).ok,
    true,
  );
});

test("loopback: a real http server signs a ;key dictionary header; http.get client verifies end-to-end", async () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const server = createServer((req, res) => {
    const signed = signRequest(
      {
        method: "GET",
        url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/settle`,
        headers: { "x-dict": DICT },
        body: BODY,
        status: 200,
      },
      {
        keyId: "gateway-key",
        alg: "ed25519",
        key: privateKey,
        created: CREATED,
        coveredComponents: ["@status", 'x-dict;key="b"'],
      },
    );
    res.writeHead(200, {
      "content-type": "application/json",
      "x-dict": DICT,
      "signature-input": signed.headers["signature-input"] as string,
      signature: signed.headers["signature"] as string,
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
            assert.equal(reqLike.headers["x-dict"], DICT);
            const result = verifyRequest(reqLike, { key: publicKey, now: NOW });
            assert.equal(result.ok, true, JSON.stringify(result));
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
