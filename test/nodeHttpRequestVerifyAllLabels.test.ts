import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addSignature,
  fromNodeRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type IncomingRequestLike,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #747: `test/nodeHttp.test.ts` never mentions
// `verifyAllLabels` — every case there walks the single-label
// `verifyRequest` path. The response side gained its symmetric
// coverage in #737 (`fromNodeResponse` x `verifyAllLabels`), but the
// request side had none: whether a server receiving a dual-signed
// webhook through `fromNodeRequest` honours each label's own key,
// and whether one label's failure is reported per label instead of
// failing the whole request, was unpinned.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented. `fromNodeRequest` already carries
// the wire signature headers verbatim (lowercasing names, joining
// multi-value fields exactly as `signRequest` does), and
// `verifyAllLabels` already reports per label.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const OTHER_BODY = JSON.stringify({ amount: 999, currency: "USD" });
const URL = "https://hooks.example.com/webhook?event=push";

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a client would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    Host: "hooks.example.com",
    "Content-Type": "application/json",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
    "Content-Digest": signed.headers["content-digest"] as string,
  };
}

/** A test double shaped like the fields of http.IncomingMessage. */
function incomingRequest(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/webhook?event=push",
    socket: { encrypted: true },
    ...overrides,
  };
}

/** A dual-signed request: merchant first, gateway appended. */
function dualSigned(body: string = BODY): SignedHttpRequest {
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

/** Combine two independently signed requests into one wire header set. */
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

function adaptedDual(signed: SignedHttpRequest, body: string = BODY): RequestLike {
  return fromNodeRequest(
    incomingRequest({ headers: wireHeaders(signed) }),
    body,
  );
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

test("verifyAllLabels x fromNodeRequest: a dual-signed request verifies both labels through the adapter", () => {
  const results = verifyAllLabels(adaptedDual(dualSigned()), {
    now: NOW,
    keys: keys(),
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("@method"),
      `${r.label} must cover @method`,
    );
    assert.ok(
      r.coveredComponents?.includes("content-digest"),
      `${r.label} must cover content-digest`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key");
  assert.equal(results[1].keyId, "gateway-key");
});

test("verifyAllLabels x fromNodeRequest: a real loopback server receives a dual-signed request and verifies both labels", async () => {
  const verified = new Promise<ReturnType<typeof verifyAllLabels>>(
    (resolve, reject) => {
      const server = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => {
          try {
            // A real `IncomingMessage`'s `Socket` type is wider than
            // the adapter's minimal `{ encrypted?: boolean }` socket
            // shape, so the boundary cast is needed to compile; at
            // runtime the adapter reads only `socket.encrypted`,
            // which a plain-HTTP loopback socket leaves falsy.
            const reqLike = fromNodeRequest(
              req as unknown as IncomingRequestLike,
              Buffer.concat(chunks),
            );
            assert.equal(reqLike.method, "POST");
            const results = verifyAllLabels(reqLike, {
              now: NOW,
              keys: keys(),
            });
            resolve(results);
          } catch (e) {
            reject(e);
          } finally {
            res.writeHead(200, { "content-type": "text/plain" });
            res.end("ok");
            server.close();
          }
        });
        req.on("error", reject);
      });
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        const url = `http://127.0.0.1:${port}/webhook?event=push`;
        const dual = dualSignedForUrl(url);
        const client = request(
          url,
          {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "signature-input": dual.headers["signature-input"] as string,
              signature: dual.headers["signature"] as string,
              "content-digest": dual.headers["content-digest"] as string,
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => undefined);
          },
        );
        client.on("error", reject);
        client.end(BODY);
      });
    },
  );
  const results = await verified;
  assert.deepEqual(
    results.map((r) => [r.label, r.ok, r.keyId]),
    [
      ["merchant", true, "merchant-key"],
      ["gateway", true, "gateway-key"],
    ],
  );

  function dualSignedForUrl(url: string): SignedHttpRequest {
    const merchantSigned = signRequest(
      {
        method: "POST",
        url,
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
    return addSignature(merchantSigned, {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
    });
  }
});

test("verifyAllLabels x fromNodeRequest: a tampered label signature fails alone, the other label still verifies", () => {
  const results = verifyAllLabels(
    adaptedDual(tamperLabelSignature(dualSigned(), "gateway")),
    { now: NOW, keys: keys() },
  );
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeRequest: a label signed over a different body fails alone, the other label still verifies", () => {
  // The wire carries a single `content-digest` header, so a post-hoc
  // edit cannot tamper only one label's digest (same pattern as the
  // #730 content-digest divergence case): the gateway label is
  // minted over a different body while the wire header and body stay
  // at the merchant's values. Only the gateway label must fail.
  const divergent = mergeSignatures(
    signRequest(
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
    ),
    signRequest(
      {
        method: "POST",
        url: URL,
        headers: { "content-type": "application/json" },
        body: OTHER_BODY,
      },
      {
        keyId: "gateway-key",
        alg: "ed25519",
        key: gateway.privateKey,
        created: CREATED,
        label: "gateway",
      },
    ),
  );
  const results = verifyAllLabels(adaptedDual(divergent), {
    now: NOW,
    keys: keys(),
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeRequest: each label is checked against its own key through the adapter", () => {
  const stranger = generateEd25519KeyPair();
  const results = verifyAllLabels(adaptedDual(dualSigned()), {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: stranger.publicKey },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x fromNodeRequest: single-label verifyRequest control path is unchanged", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "webhook-key", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const reqLike = fromNodeRequest(
    incomingRequest({ headers: wireHeaders(signed) }),
    BODY,
  );
  const single = verifyRequest(reqLike, { key: publicKey, now: NOW });
  assert.equal(single.ok, true);
  assert.equal(single.keyId, "webhook-key");
  const all = verifyAllLabels(reqLike, { key: publicKey, now: NOW });
  assert.equal(all.length, 1);
  assert.equal(all[0].label, "sig1");
  assert.equal(all[0].ok, true);
});
