import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  ReplayCache,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyRequest,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1173: `SignOptions.nonce` only took effect when the caller
// supplied a value, so a client that wanted replay detection had to
// mint a fresh unique nonce per signature by hand — and a caller that
// reused one fixed nonce (e.g. a demo constant) silently made the
// `ReplayCache` useless. `autoNonce: true` has the signer generate a
// fresh UUID v4 (`crypto.randomUUID()`) per signature instead, written
// into `signature-input` exactly like an explicit nonce. The two ways
// of naming the nonce are mutually exclusive.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";

/** UUID v4, lowercase, as emitted by `crypto.randomUUID()`. */
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function signedEd(opts: {
  autoNonce?: boolean;
  nonce?: string;
  created?: number;
}): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: opts.created ?? CREATED,
      ...(opts.autoNonce !== undefined
        ? { autoNonce: opts.autoNonce }
        : {}),
      ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    },
  );
  return { signed, publicKey };
}

/** Read the `nonce="..."` parameter out of the `signature-input` header. */
function wireNonce(signed: SignedHttpRequest): string | undefined {
  const input = signed.headers["signature-input"];
  assert.ok(input !== undefined, "signature-input header is present");
  const m = /;nonce="([^"]*)"/.exec(input);
  return m === null ? undefined : m[1];
}

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

// ---------- generation: fresh, UUID v4, echoed on verify ----------

test("autoNonce signs twice with different UUID v4 nonces, each echoed by VerifyResult.nonce", () => {
  const first = signedEd({ autoNonce: true });
  const second = signedEd({ autoNonce: true });
  const nonce1 = wireNonce(first.signed);
  const nonce2 = wireNonce(second.signed);
  assert.ok(nonce1 !== undefined && UUID_V4_RE.test(nonce1));
  assert.ok(nonce2 !== undefined && UUID_V4_RE.test(nonce2));
  assert.notEqual(nonce1, nonce2);

  const res1 = verifyRequest(first.signed, { key: first.publicKey, now: NOW });
  assert.equal(res1.ok, true);
  assert.equal(res1.nonce, nonce1);
  const res2 = verifyRequest(second.signed, {
    key: second.publicKey,
    now: NOW,
  });
  assert.equal(res2.ok, true);
  assert.equal(res2.nonce, nonce2);
});

test("autoNonce nonce is a UUID v4 on the wire", () => {
  const { signed, publicKey } = signedEd({ autoNonce: true });
  const nonce = wireNonce(signed);
  assert.ok(nonce !== undefined, "a nonce is emitted");
  assert.match(nonce, UUID_V4_RE);
  assert.equal(nonce.length, 36);
  assert.equal(verifyRequest(signed, { key: publicKey, now: NOW }).ok, true);
});

// ---------- mutual exclusion and the off paths ----------

test("autoNonce: true with an explicit nonce throws (mutually exclusive)", () => {
  assert.throws(
    () => signedEd({ autoNonce: true, nonce: "caller-nonce-1" }),
    /"nonce" and "autoNonce" are mutually exclusive/,
  );
});

test("autoNonce: true with an empty-string nonce still reports the conflict, not the empty value", () => {
  assert.throws(
    () => signedEd({ autoNonce: true, nonce: "" }),
    /"nonce" and "autoNonce" are mutually exclusive/,
  );
});

test("autoNonce: false signs without a nonce", () => {
  const { signed, publicKey } = signedEd({ autoNonce: false });
  assert.equal(wireNonce(signed), undefined);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, undefined);
});

test("default (no autoNonce): no nonce on the wire, behaviour unchanged", () => {
  const { signed, publicKey } = signedEd({});
  assert.equal(wireNonce(signed), undefined);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, undefined);
});

test("explicit nonce behaviour unchanged: the caller's value is emitted and echoed", () => {
  const { signed, publicKey } = signedEd({ nonce: "fixed-nonce-1" });
  assert.equal(wireNonce(signed), "fixed-nonce-1");
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "fixed-nonce-1");
});

// ---------- the generated nonce is real replay protection ----------

test("autoNonce-signed request replays: second verify with the same ReplayCache fails NONCE_REPLAY", () => {
  const { signed, publicKey } = signedEd({ autoNonce: true });
  const nonce = wireNonce(signed);
  assert.ok(nonce !== undefined);
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const first = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(first.ok, true);
  assert.equal(first.nonce, nonce);
  assert.equal(cache.size, 1);

  const second = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
  assert.equal(second.nonce, nonce);
  assert.equal(cache.size, 1);
});

test("the generated nonce is covered by the signature: tampering the wire nonce fails SIGNATURE_MISMATCH", () => {
  const { signed, publicKey } = signedEd({ autoNonce: true });
  const nonce = wireNonce(signed);
  assert.ok(nonce !== undefined);
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        nonce,
        "00000000-0000-4000-8000-000000000000",
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: NOW });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

// ---------- inheritance through the delegation entry points ----------

test("signResponse inherits autoNonce: the response nonce is a UUID v4 echoed on verify", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed: SignedHttpResponse = signResponse(
    settlementResponse(JSON.stringify({ settled: true })),
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      autoNonce: true,
    },
  );
  const nonce = wireNonce(signed as unknown as SignedHttpRequest);
  assert.ok(nonce !== undefined && UUID_V4_RE.test(nonce));
  const res = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, nonce);
});

test("addSignature inherits autoNonce: the appended label gets its own fresh nonce", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signRequest(
    { method: "POST", url: URL, headers: {}, body: '{"amount":100}' },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      nonce: "merchant-nonce-1",
      label: "merchant",
    },
  );
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    autoNonce: true,
    label: "gateway",
  });
  const results = verifyAllLabels(dual, {
    key: merchant.publicKey,
    now: NOW,
    keys: { gateway: gatewaySecret },
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  const [merchantRes, gatewayRes] = results;
  assert.equal(merchantRes.ok, true);
  assert.equal(merchantRes.nonce, "merchant-nonce-1");
  assert.equal(gatewayRes.ok, true);
  assert.ok(
    gatewayRes.nonce !== undefined && UUID_V4_RE.test(gatewayRes.nonce),
  );
  assert.notEqual(gatewayRes.nonce, "merchant-nonce-1");
});

// ---------- the input request is not mutated ----------

test("autoNonce does not mutate the input request", () => {
  const { privateKey } = generateEd25519KeyPair();
  const req = { method: "POST", url: URL, headers: {}, body: '{"amount":100}' };
  signRequest(req, {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    autoNonce: true,
  });
  assert.deepEqual(req.headers, {});
});
