import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  verifyRequest,
  verifyResponse,
  type SignedHttpRequest,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1117: `SignOptions` only accepted an absolute `expires`
// (Unix seconds), so a caller wanting "valid for five minutes" had to
// compute `now + 300` by hand — and a fat-fingered sum mints a
// signature that is expired at birth or lives far longer than
// intended. `expiresInSec` is the relative form: the wire `expires`
// is exactly `created + expiresInSec`, resolved on the sign side, so
// verifiers need no change. `signResponse`, `addSignature`, and
// `addResponseSignature` inherit it through `signRequest` delegation.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";

function signedEd(opts: {
  created?: number;
  expires?: number;
  expiresInSec?: number;
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
      ...(opts.created !== undefined ? { created: opts.created } : {}),
      ...(opts.expires !== undefined ? { expires: opts.expires } : {}),
      ...(opts.expiresInSec !== undefined
        ? { expiresInSec: opts.expiresInSec }
        : {}),
    },
  );
  return { signed, publicKey };
}

/** Read a `;name=<int>` parameter out of the `signature-input` header. */
function wireParam(signed: SignedHttpRequest, name: string): number | undefined {
  const input = signed.headers["signature-input"];
  assert.ok(input !== undefined, "signature-input header is present");
  const m = new RegExp(`;${name}=(-?\\d+)`).exec(input);
  return m === null ? undefined : Number(m[1]);
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

// ---------- the relative expiry lands on the wire ----------

test("expiresInSec=300 mints wire expires exactly created+300", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expiresInSec: 300,
  });
  assert.equal(wireParam(signed, "created"), CREATED);
  assert.equal(wireParam(signed, "expires"), CREATED + 300);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.created, CREATED);
  assert.equal(res.expires, CREATED + 300);
});

test("explicit created is the base: created+1000 with expiresInSec=60 expires at created+1060", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED + 1000,
    expiresInSec: 60,
  });
  assert.equal(wireParam(signed, "expires"), CREATED + 1060);
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 1000 + 30,
  });
  assert.equal(res.ok, true);
  assert.equal(res.expires, CREATED + 1060);
});

test("default created: wire expires is exactly 300s after the minted created", () => {
  const { signed, publicKey } = signedEd({ expiresInSec: 300 });
  const created = wireParam(signed, "created");
  const expires = wireParam(signed, "expires");
  assert.ok(created !== undefined && expires !== undefined);
  assert.equal(expires - created, 300);
  const res = verifyRequest(signed, { key: publicKey, now: created + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.expires, created + 300);
});

// ---------- mutual exclusion and validation ----------

test("expires and expiresInSec together throw (mutually exclusive)", () => {
  assert.throws(
    () => signedEd({ created: CREATED, expires: CREATED + 300, expiresInSec: 300 }),
    /mutually exclusive/,
  );
});

test("invalid expiresInSec values fail fast: 0, negative, fractional, NaN, Infinity, non-number", () => {
  for (const bad of [0, -1, -300, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => signedEd({ created: CREATED, expiresInSec: bad }),
      /"expiresInSec" must be a positive integer/,
      `expiresInSec=${bad} must throw`,
    );
  }
  assert.throws(
    () =>
      signedEd({
        created: CREATED,
        expiresInSec: "300" as unknown as number,
      }),
    /"expiresInSec" must be a positive integer/,
  );
});

// ---------- expiry behaviour of a relative signature ----------

test("expired after the window: verify at created+101 reports EXPIRED", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expiresInSec: 100,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 101 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EXPIRED");
  assert.equal(res.expires, CREATED + 100);
});

test("boundary: now === expires still verifies", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expiresInSec: 100,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 100 });
  assert.equal(res.ok, true);
});

test("expiresInSec=1: one-second window verifies at created+1, EXPIRED at created+2", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expiresInSec: 1,
  });
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 1 }).ok,
    true,
  );
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 2 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "EXPIRED");
});

// ---------- defaults and the absolute path are untouched ----------

test("default (neither field): no expires on the wire, behaviour unchanged", () => {
  const { signed, publicKey } = signedEd({ created: CREATED });
  assert.equal(wireParam(signed, "expires"), undefined);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 3600 });
  assert.equal(res.ok, true);
  assert.equal(res.expires, undefined);
});

test("absolute expires path unchanged: expires=CREATED+300 still mints the same wire value", () => {
  const { signed, publicKey } = signedEd({
    created: CREATED,
    expires: CREATED + 300,
  });
  assert.equal(wireParam(signed, "expires"), CREATED + 300);
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.expires, CREATED + 300);
});

// ---------- inheritance through the delegation entry points ----------

test("addSignature inherits expiresInSec: both labels expire at created+300", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signRequest(
    { method: "POST", url: URL, headers: {}, body: '{"amount":100}' },
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      expiresInSec: 300,
      label: "merchant",
    },
  );
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    expiresInSec: 300,
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
  for (const r of results) {
    assert.equal(r.ok, true);
    assert.equal(r.expires, CREATED + 300);
  }
});

test("signResponse inherits expiresInSec", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed: SignedHttpResponse = signResponse(
    settlementResponse(JSON.stringify({ settled: true })),
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      expiresInSec: 300,
    },
  );
  assert.equal(wireParam(signed as unknown as SignedHttpRequest, "expires"), CREATED + 300);
  const res = verifyResponse(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.expires, CREATED + 300);
});

test("addResponseSignature inherits expiresInSec: both labels expire at created+300", () => {
  const merchant = generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");
  const merchantSigned = signResponse(
    settlementResponse(JSON.stringify({ settled: true })),
    {
      keyId: "merchant-key-1",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      expiresInSec: 300,
      label: "merchant",
    },
  );
  const dual = addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    expiresInSec: 300,
    label: "gateway",
  });
  const results = verifyAllResponseLabels(dual, {
    keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true);
    assert.equal(r.expires, CREATED + 300);
  }
});
