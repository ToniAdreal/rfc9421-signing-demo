import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// Merchant: one fixed ed25519 key, short acceptance window.
// Gateway: one HMAC secret, long acceptance window. Both signatures are
// minted at the same instant, so a single global window cannot express
// "merchant stale, gateway fresh" — the per-label map is what splits them.
const CREATED = 1700000000;
const NOW = CREATED + 3600; // both signatures are exactly 1 hour old
const COVERED = ["@method", "@authority", "@path", "content-digest"];

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: '{"amount":100}',
  };
}

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

const merchant = generateEd25519KeyPair();
const GATEWAY = secretKey(randomBytes(32));

function signMerchant(): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "merchant",
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function signGateway(): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label: "gateway",
    keyId: "gateway-key-9",
    alg: "hmac-sha256",
    key: GATEWAY,
    created: CREATED,
    coveredComponents: COVERED,
  });
}

function dual(): SignedHttpRequest {
  return mergeSignatures(signMerchant(), signGateway());
}

function keys() {
  return { merchant: merchant.publicKey, gateway: GATEWAY };
}

// `signRequest` always emits `created`; a real third-party signer may
// omit it. This helper builds such a gateway signature by hand using the
// public signature-base primitives, so the wire shape matches what a
// foreign implementation would send.
function signGatewayWithoutCreated(): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  // No content-digest here: the foreign request carries no body, and the
  // merged request's body must not change what this signature covers.
  const foreignCovered = ["@method", "@authority", "@path"];
  const params: SignatureParams = {
    keyid: "gateway-foreign",
    alg: "ed25519",
    expires: NOW + 600,
  };
  const base = buildSignatureBase(foreignCovered, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const signed: SignedHttpRequest = {
    method: req.method,
    url: req.url,
    headers: {
      "signature-input": signatureInputValue("gateway", foreignCovered, params),
      signature: `gateway=:${sig.toString("base64")}:`,
    },
  };
  return { signed, publicKey };
}

test("maxSignatureAgeSecByLabel: merchant short window rejects, gateway long window passes the same-age signatures", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    maxSignatureAgeSecByLabel: { merchant: 300, gateway: 7200 },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("maxSignatureAgeSecByLabel: a label missing from the map falls back to the global window", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    maxSignatureAgeSec: 7200,
    maxSignatureAgeSecByLabel: { merchant: 300 },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("maxSignatureAgeSecByLabel: a mapped label's window overrides the global window", () => {
  // The global window alone (7200) would pass both 1-hour-old
  // signatures; the per-label 300s windows reject both.
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    maxSignatureAgeSec: 7200,
    maxSignatureAgeSecByLabel: { merchant: 300, gateway: 300 },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_TOO_OLD");
});

test("maxSignatureAgeSecByLabel: illegal per-label values throw a configuration error naming the label", () => {
  const bad = [-1, Number.NaN, Number.POSITIVE_INFINITY, "300", null];
  for (const v of bad) {
    assert.throws(
      () =>
        verifyAllLabels(dual(), {
          now: NOW,
          keys: keys(),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          maxSignatureAgeSecByLabel: { merchant: v as any },
        }),
      (e: unknown) =>
        e instanceof Error &&
        /maxSignatureAgeSecByLabel\["merchant"\].*non-negative finite number/.test(
          e.message,
        ),
      `expected a configuration error for ${String(v)}`,
    );
  }
});

test("maxSignatureAgeSecByLabel: a malformed map throws a configuration error", () => {
  const bad = [null, ["300"], "300"];
  for (const v of bad) {
    assert.throws(
      () =>
        verifyAllLabels(dual(), {
          now: NOW,
          keys: keys(),
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          maxSignatureAgeSecByLabel: v as any,
        }),
      /maxSignatureAgeSecByLabel.*label→window object/,
      `expected a configuration error for ${String(v)}`,
    );
  }
});

test("maxSignatureAgeSecByLabel: zero is a legal per-label window", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    maxSignatureAgeSecByLabel: { merchant: 0 },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  // The gateway label has neither a map entry nor a global window, so
  // no age check applies to it.
  assert.equal(results[1].ok, true);
});

test("maxSignatureAgeSecByLabel: no global window and no map entry means no age check", () => {
  const results = verifyAllLabels(dual(), {
    now: NOW,
    keys: keys(),
    maxSignatureAgeSecByLabel: { merchant: 300 },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  assert.equal(results[1].ok, true);
});

test("maxSignatureAgeSecByLabel: an undated label bypasses its per-label window", () => {
  const { signed: gatewayUndated, publicKey } = signGatewayWithoutCreated();
  const merged = mergeSignatures(signMerchant(), gatewayUndated);
  const results = verifyAllLabels(merged, {
    now: NOW,
    keys: { merchant: merchant.publicKey, gateway: publicKey },
    maxSignatureAgeSecByLabel: { merchant: 300, gateway: 300 },
  });
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_TOO_OLD");
  // No `created` on the wire: the age check has nothing to compare, so
  // the label passes — orthogonal to `requireCreated`, which would
  // reject it with MISSING_CREATED instead.
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, true);
});

test("maxSignatureAgeSecByLabel: without any window, old signatures still verify (backwards compatible)", () => {
  const results = verifyAllLabels(dual(), { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
});
