import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  isVerifyError,
  ReplayCache,
  signRequest,
  verifyAllLabelsOrThrow,
  VerifyError,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function baseRequest(body?: string) {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body,
  };
}

/**
 * Combine two single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature.
 */
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

/** Flip the first base64 character of one label's signature bytes. */
function tamperLabel(req: SignedHttpRequest, label: string): SignedHttpRequest {
  const pattern = new RegExp(`((?:^|,)\\s*${label}\\s*=:)([A-Za-z0-9+/])`);
  const signature = req.headers["signature"].replace(
    pattern,
    (_m, prefix: string, p1: string) => `${prefix}${p1 === "A" ? "B" : "A"}`,
  );
  assert.notEqual(signature, req.headers["signature"], "tamper must change the header");
  return { ...req, headers: { ...req.headers, signature } };
}

function twoLabels() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "gateway",
  });
  return { publicKey, privateKey, merged: mergeSignatures(a, b) };
}

test("both labels verify: returns per-label success results in wire order", () => {
  const { publicKey, merged } = twoLabels();
  const results = verifyAllLabelsOrThrow(merged, { key: publicKey, now: NOW });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) assert.equal(r.ok, true);
  assert.equal(results[0].keyId, "merchant-key");
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[0].created, CREATED);
  assert.equal(results[1].keyId, "gateway-key");
  assert.deepEqual(results[0].coveredComponents, ["@method", "@authority", "@path", "content-digest"]);
});

test("one bad label throws VerifyError with that label's code and label", () => {
  const { publicKey, merged } = twoLabels();
  const tampered = tamperLabel(merged, "gateway");
  assert.throws(
    () => verifyAllLabelsOrThrow(tampered, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "SIGNATURE_MISMATCH");
      assert.equal(e.label, "gateway");
      assert.equal(e.keyId, "gateway-key");
      assert.equal(e.alg, "ed25519");
      assert.equal(e.created, CREATED);
      return true;
    },
  );
});

test("expired label throws VerifyError with code EXPIRED", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: CREATED + 10,
    label: "merchant",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "gateway",
  });
  const merged = mergeSignatures(a, b);
  assert.throws(
    () => verifyAllLabelsOrThrow(merged, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "EXPIRED");
      assert.equal(e.label, "merchant");
      assert.equal(e.expires, CREATED + 10);
      return true;
    },
  );
});

test("replayed nonce throws VerifyError with code NONCE_REPLAY", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig1",
    nonce: "nonce-replay-1",
  });
  const cache = new ReplayCache({ ttlSec: 3600, now: () => NOW });
  const first = verifyAllLabelsOrThrow(signed, {
    key: publicKey,
    now: NOW,
    replayCache: cache,
  });
  assert.equal(first.length, 1);
  assert.equal(first[0].ok, true);
  assert.equal(first[0].nonce, "nonce-replay-1");
  assert.throws(
    () => verifyAllLabelsOrThrow(signed, { key: publicKey, now: NOW, replayCache: cache }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "NONCE_REPLAY");
      assert.equal(e.label, "sig1");
      assert.equal(e.nonce, "nonce-replay-1");
      return true;
    },
  );
});

test("no signature-input returns an empty array without throwing", () => {
  const { publicKey } = generateEd25519KeyPair();
  assert.deepEqual(
    verifyAllLabelsOrThrow(baseRequest(), { key: publicKey, now: NOW }),
    [],
  );
});

test("mutually exclusive key options still throw a plain Error, not a VerifyError", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig1",
  });
  assert.throws(
    () =>
      verifyAllLabelsOrThrow(signed, {
        key: publicKey,
        keyResolver: () => publicKey,
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!(e instanceof VerifyError));
      assert.match((e as Error).message, /mutually exclusive/);
      return true;
    },
  );
});

test("first failing label wins when two labels fail differently", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const body = JSON.stringify({ amount: 100 });
  const a = signRequest(baseRequest(body), {
    keyId: "merchant-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    expires: CREATED + 10,
    label: "merchant",
  });
  const b = signRequest(baseRequest(body), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "gateway",
  });
  // merchant is EXPIRED at NOW; gateway's signature bytes are tampered.
  const merged = tamperLabel(mergeSignatures(a, b), "gateway");
  assert.throws(
    () => verifyAllLabelsOrThrow(merged, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "EXPIRED");
      assert.equal(e.label, "merchant");
      return true;
    },
  );
});

test("single label success returns a one-element array with the success shape", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(baseRequest(), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig1",
    nonce: "nonce-single",
  });
  const results = verifyAllLabelsOrThrow(signed, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].label, "sig1");
  assert.equal(results[0].keyId, "k");
  assert.equal(results[0].alg, "ed25519");
  assert.equal(results[0].nonce, "nonce-single");
  assert.equal(results[0].created, CREATED);
  assert.equal(results[0].expires, undefined);
});

test("malformed signature-input throws VerifyError MALFORMED_SIGNATURE_INPUT", () => {
  const { publicKey } = generateEd25519KeyPair();
  const req = {
    ...baseRequest(),
    headers: {
      "content-type": "application/json",
      "signature-input": 'sig1=("@method");created=1, ,',
      signature: "sig1=:AAAA:",
    },
  };
  assert.throws(
    () => verifyAllLabelsOrThrow(req, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "MALFORMED_SIGNATURE_INPUT");
      assert.equal(e.label, "");
      return true;
    },
  );
});

test("tampered first label throws with the first label, not the good second", () => {
  const { publicKey, merged } = twoLabels();
  const tampered = tamperLabel(merged, "merchant");
  assert.throws(
    () => verifyAllLabelsOrThrow(tampered, { key: publicKey, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "SIGNATURE_MISMATCH");
      assert.equal(e.label, "merchant");
      return true;
    },
  );
});
