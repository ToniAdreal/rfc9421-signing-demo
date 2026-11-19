import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  generateEd25519KeyPair,
  isVerifyError,
  secretKey,
  signResponse,
  verifyAllResponseLabels,
  verifyAllResponseLabelsOrThrow,
  verifyResponseOrThrow,
  VerifyError,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1250: the request side has had `verifyRequestOrThrow` and
// `verifyAllLabelsOrThrow` for a while, but the response side only had
// the boolean `verifyResponse` / `verifyAllResponseLabels` — a
// settlement-webhook receiver that prefers exceptions had to hand-roll
// `if (!r.ok) throw`. These are the response-side throwing twins,
// mirroring the request-side semantics exactly.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });

const merchant = generateEd25519KeyPair();
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

/** The canonical multi-party flow: merchant ed25519 signs, gateway hmac appends. */
function merchantThenGateway(): SignedHttpResponse {
  const merchantSigned = signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  return addResponseSignature(merchantSigned, {
    keyId: "gateway-key-7",
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: CREATED,
    label: "gateway",
  });
}

/** Flip the first base64 character of one label's signature bytes. */
function tamperLabel(res: SignedHttpResponse, label: string): SignedHttpResponse {
  const pattern = new RegExp(`((?:^|,)\\s*${label}\\s*=:)([A-Za-z0-9+/])`);
  const signature = res.headers["signature"]?.replace(
    pattern,
    (_m, prefix: string, p1: string) => `${prefix}${p1 === "A" ? "B" : "A"}`,
  );
  assert.notEqual(signature, res.headers["signature"], "tamper must change the header");
  return { ...res, headers: { ...res.headers, signature: signature as string } };
}

test("verifyResponseOrThrow success returns the verified identity, tag and nonce echoed", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    tag: "settlement-webhook-v1",
    nonce: "resp-nonce-001",
  });
  const identity = verifyResponseOrThrow(signed, {
    key: merchant.publicKey,
    now: NOW,
  });
  assert.equal(identity.label, "sig1");
  assert.equal(identity.keyId, "gateway-key");
  assert.equal(identity.alg, "ed25519");
  assert.equal(identity.tag, "settlement-webhook-v1");
  assert.equal(identity.nonce, "resp-nonce-001");
  assert.equal(identity.created, CREATED);
  assert.deepEqual(identity.coveredComponents, ["@status", "content-digest"]);
});

test("verifyResponseOrThrow tampered status throws VerifyError SIGNATURE_MISMATCH", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  assert.throws(
    () =>
      verifyResponseOrThrow(
        { ...signed, status: 201 },
        { key: merchant.publicKey, now: NOW },
      ),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "SIGNATURE_MISMATCH");
      assert.equal(e.label, "sig1");
      assert.equal(e.keyId, "gateway-key");
      return true;
    },
  );
});

test("verifyResponseOrThrow tampered body throws VerifyError BODY_DIGEST_MISMATCH", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  assert.throws(
    () =>
      verifyResponseOrThrow(
        { ...signed, body: JSON.stringify({ settled: true, amount: 101 }) },
        { key: merchant.publicKey, now: NOW },
      ),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "BODY_DIGEST_MISMATCH");
      return true;
    },
  );
});

test("verifyResponseOrThrow unsigned response throws VerifyError MISSING_SIGNATURE_INPUT", () => {
  assert.throws(
    () =>
      verifyResponseOrThrow(settlementResponse(BODY), {
        key: merchant.publicKey,
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "MISSING_SIGNATURE_INPUT");
      assert.equal(e.label, "sig1");
      return true;
    },
  );
});

test("verifyResponseOrThrow bad status throws a plain Error, not a VerifyError", () => {
  const signed = signResponse(settlementResponse(BODY), {
    keyId: "gateway-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  assert.throws(
    () =>
      verifyResponseOrThrow(
        { ...signed, status: 99 },
        { key: merchant.publicKey, now: NOW },
      ),
    (e: unknown) => {
      assert.ok(e instanceof Error);
      assert.ok(!isVerifyError(e));
      assert.match((e as Error).message, /"status" must be an integer HTTP status code/);
      return true;
    },
  );
});

test("verifyAllResponseLabelsOrThrow both labels verify: returns per-label results in wire order", () => {
  const dual = merchantThenGateway();
  const results = verifyAllResponseLabelsOrThrow(dual, {
    keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) assert.equal(r.ok, true);
  assert.equal(results[0]?.keyId, "merchant-key-1");
  assert.equal(results[0]?.alg, "ed25519");
  assert.equal(results[1]?.keyId, "gateway-key-7");
  assert.equal(results[1]?.alg, "hmac-sha256");
  assert.deepEqual(results[0]?.coveredComponents, ["@status", "content-digest"]);
});

test("verifyAllResponseLabelsOrThrow one bad label throws that label's code with the full verifyResults attached", () => {
  const dual = merchantThenGateway();
  const tampered = tamperLabel(dual, "gateway");
  assert.throws(
    () =>
      verifyAllResponseLabelsOrThrow(tampered, {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "SIGNATURE_MISMATCH");
      assert.equal(e.label, "gateway");
      assert.equal(e.keyId, "gateway-key-7");
      // The whole per-label array rides along: the merchant label
      // that verified stays visible instead of being hidden by the throw.
      assert.ok(e.verifyResults !== undefined);
      assert.equal(e.verifyResults?.length, 2);
      assert.deepEqual(
        e.verifyResults?.map((r) => [r.label, r.ok]),
        [
          ["merchant", true],
          ["gateway", false],
        ],
      );
      assert.equal(e.verifyResults?.[1]?.code, "SIGNATURE_MISMATCH");
      return true;
    },
  );
});

test("verifyAllResponseLabelsOrThrow attached verifyResults is a detached copy", () => {
  const dual = merchantThenGateway();
  const tampered = tamperLabel(dual, "gateway");
  let caught: VerifyError | undefined;
  try {
    verifyAllResponseLabelsOrThrow(tampered, {
      keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
      now: NOW,
    });
  } catch (e) {
    assert.ok(e instanceof VerifyError);
    caught = e;
  }
  assert.ok(caught !== undefined);
  // Mutating the attached array must never affect a later verification.
  caught?.verifyResults?.push({
    ok: false,
    code: "SIGNATURE_MISMATCH",
    reason: "forged entry",
    label: "forged",
  });
  const fresh = verifyAllResponseLabels(tampered, {
    keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
    now: NOW,
  });
  assert.equal(fresh.length, 2);
  assert.deepEqual(
    fresh.map((r) => r.label),
    ["merchant", "gateway"],
  );
});

test("verifyAllResponseLabelsOrThrow missing required label throws MISSING_REQUIRED_LABEL", () => {
  const merchantOnly = signResponse(settlementResponse(BODY), {
    keyId: "merchant-key-1",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
    label: "merchant",
  });
  assert.throws(
    () =>
      verifyAllResponseLabelsOrThrow(merchantOnly, {
        keys: { merchant: merchant.publicKey, gateway: gatewaySecret },
        requiredLabels: ["merchant", "gateway"],
        now: NOW,
      }),
    (e: unknown) => {
      assert.ok(e instanceof VerifyError);
      assert.equal(e.code, "MISSING_REQUIRED_LABEL");
      assert.equal(e.label, "gateway");
      // The synthetic failure is part of the attached array, after
      // the wire-order results.
      assert.equal(e.verifyResults?.length, 2);
      assert.deepEqual(
        e.verifyResults?.map((r) => [r.label, r.ok, r.code]),
        [
          ["merchant", true, undefined],
          ["gateway", false, "MISSING_REQUIRED_LABEL"],
        ],
      );
      return true;
    },
  );
});

test("verifyAllResponseLabelsOrThrow unsigned response returns [] without throwing", () => {
  const results = verifyAllResponseLabelsOrThrow(settlementResponse(BODY), {
    key: merchant.publicKey,
    now: NOW,
  });
  assert.deepEqual(results, []);
});
