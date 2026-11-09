import test from "node:test";
import assert from "node:assert/strict";
import {
  addResponseSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  signResponse,
  verifyAllResponseLabels,
  type HttpResponseLike,
  type RequestLike,
  type SignedHttpResponse,
} from "../src/index.js";

// Backlog #1002: the response side had only single-label
// `verifyResponse` (`opts.label ?? "sig1"`), while `addResponseSignature`
// documents a multi-party settlement flow (merchant ed25519 signs,
// gateway hmac appends) — a client verifying both labels had to
// hand-assemble a `RequestLike` and call `verifyResponse` twice, with
// no `requiredLabels` enforcement to reuse. `verifyAllResponseLabels`
// is the response-side twin of `verifyAllLabels`: per-label results
// in wire order, `requiredLabels` fail-closed, `@status` still bound
// by the response synthesis path, `request` pass-through for `;req`.

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

function triggeringRequest(method = "GET"): RequestLike {
  return { method, url: URL, headers: {} };
}

test("dual-label response verifies both labels in wire order, per-label keyId/alg reported", () => {
  const { dual } = merchantThenGateway();
  const results = verifyAllResponseLabels(dual, { keys: keys(), now: NOW });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
  assert.equal(results[0]?.keyId, "merchant-key-1");
  assert.equal(results[0]?.alg, "ed25519");
  assert.equal(results[1]?.keyId, "gateway-key-7");
  assert.equal(results[1]?.alg, "hmac-sha256");
});

test("tampered gateway signature fails only that label; merchant result unaffected", () => {
  const { dual } = merchantThenGateway();
  const tamperedSig = (dual.headers["signature"] as string).replace(
    /(gateway=:)([A-Za-z0-9+/])/,
    (_m, p1: string, c: string) => `${p1}${c === "A" ? "B" : "A"}`,
  );
  const tampered: SignedHttpResponse = {
    ...dual,
    headers: { ...dual.headers, signature: tamperedSig },
  };
  const results = verifyAllResponseLabels(tampered, {
    keys: keys(),
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.ok, true);
  assert.equal(results[0]?.label, "merchant");
  assert.equal(results[1]?.ok, false);
  assert.equal(results[1]?.label, "gateway");
  assert.equal(results[1]?.code, "SIGNATURE_MISMATCH");
});

test("requiredLabels missing from the wire yields a synthetic MISSING_REQUIRED_LABEL failure", () => {
  const { dual } = merchantThenGateway();
  const results = verifyAllResponseLabels(dual, {
    keys: keys(),
    now: NOW,
    requiredLabels: ["merchant", "gateway", "auditor"],
  });
  assert.equal(results.length, 3);
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true, false],
  );
  assert.equal(results[2]?.code, "MISSING_REQUIRED_LABEL");
  assert.equal(results[2]?.label, "auditor");
});

test("unsigned response: requiredLabels report synthetic failures, no requirement returns []", () => {
  const plain = settlementResponse(BODY);
  const required = verifyAllResponseLabels(plain, {
    keys: keys(),
    now: NOW,
    requiredLabels: ["merchant"],
  });
  assert.equal(required.length, 1);
  assert.equal(required[0]?.ok, false);
  assert.equal(required[0]?.code, "MISSING_REQUIRED_LABEL");
  assert.equal(required[0]?.label, "merchant");
  assert.deepEqual(
    verifyAllResponseLabels(plain, { keys: keys(), now: NOW }),
    [],
  );
});

test("single-label response: the absent label is reported, not silently skipped", () => {
  const { merchantSigned } = merchantThenGateway();
  const results = verifyAllResponseLabels(merchantSigned, {
    keys: keys(),
    now: NOW,
    requiredLabels: ["gateway"],
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.ok, true);
  assert.equal(results[0]?.label, "merchant");
  assert.equal(results[1]?.ok, false);
  assert.equal(results[1]?.code, "MISSING_REQUIRED_LABEL");
  assert.equal(results[1]?.label, "gateway");
  // Without the requirement the single wire label is the whole result.
  const bare = verifyAllResponseLabels(merchantSigned, {
    keys: keys(),
    now: NOW,
  });
  assert.equal(bare.length, 1);
  assert.equal(bare[0]?.ok, true);
});

test("status tamper 200 -> 500 fails both labels with SIGNATURE_MISMATCH (@status binding)", () => {
  const { dual } = merchantThenGateway();
  const results = verifyAllResponseLabels(
    { ...dual, status: 500 },
    { keys: keys(), now: NOW },
  );
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.ok),
    [false, false],
  );
  assert.deepEqual(
    results.map((r) => r.code),
    ["SIGNATURE_MISMATCH", "SIGNATURE_MISMATCH"],
  );
});

test("request pass-through: ;req component binds to the attached request", () => {
  const request = triggeringRequest("GET");
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
  const bound = verifyAllResponseLabels(dual, {
    keys: keys(),
    now: NOW,
    request,
  });
  assert.deepEqual(
    bound.map((r) => r.ok),
    [true, true],
  );
  // The same signatures transplanted onto a different request fail.
  const transplanted = verifyAllResponseLabels(dual, {
    keys: keys(),
    now: NOW,
    request: triggeringRequest("POST"),
  });
  assert.deepEqual(
    transplanted.map((r) => r.code),
    ["SIGNATURE_MISMATCH", "SIGNATURE_MISMATCH"],
  );
  // No request attached is a configuration error, not a wire failure.
  assert.throws(
    () =>
      verifyAllResponseLabels(dual, { keys: keys(), now: NOW }),
    /verifyAllResponseLabels: covered component .* derives from the request.*verifyAllLabels/,
  );
});

test("missing or non-integer status throws a configuration error", () => {
  const { dual } = merchantThenGateway();
  assert.throws(
    () =>
      verifyAllResponseLabels(
        { ...dual, status: "200" } as unknown as HttpResponseLike,
        { keys: keys(), now: NOW },
      ),
    /verifyAllResponseLabels: "status" must be an integer/,
  );
  assert.throws(
    () =>
      verifyAllResponseLabels(
        { ...dual, status: 200.5 } as unknown as HttpResponseLike,
        { keys: keys(), now: NOW },
      ),
    /verifyAllResponseLabels: "status" must be an integer/,
  );
});

test("guard runs per label: a second label covering @method without ;req throws", () => {
  const { merchantSigned } = merchantThenGateway();
  // Hand-merge a request-side signature (covering @method) as the
  // second label: the merchant label alone would pass the guard, so
  // the throw below pins the per-label check on the gateway label.
  const rogue = signRequest(
    { method: "GET", url: URL, headers: {} },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
      coveredComponents: ["@method", "@authority", "@path"],
    },
  );
  const combined: SignedHttpResponse = {
    status: 200,
    headers: {
      ...merchantSigned.headers,
      "signature-input": `${merchantSigned.headers["signature-input"]}, ${rogue.headers["signature-input"]}`,
      signature: `${merchantSigned.headers["signature"]}, ${rogue.headers["signature"]}`,
    },
    body: BODY,
  };
  assert.throws(
    () =>
      verifyAllResponseLabels(combined, { keys: keys(), now: NOW }),
    /verifyAllResponseLabels: covered component .* derives from the request.*verifyAllLabels/,
  );
});

test("malformed signature-input returns MALFORMED_SIGNATURE_INPUT, never throws", () => {
  const malformed: HttpResponseLike = {
    status: 200,
    headers: {
      "signature-input": "not-a-list",
      signature: "sig1=:AAAA:",
    },
    body: BODY,
  };
  const results = verifyAllResponseLabels(malformed, {
    keys: keys(),
    now: NOW,
  });
  assert.equal(results.length, 1);
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "MALFORMED_SIGNATURE_INPUT");
});

test("keys map fallback: a label absent from keys falls back to the global key", () => {
  const { dual } = merchantThenGateway();
  const results = verifyAllResponseLabels(dual, {
    keys: { merchant: merchant.publicKey },
    key: gatewaySecret,
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("per-label keys never leak: a wrong gateway secret fails only the gateway label", () => {
  const { dual } = merchantThenGateway();
  // A well-formed but wrong HMAC secret for the gateway label: the
  // merchant label still verifies, the gateway label fails with a
  // wire code — the map is honoured per label. (An ed25519 key handed
  // to the hmac label is a caller configuration error and throws from
  // the key-shape assert instead; that is not a wire failure.)
  const wrongGatewaySecret = secretKey("a-different-shared-secret-32byte!");
  const results = verifyAllResponseLabels(dual, {
    keys: { merchant: merchant.publicKey, gateway: wrongGatewaySecret },
    now: NOW,
  });
  assert.equal(results[0]?.ok, true);
  assert.equal(results[1]?.ok, false);
  assert.equal(results[1]?.code, "SIGNATURE_MISMATCH");
});
