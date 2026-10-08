import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type SignedHttpRequest,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// A POST covering only "@method": cryptographically valid, but it
// protects nothing — exactly the shape `requiredComponents` is meant to
// reject for payment-gateway verifiers. The body exists so a multi-label
// signature can additionally cover content-digest for the same request.
function signMethodOnly(): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      alg: "ed25519",
      key: privateKey,
      keyId: "gw-1",
      coveredComponents: ["@method"],
    },
  );
  return { signed, publicKey };
}

// A POST covering the digest of its body plus the request target.
function signWithDigest(): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      alg: "ed25519",
      key: privateKey,
      keyId: "gw-1",
      coveredComponents: ["@method", "@path", "content-digest"],
    },
  );
  return { signed, publicKey };
}

// ---------- narrow signature rejected ----------

test("requiredComponents: signature covering only @method is rejected with MISSING_REQUIRED_COMPONENT", () => {
  const { signed, publicKey } = signMethodOnly();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  // The reason names the missing component.
  assert.match(res.reason ?? "", /content-digest/);
});

test("requiredComponents: reason names every missing component", () => {
  const { signed, publicKey } = signMethodOnly();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest", "@path"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.match(res.reason ?? "", /content-digest/);
  assert.match(res.reason ?? "", /@path/);
});

test("requiredComponents: failure carries the wire context (keyId)", () => {
  const { signed, publicKey } = signMethodOnly();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.equal(res.keyId, "gw-1");
});

// ---------- covered signatures pass ----------

test("requiredComponents: fully covered signature passes", () => {
  const { signed, publicKey } = signWithDigest();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest", "@method", "@path"],
  });
  assert.equal(res.ok, true);
});

test("requiredComponents: comparison is case-insensitive", () => {
  const { signed, publicKey } = signWithDigest();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["Content-Digest", "@METHOD"],
  });
  assert.equal(res.ok, true);
});

// ---------- defaults and opt-out ----------

test("requiredComponents: unset keeps legacy behavior (narrow signature still verifies)", () => {
  const { signed, publicKey } = signMethodOnly();
  const res = verifyRequest(signed, { key: publicKey });
  assert.equal(res.ok, true);
});

test("requiredComponents: empty array performs no check", () => {
  const { signed, publicKey } = signMethodOnly();
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: [],
  });
  assert.equal(res.ok, true);
});

// ---------- invalid configuration throws ----------

test("requiredComponents: non-array value throws a configuration error", () => {
  const { signed, publicKey } = signMethodOnly();
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        requiredComponents: "content-digest" as unknown as string[],
      }),
    /requiredComponents.*must be an array/,
  );
});

test("requiredComponents: empty-string entry throws a configuration error", () => {
  const { signed, publicKey } = signMethodOnly();
  assert.throws(
    () =>
      verifyRequest(signed, {
        key: publicKey,
        requiredComponents: ["@method", ""],
      }),
    /requiredComponents.*non-empty strings/,
  );
});

// ---------- integration points ----------

test("requiredComponents: verifyRequestOrThrow throws VerifyError with the code", () => {
  const { signed, publicKey } = signMethodOnly();
  try {
    verifyRequestOrThrow(signed, {
      key: publicKey,
      requiredComponents: ["content-digest"],
    });
    assert.fail("expected verifyRequestOrThrow to throw");
  } catch (e) {
    assert.ok(isVerifyError(e), "expected a VerifyError");
    assert.equal(e.code, "MISSING_REQUIRED_COMPONENT");
    assert.match(e.reason, /content-digest/);
  }
});

test("requiredComponents: verifyAllLabels enforces per label", () => {
  // "sig1" covers only @method; "gateway" covers content-digest too.
  const narrow = signMethodOnly();
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const multi = addSignature(narrow.signed, {
    alg: "ed25519",
    key: privateKey,
    keyId: "gw-1",
    label: "gateway",
    coveredComponents: ["@method", "@path", "content-digest"],
  });
  const results = verifyAllLabels(multi, {
    keys: { sig1: narrow.publicKey, gateway: publicKey },
    requiredComponents: ["content-digest"],
  });
  assert.equal(results.length, 2);
  const byLabel = new Map(results.map((r) => [r.label, r]));
  assert.equal(byLabel.get("sig1")?.ok, false);
  assert.equal(byLabel.get("sig1")?.code, "MISSING_REQUIRED_COMPONENT");
  assert.equal(byLabel.get("gateway")?.ok, true);
});
