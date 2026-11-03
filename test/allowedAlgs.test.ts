import test from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  randomBytes,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  ReplayCache,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// `VerifyOptions.allowedAlgs` (backlog #851): an opt-in algorithm
// whitelist. A gateway that only accepts ed25519 should not have to
// hand-roll a pre-check whose answer for a missing or misspelled `alg`
// varies by caller — the library answers it uniformly, before crypto.

const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@path"];

function baseRequest(): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
}

function signedEd(label: string, pair: ReturnType<typeof generateEd25519KeyPair>): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg: "ed25519",
    key: pair.privateKey,
    created: CREATED,
  });
}

function signedHmac(
  label: string,
  alg: "hmac-sha256" | "hmac-sha512",
  secret: KeyObject,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    label,
    keyId: label,
    alg,
    key: secret,
    created: CREATED,
  });
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

/**
 * Sign like a foreign signer that never emits the optional `alg`
 * parameter: build the signature base with params that carry no `alg`,
 * then sign with node:crypto directly (mirroring the algFallback test
 * helper). The wire shape matches what a foreign implementation sends.
 */
function signedEdWithoutAlg(
  label: string,
  pair: ReturnType<typeof generateEd25519KeyPair>,
): SignedHttpRequest {
  const req = baseRequest();
  const params = { created: CREATED, keyid: label }; // no alg, ever
  const base = buildSignatureBase(COVERED, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  const headers = {
    "signature-input": signatureInputValue(label, COVERED, params),
    signature: `${label}=:${sig.toString("base64")}:`,
  };
  assert.ok(
    !headers["signature-input"].includes("alg="),
    "precondition: foreign wire must not carry alg",
  );
  return { method: req.method, url: req.url, headers };
}

test("whitelisted alg verifies", () => {
  const pair = generateEd25519KeyPair();
  const res = verifyRequest(signedEd("sig1", pair), {
    key: pair.publicKey,
    allowedAlgs: ["ed25519"],
  });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
  assert.equal(res.alg, "ed25519");
});

test("wire alg outside the whitelist fails with ALG_NOT_ALLOWED", () => {
  const secret = secretKey(randomBytes(32));
  const res = verifyRequest(signedHmac("sig1", "hmac-sha256", secret), {
    key: secret,
    allowedAlgs: ["ed25519"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "ALG_NOT_ALLOWED");
  assert.equal(res.alg, "hmac-sha256");
});

test("without a whitelist the same hmac signature still verifies (backwards compatible)", () => {
  const secret = secretKey(randomBytes(32));
  const res = verifyRequest(signedHmac("sig1", "hmac-sha256", secret), {
    key: secret,
  });
  assert.equal(res.ok, true, `expected ok, got ${JSON.stringify(res)}`);
});

test("multi-alg whitelist accepts either member", () => {
  const pair = generateEd25519KeyPair();
  const secret64 = secretKey(randomBytes(64));
  const ed = verifyRequest(signedEd("sig1", pair), {
    key: pair.publicKey,
    allowedAlgs: ["ed25519", "hmac-sha512"],
  });
  assert.equal(ed.ok, true, `expected ok, got ${JSON.stringify(ed)}`);
  const hmac = verifyRequest(signedHmac("sig1", "hmac-sha512", secret64), {
    key: secret64,
    allowedAlgs: ["ed25519", "hmac-sha512"],
  });
  assert.equal(hmac.ok, true, `expected ok, got ${JSON.stringify(hmac)}`);
});

test("empty allowedAlgs is a caller configuration error", () => {
  const pair = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequest(signedEd("sig1", pair), {
        key: pair.publicKey,
        allowedAlgs: [],
      }),
    /allowedAlgs.*non-empty/,
  );
});

test("non-array allowedAlgs is a caller configuration error", () => {
  const pair = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequest(signedEd("sig1", pair), {
        key: pair.publicKey,
        // @ts-expect-error testing a runtime misuse the types forbid
        allowedAlgs: "ed25519",
      }),
    /allowedAlgs.*non-empty/,
  );
});

test("unknown alg entry in allowedAlgs is a caller configuration error", () => {
  const pair = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequest(signedEd("sig1", pair), {
        key: pair.publicKey,
        // @ts-expect-error testing a runtime misuse the types forbid
        allowedAlgs: ["ed25519", "rsa-md5"],
      }),
    /allowedAlgs.*implemented algorithm.*"rsa-md5"/,
  );
});

test("non-string entry in allowedAlgs is a caller configuration error", () => {
  const pair = generateEd25519KeyPair();
  assert.throws(
    () =>
      verifyRequest(signedEd("sig1", pair), {
        key: pair.publicKey,
        // @ts-expect-error testing a runtime misuse the types forbid
        allowedAlgs: [42],
      }),
    /allowedAlgs.*implemented algorithm/,
  );
});

test("alg-less signature under the legacy default is judged as ed25519", () => {
  const pair = generateEd25519KeyPair();
  const req = signedEdWithoutAlg("sig1", pair);
  const allowed = verifyRequest(req, {
    key: pair.publicKey,
    allowedAlgs: ["ed25519"],
  });
  assert.equal(allowed.ok, true, `expected ok, got ${JSON.stringify(allowed)}`);
  assert.equal(allowed.alg, "ed25519");
  const denied = verifyRequest(req, {
    key: pair.publicKey,
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "ALG_NOT_ALLOWED");
  assert.equal(denied.alg, "ed25519");
});

test("alg-less signature under algFallback infer is judged by the inferred alg", () => {
  // A B.2.5-style foreign hmac wire with no `alg`: sign the base with
  // the shared secret directly, the way the algFallback tests do.
  const secret = secretKey(randomBytes(32));
  const req = baseRequest();
  const params = { created: CREATED, keyid: "sig1" }; // no alg, ever
  const base = buildSignatureBase(COVERED, req, params);
  const sig = createHmac("sha256", secret).update(base, "utf8").digest();
  const wire: RequestLike = {
    method: req.method,
    url: req.url,
    headers: {
      "signature-input": signatureInputValue("sig1", COVERED, params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  const wireSigInput = wire.headers["signature-input"];
  assert.ok(typeof wireSigInput === "string" && !wireSigInput.includes("alg="));
  const allowed = verifyRequest(wire, {
    key: secret,
    algFallback: "infer",
    allowedAlgs: ["hmac-sha256"],
  });
  assert.equal(allowed.ok, true, `expected ok, got ${JSON.stringify(allowed)}`);
  assert.equal(allowed.alg, "hmac-sha256");
  const denied = verifyRequest(wire, {
    key: secret,
    algFallback: "infer",
    allowedAlgs: ["ed25519"],
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "ALG_NOT_ALLOWED");
  assert.equal(denied.alg, "hmac-sha256");
});

test("verifyAllLabels: per-label whitelists apply independently", () => {
  const pair = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const merged = mergeSignatures(signedEd("sig1", pair), signedHmac("sig2", "hmac-sha256", secret));
  const results = verifyAllLabels(merged, {
    keys: { sig1: pair.publicKey, sig2: secret },
    allowedAlgsByLabel: { sig1: ["ed25519"], sig2: ["hmac-sha256"] },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true, `sig1: ${JSON.stringify(results[0])}`);
  assert.equal(results[1].ok, true, `sig2: ${JSON.stringify(results[1])}`);
});

test("verifyAllLabels: one label outside its whitelist does not affect the other", () => {
  const pair = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const merged = mergeSignatures(signedEd("sig1", pair), signedHmac("sig2", "hmac-sha256", secret));
  const results = verifyAllLabels(merged, {
    keys: { sig1: pair.publicKey, sig2: secret },
    allowedAlgsByLabel: { sig1: ["hmac-sha256"], sig2: ["hmac-sha256"] },
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "ALG_NOT_ALLOWED");
  assert.equal(results[1].ok, true, `sig2: ${JSON.stringify(results[1])}`);
});

test("verifyAllLabels: unmapped labels fall back to the global whitelist", () => {
  const pair = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const merged = mergeSignatures(signedEd("sig1", pair), signedHmac("sig2", "hmac-sha256", secret));
  const results = verifyAllLabels(merged, {
    keys: { sig1: pair.publicKey, sig2: secret },
    allowedAlgs: ["ed25519"],
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "ALG_NOT_ALLOWED");
});

test("verifyAllLabels: a mapped list replaces the global list, it is not unioned", () => {
  const pair = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const merged = mergeSignatures(signedEd("sig1", pair), signedHmac("sig2", "hmac-sha256", secret));
  const results = verifyAllLabels(merged, {
    keys: { sig1: pair.publicKey, sig2: secret },
    allowedAlgs: ["ed25519", "hmac-sha256"],
    allowedAlgsByLabel: { sig2: ["ed25519"] },
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "ALG_NOT_ALLOWED");
});

test("verifyAllLabels: malformed per-label whitelist is a caller configuration error", () => {
  const pair = generateEd25519KeyPair();
  const secret = secretKey(randomBytes(32));
  const merged = mergeSignatures(signedEd("sig1", pair), signedHmac("sig2", "hmac-sha256", secret));
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        keys: { sig1: pair.publicKey, sig2: secret },
        allowedAlgsByLabel: { sig1: [] },
      }),
    /allowedAlgsByLabel\["sig1"\]/,
  );
  assert.throws(
    () =>
      verifyAllLabels(merged, {
        keys: { sig1: pair.publicKey, sig2: secret },
        // @ts-expect-error testing a runtime misuse the types forbid
        allowedAlgsByLabel: { sig2: ["bogus"] },
      }),
    /allowedAlgsByLabel\["sig2"\]/,
  );
});

test("verifyRequestOrThrow raises VerifyError with ALG_NOT_ALLOWED", () => {
  const secret = secretKey(randomBytes(32));
  assert.throws(
    () =>
      verifyRequestOrThrow(signedHmac("sig1", "hmac-sha256", secret), {
        key: secret,
        allowedAlgs: ["ed25519"],
      }),
    (e: unknown) => isVerifyError(e) && e.code === "ALG_NOT_ALLOWED",
  );
});

test("a whitelist rejection happens before crypto, so it never records the nonce", () => {
  const secret = secretKey(randomBytes(32));
  const cache = new ReplayCache({ ttlSec: 600 });
  const req = signRequest(baseRequest(), {
    label: "sig1",
    keyId: "sig1",
    alg: "hmac-sha256",
    key: secret,
    created: CREATED,
    nonce: "once-only-nonce",
  });
  const denied = verifyRequest(req, {
    key: secret,
    allowedAlgs: ["ed25519"],
    replayCache: cache,
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.code, "ALG_NOT_ALLOWED");
  // The same nonce, now under an allowed alg, must still be fresh:
  // the rejected attempt never reached (or polluted) the cache.
  const allowed = verifyRequest(req, {
    key: secret,
    allowedAlgs: ["hmac-sha256"],
    replayCache: cache,
  });
  assert.equal(allowed.ok, true, `expected ok, got ${JSON.stringify(allowed)}`);
});
