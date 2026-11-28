import test from "node:test";
import assert from "node:assert/strict";
import type { KeyObject } from "node:crypto";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyAllLabelsAsync,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function baseRequest() {
  return {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ amount: 250 }),
  };
}

/**
 * Combine single-signature requests into one genuinely multi-label
 * RFC 9421 request, as a proxy would when appending its own signature
 * (same shape as the merge helper in verifyAllLabelsJwksKeyResolvers.test.ts).
 */
function mergeSignatures(
  ...signed: SignedHttpRequest[]
): SignedHttpRequest {
  const first = signed[0];
  return {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": signed
        .map((s) => s.headers["signature-input"])
        .join(", "),
      signature: signed.map((s) => s.headers["signature"]).join(", "),
    },
  };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  label: string,
  nonce?: string,
): SignedHttpRequest {
  return signRequest(baseRequest(), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label,
    ...(nonce !== undefined ? { nonce } : {}),
  });
}

/** Flip the last byte of one label's signature value in a merged request. */
function tamperLabel(signed: SignedHttpRequest, label: string): SignedHttpRequest {
  const field = signed.headers["signature"] as string;
  const parts = field.split(", ");
  const idx = parts.findIndex((p) => p.startsWith(`${label}=:`));
  assert.notEqual(idx, -1, `label ${label} present`);
  const match = new RegExp(`^${label}=:([A-Za-z0-9+/=]+):$`).exec(parts[idx]);
  assert.ok(match, "signature part shape");
  const bytes = Buffer.from(match[1], "base64");
  bytes[bytes.length - 1] ^= 0xff;
  parts[idx] = `${label}=:${bytes.toString("base64")}:`;
  return {
    ...signed,
    headers: { ...signed.headers, signature: parts.join(", ") },
  };
}

test("verifyAllLabelsAsync: dual label round-trip through one global async resolver", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key", merchant.publicKey],
    ["gateway-key", gateway.publicKey],
  ]);
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const results = await verifyAllLabelsAsync(dual, {
    keyResolver: async (keyId: string) => {
      await new Promise((resolve) => setImmediate(resolve));
      return store.get(keyId);
    },
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].label, "gateway");
});

test("verifyAllLabelsAsync: per-label async resolvers resolve independently", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const results = await verifyAllLabelsAsync(dual, {
    keyResolvers: {
      merchant: async (keyId: string) => {
        await new Promise((resolve) => setImmediate(resolve));
        return keyId === "merchant-key" ? merchant.publicKey : undefined;
      },
      gateway: async (keyId: string) => {
        await new Promise((resolve) => setImmediate(resolve));
        return keyId === "gateway-key" ? gateway.publicKey : undefined;
      },
    },
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["merchant", true],
      ["gateway", true],
    ],
  );
});

test("verifyAllLabelsAsync: one label's resolver throwing fails only that label, contained to VERIFICATION_ERROR", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const results = await verifyAllLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => {
        throw new Error("merchant-vault-down: bearer xyz");
      },
      gateway: async (keyId: string) => (keyId === "gateway-key" ? gateway.publicKey : undefined),
    },
    now: NOW,
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "VERIFICATION_ERROR");
  assert.equal(results[0].label, "merchant");
  assert.ok(!results[0].reason?.includes("merchant-vault-down"));
  assert.ok(!results[0].reason?.includes("bearer xyz"));
  assert.equal(results[1].ok, true);
  assert.equal(results[1].label, "gateway");
});

test("verifyAllLabelsAsync: unknown keyid on one label fails only that label", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const results = await verifyAllLabelsAsync(dual, {
    keyResolvers: {
      merchant: async () => undefined,
      gateway: async (keyId: string) => (keyId === "gateway-key" ? gateway.publicKey : undefined),
    },
    now: NOW,
  });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "KEY_RESOLUTION_FAILED");
  assert.equal(results[1].ok, true);
});

test("verifyAllLabelsAsync: one tampered label fails with SIGNATURE_MISMATCH, the other still verifies", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const tampered = tamperLabel(dual, "gateway");
  const results = await verifyAllLabelsAsync(tampered, {
    keyResolver: async (keyId: string) => {
      const store = new Map<string, KeyObject>([
        ["merchant-key", merchant.publicKey],
        ["gateway-key", gateway.publicKey],
      ]);
      return store.get(keyId);
    },
    now: NOW,
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabelsAsync: synchronous resolvers still work (assignable to the async slots)", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const results = await verifyAllLabelsAsync(dual, {
    keyResolvers: {
      merchant: (keyId: string) => (keyId === "merchant-key" ? merchant.publicKey : undefined),
      gateway: (keyId: string) => (keyId === "gateway-key" ? gateway.publicKey : undefined),
    },
    now: NOW,
  });
  assert.deepEqual(
    results.map((r) => r.ok),
    [true, true],
  );
});

test("verifyAllLabelsAsync: unknown option key throws naming verifyAllLabelsAsync", async () => {
  const merchant = generateEd25519KeyPair();
  const dual = signAs("merchant-key", merchant.privateKey, "merchant");
  await assert.rejects(
    verifyAllLabelsAsync(dual, {
      key: merchant.publicKey,
      now: NOW,
      maxSignatureAge: 60,
    } as never),
    /invalid verifyAllLabelsAsync options: unknown option "maxSignatureAge"/,
  );
});

test("verifyAllLabelsAsync: requiredLabels appends a synthetic failure for a stripped label", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const store = new Map<string, KeyObject>([
    ["merchant-key", merchant.publicKey],
    ["gateway-key", gateway.publicKey],
  ]);
  const results = await verifyAllLabelsAsync(dual, {
    keyResolver: async (keyId: string) => store.get(keyId),
    requiredLabels: ["merchant", "gateway", "auditor"],
    now: NOW,
  });
  assert.equal(results.length, 3);
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, true);
  assert.equal(results[2].ok, false);
  assert.equal(results[2].code, "MISSING_REQUIRED_LABEL");
  assert.equal(results[2].label, "auditor");
});

test("verifyAllLabelsAsync: unsigned request with requiredLabels reports synthetic failures", async () => {
  const results = await verifyAllLabelsAsync(baseRequest(), {
    keyResolver: async () => undefined,
    requiredLabels: ["merchant", "gateway"],
    now: NOW,
  });
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.code === "MISSING_REQUIRED_LABEL"));
});

test("verifyAllLabelsAsync: per-label replay stores partition the same nonce; a shared store replays the second label", async () => {
  const signer = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([["shared-key", signer.publicKey]]);
  const keyResolver = async (keyId: string) => store.get(keyId);
  // Both labels carry the same keyid (one signer, two labels) and the
  // same nonce string: under the keyid-scoped nonce contract (#1412)
  // the shared store sees one (keyid, nonce) pair twice, while
  // per-label stores partition it.
  const dual = mergeSignatures(
    signAs("shared-key", signer.privateKey, "merchant", "shared-nonce-1"),
    signAs("shared-key", signer.privateKey, "gateway", "shared-nonce-1"),
  );
  // Per-label stores: the same nonce string is fresh in each partition.
  const perLabel = await verifyAllLabelsAsync(dual, {
    keyResolver,
    replayCacheByLabel: {
      merchant: new ReplayCache({ ttlSec: 3600 }),
      gateway: new ReplayCache({ ttlSec: 3600 }),
    },
    maxSignatureAgeSec: 60,
    now: NOW,
  });
  assert.deepEqual(
    perLabel.map((r) => r.ok),
    [true, true],
  );
  // One shared store: the gateway label replays the merchant's nonce.
  const shared = await verifyAllLabelsAsync(dual, {
    keyResolver,
    replayCache: new ReplayCache({ ttlSec: 3600 }),
    maxSignatureAgeSec: 60,
    now: NOW,
  });
  assert.equal(shared[0].ok, true);
  assert.equal(shared[1].ok, false);
  assert.equal(shared[1].code, "NONCE_REPLAY");
});

test("verifyAllLabelsAsync: sync/async parity — identical per-label verdicts for the same request", async () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key", merchant.publicKey],
    ["gateway-key", gateway.publicKey],
  ]);
  const keyResolver = (keyId: string) => store.get(keyId);
  const dual = mergeSignatures(
    signAs("merchant-key", merchant.privateKey, "merchant"),
    signAs("gateway-key", gateway.privateKey, "gateway"),
  );
  const syncResults = verifyAllLabels(dual, { keyResolver, now: NOW });
  const asyncResults = await verifyAllLabelsAsync(dual, { keyResolver, now: NOW });
  assert.deepEqual(asyncResults, syncResults);
  const tampered = tamperLabel(dual, "merchant");
  assert.deepEqual(
    await verifyAllLabelsAsync(tampered, { keyResolver, now: NOW }),
    verifyAllLabels(tampered, { keyResolver, now: NOW }),
  );
});
