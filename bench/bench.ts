/**
 * Local micro-benchmark for the RFC 9421 signing demo.
 *
 * Measures real, locally-observed sign/verify throughput for each
 * algorithm in the benchmark loop below (ed25519, hmac-sha256,
 * hmac-sha512, ecdsa-p256-sha256, rsa-pss-sha512, rsa-v1_5-sha256) on the machine that
 * runs it, plus a multi-party scenario (merchant ed25519 + gateway
 * hmac-sha256 dual labels via verifyAllLabels) and the key-resolution
 * hot path a gateway verifier hits on every request: `JwksKeyStore.resolve`
 * (Map hit on an offline-restored snapshot, zero network) and
 * `memoizeKeyResolver` cache hits / misses. Numbers vary with
 * hardware — do not treat them as guaranteed throughput.
 *
 * Run: `npm run bench`
 */
import { cpus } from "node:os";
import {
  addSignature,
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  generateRsaV15KeyPair,
  JwksKeyStore,
  memoizeKeyResolver,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignAlg,
  type SignedHttpRequest,
} from "../src/index.js";

const ITERATIONS = 3000;
const WARMUP = 200;

const fixture = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ amount: 100, currency: "USD" }),
};

function measure(fn: () => void, iterations: number): number {
  for (let i = 0; i < WARMUP; i++) fn(); // warmup: JIT, key caching
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedSec = Number(process.hrtime.bigint() - start) / 1e9;
  return iterations / elapsedSec;
}

function benchmarkScenario(alg: SignAlg): { signOps: number; verifyOps: number } {
  let signKey: Parameters<typeof signRequest>[1]["key"];
  let verifyKey: Parameters<typeof verifyRequest>[1]["key"];

  if (alg === "ed25519") {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "ecdsa-p256-sha256") {
    const { publicKey, privateKey } = generateP256KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "rsa-pss-sha512") {
    const { publicKey, privateKey } = generateRsaPssKeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "rsa-v1_5-sha256") {
    const { publicKey, privateKey } = generateRsaV15KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else {
    // Per-algorithm HMAC floors (RFC 2104 §3): hmac-sha256 → ≥ 32 bytes,
    // hmac-sha512 → ≥ 64 bytes. secretKey() enforces the 32-byte floor;
    // the 64-byte secret here also satisfies it, so the same helper works.
    const secret = secretKey(Buffer.alloc(alg === "hmac-sha512" ? 64 : 32, 0x42));
    signKey = secret;
    verifyKey = secret;
  }

  // A fresh request object per sign call: signRequest does not mutate its
  // input, and re-signing the same object is the honest steady-state cost.
  const signOpts = { keyId: "bench-key", alg, key: signKey };
  const signOps = measure(() => {
    signRequest(fixture, signOpts);
  }, ITERATIONS);

  const signed: SignedHttpRequest = signRequest(fixture, signOpts);
  const verifyOpts = { key: verifyKey };
  const verifyOps = measure(() => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok) throw new Error(`benchmark self-check failed: ${r.reason}`);
  }, ITERATIONS);

  return { signOps, verifyOps };
}

/**
 * The canonical multi-party scenario from test/addSignature.test.ts:
 * the merchant signs the request with its ed25519 key, then the payment
 * gateway appends its own hmac-sha256 signature under a second label.
 * Measures the steady-state throughput of verifyAllLabels (both labels
 * verified independently per call).
 */
function benchmarkMultiLabel(): number {
  const { publicKey: merchantPublic, privateKey: merchantPrivate } =
    generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

  const merchantSigned = signRequest(fixture, {
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "hmac-sha256",
    key: gatewaySecret,
    label: "gateway",
  });

  return measure(() => {
    const results = verifyAllLabels(dual, {
      key: merchantPublic,
      keys: { gateway: gatewaySecret },
    });
    if (results.length !== 2 || results.some((r) => !r.ok)) {
      throw new Error(
        `benchmark self-check failed: ${JSON.stringify(results)}`,
      );
    }
  }, ITERATIONS);
}

/**
 * Build a JwksKeyStore entirely offline, as the backlog requires: the
 * store is restored from a snapshot of one freshly generated ed25519
 * key, and its fetch implementation throws if it is ever called — the
 * key-resolution benchmarks below perform zero network I/O.
 */
function offlineJwksStore(): JwksKeyStore {
  const { publicKey } = generateEd25519KeyPair();
  const snapshot = {
    v: 1 as const,
    fetchedAtSec: 1_700_000_000,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid: "bench-key" }],
  };
  return JwksKeyStore.restore(
    snapshot,
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        throw new Error("benchmark must not fetch (offline store)");
      },
      now: () => 1_700_000_000,
    },
  );
}

/** Steady-state `JwksKeyStore.resolve` hit: a Map lookup by keyid. */
function benchmarkJwksResolve(store: JwksKeyStore): number {
  return measure(() => {
    if (store.resolve("bench-key") === undefined)
      throw new Error("benchmark self-check failed: resolve missed bench-key");
  }, ITERATIONS);
}

/**
 * `memoizeKeyResolver` cache hit: the wrapper is primed once, then every
 * measured call must be served from the cache — the self-check asserts
 * the counting underlying resolver was still called exactly once after
 * the whole measured run (warmup included).
 */
function benchmarkMemoizeHit(store: JwksKeyStore): number {
  let underlying = 0;
  const counting = (keyId: string) => {
    underlying++;
    return store.resolve(keyId);
  };
  const memoized = memoizeKeyResolver(counting, {
    ttlSec: 300,
    now: () => 1_700_000_000,
  });
  if (memoized("bench-key") === undefined)
    throw new Error("benchmark self-check failed: priming resolve missed");
  const ops = measure(() => {
    if (memoized("bench-key") === undefined)
      throw new Error("benchmark self-check failed: memoized hit missed");
  }, ITERATIONS);
  if (underlying !== 1)
    throw new Error(
      `benchmark self-check failed: hit path penetrated to the underlying resolver ${underlying} times (expected 1)`,
    );
  return ops;
}

/**
 * `memoizeKeyResolver` cache miss: every call uses an unknown keyid.
 * Unknown keyids are deliberately never cached (see memoizeKeyResolver),
 * so every measured call penetrates to the counting underlying resolver
 * and returns undefined — the steady-state cost of verifying against a
 * keyid the store does not hold. The self-check asserts the underlying
 * call count equals warmup + timed iterations exactly.
 */
function benchmarkMemoizeMiss(store: JwksKeyStore): number {
  let underlying = 0;
  const counting = (keyId: string) => {
    underlying++;
    return store.resolve(keyId);
  };
  const memoized = memoizeKeyResolver(counting, {
    ttlSec: 300,
    now: () => 1_700_000_000,
  });
  const ops = measure(() => {
    if (memoized("bench-unknown") !== undefined)
      throw new Error("benchmark self-check failed: unknown keyid resolved");
  }, ITERATIONS);
  if (underlying !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: miss path made ${underlying} underlying calls (expected ${WARMUP + ITERATIONS})`,
    );
  return ops;
}

function fmt(ops: number): string {
  const s = ops >= 1000 ? ops.toLocaleString("en-US", { maximumFractionDigits: 0 }) : ops.toFixed(1);
  const perOpUs = (1e6 / ops).toFixed(2);
  return `${s} ops/sec (${perOpUs} µs/op)`;
}

console.log("rfc9421-signing-demo benchmark");
console.log(`Node: ${process.version} on ${process.platform}/${process.arch}`);
console.log(`CPU: ${cpus()[0]?.model ?? "unknown"}`);
console.log(`Request: POST with JSON body (${Buffer.byteLength(fixture.body)} bytes), covered: @method @authority @path content-digest`);
console.log(`Iterations per op: ${ITERATIONS} (after ${WARMUP} warmup)`);
console.log("");

const results: Array<{ alg: string; op: string; ops: number }> = [];
for (const alg of [
  "ed25519",
  "hmac-sha256",
  "hmac-sha512",
  "ecdsa-p256-sha256",
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
] as const) {
  const { signOps, verifyOps } = benchmarkScenario(alg);
  results.push({ alg, op: "sign", ops: signOps });
  results.push({ alg, op: "verify", ops: verifyOps });
}
results.push({
  alg: "verifyAllLabels (2 labels)",
  op: "verify",
  ops: benchmarkMultiLabel(),
});
const benchStore = offlineJwksStore();
results.push({
  alg: "JwksKeyStore.resolve (hit)",
  op: "resolve",
  ops: benchmarkJwksResolve(benchStore),
});
results.push({
  alg: "memoizeKeyResolver (hit)",
  op: "resolve",
  ops: benchmarkMemoizeHit(benchStore),
});
results.push({
  alg: "memoizeKeyResolver (miss)",
  op: "resolve",
  ops: benchmarkMemoizeMiss(benchStore),
});

console.log("alg                         op      throughput");
console.log("-------------------------------------------------------------");
for (const r of results) {
  console.log(`${r.alg.padEnd(27)} ${r.op.padEnd(7)} ${fmt(r.ops)}`);
}
console.log("");
console.log("Numbers are machine-local measurements, not guarantees.");
