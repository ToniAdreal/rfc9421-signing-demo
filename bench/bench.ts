/**
 * Local micro-benchmark for the RFC 9421 signing demo.
 *
 * Measures real, locally-observed sign/verify throughput for each supported
 * algorithm (ed25519, hmac-sha256) on the machine that runs it. Numbers vary
 * with hardware — do not treat them as guaranteed throughput.
 *
 * Run: `npm run bench`
 */
import { cpus } from "node:os";
import {
  generateEd25519KeyPair,
  secretKey,
  signRequest,
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
  } else {
    const secret = secretKey("bench-shared-secret");
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

const results: Array<{ alg: SignAlg; op: string; ops: number }> = [];
for (const alg of ["ed25519", "hmac-sha256"] as const) {
  const { signOps, verifyOps } = benchmarkScenario(alg);
  results.push({ alg, op: "sign", ops: signOps });
  results.push({ alg, op: "verify", ops: verifyOps });
}

console.log("alg           op      throughput");
console.log("-----------------------------------------------");
for (const r of results) {
  console.log(`${r.alg.padEnd(13)} ${r.op.padEnd(7)} ${fmt(r.ops)}`);
}
console.log("");
console.log("Numbers are machine-local measurements, not guarantees.");
