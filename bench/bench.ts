/**
 * Local micro-benchmark for the RFC 9421 signing demo.
 *
 * Measures real, locally-observed sign/verify throughput for each
 * algorithm in the benchmark loop below (ed25519, hmac-sha256,
 * hmac-sha512, ecdsa-p256-sha256, ecdsa-p384-sha384, rsa-pss-sha512,
 * rsa-v1_5-sha256) on the machine that
 * runs it, plus a multi-party scenario (merchant ed25519 + gateway
 * hmac-sha256 dual labels via verifyAllLabels) and the key-resolution
 * hot path a gateway verifier hits on every request: `JwksKeyStore.resolve`
 * (Map hit on an offline-restored snapshot, zero network) and
 * `memoizeKeyResolver` cache hits / misses, plus the key-management
 * derivation a JWKS publisher runs for every key at publish/rotation
 * time: `jwkThumbprint` (RFC 7638) over a fixed three-shape fixture
 * (ed25519 / P-256 / RSA public JWKs, one derivation per shape per
 * measured call, self-checked outside timing against independently
 * pinned thumbprints — the RSA one is the RFC 7638 §3.1 published
 * value), plus the replay-detection
 * hot path a verifier with `requireNonce` hits on every request:
 * `ReplayCache.check` hits against a cache prefilled with 1,000 nonces
 * under a deterministic fake clock (zero network, zero wall clock for
 * the cache itself), plus the malformed-input rejection path:
 * `verifyRequest` over a fixed-seed corpus of malformed
 * signature-input / signature values (the parser rejection traffic a
 * verification gateway faces), self-checked to always return
 * `{ ok: false, code }` and never throw. Numbers vary with hardware —
 * do not treat them as guaranteed throughput.
 *
 * Run: `npm run bench`
 */
import { cpus } from "node:os";
import {
  addSignature,
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateRsaPssKeyPair,
  generateRsaV15KeyPair,
  JwksKeyStore,
  jwkThumbprint,
  memoizeKeyResolver,
  ReplayCache,
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
  } else if (alg === "ecdsa-p384-sha384") {
    // Same fixture caliber as the P-256 path above: one fresh key pair
    // (generateP384KeyPair) generated once per scenario, outside the
    // timed loops; only sign/verify calls are measured.
    const { publicKey, privateKey } = generateP384KeyPair();
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

/**
 * Fixed public-JWK fixture for the `jwkThumbprint` path — the three
 * shapes this library exports, with sources that exist independently
 * of this implementation:
 * - ed25519: the RFC 8032 §7.1 Test 1 public key.
 * - P-256: the curve generator point G (SEC 2), as a public JWK.
 * - RSA: the RFC 7638 §3.1 example JWK, verbatim (including its
 *   non-required `alg`/`kid` members, which must not participate).
 */
const THUMBPRINT_FIXTURE = {
  ed25519: {
    kty: "OKP",
    crv: "Ed25519",
    x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  },
  p256: {
    kty: "EC",
    crv: "P-256",
    x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
  },
  rsa: {
    kty: "RSA",
    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    e: "AQAB",
    alg: "RS256",
    kid: "2011-04-29",
  },
} as const;

/**
 * Expected thumbprints for the fixture above. The RSA value is the
 * thumbprint published in RFC 7638 §3.1 itself (the same value
 * test/jwkThumbprint.test.ts pins). The ed25519 / P-256 values were
 * computed independently of this implementation (canonical required-
 * member JSON + SHA-256, cross-checked in Python's hashlib, whose
 * RSA output reproduces the RFC value exactly) and are pinned here
 * as literals — never derived from `jwkThumbprint` at bench time.
 */
const THUMBPRINT_EXPECTED = {
  ed25519: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
  p256: "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  rsa: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
} as const;

/**
 * `jwkThumbprint` steady state: one measured call derives the
 * thumbprint of each of the three fixture shapes (3 derivations per
 * call) — the per-key cost a JWKS publisher/rotator pays to assign
 * stable keyids. Self-checks run outside timing: every shape must
 * reproduce its pinned expected thumbprint above.
 */
function benchmarkJwkThumbprint(): number {
  for (const shape of ["ed25519", "p256", "rsa"] as const) {
    const tp = jwkThumbprint(THUMBPRINT_FIXTURE[shape]);
    if (tp !== THUMBPRINT_EXPECTED[shape])
      throw new Error(
        `benchmark self-check failed: ${shape} thumbprint ${tp} ` +
          `(expected ${THUMBPRINT_EXPECTED[shape]})`,
      );
  }
  return measure(() => {
    jwkThumbprint(THUMBPRINT_FIXTURE.ed25519);
    jwkThumbprint(THUMBPRINT_FIXTURE.p256);
    jwkThumbprint(THUMBPRINT_FIXTURE.rsa);
  }, ITERATIONS);
}

/** Number of nonces prefilled into the ReplayCache benchmark fixture. */
const REPLAY_PREFILL = 1000;

/**
 * `ReplayCache.check` steady-state hit: the cache is prefilled with
 * REPLAY_PREFILL nonces under a fixed fake clock (no wall clock, no
 * randomness, no network), then every measured call checks a nonce
 * that is already recorded — the replay path a verifier with
 * `requireNonce` takes on a duplicate nonce. Calls rotate over the
 * whole prefilled set so the LRU recency refresh is exercised across
 * entries, not just on one hot key.
 *
 * Self-checks: every prefill call must report not-a-replay; an unseen
 * nonce must report false on first check and true on the second; and
 * after the measured run the stats counters must match the exact
 * number of check calls made (prefill misses + one unseen miss, and
 * the unseen re-check hit + warmup + timed hits).
 */
function benchmarkReplayCacheHit(): number {
  const FIXED_NOW = 1_700_000_000;
  const cache = new ReplayCache({
    maxEntries: 10_000,
    ttlSec: 3600,
    now: () => FIXED_NOW,
  });
  for (let i = 0; i < REPLAY_PREFILL; i++) {
    if (cache.check(`bench-nonce-${i}`) !== false)
      throw new Error(
        `benchmark self-check failed: prefill nonce ${i} reported as replay`,
      );
  }
  if (cache.check("bench-unseen") !== false)
    throw new Error(
      "benchmark self-check failed: unseen nonce reported as replay",
    );
  if (cache.check("bench-unseen") !== true)
    throw new Error(
      "benchmark self-check failed: second check of unseen nonce not a replay",
    );
  let idx = 0;
  const ops = measure(() => {
    const nonce = `bench-nonce-${idx % REPLAY_PREFILL}`;
    idx++;
    if (cache.check(nonce) !== true)
      throw new Error(
        `benchmark self-check failed: prefilled nonce ${nonce} not a replay`,
      );
  }, ITERATIONS);
  const stats = cache.stats();
  const expectedHits = 1 + WARMUP + ITERATIONS;
  const expectedMisses = REPLAY_PREFILL + 1;
  if (
    stats.hits !== expectedHits ||
    stats.misses !== expectedMisses ||
    stats.size !== REPLAY_PREFILL + 1 ||
    stats.evictions !== 0
  )
    throw new Error(
      `benchmark self-check failed: stats ${JSON.stringify(stats)} ` +
        `(expected hits=${expectedHits}, misses=${expectedMisses}, ` +
        `size=${REPLAY_PREFILL + 1}, evictions=0)`,
    );
  return ops;
}

/** Fixed seed for the malformed corpus (same seed as test/parserFuzz). */
const MALFORMED_SEED = 20261005;
/** `created` of the malformed corpus's base signature (fixed, no wall clock). */
const MALFORMED_CREATED = 1_700_000_000;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface MalformedCase {
  kind: string;
  sigInput: string;
  sig: string;
}

/**
 * Deterministic malformed-input corpus for the rejection path, built
 * with the same generation approach as test/parserFuzz.test.ts (fixed
 * mulberry32 seed, truncations / byte-level mutations / hand-built
 * shapes / printable soup over a valid signed request, plus malformed
 * `signature` values and missing headers). Pathological-size cases
 * (multi-KB labels, thousands of members) are deliberately excluded:
 * the fuzz test already pins their per-call latency, and they would
 * dominate a steady-state throughput number.
 */
function buildMalformedCorpus(
  validInput: string,
  validSig: string,
): MalformedCase[] {
  const rand = mulberry32(MALFORMED_SEED);
  const int = (n: number): number => Math.floor(rand() * n);
  const pick = <T,>(arr: readonly T[]): T => arr[int(arr.length)];
  const NASTY = '";=()\\,\' \t\n<>[]{}|~!#$%&*+^`'.split("");
  const mutate = (s: string, edits: number): string => {
    let out = s;
    for (let i = 0; i < edits; i++) {
      const op = int(3);
      if (out.length === 0) {
        out = pick(NASTY);
        continue;
      }
      const pos = int(out.length);
      if (op === 0) out = out.slice(0, pos) + pick(NASTY) + out.slice(pos);
      else if (op === 1) out = out.slice(0, pos) + out.slice(pos + 1);
      else out = out.slice(0, pos) + pick(NASTY) + out.slice(pos + 1);
    }
    return out;
  };
  // Hand-built malformed signature-input shapes (from parserFuzz).
  const SYNTH: readonly string[] = [
    "sig1=",
    'sig1=("a"',
    'sig1=("a" "b"',
    "sig1=(\"a\");created=",
    'sig1=("a");created=abc',
    'sig1=("a");created="yesterday"',
    'sig1="a";created=1',
    'sig1=(("nested"))',
    "sig1=((((",
    'sig1=("unterminated);created=1',
    'sig1=("esc\\',
    'sig1=("bad-escape-\\q");created=1',
    'sig1=("a");created=1\\',
    "=",
    ",",
    "sig1",
    "sig1=;",
    "sig1=( );",
    "sig1=();created=1",
    "sig1=() garbage",
    '"sig1"=("@method");created=1',
    'sig1 = ("@method") ; created = 1',
    'SIG1=("@method");CREATED=1',
    'sig1=("@method");;created=1',
    'sig1=("@method"),,sig2=("@path")',
    'sig1=("@method");created=1,sig2',
    'sig1=("@method");created=1,',
    ',sig1=("@method");created=1',
    'sig1=("@method");keyid=',
    'sig1=("@method");keyid=""',
    'sig1=("@method");keyid="k',
    'sig1=("@method");alg=',
    'sig1=("@method");alg="',
    'sig1=("@method");nonce="\\',
    'sig1=("@method");created=-5',
    'sig1=("@method");created=99999999999999999999999',
    'sig1=("@method");created=0x10',
    'sig1=("@method");created=1.5',
    'sig1=("@method");created=+1',
    'sig1=("@method");created= 1',
    'sig1=("@method");unknown-param',
    'sig1=("@method");=1',
    'sig1=("@method");1=2',
    'sig1=("@CREATE\\d");created=1',
    'sig1=("@method" "@path");created=1',
    'sig1=("@method",);created=1',
    'sig1=(,@method,);created=1',
    'sig1=("@method");created=1;created=2',
    'sig 1=("@method");created=1',
    'sig1 =("@method");created=1',
    'sig-1=("@method");created=1',
    '1sig=("@method");created=1',
    "sig1:=:aGk=:",
    'sig1=("@method");created=1\x00',
  ];
  const SIG_SYNTH: readonly string[] = [
    "sig1=",
    "sig1=:",
    "sig1=::",
    "sig1=:!!!:",
    "sig1=:aGk",
    "sig1=aGk=:",
    "sig1=:aGk=",
    "sig1=:aGk=::extra",
    "sig1=:====:",
    "garbage",
  ];

  const cases: MalformedCase[] = [];
  for (let i = 0; i < 100; i++)
    cases.push({
      kind: "truncation",
      sigInput: validInput.slice(0, int(validInput.length)),
      sig: validSig,
    });
  for (let i = 0; i < 200; i++)
    cases.push({
      kind: "mutation",
      sigInput: mutate(validInput, 1 + int(4)),
      sig: validSig,
    });
  for (const s of SYNTH) cases.push({ kind: "synthetic", sigInput: s, sig: validSig });
  const PRINTABLE = Array.from({ length: 95 }, (_, i) =>
    String.fromCharCode(32 + i),
  );
  const soup = (len: number): string => {
    let s = "";
    for (let i = 0; i < len; i++) s += pick(PRINTABLE);
    return s;
  };
  for (let i = 0; i < 100; i++)
    cases.push({ kind: "soup", sigInput: soup(int(401)), sig: validSig });
  for (const s of SIG_SYNTH)
    cases.push({ kind: "sig-synthetic", sigInput: validInput, sig: s });
  for (let i = 0; i < 100; i++)
    cases.push({
      kind: "sig-mutation",
      sigInput: validInput,
      sig: mutate(validSig, 1 + int(3)),
    });
  cases.push({ kind: "missing-input", sigInput: "", sig: validSig });
  cases.push({ kind: "missing-sig", sigInput: validInput, sig: "" });
  return cases;
}

/**
 * `verifyRequest` rejection-path steady state: measured calls rotate
 * over the fixed malformed corpus, so the mix of parse failures,
 * base-build failures, malformed signature fields and signature
 * mismatches matches the corpus construction on every call.
 *
 * Self-checks (construction consistency, all untimed except the
 * per-call rejection assertion inside the measured loop): the whole
 * corpus is run once before timing — every case must return
 * `{ ok: false, code }` (a throw escapes and fails the bench), the two
 * missing-header cases must carry their exact codes, every
 * sig-synthetic case must fail at the signature field
 * (MALFORMED_SIGNATURE or SIGNATURE_MISMATCH), and
 * MALFORMED_SIGNATURE_INPUT must be the single largest error-code
 * bucket (the corpus is mostly input-side breakage by construction).
 * The measured loop asserts every call rejects, and the rejection
 * count afterwards must equal warmup + timed iterations exactly.
 */
function benchmarkMalformedReject(): { ops: number; corpusSize: number } {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const base: SignedHttpRequest = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: privateKey,
    created: MALFORMED_CREATED,
  });
  const corpus = buildMalformedCorpus(
    base.headers["signature-input"],
    base.headers["signature"],
  );
  const requestFor = (c: MalformedCase): SignedHttpRequest => {
    const headers = { ...base.headers };
    if (c.sigInput !== "") headers["signature-input"] = c.sigInput;
    else delete headers["signature-input"];
    if (c.sig !== "") headers["signature"] = c.sig;
    else delete headers["signature"];
    return { ...fixture, headers };
  };
  const verifyOpts = { key: publicKey, now: MALFORMED_CREATED + 60 };

  const histogram = new Map<string, number>();
  for (const c of corpus) {
    const res = verifyRequest(requestFor(c), verifyOpts);
    if (res.ok || typeof res.code !== "string" || res.code.length === 0)
      throw new Error(
        `benchmark self-check failed: ${c.kind} case was not rejected with a code: ${JSON.stringify(res)}`,
      );
    histogram.set(res.code, (histogram.get(res.code) ?? 0) + 1);
    if (c.kind === "missing-input" && res.code !== "MISSING_SIGNATURE_INPUT")
      throw new Error(
        `benchmark self-check failed: missing-input case gave ${res.code}`,
      );
    if (c.kind === "missing-sig" && res.code !== "MISSING_SIGNATURE")
      throw new Error(
        `benchmark self-check failed: missing-sig case gave ${res.code}`,
      );
    if (
      c.kind === "sig-synthetic" &&
      res.code !== "MALFORMED_SIGNATURE" &&
      res.code !== "SIGNATURE_MISMATCH"
    )
      throw new Error(
        `benchmark self-check failed: sig-synthetic case gave ${res.code}`,
      );
  }
  const malformedInputCount = histogram.get("MALFORMED_SIGNATURE_INPUT") ?? 0;
  for (const [code, count] of histogram) {
    if (code !== "MALFORMED_SIGNATURE_INPUT" && count >= malformedInputCount)
      throw new Error(
        `benchmark self-check failed: code ${code} (${count}) is not below MALFORMED_SIGNATURE_INPUT (${malformedInputCount})`,
      );
  }

  let idx = 0;
  let rejected = 0;
  const ops = measure(() => {
    const res = verifyRequest(requestFor(corpus[idx % corpus.length]), verifyOpts);
    idx++;
    if (res.ok || typeof res.code !== "string" || res.code.length === 0)
      throw new Error(
        "benchmark self-check failed: malformed corpus case verified ok or without a code",
      );
    rejected++;
  }, ITERATIONS);
  if (rejected !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: ${rejected} rejections (expected ${WARMUP + ITERATIONS})`,
    );
  return { ops, corpusSize: corpus.length };
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
  "ecdsa-p384-sha384",
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
results.push({
  alg: "jwkThumbprint (3 JWK shapes)",
  op: "derive",
  ops: benchmarkJwkThumbprint(),
});
results.push({
  alg: "ReplayCache.check (hit, 1k)",
  op: "check",
  ops: benchmarkReplayCacheHit(),
});
const malformed = benchmarkMalformedReject();
results.push({
  alg: `verifyRequest (malformed, ${malformed.corpusSize} cases)`,
  op: "reject",
  ops: malformed.ops,
});

console.log("alg                                    op      throughput");
console.log("--------------------------------------------------------------------");
for (const r of results) {
  console.log(`${r.alg.padEnd(38)} ${r.op.padEnd(7)} ${fmt(r.ops)}`);
}
console.log("");
console.log("Numbers are machine-local measurements, not guarantees.");
