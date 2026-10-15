/**
 * Local micro-benchmark for the RFC 9421 signing demo.
 *
 * Measures real, locally-observed sign/verify throughput for each
 * algorithm in the benchmark loop below (ed25519, hmac-sha256,
 * hmac-sha512, ecdsa-p256-sha256, ecdsa-p384-sha384,
 * ecdsa-p521-sha512, rsa-pss-sha512,
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
 * `{ ok: false, code }` and never throw, plus the standalone body-hash
 * primitive every signed/verified request pays for: `contentDigest`
 * over the shared 31-byte fixture body, measured separately for
 * sha-512 and sha-256 and self-checked outside timing against
 * independently pinned digest values (see DIGEST_EXPECTED below), so
 * the cost of hashing a body is visible apart from the asymmetric
 * signing it is normally bundled into, plus the inbound
 * normalization every gateway request pays before verification even
 * starts: `fromNodeRequest` over a fixed mock `IncomingRequestLike`
 * (no real server, zero network), self-checked outside timing
 * against a hand-pinned expected `RequestLike` (see NODE_FIXTURE
 * below), plus the key-distribution round trip a JWKS publisher /
 * verifier pays for every non-ed25519 key: `exportPublicKeyJwk*` →
 * JSON stringify/parse → `importPublicKeyJwk*` for each of P-256,
 * P-384, P-521 and RSA (one freshly generated key pair per shape,
 * generated outside timing; the RSA pair is the library's 2048-bit
 * default and its JWK is shared by both RSA algorithms),
 * self-checked outside timing by comparing the re-imported public
 * key's SPKI DER byte-for-byte against the original's — an
 * independent node:crypto encoding, not the JWK helpers' own
 * output, plus the pure string-building step every sign/verify pays
 * before any cryptography runs: `buildSignatureBase` over the
 * shared fixture request with the fixed covered set
 * `@method @authority @path content-digest`, self-checked outside
 * timing against a hand-written expected base text (see
 * BASE_EXPECTED below), so the cost of resolving covered
 * components and serializing the signature base is visible apart
 * from the algorithm costs it is normally bundled into, plus the
 * three standalone parsers a gateway pre-screen calls directly —
 * `listSignatureLabels`, `parseSignatureInput` and
 * `parseSignatureField` — over a fixed hand-written dual-label
 * fixture (see PARSER_* below), self-checked outside timing
 * against hand-pinned parse shapes and a hand-pinned malformed
 * set that must all throw, so the pure parsing cost before any
 * cryptography is visible apart from the end-to-end verify paths
 * that bundle it, plus the strict Structured Field canonicalization
 * every `;sf` covered component pays on both sides:
 * `canonicalizeStructuredFieldValue` over a fixed six-value corpus
 * (Dictionary / List / Item shapes, decimal and leading-zero integer
 * boundaries, and a Byte Sequence member — see SF_FIXTURE below),
 * self-checked on every measured pass against hand-pinned expected
 * serializations, so the parse-then-reserialize cost of the `;sf`
 * path is visible apart from the end-to-end `;sf` verify total that
 * bundles it, plus the throwing verify wrapper a middleware-style
 * caller actually uses: `verifyRequestOrThrow`, measured as two
 * separate rows — the success path (result unwrapping) over one
 * fixed valid ed25519 request and the failure path (VerifyError
 * construction carrying the pinned `SIGNATURE_MISMATCH` code) over
 * the same request with one signature byte flipped, each
 * self-checked on every measured call (see ORTHROW_* below), so the
 * cost difference between the result-object and throwing APIs —
 * including exception construction on failure — is visible.
 * Numbers
 * vary with hardware — do not treat them as guaranteed throughput.
 *
 * Run: `npm run bench`
 */
import { type KeyObject } from "node:crypto";
import { cpus } from "node:os";
import {
  addSignature,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  contentDigest,
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  fromNodeRequest,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  generateRsaV15KeyPair,
  importPublicKeyJwkP256,
  importPublicKeyJwkP384,
  importPublicKeyJwkP521,
  importPublicKeyJwkRsa,
  isVerifyError,
  JwksKeyStore,
  jwkThumbprint,
  listSignatureLabels,
  memoizeKeyResolver,
  parseSignatureField,
  parseSignatureInput,
  ReplayCache,
  secretKey,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type ContentDigestAlg,
  type IncomingRequestLike,
  type RequestLike,
  type SignatureParams,
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
  } else if (alg === "ecdsa-p521-sha512") {
    // Same fixture caliber as the P-256 / P-384 paths above: one fresh
    // key pair (generateP521KeyPair) generated once per scenario,
    // outside the timed loops; only sign/verify calls are measured.
    // P-521 signatures are raw r||s with each limb padded to 66 bytes
    // (132 bytes total, RFC 9421 §3.3.6).
    const { publicKey, privateKey } = generateP521KeyPair();
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

/**
 * Expected Content-Digest wire values for the shared fixture body
 * (`JSON.stringify({ amount: 100, currency: "USD" })`, 31 bytes),
 * pinned as literals — never derived from `contentDigest` at bench
 * time:
 * - sha-256: the OpenSSL-derived vector for these exact bytes in
 *   test/contentDigestSha256Openssl.test.ts (openssl dgst -sha256).
 * - sha-512: computed outside this library with
 *   `openssl dgst -sha512` and cross-checked with Python hashlib
 *   (both agreed byte-for-byte) on 2026-10-14.
 * The sha-512 self-check additionally pins the pre-existing golden
 * vector from test/golden.test.ts: contentDigest("hello").
 */
const DIGEST_EXPECTED: Record<ContentDigestAlg, string> = {
  "sha-512":
    "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  "sha-256": "sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:",
};
const DIGEST_HELLO_SHA512 =
  "sha-512=:m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==:";

/**
 * `contentDigest` steady state over the shared fixture body (31
 * bytes, printed in the bench header): the standalone RFC 9530 body
 * hash, isolated from the sign/verify paths that normally bundle it
 * with an asymmetric signature, so a reader can see what hashing a
 * body costs on its own and how sha-512 compares with sha-256 at
 * this size. Self-checks run outside timing: the fixture body must
 * reproduce the pinned wire value for the algorithm, and the
 * sha-512 path must also reproduce the golden "hello" vector.
 */
function benchmarkContentDigest(alg: ContentDigestAlg): number {
  const actual = contentDigest(fixture.body, alg);
  if (actual !== DIGEST_EXPECTED[alg])
    throw new Error(
      `benchmark self-check failed: contentDigest(fixture, ${alg}) gave ${actual} ` +
        `(expected ${DIGEST_EXPECTED[alg]})`,
    );
  if (alg === "sha-512" && contentDigest("hello") !== DIGEST_HELLO_SHA512)
    throw new Error(
      "benchmark self-check failed: contentDigest(\"hello\") sha-512 golden mismatch",
    );
  return measure(() => {
    contentDigest(fixture.body, alg);
  }, ITERATIONS);
}

/**
 * Fixed mock inbound request for the `fromNodeRequest` path — a plain
 * `IncomingRequestLike` test double, NOT a real server (the bench
 * performs zero network I/O and never opens a socket). Composition,
 * item by item:
 * - method POST, origin-form url "/v1/payments?event=charge.succeeded";
 * - `socket.encrypted` true, so the rebuilt absolute URL is https;
 * - seven header entries: Host with a port (mixed-case name),
 *   Content-Type, Content-Digest (the pinned sha-512 wire value of
 *   the shared fixture body — the adapter passes header values
 *   through unvalidated; it never recomputes digests),
 *   Signature-Input / Signature (pass-through strings in the shapes
 *   `verifyRequest` would later parse), one multi-value
 *   X-Forwarded-For whose first element carries padding whitespace
 *   (exercising the per-element trim + ", " join), and one
 *   `undefined` X-Debug-Skip entry (must be dropped);
 * - trailers in BOTH Node forms, mutually consistent: `rawTrailers`
 *   in wire order with a duplicated X-Dup name (must merge to
 *   "a, b"), and the parsed `trailers` object saying the same thing;
 * - body: the shared 31-byte fixture body, passed as the buffered
 *   second argument exactly as a real handler would after `end`.
 */
const NODE_FIXTURE_REQ: IncomingRequestLike = {
  method: "POST",
  url: "/v1/payments?event=charge.succeeded",
  socket: { encrypted: true },
  headers: {
    Host: "gateway.example.com:8443",
    "Content-Type": "application/json",
    "Content-Digest":
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    "Signature-Input":
      'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"',
    Signature: "sig1=:dGVzdA==:",
    "X-Forwarded-For": [" 203.0.113.10 ", "10.0.0.8"],
    "X-Debug-Skip": undefined,
  },
  trailers: { "x-checksum": "trailer-value", "x-dup": ["a", "b"] },
  rawTrailers: [
    "X-Checksum", "trailer-value",
    "X-Dup", "a",
    "x-dup", "b",
  ],
};

/**
 * Hand-pinned expected normalization of NODE_FIXTURE_REQ — written
 * out literally from the adapter's documented rules (absolute-URL
 * rebuild from scheme + verbatim host + origin-form path, header
 * names lowercased, multi-value values trimmed and joined with
 * ", ", `undefined` entries dropped, raw trailers merged by
 * lowercased name), never derived from `fromNodeRequest` at bench
 * time.
 */
const NODE_EXPECTED_URL =
  "https://gateway.example.com:8443/v1/payments?event=charge.succeeded";
const NODE_EXPECTED_HEADERS: Record<string, string> = {
  host: "gateway.example.com:8443",
  "content-type": "application/json",
  "content-digest":
    "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  "signature-input":
    'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"',
  signature: "sig1=:dGVzdA==:",
  "x-forwarded-for": "203.0.113.10, 10.0.0.8",
};
const NODE_EXPECTED_TRAILERS: Record<string, string> = {
  "x-checksum": "trailer-value",
  "x-dup": "a, b",
};

/** Field-by-field equality of a normalized request against the pins above. */
function assertNodeShape(
  actual: ReturnType<typeof fromNodeRequest>,
  label: string,
): void {
  const fail = (what: string): never => {
    throw new Error(`benchmark self-check failed (${label}): ${what}`);
  };
  if (actual.method !== "POST") fail(`method ${actual.method}`);
  if (actual.url !== NODE_EXPECTED_URL) fail(`url ${actual.url}`);
  if (actual.body !== fixture.body) fail("body did not pass through");
  const headerKeys = Object.keys(actual.headers);
  if (headerKeys.length !== Object.keys(NODE_EXPECTED_HEADERS).length)
    fail(`headers ${JSON.stringify(actual.headers)}`);
  for (const [name, value] of Object.entries(NODE_EXPECTED_HEADERS)) {
    if (actual.headers[name] !== value)
      fail(`header ${name} is ${actual.headers[name]} (expected ${value})`);
  }
  if ("x-debug-skip" in actual.headers) fail("undefined header not dropped");
  if ("Host" in actual.headers) fail("header name not lowercased");
  const trailers = actual.trailers;
  if (trailers === undefined)
    throw new Error(
      `benchmark self-check failed (${label}): trailers missing`,
    );
  const trailerKeys = Object.keys(trailers);
  if (trailerKeys.length !== Object.keys(NODE_EXPECTED_TRAILERS).length)
    fail(`trailers ${JSON.stringify(trailers)}`);
  for (const [name, value] of Object.entries(NODE_EXPECTED_TRAILERS)) {
    if (trailers[name] !== value)
      fail(`trailer ${name} is ${trailers[name]} (expected ${value})`);
  }
}

/**
 * `fromNodeRequest` steady state: the inbound normalization a
 * gateway runs on every received request before `verifyRequest` —
 * header folding, absolute-URL rebuild and trailer carry-over over
 * the fixed mock above. Self-checks run outside timing: the fixture
 * must normalize to the hand-pinned expectation field by field; the
 * parsed-trailers-object form (no `rawTrailers`) must produce the
 * identical result; a disagreeing parsed object must lose to
 * `rawTrailers`; and a trailer-less message must gain no `trailers`
 * field at all. The measured loop additionally pins the rebuilt URL
 * on every call.
 */
function benchmarkFromNodeRequest(): number {
  assertNodeShape(
    fromNodeRequest(NODE_FIXTURE_REQ, fixture.body),
    "raw-trailers fixture",
  );
  assertNodeShape(
    fromNodeRequest(
      { ...NODE_FIXTURE_REQ, rawTrailers: undefined },
      fixture.body,
    ),
    "trailers-object fixture",
  );
  const precedence = fromNodeRequest(
    {
      ...NODE_FIXTURE_REQ,
      trailers: { "x-checksum": "stale-object-value" },
    },
    fixture.body,
  );
  if (precedence.trailers?.["x-checksum"] !== "trailer-value")
    throw new Error(
      "benchmark self-check failed: rawTrailers did not take precedence",
    );
  const bare = fromNodeRequest(
    { ...NODE_FIXTURE_REQ, rawTrailers: undefined, trailers: undefined },
    fixture.body,
  );
  if ("trailers" in bare)
    throw new Error(
      "benchmark self-check failed: trailer-less request gained trailers",
    );
  return measure(() => {
    const r = fromNodeRequest(NODE_FIXTURE_REQ, fixture.body);
    if (r.url !== NODE_EXPECTED_URL)
      throw new Error(
        "benchmark self-check failed: fromNodeRequest rebuilt an unexpected URL",
      );
  }, ITERATIONS);
}

/**
 * Per-curve JWK round-trip steady state: for one key shape, a measured
 * call runs `exportPublicKeyJwk*` on a fixed public key, pushes the
 * JWK through a JSON stringify/parse round trip (the wire form a JWKS
 * document actually travels in), and re-imports it with
 * `importPublicKeyJwk*` — the key-distribution work a publisher pays
 * when serializing a key set and a verifier pays when loading one,
 * for the shapes the generic ed25519-only `exportPublicKeyJwk` does
 * not cover.
 *
 * Fixture caliber (fixed, stated here as the backlog requires): one
 * fresh key pair per shape, generated ONCE before timing with the
 * library's own generators — P-256 / P-384 / P-521 via
 * generateP256KeyPair / generateP384KeyPair / generateP521KeyPair,
 * RSA via generateRsaPssKeyPair (2048-bit modulus, the library
 * default; the RSA JWK carries no `alg`, so this one round trip
 * serves both `rsa-pss-sha512` and `rsa-v1_5-sha256`). The keys are
 * random per bench run, but nothing measured depends on their values
 * and the only assertion is the round-trip property below — no wall
 * clock, no network.
 *
 * Self-check (outside timing): the re-imported key's SPKI DER
 * encoding — produced by node:crypto directly, independently of the
 * JWK helpers — must equal the original public key's DER
 * byte-for-byte, for every shape.
 */
function benchmarkJwkRoundTrip(
  shape: string,
  publicKey: KeyObject,
  exportJwk: (key: KeyObject) => unknown,
  importJwk: (jwk: unknown) => KeyObject,
): number {
  const originalDer = publicKey.export({ format: "der", type: "spki" });
  const revived = importJwk(JSON.parse(JSON.stringify(exportJwk(publicKey))));
  const revivedDer = revived.export({ format: "der", type: "spki" });
  if (!originalDer.equals(revivedDer))
    throw new Error(
      `benchmark self-check failed: ${shape} JWK round trip changed the key ` +
        `(re-imported DER ${revivedDer.length} bytes, original ${originalDer.length} bytes)`,
    );
  return measure(() => {
    importJwk(JSON.parse(JSON.stringify(exportJwk(publicKey))));
  }, ITERATIONS);
}

/**
 * Fixed covered set for the `buildSignatureBase` path — the same
 * set the bench header names for the sign/verify scenarios
 * (`@method @authority @path content-digest`).
 */
const BASE_COMPONENTS = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
] as const;

/** Fixed signature parameters for the base path (no wall clock). */
const BASE_PARAMS: SignatureParams = {
  created: 1_700_000_000,
  keyid: "bench-key",
  alg: "ed25519",
};

/**
 * Fixed request for the base path: the shared bench fixture (same
 * method / URL / body shape as every other path), with the
 * `content-digest` header the covered set resolves — its value is
 * the pinned sha-512 wire value of the fixture body from
 * DIGEST_EXPECTED above, written out literally here.
 */
const BASE_REQUEST: RequestLike = {
  method: fixture.method,
  url: fixture.url,
  headers: {
    "content-type": "application/json",
    "content-digest":
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  },
  body: fixture.body,
};

/**
 * Hand-written expected signature base for BASE_REQUEST /
 * BASE_COMPONENTS / BASE_PARAMS — written out literally from the
 * RFC 9421 §2.5 rules (one `"id": value` line per covered component:
 * method uppercased, authority lowercased host, path alone, the
 * digest header value verbatim; then the `@signature-params` line
 * with parameters in created / keyid / alg order), in the same
 * hand-pinned style as the golden vector in test/golden.test.ts.
 * Never derived from `buildSignatureBase` at bench time.
 */
const BASE_EXPECTED =
  `"@method": POST\n` +
  `"@authority": api.example.com\n` +
  `"@path": /v1/payments\n` +
  `"content-digest": sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:\n` +
  `"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"`;

/**
 * `buildSignatureBase` steady state: the pure string-building step
 * every sign and verify pays before any cryptography — resolving
 * each covered component against the fixture request and
 * serializing the `"@signature-params"` line. Isolated here so a
 * reader can see what base construction costs on its own and how
 * much of a sign/verify number is cryptography versus base
 * building. Self-check outside timing: the built base must equal
 * BASE_EXPECTED byte-for-byte; the measured loop re-pins the full
 * text on every call. Zero network, zero randomness, no wall-clock
 * assertions.
 */
function benchmarkBuildSignatureBase(): number {
  const actual = buildSignatureBase(
    [...BASE_COMPONENTS],
    BASE_REQUEST,
    BASE_PARAMS,
  );
  if (actual !== BASE_EXPECTED)
    throw new Error(
      `benchmark self-check failed: buildSignatureBase gave ${JSON.stringify(actual)} ` +
        `(expected ${JSON.stringify(BASE_EXPECTED)})`,
    );
  return measure(() => {
    const base = buildSignatureBase(
      [...BASE_COMPONENTS],
      BASE_REQUEST,
      BASE_PARAMS,
    );
    if (base !== BASE_EXPECTED)
      throw new Error(
        "benchmark self-check failed: buildSignatureBase diverged from the pinned base text",
      );
  }, ITERATIONS);
}

/**
 * Fixed dual-label wire fixture for the standalone-parser paths —
 * written out literally here, NOT produced by `signRequest` at
 * bench time, so the expected parse shapes pinned below are
 * checked against the wire text itself:
 * - `signature-input`: two members. `merchant` covers
 *   `@method @authority @path content-digest` with parameters
 *   created=1700000000, keyid="merchant-key", alg="ed25519",
 *   nonce="bench-nonce" (no expires). `gateway` covers
 *   `@method @authority content-type` with parameters
 *   created=1700000060, expires=1700003600, keyid="gateway-key",
 *   alg="hmac-sha256" (no nonce).
 * - `signature`: the `merchant` member is the base64 of the 16
 *   bytes 0,1,…,15; the `gateway` member is the base64 of the
 *   11 ASCII bytes `hello-world`. Neither value is a real
 *   signature — the parsers never verify, they only decode.
 */
const PARSER_INPUT =
  'merchant=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="merchant-key";alg="ed25519";nonce="bench-nonce", ' +
  'gateway=("@method" "@authority" "content-type");created=1700000060;expires=1700003600;keyid="gateway-key";alg="hmac-sha256"';
const PARSER_SIG =
  "merchant=:AAECAwQFBgcICQoLDA0ODw==:, gateway=:aGVsbG8td29ybGQ=:";

/** Hand-pinned parse shapes for the fixture above. */
const PARSER_EXPECTED_LABELS = ["merchant", "gateway"] as const;
const PARSER_EXPECTED_MERCHANT_COMPONENTS = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
] as const;
const PARSER_EXPECTED_GATEWAY_COMPONENTS = [
  "@method",
  "@authority",
  "content-type",
] as const;
const PARSER_EXPECTED_MERCHANT_BYTES = Buffer.from([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
]);
const PARSER_EXPECTED_GATEWAY_BYTES = Buffer.from("hello-world", "utf8");

/**
 * Hand-pinned malformed set for the standalone parsers: every entry
 * must throw, with a message containing the pinned substring.
 * (The two `parseSignatureField` shape cases report "not present"
 * because that parser's only failure mode is finding no
 * `:base64:` member for the label — pinned as its actual contract.)
 */
const PARSER_MALFORMED: ReadonlyArray<{
  name: string;
  run: () => unknown;
  message: string;
}> = [
  {
    name: "listSignatureLabels empty value",
    run: () => listSignatureLabels(""),
    message: "malformed Signature-Input member",
  },
  {
    name: "listSignatureLabels trailing empty member",
    run: () => listSignatureLabels('sig1=("@method");created=1, ,'),
    message: "malformed Signature-Input member",
  },
  {
    name: "parseSignatureInput unknown label",
    run: () => parseSignatureInput(PARSER_INPUT, "missing"),
    message: "not present in Signature-Input",
  },
  {
    name: "parseSignatureInput unterminated inner list",
    run: () => parseSignatureInput('sig1=("a"', "sig1"),
    message: "unterminated inner list",
  },
  {
    name: "parseSignatureInput missing inner list",
    run: () => parseSignatureInput('sig1="a";created=1', "sig1"),
    message: "expected inner list",
  },
  {
    name: "parseSignatureField unknown label",
    run: () => parseSignatureField(PARSER_SIG, "missing"),
    message: "not present in Signature field",
  },
  {
    name: "parseSignatureField non-base64 member value",
    run: () => parseSignatureField("merchant=:!!!:", "merchant"),
    message: "not present in Signature field",
  },
  {
    name: "parseSignatureField member without colons",
    run: () => parseSignatureField("merchant=aGk=", "merchant"),
    message: "not present in Signature field",
  },
];

function assertParserComponents(
  actual: readonly string[],
  expected: readonly string[],
  what: string,
): void {
  if (
    actual.length !== expected.length ||
    actual.some((v, i) => v !== expected[i])
  )
    throw new Error(
      `benchmark self-check failed: ${what} parsed to ${JSON.stringify(actual)} ` +
        `(expected ${JSON.stringify(expected)})`,
    );
}

/**
 * Outside-timing self-checks for the standalone-parser fixture:
 * the label list, both members' component lists and every pinned
 * parameter, both members' decoded bytes, and the whole malformed
 * set (each entry must throw with its pinned message substring).
 */
function assertParserFixture(): void {
  const labels = listSignatureLabels(PARSER_INPUT);
  assertParserComponents(labels, PARSER_EXPECTED_LABELS, "label list");

  const merchant = parseSignatureInput(PARSER_INPUT, "merchant");
  if (merchant.label !== "merchant")
    throw new Error("benchmark self-check failed: merchant label mismatch");
  assertParserComponents(
    merchant.componentIds,
    PARSER_EXPECTED_MERCHANT_COMPONENTS,
    "merchant components",
  );
  if (
    merchant.params.created !== 1700000000 ||
    merchant.params.keyid !== "merchant-key" ||
    merchant.params.alg !== "ed25519" ||
    merchant.params.nonce !== "bench-nonce" ||
    merchant.params.expires !== undefined
  )
    throw new Error(
      `benchmark self-check failed: merchant params ${JSON.stringify(merchant.params)}`,
    );

  const gateway = parseSignatureInput(PARSER_INPUT, "gateway");
  if (gateway.label !== "gateway")
    throw new Error("benchmark self-check failed: gateway label mismatch");
  assertParserComponents(
    gateway.componentIds,
    PARSER_EXPECTED_GATEWAY_COMPONENTS,
    "gateway components",
  );
  if (
    gateway.params.created !== 1700000060 ||
    gateway.params.expires !== 1700003600 ||
    gateway.params.keyid !== "gateway-key" ||
    gateway.params.alg !== "hmac-sha256" ||
    gateway.params.nonce !== undefined
  )
    throw new Error(
      `benchmark self-check failed: gateway params ${JSON.stringify(gateway.params)}`,
    );

  if (!parseSignatureField(PARSER_SIG, "merchant").equals(PARSER_EXPECTED_MERCHANT_BYTES))
    throw new Error(
      "benchmark self-check failed: merchant signature bytes mismatch",
    );
  if (!parseSignatureField(PARSER_SIG, "gateway").equals(PARSER_EXPECTED_GATEWAY_BYTES))
    throw new Error(
      "benchmark self-check failed: gateway signature bytes mismatch",
    );

  for (const bad of PARSER_MALFORMED) {
    let thrown: unknown;
    try {
      bad.run();
    } catch (e) {
      thrown = e;
    }
    if (!(thrown instanceof Error) || !thrown.message.includes(bad.message))
      throw new Error(
        `benchmark self-check failed: ${bad.name} did not throw "${bad.message}" ` +
          `(got ${thrown instanceof Error ? JSON.stringify(thrown.message) : "no throw"})`,
      );
  }
}

/**
 * Standalone-parser steady states: each measured call runs ONE of
 * the three parsers over the valid dual-label fixture above (the
 * three are reported as separate rows, matching the table) and
 * re-pins the core of its expected result on every call. This is
 * the pre-screening work a gateway does before any cryptography —
 * splitting labels, parsing one member's covered components and
 * parameters, decoding one member's signature bytes — isolated
 * from the end-to-end `verifyRequest` paths that bundle it with
 * base building and crypto. Zero network, zero randomness, no
 * wall-clock assertions.
 */
function benchmarkListSignatureLabels(): number {
  assertParserFixture();
  return measure(() => {
    const labels = listSignatureLabels(PARSER_INPUT);
    if (
      labels.length !== 2 ||
      labels[0] !== "merchant" ||
      labels[1] !== "gateway"
    )
      throw new Error(
        "benchmark self-check failed: listSignatureLabels diverged from the pinned labels",
      );
  }, ITERATIONS);
}

function benchmarkParseSignatureInput(): number {
  assertParserFixture();
  return measure(() => {
    const parsed = parseSignatureInput(PARSER_INPUT, "merchant");
    if (
      parsed.componentIds.length !== 4 ||
      parsed.componentIds[3] !== "content-digest" ||
      parsed.params.created !== 1700000000 ||
      parsed.params.keyid !== "merchant-key" ||
      parsed.params.nonce !== "bench-nonce"
    )
      throw new Error(
        "benchmark self-check failed: parseSignatureInput diverged from the pinned shape",
      );
  }, ITERATIONS);
}

function benchmarkParseSignatureField(): number {
  assertParserFixture();
  return measure(() => {
    const bytes = parseSignatureField(PARSER_SIG, "merchant");
    if (!bytes.equals(PARSER_EXPECTED_MERCHANT_BYTES))
      throw new Error(
        "benchmark self-check failed: parseSignatureField diverged from the pinned bytes",
      );
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `canonicalizeStructuredFieldValue` path —
 * six values written out literally here, covering the three shapes
 * the function tries (Dictionary, then List, then Item) and the
 * normalization boundaries a gateway's `;sf` values actually hit.
 * Every expected serialization is hand-pinned below from the
 * RFC 8941 §4 strict-serialization rules (and matches the values
 * pinned independently in test/sfComponent.test.ts) — never
 * derived from `canonicalizeStructuredFieldValue` at bench time:
 * - dict-decimal: a Dictionary whose second member is a Decimal —
 *   decimals serialize with exactly three fractional digits
 *   (`1.5` → `1.500`); the Integer member is already canonical.
 * - dict-params-inner-list: a Dictionary with sloppy spacing,
 *   member parameters, and an Inner List — separators collapse
 *   to `, ` between members and `;` with no space before each
 *   parameter, inner-list items join with a single space.
 * - list-strings: a List of two Strings — the member separator
 *   collapses to `, ` regardless of the wire spacing.
 * - item-decimal: a lone Decimal Item — same three-digit rule.
 * - item-leading-zero-int: a lone Integer Item with leading
 *   zeros — integers serialize as the bare number (`007` → `7`).
 * - dict-byte-sequence: a Dictionary member holding a Byte
 *   Sequence with a Boolean parameter — the base64 is re-encoded
 *   canonically (this value is already canonical, so input and
 *   expectation coincide) and `?0` stays `?0`.
 */
const SF_FIXTURE: ReadonlyArray<{
  name: string;
  input: string;
  expected: string;
}> = [
  {
    name: "dict-decimal",
    input: "limit=1500, remaining=1.5",
    expected: "limit=1500, remaining=1.500",
  },
  {
    name: "dict-params-inner-list",
    input: "a=1,  b=2;x=1;  y=2, c=(a   b  c)",
    expected: "a=1, b=2;x=1;y=2, c=(a b c)",
  },
  {
    name: "list-strings",
    input: '"a" ,  "b"',
    expected: '"a", "b"',
  },
  {
    name: "item-decimal",
    input: "1.5",
    expected: "1.500",
  },
  {
    name: "item-leading-zero-int",
    input: "007",
    expected: "7",
  },
  {
    name: "dict-byte-sequence",
    input: "sig=:aGVsbG8=:;x=?0",
    expected: "sig=:aGVsbG8=:;x=?0",
  },
];

/**
 * `canonicalizeStructuredFieldValue` steady state: one measured
 * call is one pass over the whole six-value SF_FIXTURE corpus
 * (6 canonicalizations per op) — the parse-as-Dictionary/List/Item
 * plus strict-reserialize work every `;sf` covered component pays
 * on the signer and the verifier, isolated from the end-to-end
 * `;sf` verify path that bundles it with base building and
 * cryptography. Self-checks: every corpus entry is verified
 * against its hand-pinned expectation outside timing first, and
 * the measured loop re-pins every entry's result on every pass.
 * Zero network, zero randomness, no wall-clock assertions.
 */
function benchmarkCanonicalizeStructuredFieldValue(): number {
  for (const entry of SF_FIXTURE) {
    const actual = canonicalizeStructuredFieldValue(entry.input);
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: ${entry.name} canonicalized to ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  return measure(() => {
    for (const entry of SF_FIXTURE) {
      const actual = canonicalizeStructuredFieldValue(entry.input);
      if (actual !== entry.expected)
        throw new Error(
          `benchmark self-check failed: ${entry.name} canonicalization diverged from the pinned serialization`,
        );
    }
  }, ITERATIONS);
}

/** Fixed `created` for the OrThrow fixture (no wall clock). */
const ORTHROW_CREATED = 1_700_000_000;
/** Pinned failure code for the tampered OrThrow fixture — written
 * here as a literal, from the verify contract: flipping a signature
 * byte leaves the base rebuildable but fails the cryptography, so
 * the code is SIGNATURE_MISMATCH (same pin as test/verifyErrors). */
const ORTHROW_TAMPERED_CODE = "SIGNATURE_MISMATCH";

/**
 * Fixed corpus for the `verifyRequestOrThrow` paths: one valid
 * ed25519-signed request over the shared fixture (created pinned at
 * ORTHROW_CREATED, verified at created+60 — no wall clock) and the
 * same request with the first signature byte flipped (`buf[0] ^= 0xff`,
 * the tamper construction from test/verifyErrors.test.ts).
 * Reported as TWO separate rows (success / tampered), not merged:
 * the success row is the unwrapping cost over `verifyRequest`, the
 * tampered row additionally pays for VerifyError construction.
 */
function buildOrThrowFixture(): {
  valid: SignedHttpRequest;
  tampered: SignedHttpRequest;
  verifyOpts: { key: ReturnType<typeof generateEd25519KeyPair>["publicKey"]; now: number };
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const valid: SignedHttpRequest = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: privateKey,
    created: ORTHROW_CREATED,
  });
  const sigHeader = valid.headers["signature"];
  const tamperedSig = sigHeader.replace(
    /:([A-Za-z0-9+/=]+):/,
    (_m, b64: string) => {
      const buf = Buffer.from(b64, "base64");
      buf[0] ^= 0xff;
      return `:${buf.toString("base64")}:`;
    },
  );
  if (tamperedSig === sigHeader)
    throw new Error("benchmark self-check failed: tamper did not change the signature");
  const tampered: SignedHttpRequest = {
    ...valid,
    headers: { ...valid.headers, signature: tamperedSig },
  };
  return { valid, tampered, verifyOpts: { key: publicKey, now: ORTHROW_CREATED + 60 } };
}

function assertOrThrowFixture(
  fx: ReturnType<typeof buildOrThrowFixture>,
): void {
  const ok = verifyRequestOrThrow(fx.valid, fx.verifyOpts);
  if (ok.label !== "sig1" || ok.keyId !== "bench-key" || ok.alg !== "ed25519")
    throw new Error(
      `benchmark self-check failed: verifyRequestOrThrow(valid) gave ${JSON.stringify(ok)}`,
    );
  let thrown: unknown;
  try {
    verifyRequestOrThrow(fx.tampered, fx.verifyOpts);
  } catch (e) {
    thrown = e;
  }
  if (!isVerifyError(thrown) || thrown.code !== ORTHROW_TAMPERED_CODE)
    throw new Error(
      `benchmark self-check failed: verifyRequestOrThrow(tampered) gave ` +
        `${thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : "no throw"} ` +
        `(expected VerifyError ${ORTHROW_TAMPERED_CODE})`,
    );
}

/** `verifyRequestOrThrow` success path: result unwrapping, no throw. */
function benchmarkVerifyRequestOrThrowOk(): number {
  const fx = buildOrThrowFixture();
  assertOrThrowFixture(fx);
  return measure(() => {
    const r = verifyRequestOrThrow(fx.valid, fx.verifyOpts);
    if (r.label !== "sig1" || r.keyId !== "bench-key" || r.alg !== "ed25519")
      throw new Error(
        "benchmark self-check failed: verifyRequestOrThrow(valid) diverged in the measured loop",
      );
  }, ITERATIONS);
}

/**
 * `verifyRequestOrThrow` failure path: every call must throw a
 * VerifyError carrying the pinned code; the throw count afterwards
 * must equal warmup + timed iterations exactly.
 */
function benchmarkVerifyRequestOrThrowTampered(): number {
  const fx = buildOrThrowFixture();
  assertOrThrowFixture(fx);
  let thrownCount = 0;
  const ops = measure(() => {
    let thrown: unknown;
    try {
      verifyRequestOrThrow(fx.tampered, fx.verifyOpts);
    } catch (e) {
      thrown = e;
    }
    if (!isVerifyError(thrown) || thrown.code !== ORTHROW_TAMPERED_CODE)
      throw new Error(
        "benchmark self-check failed: verifyRequestOrThrow(tampered) did not throw the pinned VerifyError in the measured loop",
      );
    thrownCount++;
  }, ITERATIONS);
  if (thrownCount !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: ${thrownCount} tampered throws (expected ${WARMUP + ITERATIONS})`,
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
  "ecdsa-p384-sha384",
  "ecdsa-p521-sha512",
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
results.push({
  alg: "contentDigest sha-512 (31-byte body)",
  op: "digest",
  ops: benchmarkContentDigest("sha-512"),
});
results.push({
  alg: "contentDigest sha-256 (31-byte body)",
  op: "digest",
  ops: benchmarkContentDigest("sha-256"),
});
results.push({
  alg: "fromNodeRequest (inbound, trailers)",
  op: "normalize",
  ops: benchmarkFromNodeRequest(),
});
results.push({
  alg: "JWK round-trip P-256",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-256",
    generateP256KeyPair().publicKey,
    exportPublicKeyJwkP256,
    importPublicKeyJwkP256,
  ),
});
results.push({
  alg: "JWK round-trip P-384",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-384",
    generateP384KeyPair().publicKey,
    exportPublicKeyJwkP384,
    importPublicKeyJwkP384,
  ),
});
results.push({
  alg: "JWK round-trip P-521",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-521",
    generateP521KeyPair().publicKey,
    exportPublicKeyJwkP521,
    importPublicKeyJwkP521,
  ),
});
results.push({
  alg: "JWK round-trip RSA-2048",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "RSA",
    generateRsaPssKeyPair().publicKey,
    exportPublicKeyJwkRsa,
    importPublicKeyJwkRsa,
  ),
});
results.push({
  alg: "buildSignatureBase (4 components)",
  op: "build",
  ops: benchmarkBuildSignatureBase(),
});
results.push({
  alg: "listSignatureLabels (2 labels)",
  op: "parse",
  ops: benchmarkListSignatureLabels(),
});
results.push({
  alg: "parseSignatureInput (merchant)",
  op: "parse",
  ops: benchmarkParseSignatureInput(),
});
results.push({
  alg: "parseSignatureField (merchant)",
  op: "parse",
  ops: benchmarkParseSignatureField(),
});
results.push({
  alg: "canonicalizeStructuredFieldValue (6 values)",
  op: "canon",
  ops: benchmarkCanonicalizeStructuredFieldValue(),
});
results.push({
  alg: "verifyRequestOrThrow (valid)",
  op: "verify",
  ops: benchmarkVerifyRequestOrThrowOk(),
});
results.push({
  alg: "verifyRequestOrThrow (tampered)",
  op: "throw",
  ops: benchmarkVerifyRequestOrThrowTampered(),
});

console.log("alg                                    op      throughput");
console.log("--------------------------------------------------------------------");
for (const r of results) {
  console.log(`${r.alg.padEnd(38)} ${r.op.padEnd(7)} ${fmt(r.ops)}`);
}
console.log("");
console.log("Numbers are machine-local measurements, not guarantees.");
