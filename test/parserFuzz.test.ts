import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import {
  generateEd25519KeyPair,
  listSignatureLabels,
  parseSignatureField,
  parseSignatureInput,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
  type VerifyResult,
} from "../src/index.js";

/**
 * Parser fuzz: `parseSignatureInput` / `parseSignatureField` /
 * `listSignatureLabels` face adversarial input so `verifyRequest` must
 * never let an exception escape — every malformed header becomes
 * `{ ok: false, code }`. A fixed seed (mulberry32) keeps the corpus
 * deterministic; a 50ms per-call budget guards against catastrophic
 * backtracking in the parsing regexes.
 */

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

const CREATED = 1700000000;
const SEED = 20261005;
const MAX_MS = 50;

const rand = mulberry32(SEED);
const int = (n: number): number => Math.floor(rand() * n);
const pick = <T>(arr: readonly T[]): T => arr[int(arr.length)];

const { publicKey, privateKey } = generateEd25519KeyPair();
const BASE: SignedHttpRequest = signRequest(
  {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "x-request-id": "req-123" },
  },
  { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
);
const VALID_INPUT = BASE.headers["signature-input"];
const VALID_SIG = BASE.headers["signature"];

interface FuzzCase {
  kind: string;
  sigInput: string;
  sig: string;
  url?: string;
}

const NASTY = '";=()\\,\' \t\n<>[]{}|~!#$%&*+^`'.split("");

function mutate(s: string, edits: number): string {
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
}

// Hand-built malformed shapes: truncated quotes, illegal escapes,
// unbalanced parens, bad params, missing labels.
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

function buildCases(): FuzzCase[] {
  const cases: FuzzCase[] = [];

  // 1) Truncations of a valid header (incl. mid-quote / mid-param cuts).
  for (let i = 0; i < 150; i++)
    cases.push({
      kind: "truncation",
      sigInput: VALID_INPUT.slice(0, int(VALID_INPUT.length + 1)),
      sig: VALID_SIG,
    });

  // 2) Random byte-level mutations of a valid header.
  for (let i = 0; i < 350; i++)
    cases.push({
      kind: "mutation",
      sigInput: mutate(VALID_INPUT, 1 + int(4)),
      sig: VALID_SIG,
    });

  // 3) Hand-built malformed shapes.
  for (const s of SYNTH)
    cases.push({ kind: "synthetic", sigInput: s, sig: VALID_SIG });

  // 4) Pathological sizes: long labels/ids/params, deep nesting,
  //    thousands of components and members (regex backtracking bait).
  const rep = (n: number, ch: string): string => ch.repeat(n);
  cases.push({
    kind: "long-label",
    sigInput: `${rep(1000, "x")}=("@method");created=1`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "long-label",
    sigInput: `${rep(20000, "x")}=("@method");created=1`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "long-component",
    sigInput: `sig1=("${rep(5000, "c")}");created=1`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "long-param",
    sigInput: `sig1=("@method");keyid="${rep(8000, "k")}"`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "deep-parens",
    sigInput: `sig1=${rep(500, "(")}${rep(500, ")")};created=1`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "deep-parens",
    sigInput: `sig1=${rep(2000, "(")}`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "many-components",
    sigInput: `sig1=(${Array.from({ length: 3000 }, (_, i) => `"c${i}"`).join(
      " ",
    )});created=1`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "many-labels",
    sigInput: Array.from(
      { length: 500 },
      (_, i) => `s${i}=("@method");created=1`,
    ).join(","),
    sig: VALID_SIG,
  });
  cases.push({
    kind: "many-commas",
    sigInput: `sig1=("@method");created=1${",garbage".repeat(1000)}`,
    sig: VALID_SIG,
  });
  cases.push({
    kind: "quote-heavy",
    sigInput: `sig1=(${'\"a\"'.repeat(2000)});created=1`,
    sig: VALID_SIG,
  });

  // 5) Random byte soup as the whole header.
  const PRINTABLE = Array.from({ length: 95 }, (_, i) =>
    String.fromCharCode(32 + i),
  );
  const soup = (len: number): string => {
    let s = "";
    for (let i = 0; i < len; i++) s += pick(PRINTABLE);
    return s;
  };
  for (let i = 0; i < 350; i++)
    cases.push({ kind: "soup", sigInput: soup(int(401)), sig: VALID_SIG });

  // 6) Malformed `signature` field (base64 section) with a valid input.
  const SIG_SYNTH = [
    "",
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
  for (const s of SIG_SYNTH)
    cases.push({ kind: "sig-synthetic", sigInput: VALID_INPUT, sig: s });
  for (let i = 0; i < 240; i++)
    cases.push({
      kind: "sig-mutation",
      sigInput: VALID_INPUT,
      sig: mutate(VALID_SIG, 1 + int(3)),
    });

  // 7) Garbage URLs (signature base rebuild must not throw either).
  const URL_SYNTH = [
    "",
    "not a url",
    "://missing-scheme",
    "https://",
    "\x00",
    "https://api.example.com/v1/payments".repeat(50),
  ];
  for (const u of URL_SYNTH)
    cases.push({ kind: "bad-url", sigInput: VALID_INPUT, sig: VALID_SIG, url: u });
  for (let i = 0; i < 24; i++)
    cases.push({
      kind: "bad-url",
      sigInput: VALID_INPUT,
      sig: VALID_SIG,
      url: mutate("https://api.example.com/v1/payments", 1 + int(3)),
    });

  // 8) Missing headers entirely.
  cases.push({ kind: "missing-input", sigInput: "", sig: VALID_SIG });
  cases.push({ kind: "missing-sig", sigInput: VALID_INPUT, sig: "" });

  return cases;
}

const CASES = buildCases();

function requestFor(c: FuzzCase): SignedHttpRequest {
  const headers: Record<string, string> = {};
  if (c.sigInput !== "") headers["signature-input"] = c.sigInput;
  if (c.sig !== "") headers["signature"] = c.sig;
  // Keep one benign header so header-lookup paths stay exercised.
  headers["x-request-id"] = "req-123";
  return {
    method: "POST",
    url: c.url ?? "https://api.example.com/v1/payments",
    headers,
    body: '{"amount":100}',
  };
}

function assertResultShape(res: VerifyResult, kind: string): void {
  assert.equal(typeof res.ok, "boolean", `ok not boolean (${kind})`);
  assert.equal(typeof res.label, "string", `label not string (${kind})`);
  if (!res.ok)
    assert.ok(
      typeof res.code === "string" && res.code.length > 0,
      `failure without code (${kind})`,
    );
}

test("fuzz corpus has at least 1000 cases", () => {
  assert.ok(CASES.length >= 1000, `only ${CASES.length} cases`);
});

test("verifyRequest never throws on malformed parser input", () => {
  let worst = 0;
  let worstKind = "";
  for (const c of CASES) {
    const t0 = performance.now();
    let res: VerifyResult;
    try {
      res = verifyRequest(requestFor(c), { key: publicKey, now: CREATED + 60 });
    } catch (e) {
      assert.fail(
        `verifyRequest threw on ${c.kind}: ${(e as Error).message} ` +
          `(input=${JSON.stringify(c.sigInput).slice(0, 160)})`,
      );
    }
    const dt = performance.now() - t0;
    if (dt > worst) {
      worst = dt;
      worstKind = c.kind;
    }
    assert.ok(
      dt < MAX_MS,
      `verifyRequest took ${dt.toFixed(1)}ms (>= ${MAX_MS}ms) on ${c.kind}`,
    );
    assertResultShape(res, c.kind);
  }
  console.log(
    `fuzz: ${CASES.length} cases, worst verifyRequest ${worst.toFixed(1)}ms (${worstKind})`,
  );
});

test("verifyAllLabels never throws on malformed signature-input", () => {
  for (const c of CASES) {
    let results: VerifyResult[];
    try {
      results = verifyAllLabels(requestFor(c), { key: publicKey });
    } catch (e) {
      assert.fail(
        `verifyAllLabels threw on ${c.kind}: ${(e as Error).message} ` +
          `(input=${JSON.stringify(c.sigInput).slice(0, 160)})`,
      );
    }
    assert.ok(Array.isArray(results), `not an array (${c.kind})`);
    for (const r of results) assertResultShape(r, `verifyAllLabels/${c.kind}`);
  }
});

test("verifyAllLabels on an unparseable header returns MALFORMED_SIGNATURE_INPUT", () => {
  const req = requestFor({
    kind: "explicit",
    sigInput: "garbage with no equals",
    sig: VALID_SIG,
  });
  const results = verifyAllLabels(req, { key: publicKey });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "MALFORMED_SIGNATURE_INPUT");
});

test("parsers terminate quickly on malformed input (may throw, never hang)", () => {
  const inputs = CASES.map((c) => c.sigInput);
  let worst = 0;
  for (const input of inputs) {
    const fns: Array<() => unknown> = [
      () => parseSignatureInput(input, "sig1"),
      () => parseSignatureField(input, "sig1"),
      () => listSignatureLabels(input),
    ];
    for (const fn of fns) {
      const t0 = performance.now();
      try {
        fn();
      } catch {
        // Documented behavior: the parsers throw Error on malformed
        // input. The fuzz only requires they terminate promptly.
      }
      const dt = performance.now() - t0;
      if (dt > worst) worst = dt;
      assert.ok(
        dt < MAX_MS,
        `parser took ${dt.toFixed(1)}ms (>= ${MAX_MS}ms) on input ${JSON.stringify(
          input,
        ).slice(0, 120)}`,
      );
    }
  }
  console.log(`fuzz: parsers worst single call ${worst.toFixed(1)}ms`);
});
