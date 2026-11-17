import test from "node:test";
import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import {
  canonicalizeStructuredFieldValue,
  canonicalizeStructuredFieldValueAs,
  serializeDictionaryMemberValue,
  type StructuredFieldType,
} from "../src/index.js";

/**
 * Structured Fields fuzz (backlog #1199): `canonicalizeStructuredFieldValue`
 * (Dictionary → List → Item trial order), `canonicalizeStructuredFieldValueAs`
 * (pinned type), and `serializeDictionaryMemberValue` (Dictionary member
 * extraction) face adversarial input. The corpus is built from a fixed seed
 * (mulberry32) so every run sees the same inputs, and every case asserts an
 * either/or contract:
 *
 * - accepted → sanitized fixed point: re-canonicalizing the output returns
 *   byte-identical output, and a Dictionary member re-derived from the
 *   canonicalized value (or from a fresh `key=<member>` Dictionary) matches
 *   the first derivation;
 * - rejected → a plain `Error` (never TypeError/ReferenceError) whose
 *   message carries one of the known prefixes, so a malformed header can
 *   never be silently accepted or crash a caller with an exotic error.
 *
 * Timing guard (backlog #242 pattern, as in parserFuzz.test.ts): the corpus
 * MEDIAN per-call time against the same 50ms budget, plus a catastrophic
 * worst-case bound of 20x the budget, so one pathological input cannot hide
 * behind the median.
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

const SEED = 20261117;
const MAX_MS = 50;
/** Catastrophic single-case bound: 20x the median budget (see header). */
const CATASTROPHIC_MS = MAX_MS * 20;
const MEMBER_KEY = "a";
const SF_TYPES: readonly StructuredFieldType[] = [
  "dictionary",
  "list",
  "item",
];

/**
 * Load-insensitive timing guard (backlog #242): assert the median
 * per-call time stays under MAX_MS and no single case exceeds
 * CATASTROPHIC_MS.
 */
function assertTimingGuard(
  label: string,
  dts: readonly number[],
): { median: number; worst: number } {
  assert.ok(dts.length > 0, `${label}: no timing samples collected`);
  const sorted = [...dts].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const worst = sorted[sorted.length - 1];
  assert.ok(
    median < MAX_MS,
    `${label} median took ${median.toFixed(1)}ms (budget ${MAX_MS}ms)`,
  );
  assert.ok(
    worst < CATASTROPHIC_MS,
    `${label} worst case took ${worst.toFixed(1)}ms (catastrophic budget ${CATASTROPHIC_MS}ms)`,
  );
  return { median, worst };
}

/** Hand-built valid Structured Field values, one per shape the module owns. */
const VALID_BASES: readonly string[] = [
  // Integers and Decimals.
  "0",
  "42",
  "-7",
  "007",
  "-0",
  "123456789012345",
  "-123456789012345",
  "1.5",
  "-0.25",
  "12.345",
  "007.500",
  "999999999999.999",
  "0.001",
  "-12.000",
  // Strings.
  '""',
  '"hello"',
  '"a\\"b"',
  '"a\\\\b"',
  '"café"',
  '"a-b_c.d*e!f"',
  '"a b"',
  // Tokens.
  "token",
  "*",
  "a-b_c.d*e",
  "ABC123",
  "foo/bar",
  "t1",
  "a:b",
  "x~y",
  // Byte Sequences.
  ":aGk=:",
  ":AAE=:",
  "::",
  ":QUJD:",
  ":AA==:",
  // Booleans.
  "?1",
  "?0",
  // Dates.
  "@1700000000",
  "@-42",
  "@0",
  // Display Strings.
  '%"hello"',
  '%"%c3%a9"',
  '%"a%22b"',
  '%"%25"',
  '%"%5c"',
  '%"a b"',
  '%"%e2%82%ac"',
  // Items with parameters.
  "1;foo",
  "1;foo=2",
  '1;foo="bar"',
  'token;a=?1;b=:AAE=:;c=@5;d=%"x";e=1.5;f="s"',
  "?1;flag",
  "@5;created=1",
  // Inner Lists.
  "(1 2 3)",
  "()",
  '("a" "b");x=1',
  "(?1 ?0)",
  "(@1 @2)",
  "(1 2);a=1;b=2",
  // Lists.
  '1, 2, "three"',
  "(1 2), 3",
  "token1, token2;param",
  "?1, ?0",
  "@100, @200",
  ":AAE=:, :AAE=:",
  '%"a", %"b"',
  "1.5, -2.25, 0.001",
  // Dictionaries.
  "a=1, b=2",
  "a, b",
  "a=1;b=2",
  'a=(1 2), b="x"',
  "*=1",
  "a=?1",
  "a=@123",
  'a=%"x"',
  "a=:AAE=:",
  "a=1.5",
  'a="s"',
  "a, b=2;flag",
  "key1=1, key2=2, key3=3",
  "a=?0, b=?1;flag, c=(1 2)",
  // Leading/trailing whitespace (trimmed before parsing).
  "  a=1  ",
  "a=1,   b=2",
  "a=1,\tb=2",
  "\t1, 2\t",
];

/** Hand-built malformed shapes: the either/or contract must reject these. */
const SYNTH: readonly string[] = [
  "",
  " ",
  "\t",
  "  \t  ",
  "a=1,",
  ",a=1",
  "a=1,,b=2",
  "a==1",
  "a =1",
  "a= 1",
  "a = 1",
  "a=1;;b=2",
  "a=1;Foo=2",
  "A=1",
  "a=1, B=2",
  "1.2345",
  "1.",
  "1..5",
  ".5",
  "+1",
  "--1",
  "- 1",
  "1.5e3",
  "1234567890123.5",
  "1234567890123456",
  "99999999999999999999",
  "@1.5",
  "@",
  "@-",
  "@1.5e3",
  "@ 5",
  "?",
  "?2",
  "?12",
  "? 1",
  ":",
  ":YQ:",
  ":!!!:",
  ":AAE=",
  ":AAE=:extra",
  ":AA=E:",
  '"unterminated',
  '"a\\qb"',
  '"a\x01b"',
  '"a\x7fb"',
  "%",
  "%a",
  '%"unterminated',
  '%"%C3%A9"',
  '%"%ff"',
  '%"%c3"',
  '%"%c3%28"',
  '%"%zz"',
  '%"%1"',
  "(1 (2))",
  "(1 2",
  "((1))",
  "(1) (2",
  "(1 2))",
  "((1)",
  "(,)",
  "(1,,2)",
  "a=(1 2",
  "a=(1 (2))",
  "a=1 b=2",
  "a,b c",
  "a;b c",
  "1 2",
  "a=1, b=2,",
  "a=1, ,b=2",
  "a=1\x00",
  "\x00a=1",
  "a=1\nb=2",
  "a=1\rb=2",
  "a=1;b=2\x7f",
  '"a" "b"',
  "token@",
  "0x10",
  "1_000",
  "0.0001",
  "a=?2",
  ";a=1",
  "=1",
  "=",
  ",",
  "(",
  ")",
  ";",
  "?",
  "@",
  "%",
  ":",
  '"',
  "'",
  "\\",
  "a..b",
  "a.-b",
];

interface FuzzCase {
  kind: string;
  value: string;
}

const KEY_POOL = ["a", "b", "k1", "x", "y-z", "key_2", "a.b", "*", "ab"];
const TOKEN_POOL = ["token", "abc", "x", "a-b", "foo/bar", "*", "t1", "TOKEN"];
const DISPLAY_ESCAPES = ["%20", "%25", "%22", "%5c", "%c3%a9", "%e2%82%ac"];
const LETTERS = "abcdefghijklmnopqrstuvwxyz";
const TOKEN_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-_.".split("");

function buildCases(seed: number): FuzzCase[] {
  const rand = mulberry32(seed);
  const int = (n: number): number => Math.floor(rand() * n);
  const pick = <T>(arr: readonly T[]): T => arr[int(arr.length)];

  const NASTY = '";=(), \t\n\x00\x1f\x7f<>[]{}\\|~!#$%&*+^`@/?:\'é0123456789ab'
    .split("");

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

  function randBareItem(): string {
    switch (int(8)) {
      case 0: {
        // Integer: sometimes negative, sometimes leading zeros.
        const n = int(100000);
        const s = rand() < 0.3 ? `00${n}` : String(n);
        return rand() < 0.3 ? `-${s}` : s;
      }
      case 1: {
        // Decimal: 1-3 fraction digits, integer part up to 12 digits.
        const ip =
          rand() < 0.2 ? String(int(999999999999)) : String(int(1000));
        const fp = String(int(1000)).padStart(1 + int(3), "0").slice(0, 3);
        return `${rand() < 0.3 ? "-" : ""}${ip}.${fp}`;
      }
      case 2: {
        // String: printable content, escaped quote/backslash, non-ASCII.
        const len = int(13);
        let inner = "";
        for (let i = 0; i < len; i++) {
          const r = rand();
          if (r < 0.08) inner += '\\"';
          else if (r < 0.16) inner += "\\\\";
          else if (r < 0.24) inner += "é";
          else if (r < 0.32) inner += " ";
          else inner += LETTERS[int(LETTERS.length)];
        }
        return `"${inner}"`;
      }
      case 3: {
        // Token.
        return rand() < 0.5
          ? pick(TOKEN_POOL)
          : Array.from({ length: 1 + int(8) }, () =>
              pick(TOKEN_CHARS),
            ).join("");
      }
      case 4: {
        // Byte Sequence: random bytes, canonically base64-encoded.
        const bytes = Array.from({ length: int(7) }, () => int(256));
        return `:${Buffer.from(bytes).toString("base64")}:`;
      }
      case 5:
        return rand() < 0.5 ? "?1" : "?0";
      case 6: {
        // Date: sometimes negative.
        const n = int(2000000000);
        return `@${rand() < 0.2 ? "-" : ""}${n}`;
      }
      default: {
        // Display String: literal ASCII plus valid percent escapes.
        const len = int(10);
        let inner = "";
        for (let i = 0; i < len; i++) {
          const r = rand();
          if (r < 0.25) inner += pick(DISPLAY_ESCAPES);
          else if (r < 0.35) inner += " ";
          else inner += LETTERS[int(LETTERS.length)];
        }
        return `%"${inner}"`;
      }
    }
  }

  function randParams(): string {
    const n = int(4);
    let out = "";
    for (let i = 0; i < n; i++) {
      out += `;${pick(KEY_POOL)}`;
      if (rand() < 0.7) out += `=${randBareItem()}`;
    }
    return out;
  }

  function randItem(): string {
    return `${randBareItem()}${randParams()}`;
  }

  function randInnerList(): string {
    const n = int(5);
    const items = Array.from({ length: n }, () => randItem());
    return `(${items.join(" ")})${randParams()}`;
  }

  function randMember(): string {
    return rand() < 0.3 ? randInnerList() : randItem();
  }

  function randList(): string {
    const n = 1 + int(5);
    return Array.from({ length: n }, () => randMember()).join(", ");
  }

  function randDict(): string {
    const n = 1 + int(5);
    return Array.from({ length: n }, () => {
      const key = pick(KEY_POOL);
      return rand() < 0.25 ? key : `${key}=${randMember()}`;
    }).join(", ");
  }

  function randValue(): string {
    const r = rand();
    if (r < 0.25) return randItem();
    if (r < 0.55) return randList();
    if (r < 0.9) return randDict();
    return randInnerList();
  }

  const cases: FuzzCase[] = [];

  // 1) Hand-built valid bases, as-is.
  for (const v of VALID_BASES) cases.push({ kind: "valid-base", value: v });

  // 2) Truncations of valid bases (incl. mid-quote / mid-escape cuts).
  for (let i = 0; i < 150; i++) {
    const base = pick(VALID_BASES);
    cases.push({
      kind: "truncation",
      value: base.slice(0, int(base.length + 1)),
    });
  }

  // 3) Random byte-level mutations of valid bases.
  for (let i = 0; i < 400; i++)
    cases.push({
      kind: "mutation",
      value: mutate(pick(VALID_BASES), 1 + int(4)),
    });

  // 4) Structured values generated from the SF grammar (valid by build).
  for (let i = 0; i < 300; i++)
    cases.push({ kind: "generated", value: randValue() });

  // 5) Mutations of generated values.
  for (let i = 0; i < 200; i++)
    cases.push({
      kind: "generated-mutation",
      value: mutate(randValue(), 1 + int(3)),
    });

  // 6) Hand-built malformed shapes.
  for (const s of SYNTH) cases.push({ kind: "synthetic", value: s });

  // 7) Random byte soup as the whole value.
  const PRINTABLE = Array.from({ length: 95 }, (_, i) =>
    String.fromCharCode(32 + i),
  );
  const soup = (len: number): string => {
    let s = "";
    for (let i = 0; i < len; i++) s += pick(PRINTABLE);
    return s;
  };
  for (let i = 0; i < 300; i++)
    cases.push({ kind: "soup", value: soup(int(401)) });

  // 8) Pathological sizes: long values, deep nesting, thousands of members.
  const rep = (n: number, ch: string): string => ch.repeat(n);
  cases.push({ kind: "long-token", value: rep(5000, "x") });
  cases.push({ kind: "long-token", value: `a=${rep(8000, "x")}` });
  cases.push({ kind: "long-string", value: `"${rep(8000, "x")}"` });
  cases.push({
    kind: "deep-parens",
    value: `${rep(500, "(")}${rep(500, ")")}`,
  });
  cases.push({ kind: "deep-parens", value: rep(2000, "(") });
  cases.push({
    kind: "many-members",
    value: Array.from({ length: 3000 }, (_, i) => `"c${i}"`).join(", "),
  });
  cases.push({
    kind: "many-members",
    value: Array.from({ length: 500 }, (_, i) => `k${i}=${i}`).join(", "),
  });
  cases.push({
    kind: "many-members",
    value: `a=1${",garbage".repeat(1000)}`,
  });
  cases.push({
    kind: "many-params",
    value: `a=1;${Array.from({ length: 1000 }, (_, i) => `p${i}=1`).join(";")}`,
  });
  cases.push({ kind: "long-decimal", value: `1.${rep(5000, "5")}` });
  cases.push({ kind: "long-int", value: rep(100, "9") });
  cases.push({ kind: "long-int", value: `a=${rep(100, "9")}` });
  cases.push({ kind: "unterminated-string", value: `"${rep(8000, "x")}` });
  cases.push({
    kind: "long-display-string",
    value: `%"${rep(4000, "%c3")}"`,
  });
  cases.push({
    kind: "many-members",
    value: `a=1, b=2, ${"c=3, ".repeat(500)}`,
  });
  cases.push({ kind: "nul-byte", value: "a=1\x00" });

  return cases;
}

const CASES = buildCases(SEED);

type EntryPoint =
  | { name: "trial" }
  | { name: "as"; type: StructuredFieldType }
  | { name: "member"; key: string };

const ENTRY_POINTS: readonly EntryPoint[] = [
  { name: "trial" },
  { name: "as", type: "dictionary" },
  { name: "as", type: "list" },
  { name: "as", type: "item" },
  { name: "member", key: MEMBER_KEY },
];

function entryLabel(ep: EntryPoint): string {
  return ep.name === "as" ? `as:${ep.type}` : ep.name;
}

function callEntry(ep: EntryPoint, value: string): string {
  switch (ep.name) {
    case "trial":
      return canonicalizeStructuredFieldValue(value);
    case "as":
      return canonicalizeStructuredFieldValueAs(value, ep.type);
    case "member":
      return serializeDictionaryMemberValue(value, ep.key);
  }
}

/** The only error-message prefixes the three entry points may produce. */
const ERROR_PREFIXES: readonly string[] = [
  "empty value is not a valid",
  "not a valid ",
  "dictionary member ",
  "invalid Structured Field type ",
];

/**
 * A rejection must be a plain `Error` with a clear prefix — never a
 * TypeError/ReferenceError escaping the parser, never a bare string.
 * Returns the message for the outcome fingerprint.
 */
function assertPlainError(err: unknown, where: string): string {
  assert.ok(
    err instanceof Error,
    `${where}: threw a non-Error: ${String(err)}`,
  );
  assert.equal(
    err.name,
    "Error",
    `${where}: escaped a ${err.name} instead of a plain Error: ${err.message}`,
  );
  assert.ok(err.message.length > 0, `${where}: error with an empty message`);
  assert.ok(
    ERROR_PREFIXES.some((p) => err.message.startsWith(p)),
    `${where}: error without a clear prefix: ${JSON.stringify(err.message)}`,
  );
  return err.message;
}

/**
 * An accepted value must be a sanitized fixed point: re-running the same
 * entry point on the output returns byte-identical output. The member
 * path is the exception: a member serialization is not itself a
 * Dictionary value, so its fixed point is re-derivation from a fresh
 * `key=<member>` Dictionary instead of re-running the member lookup on it.
 */
function assertFixedPoint(
  ep: EntryPoint,
  out: string,
  where: string,
): void {
  assert.ok(out.length > 0, `${where}: accepted an empty serialization`);
  if (ep.name === "member") {
    const rederived = serializeDictionaryMemberValue(
      `${MEMBER_KEY}=${out}`,
      MEMBER_KEY,
    );
    assert.equal(
      rederived,
      out,
      `${where}: member does not re-derive from a fresh dictionary — first ${JSON.stringify(out)}, re-derived ${JSON.stringify(rederived)}`,
    );
    return;
  }
  const again = callEntry(ep, out);
  assert.equal(
    again,
    out,
    `${where}: not a fixed point — first ${JSON.stringify(out)}, second ${JSON.stringify(again)}`,
  );
}

/**
 * Run every entry point over every case, asserting the either/or contract
 * and (optionally) collecting per-call timings. Returns the outcome
 * fingerprint: one `label=ok:<output>` / `label=err:<message>` string per
 * entry point, joined per case — the determinism check compares these.
 */
function runCorpus(cases: readonly FuzzCase[], dts?: number[]): string[] {
  const fingerprint: string[] = [];
  for (const c of cases) {
    const perCase: string[] = [];
    let trialOut: string | undefined;
    let memberOut: string | undefined;
    for (const ep of ENTRY_POINTS) {
      const label = entryLabel(ep);
      const where = `${c.kind}/${label} (value=${JSON.stringify(c.value).slice(0, 160)})`;
      const t0 = performance.now();
      let out: string | undefined;
      let errMsg: string | undefined;
      try {
        out = callEntry(ep, c.value);
      } catch (err) {
        errMsg = assertPlainError(err, where);
      } finally {
        if (dts !== undefined) dts.push(performance.now() - t0);
      }
      if (out !== undefined) {
        assertFixedPoint(ep, out, where);
        perCase.push(`${label}=ok:${out}`);
        if (ep.name === "trial") trialOut = out;
        if (ep.name === "member") memberOut = out;
      } else {
        perCase.push(`${label}=err:${errMsg}`);
      }
    }
    // Cross-check: a member derived from the raw value must match the
    // member derived from the canonicalized value (Dictionary is tried
    // first, so a Dictionary value canonicalizes as a Dictionary).
    if (trialOut !== undefined && memberOut !== undefined) {
      const fromCanonical = serializeDictionaryMemberValue(
        trialOut,
        MEMBER_KEY,
      );
      assert.equal(
        fromCanonical,
        memberOut,
        `${c.kind}/member-vs-trial (value=${JSON.stringify(c.value).slice(0, 160)}): member from raw ${JSON.stringify(memberOut)} differs from member from canonicalized ${JSON.stringify(fromCanonical)}`,
      );
    }
    fingerprint.push(perCase.join("|"));
  }
  return fingerprint;
}

test("fuzz corpus has at least 1500 cases", () => {
  assert.ok(CASES.length >= 1500, `only ${CASES.length} cases`);
  const kinds = new Map<string, number>();
  for (const c of CASES) kinds.set(c.kind, (kinds.get(c.kind) ?? 0) + 1);
  console.log(
    `structured-fields fuzz: ${CASES.length} cases (${[...kinds.entries()].map(([k, n]) => `${k} ${n}`).join(", ")})`,
  );
});

test("hand-built valid bases all canonicalize to a fixed point", () => {
  for (const v of VALID_BASES) {
    const out = canonicalizeStructuredFieldValue(v);
    assert.equal(
      canonicalizeStructuredFieldValue(out),
      out,
      `valid base not a fixed point: ${JSON.stringify(v)} -> ${JSON.stringify(out)}`,
    );
    // A base accepted by the trial order must also be a fixed point
    // under every pinned type that accepts it.
    for (const type of SF_TYPES) {
      try {
        const asOut = canonicalizeStructuredFieldValueAs(v, type);
        assert.equal(
          canonicalizeStructuredFieldValueAs(asOut, type),
          asOut,
          `valid base not a fixed point as ${type}: ${JSON.stringify(v)} -> ${JSON.stringify(asOut)}`,
        );
      } catch (err) {
        // A pinned type may legitimately refuse a value of another
        // shape; the rejection itself must still be a plain Error.
        assertPlainError(err, `valid-base/as:${type}`);
      }
    }
  }
});

test("structured field parsers/serializers hold the either/or contract on the fuzz corpus", () => {
  const dts: number[] = [];
  const fingerprint = runCorpus(CASES, dts);
  const accepted = fingerprint.filter((f) => f.includes("=ok:")).length;
  const { median, worst } = assertTimingGuard("structured-fields fuzz", dts);
  console.log(
    `structured-fields fuzz: ${CASES.length} cases, ${accepted} with at least one accepted entry point, median ${median.toFixed(3)}ms/call, worst ${worst.toFixed(1)}ms/call`,
  );
});

test("known-illegal values are rejected, never silently accepted", () => {
  // Every value here must be refused by all five entry points: an
  // uppercase percent-escape, a Decimal Date, a control character in a
  // String, an illegal escape, an unterminated String, over-long
  // numbers, a bad Boolean, bad base64, a nested Inner List, and the
  // other strict-parsing failures of RFC 9651 §4.2.
  const MUST_REJECT: readonly string[] = [
    '%"%C3%A9"',
    "@1.5",
    '"a\x01b"',
    '"a\\qb"',
    '"unterminated',
    "1.2345",
    "1234567890123.5",
    "1234567890123456",
    "?2",
    ":YQ:",
    ":!!!:",
    "(1 (2))",
    "a==1",
    "a=1,",
    ",a=1",
    "",
    "   ",
    "a =1",
    "@",
    "%",
    ":",
    "?",
    '%"%ff"',
    '%"%c3"',
    '%"%c3%28"',
    "1..5",
    "--1",
    "+1",
    "a;Foo=1",
    "A=1",
    "1.5e3",
    "a=1;;b=2",
    "(1 2",
    "a=(1 2",
    '"a" "b"',
    "0x10",
    "1_000",
    "0.0001",
    "a=?2",
    "99999999999999999999",
    "a=1 b=2",
  ];
  for (const v of MUST_REJECT) {
    for (const ep of ENTRY_POINTS) {
      assert.throws(
        () => callEntry(ep, v),
        (err: unknown) => {
          assertPlainError(err, `must-reject/${entryLabel(ep)}`);
          return true;
        },
        `must-reject value was accepted by ${entryLabel(ep)}: ${JSON.stringify(v)}`,
      );
    }
  }
});

test("corpus is deterministic: same seed rebuilds identical cases and outcomes", () => {
  const rebuilt = buildCases(SEED);
  assert.deepEqual(rebuilt, CASES, "same seed rebuilt different cases");
  const first = runCorpus(CASES);
  const second = runCorpus(rebuilt);
  assert.deepEqual(second, first, "same seed produced different outcomes");
});
