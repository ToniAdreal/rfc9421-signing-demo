import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  canonicalizeStructuredFieldValueAs,
  generateEd25519KeyPair,
  serializeDictionaryMemberValue,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;

// ---------------------------------------------------------------------------
// Date (RFC 9651 §3.3.7 / §4.2.9 / §4.1.10)
// ---------------------------------------------------------------------------

test("Date item round-trips and canonicalizes (leading zeros, -0)", () => {
  assert.equal(canonicalizeStructuredFieldValue("@1659578233"), "@1659578233");
  assert.equal(canonicalizeStructuredFieldValue("@00042"), "@42");
  assert.equal(canonicalizeStructuredFieldValue("@-0"), "@0");
  assert.equal(canonicalizeStructuredFieldValue("@0"), "@0");
});

test("Negative Dates are valid per RFC 9651 §3.3.7 (a possibly negative delta)", () => {
  // §3.3.7: a Date is a (possibly negative) delta in seconds from
  // 1970-01-01T00:00:00Z; parsers MUST support years 1-9999, i.e.
  // -62,135,596,800 to 253,402,214,400. A negative Date is therefore
  // a real pre-epoch timestamp, not a malformed value.
  assert.equal(
    canonicalizeStructuredFieldValue("@-62135596800"),
    "@-62135596800",
  );
  assert.equal(canonicalizeStructuredFieldValue("@-1"), "@-1");
  assert.equal(
    canonicalizeStructuredFieldValue("@253402214400"),
    "@253402214400",
  );
});

test("Date in a Dictionary, a List, an Inner List, and as a parameter value", () => {
  assert.equal(
    canonicalizeStructuredFieldValue("created=@1659578233, expires=@1659581833"),
    "created=@1659578233, expires=@1659581833",
  );
  assert.equal(
    canonicalizeStructuredFieldValue("@1659578233, @1659581833"),
    "@1659578233, @1659581833",
  );
  assert.equal(
    canonicalizeStructuredFieldValue('(@1659578233 "x")'),
    '(@1659578233 "x")',
  );
  // A Date as a parameter value keeps its canonical form.
  assert.equal(
    canonicalizeStructuredFieldValue("x=1;when=@1659578233"),
    "x=1;when=@1659578233",
  );
});

test("Invalid Dates fail closed", () => {
  // Decimal, non-numeric, empty, and over the 15-digit Integer bound.
  for (const bad of ["@1.5", "@abc", "@", "@1000000000000000", "@-1000000000000000"]) {
    assert.throws(
      () => canonicalizeStructuredFieldValue(bad),
      /not a valid Structured Field value/,
      bad,
    );
  }
});

test("Date pins as an Item via the registry path; Dictionary member via ;key", () => {
  assert.equal(
    canonicalizeStructuredFieldValueAs("@1659578233", "item"),
    "@1659578233",
  );
  assert.throws(
    () => canonicalizeStructuredFieldValueAs("a=@1659578233", "item"),
    /not a valid Item Structured Field value/,
  );
  // ;key serializes the selected member with the strict rules, so a
  // Date member comes out as its canonical `@…` form.
  assert.equal(
    serializeDictionaryMemberValue("agent=@1659578233, other=1", "agent"),
    "@1659578233",
  );
});

// ---------------------------------------------------------------------------
// Display String (RFC 9651 §3.3.8 / §4.2.10 / §4.1.11)
// ---------------------------------------------------------------------------

test("Display String ASCII round-trip", () => {
  assert.equal(
    canonicalizeStructuredFieldValue('%"hello world"'),
    '%"hello world"',
  );
  assert.equal(canonicalizeStructuredFieldValue('%"%25"'), '%"%25"');
});

test("Display String non-ASCII round-trips (lowercase hex is canonical)", () => {
  // The §3.3.8 example: Fryslân.
  assert.equal(
    canonicalizeStructuredFieldValue('%"Frysl%c3%a2n"'),
    '%"Frysl%c3%a2n"',
  );
  assert.equal(
    canonicalizeStructuredFieldValue('%"M%c3%bcnchen"'),
    '%"M%c3%bcnchen"',
  );
});

test("Display String containing DQUOTE and backslash round-trips via percent-encoding", () => {
  // `"` and `\` inside the value travel as %22 / %5c on the wire;
  // the decoded value holds the literal characters. On
  // re-serialization the `"` stays %22 but the backslash comes back
  // raw: §4.1.11 percent-encodes only `%`, DQUOTE, and bytes outside
  // printable ASCII, and `\` (0x5c) is printable ASCII. The VALUE
  // round-trips; the canonical wire form is `%"a%22b\c"`.
  assert.equal(
    canonicalizeStructuredFieldValue('%"a%22b%5cc"'),
    '%"a%22b\\c"',
  );
  // A literal backslash byte (0x5c) is printable ASCII, so it is NOT
  // escaped on serialization — it round-trips raw.
  assert.equal(
    canonicalizeStructuredFieldValue('%"a\\b"'),
    '%"a\\b"',
  );
});

test("Uppercase percent-escapes fail (RFC 9651 §4.2.10 requires lowercase hex)", () => {
  for (const bad of ['%"%C3%A2"', '%"%C3%a2"', '%"a%2Fb"']) {
    assert.throws(
      () => canonicalizeStructuredFieldValue(bad),
      /not a valid Structured Field value/,
      bad,
    );
  }
});

test("Malformed percent-escapes fail closed", () => {
  for (const bad of ['%"%2"', '%"%zz"', '%"%2g"', '%"abc%2"', '%"%"']) {
    assert.throws(
      () => canonicalizeStructuredFieldValue(bad),
      /not a valid Structured Field value/,
      bad,
    );
  }
});

test("Percent-encoded bytes that are not valid UTF-8 fail closed", () => {
  for (const bad of ['%"%ff"', '%"%c3%28"', '%"%c3"', '%"%80"', '%"%ed%a0%80"']) {
    assert.throws(
      () => canonicalizeStructuredFieldValue(bad),
      /not a valid Structured Field value/,
      bad,
    );
  }
});

test("Raw non-ASCII and control characters fail closed in a Display String", () => {
  for (const bad of ['%"é"', '%"a\tb"', '%"a\x7fb"']) {
    assert.throws(
      () => canonicalizeStructuredFieldValue(bad),
      /not a valid Structured Field value/,
      JSON.stringify(bad),
    );
  }
});

test("Backslash is literal, not an escape, in Display Strings", () => {
  // `\"` does not escape the quote: the string ends at the DQUOTE
  // after the backslash and the trailing `b"` fails at the top level.
  assert.throws(
    () => canonicalizeStructuredFieldValue('%"a\\"b"'),
    /not a valid Structured Field value/,
  );
});

test("Display String with parameters and in a List", () => {
  assert.equal(
    canonicalizeStructuredFieldValue('%"M%c3%bcnchen";lang=de'),
    '%"M%c3%bcnchen";lang=de',
  );
  assert.equal(
    canonicalizeStructuredFieldValue('%"a", %"b"'),
    '%"a", %"b"',
  );
  assert.equal(
    canonicalizeStructuredFieldValue('label=%"M%c3%bcnchen"'),
    'label=%"M%c3%bcnchen"',
  );
});

// ---------------------------------------------------------------------------
// The RFC 8941 core types are unaffected
// ---------------------------------------------------------------------------

test("RFC 8941 core types are unaffected by the RFC 9651 additions", () => {
  assert.equal(canonicalizeStructuredFieldValue('"a", "b"'), '"a", "b"');
  assert.equal(canonicalizeStructuredFieldValue("007"), "7");
  assert.equal(canonicalizeStructuredFieldValue("1.5"), "1.500");
  assert.equal(canonicalizeStructuredFieldValue("?1"), "?1");
  assert.equal(canonicalizeStructuredFieldValue(":aGVsbG8=:"), ":aGVsbG8=:");
  assert.equal(canonicalizeStructuredFieldValue("a=1, b=2"), "a=1, b=2");
  assert.equal(canonicalizeStructuredFieldValue("tok"), "tok");
  // A bare `@`/`%` with nothing valid after them still fails closed.
  assert.throws(() => canonicalizeStructuredFieldValue("@"), /not a valid/);
  assert.throws(() => canonicalizeStructuredFieldValue("%"), /not a valid/);
});

// ---------------------------------------------------------------------------
// ;sf sign→verify round-trips (the interop case from backlog #926)
// ---------------------------------------------------------------------------

function makeReq(headers: Record<string, string>): RequestLike {
  return {
    method: "POST",
    url: "https://api.example.com/v1/charge",
    headers,
    body: "hello",
  };
}

function signSf(headers: Record<string, string>, covered: string[]) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeReq(headers), {
    keyId: "sf-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents: covered,
  });
  return { ...keys, signed };
}

test("sign→verify round-trip: Date header under ;sf", () => {
  const { publicKey, signed } = signSf(
    { "signature-agent": "@1659578233,  @1659581833" },
    ["@method", "signature-agent;sf"],
  );
  assert.equal(
    buildSignatureBase(
      ["signature-agent;sf"],
      makeReq({ "signature-agent": "@1659578233,  @1659581833" }),
      {},
    ),
    `"signature-agent";sf: @1659578233, @1659581833\n"@signature-params": ("signature-agent";sf)`,
  );
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
  // Re-spacing the wire value still verifies: the Dates canonicalize.
  const respaced = {
    ...signed,
    headers: { ...signed.headers, "signature-agent": "@1659578233, @1659581833" },
  };
  assert.equal(
    verifyRequest(respaced, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
});

test("sign→verify round-trip: Display String header under ;sf", () => {
  const { publicKey, signed } = signSf(
    { "signature-agent": '%"M%c3%bcnchen"' },
    ["@method", "signature-agent;sf"],
  );
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
});

test("tampering a ;sf Date value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signSf(
    { "signature-agent": "@1659578233" },
    ["@method", "signature-agent;sf"],
  );
  const tampered = {
    ...signed,
    headers: { ...signed.headers, "signature-agent": "@1659578234" },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampering a ;sf Display String value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signSf(
    { "signature-agent": '%"M%c3%bcnchen"' },
    ["@method", "signature-agent;sf"],
  );
  // Same percent-encoded form, different decoded content (n -> o).
  const tampered = {
    ...signed,
    headers: { ...signed.headers, "signature-agent": '%"M%c3%bcochen"' },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("sign→verify round-trip: Dictionary with a Date member via ;key", () => {
  const { publicKey, signed } = signSf(
    { "agent-timestamps": "created=@1659578233, expires=@1659581833" },
    ["@method", 'agent-timestamps;key="created"'],
  );
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "agent-timestamps": "created=@1659578234, expires=@1659581833",
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});
