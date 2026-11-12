import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  listSignatureLabels,
  parseSignatureInput,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;

function makeReq(url: string, headers: Record<string, string> = {}): RequestLike {
  return { method: "GET", url, headers };
}

// A hand-built Signature-Input value whose inner list carries a quoted
// parameter value containing ")". No signer can mint `;name="a)b"` for
// `@query-param` (a literal ")" is not a percent-encoded name, so the
// resolve step rightly refuses it), but the header is a well-formed
// Structured Field inner list, so the parser must return it whole —
// the semantic rejection belongs to the resolve step, not the parser.
function headerWithName(name: string): string {
  return (
    `sig1=("@query-param";name="${name}" "@method")` +
    `;created=${CREATED};keyid="k1";alg="ed25519"`
  );
}

for (const name of ["a)b", "a(b", "a)b(c"]) {
  test(`parseSignatureInput keeps a ")" inside ;name="${name}" instead of truncating the inner list`, () => {
    const parsed = parseSignatureInput(headerWithName(name), "sig1");
    assert.deepEqual(parsed.componentIds, [
      `@query-param;name="${name}"`,
      "@method",
    ]);
    assert.equal(parsed.params.created, CREATED);
    assert.equal(parsed.params.keyid, "k1");
    assert.equal(parsed.params.alg, "ed25519");
  });
}

test("parseSignatureInput keeps a ) after an escaped quote inside ;name", () => {
  const parsed = parseSignatureInput(
    `sig1=("@query-param";name="a\\"b)c" "@method");created=${CREATED};keyid="k1";alg="ed25519"`,
    "sig1",
  );
  assert.deepEqual(parsed.componentIds, [
    '@query-param;name="a\\"b)c"',
    "@method",
  ]);
});

test("parseSignatureInput keeps a ) after an escaped backslash inside ;name", () => {
  const parsed = parseSignatureInput(
    `sig1=("@query-param";name="a\\\\b)c" "@method");created=${CREATED};keyid="k1";alg="ed25519"`,
    "sig1",
  );
  assert.deepEqual(parsed.componentIds, [
    '@query-param;name="a\\\\b)c"',
    "@method",
  ]);
});

test("sign/verify round-trip covers a header field whose name contains )", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeReq("https://api.example.com/", {
    "x-a)b": "v1",
    host: "api.example.com",
  });
  const signed = signRequest(req, {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["x-a)b", "@method"],
  });
  // The minted wire form really does carry the ) inside quotes.
  assert.match(
    signed.headers["signature-input"] as string,
    /^sig1=\("x-a\)b" "@method"\);/,
  );
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, ["x-a)b", "@method"]);
});

test("tampering the ) -named header value fails as a signature mismatch, not a parse failure", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeReq("https://api.example.com/", {
    "x-a)b": "v1",
    host: "api.example.com",
  });
  const signed = signRequest(req, {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["x-a)b", "@method"],
  });
  const tampered = { ...signed, headers: { ...signed.headers, "x-a)b": "v2" } };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("verifyRequest rejects ;name=\"a)b\" semantically (base build), not as malformed input", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeReq("https://api.example.com/pay?order=42&amount=100", {
    host: "api.example.com",
  });
  const signed = signRequest(req, {
    keyId: "k1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ['@query-param;name="amount"', "@method"],
  });
  // Keep the real Signature bytes, swap only the covered component
  // name: the header now parses whole, and the resolve step — not the
  // parser — refuses the non-percent-encoded name.
  const swapped = (signed.headers["signature-input"] as string).replace(
    ';name="amount"',
    ';name="a)b"',
  );
  const res = verifyRequest(
    { ...signed, headers: { ...signed.headers, "signature-input": swapped } },
    { key: publicKey, now: CREATED + 60 },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
  assert.match(res.reason as string, /does not occur/);
});

test("parseSignatureInput still rejects a genuinely unterminated inner list", () => {
  assert.throws(
    () => parseSignatureInput('sig1=("@method"', "sig1"),
    (e: unknown) =>
      e instanceof Error &&
      e.message === "malformed Signature-Input: unterminated inner list",
  );
});

test("parseSignatureInput agrees with listSignatureLabels when a later label carries a ) in ;name", () => {
  const value =
    `sig1=("@method");created=${CREATED};keyid="k1";alg="ed25519", ` +
    headerWithName("a)b").replace(/^sig1=/, "sig2=");
  assert.deepEqual(listSignatureLabels(value), ["sig1", "sig2"]);
  const parsed1 = parseSignatureInput(value, "sig1");
  assert.deepEqual(parsed1.componentIds, ["@method"]);
  const parsed2 = parseSignatureInput(value, "sig2");
  assert.deepEqual(parsed2.componentIds, [
    '@query-param;name="a)b"',
    "@method",
  ]);
});

test("parseSignatureInput keeps a ) inside a quoted ;tag parameter value after the inner list", () => {
  const parsed = parseSignatureInput(
    `sig1=("@method");created=${CREATED};keyid="k1";alg="ed25519";tag="a)b"`,
    "sig1",
  );
  assert.deepEqual(parsed.componentIds, ["@method"]);
  assert.equal(parsed.params.tag, "a)b");
});
