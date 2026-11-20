import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  signatureInputValue,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@query"];

function makeReq(url: string) {
  return { method: "GET", url, headers: {} };
}

test("sign→verify round-trip with @query covered", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items?limit=10&cursor=abc"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  assert.match(signed.headers["signature-input"], /"@query"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("tampered query value fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items?limit=10"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const tampered = { ...signed, url: "https://api.example.com/v1/items?limit=999" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("added query parameter on a no-query signature fails", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  // @query was "?" when signed (RFC 9421 §2.2.7: absent query binds
  // the bare "?"); a non-empty query must now fail.
  const tampered = { ...signed, url: "https://api.example.com/v1/items?x=1" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("URL without a query string verifies (@query is \"?\", RFC 9421 §2.2.7)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("golden signature base contains the \"@query\": \"?a=1\" line", () => {
  const base = buildSignatureBase(
    ["@method", "@query", "@path"],
    makeReq("https://api.example.com/items?a=1"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": GET\n` +
      `"@query": ?a=1\n` +
      `"@path": /items\n` +
      `"@signature-params": ("@method" "@query" "@path");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("golden signature base with no query emits a bare \"?\" \"@query\" line", () => {
  const base = buildSignatureBase(
    ["@method", "@query"],
    makeReq("https://api.example.com/items"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": GET\n` +
      `"@query": ?\n` +
      `"@signature-params": ("@method" "@query");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("bare trailing \"?\" (empty query) also binds \"?\"", () => {
  // WHATWG URL reports a bare "?" as search === "", exactly like no
  // query at all — both take "?" under RFC 9421 §2.2.7.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items?"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  const base = buildSignatureBase(
    ["@method", "@query"],
    makeReq("https://api.example.com/items?"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": GET\n` +
      `"@query": ?\n` +
      `"@signature-params": ("@method" "@query");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("@request-target with no query still has no trailing \"?\"", () => {
  // §2.2.5 origin form keeps the query out entirely when absent —
  // the "?" default belongs to @query alone, not to @request-target.
  const base = buildSignatureBase(
    ["@method", "@request-target"],
    makeReq("https://api.example.com/items"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": GET\n` +
      `"@request-target": /items\n` +
      `"@signature-params": ("@method" "@request-target");created=1700000000;keyid="k1";alg="ed25519"`,
  );
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@request-target", "@query"],
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("signature minted under the old empty-string @query no longer verifies", () => {
  // Breaking-change pin (backlog #1277): a no-query @query signature
  // built with the pre-fix "" line must fail now that the library
  // binds "?" — the caller must re-sign. Hand-built with the public
  // signature-base primitives, the way a foreign signer would send it.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const req = makeReq("https://api.example.com/v1/items");
  const params = { created: CREATED, keyid: "k1", alg: "ed25519" };
  const oldBase =
    `"@method": GET\n` +
    `"@query": \n` +
    `"@signature-params": ("@method" "@query");created=1700000000;keyid="k1";alg="ed25519"`;
  const sig = edSign(null, Buffer.from(oldBase, "utf8"), privateKey);
  const signed = {
    ...req,
    headers: {
      "signature-input": signatureInputValue("sig1", ["@method", "@query"], params),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("@query is order-sensitive (no query normalization)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items?a=1&b=2"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const reordered = { ...signed, url: "https://api.example.com/v1/items?b=2&a=1" };
  const res = verifyRequest(reordered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("percent-encoded query round-trips verbatim", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/search?q=hello%20world"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: COVERED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("@query component id is matched case-insensitively on the wire", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(makeReq("https://api.example.com/v1/items?page=3"), {
    keyId: "q1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@QUERY"],
  });
  assert.match(signed.headers["signature-input"], /"@query"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});
