import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
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
  // @query was "" when signed; a non-empty query must now fail.
  const tampered = { ...signed, url: "https://api.example.com/v1/items?x=1" };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("URL without a query string verifies (@query is the empty string)", () => {
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

test("golden signature base with no query emits an empty \"@query\" line", () => {
  const base = buildSignatureBase(
    ["@method", "@query"],
    makeReq("https://api.example.com/items"),
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"@method": GET\n` +
      `"@query": \n` +
      `"@signature-params": ("@method" "@query");created=1700000000;keyid="k1";alg="ed25519"`,
  );
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
