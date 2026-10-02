import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  contentDigest,
  signRequest,
  verifyRequest,
  generateEd25519KeyPair,
} from "../src/index.js";

test("signature base golden vector", () => {
  const base = buildSignatureBase(
    ["@method", "@authority", "@path", "content-digest"],
    {
      method: "post",
      url: "https://API.example.com:443/v1/payments",
      headers: { "Content-Digest": "sha-512=:abc123:" },
    },
    { created: 1700000000, keyid: "k1", alg: "hmac-sha256" },
  );
  assert.equal(
    base,
    `"@method": POST\n` +
      `"@authority": api.example.com\n` + // WHATWG URL elides the default :443 port
      `"@path": /v1/payments\n` +
      `"content-digest": sha-512=:abc123:\n` +
      `"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"`,
  );
});

test("content-digest is deterministic (RFC 9530 sha-512)", () => {
  assert.equal(
    contentDigest("hello"),
    "sha-512=:m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==:",
  );
});

test("freshness: small clock skew accepted, large rejected", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const now = 1700000000;
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: now + 30 },
  );
  // 30s in the future is within the default 60s tolerance
  assert.equal(
    verifyRequest(signed, { key: publicKey, now }).ok,
    true,
  );
  // 1h in the future is not
  const signed2 = signRequest(
    { method: "GET", url: "https://api.example.com/v1/x", headers: {} },
    { keyId: "k", alg: "ed25519", key: privateKey, created: now + 3600 },
  );
  const res = verifyRequest(signed2, { key: publicKey, now });
  assert.equal(res.ok, false);
  assert.match(res.reason ?? "", /future/);
});
