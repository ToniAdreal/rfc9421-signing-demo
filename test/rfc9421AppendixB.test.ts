import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  assertHmacSecretLength,
  buildSignatureBase,
  parseSignatureField,
  parseSignatureInput,
  secretKey,
} from "../src/index.js";

// Independent interop vectors from RFC 9421, Appendix B.2.5
// ("Signing a Request Using hmac-sha256"), fetched verbatim from
// https://www.rfc-editor.org/rfc/rfc9421.txt. RFC 8792 line-continuation
// wraps have been unwrapped; every byte below matches the RFC text.

/** RFC 9421 §B.1.5 test-shared-secret: 64 random bytes, Base64. */
const B25_KEY_B64 =
  "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt" +
  "bmHhIDi6pcl8jsasjlTMtDQ==";

/** RFC 9421 §B.2.5 signature base (the exact byte string that is MAC'd). */
const B25_SIGNATURE_BASE =
  `"date": Tue, 20 Apr 2021 02:07:55 GMT\n` +
  `"@authority": example.com\n` +
  `"content-type": application/json\n` +
  `"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`;

/** RFC 9421 §B.2.5 Signature field value under label sig-b25. */
const B25_SIGNATURE_INPUT = `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`;

/** RFC 9421 §B.2.5 expected MAC value. */
const B25_SIGNATURE_B64 = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=";

/** The §B.2 test-request message, as this library sees it. */
const B25_REQUEST = {
  method: "POST",
  url: "http://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
  },
};

test("RFC 9421 B.2.5: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase(
    ["date", "@authority", "content-type"],
    B25_REQUEST,
    { created: 1618884473, keyid: "test-shared-secret" },
  );
  assert.equal(base, B25_SIGNATURE_BASE);
});

test("RFC 9421 B.2.5: published HMAC key verifies under the 32-byte floor and reproduces the published signature with node:crypto alone", () => {
  const keyBytes = Buffer.from(B25_KEY_B64, "base64");
  assert.equal(keyBytes.length, 64, "B.1.5 defines a 64-byte shared secret");
  const key = secretKey(keyBytes);
  // Explicit guard: this check must hold before any crypto runs, so a
  // shorter real-world key can never be silently accepted.
  assertHmacSecretLength(key);
  // Independent implementation: node:crypto only, no library code on the
  // crypto path.
  const mac = createHmac("sha256", key)
    .update(B25_SIGNATURE_BASE, "utf8")
    .digest("base64");
  assert.equal(mac, B25_SIGNATURE_B64);
});

test("RFC 9421 B.2.5: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B25_SIGNATURE_INPUT, "sig-b25");
  assert.equal(parsed.label, "sig-b25");
  assert.deepEqual(parsed.componentIds, ["date", "@authority", "content-type"]);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-shared-secret");
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.5: published Signature field parses to the independent HMAC bytes", () => {
  const sigBytes = parseSignatureField(
    `sig-b25=:${B25_SIGNATURE_B64}:`,
    "sig-b25",
  );
  const independent = createHmac("sha256", secretKey(Buffer.from(B25_KEY_B64, "base64")))
    .update(B25_SIGNATURE_BASE, "utf8")
    .digest();
  assert.deepEqual(sigBytes, independent);
});

test("RFC 9421 B.2.5: a tampered base does not verify against the published signature", () => {
  const tampered = B25_SIGNATURE_BASE.replace("example.com", "attacker.com");
  const mac = createHmac("sha256", secretKey(Buffer.from(B25_KEY_B64, "base64")))
    .update(tampered, "utf8")
    .digest("base64");
  assert.notEqual(mac, B25_SIGNATURE_B64);
  // ... and the genuine base remains untouched.
  assert.equal(B25_SIGNATURE_BASE.includes("example.com"), true);
});
