import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, createVerify, verify as edVerify } from "node:crypto";
import {
  assertHmacSecretLength,
  buildSignatureBase,
  importPublicKey,
  parseSignatureField,
  parseSignatureInput,
  secretKey,
  verifyRequest,
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

// ---------------------------------------------------------------------------
// Appendix B.2.6 (ed25519) and B.2.4 (ecdsa-p256-sha256) — added later.
// Section-number note: in the published RFC, B.2.4 is the ecdsa-p256
// response example and B.2.6 is the ed25519 request example (B.2.3 is an
// rsa-pss-sha512 example). An earlier backlog entry mislabeled these two
// vectors as "B.2.4 (ed25519) / B.2.3 (ecdsa)"; the values below are the
// RFC's ed25519 and ecdsa-p256 vectors under their correct numbers,
// fetched from https://www.rfc-editor.org/rfc/rfc9421.txt with RFC 8792
// line-continuation wraps unwrapped.
// ---------------------------------------------------------------------------

/** RFC 9421 §B.1.4 test-key-ed25519 public key, PEM (SPKI). */
const ED25519_PUB_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=\n" +
  "-----END PUBLIC KEY-----\n";

/** RFC 9421 §B.1.3 test-key-ecc-p256 public key, PEM (SPKI). */
const P256_PUB_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf\n" +
  "w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==\n" +
  "-----END PUBLIC KEY-----\n";

/** RFC 9421 §B.2.6 signature base. */
const B26_SIGNATURE_BASE =
  `"date": Tue, 20 Apr 2021 02:07:55 GMT\n` +
  `"@method": POST\n` +
  `"@path": /foo\n` +
  `"@authority": example.com\n` +
  `"content-type": application/json\n` +
  `"content-length": 18\n` +
  `"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`;

const B26_SIGNATURE_INPUT = `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`;
const B26_SIGNATURE_B64 =
  "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1" +
  "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";

const B26_COMPONENTS = [
  "date",
  "@method",
  "@path",
  "@authority",
  "content-type",
  "content-length",
];

const B26_REQUEST = {
  method: "POST",
  url: "http://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-length": "18",
  },
};

test("RFC 9421 B.2.6: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase(B26_COMPONENTS, B26_REQUEST, {
    created: 1618884473,
    keyid: "test-key-ed25519",
  });
  assert.equal(base, B26_SIGNATURE_BASE);
});

test("RFC 9421 B.2.6: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B26_SIGNATURE_INPUT, "sig-b26");
  assert.equal(parsed.label, "sig-b26");
  assert.deepEqual(parsed.componentIds, B26_COMPONENTS);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-key-ed25519");
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.6: published ed25519 signature verifies with node:crypto alone", () => {
  const ok = edVerify(
    null,
    Buffer.from(B26_SIGNATURE_BASE, "utf8"),
    importPublicKey(ED25519_PUB_PEM),
    Buffer.from(B26_SIGNATURE_B64, "base64"),
  );
  assert.equal(ok, true);
});

test("RFC 9421 B.2.6: published signature verifies end-to-end via verifyRequest", () => {
  const signed = {
    ...B26_REQUEST,
    headers: {
      ...B26_REQUEST.headers,
      "signature-input": B26_SIGNATURE_INPUT,
      signature: `sig-b26=:${B26_SIGNATURE_B64}:`,
    },
  };
  // B.2.6 carries no `alg`; the library's legacy default for a missing
  // `alg` is ed25519, which is exactly this vector's algorithm.
  const res = verifyRequest(signed, {
    key: importPublicKey(ED25519_PUB_PEM),
    label: "sig-b26",
    now: 1618884473 + 60,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-key-ed25519");
  assert.equal(res.alg, "ed25519");
});

test("RFC 9421 B.2.6: tampering a covered component fails verification", () => {
  const signed = {
    ...B26_REQUEST,
    headers: {
      ...B26_REQUEST.headers,
      "content-length": "19",
      "signature-input": B26_SIGNATURE_INPUT,
      signature: `sig-b26=:${B26_SIGNATURE_B64}:`,
    },
  };
  const res = verifyRequest(signed, {
    key: importPublicKey(ED25519_PUB_PEM),
    label: "sig-b26",
    now: 1618884473 + 60,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

/** RFC 9421 §B.2 test-response Content-Digest value. */
const B24_CONTENT_DIGEST =
  "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41Q" +
  "JgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:";

/** RFC 9421 §B.2.4 signature base. */
const B24_SIGNATURE_BASE =
  `"@status": 200\n` +
  `"content-type": application/json\n` +
  `"content-digest": ${B24_CONTENT_DIGEST}\n` +
  `"content-length": 23\n` +
  `"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`;

const B24_SIGNATURE_INPUT = `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`;
const B24_SIGNATURE_B64 =
  "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK" +
  "ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==";

const B24_COMPONENTS = [
  "@status",
  "content-type",
  "content-digest",
  "content-length",
];

/** The §B.2 test-response message, as this library sees it. */
const B24_RESPONSE = {
  method: "GET",
  url: "http://example.com/foo?param=Value&Pet=dog",
  status: 200,
  headers: {
    "content-type": "application/json",
    "content-digest": B24_CONTENT_DIGEST,
    "content-length": "23",
  },
  body: '{"message": "good dog"}',
};

test("RFC 9421 B.2.4: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase(B24_COMPONENTS, B24_RESPONSE, {
    created: 1618884473,
    keyid: "test-key-ecc-p256",
  });
  assert.equal(base, B24_SIGNATURE_BASE);
});

test("RFC 9421 B.2.4: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B24_SIGNATURE_INPUT, "sig-b24");
  assert.equal(parsed.label, "sig-b24");
  assert.deepEqual(parsed.componentIds, B24_COMPONENTS);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-key-ecc-p256");
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.4: published signature is 64 octets and verifies under the RFC 9421 §3.3.4 encoding with node:crypto alone", () => {
  const sigBytes = parseSignatureField(
    `sig-b24=:${B24_SIGNATURE_B64}:`,
    "sig-b24",
  );
  // §3.3.4 defines the value as the raw concatenation of the two ECDSA
  // integers, each padded to 32 octets — 64 octets in total, not a
  // DER-encoded value.
  assert.equal(sigBytes.length, 64);
  const ok = createVerify("sha256")
    .update(B24_SIGNATURE_BASE, "utf8")
    .verify(
      { key: importPublicKey(P256_PUB_PEM), dsaEncoding: "ieee-p1363" },
      sigBytes,
    );
  assert.equal(ok, true);
  // Tampering a covered component breaks even this independent check.
  const tampered = createVerify("sha256")
    .update(B24_SIGNATURE_BASE.replace('"@status": 200', '"@status": 201'), "utf8")
    .verify(
      { key: importPublicKey(P256_PUB_PEM), dsaEncoding: "ieee-p1363" },
      sigBytes,
    );
  assert.equal(tampered, false);
});

test("RFC 9421 B.2.4: published signature verifies end-to-end via verifyRequest", () => {
  const signed = {
    ...B24_RESPONSE,
    headers: {
      ...B24_RESPONSE.headers,
      "signature-input": B24_SIGNATURE_INPUT,
      signature: `sig-b24=:${B24_SIGNATURE_B64}:`,
    },
  };
  // B.2.4 carries no `alg`; `algFallback: "infer"` resolves the P-256
  // key shape to ecdsa-p256-sha256. The published value is the raw
  // r||s encoding RFC 9421 §3.3.4 defines (64 octets, checked above) —
  // the same encoding this library now signs and verifies with, so the
  // official vector passes end-to-end. (Earlier versions expected DER
  // and rejected this vector; that divergence is fixed, not pinned.)
  const res = verifyRequest(signed, {
    key: importPublicKey(P256_PUB_PEM),
    label: "sig-b24",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-key-ecc-p256");
  assert.equal(res.alg, "ecdsa-p256-sha256");
});

test("RFC 9421 B.2.4: tampering a covered component fails end-to-end verification", () => {
  const signed = {
    ...B24_RESPONSE,
    headers: {
      ...B24_RESPONSE.headers,
      "content-length": "24",
      "signature-input": B24_SIGNATURE_INPUT,
      signature: `sig-b24=:${B24_SIGNATURE_B64}:`,
    },
  };
  const res = verifyRequest(signed, {
    key: importPublicKey(P256_PUB_PEM),
    label: "sig-b24",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.alg, "ecdsa-p256-sha256");
});
