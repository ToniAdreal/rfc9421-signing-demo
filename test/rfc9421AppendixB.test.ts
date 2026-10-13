import test from "node:test";
import assert from "node:assert/strict";
import {
  constants,
  createHmac,
  createVerify,
  verify as edVerify,
} from "node:crypto";
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
// Appendix B.2.6 (ed25519), B.2.4 (ecdsa-p256-sha256), and B.2.3
// (rsa-pss-sha512) — added later.
// Section-number note: in the published RFC, B.2.4 is the ecdsa-p256
// response example, B.2.6 is the ed25519 request example, and B.2.3 is
// the rsa-pss-sha512 full-coverage request example. An earlier backlog
// entry mislabeled the ed25519/ecdsa vectors as "B.2.4 (ed25519) /
// B.2.3 (ecdsa)"; the values below are the RFC's vectors under their
// correct numbers, fetched from
// https://www.rfc-editor.org/rfc/rfc9421.txt with RFC 8792
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

// ---------------------------------------------------------------------------
// Appendix B.2.3 (rsa-pss-sha512, full coverage) — the last Appendix B
// request vector not covered above. Values fetched verbatim from
// https://www.rfc-editor.org/rfc/rfc9421.txt (§B.1.2 key, §B.2 test
// request, §B.2.3 base and signature) with RFC 8792 line-continuation
// wraps unwrapped. RSA-PSS is probabilistic: the published value can
// be validated against the published key, but a fresh signature over
// the same base is not expected to equal it (RFC §7.3.5).
// ---------------------------------------------------------------------------

/** RFC 9421 §B.1.2 test-key-rsa-pss public key, PEM (SPKI). */
const RSA_PSS_PUB_PEM =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2\n" +
  "+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+\n" +
  "oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq\n" +
  "gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W\n" +
  "Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4\n" +
  "aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI\n" +
  "2wIDAQAB\n" +
  "-----END PUBLIC KEY-----\n";

/** RFC 9421 §B.2 test-request Content-Digest value. */
const B23_CONTENT_DIGEST =
  "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX" +
  "+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

/** RFC 9421 §B.2.3 signature base. */
const B23_SIGNATURE_BASE =
  `"date": Tue, 20 Apr 2021 02:07:55 GMT\n` +
  `"@method": POST\n` +
  `"@path": /foo\n` +
  `"@query": ?param=Value&Pet=dog\n` +
  `"@authority": example.com\n` +
  `"content-type": application/json\n` +
  `"content-digest": ${B23_CONTENT_DIGEST}\n` +
  `"content-length": 18\n` +
  `"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`;

const B23_SIGNATURE_INPUT = `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`;
const B23_SIGNATURE_B64 =
  "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yB" +
  "iMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fU" +
  "xN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1" +
  "pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9" +
  "bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5Z" +
  "JzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==";

const B23_COMPONENTS = [
  "date",
  "@method",
  "@path",
  "@query",
  "@authority",
  "content-type",
  "content-digest",
  "content-length",
];

/** The §B.2 test-request message, as this library sees it. */
const B23_REQUEST = {
  method: "POST",
  url: "http://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-digest": B23_CONTENT_DIGEST,
    "content-length": "18",
  },
  body: '{"hello": "world"}',
};

test("RFC 9421 B.2.3: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase(B23_COMPONENTS, B23_REQUEST, {
    created: 1618884473,
    keyid: "test-key-rsa-pss",
  });
  assert.equal(base, B23_SIGNATURE_BASE);
});

test("RFC 9421 B.2.3: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B23_SIGNATURE_INPUT, "sig-b23");
  assert.equal(parsed.label, "sig-b23");
  assert.deepEqual(parsed.componentIds, B23_COMPONENTS);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-key-rsa-pss");
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.3: published signature is 256 octets and verifies under RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt) with node:crypto alone", () => {
  const sigBytes = parseSignatureField(
    `sig-b23=:${B23_SIGNATURE_B64}:`,
    "sig-b23",
  );
  // A 2048-bit RSA modulus yields a 256-octet signature value.
  assert.equal(sigBytes.length, 256);
  const pss = {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 64,
  };
  const ok = createVerify("sha512")
    .update(B23_SIGNATURE_BASE, "utf8")
    .verify(pss, sigBytes);
  assert.equal(ok, true);
  // Tampering a covered component breaks even this independent check.
  const tampered = createVerify("sha512")
    .update(B23_SIGNATURE_BASE.replace('"@path": /foo', '"@path": /bar'), "utf8")
    .verify(pss, sigBytes);
  assert.equal(tampered, false);
});

test("RFC 9421 B.2.3: published signature verifies end-to-end via verifyRequest", () => {
  const signed = {
    ...B23_REQUEST,
    headers: {
      ...B23_REQUEST.headers,
      "signature-input": B23_SIGNATURE_INPUT,
      signature: `sig-b23=:${B23_SIGNATURE_B64}:`,
    },
  };
  // B.2.3 carries no `alg`; `algFallback: "infer"` resolves the RSA
  // key shape to rsa-pss-sha512 (RFC 9421 §3.3.1) — the only RSA
  // padding key shape alone can imply.
  const res = verifyRequest(signed, {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    label: "sig-b23",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-key-rsa-pss");
  assert.equal(res.alg, "rsa-pss-sha512");
});

test("RFC 9421 B.2.3: tampering a covered component fails end-to-end verification", () => {
  const signed = {
    ...B23_REQUEST,
    headers: {
      ...B23_REQUEST.headers,
      "content-length": "19",
      "signature-input": B23_SIGNATURE_INPUT,
      signature: `sig-b23=:${B23_SIGNATURE_B64}:`,
    },
  };
  const res = verifyRequest(signed, {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    label: "sig-b23",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.alg, "rsa-pss-sha512");
});

// ---------------------------------------------------------------------------
// Appendix B.2.1 (rsa-pss-sha512, minimal coverage) — the empty covered-
// components baseline. Values taken from the RFC text (§B.1.2 key,
// §B.2 test request, §B.2.1 base and signature) with RFC 8792 wraps
// unwrapped. This vector covers no message components at all: its base
// is a single @signature-params line carrying created, keyid and a
// nonce. RSA-PSS is probabilistic (RFC §7.3.5): the published value is
// validated against the published key, not reproduced by re-signing.
// ---------------------------------------------------------------------------

/** RFC 9421 §B.2.1 signature base. */
const B21_SIGNATURE_BASE = `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`;

const B21_SIGNATURE_INPUT = `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`;
const B21_NONCE = "b3k2pp5k7z-50gnwp.yemd";
const B21_SIGNATURE_B64 =
  "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopem" +
  "LJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG" +
  "52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx" +
  "2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6" +
  "UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3" +
  "+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==";

/** The §B.2 test-request message, as this library sees it. */
const B21_REQUEST = {
  method: "POST",
  url: "http://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-digest": B23_CONTENT_DIGEST,
    "content-length": "18",
  },
  body: '{"hello": "world"}',
};

test("RFC 9421 B.2.1: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase([], B21_REQUEST, {
    created: 1618884473,
    keyid: "test-key-rsa-pss",
    nonce: B21_NONCE,
  });
  assert.equal(base, B21_SIGNATURE_BASE);
});

test("RFC 9421 B.2.1: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B21_SIGNATURE_INPUT, "sig-b21");
  assert.equal(parsed.label, "sig-b21");
  assert.deepEqual(parsed.componentIds, []);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-key-rsa-pss");
  assert.equal(parsed.params.nonce, B21_NONCE);
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.1: published signature is 256 octets and verifies under RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt) with node:crypto alone", () => {
  const sigBytes = parseSignatureField(
    `sig-b21=:${B21_SIGNATURE_B64}:`,
    "sig-b21",
  );
  assert.equal(sigBytes.length, 256);
  const pss = {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 64,
  };
  const ok = createVerify("sha512")
    .update(B21_SIGNATURE_BASE, "utf8")
    .verify(pss, sigBytes);
  assert.equal(ok, true);
  // Flipping one signature octet breaks even this independent check.
  const mutated = Buffer.from(sigBytes);
  mutated[0] ^= 0x01;
  const bad = createVerify("sha512")
    .update(B21_SIGNATURE_BASE, "utf8")
    .verify(pss, mutated);
  assert.equal(bad, false);
  // The nonce is part of @signature-params, so tampering it also
  // breaks the independent check.
  const tampered = createVerify("sha512")
    .update(B21_SIGNATURE_BASE.replace(B21_NONCE, "attacker-nonce"), "utf8")
    .verify(pss, sigBytes);
  assert.equal(tampered, false);
});

test("RFC 9421 B.2.1: published signature verifies end-to-end via verifyRequest", () => {
  const signed = {
    ...B21_REQUEST,
    headers: {
      ...B21_REQUEST.headers,
      "signature-input": B21_SIGNATURE_INPUT,
      signature: `sig-b21=:${B21_SIGNATURE_B64}:`,
    },
  };
  // B.2.1 carries no `alg`; `algFallback: "infer"` resolves the RSA
  // key shape to rsa-pss-sha512, as with B.2.3.
  const res = verifyRequest(signed, {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    label: "sig-b21",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-key-rsa-pss");
  assert.equal(res.alg, "rsa-pss-sha512");
  assert.equal(res.nonce, B21_NONCE);
});

test("RFC 9421 B.2.1: tampering the nonce fails end-to-end verification", () => {
  // No message component is covered, so there is no covered component
  // to tamper; the nonce is the vector's authenticated parameter, and
  // changing it on the wire rebuilds a different signature base.
  const signed = {
    ...B21_REQUEST,
    headers: {
      ...B21_REQUEST.headers,
      "signature-input": B21_SIGNATURE_INPUT.replace(B21_NONCE, "attacker-nonce"),
      signature: `sig-b21=:${B21_SIGNATURE_B64}:`,
    },
  };
  const res = verifyRequest(signed, {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    label: "sig-b21",
    now: 1618884473 + 60,
    algFallback: "infer",
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
  assert.equal(res.alg, "rsa-pss-sha512");
});

// ---------------------------------------------------------------------------
// Appendix B.2.2 (rsa-pss-sha512, selective coverage) — covers only
// @authority, content-digest, and one named query parameter, plus a
// tag parameter. Values taken from the RFC text (key in B.1.2, test
// request in B.2, base and signature in B.2.2) with RFC 8792 wraps
// unwrapped. RSA-PSS is probabilistic: validate the published value
// against the published key, do not re-sign and compare.
// ---------------------------------------------------------------------------

/** RFC 9421 B.2.2 signature base. */
const B22_SIGNATURE_BASE =
  `"@authority": example.com\n` +
  `"content-digest": ${B23_CONTENT_DIGEST}\n` +
  `"@query-param";name="Pet": dog\n` +
  `"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`;

const B22_SIGNATURE_INPUT = `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`;
const B22_SIGNATURE_B64 =
  "LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQ" +
  "EdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT" +
  "8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SA" +
  "RYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd" +
  "4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoK" +
  "UqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==";

const B22_COMPONENTS = [
  "@authority",
  "content-digest",
  '@query-param;name="Pet"',
];

/** The B.2 test-request message, as this library sees it. */
const B22_REQUEST = {
  method: "POST",
  url: "http://example.com/foo?param=Value&Pet=dog",
  headers: {
    date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "content-type": "application/json",
    "content-digest": B23_CONTENT_DIGEST,
    "content-length": "18",
  },
  body: '{"hello": "world"}',
};

function b22Signed(overrides: Record<string, unknown> = {}) {
  return {
    ...B22_REQUEST,
    ...overrides,
    headers: {
      ...B22_REQUEST.headers,
      ...((overrides.headers as Record<string, string> | undefined) ?? {}),
      "signature-input": B22_SIGNATURE_INPUT,
      signature: `sig-b22=:${B22_SIGNATURE_B64}:`,
    },
  };
}

test("RFC 9421 B.2.2: buildSignatureBase matches the published base byte-for-byte", () => {
  const base = buildSignatureBase(B22_COMPONENTS, B22_REQUEST, {
    created: 1618884473,
    keyid: "test-key-rsa-pss",
    tag: "header-example",
  });
  assert.equal(base, B22_SIGNATURE_BASE);
});

test("RFC 9421 B.2.2: published Signature-Input parses to the exact components and parameters", () => {
  const parsed = parseSignatureInput(B22_SIGNATURE_INPUT, "sig-b22");
  assert.equal(parsed.label, "sig-b22");
  assert.deepEqual(parsed.componentIds, B22_COMPONENTS);
  assert.equal(parsed.params.created, 1618884473);
  assert.equal(parsed.params.keyid, "test-key-rsa-pss");
  assert.equal(parsed.params.tag, "header-example");
  assert.equal(parsed.params.alg, undefined);
});

test("RFC 9421 B.2.2: published signature is 256 octets and verifies under RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt) with node:crypto alone", () => {
  const sigBytes = parseSignatureField(
    `sig-b22=:${B22_SIGNATURE_B64}:`,
    "sig-b22",
  );
  assert.equal(sigBytes.length, 256);
  const pss = {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 64,
  };
  const ok = createVerify("sha512")
    .update(B22_SIGNATURE_BASE, "utf8")
    .verify(pss, sigBytes);
  assert.equal(ok, true);
  // Flipping one signature octet breaks even this independent check.
  const mutated = Buffer.from(sigBytes);
  mutated[10] ^= 0x01;
  const bad = createVerify("sha512")
    .update(B22_SIGNATURE_BASE, "utf8")
    .verify(pss, mutated);
  assert.equal(bad, false);
  // Tampering a covered component in the base also breaks it.
  const tampered = createVerify("sha512")
    .update(B22_SIGNATURE_BASE.replace('"Pet": dog', '"Pet": cat'), "utf8")
    .verify(pss, sigBytes);
  assert.equal(tampered, false);
});

test("RFC 9421 B.2.2: published signature verifies end-to-end via verifyRequest", () => {
  const res = verifyRequest(b22Signed(), {
    key: importPublicKey(RSA_PSS_PUB_PEM),
    label: "sig-b22",
    now: 1618884473 + 60,
    algFallback: "infer",
    expectedTag: "header-example",
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-key-rsa-pss");
  assert.equal(res.alg, "rsa-pss-sha512");
  assert.equal(res.tag, "header-example");
});

test("RFC 9421 B.2.2: tampering a covered component fails end-to-end verification", () => {
  // The covered query parameter: Pet=dog is signed, Pet=cat is not the
  // signed value.
  const byQueryParam = verifyRequest(
    b22Signed({ url: "http://example.com/foo?param=Value&Pet=cat" }),
    {
      key: importPublicKey(RSA_PSS_PUB_PEM),
      label: "sig-b22",
      now: 1618884473 + 60,
      algFallback: "infer",
    },
  );
  assert.equal(byQueryParam.ok, false);
  assert.equal(byQueryParam.code, "SIGNATURE_MISMATCH");
  // The covered authority, reached via the request URL host.
  const byAuthority = verifyRequest(
    b22Signed({ url: "http://attacker.com/foo?param=Value&Pet=dog" }),
    {
      key: importPublicKey(RSA_PSS_PUB_PEM),
      label: "sig-b22",
      now: 1618884473 + 60,
      algFallback: "infer",
    },
  );
  assert.equal(byAuthority.ok, false);
  assert.equal(byAuthority.code, "SIGNATURE_MISMATCH");
});

test("RFC 9421 B.2.2: changing uncovered components does not affect verification (selective coverage)", () => {
  // None of date, content-type, the method, or the unrelated `param`
  // query parameter is covered by this vector, so changing all of them
  // must leave the signature valid. This is the semantic boundary that
  // distinguishes selective coverage from B.2.1 (nothing covered) and
  // B.2.3 (everything covered) — asserted as-is, not as a virtue.
  const res = verifyRequest(
    b22Signed({
      method: "GET",
      url: "http://example.com/foo?param=Changed&Pet=dog",
      headers: {
        date: "Wed, 21 Apr 2021 02:07:55 GMT",
        "content-type": "text/plain",
      },
    }),
    {
      key: importPublicKey(RSA_PSS_PUB_PEM),
      label: "sig-b22",
      now: 1618884473 + 60,
      algFallback: "infer",
    },
  );
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-pss-sha512");
});
