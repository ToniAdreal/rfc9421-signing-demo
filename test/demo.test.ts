import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createSecretKey, generateKeyPairSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  assertContentDigestAlg,
  assertHmacSecretLength,
  assertRsaModulusLength,
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  getHeader,
  getHeaderRaw,
  importPublicKeyJwkP256,
  importPublicKeyJwkP384,
  importPublicKeyJwkP521,
  importPublicKeyJwkRsa,
  joinHeaderValues,
  JwksKeyStore,
  parseSignatureField,
  parseSignatureInput,
  ReplayCache,
  resolveComponent,
  signRequest,
  signatureInputValue,
  verifyRequest,
} from "../src/index.js";
import {
  DEMO_BODY,
  DEMO_COVERED_COMPONENTS,
  DEMO_CREATED,
  DEMO_DIGEST_GUARD_ACCEPTED,
  DEMO_DIGEST_GUARD_ERRORS,
  DEMO_DIGEST_GUARD_REJECTED,
  DEMO_GATEWAY_KEY_ID,
  DEMO_INBOUND_COVERED_COMPONENTS,
  DEMO_INBOUND_HOST,
  DEMO_INBOUND_NONCE,
  DEMO_INBOUND_TRACE_HOPS,
  DEMO_INBOUND_URL,
  DEMO_INBOUND_WRONG_SCHEME,
  DEMO_GATEWAY_LABEL,
  DEMO_GATEWAY_SECRET,
  DEMO_GENERATED_LONG_NONCE_BYTES,
  DEMO_GENERATED_LONG_NONCE_LENGTH,
  DEMO_GENERATED_NONCE_BYTES,
  DEMO_GENERATED_NONCE_LENGTH,
  DEMO_GET_HEADER_EXPECTED,
  DEMO_GET_HEADER_LOOKUP_NAME,
  DEMO_GET_HEADER_MISSING_NAME,
  DEMO_GET_HEADER_RAW_EXPECTED,
  DEMO_GET_HEADER_SINGLE_LOOKUP_NAME,
  DEMO_GET_HEADER_SINGLE_STORED_NAME,
  DEMO_GET_HEADER_SINGLE_VALUE,
  DEMO_GET_HEADER_STORED_NAME,
  DEMO_GET_HEADER_VALUES,
  DEMO_DICT_MEMBER_EXTRACTION,
  DEMO_DICT_MEMBER_MISSING_KEY,
  DEMO_DICT_MEMBER_VALUE,
  DEMO_SF_CANONICALIZATION,
  DEMO_SIG_PARAMS_SERIALIZATION,
  DEMO_SIG_INPUT_ALT_COMPONENTS,
  DEMO_SIG_INPUT_ALT_EXPECTED,
  DEMO_SIG_INPUT_ALT_LABEL,
  DEMO_SIG_INPUT_ALT_PARAMS,
  DEMO_SIG_INPUT_EXPECTED,
  DEMO_SIG_INPUT_LABEL,
  DEMO_SIG_INPUT_PARAMS,
  DEMO_JWKS_FETCHED_AT_SEC,
  DEMO_JWKS_URL,
  DEMO_HMAC_GUARD_ACCEPTED,
  DEMO_HMAC_GUARD_ERRORS,
  DEMO_HMAC_GUARD_REJECTED,
  DEMO_RSA_GUARD_ACCEPTED,
  DEMO_RSA_GUARD_CONTEXT,
  DEMO_RSA_GUARD_ERRORS,
  DEMO_RSA_GUARD_REJECTED,
  DEMO_RSA_JWK_ALG,
  DEMO_RSA_JWK_E,
  DEMO_RSA_JWK_E_LENGTH,
  DEMO_RSA_JWK_KEY_ID,
  DEMO_RSA_JWK_LABEL,
  DEMO_RSA_JWK_MISMATCH_ERROR,
  DEMO_RSA_JWK_N_LENGTH,
  DEMO_RSA_JWK_NONCE,
  DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD,
  DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION,
  DEMO_JWKS_REFRESH_FRESH_AT_SEC,
  DEMO_JWKS_REFRESH_LABEL,
  DEMO_JWKS_REFRESH_NEW_KEY_ID,
  DEMO_JWKS_REFRESH_NEW_NONCE,
  DEMO_JWKS_REFRESH_OLD_KEY_ID,
  DEMO_JWKS_REFRESH_OLD_NONCE,
  DEMO_JWKS_REFRESH_RETIRED_CODE,
  DEMO_JWKS_REFRESH_STALE_AT_SEC,
  DEMO_JWKS_REFRESH_TTL_SEC,
  DEMO_JWK_TAMPERED_CODE,
  DEMO_JOIN_COVERED_COMPONENTS,
  DEMO_JOIN_EXPECTED,
  DEMO_JOIN_HEADER,
  DEMO_JOIN_LABEL,
  DEMO_JOIN_NONCE,
  DEMO_JOIN_VALUES,
  DEMO_JOIN_WRONG_CODE,
  DEMO_JOIN_WRONG_VALUE,
  DEMO_KEY_ID,
  DEMO_MAIN_DIGEST_ALG,
  DEMO_MEMOIZED_CALLS_AFTER_REPEAT,
  DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY,
  DEMO_MEMOIZED_NONCE,
  DEMO_MEMOIZED_SECOND_KEY_ID,
  DEMO_MEMOIZED_TTL_SEC,
  DEMO_NONCE,
  DEMO_P256_ALG,
  DEMO_P256_KEY_ID,
  DEMO_P256_LABEL,
  DEMO_P256_NONCE,
  DEMO_P256_TAMPERED_CODE,
  DEMO_P384_ALG,
  DEMO_P384_KEY_ID,
  DEMO_P384_LABEL,
  DEMO_P384_NONCE,
  DEMO_P384_TAMPERED_CODE,
  DEMO_P521_ALG,
  DEMO_P521_KEY_ID,
  DEMO_P521_LABEL,
  DEMO_P521_NONCE,
  DEMO_P521_TAMPERED_CODE,
  DEMO_PARSE_ALG,
  DEMO_PARSE_CREATED,
  DEMO_PARSE_KEY_ID,
  DEMO_PARSE_LABEL,
  DEMO_PARSE_NONCE,
  DEMO_PARSE_PREVIEW_CHARS,
  DEMO_PARSE_RAW_INPUT,
  DEMO_PARSE_RAW_PREVIEW,
  DEMO_PARSE_TAMPERED_ERROR,
  DEMO_PEM_NONCE,
  DEMO_RESOLVE_COMPONENTS,
  DEMO_RESOLVE_ILLEGAL_COMPONENT,
  DEMO_RESOLVE_ILLEGAL_ERROR,
  DEMO_PEM_PRIVATE_HEADER,
  DEMO_PEM_PUBLIC_HEADER,
  DEMO_OTHER_NONCE,
  DEMO_SIGNATURE_LABELS,
  DEMO_REPLAY_CACHE_MAX_ENTRIES,
  DEMO_REPLAY_CACHE_TTL_SEC,
  DEMO_REPLAY_SNAPSHOT_CODE,
  DEMO_REPLAY_SNAPSHOT_ENTRIES,
  DEMO_REPLAY_SNAPSHOT_FRESH_NONCE,
  DEMO_REPLAY_SNAPSHOT_NONCE,
  DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE,
  DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE,
  DEMO_SHA256_DIGEST_ALG,
  DEMO_SIGFIELD_BYTES,
  DEMO_SIGFIELD_LABEL,
  DEMO_SIGFIELD_PREFIX_BYTES,
  DEMO_SIGFIELD_UNKNOWN_ERROR,
  DEMO_SIGFIELD_UNKNOWN_LABEL,
  DEMO_EC_JWK_CURVES,
  DEMO_EC_JWK_LABEL,
  DEMO_EC_JWK_MISMATCH_ERROR,
  DEMO_TAMPERED_BODY,
  DEMO_TAMPERED_CONTENT_TYPE,
  DEMO_THUMBPRINT_NONCE,
  DEMO_THROW_TAMPERED_CODE,
  DEMO_UNKNOWN_KEY_ID,
  DEMO_UNRECOGNIZED_DIGEST_VALUE,
  runDemo,
} from "../src/demo.js";

const repoRoot = path.dirname(
  path.dirname(path.dirname(fileURLToPath(import.meta.url))),
); // dist/test/*.test.js -> repo root

test("demo signs a fixed request with content-digest and nonce, and it verifies", async () => {
  const { signed, verification } = await runDemo();

  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(
    signed.headers["signature-input"],
    /\("@method" "@authority" "@path" "content-digest"\)/,
  );
  assert.ok(
    signed.headers["signature-input"].includes(`created=${DEMO_CREATED}`),
  );
  assert.ok(
    signed.headers["signature-input"].includes(`keyid="${DEMO_KEY_ID}"`),
  );
  assert.ok(
    signed.headers["signature-input"].includes(`nonce="${DEMO_NONCE}"`),
  );
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  assert.equal(verification.ok, true);
  assert.equal(verification.keyId, DEMO_KEY_ID);
  assert.equal(verification.alg, "ed25519");
  assert.equal(verification.nonce, DEMO_NONCE);
});

test("demo tamper changes exactly one body byte and verification rejects it", async () => {
  const { tamperedBody, tamperedVerification } = await runDemo();

  assert.equal(tamperedBody, DEMO_TAMPERED_BODY);
  assert.equal(tamperedBody.length, DEMO_BODY.length);
  let differingBytes = 0;
  for (let i = 0; i < DEMO_BODY.length; i++) {
    if (tamperedBody[i] !== DEMO_BODY[i]) differingBytes++;
  }
  assert.equal(differingBytes, 1);

  assert.equal(tamperedVerification.ok, false);
  assert.equal(tamperedVerification.code, "BODY_DIGEST_MISMATCH");
});

test("demo lines contain the headers, the success, and the tamper rejection", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature-Input: sig1=/);
  assert.match(out, /Signature: sig1=:/);
  assert.match(out, /Content-Digest: sha-512=:/);
  assert.match(out, /Verification: OK /);
  assert.match(
    out,
    /Verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
});

// Hand-written expectation for the main line's RFC 9421 §2.5
// signature base. Every line was derived by hand from the demo's
// fixed inputs, NOT from the implementation's output: the component
// values are the request's method / authority / path, the
// content-digest is the sha-512 of DEMO_BODY (cross-checked with
// `openssl dgst -sha512`), and the @signature-params line lists the
// covered set in order with the signer's parameters in wire order
// (created, keyid, alg, nonce).
const EXPECTED_SIGNATURE_BASE = [
  '"@method": POST',
  '"@authority": api.example.com',
  '"@path": /v1/payments',
  '"content-digest": sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:',
  '"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001"',
].join("\n");

const EXPECTED_SIGNATURE_BASE_EXPLANATION =
  'Each base line above is one covered component in order ("@method", "@authority", "@path", "content-digest"); the final "@signature-params" line binds that covered set to the signature parameters (created, keyid, alg, nonce)';

test("demo signature base segment rebuilds the main line's base byte-for-byte", async () => {
  const { signed, signatureBase } = await runDemo();

  // The demo's stated covered set is the signer's default set for a
  // request with a body, in order.
  assert.deepEqual(DEMO_COVERED_COMPONENTS, [
    "@method",
    "@authority",
    "@path",
    "content-digest",
  ]);

  // The rebuilt base equals the hand-written expectation exactly.
  assert.equal(signatureBase, EXPECTED_SIGNATURE_BASE);

  // Cross-check (not the expectation source): the base's final line
  // is the wire Signature-Input value for sig1, prefixed as a base
  // line — the string that was signed binds the same wire params.
  const paramsLine = signatureBase.split("\n").at(-1);
  assert.equal(
    paramsLine,
    `"@signature-params": ${signed.headers["signature-input"].slice("sig1=".length)}`,
  );

  // The base carries no key or signature bytes and every input is a
  // fixed constant, so it is identical across runs even though each
  // run generates a fresh key pair.
  assert.equal((await runDemo()).signatureBase, signatureBase);
});

test("demo lines print the signature base block verbatim, followed by its explanation", async () => {
  const { lines } = await runDemo();

  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature base (RFC 9421 §2.5):"),
  );
  assert.notEqual(headerIdx, -1);
  // The segment sits after the main verification line and before
  // the tampered-body segment.
  const verificationIdx = lines.findIndex((l) =>
    l.startsWith("Verification: OK"),
  );
  const tamperedIdx = lines.findIndex((l) =>
    l.startsWith("Tampered body:"),
  );
  assert.ok(verificationIdx !== -1 && verificationIdx < headerIdx);
  assert.ok(tamperedIdx !== -1 && headerIdx < tamperedIdx);

  // The printed block is the hand-written base, verbatim and in
  // order, and the very next line is the explanation of how the
  // base lines map to the covered components.
  assert.deepEqual(
    lines.slice(headerIdx + 1, headerIdx + 6),
    EXPECTED_SIGNATURE_BASE.split("\n"),
  );
  assert.equal(lines[headerIdx + 6], EXPECTED_SIGNATURE_BASE_EXPLANATION);
});

test("demo gateway addSignature second label verifies alongside sig1", async () => {
  const { dualSigned, dualVerification } = await runDemo();

  // The gateway secret is a labelled demo value at or above the
  // hmac-sha256 32-byte floor.
  assert.ok(Buffer.byteLength(DEMO_GATEWAY_SECRET, "utf8") >= 32);

  // Merged wire headers carry both labels, in order, and the gateway
  // entry covers content-type with its own keyid/alg.
  assert.match(
    dualSigned.headers["signature-input"],
    /sig1=\("@method" "@authority" "@path" "content-digest"\)/,
  );
  assert.match(
    dualSigned.headers["signature-input"],
    new RegExp(
      `${DEMO_GATEWAY_LABEL}=\\("@method" "@authority" "@path" "content-type"\\);created=${DEMO_CREATED};keyid="${DEMO_GATEWAY_KEY_ID}";alg="hmac-sha256"`,
    ),
  );
  assert.match(dualSigned.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:, gateway=:[A-Za-z0-9+/=]+:$/);

  assert.deepEqual(
    dualVerification.map((r) => r.label),
    ["sig1", DEMO_GATEWAY_LABEL],
  );
  assert.equal(dualVerification[0].ok, true);
  assert.equal(dualVerification[0].alg, "ed25519");
  assert.equal(dualVerification[0].keyId, DEMO_KEY_ID);
  assert.equal(dualVerification[1].ok, true);
  assert.equal(dualVerification[1].alg, "hmac-sha256");
  assert.equal(dualVerification[1].keyId, DEMO_GATEWAY_KEY_ID);
});

test("demo content-type tamper fails only the gateway label", async () => {
  const { contentTypeTamperedVerification } = await runDemo();

  assert.equal(DEMO_TAMPERED_CONTENT_TYPE, "text/plain");
  assert.deepEqual(
    contentTypeTamperedVerification.map((r) => r.label),
    ["sig1", DEMO_GATEWAY_LABEL],
  );
  // sig1 does not cover content-type and its content-digest still
  // matches the untouched body, so it still verifies.
  assert.equal(contentTypeTamperedVerification[0].ok, true);
  // The gateway signature covers content-type, so it alone fails.
  assert.equal(contentTypeTamperedVerification[1].ok, false);
  assert.equal(contentTypeTamperedVerification[1].code, "SIGNATURE_MISMATCH");
});

test("demo lines contain the dual headers, dual verification, and tamper isolation", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /addSignature \(hmac-sha256\)/);
  assert.match(out, /Dual Signature-Input: sig1=.*gateway=/);
  assert.match(out, /Dual Signature: sig1=:.*gateway=:/);
  assert.match(out, /Dual verification sig1: OK /);
  assert.match(out, /Dual verification gateway: OK /);
  assert.match(out, /Signature labels: listSignatureLabels enumerates the labels in the dual-signed request's Signature-Input in wire order/);
  assert.match(out, /Signature labels in the dual-signed request: sig1, gateway \(2 labels\)/);
  assert.match(out, /Tampered content-type: text\/plain /);
  assert.match(out, /After content-type tampering sig1: OK /);
  assert.match(
    out,
    /After content-type tampering gateway: FAILED \(code SIGNATURE_MISMATCH:/,
  );
});

test("demo replay segment rejects the same request twice via ReplayCache", async () => {
  const {
    replayFirstVerification,
    replaySecondVerification,
    replayOtherNonceVerification,
  } = await runDemo();

  assert.ok(DEMO_REPLAY_CACHE_MAX_ENTRIES >= 1);
  assert.ok(DEMO_REPLAY_CACHE_TTL_SEC > 0);
  assert.notEqual(DEMO_OTHER_NONCE, DEMO_NONCE);

  // First presentation of the nonce spends it and verifies.
  assert.equal(replayFirstVerification.ok, true);
  assert.equal(replayFirstVerification.nonce, DEMO_NONCE);
  // The identical request presented again is a replay: the signature
  // is still valid, but the nonce has already been seen.
  assert.equal(replaySecondVerification.ok, false);
  assert.equal(replaySecondVerification.code, "NONCE_REPLAY");
  assert.equal(replaySecondVerification.nonce, DEMO_NONCE);
  // A fresh nonce against the same cache is not a replay.
  assert.equal(replayOtherNonceVerification.ok, true);
  assert.equal(replayOtherNonceVerification.nonce, DEMO_OTHER_NONCE);
});

test("demo lines contain the replay segment (first ok, replay rejected, fresh nonce ok)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Replay protection: same request verified twice against a ReplayCache/);
  assert.match(
    out,
    new RegExp(`Replay check, first presentation of nonce "${DEMO_NONCE}": OK`),
  );
  assert.match(
    out,
    /Replay check, second presentation of the same request: FAILED \(code NONCE_REPLAY:/,
  );
  assert.match(
    out,
    new RegExp(`Replay check, new request with nonce "${DEMO_OTHER_NONCE}": OK`),
  );
});

test("demo request data is deterministic across runs (fresh key aside)", async () => {
  const a = await runDemo();
  const b = await runDemo();

  // Everything except the Signature lines is byte-identical: the key pair
  // is generated fresh per run, so the signature bytes themselves differ.
  // The Dual Signature line embeds the same fresh sig1 signature, so it
  // is filtered too (the gateway HMAC signature in it is deterministic).
  const withoutSignature = (lines: string[]) =>
    lines.filter(
      (l) =>
        !l.startsWith("Signature: ") &&
        !l.startsWith("Dual Signature: ") &&
        // The thumbprint is derived from the fresh key, so it (and the
        // verification line quoting it as keyid) varies like a signature.
        !l.startsWith("JWK thumbprint: ") &&
        !l.startsWith("Thumbprint-as-keyid verification: ") &&
        // The nonce-generation segment's nonces are fresh CSPRNG draws
        // per run (that is the segment's point), so the lines quoting
        // them vary like a signature; only their shapes are pinned.
        !l.startsWith("generateNonce(): ") &&
        !l.startsWith("generateNonce(32): ") &&
        !l.startsWith("Verification with the generated nonce: ") &&
        // The Signature field parsing segment's hex prefix quotes
        // the fresh signature's bytes, so it varies like a
        // signature; only its shape is pinned.
        !l.startsWith("Parsed Signature for label "),
    );
  assert.deepEqual(withoutSignature(a.lines), withoutSignature(b.lines));
  assert.equal(a.signed.headers["signature-input"], b.signed.headers["signature-input"]);
  assert.equal(a.signed.headers["content-digest"], b.signed.headers["content-digest"]);
  assert.notEqual(a.signed.headers["signature"], b.signed.headers["signature"]);
  assert.equal(
    a.dualSigned.headers["signature-input"],
    b.dualSigned.headers["signature-input"],
  );
  assert.notEqual(
    a.dualSigned.headers["signature"],
    b.dualSigned.headers["signature"],
  );
});

test("demo sha-256 segment re-signs the same request for a sha-256-only peer", async () => {
  const { signed, sha256Signed, sha256Verification, sha256TamperedVerification } =
    await runDemo();

  // Same body, different digest algorithm: the sha-256 header has the
  // 44-char base64 wire shape and differs from the main line's sha-512.
  assert.match(
    sha256Signed.headers["content-digest"],
    /^sha-256=:[A-Za-z0-9+/]{43}=:$/,
  );
  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.notEqual(
    sha256Signed.headers["content-digest"],
    signed.headers["content-digest"],
  );
  assert.equal(sha256Signed.body, DEMO_BODY);
  // Everything else about the signing inputs matches the main line.
  assert.equal(
    sha256Signed.headers["signature-input"],
    signed.headers["signature-input"],
  );

  assert.equal(sha256Verification.ok, true);
  assert.equal(sha256Verification.keyId, DEMO_KEY_ID);
  assert.equal(sha256Verification.alg, "ed25519");
  // The same one-byte body tamper as the main line is a digest mismatch.
  assert.equal(sha256TamperedVerification.ok, false);
  assert.equal(sha256TamperedVerification.code, "BODY_DIGEST_MISMATCH");
});

test("demo lines contain the sha-256 segment (comparison, verification, tamper rejection)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Content-Digest algorithms on the same body: main line sha-512=:.* vs sha-256 peer line sha-256=:/,
  );
  assert.match(out, /sha-256 Content-Digest: sha-256=:/);
  assert.match(out, /sha-256 verification: OK /);
  assert.match(
    out,
    /sha-256 verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
});

test("demo digest-alg identification segment reads the algorithm off both emitted headers and fails closed on an unrecognized value", async () => {
  const {
    contentDigestAlg,
    sha256ContentDigestAlg,
    unrecognizedContentDigestAlg,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_MAIN_DIGEST_ALG / DEMO_SHA256_DIGEST_ALG: the main line
  // emits the library default and the peer line emits sha-256 —
  // the same two values pinned in test/contentDigestAlg.test.ts
  // and the bench DIGEST_ALG_CORPUS.
  assert.equal(DEMO_MAIN_DIGEST_ALG, "sha-512");
  assert.equal(DEMO_SHA256_DIGEST_ALG, "sha-256");
  assert.equal(contentDigestAlg, DEMO_MAIN_DIGEST_ALG);
  assert.equal(sha256ContentDigestAlg, DEMO_SHA256_DIGEST_ALG);

  // The sha-1-shaped value is not an algorithm this library can
  // emit, so identification returns undefined (fail-closed) — the
  // same shape the contentDigestAlg tests pin for the
  // addSignature rejection and the bench corpus pins here.
  assert.equal(DEMO_UNRECOGNIZED_DIGEST_VALUE, "sha-1=:abc=:");
  assert.equal(unrecognizedContentDigestAlg, undefined);
});

test("demo lines contain the digest-alg identification segment (after the sha-256 segment, before inbound normalization)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Content-Digest algorithm identification: contentDigestAlgOf reads the algorithm off an existing Content-Digest header/,
  );
  assert.ok(
    out.includes("contentDigestAlgOf on the main line's Content-Digest: sha-512"),
  );
  assert.ok(
    out.includes(
      "contentDigestAlgOf on the sha-256 peer line's Content-Digest: sha-256",
    ),
  );
  assert.ok(
    out.includes(
      `contentDigestAlgOf on the unrecognized value "${DEMO_UNRECOGNIZED_DIGEST_VALUE}": undefined (an algorithm this library cannot emit — a caller must reject it)`,
    ),
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Content-Digest algorithm identification:"),
  );
  const sha256Idx = lines.findIndex((l) =>
    l.startsWith("sha-256 verification after tampering:"),
  );
  const inboundIdx = lines.findIndex((l) =>
    l.startsWith("Inbound normalization:"),
  );
  assert.ok(sha256Idx !== -1 && headerIdx !== -1 && inboundIdx !== -1);
  assert.ok(sha256Idx < headerIdx && headerIdx < inboundIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "Content-Digest algorithm identification: contentDigestAlgOf reads the algorithm off an existing Content-Digest header — the receiver's first step before deciding whether to verify",
    "contentDigestAlgOf on the main line's Content-Digest: sha-512",
    "contentDigestAlgOf on the sha-256 peer line's Content-Digest: sha-256",
    `contentDigestAlgOf on the unrecognized value "${DEMO_UNRECOGNIZED_DIGEST_VALUE}": undefined (an algorithm this library cannot emit — a caller must reject it)`,
  ]);
});

test("demo inbound segment normalizes a mock IncomingMessage and verifies it", async () => {
  const {
    inboundSigned,
    inboundNormalized,
    inboundVerification,
    inboundWrongSchemeVerification,
  } = await runDemo();

  // The signer-side request is the port-carrying https URL, with
  // @scheme and the multi-value trace header covered.
  assert.equal(DEMO_INBOUND_URL, `https://${DEMO_INBOUND_HOST}/v1/payments`);
  assert.ok(DEMO_INBOUND_COVERED_COMPONENTS.includes("@scheme"));
  assert.ok(DEMO_INBOUND_COVERED_COMPONENTS.includes("x-trace-hops"));
  assert.match(
    inboundSigned.headers["signature-input"],
    /\("@method" "@scheme" "@authority" "@path" "content-digest" "x-trace-hops"\)/,
  );
  assert.ok(
    inboundSigned.headers["signature-input"].includes(
      `nonce="${DEMO_INBOUND_NONCE}"`,
    ),
  );

  // Normalization: method/url rebuilt from origin form + host with
  // port, mixed-case names lowercased, multi-value header joined.
  assert.equal(inboundNormalized.method, "POST");
  assert.equal(inboundNormalized.url, DEMO_INBOUND_URL);
  assert.equal(inboundNormalized.headers["host"], DEMO_INBOUND_HOST);
  assert.equal(
    inboundNormalized.headers["x-trace-hops"],
    DEMO_INBOUND_TRACE_HOPS.join(", "),
  );
  assert.equal(inboundNormalized.headers["content-type"], "application/json");
  assert.ok(!("Host" in inboundNormalized.headers));
  assert.ok(!("X-Trace-Hops" in inboundNormalized.headers));
  assert.equal(inboundNormalized.body, DEMO_BODY);

  assert.equal(inboundVerification.ok, true);
  assert.equal(inboundVerification.keyId, DEMO_KEY_ID);
  assert.equal(inboundVerification.alg, "ed25519");
  // Rebuilding with the wrong scheme changes the covered @scheme
  // component, so the same wire request is rejected.
  assert.equal(DEMO_INBOUND_WRONG_SCHEME, "http");
  assert.equal(inboundWrongSchemeVerification.ok, false);
  assert.equal(inboundWrongSchemeVerification.code, "SIGNATURE_MISMATCH");
});

test("demo lines contain the inbound segment (normalized shape, verified, wrong scheme rejected)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Inbound normalization: mock Node IncomingMessage normalized with fromNodeRequest \(mixed-case headers, multi-value x-trace-hops, host with port\)/,
  );
  assert.match(
    out,
    new RegExp(
      `Inbound normalized: POST ${DEMO_INBOUND_URL.replace(/\./g, "\\.")} \\(host "${DEMO_INBOUND_HOST}", x-trace-hops "${DEMO_INBOUND_TRACE_HOPS.join(", ")}", content-type "application/json"\\)`,
    ),
  );
  assert.match(out, /Inbound verification: OK /);
  assert.match(
    out,
    new RegExp(
      `Inbound verification with wrong scheme "${DEMO_INBOUND_WRONG_SCHEME}": FAILED \\(code SIGNATURE_MISMATCH:`,
    ),
  );
});

test("demo JWKS segment verifies via a restored store and rejects an unknown keyid", async () => {
  const {
    jwksSnapshot,
    jwksStoreSize,
    jwksVerification,
    jwksUnknownKeyVerification,
  } = await runDemo();

  // The snapshot is the hand-pinned v1 shape: the demo key's public
  // JWK under DEMO_KEY_ID, fetched at the pinned instant, and it
  // carries no private material.
  assert.equal(DEMO_JWKS_FETCHED_AT_SEC, DEMO_CREATED);
  assert.equal(jwksSnapshot.v, 1);
  assert.equal(jwksSnapshot.fetchedAtSec, DEMO_JWKS_FETCHED_AT_SEC);
  assert.equal(jwksSnapshot.keys.length, 1);
  assert.equal(jwksSnapshot.keys[0].kid, DEMO_KEY_ID);
  assert.equal(jwksSnapshot.keys[0].kty, "OKP");
  assert.ok(!("d" in jwksSnapshot.keys[0]));
  assert.equal(jwksStoreSize, 1);
  assert.notEqual(DEMO_UNKNOWN_KEY_ID, DEMO_KEY_ID);

  // The demo request verifies through the store's key resolver.
  assert.equal(jwksVerification.ok, true);
  assert.equal(jwksVerification.keyId, DEMO_KEY_ID);
  assert.equal(jwksVerification.alg, "ed25519");
  // A request signed under a keyid absent from the snapshot fails
  // closed at key resolution, before any signature check.
  assert.equal(jwksUnknownKeyVerification.ok, false);
  assert.equal(jwksUnknownKeyVerification.code, "KEY_RESOLUTION_FAILED");
});

test("demo lines contain the JWKS segment (hit verifies, unknown keyid rejected)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    new RegExp(
      `JWKS key resolution: JwksKeyStore restored offline from a v1 snapshot \\(endpoint ${DEMO_JWKS_URL.replace(/\./g, "\\.")}, fetchedAtSec=${DEMO_JWKS_FETCHED_AT_SEC}, 1 key\\)`,
    ),
  );
  assert.match(
    out,
    new RegExp(`JWKS verification for keyid "${DEMO_KEY_ID}": OK `),
  );
  assert.match(
    out,
    new RegExp(
      `JWKS verification for unknown keyid "${DEMO_UNKNOWN_KEY_ID}": FAILED \\(code KEY_RESOLUTION_FAILED:`,
    ),
  );
});

test("demo thumbprint segment derives the RFC 7638 thumbprint and binds it as keyid", async () => {
  const { thumbprint, thumbprintSigned, thumbprintVerification } = await runDemo();

  // A SHA-256 thumbprint is a 43-char base64url digest (RFC 7638).
  assert.match(thumbprint, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(thumbprint, DEMO_KEY_ID);

  // The segment's request is signed under the thumbprint itself.
  assert.ok(
    thumbprintSigned.headers["signature-input"].includes(
      `keyid="${thumbprint}"`,
    ),
  );
  assert.ok(
    thumbprintSigned.headers["signature-input"].includes(
      `nonce="${DEMO_THUMBPRINT_NONCE}"`,
    ),
  );
  assert.equal(thumbprintSigned.body, DEMO_BODY);

  // Verification with expectedKeyId pinned to the thumbprint passes.
  assert.equal(thumbprintVerification.ok, true);
  assert.equal(thumbprintVerification.keyId, thumbprint);
  assert.equal(thumbprintVerification.alg, "ed25519");
});

test("demo lines contain the thumbprint segment (thumbprint printed, thumbprint-as-keyid verifies)", async () => {
  const { lines, thumbprint } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    new RegExp(
      `JWK thumbprint: RFC 7638 thumbprint of the demo ed25519 public JWK is "${thumbprint}"`,
    ),
  );
  assert.match(
    out,
    new RegExp(
      `Thumbprint-as-keyid verification: OK \\(label sig1, keyid="${thumbprint}", alg="ed25519"\\)`,
    ),
  );
});

test("demo canonicalization segment canonicalizes the fixed corpus to the hand-pinned forms", async () => {
  const { sfCanonicalization } = await runDemo();

  // Expectations are the literal values pinned in
  // DEMO_SF_CANONICALIZATION (hand-derived from RFC 8941 §4, matching
  // test/sfComponent.test.ts and the bench corpus) — the test pins
  // them again here so a drift in either place fails loudly.
  assert.deepEqual(sfCanonicalization, [
    {
      name: "dictionary-decimal",
      input: "limit=1500, remaining=1.5",
      canonical: "limit=1500, remaining=1.500",
    },
    {
      name: "item-leading-zero-integer",
      input: "007",
      canonical: "7",
    },
    {
      name: "dictionary-byte-sequence",
      input: "sig=:aGVsbG8=:;x=?0",
      canonical: "sig=:aGVsbG8=:;x=?0",
    },
  ]);
  assert.deepEqual(
    DEMO_SF_CANONICALIZATION.map((c) => c.expected),
    sfCanonicalization.map((c) => c.canonical),
  );
});

test("demo lines contain the canonicalization segment (raw -> canonical pairs)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Structured-field canonicalization \(;sf\): a verifier compares the parsed value re-serialized strictly, not the wire bytes/);
  assert.ok(out.includes("Canonicalize dictionary-decimal: limit=1500, remaining=1.5 -> limit=1500, remaining=1.500"));
  assert.ok(out.includes("Canonicalize item-leading-zero-integer: 007 -> 7"));
  assert.ok(out.includes("Canonicalize dictionary-byte-sequence: sig=:aGVsbG8=:;x=?0 -> sig=:aGVsbG8=:;x=?0"));
  // The canonicalization segment is followed by the member-extraction
  // segment: its header comes after the last canonicalization pair.
  const canonIdx = lines.findIndex((l) =>
    l.startsWith("Canonicalize dictionary-byte-sequence:"),
  );
  const extractIdx = lines.findIndex((l) =>
    l.startsWith("Dictionary-member extraction (;key):"),
  );
  assert.ok(canonIdx !== -1 && extractIdx !== -1 && canonIdx < extractIdx);
});

test("demo member-extraction segment extracts the fixed keys to the hand-pinned values", async () => {
  const { dictMemberExtraction, dictMemberMissingKeyError } = await runDemo();

  // The demo's Dictionary value is the literal pinned here and in
  // the bench corpus — the same multi-member value, pinned
  // independently in both places.
  assert.equal(
    DEMO_DICT_MEMBER_VALUE,
    "a=1, b=2;x=1;y=2, n=1.5, sig=:aGVsbG8=:;x=?0, c=(a b c), d",
  );

  // Expectations are the literal values pinned in
  // DEMO_DICT_MEMBER_EXTRACTION (hand-derived from RFC 8941
  // §4.1.2, matching test/keyComponent.test.ts,
  // test/sfComponent.test.ts and the bench corpus) — the test pins
  // them again here so a drift in either place fails loudly.
  assert.deepEqual(dictMemberExtraction, [
    { key: "a", value: "1" },
    { key: "b", value: "2;x=1;y=2" },
    { key: "n", value: "1.500" },
    { key: "sig", value: ":aGVsbG8=:;x=?0" },
    { key: "c", value: "(a b c)" },
    { key: "d", value: "?1" },
  ]);
  assert.deepEqual(
    DEMO_DICT_MEMBER_EXTRACTION.map((c) => c.expected),
    dictMemberExtraction.map((c) => c.value),
  );
  assert.deepEqual(
    DEMO_DICT_MEMBER_EXTRACTION.map((c) => c.key),
    dictMemberExtraction.map((c) => c.key),
  );

  // A missing key fails closed with the pinned message.
  assert.equal(DEMO_DICT_MEMBER_MISSING_KEY, "zzz");
  assert.equal(
    dictMemberMissingKeyError,
    'dictionary member "zzz" is not present in the field value',
  );
});

test("demo lines contain the member-extraction segment (key -> value pairs, missing key rejected)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Dictionary-member extraction \(;key\): a ;key covered component contributes only the named member, re-serialized without its Dictionary key/);
  assert.ok(out.includes("Dictionary: a=1, b=2;x=1;y=2, n=1.5, sig=:aGVsbG8=:;x=?0, c=(a b c), d"));
  assert.ok(out.includes("Extract member a: 1"));
  assert.ok(out.includes("Extract member b: 2;x=1;y=2"));
  assert.ok(out.includes("Extract member n: 1.500"));
  assert.ok(out.includes("Extract member sig: :aGVsbG8=:;x=?0"));
  assert.ok(out.includes("Extract member c: (a b c)"));
  assert.ok(out.includes("Extract member d: ?1"));
  assert.ok(
    out.includes(
      'Extract member zzz: FAILED (dictionary member "zzz" is not present in the field value)',
    ),
  );
  // The extraction block sits after the canonicalization segment,
  // and the serialization segment follows it: the missing-key line
  // is the extraction block's last line, not the demo's last line.
  const missingIdx = lines.findIndex((l) =>
    l.startsWith("Extract member zzz:"),
  );
  const serializeIdx = lines.findIndex((l) =>
    l.startsWith("Signature-params serialization:"),
  );
  assert.ok(missingIdx !== -1 && serializeIdx !== -1 && missingIdx < serializeIdx);
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Dictionary-member extraction (;key):"),
  );
  const canonIdx = lines.findIndex((l) =>
    l.startsWith("Structured-field canonicalization (;sf):"),
  );
  assert.ok(canonIdx !== -1 && headerIdx !== -1 && canonIdx < headerIdx);
  assert.equal(lines[headerIdx + 1], `Dictionary: ${DEMO_DICT_MEMBER_VALUE}`);
  assert.deepEqual(lines.slice(headerIdx + 2, headerIdx + 8), [
    "Extract member a: 1",
    "Extract member b: 2;x=1;y=2",
    "Extract member n: 1.500",
    "Extract member sig: :aGVsbG8=:;x=?0",
    "Extract member c: (a b c)",
    "Extract member d: ?1",
  ]);
});

test("demo signature-params segment serializes the fixed corpus to the hand-pinned strings", async () => {
  const { sigParamsSerialization } = await runDemo();

  // Expectations are the literal values pinned in
  // DEMO_SIG_PARAMS_SERIALIZATION (hand-derived from the
  // serializer's contract, matching the bench corpus and the
  // Appendix B / golden / parameterized-component / nonce test
  // suites) — the test pins them again here so a drift in either
  // place fails loudly.
  assert.deepEqual(sigParamsSerialization, [
    {
      name: "empty",
      serialized:
        '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    },
    {
      name: "golden",
      serialized:
        '("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"',
    },
    {
      name: "full",
      serialized:
        '("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"',
    },
    {
      name: "parameterized",
      serialized:
        '("@method";req "x-checksum";tr "@query-param";name="amount" "x-dict";key="b");created=1700000000;keyid="k1";alg="ed25519"',
    },
    {
      name: "escaped",
      serialized:
        '("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
    },
  ]);
  assert.deepEqual(
    DEMO_SIG_PARAMS_SERIALIZATION.map((c) => c.expected),
    sigParamsSerialization.map((c) => c.serialized),
  );
  assert.deepEqual(
    DEMO_SIG_PARAMS_SERIALIZATION.map((c) => c.name),
    sigParamsSerialization.map((c) => c.name),
  );
});

test("demo lines contain the signature-params segment (name -> serialized pairs)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature-params serialization: the covered-component inner list plus its parameters in fixed order \(created, expires, keyid, alg, nonce, tag\), strings quoted and escaped/);
  assert.ok(out.includes('Serialize empty: ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"'));
  assert.ok(out.includes('Serialize golden: ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"'));
  assert.ok(out.includes('Serialize full: ("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"'));
  assert.ok(out.includes('Serialize parameterized: ("@method";req "x-checksum";tr "@query-param";name="amount" "x-dict";key="b");created=1700000000;keyid="k1";alg="ed25519"'));
  assert.ok(out.includes('Serialize escaped: ("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"'));
  // The serialization block sits after the member-extraction
  // segment's missing-key line, and the PEM round-trip segment
  // follows it (the escaped line is no longer the demo's last line).
  const pemIdx = lines.findIndex((l) =>
    l.startsWith("PEM key round-trip:"),
  );
  assert.ok(pemIdx !== -1);
  assert.equal(
    lines[pemIdx - 1],
    "",
  );
  assert.equal(
    lines[pemIdx - 2],
    'Serialize escaped: ("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature-params serialization:"),
  );
  const missingIdx = lines.findIndex((l) =>
    l.startsWith("Extract member zzz:"),
  );
  assert.ok(missingIdx !== -1 && headerIdx !== -1 && missingIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx + 1, headerIdx + 6), [
    'Serialize empty: ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    'Serialize golden: ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"',
    'Serialize full: ("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"',
    'Serialize parameterized: ("@method";req "x-checksum";tr "@query-param";name="amount" "x-dict";key="b");created=1700000000;keyid="k1";alg="ed25519"',
    'Serialize escaped: ("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
  ]);
});

test("demo PEM segment exports the main key pair as PEM, imports it back, and the imported keys sign and verify", async () => {
  const { pemPublicHeader, pemPrivateHeader, pemSigned, pemVerification } =
    await runDemo();

  // Expectations are the literal PEM type headers hand-pinned in
  // DEMO_PEM_*_HEADER (SPKI public / PKCS#8 private, per src/keys.ts)
  // — the test pins them again here so a drift in either place fails.
  assert.equal(DEMO_PEM_PUBLIC_HEADER, "-----BEGIN PUBLIC KEY-----");
  assert.equal(DEMO_PEM_PRIVATE_HEADER, "-----BEGIN PRIVATE KEY-----");
  assert.equal(pemPublicHeader, DEMO_PEM_PUBLIC_HEADER);
  assert.equal(pemPrivateHeader, DEMO_PEM_PRIVATE_HEADER);

  // The round-trip request is the same fixed request, signed under
  // the imported private key with the PEM segment's own nonce.
  assert.equal(pemSigned.body, DEMO_BODY);
  assert.ok(
    pemSigned.headers["signature-input"].includes(`keyid="${DEMO_KEY_ID}"`),
  );
  assert.ok(
    pemSigned.headers["signature-input"].includes(
      `nonce="${DEMO_PEM_NONCE}"`,
    ),
  );
  assert.notEqual(DEMO_PEM_NONCE, DEMO_NONCE);

  // Verification with the imported public key passes.
  assert.equal(pemVerification.ok, true);
  assert.equal(pemVerification.keyId, DEMO_KEY_ID);
  assert.equal(pemVerification.alg, "ed25519");
});

test("demo lines contain the PEM segment (headers printed, round-trip verifies)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /PEM key round-trip: the main ed25519 key pair exported as PEM, imported back, and the imported keys sign and verify a fresh request/,
  );
  assert.ok(out.includes("PEM public key header: -----BEGIN PUBLIC KEY-----"));
  assert.ok(
    out.includes("PEM private key header: -----BEGIN PRIVATE KEY-----"),
  );
  assert.match(
    out,
    new RegExp(
      `PEM round-trip verification: OK \\(label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519"\\)`,
    ),
  );
  // The PEM block sits after the signature-params segment, and the
  // throwing-verification segment follows it (the PEM verification
  // line is no longer the demo's last line).
  const throwIdx = lines.findIndex((l) =>
    l.startsWith("Throwing verification:"),
  );
  assert.ok(throwIdx !== -1);
  assert.equal(
    lines[throwIdx - 2],
    `PEM round-trip verification: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519")`,
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("PEM key round-trip:"),
  );
  const serializeIdx = lines.findIndex((l) =>
    l.startsWith("Serialize escaped:"),
  );
  assert.ok(serializeIdx !== -1 && headerIdx !== -1 && serializeIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx + 1, headerIdx + 3), [
    "PEM public key header: -----BEGIN PUBLIC KEY-----",
    "PEM private key header: -----BEGIN PRIVATE KEY-----",
  ]);
});

test("demo throwing-verification segment returns the identity on success and throws a VerifyError with the pinned code on tamper", async () => {
  const { throwVerification, throwTamperedError, throwTamperedIsVerifyError } =
    await runDemo();

  // The hand-pinned tamper code is the same BODY_DIGEST_MISMATCH the
  // returning verifyRequest reports for the main line's one-byte
  // tamper — pinned again here so a drift in either place fails.
  assert.equal(DEMO_THROW_TAMPERED_CODE, "BODY_DIGEST_MISMATCH");

  // Success returns the verified identity directly, no result object.
  assert.deepEqual(throwVerification, {
    label: "sig1",
    keyId: DEMO_KEY_ID,
    alg: "ed25519",
    nonce: DEMO_NONCE,
    tag: undefined,
  });

  // The tampered-body call threw, the caught error passes the
  // isVerifyError guard (as recorded by the demo), and it carries
  // the pinned code plus the same identity fields.
  assert.equal(throwTamperedIsVerifyError, true);
  assert.equal(throwTamperedError.name, "VerifyError");
  assert.equal(throwTamperedError.code, DEMO_THROW_TAMPERED_CODE);
  assert.equal(throwTamperedError.message, "body does not match content-digest");
  assert.equal(throwTamperedError.label, "sig1");
  assert.equal(throwTamperedError.keyId, DEMO_KEY_ID);
  assert.equal(throwTamperedError.alg, "ed25519");
  assert.equal(throwTamperedError.nonce, DEMO_NONCE);
});

test("demo lines contain the throwing-verification segment (identity returned, VerifyError thrown, followed by the nonce-generation segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Throwing verification: verifyRequestOrThrow returns the verified identity on success and throws a VerifyError carrying a stable code on failure/,
  );
  assert.ok(
    out.includes(
      `verifyRequestOrThrow on the main request: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519", nonce="${DEMO_NONCE}")`,
    ),
  );
  assert.ok(
    out.includes(
      "verifyRequestOrThrow on the tampered-body request: FAILED (threw VerifyError, code BODY_DIGEST_MISMATCH: body does not match content-digest)",
    ),
  );
  // The throwing-verification block sits after the PEM segment, and
  // the nonce-generation segment follows it (the tamper line is no
  // longer the demo's last line).
  const nonceIdx = lines.findIndex((l) => l.startsWith("Nonce generation:"));
  assert.ok(nonceIdx !== -1);
  assert.equal(
    lines[nonceIdx - 2],
    "verifyRequestOrThrow on the tampered-body request: FAILED (threw VerifyError, code BODY_DIGEST_MISMATCH: body does not match content-digest)",
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Throwing verification:"),
  );
  const pemIdx = lines.findIndex((l) => l.startsWith("PEM key round-trip:"));
  assert.ok(pemIdx !== -1 && headerIdx !== -1 && pemIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx + 1, headerIdx + 3), [
    `verifyRequestOrThrow on the main request: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519", nonce="${DEMO_NONCE}")`,
    "verifyRequestOrThrow on the tampered-body request: FAILED (threw VerifyError, code BODY_DIGEST_MISMATCH: body does not match content-digest)",
  ]);
});

test("demo nonce-generation segment draws pinned-shape base64url nonces and the short one round-trips through sign and verify", async () => {
  const {
    generatedNonce,
    generatedLongNonce,
    generatedNonceSigned,
    generatedNonceVerification,
  } = await runDemo();

  // Expectations are the literals hand-pinned in DEMO_GENERATED_*:
  // the default draw is 16 bytes -> 22 base64url chars, the explicit
  // draw is 32 bytes -> 43 chars — the same shapes pinned
  // independently in test/generateNonce.test.ts and src/keys.ts.
  // The test pins them again here so a drift in either place fails.
  assert.equal(DEMO_GENERATED_NONCE_BYTES, 16);
  assert.equal(DEMO_GENERATED_NONCE_LENGTH, 22);
  assert.equal(DEMO_GENERATED_LONG_NONCE_BYTES, 32);
  assert.equal(DEMO_GENERATED_LONG_NONCE_LENGTH, 43);

  // Shape only: the values are CSPRNG draws, never pinned — charset,
  // character length and decoded byte length are what must hold.
  const BASE64URL = /^[A-Za-z0-9_-]+$/;
  assert.match(generatedNonce, BASE64URL);
  assert.equal(generatedNonce.length, DEMO_GENERATED_NONCE_LENGTH);
  assert.equal(
    Buffer.from(generatedNonce, "base64url").length,
    DEMO_GENERATED_NONCE_BYTES,
  );
  assert.match(generatedLongNonce, BASE64URL);
  assert.equal(generatedLongNonce.length, DEMO_GENERATED_LONG_NONCE_LENGTH);
  assert.equal(
    Buffer.from(generatedLongNonce, "base64url").length,
    DEMO_GENERATED_LONG_NONCE_BYTES,
  );
  assert.notEqual(generatedNonce, generatedLongNonce);

  // The short nonce is the one signed into the segment's request,
  // and the verifier parses exactly that nonce back out.
  assert.ok(
    generatedNonceSigned.headers["signature-input"].includes(
      `nonce="${generatedNonce}"`,
    ),
  );
  assert.equal(generatedNonceSigned.body, DEMO_BODY);
  assert.equal(generatedNonceVerification.ok, true);
  assert.equal(generatedNonceVerification.nonce, generatedNonce);
  assert.equal(generatedNonceVerification.keyId, DEMO_KEY_ID);
  assert.equal(generatedNonceVerification.alg, "ed25519");
});

test("demo lines contain the nonce-generation segment (shapes printed, generated nonce verifies)", async () => {
  const { lines, generatedNonce, generatedLongNonce } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Nonce generation: generateNonce draws a fresh nonce from the CSPRNG and base64url-encodes it — the standard entry point for replay-protection nonces, instead of hand-writing a nonce string/,
  );
  assert.ok(
    out.includes(
      `generateNonce(): "${generatedNonce}" (22 chars, base64url, decodes to 16 bytes)`,
    ),
  );
  assert.ok(
    out.includes(
      `generateNonce(32): "${generatedLongNonce}" (43 chars, base64url, decodes to 32 bytes)`,
    ),
  );
  // The nonce-generation segment sits after the throwing segment,
  // and the JWK import segment follows it (the nonce line is no
  // longer the demo's last line).
  const nonceLineIdx = lines.findIndex(
    (l) => l === `Verification with the generated nonce: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519", nonce="${generatedNonce}")`,
  );
  assert.ok(nonceLineIdx !== -1);
  assert.ok(
    lines.findIndex((l) => l.startsWith("JWK public-key import:")) >
      nonceLineIdx,
  );
  const headerIdx = lines.findIndex((l) => l.startsWith("Nonce generation:"));
  const throwIdx = lines.findIndex((l) =>
    l.startsWith("Throwing verification:"),
  );
  assert.ok(throwIdx !== -1 && headerIdx !== -1 && throwIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx + 1, headerIdx + 4), [
    `generateNonce(): "${generatedNonce}" (22 chars, base64url, decodes to 16 bytes)`,
    `generateNonce(32): "${generatedLongNonce}" (43 chars, base64url, decodes to 32 bytes)`,
    `Verification with the generated nonce: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519", nonce="${generatedNonce}")`,
  ]);
});

test("demo JWK import segment verifies the main request with the imported key and rejects a tampered x", async () => {
  const { exportedJwk, jwkImportedVerification, jwkTamperedVerification } =
    await runDemo();

  // Expectations are the RFC 8037 ed25519 JWK shape hand-pinned in
  // DEMO_JWK_TAMPERED_CODE and test/jwk.test.ts: kty OKP, crv
  // Ed25519, a 43-character base64url x (32 bytes), and no private
  // material — the test pins them again here so a drift in either
  // place fails. The key value itself is fresh per run, never pinned.
  assert.equal(DEMO_JWK_TAMPERED_CODE, "SIGNATURE_MISMATCH");
  assert.equal(exportedJwk.kty, "OKP");
  assert.equal(exportedJwk.crv, "Ed25519");
  assert.match(exportedJwk.x, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(!("d" in exportedJwk), "public JWK must not carry private material");
  assert.deepEqual(Object.keys(exportedJwk).sort(), ["crv", "kty", "x"]);

  // The key imported back from the wire JWK verifies the main
  // signed request, with the main line's identity.
  assert.equal(jwkImportedVerification.ok, true);
  assert.equal(jwkImportedVerification.keyId, DEMO_KEY_ID);
  assert.equal(jwkImportedVerification.alg, "ed25519");
  assert.equal(jwkImportedVerification.nonce, DEMO_NONCE);

  // The tampered copy (first x character flipped) imports as a
  // different well-formed key, so verification against it fails
  // with the pinned code — the wrong key does not verify.
  assert.equal(jwkTamperedVerification.ok, false);
  assert.equal(jwkTamperedVerification.code, DEMO_JWK_TAMPERED_CODE);
});

test("demo lines contain the JWK import segment (imported key verifies, tampered x rejected, followed by the key-resolver memoization segment)", async () => {
  const { lines, exportedJwk } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /JWK public-key import: exportPublicKeyJwk ships the main ed25519 public key as a JWK, a JSON wire round-trip carries it, and importPublicKeyJwk reads it back/,
  );
  assert.ok(
    out.includes(
      `Exported JWK: kty="OKP", crv="Ed25519", x is ${exportedJwk.x.length} base64url chars (the key itself is fresh per run; only its shape is printed)`,
    ),
  );
  // The JWK import block sits after the nonce-generation segment
  // and is followed by the key-resolver memoization segment.
  const memoIdx = lines.findIndex((l) =>
    l.startsWith("Key-resolver memoization:"),
  );
  const headerIdx = lines.findIndex((l) => l.startsWith("JWK public-key import:"));
  assert.ok(headerIdx !== -1 && memoIdx !== -1 && headerIdx < memoIdx);
  const nonceIdx = lines.findIndex((l) => l.startsWith("Nonce generation:"));
  assert.ok(nonceIdx !== -1 && headerIdx !== -1 && nonceIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "JWK public-key import: exportPublicKeyJwk ships the main ed25519 public key as a JWK, a JSON wire round-trip carries it, and importPublicKeyJwk reads it back — the gateway side of JWK key distribution",
    `Exported JWK: kty="OKP", crv="Ed25519", x is 43 base64url chars (the key itself is fresh per run; only its shape is printed)`,
    `Verification with the imported JWK key: OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519")`,
    "Verification with a tampered JWK (first x character flipped): FAILED (code SIGNATURE_MISMATCH: signature mismatch)",
  ]);
});

test("demo signature-labels segment enumerates the dual-signed request's labels in wire order", async () => {
  const { dualSigned, signatureLabels } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_SIGNATURE_LABELS: the main signature carries the library
  // default label `sig1` and the gateway appends `gateway` second —
  // the same two-label wire-order shape the bench pins as
  // PARSER_EXPECTED_LABELS and the addSignature tests pin for
  // their own dual-signed requests.
  assert.deepEqual(DEMO_SIGNATURE_LABELS, ["sig1", "gateway"]);
  assert.equal(DEMO_SIGNATURE_LABELS[1], DEMO_GATEWAY_LABEL);
  assert.deepEqual(signatureLabels, [...DEMO_SIGNATURE_LABELS]);
  assert.ok(dualSigned.headers["signature-input"].startsWith("sig1="));
  assert.ok(dualSigned.headers["signature-input"].includes(", gateway="));
});

test("demo lines contain the signature-labels segment (right after dual verification, before content-type tampering)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.ok(
    out.includes(
      "Signature labels: listSignatureLabels enumerates the labels in the dual-signed request's Signature-Input in wire order — enumerate first, then verify each label",
    ),
  );
  assert.ok(
    out.includes("Signature labels in the dual-signed request: sig1, gateway (2 labels)"),
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature labels: listSignatureLabels"),
  );
  const dualIdx = lines.findIndex((l) =>
    l.startsWith("Dual verification gateway:"),
  );
  const tamperIdx = lines.findIndex((l) =>
    l.startsWith("Tampered content-type:"),
  );
  assert.ok(dualIdx !== -1 && headerIdx !== -1 && tamperIdx !== -1);
  assert.ok(dualIdx < headerIdx && headerIdx < tamperIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 2), [
    "Signature labels: listSignatureLabels enumerates the labels in the dual-signed request's Signature-Input in wire order — enumerate first, then verify each label",
    "Signature labels in the dual-signed request: sig1, gateway (2 labels)",
  ]);
});

test("compiled demo script exits 0 and prints success plus tamper rejection", () => {
  const out = execFileSync("node", [path.join(repoRoot, "dist", "src", "demo.js")], {
    encoding: "utf8",
  });

  assert.match(out, /RFC 9421 signing demo \(ed25519\)/);
  assert.match(out, /Signature-Input: sig1=/);
  assert.match(out, /Signature: sig1=:/);
  assert.match(out, /Verification: OK /);
  assert.match(
    out,
    /Verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
  assert.match(out, /Signature base \(RFC 9421 §2\.5\): the exact string signed/);
  assert.match(out, /"@method": POST\n"@authority": api\.example\.com\n"@path": \/v1\/payments/);
  assert.match(out, /Each base line above is one covered component in order/);
  assert.match(out, /Dual Signature-Input: sig1=.*gateway=/);
  assert.match(out, /Dual verification gateway: OK /);
  assert.match(
    out,
    /After content-type tampering gateway: FAILED \(code SIGNATURE_MISMATCH:/,
  );
  assert.match(
    out,
    /Replay check, second presentation of the same request: FAILED \(code NONCE_REPLAY:/,
  );
  assert.match(out, /sha-256 Content-Digest: sha-256=:/);
  assert.match(out, /sha-256 verification: OK /);
  assert.match(
    out,
    /sha-256 verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
  assert.match(out, /Content-Digest algorithm identification: contentDigestAlgOf reads the algorithm off an existing Content-Digest header/);
  assert.match(out, /contentDigestAlgOf on the main line's Content-Digest: sha-512/);
  assert.match(out, /contentDigestAlgOf on the sha-256 peer line's Content-Digest: sha-256/);
  assert.match(out, /contentDigestAlgOf on the unrecognized value "sha-1=:abc=:": undefined/);
  assert.match(out, /Inbound normalization: mock Node IncomingMessage normalized with fromNodeRequest/);
  assert.match(out, /Inbound verification: OK /);
  assert.match(
    out,
    /Inbound verification with wrong scheme "http": FAILED \(code SIGNATURE_MISMATCH:/,
  );
  assert.match(out, /JWKS key resolution: JwksKeyStore restored offline/);
  assert.match(
    out,
    /JWKS verification for unknown keyid "demo-unknown-key-1": FAILED \(code KEY_RESOLUTION_FAILED:/,
  );
  assert.match(out, /JWK thumbprint: RFC 7638 thumbprint of the demo ed25519 public JWK is "[A-Za-z0-9_-]{43}"/);
  assert.match(out, /Thumbprint-as-keyid verification: OK /);
  assert.match(out, /Structured-field canonicalization \(;sf\):/);
  assert.match(out, /Canonicalize dictionary-decimal: limit=1500, remaining=1\.5 -> limit=1500, remaining=1\.500/);
  assert.match(out, /Canonicalize item-leading-zero-integer: 007 -> 7/);
  assert.match(out, /Dictionary-member extraction \(;key\):/);
  assert.match(out, /Extract member a: 1/);
  assert.match(out, /Extract member b: 2;x=1;y=2/);
  assert.match(out, /Extract member n: 1\.500/);
  assert.match(out, /Extract member sig: :aGVsbG8=:;x=\?0/);
  assert.match(out, /Extract member c: \(a b c\)/);
  assert.match(out, /Extract member d: \?1/);
  assert.match(out, /Extract member zzz: FAILED \(dictionary member "zzz" is not present in the field value\)/);
  assert.match(out, /Signature-params serialization: the covered-component inner list/);
  assert.match(out, /Serialize empty: \(\);created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp\.yemd"/);
  assert.match(out, /Serialize golden: \("@method" "@authority" "@path" "content-digest"\);created=1700000000;keyid="k1";alg="hmac-sha256"/);
  assert.match(out, /Serialize full: \("@method" "@authority" "@path" "content-digest"\);created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"/);
  assert.match(out, /Serialize escaped: \("@method"\);created=1700000000;keyid="k";alg="ed25519";nonce=/);
  assert.match(out, /PEM key round-trip: the main ed25519 key pair exported as PEM, imported back/);
  assert.match(out, /PEM public key header: -----BEGIN PUBLIC KEY-----/);
  assert.match(out, /PEM private key header: -----BEGIN PRIVATE KEY-----/);
  assert.match(out, /PEM round-trip verification: OK /);
  assert.match(out, /Throwing verification: verifyRequestOrThrow returns the verified identity on success/);
  assert.match(out, /verifyRequestOrThrow on the main request: OK \(label sig1, keyid="demo-key-1", alg="ed25519", nonce="demo-nonce-001"\)/);
  assert.match(out, /verifyRequestOrThrow on the tampered-body request: FAILED \(threw VerifyError, code BODY_DIGEST_MISMATCH: body does not match content-digest\)/);
  assert.match(out, /Nonce generation: generateNonce draws a fresh nonce from the CSPRNG and base64url-encodes it/);
  assert.match(out, /generateNonce\(\): "[A-Za-z0-9_-]{22}" \(22 chars, base64url, decodes to 16 bytes\)/);
  assert.match(out, /generateNonce\(32\): "[A-Za-z0-9_-]{43}" \(43 chars, base64url, decodes to 32 bytes\)/);
  assert.match(out, /Verification with the generated nonce: OK \(label sig1, keyid="demo-key-1", alg="ed25519", nonce="[A-Za-z0-9_-]{22}"\)/);
  assert.match(out, /JWK public-key import: exportPublicKeyJwk ships the main ed25519 public key as a JWK/);
  assert.match(out, /Exported JWK: kty="OKP", crv="Ed25519", x is 43 base64url chars/);
  assert.match(out, /Verification with the imported JWK key: OK \(label sig1, keyid="demo-key-1", alg="ed25519"\)/);
  assert.match(out, /Verification with a tampered JWK \(first x character flipped\): FAILED \(code SIGNATURE_MISMATCH:/);
  assert.match(out, /Key-resolver memoization: memoizeKeyResolver caches each keyid's resolved key/);
  assert.match(out, /Memoized verification, first verification of keyid "demo-key-1": OK \(label sig1, keyid="demo-key-1", alg="ed25519"\)/);
  assert.match(out, /Underlying resolver calls after verifying keyid "demo-key-1" twice: 1 \(the second verification was served from the cache\)/);
  assert.match(out, /Memoized verification for keyid "demo-key-2": OK \(label sig1, keyid="demo-key-2", alg="ed25519"\)/);
  assert.match(out, /Underlying resolver calls after verifying keyid "demo-key-2": 2 \(a new keyid misses the cache and resolves once\)/);
  assert.match(out, /HMAC secret-length guard: assertHmacSecretLength enforces the per-algorithm secret floor/);
  assert.match(out, /assertHmacSecretLength for hmac-sha256 with a 32-byte secret: OK \(meets the 32-byte floor\)/);
  assert.match(out, /assertHmacSecretLength for hmac-sha512 with a 64-byte secret: OK \(meets the 64-byte floor\)/);
  assert.match(out, /assertHmacSecretLength for hmac-sha256 with a 31-byte secret: FAILED \(assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes/);
  assert.match(out, /assertHmacSecretLength for hmac-sha512 with a 63-byte secret: FAILED \(assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes/);
  assert.match(out, /RSA modulus-length guard: assertRsaModulusLength enforces the RSA modulus floor/);
  assert.match(out, /assertRsaModulusLength for rsa-2048 public key \(2048 bits\): OK \(meets the 2048-bit floor\)/);
  assert.match(out, /assertRsaModulusLength for rsa-1024 public key \(1024 bits\): FAILED \(assertRsaModulusLength demo: RSA modulus must be at least 2048 bits, got 1024 bits\)/);
  assert.match(out, /assertRsaModulusLength for ed25519 public key: FAILED \(assertRsaModulusLength demo: expected an RSA key, got an asymmetric ed25519 key\)/);
});

test("demo key-resolver memoization segment resolves each keyid once (repeat is a cache hit, second keyid advances the count)", async () => {
  const {
    memoizedFirstVerification,
    memoizedRepeatVerification,
    memoizedSecondKeyVerification,
    memoizedResolverCallsAfterRepeat,
    memoizedResolverCallsAfterSecondKey,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_MEMOIZED_CALLS_AFTER_REPEAT /
  // DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY and cross-checked
  // against test/memoizeKeyResolver.test.ts, whose counting
  // store pins the same shape: three verifies of one keyid cost
  // one underlying call, and distinct keyids cache independently.
  // The test pins the literals again here so a drift in either
  // place fails.
  assert.equal(DEMO_MEMOIZED_SECOND_KEY_ID, "demo-key-2");
  assert.equal(DEMO_MEMOIZED_NONCE, "demo-nonce-memoized-001");
  assert.equal(DEMO_MEMOIZED_TTL_SEC, 300);
  assert.equal(DEMO_MEMOIZED_CALLS_AFTER_REPEAT, 1);
  assert.equal(DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY, 2);

  assert.equal(memoizedFirstVerification.ok, true);
  assert.equal(memoizedFirstVerification.keyId, DEMO_KEY_ID);
  assert.equal(memoizedFirstVerification.alg, "ed25519");
  assert.equal(memoizedRepeatVerification.ok, true);
  assert.equal(memoizedRepeatVerification.keyId, DEMO_KEY_ID);
  assert.equal(memoizedResolverCallsAfterRepeat, 1);

  assert.equal(memoizedSecondKeyVerification.ok, true);
  assert.equal(memoizedSecondKeyVerification.keyId, DEMO_MEMOIZED_SECOND_KEY_ID);
  assert.equal(memoizedSecondKeyVerification.alg, "ed25519");
  assert.equal(memoizedSecondKeyVerification.nonce, DEMO_MEMOIZED_NONCE);
  assert.equal(memoizedResolverCallsAfterSecondKey, 2);

  // Deterministic double run: the counts are pinned constants,
  // not values read off a wall clock or a random keystore.
  const again = await runDemo();
  assert.equal(again.memoizedResolverCallsAfterRepeat, 1);
  assert.equal(again.memoizedResolverCallsAfterSecondKey, 2);
});

test("demo lines contain the key-resolver memoization segment (counts printed, followed by the HMAC guard segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Key-resolver memoization: memoizeKeyResolver caches each keyid's resolved key for a TTL/,
  );
  // The memoization segment sits after the JWK import segment
  // and is followed by the HMAC secret-length guard segment.
  const guardIdx = lines.findIndex((l) =>
    l.startsWith("HMAC secret-length guard:"),
  );
  const memoLineIdx = lines.findIndex((l) =>
    l.startsWith(
      `Underlying resolver calls after verifying keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}"`,
    ),
  );
  assert.ok(memoLineIdx !== -1 && guardIdx !== -1 && memoLineIdx < guardIdx);
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Key-resolver memoization:"),
  );
  const jwkIdx = lines.findIndex((l) => l.startsWith("JWK public-key import:"));
  assert.ok(jwkIdx !== -1 && headerIdx !== -1 && jwkIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 5), [
    "Key-resolver memoization: memoizeKeyResolver caches each keyid's resolved key for a TTL, so a gateway verifying at high rate pays the keystore lookup once per keyid instead of once per request",
    `Memoized verification, first verification of keyid "${DEMO_KEY_ID}": OK (label sig1, keyid="${DEMO_KEY_ID}", alg="ed25519")`,
    `Underlying resolver calls after verifying keyid "${DEMO_KEY_ID}" twice: 1 (the second verification was served from the cache)`,
    `Memoized verification for keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}": OK (label sig1, keyid="${DEMO_MEMOIZED_SECOND_KEY_ID}", alg="ed25519")`,
    `Underlying resolver calls after verifying keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}": 2 (a new keyid misses the cache and resolves once)`,
  ]);
});

test("demo HMAC secret-length guard segment accepts floor lengths and rejects one byte below (per algorithm)", async () => {
  const { hmacGuardAccepted, hmacGuardRejections } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_HMAC_GUARD_ACCEPTED / DEMO_HMAC_GUARD_REJECTED /
  // DEMO_HMAC_GUARD_ERRORS and cross-checked against
  // src/keys.ts (MIN_HMAC_SECRET_BYTES 32 /
  // MIN_HMAC_SHA512_SECRET_BYTES 64) and the keyLength /
  // hmacSha512 suites. The test pins the literals again here
  // so a drift in either place fails.
  assert.deepEqual(DEMO_HMAC_GUARD_ACCEPTED, [
    { alg: "hmac-sha256", bytes: 32 },
    { alg: "hmac-sha512", bytes: 64 },
  ]);
  assert.deepEqual(DEMO_HMAC_GUARD_REJECTED, [
    { alg: "hmac-sha256", bytes: 31 },
    { alg: "hmac-sha512", bytes: 63 },
  ]);
  assert.deepEqual(DEMO_HMAC_GUARD_ERRORS, [
    "assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes (RFC 2104: the key SHOULD be at least as long as the hash output; sha-256 → 32 bytes), got 31 bytes",
    "assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes (RFC 2104: the key SHOULD be at least as long as the hash output; sha-512 → 64 bytes), got 63 bytes",
  ]);
  assert.deepEqual(hmacGuardAccepted, [...DEMO_HMAC_GUARD_ACCEPTED]);
  assert.deepEqual(
    hmacGuardRejections,
    DEMO_HMAC_GUARD_REJECTED.map((r, i) => ({
      ...r,
      error: DEMO_HMAC_GUARD_ERRORS[i],
    })),
  );

  // Cross-check against the library guard called directly:
  // the same lengths pass / throw with the same messages.
  for (const entry of DEMO_HMAC_GUARD_ACCEPTED) {
    assert.doesNotThrow(() =>
      assertHmacSecretLength(
        createSecretKey(Buffer.alloc(entry.bytes, 0xab)),
        entry.alg,
      ),
    );
  }
  DEMO_HMAC_GUARD_REJECTED.forEach((entry, i) => {
    assert.throws(
      () =>
        assertHmacSecretLength(
          createSecretKey(Buffer.alloc(entry.bytes, 0xab)),
          entry.alg,
        ),
      (e: unknown) =>
        e instanceof Error && e.message === DEMO_HMAC_GUARD_ERRORS[i],
    );
  });
});

test("demo lines contain the HMAC secret-length guard segment (accepted and rejected lines, followed by the RSA guard segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /HMAC secret-length guard: assertHmacSecretLength enforces the per-algorithm secret floor/,
  );
  // The guard block sits after the memoization segment and is
  // followed by the RSA modulus-length guard segment.
  const rsaIdx = lines.findIndex((l) =>
    l.startsWith("RSA modulus-length guard:"),
  );
  assert.ok(rsaIdx !== -1 && rsaIdx > lines.findIndex((l) => l.startsWith("HMAC secret-length guard:")));
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("HMAC secret-length guard:"),
  );
  const memoIdx = lines.findIndex((l) =>
    l.startsWith("Key-resolver memoization:"),
  );
  assert.ok(memoIdx !== -1 && headerIdx !== -1 && memoIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 5), [
    "HMAC secret-length guard: assertHmacSecretLength enforces the per-algorithm secret floor before any MAC runs — hmac-sha256 secrets at least 32 bytes, hmac-sha512 secrets at least 64 bytes (RFC 2104: the key SHOULD be at least as long as the hash output)",
    "assertHmacSecretLength for hmac-sha256 with a 32-byte secret: OK (meets the 32-byte floor)",
    "assertHmacSecretLength for hmac-sha512 with a 64-byte secret: OK (meets the 64-byte floor)",
    `assertHmacSecretLength for hmac-sha256 with a 31-byte secret: FAILED (${DEMO_HMAC_GUARD_ERRORS[0]})`,
    `assertHmacSecretLength for hmac-sha512 with a 63-byte secret: FAILED (${DEMO_HMAC_GUARD_ERRORS[1]})`,
  ]);

  // Deterministic double run: the guard segment's lines are
  // pinned constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("HMAC secret-length guard:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 5),
    lines.slice(headerIdx, headerIdx + 5),
  );
});

test("demo RSA modulus-length guard segment accepts the floor key and rejects weak and non-RSA keys", async () => {
  const { rsaGuardAccepted, rsaGuardRejections } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_RSA_GUARD_ACCEPTED / DEMO_RSA_GUARD_REJECTED /
  // DEMO_RSA_GUARD_ERRORS and cross-checked against
  // src/keys.ts (MIN_RSA_MODULUS_BITS 2048) and the bench
  // corpus / rsaV15 suite. The test pins the literals again
  // here so a drift in either place fails.
  assert.equal(DEMO_RSA_GUARD_CONTEXT, "assertRsaModulusLength demo");
  assert.deepEqual(DEMO_RSA_GUARD_ACCEPTED, [
    { label: "rsa-2048 public", bits: 2048 },
  ]);
  assert.deepEqual(DEMO_RSA_GUARD_REJECTED, [
    { label: "rsa-1024 public", bits: 1024 },
    { label: "ed25519 public", bits: null },
  ]);
  assert.deepEqual(DEMO_RSA_GUARD_ERRORS, [
    "assertRsaModulusLength demo: RSA modulus must be at least 2048 bits, got 1024 bits",
    "assertRsaModulusLength demo: expected an RSA key, got an asymmetric ed25519 key",
  ]);
  assert.deepEqual(rsaGuardAccepted, [...DEMO_RSA_GUARD_ACCEPTED]);
  assert.deepEqual(
    rsaGuardRejections,
    DEMO_RSA_GUARD_REJECTED.map((r, i) => ({
      ...r,
      error: DEMO_RSA_GUARD_ERRORS[i],
    })),
  );

  // Cross-check against the library guard called directly:
  // the same key shapes pass / throw with the same messages.
  assert.doesNotThrow(() =>
    assertRsaModulusLength(
      generateRsaPssKeyPair().publicKey,
      DEMO_RSA_GUARD_CONTEXT,
    ),
  );
  assert.throws(
    () =>
      assertRsaModulusLength(
        generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey,
        DEMO_RSA_GUARD_CONTEXT,
      ),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_RSA_GUARD_ERRORS[0],
  );
  assert.throws(
    () =>
      assertRsaModulusLength(
        generateEd25519KeyPair().publicKey,
        DEMO_RSA_GUARD_CONTEXT,
      ),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_RSA_GUARD_ERRORS[1],
  );
});

test("demo lines contain the RSA modulus-length guard segment (accepted and rejected lines, followed by the ECDSA P-256 segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /RSA modulus-length guard: assertRsaModulusLength enforces the RSA modulus floor/,
  );
  // The RSA guard block sits after the HMAC segment and is
  // followed by the ECDSA P-256 signing segment.
  const p256Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-256 signing:"),
  );
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("RSA modulus-length guard:"),
  );
  assert.ok(p256Idx !== -1 && headerIdx !== -1 && headerIdx < p256Idx);
  const hmacIdx = lines.findIndex((l) =>
    l.startsWith("HMAC secret-length guard:"),
  );
  assert.ok(hmacIdx !== -1 && headerIdx !== -1 && hmacIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "RSA modulus-length guard: assertRsaModulusLength enforces the RSA modulus floor before any RSA operation runs — RSA keys at least 2048 bits, and non-RSA keys are rejected as a caller configuration error",
    "assertRsaModulusLength for rsa-2048 public key (2048 bits): OK (meets the 2048-bit floor)",
    `assertRsaModulusLength for rsa-1024 public key (1024 bits): FAILED (${DEMO_RSA_GUARD_ERRORS[0]})`,
    `assertRsaModulusLength for ed25519 public key: FAILED (${DEMO_RSA_GUARD_ERRORS[1]})`,
  ]);

  // Deterministic double run: the guard segment's lines are
  // pinned constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("RSA modulus-length guard:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo ECDSA P-256 segment signs the fixed request, verifies, and rejects the one-byte tamper", async () => {
  const { p256Signed, p256Verification, p256TamperedVerification } =
    await runDemo();

  // Expectations are the literals hand-pinned in DEMO_P256_*
  // and cross-checked against test/ecdsaP256.test.ts (its
  // round-trip case pins the same keyid/alg identity shape and
  // its tampered-body case pins the same rejection code).
  // The test pins the literals again here so a drift in
  // either place fails.
  assert.equal(DEMO_P256_KEY_ID, "demo-p256-key-1");
  assert.equal(DEMO_P256_NONCE, "demo-nonce-p256-001");
  assert.equal(DEMO_P256_LABEL, "sig1");
  assert.equal(DEMO_P256_ALG, "ecdsa-p256-sha256");
  assert.equal(DEMO_P256_TAMPERED_CODE, "BODY_DIGEST_MISMATCH");

  assert.equal(
    p256Signed.headers["signature-input"],
    `sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P256_KEY_ID}";alg="${DEMO_P256_ALG}";nonce="${DEMO_P256_NONCE}"`,
  );
  assert.ok(p256Signed.headers["content-digest"].startsWith("sha-512=:"));
  // RFC 9421 §3.3.4 wire form: the signature is the raw
  // 64-octet r||s concatenation, never a DER value.
  const raw = Buffer.from(
    p256Signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  assert.equal(raw.length, 64);

  assert.equal(p256Verification.ok, true);
  assert.equal(p256Verification.label, DEMO_P256_LABEL);
  assert.equal(p256Verification.keyId, DEMO_P256_KEY_ID);
  assert.equal(p256Verification.alg, DEMO_P256_ALG);
  assert.equal(p256Verification.nonce, DEMO_P256_NONCE);

  assert.equal(p256TamperedVerification.ok, false);
  assert.equal(p256TamperedVerification.code, DEMO_P256_TAMPERED_CODE);

  // Cross-check against the library called directly: a fresh
  // P-256 pair signing the same fixed request shape verifies
  // with the same identity, and the same body tamper is
  // rejected with the same code.
  const { publicKey, privateKey } = generateP256KeyPair();
  const direct = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P256_KEY_ID,
      alg: "ecdsa-p256-sha256",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P256_NONCE,
    },
  );
  const directOk = verifyRequest(direct, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  assert.equal(directOk.ok, true);
  assert.equal(directOk.keyId, DEMO_P256_KEY_ID);
  assert.equal(directOk.alg, DEMO_P256_ALG);
  const directTampered = verifyRequest(
    { ...direct, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );
  assert.equal(directTampered.ok, false);
  assert.equal(directTampered.code, DEMO_P256_TAMPERED_CODE);
});

test("demo lines contain the ECDSA P-256 signing segment (signature-input, verification and tamper rejection, followed by the Content-Digest guard segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /ECDSA P-256 signing: ecdsa-p256-sha256 signs/);
  // The P-256 block sits after the RSA guard segment and is
  // followed by the Content-Digest algorithm guard segment.
  const digestIdx = lines.findIndex((l) =>
    l.startsWith("Content-Digest algorithm guard:"),
  );
  assert.ok(digestIdx !== -1);
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-256 signing:"),
  );
  const rsaIdx = lines.findIndex((l) =>
    l.startsWith("RSA modulus-length guard:"),
  );
  assert.ok(rsaIdx !== -1 && headerIdx !== -1 && rsaIdx < headerIdx);
  assert.ok(headerIdx < digestIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "ECDSA P-256 signing: ecdsa-p256-sha256 signs the same fixed payment request with a P-256 key — the NIST curve line the ed25519 main line and the hmac-sha256 gateway line never showed",
    `P-256 Signature-Input: sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P256_KEY_ID}";alg="${DEMO_P256_ALG}";nonce="${DEMO_P256_NONCE}"`,
    `P-256 verification: OK (label ${DEMO_P256_LABEL}, keyid="${DEMO_P256_KEY_ID}", alg="${DEMO_P256_ALG}", nonce="${DEMO_P256_NONCE}")`,
    "P-256 verification after tampering: FAILED (code BODY_DIGEST_MISMATCH: body does not match content-digest)",
  ]);

  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs even though the
  // P-256 key pair itself is fresh.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("ECDSA P-256 signing:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo Content-Digest algorithm guard segment accepts the two emittable algorithms and rejects the fixed corpus", async () => {
  const { digestGuardAccepted, digestGuardRejections } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_DIGEST_GUARD_ACCEPTED / DEMO_DIGEST_GUARD_REJECTED /
  // DEMO_DIGEST_GUARD_ERRORS and cross-checked against
  // src/digest.ts and the bench corpus / contentDigestAlg
  // suite. The test pins the literals again here so a drift
  // in either place fails.
  assert.deepEqual(DEMO_DIGEST_GUARD_ACCEPTED, [
    { label: "sha-512", alg: "sha-512" },
    { label: "sha-256", alg: "sha-256" },
  ]);
  assert.deepEqual(DEMO_DIGEST_GUARD_REJECTED, [
    { label: "sha-1", alg: "sha-1" },
    { label: "md5", alg: "md5" },
    { label: "empty string", alg: "" },
    { label: "SHA-512 (uppercase)", alg: "SHA-512" },
    { label: "Sha-256 (mixed case)", alg: "Sha-256" },
    { label: "sha-512 with trailing space", alg: "sha-512 " },
    { label: "undefined", alg: undefined },
    { label: "null", alg: null },
  ]);
  assert.deepEqual(DEMO_DIGEST_GUARD_ERRORS, [
    'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-1"',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got "md5"',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got ""',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got "SHA-512"',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got "Sha-256"',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-512 "',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got undefined',
    'contentDigest: "alg" must be "sha-512" or "sha-256", got null',
  ]);
  assert.deepEqual(digestGuardAccepted, [...DEMO_DIGEST_GUARD_ACCEPTED]);
  assert.deepEqual(
    digestGuardRejections,
    DEMO_DIGEST_GUARD_REJECTED.map((r, i) => ({
      ...r,
      error: DEMO_DIGEST_GUARD_ERRORS[i],
    })),
  );

  // Cross-check against the library guard called directly:
  // the same values pass / throw with the same messages.
  for (const entry of DEMO_DIGEST_GUARD_ACCEPTED) {
    assert.doesNotThrow(() => assertContentDigestAlg(entry.alg));
  }
  DEMO_DIGEST_GUARD_REJECTED.forEach((entry, i) => {
    assert.throws(
      () => assertContentDigestAlg(entry.alg),
      (e: unknown) =>
        e instanceof Error && e.message === DEMO_DIGEST_GUARD_ERRORS[i],
    );
  });
});

test("demo lines contain the Content-Digest algorithm guard segment (accepted and rejected lines, followed by the ReplayCache snapshot segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /Content-Digest algorithm guard: assertContentDigestAlg enforces the emittable digest set/,
  );
  // The digest guard block sits after the ECDSA P-256
  // signing segment and is followed by the ReplayCache
  // snapshot persistence segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Content-Digest algorithm guard:"),
  );
  const p256Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-256 signing:"),
  );
  assert.ok(p256Idx !== -1 && headerIdx !== -1 && p256Idx < headerIdx);
  const snapshotIdx = lines.findIndex((l) =>
    l.startsWith("ReplayCache snapshot persistence:"),
  );
  assert.ok(snapshotIdx !== -1 && headerIdx < snapshotIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 11), [
    "Content-Digest algorithm guard: assertContentDigestAlg enforces the emittable digest set before any hashing runs — only \"sha-512\" and \"sha-256\" pass, every other value is rejected as a caller configuration error",
    "assertContentDigestAlg for sha-512: OK (emittable digest algorithm)",
    "assertContentDigestAlg for sha-256: OK (emittable digest algorithm)",
    `assertContentDigestAlg for sha-1: FAILED (${DEMO_DIGEST_GUARD_ERRORS[0]})`,
    `assertContentDigestAlg for md5: FAILED (${DEMO_DIGEST_GUARD_ERRORS[1]})`,
    `assertContentDigestAlg for empty string: FAILED (${DEMO_DIGEST_GUARD_ERRORS[2]})`,
    `assertContentDigestAlg for SHA-512 (uppercase): FAILED (${DEMO_DIGEST_GUARD_ERRORS[3]})`,
    `assertContentDigestAlg for Sha-256 (mixed case): FAILED (${DEMO_DIGEST_GUARD_ERRORS[4]})`,
    `assertContentDigestAlg for sha-512 with trailing space: FAILED (${DEMO_DIGEST_GUARD_ERRORS[5]})`,
    `assertContentDigestAlg for undefined: FAILED (${DEMO_DIGEST_GUARD_ERRORS[6]})`,
    `assertContentDigestAlg for null: FAILED (${DEMO_DIGEST_GUARD_ERRORS[7]})`,
  ]);
  // Deterministic double run: the guard segment's lines are
  // pinned constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Content-Digest algorithm guard:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 11),
    lines.slice(headerIdx, headerIdx + 11),
  );
});

test("demo ReplayCache snapshot segment exports the seen nonce and the restored cache still rejects it", async () => {
  const {
    replaySnapshotSigned,
    replaySnapshotFirstVerification,
    replaySnapshotExport,
    replaySnapshotReplayVerification,
    replaySnapshotFreshVerification,
    replaySnapshotRestoredSize,
    replaySnapshotOriginalSize,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_REPLAY_SNAPSHOT_* and cross-checked against
  // test/replaySnapshot.test.ts (snapshot round-trip shape
  // and the end-to-end NONCE_REPLAY code). The test pins
  // the literals again here so a drift in either place fails.
  assert.equal(DEMO_REPLAY_SNAPSHOT_NONCE, "demo-nonce-replay-snapshot-001");
  assert.equal(
    DEMO_REPLAY_SNAPSHOT_FRESH_NONCE,
    "demo-nonce-replay-snapshot-002",
  );
  assert.deepEqual(DEMO_REPLAY_SNAPSHOT_ENTRIES, [
    [DEMO_REPLAY_SNAPSHOT_NONCE, DEMO_CREATED + 60],
  ]);
  assert.equal(DEMO_REPLAY_SNAPSHOT_CODE, "NONCE_REPLAY");
  assert.equal(DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE, 2);
  assert.equal(DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE, 1);

  assert.ok(
    replaySnapshotSigned.headers["signature-input"].includes(
      `nonce="${DEMO_REPLAY_SNAPSHOT_NONCE}"`,
    ),
  );
  assert.equal(replaySnapshotFirstVerification.ok, true);
  assert.equal(
    replaySnapshotFirstVerification.nonce,
    DEMO_REPLAY_SNAPSHOT_NONCE,
  );

  // The exported snapshot is exactly the pinned v1 shape:
  // one entry, the segment nonce at the fixed verify instant.
  assert.deepEqual(replaySnapshotExport, {
    v: 1,
    entries: [...DEMO_REPLAY_SNAPSHOT_ENTRIES],
  });

  // After the "restart" the same request is a replay, while
  // a fresh nonce still verifies against the restored cache.
  assert.equal(replaySnapshotReplayVerification.ok, false);
  assert.equal(
    replaySnapshotReplayVerification.code,
    DEMO_REPLAY_SNAPSHOT_CODE,
  );
  assert.equal(replaySnapshotFreshVerification.ok, true);
  assert.equal(
    replaySnapshotFreshVerification.nonce,
    DEMO_REPLAY_SNAPSHOT_FRESH_NONCE,
  );

  // The fresh record landed only in the restored cache:
  // restored holds both nonces, the original still holds
  // only the exported one.
  assert.equal(replaySnapshotRestoredSize, DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE);
  assert.equal(replaySnapshotOriginalSize, DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE);

  // Cross-check against the library called directly: a cache
  // restored from the demo's exported snapshot (through the
  // JSON persistence path) rejects the exported nonce and
  // records a fresh one — the replaySnapshot suite's shape.
  const restored = ReplayCache.restore(
    JSON.parse(JSON.stringify(replaySnapshotExport)),
    {
      maxEntries: DEMO_REPLAY_CACHE_MAX_ENTRIES,
      ttlSec: DEMO_REPLAY_CACHE_TTL_SEC,
      now: () => DEMO_CREATED + 60,
    },
  );
  assert.equal(restored.check(DEMO_REPLAY_SNAPSHOT_NONCE), true);
  assert.equal(restored.check(DEMO_REPLAY_SNAPSHOT_FRESH_NONCE), false);
});

test("demo lines contain the ReplayCache snapshot segment (export, restored replay rejection and detached original, followed by the ECDSA P-384 segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /ReplayCache snapshot persistence: exportSnapshot carries/);
  // The snapshot block sits after the Content-Digest
  // algorithm guard segment and is followed by the ECDSA
  // P-384 signing segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("ReplayCache snapshot persistence:"),
  );
  const digestIdx = lines.findIndex((l) =>
    l.startsWith("Content-Digest algorithm guard:"),
  );
  assert.ok(digestIdx !== -1 && headerIdx !== -1 && digestIdx < headerIdx);
  const p384Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-384 signing:"),
  );
  assert.ok(p384Idx !== -1 && headerIdx < p384Idx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 6), [
    "ReplayCache snapshot persistence: exportSnapshot carries the seen nonces across a restart — ReplayCache.restore rebuilds the cache at startup, so a nonce seen before the restart is still a replay after it",
    `Replay snapshot, first verification of nonce "${DEMO_REPLAY_SNAPSHOT_NONCE}": OK (recorded in the segment's ReplayCache)`,
    `Exported ReplayCache snapshot: 1 entry in a v1 snapshot (nonce "${DEMO_REPLAY_SNAPSHOT_NONCE}", first seen at ${DEMO_CREATED + 60})`,
    `Replay snapshot, same request against the restored cache: FAILED (code NONCE_REPLAY: nonce replay detected: "${DEMO_REPLAY_SNAPSHOT_NONCE}" was already seen)`,
    `Replay snapshot, new request with nonce "${DEMO_REPLAY_SNAPSHOT_FRESH_NONCE}" against the restored cache: OK (a fresh nonce is not a replay — recorded only in the restored cache)`,
    `Original ReplayCache after the restored cache recorded the fresh nonce: 1 entry (restored cache: 2 entries — the restore is detached, the original is unaffected)`,
  ]);
  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("ReplayCache snapshot persistence:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 6),
    lines.slice(headerIdx, headerIdx + 6),
  );
});

test("demo ECDSA P-384 segment signs the fixed request, verifies, and rejects the one-byte tamper", async () => {
  const { p384Signed, p384Verification, p384TamperedVerification } =
    await runDemo();

  // Expectations are the literals hand-pinned in DEMO_P384_*
  // and cross-checked against test/ecdsaP384.test.ts (its
  // round-trip case pins the same keyid/alg identity shape and
  // its tampered-body case pins the same rejection code).
  // The test pins the literals again here so a drift in
  // either place fails.
  assert.equal(DEMO_P384_KEY_ID, "demo-p384-key-1");
  assert.equal(DEMO_P384_NONCE, "demo-nonce-p384-001");
  assert.equal(DEMO_P384_LABEL, "sig1");
  assert.equal(DEMO_P384_ALG, "ecdsa-p384-sha384");
  assert.equal(DEMO_P384_TAMPERED_CODE, "BODY_DIGEST_MISMATCH");

  assert.equal(
    p384Signed.headers["signature-input"],
    `sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P384_KEY_ID}";alg="${DEMO_P384_ALG}";nonce="${DEMO_P384_NONCE}"`,
  );
  assert.ok(p384Signed.headers["content-digest"].startsWith("sha-512=:"));
  // RFC 9421 §3.3.5 wire form: the signature is the raw
  // 96-octet r||s concatenation (48 octets per limb), never
  // a DER value and never the 64-octet P-256 width.
  const raw = Buffer.from(
    p384Signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  assert.equal(raw.length, 96);

  assert.equal(p384Verification.ok, true);
  assert.equal(p384Verification.label, DEMO_P384_LABEL);
  assert.equal(p384Verification.keyId, DEMO_P384_KEY_ID);
  assert.equal(p384Verification.alg, DEMO_P384_ALG);
  assert.equal(p384Verification.nonce, DEMO_P384_NONCE);

  assert.equal(p384TamperedVerification.ok, false);
  assert.equal(p384TamperedVerification.code, DEMO_P384_TAMPERED_CODE);

  // Cross-check against the library called directly: a fresh
  // P-384 pair signing the same fixed request shape verifies
  // with the same identity, and the same body tamper is
  // rejected with the same code.
  const { publicKey, privateKey } = generateP384KeyPair();
  const direct = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P384_KEY_ID,
      alg: "ecdsa-p384-sha384",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P384_NONCE,
    },
  );
  const directOk = verifyRequest(direct, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  assert.equal(directOk.ok, true);
  assert.equal(directOk.keyId, DEMO_P384_KEY_ID);
  assert.equal(directOk.alg, DEMO_P384_ALG);
  const directTampered = verifyRequest(
    { ...direct, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );
  assert.equal(directTampered.ok, false);
  assert.equal(directTampered.code, DEMO_P384_TAMPERED_CODE);
});

test("demo lines contain the ECDSA P-384 signing segment (signature-input, verification and tamper rejection, followed by the Signature-Input parsing segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /ECDSA P-384 signing: ecdsa-p384-sha384 signs/);
  // The P-384 block sits after the ReplayCache snapshot
  // persistence segment and is followed by the
  // Signature-Input parsing segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-384 signing:"),
  );
  const snapshotIdx = lines.findIndex((l) =>
    l.startsWith("ReplayCache snapshot persistence:"),
  );
  assert.ok(snapshotIdx !== -1 && headerIdx !== -1 && snapshotIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "ECDSA P-384 signing: ecdsa-p384-sha384 signs the same fixed payment request with a P-384 key — the wider NIST curve whose 96-byte raw signature the P-256 segment's 64-byte form never showed",
    `P-384 Signature-Input: sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P384_KEY_ID}";alg="${DEMO_P384_ALG}";nonce="${DEMO_P384_NONCE}"`,
    `P-384 verification: OK (label ${DEMO_P384_LABEL}, keyid="${DEMO_P384_KEY_ID}", alg="${DEMO_P384_ALG}", nonce="${DEMO_P384_NONCE}")`,
    "P-384 verification after tampering: FAILED (code BODY_DIGEST_MISMATCH: body does not match content-digest)",
  ]);
  const parseIdx = lines.findIndex((l) =>
    l.startsWith("Signature-Input parsing:"),
  );
  assert.ok(parseIdx !== -1 && headerIdx < parseIdx);

  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs even though the
  // P-384 key pair itself is fresh.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("ECDSA P-384 signing:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo Signature-Input parsing segment parses the main signature and rejects the truncated copy", async () => {
  const { signed, signatureInputRaw, parsedSignatureInput, parseTamperedError } =
    await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_PARSE_* and cross-checked against the bench parser
  // fixture (its merchant member pins the same parameter
  // shape) and src/components.ts (which builds the pinned
  // tamper message). The test pins the literals again here
  // so a drift in either place fails.
  assert.equal(DEMO_PARSE_LABEL, "sig1");
  assert.equal(DEMO_PARSE_KEY_ID, "demo-key-1");
  assert.equal(DEMO_PARSE_ALG, "ed25519");
  assert.equal(DEMO_PARSE_CREATED, 1700000000);
  assert.equal(DEMO_PARSE_CREATED, DEMO_CREATED);
  assert.equal(DEMO_PARSE_NONCE, "demo-nonce-001");
  assert.equal(DEMO_PARSE_PREVIEW_CHARS, 72);
  assert.equal(
    DEMO_PARSE_RAW_INPUT,
    'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001"',
  );
  assert.equal(DEMO_PARSE_RAW_INPUT.length, 129);
  assert.equal(
    DEMO_PARSE_RAW_PREVIEW,
    DEMO_PARSE_RAW_INPUT.slice(0, DEMO_PARSE_PREVIEW_CHARS),
  );
  assert.equal(
    DEMO_PARSE_TAMPERED_ERROR,
    "malformed Signature-Input: unterminated inner list",
  );

  // The raw read-back is the main signed request's own
  // header, byte for byte.
  assert.equal(signatureInputRaw, DEMO_PARSE_RAW_INPUT);
  assert.equal(signatureInputRaw, signed.headers["signature-input"]);

  assert.equal(parsedSignatureInput.label, DEMO_PARSE_LABEL);
  assert.deepEqual(
    parsedSignatureInput.componentIds,
    DEMO_COVERED_COMPONENTS,
  );
  assert.equal(parsedSignatureInput.params.created, DEMO_PARSE_CREATED);
  assert.equal(parsedSignatureInput.params.keyid, DEMO_PARSE_KEY_ID);
  assert.equal(parsedSignatureInput.params.alg, DEMO_PARSE_ALG);
  assert.equal(parsedSignatureInput.params.nonce, DEMO_PARSE_NONCE);
  assert.equal(parsedSignatureInput.params.expires, undefined);

  assert.equal(parseTamperedError, DEMO_PARSE_TAMPERED_ERROR);

  // Cross-check against the library called directly: the
  // same raw read and parse over the demo's signed request
  // give the same shape, and the same truncated copy throws
  // the same pinned message.
  const directRaw = getHeaderRaw(signed.headers, "signature-input");
  assert.equal(directRaw, DEMO_PARSE_RAW_INPUT);
  const direct = parseSignatureInput(directRaw as string, DEMO_PARSE_LABEL);
  assert.deepEqual(direct, parsedSignatureInput);
  const directTampered = (directRaw as string).slice(
    0,
    (directRaw as string).indexOf(")"),
  );
  assert.throws(
    () => parseSignatureInput(directTampered, DEMO_PARSE_LABEL),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_PARSE_TAMPERED_ERROR,
  );
});

test("demo lines contain the Signature-Input parsing segment (raw preview, parsed fields and tamper rejection, followed by the ECDSA P-521 segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature-Input parsing: parseSignatureInput exposes/);
  // The parsing block sits after the ECDSA P-384 signing
  // segment and is followed by the ECDSA P-521 signing
  // segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature-Input parsing:"),
  );
  const p384Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-384 signing:"),
  );
  assert.ok(p384Idx !== -1 && headerIdx !== -1 && p384Idx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 5), [
    "Signature-Input parsing: parseSignatureInput exposes the parse layer a receiver debugs first — the raw header value, then the label, parameters and covered components the verifier rebuilds from it",
    `Raw Signature-Input (first ${DEMO_PARSE_PREVIEW_CHARS} of ${DEMO_PARSE_RAW_INPUT.length} chars): ${DEMO_PARSE_RAW_PREVIEW}…`,
    `Parsed ${DEMO_PARSE_LABEL}: keyid="${DEMO_PARSE_KEY_ID}", alg="${DEMO_PARSE_ALG}", created=${DEMO_PARSE_CREATED}, nonce="${DEMO_PARSE_NONCE}"`,
    `Parsed covered components: ${DEMO_COVERED_COMPONENTS.map((c) => `"${c}"`).join(" ")}`,
    `Tampered Signature-Input (closing parenthesis removed): FAILED (${DEMO_PARSE_TAMPERED_ERROR})`,
  ]);
  const p521Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-521 signing:"),
  );
  assert.ok(headerIdx !== -1 && p521Idx !== -1 && headerIdx < p521Idx);

  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Signature-Input parsing:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 5),
    lines.slice(headerIdx, headerIdx + 5),
  );
});

test("demo ECDSA P-521 segment signs the fixed request, verifies, and rejects the one-byte tamper", async () => {
  const { p521Signed, p521Verification, p521TamperedVerification } =
    await runDemo();

  // Expectations are the literals hand-pinned in DEMO_P521_*
  // and cross-checked against test/ecdsaP521.test.ts (its
  // round-trip case pins the same keyid/alg identity shape and
  // its tampered-body case pins the same rejection code).
  // The test pins the literals again here so a drift in
  // either place fails.
  assert.equal(DEMO_P521_KEY_ID, "demo-p521-key-1");
  assert.equal(DEMO_P521_NONCE, "demo-nonce-p521-001");
  assert.equal(DEMO_P521_LABEL, "sig1");
  assert.equal(DEMO_P521_ALG, "ecdsa-p521-sha512");
  assert.equal(DEMO_P521_TAMPERED_CODE, "BODY_DIGEST_MISMATCH");

  assert.equal(
    p521Signed.headers["signature-input"],
    `sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P521_KEY_ID}";alg="${DEMO_P521_ALG}";nonce="${DEMO_P521_NONCE}"`,
  );
  assert.ok(p521Signed.headers["content-digest"].startsWith("sha-512=:"));
  // RFC 9421 §3.3.6 wire form: the signature is the raw
  // 132-octet r||s concatenation (66 octets per limb), never
  // a DER value and never the 96-octet P-384 width.
  const raw = Buffer.from(
    p521Signed.headers["signature"].slice("sig1=:".length, -1),
    "base64",
  );
  assert.equal(raw.length, 132);

  assert.equal(p521Verification.ok, true);
  assert.equal(p521Verification.label, DEMO_P521_LABEL);
  assert.equal(p521Verification.keyId, DEMO_P521_KEY_ID);
  assert.equal(p521Verification.alg, DEMO_P521_ALG);
  assert.equal(p521Verification.nonce, DEMO_P521_NONCE);

  assert.equal(p521TamperedVerification.ok, false);
  assert.equal(p521TamperedVerification.code, DEMO_P521_TAMPERED_CODE);

  // Cross-check against the library called directly: a fresh
  // P-521 pair signing the same fixed request shape verifies
  // with the same identity, and the same body tamper is
  // rejected with the same code.
  const { publicKey, privateKey } = generateP521KeyPair();
  const direct = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P521_KEY_ID,
      alg: "ecdsa-p521-sha512",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P521_NONCE,
    },
  );
  const directOk = verifyRequest(direct, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  assert.equal(directOk.ok, true);
  assert.equal(directOk.keyId, DEMO_P521_KEY_ID);
  assert.equal(directOk.alg, DEMO_P521_ALG);
  const directTampered = verifyRequest(
    { ...direct, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );
  assert.equal(directTampered.ok, false);
  assert.equal(directTampered.code, DEMO_P521_TAMPERED_CODE);
});

test("demo lines contain the ECDSA P-521 signing segment (signature-input, verification and tamper rejection, followed by the component-resolution segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /ECDSA P-521 signing: ecdsa-p521-sha512 signs/);
  // The P-521 block sits after the Signature-Input parsing
  // segment and is followed by the component-resolution
  // segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-521 signing:"),
  );
  const parseIdx = lines.findIndex((l) =>
    l.startsWith("Signature-Input parsing:"),
  );
  assert.ok(parseIdx !== -1 && headerIdx !== -1 && parseIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "ECDSA P-521 signing: ecdsa-p521-sha512 signs the same fixed payment request with a P-521 key — the widest NIST curve, whose 132-byte raw signature completes the ladder the P-256 segment's 64-byte and the P-384 segment's 96-byte forms began",
    `P-521 Signature-Input: sig1=("@method" "@authority" "@path" "content-digest");created=${DEMO_CREATED};keyid="${DEMO_P521_KEY_ID}";alg="${DEMO_P521_ALG}";nonce="${DEMO_P521_NONCE}"`,
    `P-521 verification: OK (label ${DEMO_P521_LABEL}, keyid="${DEMO_P521_KEY_ID}", alg="${DEMO_P521_ALG}", nonce="${DEMO_P521_NONCE}")`,
    "P-521 verification after tampering: FAILED (code BODY_DIGEST_MISMATCH: body does not match content-digest)",
  ]);
  const resolveIdx = lines.findIndex((l) =>
    l.startsWith("Component resolution:"),
  );
  assert.ok(headerIdx !== -1 && resolveIdx !== -1 && headerIdx < resolveIdx);

  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs even though the
  // P-521 key pair itself is fresh.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("ECDSA P-521 signing:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo component-resolution segment resolves each covered component and rejects the illegal component", async () => {
  const { resolvedComponents, resolveIllegalComponentError, signed } =
    await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_RESOLVE_* and cross-checked against the
  // signature-base lines the demo prints for the same
  // request and the component suites' own pins (the
  // `;zz` rejection shape is the one
  // test/reqComponent.test.ts pins on the sign side). The
  // test pins the literals again here so a drift in either
  // place fails.
  assert.deepEqual(DEMO_RESOLVE_COMPONENTS, [
    { component: "@method", expected: "POST" },
    { component: "@authority", expected: "api.example.com" },
    { component: "@path", expected: "/v1/payments" },
    {
      component: "content-digest",
      expected:
        "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    },
  ]);
  assert.equal(DEMO_RESOLVE_ILLEGAL_COMPONENT, "content-digest;zz");
  assert.equal(
    DEMO_RESOLVE_ILLEGAL_ERROR,
    'unsupported component parameter ";zz" on component "content-digest": only ";req", ";bs", ";sf", ";key", ";tr" and ";name" are supported',
  );

  // The segment resolves exactly the main signature's
  // covered components, in covered order.
  assert.deepEqual(
    resolvedComponents.map((r) => r.component),
    [...DEMO_COVERED_COMPONENTS],
  );
  assert.deepEqual(
    resolvedComponents,
    DEMO_RESOLVE_COMPONENTS.map(({ component, expected }) => ({
      component,
      value: expected,
    })),
  );
  assert.equal(resolveIllegalComponentError, DEMO_RESOLVE_ILLEGAL_ERROR);

  // Cross-check against the library called directly: the
  // resolver over a freshly signed copy of the same fixed
  // request returns the same values, and the illegal
  // component throws the same message.
  const { privateKey } = generateEd25519KeyPair();
  const direct = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_KEY_ID,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_NONCE,
    },
  );
  const params = {
    created: DEMO_CREATED,
    keyid: DEMO_KEY_ID,
    alg: "ed25519",
    nonce: DEMO_NONCE,
  };
  for (const { component, expected } of DEMO_RESOLVE_COMPONENTS) {
    assert.equal(resolveComponent(component, direct, params), expected);
  }
  assert.throws(
    () => resolveComponent(DEMO_RESOLVE_ILLEGAL_COMPONENT, direct, params),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_RESOLVE_ILLEGAL_ERROR,
  );
  // The demo's own signed request resolves identically.
  for (const { component, expected } of DEMO_RESOLVE_COMPONENTS) {
    assert.equal(resolveComponent(component, signed, params), expected);
  }
});

test("demo lines contain the component-resolution segment (per-component values and illegal-component rejection, followed by the multi-value header combination segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Component resolution: resolveComponent turns/);
  // The resolution block sits after the ECDSA P-521 signing
  // segment and is followed by the multi-value header
  // combination segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Component resolution:"),
  );
  const p521Idx = lines.findIndex((l) =>
    l.startsWith("ECDSA P-521 signing:"),
  );
  assert.ok(p521Idx !== -1 && headerIdx !== -1 && p521Idx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 6), [
    "Component resolution: resolveComponent turns each covered component into the exact value its signature-base line carries — derived components from the request target, header fields from the normalized field value",
    ...DEMO_RESOLVE_COMPONENTS.map(
      ({ component, expected }) => `Resolve "${component}": ${expected}`,
    ),
    `Resolve "${DEMO_RESOLVE_ILLEGAL_COMPONENT}": FAILED (${DEMO_RESOLVE_ILLEGAL_ERROR})`,
  ]);
  // The multi-value header combination segment follows
  // the resolution segment.
  const joinIdx = lines.findIndex((l) =>
    l.startsWith("Multi-value header combination:"),
  );
  assert.ok(headerIdx !== -1 && joinIdx !== -1 && headerIdx < joinIdx);

  // Deterministic double run: the segment's printed lines
  // are pinned constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Component resolution:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 6),
    lines.slice(headerIdx, headerIdx + 6),
  );
});

test("demo multi-value header combination segment joins the repeated field and rejects the wrong join", async () => {
  const {
    joinedHeaderValue,
    joinSigned,
    joinVerification,
    joinWrongVerification,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_JOIN_* and cross-checked against the multi-value
  // suite's own pins (the padded fixture shape and the
  // SIGNATURE_MISMATCH code for a genuinely different
  // value in test/multiValueHeaderWhitespace.test.ts). The
  // test pins the literals again here so a drift in either
  // place fails.
  assert.equal(DEMO_JOIN_HEADER, "x-foo");
  assert.deepEqual(DEMO_JOIN_VALUES, ["  alpha ", " beta  "]);
  assert.equal(DEMO_JOIN_EXPECTED, "alpha, beta");
  assert.equal(DEMO_JOIN_WRONG_VALUE, "alpha,beta");
  assert.equal(DEMO_JOIN_NONCE, "demo-nonce-join-001");
  assert.equal(DEMO_JOIN_LABEL, "sig1");
  assert.deepEqual(DEMO_JOIN_COVERED_COMPONENTS, [
    "@method",
    "@authority",
    "@path",
    "x-foo",
  ]);
  assert.equal(DEMO_JOIN_WRONG_CODE, "SIGNATURE_MISMATCH");

  // The combination is exact, character for character, and
  // the signer emits it as the field's wire value.
  assert.equal(joinedHeaderValue, DEMO_JOIN_EXPECTED);
  assert.equal(
    joinSigned.headers[DEMO_JOIN_HEADER],
    DEMO_JOIN_EXPECTED,
  );
  assert.equal(joinVerification.ok, true);
  assert.equal(joinVerification.label, DEMO_JOIN_LABEL);
  assert.equal(joinVerification.keyId, DEMO_KEY_ID);
  assert.equal(joinVerification.alg, "ed25519");
  assert.equal(joinVerification.nonce, DEMO_JOIN_NONCE);
  assert.equal(joinWrongVerification.ok, false);
  assert.equal(joinWrongVerification.code, DEMO_JOIN_WRONG_CODE);

  // Cross-check against the library called directly: the
  // helper combines the same values, a freshly signed copy
  // of the same fixed request verifies, and the wrongly
  // joined copy is rejected with the same code.
  assert.equal(joinHeaderValues(DEMO_JOIN_VALUES), DEMO_JOIN_EXPECTED);
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const direct = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {
        "content-type": "application/json",
        [DEMO_JOIN_HEADER]: [...DEMO_JOIN_VALUES],
      },
    },
    {
      keyId: DEMO_KEY_ID,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_JOIN_NONCE,
      coveredComponents: DEMO_JOIN_COVERED_COMPONENTS,
    },
  );
  assert.equal(direct.headers[DEMO_JOIN_HEADER], DEMO_JOIN_EXPECTED);
  assert.equal(
    verifyRequest(direct, { key: publicKey, now: DEMO_CREATED + 60 })
      .ok,
    true,
  );
  const wrong = verifyRequest(
    {
      ...direct,
      headers: {
        ...direct.headers,
        [DEMO_JOIN_HEADER]: DEMO_JOIN_WRONG_VALUE,
      },
    },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );
  assert.equal(wrong.ok, false);
  assert.equal(wrong.code, DEMO_JOIN_WRONG_CODE);
});

test("demo lines contain the multi-value header combination segment (joined value, verification and wrong-join rejection, followed by the Signature field parsing segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Multi-value header combination: joinHeaderValues combines/);
  // The combination block sits after the
  // component-resolution segment and is followed by the
  // Signature field parsing segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Multi-value header combination:"),
  );
  const resolveIdx = lines.findIndex((l) =>
    l.startsWith("Component resolution:"),
  );
  assert.ok(
    resolveIdx !== -1 && headerIdx !== -1 && resolveIdx < headerIdx,
  );
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), [
    "Multi-value header combination: joinHeaderValues combines a repeated field's values into the single value its signature-base line carries — each element trimmed, the elements joined with \", \" (RFC 9421 §2.5), so signer, verifier and adapters can never disagree on the bytes",
    `Join "${DEMO_JOIN_HEADER}" values ${JSON.stringify(DEMO_JOIN_VALUES)}: ${DEMO_JOIN_EXPECTED}`,
    `Multi-value verification: OK (label ${DEMO_JOIN_LABEL}, keyid="${DEMO_KEY_ID}", alg="ed25519", nonce="${DEMO_JOIN_NONCE}")`,
    `Multi-value verification with the wrong join "${DEMO_JOIN_WRONG_VALUE}" (space after the comma dropped): FAILED (code SIGNATURE_MISMATCH: signature mismatch)`,
  ]);
  // The Signature field parsing segment follows the
  // combination segment.
  const sigFieldIdx = lines.findIndex((l) =>
    l.startsWith("Signature field parsing:"),
  );
  assert.ok(headerIdx !== -1 && sigFieldIdx !== -1 && headerIdx < sigFieldIdx);

  // Deterministic double run: the segment's printed lines
  // carry no key or signature bytes, so they are pinned
  // constants, identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Multi-value header combination:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo Signature field parsing segment extracts the signer's bytes and rejects the unknown label", async () => {
  const {
    signed,
    signatureFieldBytes,
    signatureFieldHexPrefix,
    signatureFieldUnknownError,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_SIGFIELD_* and cross-checked against
  // src/components.ts (which builds the pinned
  // not-present message) and the ed25519 signature length
  // the golden and round-trip suites pin (64 bytes,
  // RFC 9421 §3.3.2). The test pins the literals again
  // here so a drift in either place fails.
  assert.equal(DEMO_SIGFIELD_LABEL, "sig1");
  assert.equal(DEMO_SIGFIELD_BYTES, 64);
  assert.equal(DEMO_SIGFIELD_PREFIX_BYTES, 8);
  assert.equal(DEMO_SIGFIELD_UNKNOWN_LABEL, "sig-unknown");
  assert.equal(
    DEMO_SIGFIELD_UNKNOWN_ERROR,
    'signature "sig-unknown" not present in Signature field',
  );

  // The extracted bytes are, byte for byte, the bytes the
  // signer emitted: decoded independently here from the
  // main signed request's own Signature header member,
  // without the parser under test.
  const wire = signed.headers["signature"];
  assert.match(wire, /^sig1=:[A-Za-z0-9+/=]+:$/);
  const emitted = Buffer.from(wire.slice("sig1=:".length, -1), "base64");
  assert.equal(emitted.length, DEMO_SIGFIELD_BYTES);
  assert.ok(Buffer.isBuffer(signatureFieldBytes));
  assert.equal(signatureFieldBytes.length, DEMO_SIGFIELD_BYTES);
  assert.ok(signatureFieldBytes.equals(emitted));

  // The printed prefix is exactly the first
  // DEMO_SIGFIELD_PREFIX_BYTES bytes in hex — and only a
  // prefix: it never carries the full signature.
  assert.equal(
    signatureFieldHexPrefix,
    emitted.subarray(0, DEMO_SIGFIELD_PREFIX_BYTES).toString("hex"),
  );
  assert.equal(
    signatureFieldHexPrefix.length,
    DEMO_SIGFIELD_PREFIX_BYTES * 2,
  );
  assert.match(signatureFieldHexPrefix, /^[0-9a-f]+$/);

  assert.equal(signatureFieldUnknownError, DEMO_SIGFIELD_UNKNOWN_ERROR);

  // Cross-check against the library called directly: the
  // same parse over the demo's signed request gives the
  // same bytes, and the unknown label throws the same
  // pinned message.
  const direct = parseSignatureField(wire, DEMO_SIGFIELD_LABEL);
  assert.ok(direct.equals(signatureFieldBytes));
  assert.throws(
    () => parseSignatureField(wire, DEMO_SIGFIELD_UNKNOWN_LABEL),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_SIGFIELD_UNKNOWN_ERROR,
  );
});

test("demo lines contain the Signature field parsing segment (byte length and hex prefix, unknown-label rejection, followed by the EC JWK segment)", async () => {
  const { lines, signatureFieldBytes, signatureFieldHexPrefix } =
    await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature field parsing: parseSignatureField extracts/);
  // The parsing block sits after the multi-value header
  // combination segment and is followed by the EC JWK
  // key distribution segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature field parsing:"),
  );
  const joinIdx = lines.findIndex((l) =>
    l.startsWith("Multi-value header combination:"),
  );
  assert.ok(joinIdx !== -1 && headerIdx !== -1 && joinIdx < headerIdx);
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 3), [
    "Signature field parsing: parseSignatureField extracts the raw signature bytes for one label from the Signature field — the bytes a verifier feeds to the cryptographic check, decoded from their base64 byte-string wrapper",
    `Parsed Signature for label "${DEMO_SIGFIELD_LABEL}": ${DEMO_SIGFIELD_BYTES} bytes, hex prefix ${signatureFieldHexPrefix}… (only the prefix is printed — never the full signature)`,
    `Parsed Signature for unknown label "${DEMO_SIGFIELD_UNKNOWN_LABEL}": FAILED (${DEMO_SIGFIELD_UNKNOWN_ERROR})`,
  ]);
  // The EC JWK segment follows the parsing segment, and
  // no printed line carries the full signature in hex.
  const ecJwkIdx = lines.findIndex((l) =>
    l.startsWith("EC JWK key distribution:"),
  );
  assert.ok(headerIdx !== -1 && ecJwkIdx !== -1 && headerIdx < ecJwkIdx);
  assert.ok(!out.includes(signatureFieldBytes.toString("hex")));

  // Double run: the header and rejection lines are pinned
  // constants, and the prefix line keeps its pinned shape
  // — the prefix itself differs between runs because the
  // main key pair is fresh, so only its shape is pinned.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Signature field parsing:"),
  );
  assert.equal(again.lines[againIdx], lines[headerIdx]);
  assert.equal(again.lines[againIdx + 2], lines[headerIdx + 2]);
  assert.match(
    again.lines[againIdx + 1],
    new RegExp(
      `^Parsed Signature for label "${DEMO_SIGFIELD_LABEL}": ${DEMO_SIGFIELD_BYTES} bytes, hex prefix [0-9a-f]{${DEMO_SIGFIELD_PREFIX_BYTES * 2}}… \\(only the prefix is printed — never the full signature\\)$`,
    ),
  );
});

test("demo EC JWK segment exports each curve's JWK shape and verifies through the imported keys", async () => {
  const { ecJwkExports, ecJwkSigned, ecJwkVerifications, ecJwkMismatchError } =
    await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_EC_JWK_* and cross-checked against src/keys.ts
  // (which builds the pinned crv-mismatch message) and the
  // coordinate lengths the per-curve JWK suites pin
  // (32-byte -> 43 chars, 48-byte -> 64, 66-byte -> 88).
  // The test pins the literals again here so a drift in
  // either place fails.
  assert.deepEqual(
    DEMO_EC_JWK_CURVES.map((c) => [c.crv, c.alg, c.xLength, c.yLength]),
    [
      ["P-256", "ecdsa-p256-sha256", 43, 43],
      ["P-384", "ecdsa-p384-sha384", 64, 64],
      ["P-521", "ecdsa-p521-sha512", 88, 88],
    ],
  );
  assert.equal(DEMO_EC_JWK_LABEL, "sig1");
  assert.equal(
    DEMO_EC_JWK_MISMATCH_ERROR,
    'importPublicKeyJwkP384: invalid JWK: expected crv "P-384", got "P-256"',
  );

  assert.equal(ecJwkExports.length, 3);
  assert.equal(ecJwkSigned.length, 3);
  assert.equal(ecJwkVerifications.length, 3);
  const importers = [
    importPublicKeyJwkP256,
    importPublicKeyJwkP384,
    importPublicKeyJwkP521,
  ];
  const exporters = [
    exportPublicKeyJwkP256,
    exportPublicKeyJwkP384,
    exportPublicKeyJwkP521,
  ];
  const generators = [
    generateP256KeyPair,
    generateP384KeyPair,
    generateP521KeyPair,
  ];
  for (const [i, expected] of DEMO_EC_JWK_CURVES.entries()) {
    const jwk = ecJwkExports[i]!;
    assert.deepEqual(Object.keys(jwk).sort(), ["crv", "kty", "x", "y"]);
    assert.equal(jwk.kty, "EC");
    assert.equal(jwk.crv, expected.crv);
    assert.equal(jwk.x.length, expected.xLength);
    assert.equal(jwk.y.length, expected.yLength);
    assert.match(jwk.x, /^[A-Za-z0-9_-]+$/);
    assert.match(jwk.y, /^[A-Za-z0-9_-]+$/);
    assert.ok(!("d" in jwk), "public JWK must not carry private material");

    const v = ecJwkVerifications[i]!;
    assert.equal(v.ok, true);
    if (v.ok) {
      assert.equal(v.label, DEMO_EC_JWK_LABEL);
      assert.equal(v.keyId, expected.keyId);
      assert.equal(v.alg, expected.alg);
      assert.equal(v.nonce, expected.nonce);
    }

    // Cross-check against the library called directly: the
    // demo's exported JWK, imported through a JSON wire
    // round-trip, verifies the demo's signed request for
    // that curve.
    const imported = importers[i]!(
      JSON.parse(JSON.stringify(jwk)) as unknown,
    );
    const direct = verifyRequest(ecJwkSigned[i]!, {
      key: imported,
      now: DEMO_CREATED + 60,
    });
    assert.equal(direct.ok, true);

    // And a fresh pair on the same curve exports the same
    // pinned shape through the same exporter.
    const fresh = exporters[i]!(generators[i]!().publicKey);
    assert.equal(fresh.kty, "EC");
    assert.equal(fresh.crv, expected.crv);
    assert.equal(fresh.x.length, expected.xLength);
    assert.equal(fresh.y.length, expected.yLength);
  }

  assert.equal(ecJwkMismatchError, DEMO_EC_JWK_MISMATCH_ERROR);
  assert.throws(
    () => importPublicKeyJwkP384(ecJwkExports[0]),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_EC_JWK_MISMATCH_ERROR,
  );
});

test("demo lines contain the EC JWK segment (three curve shapes and round-trip verifications, crv mismatch rejection, followed by the RSA JWK segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /EC JWK key distribution: exportPublicKeyJwkP256/);
  // The EC JWK block sits after the Signature field
  // parsing segment and is followed by the RSA JWK
  // key distribution segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("EC JWK key distribution:"),
  );
  const sigFieldIdx = lines.findIndex((l) =>
    l.startsWith("Signature field parsing:"),
  );
  assert.ok(
    sigFieldIdx !== -1 && headerIdx !== -1 && sigFieldIdx < headerIdx,
  );
  const expectedLines = [
    "EC JWK key distribution: exportPublicKeyJwkP256 / exportPublicKeyJwkP384 / exportPublicKeyJwkP521 ship each EC public key as a JWK (kty \"EC\", crv, x/y coordinates), a JSON wire round-trip carries it, and the matching importPublicKeyJwkP* reads it back — the EC key form gateways and webhook verifiers distribute most often",
    ...DEMO_EC_JWK_CURVES.flatMap((c) => [
      `EC JWK ${c.crv}: kty="EC", crv="${c.crv}", x is ${c.xLength} base64url chars, y is ${c.yLength} base64url chars (the keys themselves are fresh per run; only their shapes are printed)`,
      `EC JWK ${c.crv} round-trip verification: OK (label ${DEMO_EC_JWK_LABEL}, keyid="${c.keyId}", alg="${c.alg}", nonce="${c.nonce}")`,
    ]),
    `EC JWK crv mismatch, P-256 JWK fed to importPublicKeyJwkP384: FAILED (${DEMO_EC_JWK_MISMATCH_ERROR})`,
  ];
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 8), expectedLines);
  // The RSA JWK segment follows the EC JWK segment: a
  // blank line, then its header.
  const rsaJwkIdx = lines.findIndex((l) =>
    l.startsWith("RSA JWK key distribution:"),
  );
  assert.ok(headerIdx !== -1 && rsaJwkIdx !== -1 && headerIdx < rsaJwkIdx);
  assert.equal(lines[headerIdx + 8], "");
  assert.equal(rsaJwkIdx, headerIdx + 9);

  // Deterministic double run: the segment's printed lines
  // carry no key bytes, so they are pinned constants,
  // identical between runs even though the key pairs are
  // fresh.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("EC JWK key distribution:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 8),
    lines.slice(headerIdx, headerIdx + 8),
  );
});

test("demo RSA JWK segment exports the RSA JWK shape and verifies through the imported key", async () => {
  const { rsaJwkExport, rsaJwkSigned, rsaJwkVerification, rsaJwkMismatchError, ecJwkExports } =
    await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_RSA_JWK_* and cross-checked against src/keys.ts
  // (which builds the pinned kty-mismatch message) and the
  // shapes test/rsaJwk.test.ts pins (a 2048-bit modulus
  // encodes to 342 base64url chars; the exponent is the
  // standard 65537, "AQAB"). The test pins the literals
  // again here so a drift in either place fails.
  assert.equal(DEMO_RSA_JWK_KEY_ID, "demo-rsa-jwk-1");
  assert.equal(DEMO_RSA_JWK_NONCE, "demo-nonce-rsa-jwk-001");
  assert.equal(DEMO_RSA_JWK_LABEL, "sig1");
  assert.equal(DEMO_RSA_JWK_ALG, "rsa-pss-sha512");
  assert.equal(DEMO_RSA_JWK_N_LENGTH, 342);
  assert.equal(DEMO_RSA_JWK_E, "AQAB");
  assert.equal(DEMO_RSA_JWK_E_LENGTH, 4);
  assert.equal(
    DEMO_RSA_JWK_MISMATCH_ERROR,
    'importPublicKeyJwkRsa: invalid JWK: expected kty "RSA", got "EC"',
  );

  // The exported JWK is exactly the RFC 7518 RSA shape:
  // kty/e/n and nothing else — in particular no private
  // material.
  assert.deepEqual(Object.keys(rsaJwkExport).sort(), ["e", "kty", "n"]);
  assert.equal(rsaJwkExport.kty, "RSA");
  assert.equal(rsaJwkExport.n.length, DEMO_RSA_JWK_N_LENGTH);
  assert.match(rsaJwkExport.n, /^[A-Za-z0-9_-]+$/);
  assert.equal(rsaJwkExport.e, DEMO_RSA_JWK_E);
  assert.equal(rsaJwkExport.e.length, DEMO_RSA_JWK_E_LENGTH);
  assert.ok(!("d" in rsaJwkExport), "public JWK must not carry private material");

  // The segment's request carries the pinned identity,
  // and verification through the imported key passes with
  // that identity.
  assert.equal(rsaJwkSigned.body, DEMO_BODY);
  assert.ok(
    rsaJwkSigned.headers["signature-input"].includes(
      `keyid="${DEMO_RSA_JWK_KEY_ID}"`,
    ),
  );
  assert.ok(
    rsaJwkSigned.headers["signature-input"].includes(
      `nonce="${DEMO_RSA_JWK_NONCE}"`,
    ),
  );
  assert.equal(rsaJwkVerification.ok, true);
  if (rsaJwkVerification.ok) {
    assert.equal(rsaJwkVerification.label, DEMO_RSA_JWK_LABEL);
    assert.equal(rsaJwkVerification.keyId, DEMO_RSA_JWK_KEY_ID);
    assert.equal(rsaJwkVerification.alg, DEMO_RSA_JWK_ALG);
    assert.equal(rsaJwkVerification.nonce, DEMO_RSA_JWK_NONCE);
  }

  // Cross-check against the library called directly: the
  // demo's exported JWK, imported through a JSON wire
  // round-trip, verifies the demo's signed request.
  const imported = importPublicKeyJwkRsa(
    JSON.parse(JSON.stringify(rsaJwkExport)) as unknown,
  );
  const direct = verifyRequest(rsaJwkSigned, {
    key: imported,
    now: DEMO_CREATED + 60,
  });
  assert.equal(direct.ok, true);

  // And a fresh RSA pair exports the same pinned shape
  // through the same exporter.
  const fresh = exportPublicKeyJwkRsa(generateRsaPssKeyPair().publicKey);
  assert.equal(fresh.kty, "RSA");
  assert.equal(fresh.n.length, DEMO_RSA_JWK_N_LENGTH);
  assert.equal(fresh.e, DEMO_RSA_JWK_E);

  // The wrong-type rejection is the pinned message, and
  // the library called directly throws it for the EC
  // segment's P-256 JWK as well.
  assert.equal(rsaJwkMismatchError, DEMO_RSA_JWK_MISMATCH_ERROR);
  assert.throws(
    () => importPublicKeyJwkRsa(ecJwkExports[0]),
    (e: unknown) =>
      e instanceof Error && e.message === DEMO_RSA_JWK_MISMATCH_ERROR,
  );
});

test("demo lines contain the RSA JWK segment (shape, round-trip verification, kty mismatch rejection, followed by the JWKS refresh segment)", async () => {
  const { lines, rsaJwkExport } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /RSA JWK key distribution: exportPublicKeyJwkRsa/);
  // The RSA JWK block sits after the EC JWK segment and
  // before the JWKS refresh segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("RSA JWK key distribution:"),
  );
  const ecJwkIdx = lines.findIndex((l) =>
    l.startsWith("EC JWK key distribution:"),
  );
  assert.ok(ecJwkIdx !== -1 && headerIdx !== -1 && ecJwkIdx < headerIdx);
  const expectedLines = [
    "RSA JWK key distribution: exportPublicKeyJwkRsa ships the RSA public key as a JWK (kty \"RSA\", n/e), a JSON wire round-trip carries it, and importPublicKeyJwkRsa reads it back — the RSA member shape JWKS documents carry most often",
    `RSA JWK: kty="RSA", n is ${DEMO_RSA_JWK_N_LENGTH} base64url chars, e is ${DEMO_RSA_JWK_E_LENGTH} base64url chars ("${DEMO_RSA_JWK_E}") (the key itself is generated once per process; only its shape is printed — never the full modulus)`,
    `RSA JWK round-trip verification: OK (label ${DEMO_RSA_JWK_LABEL}, keyid="${DEMO_RSA_JWK_KEY_ID}", alg="${DEMO_RSA_JWK_ALG}", nonce="${DEMO_RSA_JWK_NONCE}")`,
    `RSA JWK kty mismatch, EC JWK (P-256) fed to importPublicKeyJwkRsa: FAILED (${DEMO_RSA_JWK_MISMATCH_ERROR})`,
  ];
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 4), expectedLines);
  // The JWKS refresh segment follows the RSA JWK segment,
  // and no printed line carries the full modulus.
  assert.ok(
    lines[headerIdx + 5]?.startsWith("JWKS refresh and rotation:"),
  );
  assert.ok(!out.includes(rsaJwkExport.n));

  // Deterministic double run: the segment's printed lines
  // carry no key bytes, so they are pinned constants,
  // identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("RSA JWK key distribution:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 4),
    lines.slice(headerIdx, headerIdx + 4),
  );
});

test("demo JWKS refresh segment loads the old key, skips the fresh fetch, rotates past the TTL, and retires the old keyid", async () => {
  const {
    jwksRefreshInitialRefreshed,
    jwksRefreshFetchCallsAfterLoad,
    jwksRefreshOldSigned,
    jwksRefreshOldVerification,
    jwksRefreshFreshRefreshed,
    jwksRefreshFetchCallsAfterFresh,
    jwksRefreshStaleRefreshed,
    jwksRefreshFetchCallsAfterRotation,
    jwksRefreshNewSigned,
    jwksRefreshNewVerification,
    jwksRefreshRetiredVerification,
  } = await runDemo();

  // Expectations are the literals hand-pinned in
  // DEMO_JWKS_REFRESH_* (the same return-value, fetch-count
  // and TTL-boundary shapes test/jwksRefreshIfStale.test.ts
  // pins for its own store) — the test pins them again here
  // so a drift in either place fails.
  assert.equal(DEMO_JWKS_REFRESH_OLD_KEY_ID, "demo-jwks-refresh-old-1");
  assert.equal(DEMO_JWKS_REFRESH_NEW_KEY_ID, "demo-jwks-refresh-new-1");
  assert.equal(
    DEMO_JWKS_REFRESH_OLD_NONCE,
    "demo-nonce-jwks-refresh-old-001",
  );
  assert.equal(
    DEMO_JWKS_REFRESH_NEW_NONCE,
    "demo-nonce-jwks-refresh-new-001",
  );
  assert.equal(DEMO_JWKS_REFRESH_LABEL, "sig1");
  assert.equal(DEMO_JWKS_REFRESH_TTL_SEC, 120);
  assert.equal(DEMO_JWKS_REFRESH_FRESH_AT_SEC, DEMO_CREATED + 60);
  assert.equal(DEMO_JWKS_REFRESH_STALE_AT_SEC, DEMO_CREATED + 180);
  assert.equal(DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD, 1);
  assert.equal(DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION, 2);
  assert.equal(DEMO_JWKS_REFRESH_RETIRED_CODE, "KEY_RESOLUTION_FAILED");

  // Initial load: a never-refreshed store is stale, so the
  // first refreshIfStale() fetches exactly once and returns
  // true; the pre-rotation request then verifies through
  // the store under the old keyid.
  assert.equal(jwksRefreshInitialRefreshed, true);
  assert.equal(
    jwksRefreshFetchCallsAfterLoad,
    DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD,
  );
  assert.ok(
    jwksRefreshOldSigned.headers["signature-input"].includes(
      `keyid="${DEMO_JWKS_REFRESH_OLD_KEY_ID}"`,
    ),
  );
  assert.ok(
    jwksRefreshOldSigned.headers["signature-input"].includes(
      `nonce="${DEMO_JWKS_REFRESH_OLD_NONCE}"`,
    ),
  );
  assert.equal(jwksRefreshOldVerification.ok, true);
  if (jwksRefreshOldVerification.ok) {
    assert.equal(jwksRefreshOldVerification.label, DEMO_JWKS_REFRESH_LABEL);
    assert.equal(jwksRefreshOldVerification.keyId, DEMO_JWKS_REFRESH_OLD_KEY_ID);
    assert.equal(jwksRefreshOldVerification.alg, "ed25519");
    assert.equal(jwksRefreshOldVerification.nonce, DEMO_JWKS_REFRESH_OLD_NONCE);
  }

  // Freshness probe: inside the TTL the second call
  // returns false and the fetch count does not move.
  assert.equal(jwksRefreshFreshRefreshed, false);
  assert.equal(
    jwksRefreshFetchCallsAfterFresh,
    DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD,
  );

  // Rotation: past the TTL, with the endpoint serving only
  // the rotated key, the third call returns true after
  // exactly one more fetch; the rotated request verifies
  // under the new keyid, and the retired keyid fails
  // closed at key resolution.
  assert.equal(jwksRefreshStaleRefreshed, true);
  assert.equal(
    jwksRefreshFetchCallsAfterRotation,
    DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION,
  );
  assert.ok(
    jwksRefreshNewSigned.headers["signature-input"].includes(
      `keyid="${DEMO_JWKS_REFRESH_NEW_KEY_ID}"`,
    ),
  );
  assert.ok(
    jwksRefreshNewSigned.headers["signature-input"].includes(
      `nonce="${DEMO_JWKS_REFRESH_NEW_NONCE}"`,
    ),
  );
  assert.equal(jwksRefreshNewVerification.ok, true);
  if (jwksRefreshNewVerification.ok) {
    assert.equal(jwksRefreshNewVerification.label, DEMO_JWKS_REFRESH_LABEL);
    assert.equal(jwksRefreshNewVerification.keyId, DEMO_JWKS_REFRESH_NEW_KEY_ID);
    assert.equal(jwksRefreshNewVerification.alg, "ed25519");
    assert.equal(jwksRefreshNewVerification.nonce, DEMO_JWKS_REFRESH_NEW_NONCE);
  }
  assert.equal(jwksRefreshRetiredVerification.ok, false);
  assert.equal(
    jwksRefreshRetiredVerification.code,
    DEMO_JWKS_REFRESH_RETIRED_CODE,
  );

  // Cross-check against the library called directly: an
  // independent store driven by its own counting fake fetch
  // and injected clock reproduces the segment's exact
  // return-value / fetch-count sequence, and after rotation
  // resolves only the new keyid.
  const directOldPair = generateEd25519KeyPair();
  const directNewPair = generateEd25519KeyPair();
  let directRotated = false;
  let directCalls = 0;
  let directNowSec = DEMO_CREATED;
  const directStore = new JwksKeyStore(DEMO_JWKS_URL, {
    fetchImpl: async () => {
      directCalls++;
      const pair = directRotated ? directNewPair : directOldPair;
      const kid = directRotated
        ? DEMO_JWKS_REFRESH_NEW_KEY_ID
        : DEMO_JWKS_REFRESH_OLD_KEY_ID;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          keys: [{ ...exportPublicKeyJwk(pair.publicKey), kid }],
        }),
      };
    },
    ttlSec: DEMO_JWKS_REFRESH_TTL_SEC,
    now: () => directNowSec,
  });
  assert.equal(await directStore.refreshIfStale(), jwksRefreshInitialRefreshed);
  assert.equal(directCalls, jwksRefreshFetchCallsAfterLoad);
  directNowSec = DEMO_JWKS_REFRESH_FRESH_AT_SEC;
  assert.equal(await directStore.refreshIfStale(), jwksRefreshFreshRefreshed);
  assert.equal(directCalls, jwksRefreshFetchCallsAfterFresh);
  directRotated = true;
  directNowSec = DEMO_JWKS_REFRESH_STALE_AT_SEC;
  assert.equal(await directStore.refreshIfStale(), jwksRefreshStaleRefreshed);
  assert.equal(directCalls, jwksRefreshFetchCallsAfterRotation);
  assert.ok(directStore.resolve(DEMO_JWKS_REFRESH_NEW_KEY_ID) !== undefined);
  assert.equal(directStore.resolve(DEMO_JWKS_REFRESH_OLD_KEY_ID), undefined);
});

test("demo lines contain the JWKS refresh segment (initial load, fresh skip, rotation, retired keyid rejection, followed by the header lookup segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /JWKS refresh and rotation: JwksKeyStore\.refreshIfStale/);
  // The JWKS refresh block sits after the RSA JWK segment
  // and before the header lookup segment.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("JWKS refresh and rotation:"),
  );
  const rsaJwkIdx = lines.findIndex((l) =>
    l.startsWith("RSA JWK key distribution:"),
  );
  assert.ok(rsaJwkIdx !== -1 && headerIdx !== -1 && rsaJwkIdx < headerIdx);
  const expectedLines = [
    "JWKS refresh and rotation: JwksKeyStore.refreshIfStale fetches only when the snapshot is stale — a counting fake JWKS fetch (zero network) and an injected clock show the store loading the pre-rotation key, refusing to re-fetch while fresh, then swapping in the rotated key once the TTL passes",
    `JWKS refresh initial load: refreshIfStale() returned true (fetch count ${DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD})`,
    `JWKS verification before rotation: OK (label ${DEMO_JWKS_REFRESH_LABEL}, keyid="${DEMO_JWKS_REFRESH_OLD_KEY_ID}", alg="ed25519", nonce="${DEMO_JWKS_REFRESH_OLD_NONCE}")`,
    `JWKS refresh while fresh (${DEMO_JWKS_REFRESH_FRESH_AT_SEC - DEMO_CREATED}s into the ${DEMO_JWKS_REFRESH_TTL_SEC}s TTL): refreshIfStale() returned false (fetch count still ${DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD})`,
    `JWKS refresh after rotation (clock past the ${DEMO_JWKS_REFRESH_TTL_SEC}s TTL, endpoint now serves only the rotated key): refreshIfStale() returned true (fetch count ${DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION})`,
    `JWKS verification after rotation: OK (label ${DEMO_JWKS_REFRESH_LABEL}, keyid="${DEMO_JWKS_REFRESH_NEW_KEY_ID}", alg="ed25519", nonce="${DEMO_JWKS_REFRESH_NEW_NONCE}")`,
    `JWKS verification of the retired keyid "${DEMO_JWKS_REFRESH_OLD_KEY_ID}" after rotation: FAILED (code ${DEMO_JWKS_REFRESH_RETIRED_CODE}: keyid "${DEMO_JWKS_REFRESH_OLD_KEY_ID}" could not be resolved to a key)`,
  ];
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 7), expectedLines);
  // The header lookup segment follows the JWKS refresh
  // segment.
  assert.ok(lines[headerIdx + 8]?.startsWith("Header lookup:"));

  // Deterministic double run: the segment's printed lines
  // carry no key bytes, so they are pinned constants,
  // identical between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("JWKS refresh and rotation:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 7),
    lines.slice(headerIdx, headerIdx + 7),
  );
});

test("demo getHeader segment shows the normalized lookup, the raw contrast, and undefined for a missing header", async () => {
  const {
    getHeaderHeaders,
    getHeaderValue,
    getHeaderRawValue,
    getHeaderSingleValue,
    getHeaderMissingValue,
    getHeaderRawMissingValue,
  } = await runDemo();

  // The fixture record is exactly the hand-pinned one: the
  // multi-value field under its mixed-case stored key plus
  // the single string field.
  assert.deepEqual(getHeaderHeaders, {
    [DEMO_GET_HEADER_STORED_NAME]: DEMO_GET_HEADER_VALUES,
    [DEMO_GET_HEADER_SINGLE_STORED_NAME]: DEMO_GET_HEADER_SINGLE_VALUE,
  });

  // The normalized read trims and joins; the raw read
  // preserves every element's padding, so the two results
  // differ exactly by the per-element trimming.
  assert.equal(getHeaderValue, DEMO_GET_HEADER_EXPECTED);
  assert.equal(getHeaderRawValue, DEMO_GET_HEADER_RAW_EXPECTED);
  assert.notEqual(getHeaderValue, getHeaderRawValue);
  // A single string value is returned exactly as stored,
  // and a missing field is undefined from both reads.
  assert.equal(getHeaderSingleValue, DEMO_GET_HEADER_SINGLE_VALUE);
  assert.equal(getHeaderMissingValue, undefined);
  assert.equal(getHeaderRawMissingValue, undefined);

  // Direct cross-check against the library functions on
  // the same fixture: the lookup name's case is irrelevant
  // (lower-case and stored-case names read identically),
  // and the raw read of the single field agrees with the
  // normalized one because there is nothing to trim.
  assert.equal(
    getHeader(getHeaderHeaders, DEMO_GET_HEADER_LOOKUP_NAME),
    DEMO_GET_HEADER_EXPECTED,
  );
  assert.equal(
    getHeader(getHeaderHeaders, DEMO_GET_HEADER_STORED_NAME),
    DEMO_GET_HEADER_EXPECTED,
  );
  assert.equal(
    getHeaderRaw(getHeaderHeaders, DEMO_GET_HEADER_LOOKUP_NAME),
    DEMO_GET_HEADER_RAW_EXPECTED,
  );
  assert.equal(
    getHeader(getHeaderHeaders, DEMO_GET_HEADER_SINGLE_LOOKUP_NAME),
    DEMO_GET_HEADER_SINGLE_VALUE,
  );
  assert.equal(
    getHeaderRaw(getHeaderHeaders, DEMO_GET_HEADER_SINGLE_LOOKUP_NAME),
    DEMO_GET_HEADER_SINGLE_VALUE,
  );
  assert.equal(
    getHeader(getHeaderHeaders, DEMO_GET_HEADER_MISSING_NAME),
    undefined,
  );
  assert.equal(
    getHeaderRaw(getHeaderHeaders, DEMO_GET_HEADER_MISSING_NAME),
    undefined,
  );
});

test("demo lines contain the getHeader segment (normalized value, raw contrast, single value, missing undefined, followed by the signature-input construction segment)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Header lookup: getHeader is the normalized read/);
  // The header lookup block sits after the JWKS refresh
  // segment and closes the demo.
  const headerIdx = lines.findIndex((l) => l.startsWith("Header lookup:"));
  const refreshIdx = lines.findIndex((l) =>
    l.startsWith("JWKS refresh and rotation:"),
  );
  assert.ok(refreshIdx !== -1 && headerIdx !== -1 && refreshIdx < headerIdx);
  const expectedLines = [
    "Header lookup: getHeader is the normalized read the verifier itself uses — the lookup name's case need not match the stored key, multi-value fields come back trimmed and joined with \", \" (RFC 9421 §2.5), and a missing field comes back undefined — while getHeaderRaw returns the field exactly as stored, the raw read a ;bs component binds",
    `getHeader("${DEMO_GET_HEADER_LOOKUP_NAME}") over the stored "${DEMO_GET_HEADER_STORED_NAME}" values ${JSON.stringify(DEMO_GET_HEADER_VALUES)}: "${DEMO_GET_HEADER_EXPECTED}"`,
    `getHeaderRaw("${DEMO_GET_HEADER_LOOKUP_NAME}") over the same stored values: "${DEMO_GET_HEADER_RAW_EXPECTED}" (every element's padding preserved — the two reads differ exactly by the per-element trimming)`,
    `getHeader("${DEMO_GET_HEADER_SINGLE_LOOKUP_NAME}") over the stored "${DEMO_GET_HEADER_SINGLE_STORED_NAME}": "${DEMO_GET_HEADER_SINGLE_VALUE}" (a single string value is returned exactly as stored)`,
    `getHeader("${DEMO_GET_HEADER_MISSING_NAME}"): undefined (no such field in the record — a missing header is undefined, never an empty string)`,
  ];
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 5), expectedLines);
  // The signature-input construction segment follows the
  // header lookup segment.
  assert.ok(lines[headerIdx + 6]?.startsWith("Signature-Input value construction:"));

  // Deterministic double run: every input is a fixed
  // constant, so the segment's printed lines are identical
  // between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) => l.startsWith("Header lookup:"));
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 5),
    lines.slice(headerIdx, headerIdx + 5),
  );
});

test("demo signatureInputValue segment builds the main member byte-for-byte and the second label in fixed parameter order", async () => {
  const { signed, signatureInputValueMain, signatureInputValueAlt } =
    await runDemo();

  // The main call replays the main line's own inputs, so its
  // built value equals both the hand-pinned expectation and
  // the main signed request's actual signature-input header.
  assert.equal(signatureInputValueMain, DEMO_SIG_INPUT_EXPECTED);
  assert.equal(signatureInputValueMain, signed.headers["signature-input"]);
  assert.equal(DEMO_SIG_INPUT_EXPECTED, DEMO_PARSE_RAW_INPUT);
  // The second call carries all six parameter slots and
  // equals its own hand-pinned expectation.
  assert.equal(signatureInputValueAlt, DEMO_SIG_INPUT_ALT_EXPECTED);

  // Direct cross-check against the library function on the
  // same pinned inputs: the demo's fields are exactly what
  // a direct call builds, in both cases.
  assert.equal(
    signatureInputValue(DEMO_SIG_INPUT_LABEL, DEMO_COVERED_COMPONENTS, DEMO_SIG_INPUT_PARAMS),
    DEMO_SIG_INPUT_EXPECTED,
  );
  assert.equal(
    signatureInputValue(
      DEMO_SIG_INPUT_ALT_LABEL,
      DEMO_SIG_INPUT_ALT_COMPONENTS,
      DEMO_SIG_INPUT_ALT_PARAMS,
    ),
    DEMO_SIG_INPUT_ALT_EXPECTED,
  );
  // The alt parameters serialize in the fixed order:
  // created before expires before keyid before alg before
  // nonce before tag.
  const order = ["created=", "expires=", "keyid=", "alg=", "nonce=", "tag="].map(
    (k) => signatureInputValueAlt.indexOf(k),
  );
  assert.ok(order.every((v, i) => v !== -1 && (i === 0 || order[i - 1] < v)));
});

test("demo lines contain the signatureInputValue segment (main member, second label, closing the demo)", async () => {
  const { lines } = await runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature-Input value construction: signatureInputValue/);
  // The construction block sits after the header lookup
  // segment and closes the demo.
  const headerIdx = lines.findIndex((l) =>
    l.startsWith("Signature-Input value construction:"),
  );
  const lookupIdx = lines.findIndex((l) => l.startsWith("Header lookup:"));
  assert.ok(lookupIdx !== -1 && headerIdx !== -1 && lookupIdx < headerIdx);
  const expectedLines = [
    "Signature-Input value construction: signatureInputValue(label, componentIds, params) builds one label's Signature-Input member — the label= prefix plus the serialized inner list and parameters — exactly the member signRequest writes into the header when it signs",
    `Main label: signatureInputValue("${DEMO_SIG_INPUT_LABEL}", the main covered components, the main parameters) = "${DEMO_SIG_INPUT_EXPECTED}" — byte-for-byte the main signed request's signature-input header`,
    `Second label: signatureInputValue("${DEMO_SIG_INPUT_ALT_LABEL}", ${DEMO_SIG_INPUT_ALT_COMPONENTS.map((c) => `"${c}"`).join(" ")}, parameters with expires/nonce/tag) = "${DEMO_SIG_INPUT_ALT_EXPECTED}" — parameters serialize in the fixed created, expires, keyid, alg, nonce, tag order`,
  ];
  assert.deepEqual(lines.slice(headerIdx, headerIdx + 3), expectedLines);
  // The construction segment closes the demo: its second
  // label line is final.
  assert.equal(lines[lines.length - 1], expectedLines[expectedLines.length - 1]);

  // Deterministic double run: every input is a fixed
  // constant, so the segment's printed lines are identical
  // between runs.
  const again = await runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("Signature-Input value construction:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 3),
    lines.slice(headerIdx, headerIdx + 3),
  );
});
