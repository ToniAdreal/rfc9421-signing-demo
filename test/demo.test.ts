import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createSecretKey } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { assertHmacSecretLength } from "../src/index.js";
import {
  DEMO_BODY,
  DEMO_COVERED_COMPONENTS,
  DEMO_CREATED,
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
  DEMO_DICT_MEMBER_EXTRACTION,
  DEMO_DICT_MEMBER_MISSING_KEY,
  DEMO_DICT_MEMBER_VALUE,
  DEMO_SF_CANONICALIZATION,
  DEMO_SIG_PARAMS_SERIALIZATION,
  DEMO_JWKS_FETCHED_AT_SEC,
  DEMO_JWKS_URL,
  DEMO_HMAC_GUARD_ACCEPTED,
  DEMO_HMAC_GUARD_ERRORS,
  DEMO_HMAC_GUARD_REJECTED,
  DEMO_JWK_TAMPERED_CODE,
  DEMO_KEY_ID,
  DEMO_MAIN_DIGEST_ALG,
  DEMO_MEMOIZED_CALLS_AFTER_REPEAT,
  DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY,
  DEMO_MEMOIZED_NONCE,
  DEMO_MEMOIZED_SECOND_KEY_ID,
  DEMO_MEMOIZED_TTL_SEC,
  DEMO_NONCE,
  DEMO_PEM_NONCE,
  DEMO_PEM_PRIVATE_HEADER,
  DEMO_PEM_PUBLIC_HEADER,
  DEMO_OTHER_NONCE,
  DEMO_SIGNATURE_LABELS,
  DEMO_REPLAY_CACHE_MAX_ENTRIES,
  DEMO_REPLAY_CACHE_TTL_SEC,
  DEMO_SHA256_DIGEST_ALG,
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

test("demo signs a fixed request with content-digest and nonce, and it verifies", () => {
  const { signed, verification } = runDemo();

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

test("demo tamper changes exactly one body byte and verification rejects it", () => {
  const { tamperedBody, tamperedVerification } = runDemo();

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

test("demo lines contain the headers, the success, and the tamper rejection", () => {
  const { lines } = runDemo();
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

test("demo signature base segment rebuilds the main line's base byte-for-byte", () => {
  const { signed, signatureBase } = runDemo();

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
  assert.equal(runDemo().signatureBase, signatureBase);
});

test("demo lines print the signature base block verbatim, followed by its explanation", () => {
  const { lines } = runDemo();

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

test("demo gateway addSignature second label verifies alongside sig1", () => {
  const { dualSigned, dualVerification } = runDemo();

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

test("demo content-type tamper fails only the gateway label", () => {
  const { contentTypeTamperedVerification } = runDemo();

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

test("demo lines contain the dual headers, dual verification, and tamper isolation", () => {
  const { lines } = runDemo();
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

test("demo replay segment rejects the same request twice via ReplayCache", () => {
  const {
    replayFirstVerification,
    replaySecondVerification,
    replayOtherNonceVerification,
  } = runDemo();

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

test("demo lines contain the replay segment (first ok, replay rejected, fresh nonce ok)", () => {
  const { lines } = runDemo();
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

test("demo request data is deterministic across runs (fresh key aside)", () => {
  const a = runDemo();
  const b = runDemo();

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
        !l.startsWith("Verification with the generated nonce: "),
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

test("demo sha-256 segment re-signs the same request for a sha-256-only peer", () => {
  const { signed, sha256Signed, sha256Verification, sha256TamperedVerification } =
    runDemo();

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

test("demo lines contain the sha-256 segment (comparison, verification, tamper rejection)", () => {
  const { lines } = runDemo();
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

test("demo digest-alg identification segment reads the algorithm off both emitted headers and fails closed on an unrecognized value", () => {
  const {
    contentDigestAlg,
    sha256ContentDigestAlg,
    unrecognizedContentDigestAlg,
  } = runDemo();

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

test("demo lines contain the digest-alg identification segment (after the sha-256 segment, before inbound normalization)", () => {
  const { lines } = runDemo();
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

test("demo inbound segment normalizes a mock IncomingMessage and verifies it", () => {
  const {
    inboundSigned,
    inboundNormalized,
    inboundVerification,
    inboundWrongSchemeVerification,
  } = runDemo();

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

test("demo lines contain the inbound segment (normalized shape, verified, wrong scheme rejected)", () => {
  const { lines } = runDemo();
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

test("demo JWKS segment verifies via a restored store and rejects an unknown keyid", () => {
  const {
    jwksSnapshot,
    jwksStoreSize,
    jwksVerification,
    jwksUnknownKeyVerification,
  } = runDemo();

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

test("demo lines contain the JWKS segment (hit verifies, unknown keyid rejected)", () => {
  const { lines } = runDemo();
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

test("demo thumbprint segment derives the RFC 7638 thumbprint and binds it as keyid", () => {
  const { thumbprint, thumbprintSigned, thumbprintVerification } = runDemo();

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

test("demo lines contain the thumbprint segment (thumbprint printed, thumbprint-as-keyid verifies)", () => {
  const { lines, thumbprint } = runDemo();
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

test("demo canonicalization segment canonicalizes the fixed corpus to the hand-pinned forms", () => {
  const { sfCanonicalization } = runDemo();

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

test("demo lines contain the canonicalization segment (raw -> canonical pairs)", () => {
  const { lines } = runDemo();
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

test("demo member-extraction segment extracts the fixed keys to the hand-pinned values", () => {
  const { dictMemberExtraction, dictMemberMissingKeyError } = runDemo();

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

test("demo lines contain the member-extraction segment (key -> value pairs, missing key rejected)", () => {
  const { lines } = runDemo();
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

test("demo signature-params segment serializes the fixed corpus to the hand-pinned strings", () => {
  const { sigParamsSerialization } = runDemo();

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

test("demo lines contain the signature-params segment (name -> serialized pairs)", () => {
  const { lines } = runDemo();
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

test("demo PEM segment exports the main key pair as PEM, imports it back, and the imported keys sign and verify", () => {
  const { pemPublicHeader, pemPrivateHeader, pemSigned, pemVerification } =
    runDemo();

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

test("demo lines contain the PEM segment (headers printed, round-trip verifies)", () => {
  const { lines } = runDemo();
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

test("demo throwing-verification segment returns the identity on success and throws a VerifyError with the pinned code on tamper", () => {
  const { throwVerification, throwTamperedError, throwTamperedIsVerifyError } =
    runDemo();

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

test("demo lines contain the throwing-verification segment (identity returned, VerifyError thrown, followed by the nonce-generation segment)", () => {
  const { lines } = runDemo();
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

test("demo nonce-generation segment draws pinned-shape base64url nonces and the short one round-trips through sign and verify", () => {
  const {
    generatedNonce,
    generatedLongNonce,
    generatedNonceSigned,
    generatedNonceVerification,
  } = runDemo();

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

test("demo lines contain the nonce-generation segment (shapes printed, generated nonce verifies)", () => {
  const { lines, generatedNonce, generatedLongNonce } = runDemo();
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

test("demo JWK import segment verifies the main request with the imported key and rejects a tampered x", () => {
  const { exportedJwk, jwkImportedVerification, jwkTamperedVerification } =
    runDemo();

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

test("demo lines contain the JWK import segment (imported key verifies, tampered x rejected, followed by the key-resolver memoization segment)", () => {
  const { lines, exportedJwk } = runDemo();
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

test("demo signature-labels segment enumerates the dual-signed request's labels in wire order", () => {
  const { dualSigned, signatureLabels } = runDemo();

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

test("demo lines contain the signature-labels segment (right after dual verification, before content-type tampering)", () => {
  const { lines } = runDemo();
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
});

test("demo key-resolver memoization segment resolves each keyid once (repeat is a cache hit, second keyid advances the count)", () => {
  const {
    memoizedFirstVerification,
    memoizedRepeatVerification,
    memoizedSecondKeyVerification,
    memoizedResolverCallsAfterRepeat,
    memoizedResolverCallsAfterSecondKey,
  } = runDemo();

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
  const again = runDemo();
  assert.equal(again.memoizedResolverCallsAfterRepeat, 1);
  assert.equal(again.memoizedResolverCallsAfterSecondKey, 2);
});

test("demo lines contain the key-resolver memoization segment (counts printed, followed by the HMAC guard segment)", () => {
  const { lines } = runDemo();
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

test("demo HMAC secret-length guard segment accepts floor lengths and rejects one byte below (per algorithm)", () => {
  const { hmacGuardAccepted, hmacGuardRejections } = runDemo();

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

test("demo lines contain the HMAC secret-length guard segment (accepted and rejected lines, closing the demo)", () => {
  const { lines } = runDemo();
  const out = lines.join("\n");

  assert.match(
    out,
    /HMAC secret-length guard: assertHmacSecretLength enforces the per-algorithm secret floor/,
  );
  // The guard segment closes the demo: its last rejection line
  // is final, and the block sits after the memoization segment.
  assert.equal(
    lines[lines.length - 1],
    `assertHmacSecretLength for hmac-sha512 with a 63-byte secret: FAILED (${DEMO_HMAC_GUARD_ERRORS[1]})`,
  );
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
  const again = runDemo();
  const againIdx = again.lines.findIndex((l) =>
    l.startsWith("HMAC secret-length guard:"),
  );
  assert.deepEqual(
    again.lines.slice(againIdx, againIdx + 5),
    lines.slice(headerIdx, headerIdx + 5),
  );
});
