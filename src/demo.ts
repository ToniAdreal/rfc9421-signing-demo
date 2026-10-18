/**
 * Demo: sign one fixed request with a freshly generated ed25519 key,
 * print the wire headers, verify it, then tamper the body by one byte
 * and show the verifier rejecting it. After that single-signature
 * script, the demo runs the canonical multi-party payments flow: the
 * payment gateway appends a second signature with `addSignature`
 * (label `gateway`, hmac-sha256), the merged wire headers are printed,
 * and `verifyAllLabels` verifies each label independently. Right
 * after that multi-party script, the demo enumerates the finished
 * request's signature labels with `listSignatureLabels` over its
 * `Signature-Input` value and prints them in wire order — the
 * enumerate-first entry point a receiver uses before verifying
 * each label — asserting outside the printed lines that the
 * enumerated labels equal the hand-pinned `sig1`, `gateway`
 * expectation below. Finally the
 * demo tampers `content-type` — a component only the gateway signature
 * covers — to show one label failing while the other still verifies.
 * The next segment demonstrates nonce replay protection: the demo
 * signs in with an opt-in `ReplayCache`, so the *same* signed request
 * verifies once and is then rejected with `NONCE_REPLAY`, while a
 * request carrying a different nonce still verifies. The next segment
 * re-signs the same request with `contentDigestAlg: "sha-256"` for a
 * peer that only accepts sha-256 digests: its `content-digest` header
 * and verification are printed alongside the main line's sha-512
 * header, and a one-byte body tamper is rejected with
 * `BODY_DIGEST_MISMATCH`. Right after that segment, the demo
 * identifies the digest algorithm of both already-emitted headers
 * with `contentDigestAlgOf` — the receiver's first step on an
 * inbound `Content-Digest` value, before any hashing — and shows
 * an unrecognized sha-1-shaped value coming back `undefined`,
 * the fail-closed shape a caller must turn into a rejection.
 * The next segment demonstrates inbound
 * normalization: a mock Node `IncomingMessage`-shaped object
 * (mixed-case headers, a multi-value header, a host with a port) is
 * normalized with `fromNodeRequest` and verifies, while rebuilding
 * it with the wrong scheme is rejected with `SIGNATURE_MISMATCH`
 * because the inbound signature covers `@scheme`. The closing
 * segment demonstrates JWKS key resolution: a `JwksKeyStore` is
 * restored offline from a snapshot of the demo public key, the demo
 * request verifies through its key resolver, and a request signed
 * under an unknown `keyid` is rejected with `KEY_RESOLUTION_FAILED`.
 * The closing segment demonstrates RFC 7638 thumbprint keyids: the
 * demo public key is exported as a JWK, its `jwkThumbprint` is
 * printed, and a request signed with that thumbprint as its `keyid`
 * verifies under `expectedKeyId` pinned to the same thumbprint.
 * The demo closes with a structured-field canonicalization segment:
 * three fixed field values (a Dictionary with a Decimal member, an
 * Integer Item with leading zeros, a Dictionary Byte Sequence
 * member) are run through `canonicalizeStructuredFieldValue` and
 * printed as raw -> canonical pairs — the canonical form is what a
 * verifier actually compares for a `;sf` covered component, because
 * it re-serializes the parsed value strictly (Decimals gain three
 * fractional digits, leading-zero Integers collapse, Byte Sequences
 * are re-encoded). Every input and expectation is a fixed constant,
 * so the segment is byte-identical between runs.
 * The demo closes with a dictionary-member extraction segment:
 * one fixed multi-member Dictionary value is run through
 * `serializeDictionaryMemberValue` once per fixed key (an Integer
 * member, a member with parameters, a Decimal member, a Byte
 * Sequence member, an Inner List member and a bare key), and each
 * extraction is printed as a key -> serialized-value pair — the
 * member value WITHOUT its Dictionary key, parameters still
 * attached, which is what a `;key` covered component contributes
 * to the signature base when a gateway forwards only the single
 * member its signature covers. A missing key is asserted to throw
 * outside the printed extractions and its rejection is printed as
 * one line. Every input and expectation is a fixed constant, so
 * the segment is byte-identical between runs.
 * The demo closes with a signature-params serialization segment:
 * five fixed (covered components, parameters) cases — the same
 * corpus the benchmark measures for this function — are run
 * through `serializeSignatureParams` and printed as name ->
 * serialized pairs, showing how the covered-component inner list
 * and the created/expires/keyid/alg/nonce/tag parameters are
 * assembled into the single `@signature-params` line a verifier
 * rebuilds byte-for-byte before comparing. Every expectation is
 * a fixed constant, so the segment is byte-identical between runs.
 * The demo closes with a PEM key round-trip segment: the main
 * line's ed25519 key pair is exported with `exportPublicKeyPem` /
 * `exportPrivateKeyPem`, only the first line of each PEM (its type
 * header) is printed, the PEM texts are imported back with
 * `importPublicKey` / `importPrivateKey`, and the imported keys
 * complete a fresh sign -> verify round-trip — the PEM
 * export -> import -> verify path a gateway or ops tool performs
 * when keys are distributed as PEM files rather than JWKs. Outside
 * the printed lines the demo asserts the round-trip verification
 * passed and that both PEM headers equal the hand-pinned
 * expectations below. The request, `created` and nonce are fixed
 * constants, so the segment's printed lines are identical between
 * runs even though the key pair itself is fresh.
 * The demo closes with a throwing-verification segment: the main
 * signed request is verified with `verifyRequestOrThrow`, which
 * returns the verified identity (label, keyid, alg, nonce) instead
 * of a result object, and the same request with the body tampered
 * by one byte is verified again — this time the call throws a
 * `VerifyError` whose stable `code` is printed, and the demo
 * asserts outside the printed lines that the caught error passes
 * the `isVerifyError` guard and that its code equals the
 * hand-pinned `BODY_DIGEST_MISMATCH` expectation below (the same
 * rejection the returning `verifyRequest` reports for the same
 * tamper). Every input is a fixed demo constant, so the segment
 * is byte-identical between runs.
 * The demo closes with a nonce-generation segment: every earlier
 * segment signs with a hand-written nonce constant, but a real
 * signer must not hand-roll its replay-protection nonce — a
 * predictable nonce makes the replay cache meaningless.
 * `generateNonce()` draws from the CSPRNG and base64url-encodes
 * the bytes: the demo calls it once with the default (16 bytes)
 * and once with 32 bytes, prints both nonces with their lengths,
 * signs a fresh request with the short one, and prints the nonce
 * the verifier parses back out. Outside the printed lines the
 * demo asserts both shapes against the hand-pinned expectations
 * below (decoded byte lengths, character lengths, base64url
 * alphabet, the two draws distinct) and that the parsed-back
 * nonce equals the signed one character for character. The nonce
 * values themselves are fresh on every run — like the key pair,
 * only their shapes are stable — so this segment is the one
 * deliberate exception to the demo's fixed-nonce determinism.
 * The demo closes with a JWK public-key import segment: the main
 * line's ed25519 public key is exported with `exportPublicKeyJwk`,
 * carried through a JSON stringify/parse round-trip exactly as it
 * would cross the wire to a gateway, and read back with
 * `importPublicKeyJwk` — the inbound half of JWK key distribution,
 * which the thumbprint segment above (export only) never showed and
 * the PEM round-trip segment covers only for the PEM format. The
 * main signed request is then verified with the imported key and
 * the result printed. A detached copy of the JWK whose `x`
 * coordinate has its first character flipped is imported as well:
 * the flipped coordinate is still a well-formed 32-byte value, so
 * the import succeeds, but verification against that wrong key is
 * rejected with `SIGNATURE_MISMATCH` — asserted outside the printed
 * lines against the hand-pinned expectation below (the rejection
 * shape `test/jwk.test.ts` pins for an imported key facing a
 * request it did not sign). Only the exported JWK's shape
 * (`kty`/`crv`/the 43-character `x` length) is printed, never the
 * key bytes, so the segment's printed lines are identical between
 * runs even though the key pair itself is fresh.
 * The demo closes with a key-resolver memoization segment: the
 * JWKS segment above resolves keys through a store, but a plain
 * `keyResolver` is called on *every* `verifyRequest` — in front
 * of a remote or slow keystore that is one lookup per request.
 * A counting resolver over a fixed two-key store is wrapped with
 * `memoizeKeyResolver` (TTL pinned, injected clock pinned to the
 * demo's fixed verify instant) and passed as `keyResolver`: the
 * main request verifies twice under the same `keyid` while the
 * underlying resolver is called only once, then a request signed
 * under a second `keyid` verifies and the count advances to two.
 * Outside the printed lines the demo asserts all three
 * verifications passed and that both counts equal the
 * hand-pinned expectations below (the same counts
 * `test/memoizeKeyResolver.test.ts` pins for its counting
 * store). No key bytes are printed — only keyids and counts —
 * so the segment is byte-identical between runs.
 * The demo closes with an HMAC secret-length guard segment: the
 * gateway line above signs with hmac-sha256, but the demo never
 * showed the setup-time guard every HMAC secret passes through.
 * Fixed secrets built from a fixed fill byte (only their lengths
 * matter) are run through `assertHmacSecretLength`: a 32-byte
 * secret passes for `hmac-sha256` and a 64-byte secret passes
 * for `hmac-sha512`, while a secret one byte below each floor
 * (31 bytes for sha256, 63 bytes for sha512) is rejected.
 * Outside the printed lines the demo asserts the accepted group
 * all passed and both rejection messages equal the hand-pinned
 * expectations below (the same messages `src/keys.ts` builds
 * from `MIN_HMAC_SECRET_BYTES` / `MIN_HMAC_SHA512_SECRET_BYTES`
 * and the keyLength / hmacSha512 suites pin). Only algorithm
 * names and byte lengths are printed, never key bytes, so the
 * segment is byte-identical between runs.
 * The demo closes with an RSA modulus-length guard segment: the
 * RSA lines above sign and verify with RSA keys, but the demo
 * never showed the setup-time guard every RSA key passes
 * through on the `rsa-v1_5-sha256` sign and verify paths.
 * Fixed-shape keys (an RSA public key exactly at the
 * 2048-bit floor, an RSA public key at 1024 bits, and the main
 * line's ed25519 public key — the RSA pairs are generated once
 * per process, only their types and modulus lengths matter)
 * are run through `assertRsaModulusLength` under a fixed
 * caller context: the at-floor RSA key passes, while the
 * 1024-bit RSA key and the non-RSA ed25519 key are each
 * rejected. Outside the printed lines the demo asserts the
 * accepted case passed and both rejection messages equal the
 * hand-pinned expectations below (the same messages
 * `src/keys.ts` builds from `MIN_RSA_MODULUS_BITS` and the
 * bench corpus / rsaV15 suite pin). Only key types and
 * modulus lengths are printed, never key bytes, so the
 * segment is byte-identical between runs.
 * Right after the main line's verification, the demo also prints a
 * signature-base segment: the RFC 9421 §2.5 signature base of the
 * main signed request — the exact string that was signed — rebuilt
 * with `buildSignatureBase` over the request's actual covered
 * components, so readers can compare it line by line with the RFC
 * text. The base carries no key or signature bytes and every input
 * is a fixed demo constant, so the printed base is identical
 * between runs.
 *
 * Usage: `npm run demo` (builds with tsc, then runs node on the compiled
 * output). Zero runtime dependencies: this file only imports the library
 * itself.
 *
 * The request data is deterministic — fixed method, URL, body, `created`
 * timestamp, key id, and nonce are constants below; no wall clock beyond
 * the injected verify instant, no network. The ed25519 key pair itself
 * is generated fresh on every run (see `generateEd25519KeyPair`), so the
 * signature bytes differ between runs while every other printed line is
 * identical. The gateway HMAC secret below is a fixed demo value (never
 * use it anywhere else), so the gateway signature itself is
 * deterministic; only the merchant's fresh-key signature varies.
 * The nonce-generation segment's two nonces are likewise fresh on
 * every run (that is the segment's point); only their printed
 * shapes — character lengths, decoded byte lengths, alphabet —
 * are stable between runs.
 */

import { fileURLToPath } from "node:url";
import {
  createSecretKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import {
  addSignature,
  assertHmacSecretLength,
  assertRsaModulusLength,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  contentDigestAlgOf,
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyPem,
  fromNodeRequest,
  generateEd25519KeyPair,
  generateNonce,
  generateRsaPssKeyPair,
  importPrivateKey,
  importPublicKey,
  importPublicKeyJwk,
  isVerifyError,
  jwkThumbprint,
  JwksKeyStore,
  listSignatureLabels,
  memoizeKeyResolver,
  ReplayCache,
  secretKey,
  serializeDictionaryMemberValue,
  serializeSignatureParams,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type ContentDigestAlg,
  type Ed25519PublicJwk,
  type IncomingRequestLike,
  type JwksKeyStoreSnapshot,
  type RequestLike,
  type SignatureParams,
  type SignedHttpRequest,
  type VerifyError,
  type VerifyFailureCode,
  type VerifyResult,
} from "./index.js";

export const DEMO_KEY_ID = "demo-key-1";
export const DEMO_CREATED = 1700000000;
export const DEMO_NONCE = "demo-nonce-001";
export const DEMO_BODY = JSON.stringify({ amount: 100, currency: "USD" });
/** DEMO_BODY with exactly one byte changed: amount 100 -> 101. */
export const DEMO_TAMPERED_BODY = JSON.stringify({
  amount: 101,
  currency: "USD",
});
/**
 * Components the main `sig1` signature covers: `signRequest`'s
 * default set for a request with a body. It is repeated here
 * explicitly so the signature-base segment below can rebuild the
 * base over exactly the set the signer used.
 */
export const DEMO_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
];
/** Label of the gateway's appended second signature. */
export const DEMO_GATEWAY_LABEL = "gateway";
export const DEMO_GATEWAY_KEY_ID = "gateway-key-1";
/**
 * Hand-pinned labels of the dual-signed request, in wire order:
 * the main `signRequest` call passes no label, so its signature
 * carries the library default `sig1` (see `src/sign.ts`), and the
 * gateway appends `DEMO_GATEWAY_LABEL` second. The two-label
 * wire-order shape is the same one the bench pins independently
 * as `PARSER_EXPECTED_LABELS` (`["merchant", "gateway"]`) and
 * the parser / `addSignature` tests pin for their own dual-signed
 * requests — the demo never derives this expectation from the
 * `listSignatureLabels` output it is checking.
 */
export const DEMO_SIGNATURE_LABELS: ReadonlyArray<string> = [
  "sig1",
  "gateway",
];
/**
 * Demo-only gateway HMAC secret: 49 bytes (the hmac-sha256 floor is
 * 32), fixed so the gateway signature is deterministic, and labelled
 * as a demo value — it must never be used outside this demo.
 */
export const DEMO_GATEWAY_SECRET =
  "demo-gateway-secret-do-not-use-in-prod-0123456789";
/**
 * Components the gateway signature covers. Unlike the merchant's
 * `sig1` signature (the default set, including `content-digest`), the
 * gateway additionally covers `content-type` — which is what makes
 * the tamper-isolation step below possible: changing `content-type`
 * breaks only the gateway label.
 */
export const DEMO_GATEWAY_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
  "content-type",
];
/** Value `content-type` is tampered to in the isolation step. */
export const DEMO_TAMPERED_CONTENT_TYPE = "text/plain";
/**
 * Nonce of the second request in the replay segment: distinct from
 * `DEMO_NONCE`, so the replay cache must let it through — the cache
 * rejects *repeats*, not new nonces.
 */
export const DEMO_OTHER_NONCE = "demo-nonce-002";
/**
 * Hand-pinned digest algorithms of the identification segment:
 * the main line emits the library default `sha-512` and the
 * sha-256 peer line emits `sha-256` — the only two algorithms
 * this library can emit (see `src/digest.ts`), pinned
 * independently in `test/contentDigestAlg.test.ts` and the bench
 * `DIGEST_ALG_CORPUS`. The demo never derives these expectations
 * from the `contentDigestAlgOf` output it is checking.
 */
export const DEMO_MAIN_DIGEST_ALG: ContentDigestAlg = "sha-512";
export const DEMO_SHA256_DIGEST_ALG: ContentDigestAlg = "sha-256";
/**
 * Unrecognized `Content-Digest` value of the identification
 * segment: a sha-1-shaped value (the same shape the
 * contentDigestAlg tests pin for the `addSignature` rejection of
 * a header this library cannot emit, and the bench corpus pins
 * for this helper). `contentDigestAlgOf` must return `undefined`
 * for it — the fail-closed shape a caller rejects explicitly.
 */
export const DEMO_UNRECOGNIZED_DIGEST_VALUE = "sha-1=:abc=:";
/**
 * Replay-cache configuration for the closing segment: capacity 100
 * entries, a nonce stays tracked for 3600 seconds, and the clock is
 * pinned to the demo's fixed verify instant (`DEMO_CREATED + 60`), so
 * the segment is fully deterministic — no wall clock.
 */
export const DEMO_REPLAY_CACHE_MAX_ENTRIES = 100;
export const DEMO_REPLAY_CACHE_TTL_SEC = 3600;
/**
 * JWKS endpoint the closing segment's store is configured with. The
 * store is restored from a snapshot, so this URL is never fetched in
 * the demo — it is the endpoint a production verifier would refresh
 * from, and it matches the signed request's host.
 */
export const DEMO_JWKS_URL = "https://api.example.com/.well-known/jwks.json";
/**
 * `fetchedAtSec` of the closing segment's JWKS snapshot: pinned to
 * `DEMO_CREATED`, and the store's injected clock is pinned to the
 * demo's fixed verify instant (`DEMO_CREATED + 60`), so the restored
 * snapshot is fresh (well inside the default 300s TTL) and the
 * segment is fully deterministic — no wall clock.
 */
export const DEMO_JWKS_FETCHED_AT_SEC = DEMO_CREATED;
/**
 * Key id of the second request in the JWKS segment: it is absent from
 * the restored snapshot, so key resolution must fail closed with
 * `KEY_RESOLUTION_FAILED` even though the request is signed with the
 * demo's own private key.
 */
export const DEMO_UNKNOWN_KEY_ID = "demo-unknown-key-1";
/**
 * Fixed structured-field values of the closing canonicalization
 * segment, with the canonical form of each hand-pinned from the
 * RFC 8941 §4 strict-serialization rules (the same values pinned
 * independently in `test/sfComponent.test.ts` and the bench corpus)
 * — the demo never derives an expectation from the function it
 * demonstrates.
 */
export const DEMO_SF_CANONICALIZATION: ReadonlyArray<{
  name: string;
  input: string;
  expected: string;
}> = [
  {
    name: "dictionary-decimal",
    input: "limit=1500, remaining=1.5",
    expected: "limit=1500, remaining=1.500",
  },
  {
    name: "item-leading-zero-integer",
    input: "007",
    expected: "7",
  },
  {
    name: "dictionary-byte-sequence",
    input: "sig=:aGVsbG8=:;x=?0",
    expected: "sig=:aGVsbG8=:;x=?0",
  },
];
/**
 * Fixed Dictionary value of the closing member-extraction segment:
 * the same multi-member value pinned in the bench corpus for
 * `serializeDictionaryMemberValue` (backlog #314), written out
 * literally here so the demo and the bench pin it independently.
 */
export const DEMO_DICT_MEMBER_VALUE =
  "a=1, b=2;x=1;y=2, n=1.5, sig=:aGVsbG8=:;x=?0, c=(a b c), d";
/**
 * Fixed key set of the closing member-extraction segment, with the
 * serialized value of each member hand-pinned from the RFC 8941
 * §4.1.2 member-serialization rules — the member value WITHOUT its
 * Dictionary key, parameters still attached — and matching the
 * values pinned independently in `test/keyComponent.test.ts`,
 * `test/sfComponent.test.ts` and the bench corpus — the demo never
 * derives an expectation from the function it demonstrates:
 * - a: an Integer member, already canonical -> `1`.
 * - b: a member carrying parameters -> `2;x=1;y=2`.
 * - n: a Decimal member -> `1.500`.
 * - sig: a Byte Sequence member with a Boolean parameter ->
 *   `:aGVsbG8=:;x=?0`.
 * - c: an Inner List member -> `(a b c)`.
 * - d: a bare key (Boolean-true member) -> `?1`.
 */
export const DEMO_DICT_MEMBER_EXTRACTION: ReadonlyArray<{
  key: string;
  expected: string;
}> = [
  { key: "a", expected: "1" },
  { key: "b", expected: "2;x=1;y=2" },
  { key: "n", expected: "1.500" },
  { key: "sig", expected: ":aGVsbG8=:;x=?0" },
  { key: "c", expected: "(a b c)" },
  { key: "d", expected: "?1" },
];
/**
 * Key absent from `DEMO_DICT_MEMBER_VALUE`: extracting it must
 * throw `dictionary member "zzz" is not present in the field
 * value` — the extraction fails closed rather than returning an
 * empty or whole-field value.
 */
export const DEMO_DICT_MEMBER_MISSING_KEY = "zzz";
/**
 * Fixed corpus of the closing signature-params serialization
 * segment: the same five (componentIds, params) cases the bench
 * corpus pins for `serializeSignatureParams` (backlog #320),
 * written out literally here so the demo and the bench pin them
 * independently. Every expected serialization is hand-pinned from
 * the serializer's contract — the inner list is the covered
 * component ids in canonical wire form (quoted base, then
 * `;req` / `;tr` / `;name=` / `;key=` parameters), followed by the
 * signature parameters in the fixed order created, expires, keyid,
 * alg, nonce, tag, with string values quoted and backslash / quote
 * characters escaped — and matches the values pinned in
 * `test/rfc9421AppendixB.test.ts` (empty), `test/golden.test.ts`
 * (golden), the parameterized-component tests (parameterized) and
 * `test/nonce.test.ts` (escaped) — the demo never derives an
 * expectation from the function it demonstrates:
 * - empty: no covered components, created + keyid + nonce.
 * - golden: the shared four components with created + keyid + alg.
 * - full: the same four components with all six parameters set
 *   (expires sits between created and keyid, tag last).
 * - parameterized: four component ids carrying `;req`, `;tr`,
 *   `;name="amount"` and `;key="b"`.
 * - escaped: a nonce carrying a quote and a backslash
 *   (`a"b\c d`) serializes with both escaped.
 */
export const DEMO_SIG_PARAMS_SERIALIZATION: ReadonlyArray<{
  name: string;
  componentIds: string[];
  params: SignatureParams;
  expected: string;
}> = [
  {
    name: "empty",
    componentIds: [],
    params: {
      created: 1618884473,
      keyid: "test-key-rsa-pss",
      nonce: "b3k2pp5k7z-50gnwp.yemd",
    },
    expected:
      '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
  },
  {
    name: "golden",
    componentIds: ["@method", "@authority", "@path", "content-digest"],
    params: { created: 1700000000, keyid: "k1", alg: "hmac-sha256" },
    expected:
      '("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"',
  },
  {
    name: "full",
    componentIds: ["@method", "@authority", "@path", "content-digest"],
    params: {
      created: 1700000000,
      expires: 1700000300,
      keyid: "demo-key-1",
      alg: "ed25519",
      nonce: "demo-nonce-001",
      tag: "payment-webhook-v1",
    },
    expected:
      '("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"',
  },
  {
    name: "parameterized",
    componentIds: [
      "@method;req",
      "x-checksum;tr",
      '@query-param;name="amount"',
      'x-dict;key="b"',
    ],
    params: { created: 1700000000, keyid: "k1", alg: "ed25519" },
    expected:
      '("@method";req "x-checksum";tr "@query-param";name="amount" "x-dict";key="b");created=1700000000;keyid="k1";alg="ed25519"',
  },
  {
    name: "escaped",
    componentIds: ["@method"],
    params: {
      created: 1700000000,
      keyid: "k",
      alg: "ed25519",
      nonce: 'a"b\\c d',
    },
    expected:
      '("@method");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
  },
];

/** Nonce of the PEM round-trip segment's signed request. */
export const DEMO_PEM_NONCE = "demo-nonce-pem-001";
/**
 * Hand-pinned first lines (PEM type headers) of the PEM round-trip
 * segment: `exportPublicKeyPem` exports in SPKI form, whose PEM
 * header is `-----BEGIN PUBLIC KEY-----`, and
 * `exportPrivateKeyPem` exports in PKCS#8 form, whose PEM header is
 * `-----BEGIN PRIVATE KEY-----` — the formats written literally in
 * `src/keys.ts` (spki / pkcs8). The expectations are written out
 * here, never derived from the exported text the demo is checking.
 */
export const DEMO_PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----";
export const DEMO_PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----";

/**
 * Hand-pinned failure code of the throwing-verification segment:
 * verifying the main signed request with its body tampered by the
 * same one byte as the main line (amount 100 -> 101) must throw a
 * `VerifyError` carrying `BODY_DIGEST_MISMATCH` — the same code
 * the returning `verifyRequest` reports for that tamper (pinned
 * independently in the demo tamper test above). The expectation
 * is written out here, never derived from the thrown error the
 * demo is checking.
 */
export const DEMO_THROW_TAMPERED_CODE: VerifyFailureCode =
  "BODY_DIGEST_MISMATCH";

/**
 * Hand-pinned shapes of the closing nonce-generation segment:
 * `generateNonce()` defaults to 16 bytes (128 bits), which
 * base64url-encodes to 22 characters with no padding, and
 * `generateNonce(32)` draws 32 bytes, encoding to 43 characters —
 * the same shapes pinned independently in
 * `test/generateNonce.test.ts` and the `src/keys.ts` doc. The
 * expectations are written out here, never derived from the
 * generated values the demo is checking; the values themselves
 * are random per run, only the shapes are pinned.
 */
export const DEMO_GENERATED_NONCE_BYTES = 16;
export const DEMO_GENERATED_NONCE_LENGTH = 22;
export const DEMO_GENERATED_LONG_NONCE_BYTES = 32;
export const DEMO_GENERATED_LONG_NONCE_LENGTH = 43;

/**
 * Hand-pinned failure code of the JWK import segment's tampered
 * copy: flipping the first character of the exported JWK's `x`
 * coordinate yields a different, still well-formed ed25519 public
 * key, so `importPublicKeyJwk` accepts it but verification of the
 * main signed request against that wrong key must fail with
 * `SIGNATURE_MISMATCH` — the same code the verifier reports for
 * any signature checked against a key that did not produce it
 * (pinned independently for the imported-key shape in
 * `test/jwk.test.ts`, which rejects requests an imported key did
 * not sign). The expectation is written out here, never derived
 * from the verification the demo is checking.
 */
export const DEMO_JWK_TAMPERED_CODE: VerifyFailureCode =
  "SIGNATURE_MISMATCH";

/**
 * Key id of the second key in the closing key-resolver
 * memoization segment: its public key sits next to the main
 * demo key in the segment's fixed two-key store, under a keyid
 * no other segment uses, so its first verification must miss
 * the memoization cache exactly once.
 */
export const DEMO_MEMOIZED_SECOND_KEY_ID = "demo-key-2";
/** Nonce of the memoization segment's second-key signed request. */
export const DEMO_MEMOIZED_NONCE = "demo-nonce-memoized-001";
/**
 * TTL (seconds) of the memoization segment's
 * `memoizeKeyResolver` wrapper: the library default (300), with
 * the wrapper's injected clock pinned to the demo's fixed
 * verify instant (`DEMO_CREATED + 60`), so no entry can expire
 * mid-segment and the call counts below are deterministic.
 */
export const DEMO_MEMOIZED_TTL_SEC = 300;
/**
 * Hand-pinned underlying-resolver call counts of the
 * memoization segment: verifying the main request twice under
 * `DEMO_KEY_ID` resolves the keyid exactly once (the second
 * verification is a cache hit), and verifying the second keyid
 * afterwards advances the count to exactly two (one miss, one
 * resolution) — the same counting-store expectations
 * `test/memoizeKeyResolver.test.ts` pins. The expectations are
 * written out here, never derived from the counter the demo is
 * checking.
 */
export const DEMO_MEMOIZED_CALLS_AFTER_REPEAT = 1;
export const DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY = 2;

/**
 * Fixed HMAC secret-length guard corpus of the closing guard
 * segment: each case is a secret of a fixed byte length (built
 * from a fixed 0xab fill — only the length matters to the guard,
 * never the content) paired with its algorithm. The accepted
 * lengths sit exactly on each algorithm's floor
 * (`MIN_HMAC_SECRET_BYTES` 32 for hmac-sha256,
 * `MIN_HMAC_SHA512_SECRET_BYTES` 64 for hmac-sha512, RFC 2104
 * §3); the rejected lengths sit exactly one byte below each
 * floor — the same boundary shape the bench corpus
 * (`HMAC_GUARD_CORPUS`) and the keyLength / hmacSha512 suites
 * pin. No outcome is derived from `assertHmacSecretLength`
 * itself.
 */
export const DEMO_HMAC_GUARD_ACCEPTED: ReadonlyArray<{
  alg: "hmac-sha256" | "hmac-sha512";
  bytes: number;
}> = [
  { alg: "hmac-sha256", bytes: 32 },
  { alg: "hmac-sha512", bytes: 64 },
];
export const DEMO_HMAC_GUARD_REJECTED: ReadonlyArray<{
  alg: "hmac-sha256" | "hmac-sha512";
  bytes: number;
}> = [
  { alg: "hmac-sha256", bytes: 31 },
  { alg: "hmac-sha512", bytes: 63 },
];
/**
 * Hand-pinned rejection messages of the guard segment, one per
 * rejected case in `DEMO_HMAC_GUARD_REJECTED` order: the exact
 * strings `assertHmacSecretLength` throws for a 31-byte
 * hmac-sha256 secret and a 63-byte hmac-sha512 secret (written
 * out here, never derived from the guard under test).
 */
export const DEMO_HMAC_GUARD_ERRORS: ReadonlyArray<string> = [
  "assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes (RFC 2104: the key SHOULD be at least as long as the hash output; sha-256 → 32 bytes), got 31 bytes",
  "assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes (RFC 2104: the key SHOULD be at least as long as the hash output; sha-512 → 64 bytes), got 63 bytes",
];

/**
 * Fixed caller context the closing RSA guard segment passes to
 * `assertRsaModulusLength` — the guard prefixes every throw
 * with the caller-supplied context, exactly as the sign/verify
 * paths pass theirs (see `src/keys.ts`) and as the bench
 * corpus passes its own (`assertRsaModulusLength bench`).
 */
export const DEMO_RSA_GUARD_CONTEXT = "assertRsaModulusLength demo";
/**
 * Fixed RSA modulus-length guard corpus of the closing guard
 * segment: the accepted case is an RSA public key exactly on
 * the floor (`MIN_RSA_MODULUS_BITS` 2048, `src/keys.ts`); the
 * rejected cases are an RSA public key at 1024 bits (below the
 * floor) and an ed25519 public key (not an RSA key at all) —
 * the same shapes the bench corpus (`RSA_GUARD_CORPUS`) and
 * the rsaV15 suite pin. Only key types and modulus lengths
 * matter to the guard, never the key bytes. No outcome is
 * derived from `assertRsaModulusLength` itself.
 */
export const DEMO_RSA_GUARD_ACCEPTED: ReadonlyArray<{
  label: string;
  bits: number;
}> = [{ label: "rsa-2048 public", bits: 2048 }];
export const DEMO_RSA_GUARD_REJECTED: ReadonlyArray<{
  label: string;
  bits: number | null;
}> = [
  { label: "rsa-1024 public", bits: 1024 },
  { label: "ed25519 public", bits: null },
];
/**
 * Hand-pinned rejection messages of the RSA guard segment, one
 * per rejected case in `DEMO_RSA_GUARD_REJECTED` order: the
 * exact strings `assertRsaModulusLength` throws under
 * `DEMO_RSA_GUARD_CONTEXT` for a 1024-bit RSA key and for an
 * ed25519 key (written out here, never derived from the guard
 * under test).
 */
export const DEMO_RSA_GUARD_ERRORS: ReadonlyArray<string> = [
  "assertRsaModulusLength demo: RSA modulus must be at least 2048 bits, got 1024 bits",
  "assertRsaModulusLength demo: expected an RSA key, got an asymmetric ed25519 key",
];

/** Nonce of the thumbprint segment's signed request. */
export const DEMO_THUMBPRINT_NONCE = "demo-nonce-thumbprint-001";
/**
 * Host (with port) of the inbound segment's mock `IncomingMessage`:
 * `fromNodeRequest` preserves the port verbatim in the rebuilt URL's
 * `@authority`, so the equivalent signer-side request below is
 * signed against the same host-and-port URL.
 */
export const DEMO_INBOUND_HOST = "api.example.com:8443";
/** Absolute URL the inbound segment signs and then rebuilds. */
export const DEMO_INBOUND_URL = `https://${DEMO_INBOUND_HOST}/v1/payments`;
/** Nonce of the inbound segment's signed request. */
export const DEMO_INBOUND_NONCE = "demo-nonce-inbound-001";
/**
 * Multi-value header of the inbound segment, as a mock Node server
 * would expose repeated fields (an array). It is a covered component,
 * so verification only passes if `fromNodeRequest` joins the values
 * exactly as the signer canonicalized them (`"edge-1, gateway-2"`).
 */
export const DEMO_INBOUND_TRACE_HOPS: string[] = ["edge-1", "gateway-2"];
/**
 * Covered components of the inbound segment's signature. `@scheme` is
 * covered deliberately: rebuilding the same wire request with the
 * wrong scheme (the TLS-terminating-proxy mistake) must fail
 * verification instead of silently verifying against another URL.
 */
export const DEMO_INBOUND_COVERED_COMPONENTS: string[] = [
  "@method",
  "@scheme",
  "@authority",
  "@path",
  "content-digest",
  "x-trace-hops",
];
/** Wrong scheme the inbound segment rebuilds with (must be rejected). */
export const DEMO_INBOUND_WRONG_SCHEME = "http";

export interface DemoResult {
  signed: SignedHttpRequest;
  tamperedBody: string;
  verification: VerifyResult;
  /** RFC 9421 §2.5 signature base of the main `sig1` signed request. */
  signatureBase: string;
  tamperedVerification: VerifyResult;
  /** The request after the gateway appended its second signature. */
  dualSigned: SignedHttpRequest;
  /** Per-label results for the dual-signed request (both ok). */
  dualVerification: VerifyResult[];
  /**
   * Labels enumerated by `listSignatureLabels` over the
   * dual-signed request's `Signature-Input` value, in wire order
   * (`DEMO_SIGNATURE_LABELS`: `sig1`, then `gateway`).
   */
  signatureLabels: string[];
  /**
   * Per-label results after `content-type` was tampered: the merchant
   * `sig1` label still verifies, the `gateway` label fails.
   */
  contentTypeTamperedVerification: VerifyResult[];
  /** First verification of `signed` against the demo replay cache (ok). */
  replayFirstVerification: VerifyResult;
  /**
   * Second verification of the *same* `signed` request against the same
   * cache: rejected with `NONCE_REPLAY`.
   */
  replaySecondVerification: VerifyResult;
  /**
   * Verification of a request signed with `DEMO_OTHER_NONCE` against
   * the same cache (ok — a fresh nonce is not a replay).
   */
  replayOtherNonceVerification: VerifyResult;
  /**
   * The same demo request re-signed with
   * `contentDigestAlg: "sha-256"` (its `content-digest` header carries
   * a `sha-256=:` entry instead of the main line's `sha-512=:`).
   */
  sha256Signed: SignedHttpRequest;
  /** Verification of `sha256Signed` (ok). */
  sha256Verification: VerifyResult;
  /**
   * Verification of `sha256Signed` with the body tampered by one
   * byte: rejected with `BODY_DIGEST_MISMATCH`.
   */
  sha256TamperedVerification: VerifyResult;
  /**
   * Algorithm `contentDigestAlgOf` reads off the main line's
   * `content-digest` header (`DEMO_MAIN_DIGEST_ALG`: `sha-512`).
   */
  contentDigestAlg: ContentDigestAlg | undefined;
  /**
   * Algorithm `contentDigestAlgOf` reads off the sha-256 peer
   * line's `content-digest` header (`DEMO_SHA256_DIGEST_ALG`).
   */
  sha256ContentDigestAlg: ContentDigestAlg | undefined;
  /**
   * Result of `contentDigestAlgOf` on
   * `DEMO_UNRECOGNIZED_DIGEST_VALUE`: `undefined` — an algorithm
   * this library cannot emit fails closed for the caller.
   */
  unrecognizedContentDigestAlg: ContentDigestAlg | undefined;
  /** The request signed for the inbound segment (host with port). */
  inboundSigned: SignedHttpRequest;
  /** `inboundSigned`'s wire form normalized by `fromNodeRequest`. */
  inboundNormalized: RequestLike;
  /** Verification of the normalized inbound request (ok). */
  inboundVerification: VerifyResult;
  /**
   * Verification of the same wire request rebuilt with the wrong
   * scheme: rejected with `SIGNATURE_MISMATCH` (`@scheme` is covered).
   */
  inboundWrongSchemeVerification: VerifyResult;
  /** The v1 snapshot the JWKS segment restores its store from. */
  jwksSnapshot: JwksKeyStoreSnapshot;
  /** Number of keys in the restored JWKS store (1: the demo key). */
  jwksStoreSize: number;
  /**
   * Verification of `signed` through the restored store's key
   * resolver (ok — the snapshot carries `DEMO_KEY_ID`).
   */
  jwksVerification: VerifyResult;
  /**
   * Verification of a request signed under `DEMO_UNKNOWN_KEY_ID`
   * through the same resolver: rejected with `KEY_RESOLUTION_FAILED`.
   */
  jwksUnknownKeyVerification: VerifyResult;
  /** RFC 7638 thumbprint of the demo public key's exported JWK. */
  thumbprint: string;
  /** The request signed with `thumbprint` as its `keyid`. */
  thumbprintSigned: SignedHttpRequest;
  /**
   * Verification of `thumbprintSigned` with `expectedKeyId` pinned
   * to the thumbprint (ok — thumbprint-as-keyid binding holds).
   */
  thumbprintVerification: VerifyResult;
  /**
   * The closing canonicalization segment's results: each fixed input
   * paired with its `canonicalizeStructuredFieldValue` output.
   */
  sfCanonicalization: ReadonlyArray<{
    name: string;
    input: string;
    canonical: string;
  }>;
  /**
   * The closing member-extraction segment's results: each fixed
   * key paired with its `serializeDictionaryMemberValue` output
   * over `DEMO_DICT_MEMBER_VALUE`.
   */
  dictMemberExtraction: ReadonlyArray<{
    key: string;
    value: string;
  }>;
  /**
   * Error message thrown when extracting
   * `DEMO_DICT_MEMBER_MISSING_KEY` from `DEMO_DICT_MEMBER_VALUE`
   * (empty only if the extraction unexpectedly did not throw,
   * which the demo tests reject).
   */
  dictMemberMissingKeyError: string;
  /**
   * The closing serialization segment's results: each fixed case
   * name paired with its `serializeSignatureParams` output over
   * `DEMO_SIG_PARAMS_SERIALIZATION`.
   */
  sigParamsSerialization: ReadonlyArray<{
    name: string;
    serialized: string;
  }>;
  /** First line (type header) of the main public key's PEM export. */
  pemPublicHeader: string;
  /** First line (type header) of the main private key's PEM export. */
  pemPrivateHeader: string;
  /**
   * The request signed in the PEM segment with the private key
   * imported back from its PEM export.
   */
  pemSigned: SignedHttpRequest;
  /**
   * Verification of `pemSigned` with the public key imported back
   * from its PEM export (ok — the PEM round-trip holds).
   */
  pemVerification: VerifyResult;
  /**
   * Identity returned by `verifyRequestOrThrow` for the main
   * signed request (label, keyid, alg, nonce — no result object).
   */
  throwVerification: {
    label: string;
    keyId?: string;
    alg?: string;
    nonce?: string;
    tag?: string;
  };
  /**
   * The `VerifyError` thrown by `verifyRequestOrThrow` for the
   * tampered-body request (code `DEMO_THROW_TAMPERED_CODE`).
   */
  throwTamperedError: VerifyError;
  /** Whether the caught tamper error passed the `isVerifyError` guard. */
  throwTamperedIsVerifyError: boolean;
  /**
   * Fresh nonce drawn by `generateNonce()` in the closing segment
   * (default draw: decodes to `DEMO_GENERATED_NONCE_BYTES` bytes,
   * `DEMO_GENERATED_NONCE_LENGTH` base64url characters). Random
   * per run — only its shape is pinned.
   */
  generatedNonce: string;
  /**
   * Fresh nonce drawn by `generateNonce(DEMO_GENERATED_LONG_NONCE_BYTES)`
   * in the closing segment (decodes to 32 bytes,
   * `DEMO_GENERATED_LONG_NONCE_LENGTH` base64url characters).
   */
  generatedLongNonce: string;
  /** The request signed in the closing segment with `generatedNonce`. */
  generatedNonceSigned: SignedHttpRequest;
  /**
   * Verification of `generatedNonceSigned` (ok — and the nonce the
   * verifier parses back out equals `generatedNonce` exactly).
   */
  generatedNonceVerification: VerifyResult;
  /**
   * The JWK the closing import segment exports from the main
   * line's ed25519 public key (`kty "OKP"`, `crv "Ed25519"`, a
   * 43-character base64url `x`; the key itself is fresh per run).
   */
  exportedJwk: Ed25519PublicJwk;
  /**
   * Verification of the main signed request with the public key
   * imported back from `exportedJwk` via `importPublicKeyJwk`
   * after a JSON wire round-trip (ok — the JWK import holds).
   */
  jwkImportedVerification: VerifyResult;
  /**
   * Verification of the main signed request with the key imported
   * from a detached copy of `exportedJwk` whose `x` first
   * character was flipped: rejected with
   * `DEMO_JWK_TAMPERED_CODE` (`SIGNATURE_MISMATCH`).
   */
  jwkTamperedVerification: VerifyResult;
  /**
   * First verification of the main signed request through the
   * closing segment's memoized resolver (ok — a cache miss that
   * resolves `DEMO_KEY_ID` once).
   */
  memoizedFirstVerification: VerifyResult;
  /**
   * Second verification of the same request through the same
   * memoized resolver (ok — served from the cache, so the
   * underlying resolver is not called again).
   */
  memoizedRepeatVerification: VerifyResult;
  /**
   * Verification of the request signed under
   * `DEMO_MEMOIZED_SECOND_KEY_ID` through the same memoized
   * resolver (ok — a new keyid misses the cache and resolves).
   */
  memoizedSecondKeyVerification: VerifyResult;
  /**
   * Underlying resolver calls after the two `DEMO_KEY_ID`
   * verifications (`DEMO_MEMOIZED_CALLS_AFTER_REPEAT`: 1).
   */
  memoizedResolverCallsAfterRepeat: number;
  /**
   * Underlying resolver calls after the second keyid's
   * verification (`DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY`: 2).
   */
  memoizedResolverCallsAfterSecondKey: number;
  /**
   * The closing HMAC guard segment's accepted cases: each fixed
   * secret length passed `assertHmacSecretLength` for its
   * algorithm (exactly on the per-algorithm floor).
   */
  hmacGuardAccepted: ReadonlyArray<{
    alg: "hmac-sha256" | "hmac-sha512";
    bytes: number;
  }>;
  /**
   * The closing HMAC guard segment's rejections: each fixed
   * secret length (one byte below its algorithm's floor) was
   * rejected, paired with the exact error message the guard
   * threw (`DEMO_HMAC_GUARD_ERRORS`).
   */
  hmacGuardRejections: ReadonlyArray<{
    alg: "hmac-sha256" | "hmac-sha512";
    bytes: number;
    error: string;
  }>;
  /**
   * The closing RSA guard segment's accepted cases: each
   * fixed-shape key passed `assertRsaModulusLength` under
   * `DEMO_RSA_GUARD_CONTEXT` (exactly on the 2048-bit floor).
   */
  rsaGuardAccepted: ReadonlyArray<{
    label: string;
    bits: number;
  }>;
  /**
   * The closing RSA guard segment's rejections: the 1024-bit
   * RSA key (below the floor) and the ed25519 key (not RSA)
   * were each rejected, paired with the exact error message
   * the guard threw (`DEMO_RSA_GUARD_ERRORS`).
   */
  rsaGuardRejections: ReadonlyArray<{
    label: string;
    bits: number | null;
    error: string;
  }>;
  lines: string[];
}

/**
 * RSA key pairs for the closing RSA guard segment, generated
 * once per process and reused across `runDemo()` calls — the
 * same generate-once shape the bench corpus uses
 * (`RSA_GUARD_STRONG` / `RSA_GUARD_WEAK`), so the demo tests,
 * which call `runDemo()` many times, do not pay RSA key
 * generation on every call. Only the keys' types and modulus
 * lengths are ever printed, never their bytes.
 */
let demoRsaGuardKeys: {
  strongPublic: KeyObject;
  weakPublic: KeyObject;
} | null = null;
function rsaGuardKeys(): {
  strongPublic: KeyObject;
  weakPublic: KeyObject;
} {
  if (demoRsaGuardKeys === null) {
    demoRsaGuardKeys = {
      strongPublic: generateRsaPssKeyPair().publicKey,
      weakPublic: generateKeyPairSync("rsa", {
        modulusLength: 1024,
      }).publicKey,
    };
  }
  return demoRsaGuardKeys;
}

function formatLabelResult(prefix: string, result: VerifyResult): string {
  return result.ok
    ? `${prefix} ${result.label}: OK (label ${result.label}, keyid="${result.keyId}", alg="${result.alg}")`
    : `${prefix} ${result.label}: FAILED (code ${result.code}: ${result.reason})`;
}

/**
 * Run the demo without printing anything, and return the signed request,
 * both verification results, and the exact lines `main()` prints — so
 * tests can assert on the demo itself, not just on the library.
 */
export function runDemo(): DemoResult {
  const { publicKey, privateKey } = generateEd25519KeyPair();

  const signed = signRequest(
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

  // Verify at a fixed instant inside the signature's freshness window.
  const verification = verifyRequest(signed, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });

  // Signature-base segment: rebuild the RFC 9421 §2.5 signature base
  // of the main signed request over exactly the components and
  // parameters the signer used (the signed request itself carries
  // the resolved `content-digest` header value the base binds). The
  // base is the exact string that was signed; it contains no key or
  // signature bytes and every input is a fixed demo constant, so it
  // is identical between runs even though the key pair is fresh.
  const signatureBase = buildSignatureBase(
    [...DEMO_COVERED_COMPONENTS],
    signed,
    {
      created: DEMO_CREATED,
      keyid: DEMO_KEY_ID,
      alg: "ed25519",
      nonce: DEMO_NONCE,
    },
  );

  // One byte of the body changed (100 -> 101); the headers — including
  // the signed content-digest — are left untouched, exactly as a
  // man-in-the-middle body swap would leave them.
  const tamperedVerification = verifyRequest(
    { ...signed, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );

  // Multi-party step: the merchant's `sig1` signature above is the
  // first signature; the payment gateway now appends its own second
  // signature with `addSignature` (hmac-sha256 under a demo-only
  // secret), without touching the merchant's entries. The gateway
  // covers `content-type` in addition to the derived components —
  // see DEMO_GATEWAY_COVERED_COMPONENTS.
  const gatewaySecret = secretKey(DEMO_GATEWAY_SECRET);
  const dualSigned = addSignature(signed, {
    keyId: DEMO_GATEWAY_KEY_ID,
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: DEMO_CREATED,
    label: DEMO_GATEWAY_LABEL,
    coveredComponents: [...DEMO_GATEWAY_COVERED_COMPONENTS],
  });
  const dualVerifyOptions = {
    key: publicKey,
    keys: { [DEMO_GATEWAY_LABEL]: gatewaySecret },
    now: DEMO_CREATED + 60,
  };
  const dualVerification = verifyAllLabels(dualSigned, dualVerifyOptions);

  // Label-enumeration segment: before verifying labels one by one,
  // a receiver first enumerates which labels a multi-label request
  // actually carries. `listSignatureLabels` splits the merged
  // `Signature-Input` value on top-level commas, so the gateway's
  // appended member does not hide inside the merchant's. Outside
  // the printed lines the demo asserts the enumerated labels equal
  // the hand-pinned DEMO_SIGNATURE_LABELS in set and wire order —
  // a mismatch throws instead of printing a misleading segment.
  const signatureLabels = listSignatureLabels(
    dualSigned.headers["signature-input"],
  );
  if (
    signatureLabels.length !== DEMO_SIGNATURE_LABELS.length ||
    signatureLabels.some((label, i) => label !== DEMO_SIGNATURE_LABELS[i])
  ) {
    throw new Error(
      `demo fixture broken: listSignatureLabels enumerated ${JSON.stringify(signatureLabels)} ` +
        `instead of the pinned ${JSON.stringify(DEMO_SIGNATURE_LABELS)}`,
    );
  }

  // Tamper isolation: `content-type` is covered only by the gateway
  // signature, so changing it must fail the gateway label while the
  // merchant `sig1` label (which does not cover `content-type`, and
  // whose content-digest still matches the untouched body) still
  // verifies — `verifyAllLabels` reports each label independently.
  const contentTypeTamperedVerification = verifyAllLabels(
    {
      ...dualSigned,
      headers: {
        ...dualSigned.headers,
        "content-type": DEMO_TAMPERED_CONTENT_TYPE,
      },
    },
    dualVerifyOptions,
  );

  // Replay segment: a nonce alone does not stop replays — the verifier
  // needs a cache of seen nonces. With an opt-in ReplayCache (fixed
  // clock pinned to the demo's verify instant, capacity/TTL constants
  // above), the *same* signed request verifies the first time and is
  // rejected with NONCE_REPLAY the second time: the signature is still
  // cryptographically valid, but its nonce has already been spent.
  const replayCache = new ReplayCache({
    maxEntries: DEMO_REPLAY_CACHE_MAX_ENTRIES,
    ttlSec: DEMO_REPLAY_CACHE_TTL_SEC,
    now: () => DEMO_CREATED + 60,
  });
  const replayVerifyOptions = {
    key: publicKey,
    now: DEMO_CREATED + 60,
    replayCache,
  };
  const replayFirstVerification = verifyRequest(signed, replayVerifyOptions);
  const replaySecondVerification = verifyRequest(signed, replayVerifyOptions);

  // A different nonce is not a replay: a second request signed with
  // DEMO_OTHER_NONCE verifies against the same cache.
  const otherNonceSigned = signRequest(
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
      nonce: DEMO_OTHER_NONCE,
    },
  );
  const replayOtherNonceVerification = verifyRequest(
    otherNonceSigned,
    replayVerifyOptions,
  );

  // sha-256 Content-Digest segment: some peers (e.g. a payment
  // gateway webhook endpoint) only accept sha-256 digests. Re-sign
  // the *same* demo request — same key, keyid, created and nonce —
  // with `contentDigestAlg: "sha-256"`, so the only wire difference
  // from the main line is the digest algorithm (and the signature
  // over it). The verifier accepts sha-256, so it verifies; changing
  // the body by the same one byte as the main tamper step
  // (100 -> 101) is rejected with BODY_DIGEST_MISMATCH.
  const sha256Signed = signRequest(
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
      contentDigestAlg: "sha-256",
    },
  );
  const sha256Verification = verifyRequest(sha256Signed, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  const sha256TamperedVerification = verifyRequest(
    { ...sha256Signed, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );

  // Digest-algorithm identification segment: a receiver holding an
  // already-emitted `Content-Digest` header reads its algorithm off
  // with `contentDigestAlgOf` before deciding whether it can verify
  // the digest at all — the helper reads only the prefix before the
  // first `=` and returns `undefined` for anything this library
  // cannot emit. Outside the printed lines the demo asserts all
  // three identifications equal the hand-pinned expectations
  // (DEMO_MAIN_DIGEST_ALG / DEMO_SHA256_DIGEST_ALG / `undefined`
  // for the sha-1-shaped value) — a mismatch throws instead of
  // printing a misleading segment.
  const contentDigestAlg = contentDigestAlgOf(
    signed.headers["content-digest"],
  );
  const sha256ContentDigestAlg = contentDigestAlgOf(
    sha256Signed.headers["content-digest"],
  );
  const unrecognizedContentDigestAlg = contentDigestAlgOf(
    DEMO_UNRECOGNIZED_DIGEST_VALUE,
  );
  if (
    contentDigestAlg !== DEMO_MAIN_DIGEST_ALG ||
    sha256ContentDigestAlg !== DEMO_SHA256_DIGEST_ALG ||
    unrecognizedContentDigestAlg !== undefined
  ) {
    throw new Error(
      `demo fixture broken: contentDigestAlgOf gave ${JSON.stringify(contentDigestAlg)} / ` +
        `${JSON.stringify(sha256ContentDigestAlg)} / ${JSON.stringify(unrecognizedContentDigestAlg)} ` +
        `instead of the pinned "${DEMO_MAIN_DIGEST_ALG}" / "${DEMO_SHA256_DIGEST_ALG}" / undefined`,
    );
  }

  // Inbound segment: a real webhook gateway never sees a hand-built
  // RequestLike — it receives a Node IncomingMessage. The demo signs
  // the equivalent RequestLike first (host with port, `@scheme`
  // covered, the multi-value `x-trace-hops` header covered), then
  // rebuilds it from a mock IncomingMessage-shaped object — mixed-case
  // header names, the multi-value header still an array, the socket
  // flagged encrypted so the scheme is inferred as https — through
  // `fromNodeRequest`, with no server and no network. Normalization
  // lowercases the names and joins the multi-value header exactly as
  // the signer canonicalized it, so verification passes.
  const inboundSigned = signRequest(
    {
      method: "POST",
      url: DEMO_INBOUND_URL,
      headers: {
        "content-type": "application/json",
        "x-trace-hops": [...DEMO_INBOUND_TRACE_HOPS],
      },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_KEY_ID,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_INBOUND_NONCE,
      coveredComponents: [...DEMO_INBOUND_COVERED_COMPONENTS],
    },
  );
  const inboundWire: IncomingRequestLike = {
    method: "POST",
    url: "/v1/payments",
    headers: {
      Host: DEMO_INBOUND_HOST,
      "Content-Type": "application/json",
      "X-Trace-Hops": [...DEMO_INBOUND_TRACE_HOPS],
      "Content-Digest": inboundSigned.headers["content-digest"],
      "Signature-Input": inboundSigned.headers["signature-input"],
      Signature: inboundSigned.headers["signature"],
    },
    socket: { encrypted: true },
  };
  const inboundNormalized = fromNodeRequest(inboundWire, DEMO_BODY);
  const inboundVerification = verifyRequest(inboundNormalized, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });

  // Scheme mismatch: rebuilding the identical wire request with the
  // wrong scheme changes the covered `@scheme` component, so the
  // verifier rejects it with SIGNATURE_MISMATCH — the two sides
  // disagree on the exact URL that was signed.
  const inboundWrongSchemeVerification = verifyRequest(
    fromNodeRequest(inboundWire, DEMO_BODY, {
      scheme: DEMO_INBOUND_WRONG_SCHEME,
    }),
    { key: publicKey, now: DEMO_CREATED + 60 },
  );

  // JWKS segment: production gateways do not hand the verifier a raw
  // key — they publish a JWKS and the verifier resolves the claimed
  // keyid against it. The demo rebuilds that path offline: a v:1
  // snapshot carrying only the demo key's *public* JWK (fetchedAtSec
  // pinned to DEMO_JWKS_FETCHED_AT_SEC above) is restored into a
  // JwksKeyStore whose fetchImpl throws if it is ever called, so the
  // segment performs zero network I/O, and whose clock is pinned to
  // the fixed verify instant.
  const jwksSnapshot: JwksKeyStoreSnapshot = {
    v: 1,
    fetchedAtSec: DEMO_JWKS_FETCHED_AT_SEC,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid: DEMO_KEY_ID }],
  };
  const jwksStore = JwksKeyStore.restore(jwksSnapshot, DEMO_JWKS_URL, {
    fetchImpl: async () => {
      throw new Error("demo must not fetch (offline JWKS restore)");
    },
    now: () => DEMO_CREATED + 60,
  });
  const jwksVerification = verifyRequest(signed, {
    keyResolver: (kid) => jwksStore.resolve(kid),
    now: DEMO_CREATED + 60,
  });

  // An unknown keyid fails closed: this request is signed with the
  // demo's own private key, so its signature would verify — but its
  // claimed keyid is not in the restored snapshot, so the resolver
  // returns undefined and verification is rejected before any
  // signature check.
  const unknownKeySigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_UNKNOWN_KEY_ID,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_NONCE,
    },
  );
  const jwksUnknownKeyVerification = verifyRequest(unknownKeySigned, {
    keyResolver: (kid) => jwksStore.resolve(kid),
    now: DEMO_CREATED + 60,
  });

  // Thumbprint segment: a gateway that receives the demo public key
  // as a JWK needs a stable keyid for it. RFC 7638 defines that
  // identifier: hash the JWK's required members in canonical form.
  // The thumbprint is derived from the demo's (fresh) public key, so
  // like the signature itself it differs between runs; signing a
  // request with the thumbprint as `keyid` and verifying with
  // `expectedKeyId` pinned to it shows the fingerprint-as-keyid
  // binding a verifier would enforce.
  const thumbprint = jwkThumbprint(exportPublicKeyJwk(publicKey));
  const thumbprintSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: thumbprint,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_THUMBPRINT_NONCE,
    },
  );
  const thumbprintVerification = verifyRequest(thumbprintSigned, {
    key: publicKey,
    now: DEMO_CREATED + 60,
    expectedKeyId: thumbprint,
  });

  // Canonicalization segment: a `;sf` covered component is not
  // compared as wire bytes — the verifier parses the field value and
  // re-serializes it strictly, so the canonical form below is the
  // value that actually enters the signature base. All three inputs
  // are fixed constants (expectations hand-pinned in
  // DEMO_SF_CANONICALIZATION), so this segment is deterministic.
  const sfCanonicalization = DEMO_SF_CANONICALIZATION.map((c) => ({
    name: c.name,
    input: c.input,
    canonical: canonicalizeStructuredFieldValue(c.input),
  }));

  // Member-extraction segment: a `;key` covered component does not
  // contribute the whole Dictionary field — it contributes only the
  // one named member, re-serialized without its key. A gateway that
  // forwards a single member therefore pays and signs exactly the
  // values below, not the whole field. All keys and expectations
  // are fixed constants (hand-pinned in
  // DEMO_DICT_MEMBER_EXTRACTION), so this segment is deterministic.
  const dictMemberExtraction = DEMO_DICT_MEMBER_EXTRACTION.map((c) => ({
    key: c.key,
    value: serializeDictionaryMemberValue(DEMO_DICT_MEMBER_VALUE, c.key),
  }));

  // A missing key fails closed: the extraction throws instead of
  // returning an empty or whole-field value. The throw is asserted
  // here, outside the printed extractions; only its (fixed) message
  // is printed, as one line.
  let dictMemberMissingKeyError = "";
  try {
    serializeDictionaryMemberValue(
      DEMO_DICT_MEMBER_VALUE,
      DEMO_DICT_MEMBER_MISSING_KEY,
    );
  } catch (err) {
    dictMemberMissingKeyError =
      err instanceof Error ? err.message : String(err);
  }

  // Serialization segment: the `@signature-params` line is not a
  // header the signer invents freely — it is the canonical
  // serialization of the covered-component inner list plus the
  // signature parameters in one fixed order, and the verifier
  // rebuilds exactly this string before comparing. All five cases
  // and their expectations are fixed constants (hand-pinned in
  // DEMO_SIG_PARAMS_SERIALIZATION), so this segment is
  // deterministic.
  const sigParamsSerialization = DEMO_SIG_PARAMS_SERIALIZATION.map((c) => ({
    name: c.name,
    serialized: serializeSignatureParams(c.componentIds, c.params),
  }));

  // PEM segment: JWK is not the only key-distribution format — a
  // gateway or ops tool usually ships keys as PEM files. The main
  // line's ed25519 key pair is exported as PEM (SPKI public /
  // PKCS#8 private, see src/keys.ts), imported back, and the
  // imported keys complete a fresh sign -> verify round-trip over
  // the same fixed request. Only the first line of each PEM — its
  // type header — is printed; the key bytes themselves are fresh
  // per run, like the main signature. Outside the printed lines,
  // the demo asserts both headers equal the hand-pinned
  // expectations (DEMO_PEM_PUBLIC_HEADER / DEMO_PEM_PRIVATE_HEADER)
  // and that the round-trip verification passed — a mismatch throws
  // instead of printing a misleading segment.
  const pemPublic = exportPublicKeyPem(publicKey);
  const pemPrivate = exportPrivateKeyPem(privateKey);
  const pemPublicHeader = pemPublic.split("\n")[0] ?? "";
  const pemPrivateHeader = pemPrivate.split("\n")[0] ?? "";
  if (
    pemPublicHeader !== DEMO_PEM_PUBLIC_HEADER ||
    pemPrivateHeader !== DEMO_PEM_PRIVATE_HEADER
  ) {
    throw new Error(
      `demo fixture broken: PEM headers "${pemPublicHeader}" / "${pemPrivateHeader}" ` +
        `do not match the pinned "${DEMO_PEM_PUBLIC_HEADER}" / "${DEMO_PEM_PRIVATE_HEADER}"`,
    );
  }
  const pemSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_KEY_ID,
      alg: "ed25519",
      key: importPrivateKey(pemPrivate),
      created: DEMO_CREATED,
      nonce: DEMO_PEM_NONCE,
    },
  );
  const pemVerification = verifyRequest(pemSigned, {
    key: importPublicKey(pemPublic),
    now: DEMO_CREATED + 60,
  });
  if (!pemVerification.ok) {
    throw new Error(
      `demo fixture broken: PEM round-trip verification failed (code ${pemVerification.code}: ${pemVerification.reason})`,
    );
  }

  // Throwing-verification segment: callers that prefer exceptions
  // over result-branching use `verifyRequestOrThrow`, the throwing
  // twin of `verifyRequest`. On the main signed request it returns
  // the verified identity directly; on the same request with the
  // body tampered by the main line's one byte it throws a
  // `VerifyError` carrying the stable code. Outside the printed
  // lines the demo asserts the returned identity and the thrown
  // code both equal the hand-pinned expectations (label `sig1`,
  // `DEMO_KEY_ID`, `ed25519`, `DEMO_NONCE`, and
  // `DEMO_THROW_TAMPERED_CODE`) and that the caught error passes
  // the `isVerifyError` guard — a mismatch throws instead of
  // printing a misleading segment.
  const throwVerification = verifyRequestOrThrow(signed, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  if (
    throwVerification.label !== "sig1" ||
    throwVerification.keyId !== DEMO_KEY_ID ||
    throwVerification.alg !== "ed25519" ||
    throwVerification.nonce !== DEMO_NONCE ||
    throwVerification.tag !== undefined
  ) {
    throw new Error(
      `demo fixture broken: verifyRequestOrThrow identity ${JSON.stringify(throwVerification)} ` +
        `does not match the pinned label "sig1", keyid "${DEMO_KEY_ID}", alg "ed25519", nonce "${DEMO_NONCE}"`,
    );
  }
  let throwTamperedError: VerifyError | null = null;
  let throwTamperedIsVerifyError = false;
  try {
    verifyRequestOrThrow(
      { ...signed, body: DEMO_TAMPERED_BODY },
      { key: publicKey, now: DEMO_CREATED + 60 },
    );
  } catch (err) {
    throwTamperedIsVerifyError = isVerifyError(err);
    if (throwTamperedIsVerifyError && isVerifyError(err)) {
      throwTamperedError = err;
    }
  }
  if (
    !throwTamperedIsVerifyError ||
    throwTamperedError === null ||
    throwTamperedError.code !== DEMO_THROW_TAMPERED_CODE ||
    throwTamperedError.label !== "sig1" ||
    throwTamperedError.keyId !== DEMO_KEY_ID ||
    throwTamperedError.alg !== "ed25519" ||
    throwTamperedError.nonce !== DEMO_NONCE
  ) {
    throw new Error(
      `demo fixture broken: verifyRequestOrThrow on the tampered-body request ` +
        `did not throw a VerifyError with the pinned code "${DEMO_THROW_TAMPERED_CODE}" ` +
        `(isVerifyError=${throwTamperedIsVerifyError}, code=${throwTamperedError?.code})`,
    );
  }

  // Nonce-generation segment: every segment above signs with a
  // hand-written nonce constant, but production signers must not
  // hand-roll nonces — a predictable nonce makes the replay cache
  // above meaningless, because an attacker can pre-claim the values
  // they intend to replay. `generateNonce()` is the standard entry
  // point: it draws from the CSPRNG (`node:crypto` `randomBytes`)
  // and base64url-encodes the bytes, so the values are fresh on
  // every run (like the key pair) and only their shapes are pinned:
  // the default draw decodes to 16 bytes / 22 characters, the
  // explicit 32-byte draw to 32 bytes / 43 characters, both in the
  // base64url alphabet, and the two draws differ. Outside the
  // printed lines the demo asserts all of that, signs a fresh
  // request with the short nonce, and asserts the nonce the
  // verifier parses back out equals the signed one character for
  // character — a mismatch throws instead of printing a misleading
  // segment.
  const generatedNonce = generateNonce();
  const generatedLongNonce = generateNonce(DEMO_GENERATED_LONG_NONCE_BYTES);
  const BASE64URL = /^[A-Za-z0-9_-]+$/;
  if (
    generatedNonce.length !== DEMO_GENERATED_NONCE_LENGTH ||
    !BASE64URL.test(generatedNonce) ||
    Buffer.from(generatedNonce, "base64url").length !==
      DEMO_GENERATED_NONCE_BYTES ||
    generatedLongNonce.length !== DEMO_GENERATED_LONG_NONCE_LENGTH ||
    !BASE64URL.test(generatedLongNonce) ||
    Buffer.from(generatedLongNonce, "base64url").length !==
      DEMO_GENERATED_LONG_NONCE_BYTES ||
    generatedNonce === generatedLongNonce
  ) {
    throw new Error(
      `demo fixture broken: generateNonce gave "${generatedNonce}" (${generatedNonce.length} chars) / ` +
        `"${generatedLongNonce}" (${generatedLongNonce.length} chars) instead of distinct base64url ` +
        `nonces of ${DEMO_GENERATED_NONCE_LENGTH} chars / ${DEMO_GENERATED_NONCE_BYTES} bytes and ` +
        `${DEMO_GENERATED_LONG_NONCE_LENGTH} chars / ${DEMO_GENERATED_LONG_NONCE_BYTES} bytes`,
    );
  }
  const generatedNonceSigned = signRequest(
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
      nonce: generatedNonce,
    },
  );
  const generatedNonceVerification = verifyRequest(generatedNonceSigned, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  if (
    !generatedNonceVerification.ok ||
    generatedNonceVerification.nonce !== generatedNonce
  ) {
    throw new Error(
      `demo fixture broken: verification with the generated nonce ` +
        (generatedNonceVerification.ok
          ? `parsed back nonce "${generatedNonceVerification.nonce}" instead of the signed "${generatedNonce}"`
          : `failed (code ${generatedNonceVerification.code}: ${generatedNonceVerification.reason})`),
    );
  }

  // JWK import segment: the thumbprint and JWKS segments above
  // only ever *export* the demo public key as a JWK. A gateway on
  // the receiving end performs the inverse: it takes the JWK as
  // JSON off the wire and imports it before verifying anything.
  // The exported JWK is carried through a JSON stringify/parse
  // round-trip (the exact wire shape `test/jwk.test.ts` pins),
  // imported with `importPublicKeyJwk`, and the main signed
  // request is verified with the imported key. Outside the
  // printed lines the demo asserts the imported-key verification
  // passed, that a detached copy with the first character of its
  // `x` coordinate flipped imports as a different well-formed key
  // but fails verification with the hand-pinned
  // DEMO_JWK_TAMPERED_CODE, and that the original exported JWK is
  // untouched by the tamper copy — a mismatch throws instead of
  // printing a misleading segment.
  const exportedJwk = exportPublicKeyJwk(publicKey);
  const wireJwk: unknown = JSON.parse(JSON.stringify(exportedJwk));
  const jwkImportedVerification = verifyRequest(signed, {
    key: importPublicKeyJwk(wireJwk),
    now: DEMO_CREATED + 60,
  });
  if (!jwkImportedVerification.ok) {
    throw new Error(
      `demo fixture broken: JWK imported-key verification failed (code ${jwkImportedVerification.code}: ${jwkImportedVerification.reason})`,
    );
  }
  const tamperedJwk: Ed25519PublicJwk = {
    ...exportedJwk,
    x:
      (exportedJwk.x[0] === "A" ? "B" : "A") + exportedJwk.x.slice(1),
  };
  const jwkTamperedVerification = verifyRequest(signed, {
    key: importPublicKeyJwk(tamperedJwk),
    now: DEMO_CREATED + 60,
  });
  if (
    jwkTamperedVerification.ok ||
    jwkTamperedVerification.code !== DEMO_JWK_TAMPERED_CODE ||
    tamperedJwk.x === exportedJwk.x ||
    exportedJwk.x.length !== 43
  ) {
    throw new Error(
      `demo fixture broken: tampered-JWK verification ` +
        (jwkTamperedVerification.ok
          ? `unexpectedly passed`
          : `gave code ${jwkTamperedVerification.code} instead of the pinned "${DEMO_JWK_TAMPERED_CODE}"`),
    );
  }

  // Key-resolver memoization segment: the JWKS segment above
  // resolves through a store, but a verifier handing
  // `verifyRequest` a plain `keyResolver` pays one resolver call
  // per request — in front of a remote keystore, one lookup per
  // signature at gateway rates. `memoizeKeyResolver` is the
  // library's cache primitive for exactly that shape: successful
  // resolutions are cached per keyid for a TTL. The demo wraps a
  // counting resolver over a fixed two-key store (the main demo
  // key plus a fresh second keypair), with the TTL at the library
  // default and the wrapper clock pinned to the fixed verify
  // instant so nothing expires mid-segment. The main request
  // verifies twice: the first verification misses and resolves,
  // the second is served from the cache. A request signed under
  // the second keyid then misses once and resolves. Outside the
  // printed lines the demo asserts all three verifications
  // passed and both call counts equal the hand-pinned
  // expectations (DEMO_MEMOIZED_CALLS_AFTER_REPEAT /
  // DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY) — a mismatch throws
  // instead of printing a misleading segment.
  const memoizedSecondKeyPair = generateEd25519KeyPair();
  const memoizedStore = new Map([
    [DEMO_KEY_ID, publicKey],
    [DEMO_MEMOIZED_SECOND_KEY_ID, memoizedSecondKeyPair.publicKey],
  ]);
  let memoizedResolverCalls = 0;
  const memoizedResolver = memoizeKeyResolver(
    (keyId: string) => {
      memoizedResolverCalls++;
      return memoizedStore.get(keyId);
    },
    { ttlSec: DEMO_MEMOIZED_TTL_SEC, now: () => DEMO_CREATED + 60 },
  );
  const memoizedFirstVerification = verifyRequest(signed, {
    keyResolver: memoizedResolver,
    now: DEMO_CREATED + 60,
  });
  const memoizedRepeatVerification = verifyRequest(signed, {
    keyResolver: memoizedResolver,
    now: DEMO_CREATED + 60,
  });
  const memoizedResolverCallsAfterRepeat = memoizedResolverCalls;
  const memoizedSecondSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_MEMOIZED_SECOND_KEY_ID,
      alg: "ed25519",
      key: memoizedSecondKeyPair.privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_MEMOIZED_NONCE,
    },
  );
  const memoizedSecondKeyVerification = verifyRequest(memoizedSecondSigned, {
    keyResolver: memoizedResolver,
    now: DEMO_CREATED + 60,
  });
  const memoizedResolverCallsAfterSecondKey = memoizedResolverCalls;
  if (
    !memoizedFirstVerification.ok ||
    !memoizedRepeatVerification.ok ||
    !memoizedSecondKeyVerification.ok ||
    memoizedSecondKeyVerification.keyId !== DEMO_MEMOIZED_SECOND_KEY_ID ||
    memoizedResolverCallsAfterRepeat !== DEMO_MEMOIZED_CALLS_AFTER_REPEAT ||
    memoizedResolverCallsAfterSecondKey !==
      DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY
  ) {
    throw new Error(
      `demo fixture broken: memoized verifications ` +
        `${memoizedFirstVerification.ok}/${memoizedRepeatVerification.ok}/${memoizedSecondKeyVerification.ok} ` +
        `with resolver calls ${memoizedResolverCallsAfterRepeat} after the repeat and ` +
        `${memoizedResolverCallsAfterSecondKey} after the second keyid, instead of the pinned ` +
        `${DEMO_MEMOIZED_CALLS_AFTER_REPEAT} / ${DEMO_MEMOIZED_CALLS_AFTER_SECOND_KEY}`,
    );
  }

  // HMAC secret-length guard segment: the gateway line signs
  // with hmac-sha256, and every HMAC secret the sign and verify
  // paths consume passes the per-algorithm length floor in
  // `assertHmacSecretLength` — hmac-sha256 needs at least 32
  // bytes, hmac-sha512 at least 64 (RFC 2104 §3). The demo runs
  // fixed secrets (fixed 0xab fill; only the length matters)
  // through the guard directly: lengths exactly on each floor
  // pass, lengths one byte below are rejected. Outside the
  // printed lines the demo asserts the accepted group all
  // passed and both rejection messages equal the hand-pinned
  // DEMO_HMAC_GUARD_ERRORS — a mismatch throws instead of
  // printing a misleading segment. No key bytes are printed.
  const hmacGuardAccepted: Array<{
    alg: "hmac-sha256" | "hmac-sha512";
    bytes: number;
  }> = [];
  for (const entry of DEMO_HMAC_GUARD_ACCEPTED) {
    assertHmacSecretLength(
      createSecretKey(Buffer.alloc(entry.bytes, 0xab)),
      entry.alg,
    );
    hmacGuardAccepted.push({ alg: entry.alg, bytes: entry.bytes });
  }
  const hmacGuardRejections: Array<{
    alg: "hmac-sha256" | "hmac-sha512";
    bytes: number;
    error: string;
  }> = [];
  for (const entry of DEMO_HMAC_GUARD_REJECTED) {
    let error = "";
    try {
      assertHmacSecretLength(
        createSecretKey(Buffer.alloc(entry.bytes, 0xab)),
        entry.alg,
      );
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    hmacGuardRejections.push({ alg: entry.alg, bytes: entry.bytes, error });
  }
  if (
    hmacGuardAccepted.length !== DEMO_HMAC_GUARD_ACCEPTED.length ||
    hmacGuardRejections.some(
      (r, i) => r.error !== DEMO_HMAC_GUARD_ERRORS[i],
    )
  ) {
    throw new Error(
      `demo fixture broken: HMAC guard rejections ` +
        `${JSON.stringify(hmacGuardRejections.map((r) => r.error))} ` +
        `instead of the pinned ${JSON.stringify(DEMO_HMAC_GUARD_ERRORS)}`,
    );
  }

  // RSA modulus-length guard segment: the `rsa-v1_5-sha256`
  // sign and verify paths pass every RSA key through
  // `assertRsaModulusLength` — the key must be RSA and its
  // modulus must reach MIN_RSA_MODULUS_BITS (2048). The demo
  // runs fixed-shape keys through the guard directly under
  // DEMO_RSA_GUARD_CONTEXT: the at-floor RSA public key
  // passes, the 1024-bit RSA public key and the main line's
  // ed25519 public key (not RSA at all) are rejected.
  // Outside the printed lines the demo asserts the accepted
  // case passed and both rejection messages equal the
  // hand-pinned DEMO_RSA_GUARD_ERRORS — a mismatch throws
  // instead of printing a misleading segment. No key bytes
  // are printed.
  const rsaGuardKeyByLabel: ReadonlyMap<string, KeyObject> = new Map([
    ["rsa-2048 public", rsaGuardKeys().strongPublic],
    ["rsa-1024 public", rsaGuardKeys().weakPublic],
    ["ed25519 public", publicKey],
  ]);
  const rsaGuardAccepted: Array<{ label: string; bits: number }> = [];
  for (const entry of DEMO_RSA_GUARD_ACCEPTED) {
    assertRsaModulusLength(
      rsaGuardKeyByLabel.get(entry.label)!,
      DEMO_RSA_GUARD_CONTEXT,
    );
    rsaGuardAccepted.push({ label: entry.label, bits: entry.bits });
  }
  const rsaGuardRejections: Array<{
    label: string;
    bits: number | null;
    error: string;
  }> = [];
  for (const entry of DEMO_RSA_GUARD_REJECTED) {
    let error = "";
    try {
      assertRsaModulusLength(
        rsaGuardKeyByLabel.get(entry.label)!,
        DEMO_RSA_GUARD_CONTEXT,
      );
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    rsaGuardRejections.push({
      label: entry.label,
      bits: entry.bits,
      error,
    });
  }
  if (
    rsaGuardAccepted.length !== DEMO_RSA_GUARD_ACCEPTED.length ||
    rsaGuardRejections.some((r, i) => r.error !== DEMO_RSA_GUARD_ERRORS[i])
  ) {
    throw new Error(
      `demo fixture broken: RSA guard rejections ` +
        `${JSON.stringify(rsaGuardRejections.map((r) => r.error))} ` +
        `instead of the pinned ${JSON.stringify(DEMO_RSA_GUARD_ERRORS)}`,
    );
  }

  const lines: string[] = [
    "RFC 9421 signing demo (ed25519)",
    `Request: POST https://api.example.com/v1/payments`,
    `Body: ${DEMO_BODY}`,
    `Content-Digest: ${signed.headers["content-digest"]}`,
    `Signature-Input: ${signed.headers["signature-input"]}`,
    `Signature: ${signed.headers["signature"]}`,
    verification.ok
      ? `Verification: OK (label ${verification.label}, keyid="${verification.keyId}", alg="${verification.alg}", nonce="${verification.nonce}")`
      : `Verification: FAILED (code ${verification.code}: ${verification.reason})`,
    "",
    "Signature base (RFC 9421 §2.5): the exact string signed for the main sig1 signature, rebuilt with buildSignatureBase",
    ...signatureBase.split("\n"),
    `Each base line above is one covered component in order (${DEMO_COVERED_COMPONENTS.map((c) => `"${c}"`).join(", ")}); the final "@signature-params" line binds that covered set to the signature parameters (created, keyid, alg, nonce)`,
    "",
    `Tampered body: ${DEMO_TAMPERED_BODY} (one byte changed: amount 100 -> 101)`,
    tamperedVerification.ok
      ? "Verification after tampering: OK (unexpected — tampering was not detected)"
      : `Verification after tampering: FAILED (code ${tamperedVerification.code}: ${tamperedVerification.reason})`,
    "",
    "Multi-party signing: gateway adds a second signature with addSignature (hmac-sha256)",
    `Dual Signature-Input: ${dualSigned.headers["signature-input"]}`,
    `Dual Signature: ${dualSigned.headers["signature"]}`,
    ...dualVerification.map((r) => formatLabelResult("Dual verification", r)),
    "",
    "Signature labels: listSignatureLabels enumerates the labels in the dual-signed request's Signature-Input in wire order — enumerate first, then verify each label",
    `Signature labels in the dual-signed request: ${signatureLabels.join(", ")} (${signatureLabels.length} labels)`,
    "",
    `Tampered content-type: ${DEMO_TAMPERED_CONTENT_TYPE} (only the gateway signature covers "content-type")`,
    ...contentTypeTamperedVerification.map((r) =>
      formatLabelResult("After content-type tampering", r),
    ),
    "",
    `Replay protection: same request verified twice against a ReplayCache (capacity ${DEMO_REPLAY_CACHE_MAX_ENTRIES}, TTL ${DEMO_REPLAY_CACHE_TTL_SEC}s)`,
    replayFirstVerification.ok
      ? `Replay check, first presentation of nonce "${DEMO_NONCE}": OK`
      : `Replay check, first presentation of nonce "${DEMO_NONCE}": FAILED (code ${replayFirstVerification.code}: ${replayFirstVerification.reason})`,
    replaySecondVerification.ok
      ? "Replay check, second presentation of the same request: OK (unexpected — replay was not detected)"
      : `Replay check, second presentation of the same request: FAILED (code ${replaySecondVerification.code}: ${replaySecondVerification.reason})`,
    replayOtherNonceVerification.ok
      ? `Replay check, new request with nonce "${DEMO_OTHER_NONCE}": OK (a fresh nonce is not a replay)`
      : `Replay check, new request with nonce "${DEMO_OTHER_NONCE}": FAILED (code ${replayOtherNonceVerification.code}: ${replayOtherNonceVerification.reason})`,
    "",
    `Content-Digest algorithms on the same body: main line ${signed.headers["content-digest"]} vs sha-256 peer line ${sha256Signed.headers["content-digest"]}`,
    `sha-256 Content-Digest: ${sha256Signed.headers["content-digest"]}`,
    sha256Verification.ok
      ? `sha-256 verification: OK (label ${sha256Verification.label}, keyid="${sha256Verification.keyId}", alg="${sha256Verification.alg}")`
      : `sha-256 verification: FAILED (code ${sha256Verification.code}: ${sha256Verification.reason})`,
    sha256TamperedVerification.ok
      ? "sha-256 verification after tampering: OK (unexpected — tampering was not detected)"
      : `sha-256 verification after tampering: FAILED (code ${sha256TamperedVerification.code}: ${sha256TamperedVerification.reason})`,
    "",
    "Content-Digest algorithm identification: contentDigestAlgOf reads the algorithm off an existing Content-Digest header — the receiver's first step before deciding whether to verify",
    `contentDigestAlgOf on the main line's Content-Digest: ${contentDigestAlg}`,
    `contentDigestAlgOf on the sha-256 peer line's Content-Digest: ${sha256ContentDigestAlg}`,
    `contentDigestAlgOf on the unrecognized value "${DEMO_UNRECOGNIZED_DIGEST_VALUE}": ${unrecognizedContentDigestAlg} (an algorithm this library cannot emit — a caller must reject it)`,
    "",
    "Inbound normalization: mock Node IncomingMessage normalized with fromNodeRequest (mixed-case headers, multi-value x-trace-hops, host with port)",
    `Inbound normalized: ${inboundNormalized.method} ${inboundNormalized.url} (host "${inboundNormalized.headers["host"]}", x-trace-hops "${inboundNormalized.headers["x-trace-hops"]}", content-type "${inboundNormalized.headers["content-type"]}")`,
    inboundVerification.ok
      ? `Inbound verification: OK (label ${inboundVerification.label}, keyid="${inboundVerification.keyId}", alg="${inboundVerification.alg}")`
      : `Inbound verification: FAILED (code ${inboundVerification.code}: ${inboundVerification.reason})`,
    inboundWrongSchemeVerification.ok
      ? `Inbound verification with wrong scheme "${DEMO_INBOUND_WRONG_SCHEME}": OK (unexpected — scheme mismatch was not detected)`
      : `Inbound verification with wrong scheme "${DEMO_INBOUND_WRONG_SCHEME}": FAILED (code ${inboundWrongSchemeVerification.code}: ${inboundWrongSchemeVerification.reason})`,
    "",
    `JWKS key resolution: JwksKeyStore restored offline from a v1 snapshot (endpoint ${DEMO_JWKS_URL}, fetchedAtSec=${DEMO_JWKS_FETCHED_AT_SEC}, ${jwksStore.size} key)`,
    jwksVerification.ok
      ? `JWKS verification for keyid "${DEMO_KEY_ID}": OK (label ${jwksVerification.label}, keyid="${jwksVerification.keyId}", alg="${jwksVerification.alg}")`
      : `JWKS verification for keyid "${DEMO_KEY_ID}": FAILED (code ${jwksVerification.code}: ${jwksVerification.reason})`,
    jwksUnknownKeyVerification.ok
      ? `JWKS verification for unknown keyid "${DEMO_UNKNOWN_KEY_ID}": OK (unexpected — unknown keyid was not rejected)`
      : `JWKS verification for unknown keyid "${DEMO_UNKNOWN_KEY_ID}": FAILED (code ${jwksUnknownKeyVerification.code}: ${jwksUnknownKeyVerification.reason})`,
    "",
    `JWK thumbprint: RFC 7638 thumbprint of the demo ed25519 public JWK is "${thumbprint}"`,
    thumbprintVerification.ok
      ? `Thumbprint-as-keyid verification: OK (label ${thumbprintVerification.label}, keyid="${thumbprintVerification.keyId}", alg="${thumbprintVerification.alg}")`
      : `Thumbprint-as-keyid verification: FAILED (code ${thumbprintVerification.code}: ${thumbprintVerification.reason})`,
    "",
    "Structured-field canonicalization (;sf): a verifier compares the parsed value re-serialized strictly, not the wire bytes",
    ...sfCanonicalization.map(
      (c) => `Canonicalize ${c.name}: ${c.input} -> ${c.canonical}`,
    ),
    "",
    "Dictionary-member extraction (;key): a ;key covered component contributes only the named member, re-serialized without its Dictionary key",
    `Dictionary: ${DEMO_DICT_MEMBER_VALUE}`,
    ...dictMemberExtraction.map(
      (c) => `Extract member ${c.key}: ${c.value}`,
    ),
    `Extract member ${DEMO_DICT_MEMBER_MISSING_KEY}: FAILED (${dictMemberMissingKeyError})`,
    "",
    "Signature-params serialization: the covered-component inner list plus its parameters in fixed order (created, expires, keyid, alg, nonce, tag), strings quoted and escaped — the \"@signature-params\" value a verifier rebuilds byte-for-byte",
    ...sigParamsSerialization.map(
      (c) => `Serialize ${c.name}: ${c.serialized}`,
    ),
    "",
    "PEM key round-trip: the main ed25519 key pair exported as PEM, imported back, and the imported keys sign and verify a fresh request",
    `PEM public key header: ${pemPublicHeader}`,
    `PEM private key header: ${pemPrivateHeader}`,
    pemVerification.ok
      ? `PEM round-trip verification: OK (label ${pemVerification.label}, keyid="${pemVerification.keyId}", alg="${pemVerification.alg}")`
      : `PEM round-trip verification: FAILED (code ${pemVerification.code}: ${pemVerification.reason})`,
    "",
    "Throwing verification: verifyRequestOrThrow returns the verified identity on success and throws a VerifyError carrying a stable code on failure",
    `verifyRequestOrThrow on the main request: OK (label ${throwVerification.label}, keyid="${throwVerification.keyId}", alg="${throwVerification.alg}", nonce="${throwVerification.nonce}")`,
    `verifyRequestOrThrow on the tampered-body request: FAILED (threw VerifyError, code ${throwTamperedError.code}: ${throwTamperedError.message})`,
    "",
    "Nonce generation: generateNonce draws a fresh nonce from the CSPRNG and base64url-encodes it — the standard entry point for replay-protection nonces, instead of hand-writing a nonce string",
    `generateNonce(): "${generatedNonce}" (${generatedNonce.length} chars, base64url, decodes to ${DEMO_GENERATED_NONCE_BYTES} bytes)`,
    `generateNonce(${DEMO_GENERATED_LONG_NONCE_BYTES}): "${generatedLongNonce}" (${generatedLongNonce.length} chars, base64url, decodes to ${DEMO_GENERATED_LONG_NONCE_BYTES} bytes)`,
    generatedNonceVerification.ok
      ? `Verification with the generated nonce: OK (label ${generatedNonceVerification.label}, keyid="${generatedNonceVerification.keyId}", alg="${generatedNonceVerification.alg}", nonce="${generatedNonceVerification.nonce}")`
      : `Verification with the generated nonce: FAILED (code ${generatedNonceVerification.code}: ${generatedNonceVerification.reason})`,
    "",
    "JWK public-key import: exportPublicKeyJwk ships the main ed25519 public key as a JWK, a JSON wire round-trip carries it, and importPublicKeyJwk reads it back — the gateway side of JWK key distribution",
    `Exported JWK: kty="${exportedJwk.kty}", crv="${exportedJwk.crv}", x is ${exportedJwk.x.length} base64url chars (the key itself is fresh per run; only its shape is printed)`,
    jwkImportedVerification.ok
      ? `Verification with the imported JWK key: OK (label ${jwkImportedVerification.label}, keyid="${jwkImportedVerification.keyId}", alg="${jwkImportedVerification.alg}")`
      : `Verification with the imported JWK key: FAILED (code ${jwkImportedVerification.code}: ${jwkImportedVerification.reason})`,
    jwkTamperedVerification.ok
      ? "Verification with a tampered JWK (first x character flipped): OK (unexpected — the wrong key was not detected)"
      : `Verification with a tampered JWK (first x character flipped): FAILED (code ${jwkTamperedVerification.code}: ${jwkTamperedVerification.reason})`,
    "",
    "Key-resolver memoization: memoizeKeyResolver caches each keyid's resolved key for a TTL, so a gateway verifying at high rate pays the keystore lookup once per keyid instead of once per request",
    memoizedFirstVerification.ok
      ? `Memoized verification, first verification of keyid "${DEMO_KEY_ID}": OK (label ${memoizedFirstVerification.label}, keyid="${memoizedFirstVerification.keyId}", alg="${memoizedFirstVerification.alg}")`
      : `Memoized verification, first verification of keyid "${DEMO_KEY_ID}": FAILED (code ${memoizedFirstVerification.code}: ${memoizedFirstVerification.reason})`,
    `Underlying resolver calls after verifying keyid "${DEMO_KEY_ID}" twice: ${memoizedResolverCallsAfterRepeat} (the second verification was served from the cache)`,
    memoizedSecondKeyVerification.ok
      ? `Memoized verification for keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}": OK (label ${memoizedSecondKeyVerification.label}, keyid="${memoizedSecondKeyVerification.keyId}", alg="${memoizedSecondKeyVerification.alg}")`
      : `Memoized verification for keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}": FAILED (code ${memoizedSecondKeyVerification.code}: ${memoizedSecondKeyVerification.reason})`,
    `Underlying resolver calls after verifying keyid "${DEMO_MEMOIZED_SECOND_KEY_ID}": ${memoizedResolverCallsAfterSecondKey} (a new keyid misses the cache and resolves once)`,
    "",
    "HMAC secret-length guard: assertHmacSecretLength enforces the per-algorithm secret floor before any MAC runs — hmac-sha256 secrets at least 32 bytes, hmac-sha512 secrets at least 64 bytes (RFC 2104: the key SHOULD be at least as long as the hash output)",
    ...hmacGuardAccepted.map(
      (a) =>
        `assertHmacSecretLength for ${a.alg} with a ${a.bytes}-byte secret: OK (meets the ${a.alg === "hmac-sha512" ? 64 : 32}-byte floor)`,
    ),
    ...hmacGuardRejections.map(
      (r) =>
        `assertHmacSecretLength for ${r.alg} with a ${r.bytes}-byte secret: FAILED (${r.error})`,
    ),
    "",
    "RSA modulus-length guard: assertRsaModulusLength enforces the RSA modulus floor before any RSA operation runs — RSA keys at least 2048 bits, and non-RSA keys are rejected as a caller configuration error",
    ...rsaGuardAccepted.map(
      (a) =>
        `assertRsaModulusLength for ${a.label} key (${a.bits} bits): OK (meets the 2048-bit floor)`,
    ),
    ...rsaGuardRejections.map(
      (r) =>
        `assertRsaModulusLength for ${r.label} key${r.bits === null ? "" : ` (${r.bits} bits)`}: FAILED (${r.error})`,
    ),
  ];

  return {
    signed,
    tamperedBody: DEMO_TAMPERED_BODY,
    verification,
    signatureBase,
    tamperedVerification,
    dualSigned,
    dualVerification,
    signatureLabels,
    contentTypeTamperedVerification,
    replayFirstVerification,
    replaySecondVerification,
    replayOtherNonceVerification,
    sha256Signed,
    sha256Verification,
    sha256TamperedVerification,
    contentDigestAlg,
    sha256ContentDigestAlg,
    unrecognizedContentDigestAlg,
    inboundSigned,
    inboundNormalized,
    inboundVerification,
    inboundWrongSchemeVerification,
    jwksSnapshot,
    jwksStoreSize: jwksStore.size,
    jwksVerification,
    jwksUnknownKeyVerification,
    thumbprint,
    thumbprintSigned,
    thumbprintVerification,
    sfCanonicalization,
    dictMemberExtraction,
    dictMemberMissingKeyError,
    sigParamsSerialization,
    pemPublicHeader,
    pemPrivateHeader,
    pemSigned,
    pemVerification,
    throwVerification,
    throwTamperedError,
    throwTamperedIsVerifyError,
    generatedNonce,
    generatedLongNonce,
    generatedNonceSigned,
    generatedNonceVerification,
    exportedJwk,
    jwkImportedVerification,
    jwkTamperedVerification,
    memoizedFirstVerification,
    memoizedRepeatVerification,
    memoizedSecondKeyVerification,
    memoizedResolverCallsAfterRepeat,
    memoizedResolverCallsAfterSecondKey,
    hmacGuardAccepted,
    hmacGuardRejections,
    rsaGuardAccepted,
    rsaGuardRejections,
    lines,
  };
}

function main(): void {
  console.log(runDemo().lines.join("\n"));
}

// Run only when executed directly (`node dist/src/demo.js`), not when
// imported by tests.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
