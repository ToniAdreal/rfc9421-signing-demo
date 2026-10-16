/**
 * Demo: sign one fixed request with a freshly generated ed25519 key,
 * print the wire headers, verify it, then tamper the body by one byte
 * and show the verifier rejecting it. After that single-signature
 * script, the demo runs the canonical multi-party payments flow: the
 * payment gateway appends a second signature with `addSignature`
 * (label `gateway`, hmac-sha256), the merged wire headers are printed,
 * and `verifyAllLabels` verifies each label independently. Finally the
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
 * `BODY_DIGEST_MISMATCH`. The next segment demonstrates inbound
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
 */

import { fileURLToPath } from "node:url";
import {
  addSignature,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  exportPublicKeyJwk,
  fromNodeRequest,
  generateEd25519KeyPair,
  jwkThumbprint,
  JwksKeyStore,
  ReplayCache,
  secretKey,
  serializeDictionaryMemberValue,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type IncomingRequestLike,
  type JwksKeyStoreSnapshot,
  type RequestLike,
  type SignedHttpRequest,
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
  lines: string[];
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
  ];

  return {
    signed,
    tamperedBody: DEMO_TAMPERED_BODY,
    verification,
    signatureBase,
    tamperedVerification,
    dualSigned,
    dualVerification,
    contentTypeTamperedVerification,
    replayFirstVerification,
    replaySecondVerification,
    replayOtherNonceVerification,
    sha256Signed,
    sha256Verification,
    sha256TamperedVerification,
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
