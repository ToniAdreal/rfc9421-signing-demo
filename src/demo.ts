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
 * The demo closes with an ECDSA P-256 signing segment: the
 * same fixed payment request is signed under
 * `ecdsa-p256-sha256` with a P-256 key pair from
 * `generateP256KeyPair` — the generator the library's ecdsa
 * tests and bench corpus use — its `Signature-Input` is
 * printed (algorithm and keyid, never key bytes), verification
 * is printed passing, and the same request with its body
 * tampered by one byte is printed rejected with
 * `BODY_DIGEST_MISMATCH`, because the covered
 * `content-digest` no longer matches the body. Outside the
 * printed lines the demo asserts the verified identity
 * (label, keyid, alg, nonce) and the tamper rejection code
 * equal the hand-pinned expectations below (the same
 * identity and code `test/ecdsaP256.test.ts` pins for its
 * round-trip and tampered-body cases). The P-256 key pair is
 * fresh on every run, like the main line's ed25519 pair, so
 * the signature bytes differ between runs while every
 * printed line is identical.
 * The demo closes with a Content-Digest algorithm guard
 * segment: the sha-512 / sha-256 lines above emit
 * Content-Digest headers, but the demo never showed the
 * write-side guard every digest algorithm passes through.
 * Fixed values are run through `assertContentDigestAlg`:
 * the two emittable algorithms (`sha-512`, `sha-256`) pass,
 * while a fixed rejected corpus — unknown algorithms
 * (`sha-1`, `md5`), the empty string, wrong-case spellings,
 * a trailing-space spelling, and the non-string values
 * `undefined` and `null` — is each rejected. Outside the
 * printed lines the demo asserts the accepted group all
 * passed and every rejection message equals the hand-pinned
 * expectations below (the same messages `src/digest.ts`
 * builds and the bench corpus / contentDigestAlg suite
 * pin). Each rejected value is printed only as a fixed
 * printable label, so the segment is byte-identical
 * between runs.
 * The demo closes with a ReplayCache snapshot persistence
 * segment: the replay segment above shows a `ReplayCache`
 * rejecting a second presentation inside one process, but
 * never showed the cache's one cross-restart ability. A
 * request signed with a fixed nonce verifies against a
 * `ReplayCache` on the demo's fixed clock, the cache is
 * exported with `exportSnapshot()` (only the entry count,
 * the fixed nonce and its first-seen instant are printed),
 * and a new cache is rebuilt with `ReplayCache.restore()` —
 * the "restart". The same request verified against the
 * restored cache is rejected with `NONCE_REPLAY`, and a
 * fresh-nonce request verifies against the restored cache
 * and is recorded only there. Outside the printed lines
 * the demo asserts the restored rejection code and the
 * exported snapshot equal the hand-pinned expectations
 * below (the same snapshot shape and code
 * `test/replaySnapshot.test.ts` pins for its round-trip
 * case) and that the original cache still holds only the
 * exported entry after the restored cache records the
 * fresh nonce. Every input is a fixed demo constant, so
 * the segment is byte-identical between runs.
 * The demo closes with an ECDSA P-384 signing segment: the
 * same fixed payment request is signed under
 * `ecdsa-p384-sha384` with a P-384 key pair from
 * `generateP384KeyPair` — the generator the library's ecdsa
 * tests and bench corpus use — its `Signature-Input` is
 * printed (algorithm and keyid, never key bytes),
 * verification is printed passing, and the same request
 * with its body tampered by one byte is printed rejected
 * with `BODY_DIGEST_MISMATCH`, because the covered
 * `content-digest` no longer matches the body. P-384 is
 * the wider of the two NIST curves the demo shows: its
 * signatures are the 96-octet raw r‖s form of RFC 9421
 * §3.3.5 (48 octets per limb), against the P-256 segment's
 * 64-octet form. Outside the printed lines the demo
 * asserts the verified identity (label, keyid, alg,
 * nonce) and the tamper rejection code equal the
 * hand-pinned expectations below (the same identity and
 * code `test/ecdsaP384.test.ts` pins for its round-trip
 * and tampered-body cases). The P-384 key pair is fresh
 * on every run, like the P-256 segment's pair, so the
 * signature bytes differ between runs while every printed
 * line is identical.
 * The demo closes with a Signature-Input parsing segment:
 * every earlier segment consumes the parsed signature
 * parameters only inside `verifyRequest`, but a receiver
 * debugging an inbound request looks at the parse layer
 * first. The main signed request's `signature-input` value
 * is read back raw with `getHeaderRaw` and printed
 * truncated to a pinned preview length, then parsed with
 * `parseSignatureInput` for the main label: the parsed
 * label, keyid, alg, created and covered components are
 * printed. Outside the printed lines the demo asserts the
 * raw value and every parsed field equal the hand-pinned
 * expectations below (the same parse shape the bench
 * parser fixture and the parser suites pin for their own
 * inputs). A detached copy of the raw value with its
 * closing parenthesis removed is parsed as well: the
 * parser throws the pinned `unterminated inner list`
 * error — the fail-closed shape a receiver sees on a
 * truncated header — and that rejection is printed.
 * Every input is a fixed demo constant, so the segment
 * is byte-identical between runs.
 * The demo closes with an ECDSA P-521 signing segment: the
 * same fixed payment request is signed under
 * `ecdsa-p521-sha512` with a P-521 key pair from
 * `generateP521KeyPair` — the generator the library's ecdsa
 * tests and bench corpus use — its `Signature-Input` is
 * printed (algorithm and keyid, never key bytes),
 * verification is printed passing, and the same request
 * with its body tampered by one byte is printed rejected
 * with `BODY_DIGEST_MISMATCH`, because the covered
 * `content-digest` no longer matches the body. P-521 is
 * the widest of the three NIST curves the demo shows: its
 * signatures are the 132-octet raw r‖s form of RFC 9421
 * §3.3.6 (66 octets per limb), completing the signature
 * length ladder against the P-256 segment's 64-octet form
 * and the P-384 segment's 96-octet form. Outside the
 * printed lines the demo asserts the verified identity
 * (label, keyid, alg, nonce) and the tamper rejection code
 * equal the hand-pinned expectations below (the same
 * identity and code `test/ecdsaP521.test.ts` pins for its
 * round-trip and tampered-body cases). The P-521 key pair
 * is fresh on every run, like the P-384 segment's pair, so
 * the signature bytes differ between runs while every
 * printed line is identical.
 * The demo closes with a component-resolution segment: the
 * signature-base segment above shows the finished base, but
 * not how one covered component becomes one base line. Each
 * of the main signed request's covered components is run
 * through `resolveComponent` — the resolver
 * `buildSignatureBase` applies per component — and printed
 * as component -> resolved value: the derived components
 * come from the request target (`@method` uppercased,
 * `@authority` lowercased, `@path` from the URL) and the
 * header field component from its normalized field value.
 * A detached illegal component id — `content-digest` with
 * the unsupported `;zz` parameter — is resolved as well:
 * `resolveComponent` throws the pinned unsupported-parameter
 * error (a plain `Error`, no failure code — resolution is a
 * caller configuration error, not a verification outcome),
 * and that rejection is printed. Outside the printed lines
 * the demo asserts every resolved value and the rejection
 * message equal the hand-pinned expectations below (the
 * same values the signature-base segment's printed lines
 * carry and the component suites pin for their own inputs).
 * Every input is a fixed demo constant, so the segment is
 * byte-identical between runs.
 * The demo closes with a multi-value header combination
 * segment: a fixed request carries one field twice, as a
 * padded two-element array — the shape a receiver gets when
 * a sender or an intermediary emitted the field on two
 * lines. The values are combined with `joinHeaderValues`
 * and the combination is printed; a request signed over
 * the repeated field verifies, and the same request with
 * the field replaced by the hand-pinned wrong combination
 * (the elements joined with a bare comma, the space after
 * the comma dropped) is rejected with
 * `SIGNATURE_MISMATCH`, because the verifier rebuilds a
 * different signature base from the wrongly joined value.
 * Outside the printed lines the demo asserts the
 * combination, the signer's emitted wire value and the
 * verified identity equal the hand-pinned expectations
 * below (the same combination and code
 * `test/multiValueHeaderWhitespace.test.ts` pins for its
 * own padded fixture). Every input is a fixed demo
 * constant, so the segment is byte-identical between runs.
 * The demo closes with a Signature field parsing segment:
 * the Signature-Input parsing segment above shows how a
 * receiver reads the parameters, but not how it gets the
 * signature bytes themselves. The main signed request's
 * `signature` value is parsed with `parseSignatureField`
 * for the main label: the extracted bytes' length and
 * hexadecimal prefix are printed (never the full
 * signature). Outside the printed lines the demo asserts
 * the extracted bytes equal, byte for byte, the bytes the
 * signer emitted — decoded independently from the header's
 * base64 member — and that their length equals the pinned
 * ed25519 signature length. The same field is then parsed
 * for a hand-pinned unknown label: the parser throws the
 * pinned `not present in Signature field` error — the
 * fail-closed shape a receiver sees on a label it did not
 * negotiate — and that rejection is printed. The main key
 * pair is fresh on every run, so the printed prefix differs
 * between runs while its shape (the pinned byte length and
 * prefix length) and the rejection line are identical.
 * The demo closes with an EC JWK key distribution segment:
 * the JWK import segment above covers only the ed25519
 * (`kty: "OKP"`) form, but the EC form (`kty: "EC"` + `crv`
 * + `x`/`y` coordinates) is the key shape gateways and
 * webhook verifiers distribute most often. One fresh key
 * pair is generated per NIST curve (P-256, P-384, P-521 —
 * generation itself is not printed), each public key is
 * exported with its curve's `exportPublicKeyJwkP*` helper
 * and only the JWK's `kty`/`crv` and `x` length are
 * printed, and each JWK is read back through a JSON wire
 * round-trip with the matching `importPublicKeyJwkP*`
 * helper and completes a sign -> verify round-trip under
 * its curve's RFC 9421 algorithm, printed passing.
 * Outside the printed lines the demo asserts every JWK's
 * shape (kty, crv and both coordinate lengths) and every
 * verified identity equal the hand-pinned expectations
 * below. A P-256 JWK fed to the P-384 importer is printed
 * rejected with the importer's pinned crv-mismatch error
 * — the curves' helpers are deliberately separate so a
 * key can never be silently re-interpreted on the wrong
 * curve. The key pairs are fresh on every run; only the
 * JWK shapes and the round-trip semantics are asserted,
 * so the segment's printed lines are identical between
 * runs.
 * The demo closes with an RSA JWK key distribution segment:
 * the JWK segments above cover the ed25519 (`kty: "OKP"`)
 * and EC (`kty: "EC"`) forms, but the RSA form
 * (`kty: "RSA"` + `n`/`e`) — the member shape JWKS
 * documents carry most often — was never shown on its
 * own. The segment's RSA key pair (generated once per
 * process, like the RSA guard segment's keys, so repeated
 * `runDemo()` calls do not repay RSA key generation) is
 * exported with `exportPublicKeyJwkRsa`: only the JWK's
 * `kty` and the `n`/`e` lengths are printed, never the
 * full modulus. The JWK is read back through a JSON wire
 * round-trip with `importPublicKeyJwkRsa` and completes
 * an `rsa-pss-sha512` sign -> verify round-trip, printed
 * passing. Outside the printed lines the demo asserts
 * the JWK's shape (kty, the 342-character `n` length of
 * a 2048-bit modulus, the `AQAB` exponent) and the
 * verified identity equal the hand-pinned expectations
 * below. The EC segment's P-256 JWK fed to the RSA
 * importer is printed rejected with the importer's
 * pinned kty-mismatch error — the per-shape helpers are
 * deliberately separate so a key can never be silently
 * re-interpreted under the wrong key type. Only the JWK
 * shape and the round-trip semantics are asserted, so
 * the segment's printed lines are identical between
 * runs.
 * The demo closes with a JWKS refresh and rotation segment:
 * the restored-snapshot JWKS segment above never fetches,
 * so it cannot show how a verifier picks up a key rotation.
 * A `JwksKeyStore` over a counting fake JWKS fetch (zero
 * network — the fetch is a scripted function, never the
 * real endpoint) and an injected clock pinned to the
 * demo's fixed instants is driven through
 * `refreshIfStale()`: the first call loads the pre-rotation
 * key (one fetch) and a request signed under the old keyid
 * verifies through the store; a second call inside the TTL
 * returns `false` and fetches nothing; once the injected
 * clock is past the TTL and the fake endpoint serves only
 * the rotated key, a third call returns `true` (a second
 * fetch), the rotated keyid resolves and a request signed
 * under it verifies, and the retired keyid is rejected
 * with `KEY_RESOLUTION_FAILED`. Outside the printed lines
 * the demo asserts every return value, fetch count and
 * verified identity equal the hand-pinned expectations
 * below. Because `refreshIfStale()` is asynchronous,
 * `runDemo()` is `async` — the one deliberate change in
 * its shape when this segment landed. Only keyids, counts
 * and outcomes are printed, never key bytes, so the
 * segment's printed lines are identical between runs.
 * The demo closes with a normalized header lookup segment:
 * a fixed header record — one field stored under a
 * mixed-case key as a padded two-element array, one single
 * string field — is read with `getHeader`, the normalized
 * lookup the verifier itself uses: the lookup name's case
 * does not need to match the stored key, a multi-value
 * field comes back trimmed and joined with ", " (via
 * `joinHeaderValues`), a single string value comes back
 * exactly as stored, and a missing field comes back
 * `undefined`. The same record is read with `getHeaderRaw`
 * and the two results are printed side by side: the raw
 * read preserves every element's padding — exactly the
 * difference that makes the two reads easy to confuse, and
 * exactly why only the raw read may feed a `;bs` component.
 * Outside the printed lines the demo asserts every lookup
 * result equals the hand-pinned expectations below. Every
 * input is a fixed constant, so the segment is
 * byte-identical between runs.
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
  assertContentDigestAlg,
  assertHmacSecretLength,
  assertRsaModulusLength,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  contentDigestAlgOf,
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  exportPublicKeyPem,
  fromNodeRequest,
  generateEd25519KeyPair,
  generateNonce,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  getHeader,
  getHeaderRaw,
  importPrivateKey,
  importPublicKey,
  importPublicKeyJwk,
  importPublicKeyJwkP256,
  importPublicKeyJwkP384,
  importPublicKeyJwkP521,
  importPublicKeyJwkRsa,
  isVerifyError,
  jwkThumbprint,
  JwksKeyStore,
  joinHeaderValues,
  listSignatureLabels,
  memoizeKeyResolver,
  parseSignatureField,
  parseSignatureInput,
  ReplayCache,
  resolveComponent,
  secretKey,
  serializeDictionaryMemberValue,
  serializeSignatureParams,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type ContentDigestAlg,
  type Ed25519PublicJwk,
  type P256PublicJwk,
  type P384PublicJwk,
  type P521PublicJwk,
  type RsaPublicJwk,
  type IncomingRequestLike,
  type JwksKeyStoreSnapshot,
  type ParsedSignatureInput,
  type ReplayCacheSnapshot,
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

/** Key id of the closing ECDSA P-256 segment's signed request. */
export const DEMO_P256_KEY_ID = "demo-p256-key-1";
/** Nonce of the closing ECDSA P-256 segment's signed request. */
export const DEMO_P256_NONCE = "demo-nonce-p256-001";
/**
 * Hand-pinned verified identity of the closing ECDSA P-256
 * segment: the segment passes no label, so its signature
 * carries the library default `sig1`, and verification must
 * report the segment's own keyid, the `ecdsa-p256-sha256`
 * algorithm and its nonce — the same identity shape
 * `test/ecdsaP256.test.ts` pins for its round-trip case
 * (label default, keyid, alg). The expectations are written
 * out here, never derived from the verification the demo is
 * checking.
 */
export const DEMO_P256_LABEL = "sig1";
export const DEMO_P256_ALG = "ecdsa-p256-sha256";
/**
 * Hand-pinned failure code of the closing ECDSA P-256
 * segment's tampered request: changing the body by the same
 * one byte as the main line (amount 100 -> 101) leaves the
 * covered `content-digest` stale, so verification must fail
 * with `BODY_DIGEST_MISMATCH` — the same code
 * `test/ecdsaP256.test.ts` pins for its tampered-body case.
 * The expectation is written out here, never derived from
 * the verification the demo is checking.
 */
export const DEMO_P256_TAMPERED_CODE: VerifyFailureCode =
  "BODY_DIGEST_MISMATCH";

/**
 * Fixed Content-Digest algorithm guard corpus of the closing
 * guard segment: the accepted cases are the two algorithms
 * this library can emit (`sha-512`, the default, and
 * `sha-256`); the rejected cases are unknown algorithms
 * (`sha-1`, `md5`), the empty string, wrong-case spellings
 * (`SHA-512`, `Sha-256` — the comparison is exact and
 * case-sensitive), a trailing-space spelling (`sha-512 `,
 * no trimming), and the non-string values `undefined` and
 * `null` — the same ten-case shape the bench corpus
 * (`DIGEST_GUARD_CORPUS`) and the contentDigestAlg suite
 * pin. Each case carries a fixed printable label, so a
 * rejected value is only ever printed as that label, never
 * as raw input. No outcome is derived from
 * `assertContentDigestAlg` itself.
 */
export const DEMO_DIGEST_GUARD_ACCEPTED: ReadonlyArray<{
  label: string;
  alg: string;
}> = [
  { label: "sha-512", alg: "sha-512" },
  { label: "sha-256", alg: "sha-256" },
];
export const DEMO_DIGEST_GUARD_REJECTED: ReadonlyArray<{
  label: string;
  alg: unknown;
}> = [
  { label: "sha-1", alg: "sha-1" },
  { label: "md5", alg: "md5" },
  { label: "empty string", alg: "" },
  { label: "SHA-512 (uppercase)", alg: "SHA-512" },
  { label: "Sha-256 (mixed case)", alg: "Sha-256" },
  { label: "sha-512 with trailing space", alg: "sha-512 " },
  { label: "undefined", alg: undefined },
  { label: "null", alg: null },
];
/**
 * Hand-pinned rejection messages of the digest guard
 * segment, one per rejected case in
 * `DEMO_DIGEST_GUARD_REJECTED` order: the exact strings
 * `assertContentDigestAlg` throws for each value (the
 * `JSON.stringify` rendering of the value — bare
 * `undefined` / `null` for the non-string cases), written
 * out here, never derived from the guard under test.
 */
export const DEMO_DIGEST_GUARD_ERRORS: ReadonlyArray<string> = [
  'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-1"',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got "md5"',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got ""',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got "SHA-512"',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got "Sha-256"',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-512 "',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got undefined',
  'contentDigest: "alg" must be "sha-512" or "sha-256", got null',
];

/**
 * Nonce of the closing ReplayCache snapshot segment's first
 * signed request: it verifies against the segment's own
 * cache and is the one entry the exported snapshot carries.
 */
export const DEMO_REPLAY_SNAPSHOT_NONCE = "demo-nonce-replay-snapshot-001";
/**
 * Nonce of the closing ReplayCache snapshot segment's second
 * signed request: it verifies against the *restored* cache
 * only, so the original cache must never record it — the
 * detached-restore probe the segment asserts outside the
 * printed lines.
 */
export const DEMO_REPLAY_SNAPSHOT_FRESH_NONCE =
  "demo-nonce-replay-snapshot-002";
/**
 * Hand-pinned snapshot entries the closing segment exports
 * after its first verification: exactly one entry — the
 * segment's nonce first seen at the demo's fixed verify
 * instant (`DEMO_CREATED + 60`, the instant `verifyRequest`
 * passes to the cache and the cache's own pinned clock) —
 * in a `v: 1` snapshot, the same entry shape
 * `test/replaySnapshot.test.ts` pins for its round-trip
 * case. Written out here, never derived from the cache the
 * demo is checking.
 */
export const DEMO_REPLAY_SNAPSHOT_ENTRIES: ReadonlyArray<
  readonly [string, number]
> = [[DEMO_REPLAY_SNAPSHOT_NONCE, DEMO_CREATED + 60]];
/**
 * Hand-pinned failure code of the closing segment's restored
 * verification: the nonce was seen before the snapshot was
 * exported, so the restored cache must reject the same
 * request with `NONCE_REPLAY` — the same code
 * `test/replaySnapshot.test.ts` pins for its end-to-end
 * restored verification.
 */
export const DEMO_REPLAY_SNAPSHOT_CODE: VerifyFailureCode = "NONCE_REPLAY";
/**
 * Hand-pinned entry counts of the closing segment: the
 * restored cache holds 2 entries after it also records the
 * fresh nonce, while the original cache still holds only
 * the 1 exported entry.
 */
export const DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE = 2;
export const DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE = 1;

/** Key id of the closing ECDSA P-384 segment's signed request. */
export const DEMO_P384_KEY_ID = "demo-p384-key-1";
/** Nonce of the closing ECDSA P-384 segment's signed request. */
export const DEMO_P384_NONCE = "demo-nonce-p384-001";
/**
 * Hand-pinned verified identity of the closing ECDSA P-384
 * segment: the segment passes no label, so its signature
 * carries the library default `sig1`, and verification must
 * report the segment's own keyid, the `ecdsa-p384-sha384`
 * algorithm and its nonce — the same identity shape
 * `test/ecdsaP384.test.ts` pins for its round-trip case
 * (label default, keyid, alg). The expectations are written
 * out here, never derived from the verification the demo is
 * checking.
 */
export const DEMO_P384_LABEL = "sig1";
export const DEMO_P384_ALG = "ecdsa-p384-sha384";
/**
 * Hand-pinned failure code of the closing ECDSA P-384
 * segment's tampered request: changing the body by the same
 * one byte as the main line (amount 100 -> 101) leaves the
 * covered `content-digest` stale, so verification must fail
 * with `BODY_DIGEST_MISMATCH` — the same code
 * `test/ecdsaP384.test.ts` pins for its tampered-body case.
 * The expectation is written out here, never derived from
 * the verification the demo is checking.
 */
export const DEMO_P384_TAMPERED_CODE: VerifyFailureCode =
  "BODY_DIGEST_MISMATCH";

/** Label of the closing Signature-Input parsing segment: the main line's label. */
export const DEMO_PARSE_LABEL = "sig1";
/**
 * Hand-pinned raw `signature-input` value of the main signed
 * request: the signer's serialization of the covered
 * components (`DEMO_COVERED_COMPONENTS`) and the fixed
 * main-line parameters (created 1700000000, keyid
 * `demo-key-1`, alg `ed25519`, nonce `demo-nonce-001`) — the
 * same serialization shape the demo's own per-segment
 * signature-input literals and the bench `PARSER_INPUT`
 * fixture pin for their own requests. Written out here,
 * never derived from the header the demo is checking.
 */
export const DEMO_PARSE_RAW_INPUT =
  'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001"';
/** Characters of the raw value the parsing segment prints before truncating. */
export const DEMO_PARSE_PREVIEW_CHARS = 72;
/**
 * Hand-pinned printed preview: the first
 * `DEMO_PARSE_PREVIEW_CHARS` characters of
 * `DEMO_PARSE_RAW_INPUT`.
 */
export const DEMO_PARSE_RAW_PREVIEW =
  'sig1=("@method" "@authority" "@path" "content-digest");created=170000000';
/**
 * Hand-pinned parsed parameters of the main signature: the
 * fixed main-line keyid, algorithm, created instant and
 * nonce the signer wrote into the `signature-input` value —
 * the same parameter shape the bench parser fixture pins
 * for its merchant member. Written out here, never derived
 * from the parse the demo is checking.
 */
export const DEMO_PARSE_KEY_ID = "demo-key-1";
export const DEMO_PARSE_ALG = "ed25519";
export const DEMO_PARSE_CREATED = 1700000000;
export const DEMO_PARSE_NONCE = "demo-nonce-001";
/**
 * Hand-pinned error of the closing segment's tampered
 * parse: a detached copy of the raw value with its closing
 * parenthesis removed leaves the inner list unterminated,
 * so `parseSignatureInput` throws exactly the message
 * `src/components.ts` builds for that shape — the same
 * message the bench `PARSER_MALFORMED` corpus pins for its
 * unterminated case.
 */
export const DEMO_PARSE_TAMPERED_ERROR =
  "malformed Signature-Input: unterminated inner list";

/** Key id of the closing ECDSA P-521 segment's signed request. */
export const DEMO_P521_KEY_ID = "demo-p521-key-1";
/** Nonce of the closing ECDSA P-521 segment's signed request. */
export const DEMO_P521_NONCE = "demo-nonce-p521-001";
/**
 * Hand-pinned verified identity of the closing ECDSA P-521
 * segment: the segment passes no label, so its signature
 * carries the library default `sig1`, and verification must
 * report the segment's own keyid, the `ecdsa-p521-sha512`
 * algorithm and its nonce — the same identity shape
 * `test/ecdsaP521.test.ts` pins for its round-trip case
 * (label default, keyid, alg). The expectations are written
 * out here, never derived from the verification the demo is
 * checking.
 */
export const DEMO_P521_LABEL = "sig1";
export const DEMO_P521_ALG = "ecdsa-p521-sha512";
/**
 * Hand-pinned failure code of the closing ECDSA P-521
 * segment's tampered request: changing the body by the same
 * one byte as the main line (amount 100 -> 101) leaves the
 * covered `content-digest` stale, so verification must fail
 * with `BODY_DIGEST_MISMATCH` — the same code
 * `test/ecdsaP521.test.ts` pins for its tampered-body case.
 * The expectation is written out here, never derived from
 * the verification the demo is checking.
 */
export const DEMO_P521_TAMPERED_CODE: VerifyFailureCode =
  "BODY_DIGEST_MISMATCH";

/**
 * Fixed component-resolution corpus of the closing segment:
 * the main signed request's covered components
 * (`DEMO_COVERED_COMPONENTS`, in that order) paired with the
 * value `resolveComponent` must return for each — the exact
 * value the component contributes to its signature-base line.
 * Hand-pinned from the resolver's contract: `@method` is the
 * request method uppercased, `@authority` is the URL host
 * lowercased, `@path` is the URL pathname, and
 * `content-digest` is the signed request's normalized field
 * value — the sha-512 digest of the fixed `DEMO_BODY`, the
 * same value the golden `Content-Digest` vector and the
 * signature-base segment's printed lines pin. The
 * expectations are written out here, never derived from the
 * resolver the demo is checking.
 */
export const DEMO_RESOLVE_COMPONENTS: ReadonlyArray<{
  component: string;
  expected: string;
}> = [
  { component: "@method", expected: "POST" },
  { component: "@authority", expected: "api.example.com" },
  { component: "@path", expected: "/v1/payments" },
  {
    component: "content-digest",
    expected:
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  },
];
/**
 * Illegal component id of the closing segment: a real field
 * component carrying the unsupported `;zz` parameter.
 * `resolveComponent` must reject it before any value is
 * produced — an unsupported parameter is never silently
 * ignored, because ignoring it would rebuild a different
 * signature base than the signer signed (the same shape
 * `test/reqComponent.test.ts` pins for its sign-side
 * rejection of the same parameter).
 */
export const DEMO_RESOLVE_ILLEGAL_COMPONENT = "content-digest;zz";
/**
 * Hand-pinned rejection message of the closing segment: the
 * exact string `resolveComponent` throws for
 * `DEMO_RESOLVE_ILLEGAL_COMPONENT` — the message
 * `src/components.ts` builds for an unsupported component
 * parameter (a plain `Error`, no failure code). Written out
 * here, never derived from the resolver under test.
 */
export const DEMO_RESOLVE_ILLEGAL_ERROR =
  'unsupported component parameter ";zz" on component "content-digest": only ";req", ";bs", ";sf", ";key", ";tr" and ";name" are supported';

/**
 * Header field of the closing multi-value segment: the field
 * appears twice on the segment's request, as the array
 * `DEMO_JOIN_VALUES` — the shape a receiver gets when a
 * sender or an intermediary emitted the field on two lines.
 */
export const DEMO_JOIN_HEADER = "x-foo";
/**
 * Fixed values of the closing multi-value segment's repeated
 * field, padding included on purpose: each element carries
 * surrounding whitespace a hand-rolled join would leak into
 * the signature base. The same padded shape
 * `test/multiValueHeaderWhitespace.test.ts` pins for its
 * round-trip cases.
 */
export const DEMO_JOIN_VALUES: string[] = ["  alpha ", " beta  "];
/**
 * Hand-pinned combination of `DEMO_JOIN_VALUES`: every
 * element trimmed, the elements joined with ", " — the
 * RFC 9421 §2.5 combination `joinHeaderValues` performs and
 * the signer emits as the field's wire value. Written out
 * here, never derived from the helper under test.
 */
export const DEMO_JOIN_EXPECTED = "alpha, beta";
/**
 * Hand-pinned wrong combination of the same values: the
 * elements trimmed but joined with a bare comma, the space
 * after the comma dropped — the classic hand-rolled-join
 * mistake. A request carrying this value rebuilds a
 * different signature base than the signer signed, so
 * verification must reject it.
 */
export const DEMO_JOIN_WRONG_VALUE = "alpha,beta";
/** Nonce of the closing multi-value segment's signed request. */
export const DEMO_JOIN_NONCE = "demo-nonce-join-001";
/** Label of the closing multi-value segment's signature. */
export const DEMO_JOIN_LABEL = "sig1";
/**
 * Covered components of the closing multi-value segment's
 * signature: the request target plus the repeated field
 * itself — the field is covered deliberately, because an
 * uncovered repeated field's combination would never be
 * checked at all. The segment's request carries no body,
 * so no `content-digest` is covered (the same covered set
 * `test/multiValueHeaderWhitespace.test.ts` signs with).
 */
export const DEMO_JOIN_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
  DEMO_JOIN_HEADER,
];
/**
 * Hand-pinned rejection code of the closing multi-value
 * segment: verification of the wrongly joined request fails
 * with `SIGNATURE_MISMATCH` — the rebuilt base's line for
 * the repeated field differs from the signed one (the same
 * code the multi-value suite pins for its
 * genuinely-different-value case).
 */
export const DEMO_JOIN_WRONG_CODE: VerifyFailureCode =
  "SIGNATURE_MISMATCH";

/** Label of the closing Signature field parsing segment. */
export const DEMO_SIGFIELD_LABEL = "sig1";
/**
 * Hand-pinned byte length of the closing segment's
 * extracted signature: the main line is ed25519, whose
 * signatures are always 64 bytes (RFC 9421 §3.3.2) — the
 * same length the golden and round-trip suites pin for
 * their ed25519 signatures. Written out here, never derived
 * from the parse the demo is checking.
 */
export const DEMO_SIGFIELD_BYTES = 64;
/**
 * Bytes of the extracted signature the closing segment
 * prints as a hexadecimal prefix: enough to eyeball that
 * the extracted bytes are the signer's, without printing
 * the full signature.
 */
export const DEMO_SIGFIELD_PREFIX_BYTES = 8;
/**
 * Unknown label of the closing segment: the main signed
 * request carries only `DEMO_SIGFIELD_LABEL`, so this label
 * is not present in its Signature field.
 */
export const DEMO_SIGFIELD_UNKNOWN_LABEL = "sig-unknown";
/**
 * Hand-pinned rejection message of the closing segment:
 * the exact string `parseSignatureField` throws for
 * `DEMO_SIGFIELD_UNKNOWN_LABEL` — the message
 * `src/components.ts` builds for an absent label (the same
 * message shape the parser suites pin for their own absent
 * labels). Written out here, never derived from the parser
 * under test.
 */
export const DEMO_SIGFIELD_UNKNOWN_ERROR =
  'signature "sig-unknown" not present in Signature field';

/**
 * Hand-pinned expectations of the closing EC JWK segment, one
 * entry per NIST curve in P-256 / P-384 / P-521 order: the
 * JWK `crv`, the curve's RFC 9421 signing algorithm, the
 * segment's own keyid and nonce for that curve, and the
 * base64url lengths of the JWK `x` / `y` coordinates
 * (32-byte coordinates encode to 43 chars, 48-byte to 64,
 * 66-byte to 88 — the same shapes the per-curve JWK suites
 * and the bench round-trip corpus pin). Written out here,
 * never derived from the exporters under test.
 */
export const DEMO_EC_JWK_CURVES: ReadonlyArray<{
  crv: "P-256" | "P-384" | "P-521";
  alg: "ecdsa-p256-sha256" | "ecdsa-p384-sha384" | "ecdsa-p521-sha512";
  keyId: string;
  nonce: string;
  xLength: number;
  yLength: number;
}> = [
  {
    crv: "P-256",
    alg: "ecdsa-p256-sha256",
    keyId: "demo-ec-jwk-p256",
    nonce: "demo-nonce-ec-jwk-p256-001",
    xLength: 43,
    yLength: 43,
  },
  {
    crv: "P-384",
    alg: "ecdsa-p384-sha384",
    keyId: "demo-ec-jwk-p384",
    nonce: "demo-nonce-ec-jwk-p384-001",
    xLength: 64,
    yLength: 64,
  },
  {
    crv: "P-521",
    alg: "ecdsa-p521-sha512",
    keyId: "demo-ec-jwk-p521",
    nonce: "demo-nonce-ec-jwk-p521-001",
    xLength: 88,
    yLength: 88,
  },
];
/** Label every EC JWK segment signature carries (the library default). */
export const DEMO_EC_JWK_LABEL = "sig1";
/**
 * Hand-pinned rejection message of the closing EC JWK
 * segment: the exact string `importPublicKeyJwkP384` throws
 * when the segment's P-256 JWK is fed to it — the message
 * `src/keys.ts` builds for a crv mismatch (the same message
 * shape the per-curve JWK suites pin). Written out here,
 * never derived from the importer under test.
 */
export const DEMO_EC_JWK_MISMATCH_ERROR =
  'importPublicKeyJwkP384: invalid JWK: expected crv "P-384", got "P-256"';

/** Key id of the closing RSA JWK segment's signed request. */
export const DEMO_RSA_JWK_KEY_ID = "demo-rsa-jwk-1";
/** Nonce of the closing RSA JWK segment's signed request. */
export const DEMO_RSA_JWK_NONCE = "demo-nonce-rsa-jwk-001";
/** Label the RSA JWK segment signature carries (the library default). */
export const DEMO_RSA_JWK_LABEL = "sig1";
/**
 * Hand-pinned signing algorithm of the closing RSA JWK
 * segment: the segment signs under `rsa-pss-sha512` — the
 * RSA algorithm the library's RSA JWK suite
 * (`test/rsaJwk.test.ts`) round-trips — with the segment's
 * RSA key pair. The same exported JWK would also serve
 * `rsa-v1_5-sha256`: a JWK carries no `alg`, so the
 * distinction lives only in each signature's `alg`
 * parameter (see `src/keys.ts`).
 */
export const DEMO_RSA_JWK_ALG = "rsa-pss-sha512";
/**
 * Hand-pinned base64url length of the closing segment's
 * exported `n` (modulus): a 2048-bit modulus is 256 bytes,
 * which base64url-encodes without padding to 342
 * characters — the same shape `test/rsaJwk.test.ts` pins
 * for its exported JWKs. Written out here, never derived
 * from the exporter under test.
 */
export const DEMO_RSA_JWK_N_LENGTH = 342;
/**
 * Hand-pinned public exponent of the closing segment's
 * exported JWK: node:crypto mints RSA keys with the
 * standard exponent 65537, whose base64url form is
 * `AQAB` (4 characters) — the same value
 * `test/rsaJwk.test.ts` pins for its exported JWKs.
 */
export const DEMO_RSA_JWK_E = "AQAB";
export const DEMO_RSA_JWK_E_LENGTH = 4;
/**
 * Hand-pinned rejection message of the closing RSA JWK
 * segment: the exact string `importPublicKeyJwkRsa`
 * throws when the EC segment's P-256 JWK (`kty: "EC"`) is
 * fed to it — the message `src/keys.ts` builds for a kty
 * mismatch (the same message shape `test/rsaJwk.test.ts`
 * pins for its cross-shape rejections). Written out here,
 * never derived from the importer under test.
 */
export const DEMO_RSA_JWK_MISMATCH_ERROR =
  'importPublicKeyJwkRsa: invalid JWK: expected kty "RSA", got "EC"';

/** Key id of the closing JWKS refresh segment's pre-rotation key. */
export const DEMO_JWKS_REFRESH_OLD_KEY_ID = "demo-jwks-refresh-old-1";
/** Key id of the closing JWKS refresh segment's rotated key. */
export const DEMO_JWKS_REFRESH_NEW_KEY_ID = "demo-jwks-refresh-new-1";
/** Nonce of the closing JWKS refresh segment's pre-rotation request. */
export const DEMO_JWKS_REFRESH_OLD_NONCE =
  "demo-nonce-jwks-refresh-old-001";
/** Nonce of the closing JWKS refresh segment's rotated request. */
export const DEMO_JWKS_REFRESH_NEW_NONCE =
  "demo-nonce-jwks-refresh-new-001";
/** Label every JWKS refresh segment signature carries (the library default). */
export const DEMO_JWKS_REFRESH_LABEL = "sig1";
/**
 * TTL of the closing JWKS refresh segment's store: the
 * freshness probe runs 60 seconds into this 120-second
 * window (still fresh), and the rotation probe runs 60
 * seconds past it (stale) — the same staleness rule
 * `test/jwksRefreshIfStale.test.ts` pins at its own TTL.
 */
export const DEMO_JWKS_REFRESH_TTL_SEC = 120;
/** Injected-clock instant of the freshness probe (fresh: 60s in, TTL 120s). */
export const DEMO_JWKS_REFRESH_FRESH_AT_SEC = DEMO_CREATED + 60;
/** Injected-clock instant of the rotation probe (stale: 180s in, TTL 120s). */
export const DEMO_JWKS_REFRESH_STALE_AT_SEC =
  DEMO_CREATED + DEMO_JWKS_REFRESH_TTL_SEC + 60;
/** Fetch count after the segment's initial load (exactly one fetch). */
export const DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD = 1;
/** Fetch count after the segment's rotation refresh (exactly one more). */
export const DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION = 2;
/**
 * Hand-pinned rejection code of the closing JWKS refresh
 * segment: after rotation the retired keyid no longer
 * resolves, so the verifier fails closed with this code
 * before any signature check (the same code the JWKS
 * segment above pins for its never-known keyid).
 */
export const DEMO_JWKS_REFRESH_RETIRED_CODE: VerifyFailureCode =
  "KEY_RESOLUTION_FAILED";

/**
 * Stored key of the closing header-lookup segment's
 * multi-value field: mixed case on purpose — the segment
 * looks it up under `DEMO_GET_HEADER_LOOKUP_NAME`, whose
 * case differs, because `getHeader` matches stored keys
 * case-insensitively.
 */
export const DEMO_GET_HEADER_STORED_NAME = "X-Trace-Hops";
/** Lookup name of the same field, in lower case. */
export const DEMO_GET_HEADER_LOOKUP_NAME = "x-trace-hops";
/**
 * Fixed values of the header-lookup segment's multi-value
 * field, padding included on purpose: each element carries
 * surrounding whitespace the normalized read discards and
 * the raw read preserves — the visible difference between
 * the two reads.
 */
export const DEMO_GET_HEADER_VALUES: string[] = ["  edge-1 ", " edge-2  "];
/**
 * Hand-pinned normalized result of the multi-value lookup:
 * every element trimmed, the elements joined with ", " —
 * the RFC 9421 §2.5 combination `getHeader` performs via
 * `joinHeaderValues`. Written out here, never derived from
 * the helper under test.
 */
export const DEMO_GET_HEADER_EXPECTED = "edge-1, edge-2";
/**
 * Hand-pinned raw result of the same lookup under
 * `getHeaderRaw`: the elements joined with ", " but NOT
 * trimmed, so the first element's trailing space and the
 * second element's leading space both survive around the
 * separator. Written out here, never derived from the
 * helper under test.
 */
export const DEMO_GET_HEADER_RAW_EXPECTED = "  edge-1 ,  edge-2  ";
/** Stored key of the header-lookup segment's single string field. */
export const DEMO_GET_HEADER_SINGLE_STORED_NAME = "Content-Type";
/** Lookup name of the single field, in upper case. */
export const DEMO_GET_HEADER_SINGLE_LOOKUP_NAME = "CONTENT-TYPE";
/**
 * Fixed value of the single string field: a plain string
 * is returned exactly as stored by both reads (only array
 * values go through the trimming combination).
 */
export const DEMO_GET_HEADER_SINGLE_VALUE = "application/json";
/** Name of a field the header-lookup segment's record does not carry. */
export const DEMO_GET_HEADER_MISSING_NAME = "x-absent";

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
  /**
   * The request signed in the closing ECDSA P-256 segment
   * with a fresh P-256 key pair under `ecdsa-p256-sha256`
   * (keyid `DEMO_P256_KEY_ID`, nonce `DEMO_P256_NONCE`).
   */
  p256Signed: SignedHttpRequest;
  /**
   * Verification of `p256Signed` (ok — label, keyid, alg and
   * nonce equal the hand-pinned `DEMO_P256_*` expectations).
   */
  p256Verification: VerifyResult;
  /**
   * Verification of `p256Signed` with the body tampered by
   * one byte: rejected with `DEMO_P256_TAMPERED_CODE`
   * (`BODY_DIGEST_MISMATCH`).
   */
  p256TamperedVerification: VerifyResult;
  /**
   * The closing Content-Digest guard segment's accepted
   * cases: each fixed value passed `assertContentDigestAlg`
   * (the two emittable algorithms, `sha-512` / `sha-256`).
   */
  digestGuardAccepted: ReadonlyArray<{
    label: string;
    alg: string;
  }>;
  /**
   * The closing Content-Digest guard segment's rejections:
   * each fixed rejected value (unknown algorithms, the
   * empty string, wrong-case and trailing-space spellings,
   * and the non-string `undefined` / `null`) was rejected,
   * paired with the exact error message the guard threw
   * (`DEMO_DIGEST_GUARD_ERRORS`).
   */
  digestGuardRejections: ReadonlyArray<{
    label: string;
    alg: unknown;
    error: string;
  }>;
  /**
   * The request signed in the closing ReplayCache snapshot
   * segment with `DEMO_REPLAY_SNAPSHOT_NONCE` under the main
   * line's key and keyid.
   */
  replaySnapshotSigned: SignedHttpRequest;
  /**
   * Verification of `replaySnapshotSigned` against the
   * segment's own cache (ok — the nonce is recorded).
   */
  replaySnapshotFirstVerification: VerifyResult;
  /**
   * The v1 snapshot exported from the segment's cache after
   * the first verification (exactly the hand-pinned
   * `DEMO_REPLAY_SNAPSHOT_ENTRIES`).
   */
  replaySnapshotExport: ReplayCacheSnapshot;
  /**
   * Verification of the same `replaySnapshotSigned` request
   * against the cache restored from `replaySnapshotExport`:
   * rejected with `DEMO_REPLAY_SNAPSHOT_CODE`
   * (`NONCE_REPLAY`) — the restart did not reopen the window.
   */
  replaySnapshotReplayVerification: VerifyResult;
  /**
   * Verification of a request signed with
   * `DEMO_REPLAY_SNAPSHOT_FRESH_NONCE` against the restored
   * cache (ok — recorded only in the restored cache).
   */
  replaySnapshotFreshVerification: VerifyResult;
  /**
   * Entries in the restored cache after the fresh
   * verification (`DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE`: 2).
   */
  replaySnapshotRestoredSize: number;
  /**
   * Entries in the original cache after the restored cache
   * recorded the fresh nonce
   * (`DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE`: 1 — the restore
   * is detached, the original is unaffected).
   */
  replaySnapshotOriginalSize: number;
  /**
   * The request signed in the closing ECDSA P-384 segment
   * with a fresh P-384 key pair under `ecdsa-p384-sha384`
   * (keyid `DEMO_P384_KEY_ID`, nonce `DEMO_P384_NONCE`).
   */
  p384Signed: SignedHttpRequest;
  /**
   * Verification of `p384Signed` (ok — label, keyid, alg and
   * nonce equal the hand-pinned `DEMO_P384_*` expectations).
   */
  p384Verification: VerifyResult;
  /**
   * Verification of `p384Signed` with the body tampered by
   * one byte: rejected with `DEMO_P384_TAMPERED_CODE`
   * (`BODY_DIGEST_MISMATCH`).
   */
  p384TamperedVerification: VerifyResult;
  /**
   * Raw `signature-input` value of the main signed request,
   * read back with `getHeaderRaw` in the closing parsing
   * segment (equals the hand-pinned `DEMO_PARSE_RAW_INPUT`).
   */
  signatureInputRaw: string;
  /**
   * `parseSignatureInput` result for the main label over
   * `signatureInputRaw`: label, covered component ids and
   * parameters, each equal to the hand-pinned
   * `DEMO_PARSE_*` expectations.
   */
  parsedSignatureInput: ParsedSignatureInput;
  /**
   * Error message thrown when the detached,
   * parenthesis-stripped copy of the raw value is parsed
   * (equals the hand-pinned `DEMO_PARSE_TAMPERED_ERROR`).
   */
  parseTamperedError: string;
  /**
   * The request signed in the closing ECDSA P-521 segment
   * with a fresh P-521 key pair under `ecdsa-p521-sha512`
   * (keyid `DEMO_P521_KEY_ID`, nonce `DEMO_P521_NONCE`).
   */
  p521Signed: SignedHttpRequest;
  /**
   * Verification of `p521Signed` (ok — label, keyid, alg and
   * nonce equal the hand-pinned `DEMO_P521_*` expectations).
   */
  p521Verification: VerifyResult;
  /**
   * Verification of `p521Signed` with the body tampered by
   * one byte: rejected with `DEMO_P521_TAMPERED_CODE`
   * (`BODY_DIGEST_MISMATCH`).
   */
  p521TamperedVerification: VerifyResult;
  /**
   * The closing component-resolution segment's results: each
   * covered component of the main signed request paired with
   * its `resolveComponent` output (equal to the hand-pinned
   * `DEMO_RESOLVE_COMPONENTS` expectations).
   */
  resolvedComponents: ReadonlyArray<{
    component: string;
    value: string;
  }>;
  /**
   * Error message thrown when resolving
   * `DEMO_RESOLVE_ILLEGAL_COMPONENT` (equals the hand-pinned
   * `DEMO_RESOLVE_ILLEGAL_ERROR`; empty only if the resolver
   * unexpectedly did not throw, which the demo asserts
   * against outside the printed lines).
   */
  resolveIllegalComponentError: string;
  /**
   * The closing multi-value segment's combination:
   * `joinHeaderValues(DEMO_JOIN_VALUES)` (equals the
   * hand-pinned `DEMO_JOIN_EXPECTED`, and the wire value
   * the segment's signer emits for the repeated field).
   */
  joinedHeaderValue: string;
  /**
   * The request signed in the closing multi-value segment
   * over the repeated `DEMO_JOIN_HEADER` field (its wire
   * value for that field is the canonical combination).
   */
  joinSigned: SignedHttpRequest;
  /**
   * Verification of `joinSigned` (ok — label, keyid, alg
   * and nonce equal the hand-pinned `DEMO_JOIN_*`
   * expectations).
   */
  joinVerification: VerifyResult;
  /**
   * Verification of `joinSigned` with the repeated field
   * replaced by `DEMO_JOIN_WRONG_VALUE`: rejected with
   * `DEMO_JOIN_WRONG_CODE` (`SIGNATURE_MISMATCH`).
   */
  joinWrongVerification: VerifyResult;
  /**
   * The closing Signature field parsing segment's extracted
   * bytes: `parseSignatureField` over the main signed
   * request's `signature` value for `DEMO_SIGFIELD_LABEL`
   * (byte-for-byte equal to the bytes the signer emitted,
   * `DEMO_SIGFIELD_BYTES` long).
   */
  signatureFieldBytes: Buffer;
  /**
   * Hexadecimal prefix of `signatureFieldBytes`: its first
   * `DEMO_SIGFIELD_PREFIX_BYTES` bytes rendered as hex (the
   * only part of the signature the segment prints).
   */
  signatureFieldHexPrefix: string;
  /**
   * Error message thrown when parsing the same field for
   * `DEMO_SIGFIELD_UNKNOWN_LABEL` (equals the hand-pinned
   * `DEMO_SIGFIELD_UNKNOWN_ERROR`).
   */
  signatureFieldUnknownError: string;
  /**
   * The closing EC JWK segment's exported JWKs, one per
   * NIST curve in `DEMO_EC_JWK_CURVES` order (each
   * `kty "EC"` with its pinned crv and coordinate lengths;
   * the keys themselves are fresh per run).
   */
  ecJwkExports: ReadonlyArray<
    P256PublicJwk | P384PublicJwk | P521PublicJwk
  >;
  /**
   * The requests signed in the closing EC JWK segment, one
   * per curve with that curve's fresh private key (keyid,
   * alg and nonce equal the pinned `DEMO_EC_JWK_CURVES`
   * entry).
   */
  ecJwkSigned: SignedHttpRequest[];
  /**
   * Verification of each `ecJwkSigned` request with the
   * public key imported back from the matching exported
   * JWK after a JSON wire round-trip (all ok — the EC JWK
   * round-trip holds per curve).
   */
  ecJwkVerifications: VerifyResult[];
  /**
   * Error message thrown when the segment's P-256 JWK is
   * fed to `importPublicKeyJwkP384` (equals the hand-pinned
   * `DEMO_EC_JWK_MISMATCH_ERROR`).
   */
  ecJwkMismatchError: string;
  /**
   * The closing RSA JWK segment's exported JWK (`kty "RSA"`
   * with a 342-character base64url `n` and `e` "AQAB"; the
   * key itself is generated once per process).
   */
  rsaJwkExport: RsaPublicJwk;
  /**
   * The request signed in the closing RSA JWK segment with
   * the segment's RSA private key under `rsa-pss-sha512`
   * (keyid `DEMO_RSA_JWK_KEY_ID`, nonce
   * `DEMO_RSA_JWK_NONCE`).
   */
  rsaJwkSigned: SignedHttpRequest;
  /**
   * Verification of `rsaJwkSigned` with the public key
   * imported back from `rsaJwkExport` after a JSON wire
   * round-trip (ok — the RSA JWK round-trip holds).
   */
  rsaJwkVerification: VerifyResult;
  /**
   * Error message thrown when the EC segment's P-256 JWK
   * is fed to `importPublicKeyJwkRsa` (equals the
   * hand-pinned `DEMO_RSA_JWK_MISMATCH_ERROR`).
   */
  rsaJwkMismatchError: string;
  /**
   * The closing JWKS refresh segment's first
   * `refreshIfStale()` result: `true` — a never-refreshed
   * store is stale, so the initial load fetches.
   */
  jwksRefreshInitialRefreshed: boolean;
  /**
   * Fake-fetch count after the initial load (equals the
   * hand-pinned `DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD`).
   */
  jwksRefreshFetchCallsAfterLoad: number;
  /**
   * The request the closing JWKS refresh segment signs
   * under the pre-rotation keyid
   * (`DEMO_JWKS_REFRESH_OLD_KEY_ID`, nonce
   * `DEMO_JWKS_REFRESH_OLD_NONCE`) before rotation.
   */
  jwksRefreshOldSigned: SignedHttpRequest;
  /**
   * Verification of `jwksRefreshOldSigned` through the
   * store's resolver before rotation (ok).
   */
  jwksRefreshOldVerification: VerifyResult;
  /**
   * The segment's second `refreshIfStale()` result, probed
   * at `DEMO_JWKS_REFRESH_FRESH_AT_SEC` inside the TTL:
   * `false` — a fresh snapshot is never re-fetched.
   */
  jwksRefreshFreshRefreshed: boolean;
  /**
   * Fake-fetch count after the freshness probe (unchanged:
   * still `DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD`).
   */
  jwksRefreshFetchCallsAfterFresh: number;
  /**
   * The segment's third `refreshIfStale()` result, probed
   * at `DEMO_JWKS_REFRESH_STALE_AT_SEC` past the TTL with
   * the fake endpoint serving only the rotated key:
   * `true` — the stale snapshot was re-fetched.
   */
  jwksRefreshStaleRefreshed: boolean;
  /**
   * Fake-fetch count after the rotation refresh (equals
   * the hand-pinned
   * `DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION`).
   */
  jwksRefreshFetchCallsAfterRotation: number;
  /**
   * The request the closing JWKS refresh segment signs
   * under the rotated keyid (`DEMO_JWKS_REFRESH_NEW_KEY_ID`,
   * nonce `DEMO_JWKS_REFRESH_NEW_NONCE`) after rotation.
   */
  jwksRefreshNewSigned: SignedHttpRequest;
  /**
   * Verification of `jwksRefreshNewSigned` through the
   * store's resolver after rotation (ok — the rotated
   * keyid resolves to the rotated key).
   */
  jwksRefreshNewVerification: VerifyResult;
  /**
   * Verification of `jwksRefreshOldSigned` through the
   * store's resolver after rotation: rejected with
   * `DEMO_JWKS_REFRESH_RETIRED_CODE`
   * (`KEY_RESOLUTION_FAILED`) — the retired keyid no
   * longer resolves, so the still-valid signature is
   * never even checked.
   */
  jwksRefreshRetiredVerification: VerifyResult;
  /**
   * The closing header-lookup segment's fixture record:
   * the multi-value field under its mixed-case stored key
   * (`DEMO_GET_HEADER_STORED_NAME`, values
   * `DEMO_GET_HEADER_VALUES`) plus the single string field
   * (`DEMO_GET_HEADER_SINGLE_STORED_NAME`).
   */
  getHeaderHeaders: Record<string, string | string[]>;
  /**
   * The segment's normalized multi-value lookup:
   * `getHeader` under `DEMO_GET_HEADER_LOOKUP_NAME` (equals
   * the hand-pinned `DEMO_GET_HEADER_EXPECTED`).
   */
  getHeaderValue: string | undefined;
  /**
   * The segment's raw multi-value lookup: `getHeaderRaw`
   * under the same name (equals the hand-pinned
   * `DEMO_GET_HEADER_RAW_EXPECTED` — padding preserved).
   */
  getHeaderRawValue: string | undefined;
  /**
   * The segment's single-value lookup: `getHeader` under
   * `DEMO_GET_HEADER_SINGLE_LOOKUP_NAME` (equals
   * `DEMO_GET_HEADER_SINGLE_VALUE`, returned as stored).
   */
  getHeaderSingleValue: string | undefined;
  /**
   * The segment's missing-field lookup under `getHeader`:
   * `undefined` — a missing header has no value.
   */
  getHeaderMissingValue: string | undefined;
  /**
   * The segment's missing-field lookup under
   * `getHeaderRaw`: also `undefined`.
   */
  getHeaderRawMissingValue: string | undefined;
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

/**
 * RSA key pair for the closing RSA JWK segment, generated
 * once per process and reused across `runDemo()` calls —
 * the same generate-once shape as {@link rsaGuardKeys}
 * above, for the same reason: the demo tests call
 * `runDemo()` many times and must not pay RSA key
 * generation on every call. Only the exported JWK's shape
 * is ever printed, never the key bytes.
 */
let demoRsaJwkPair: {
  publicKey: KeyObject;
  privateKey: KeyObject;
} | null = null;
function rsaJwkPair(): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} {
  if (demoRsaJwkPair === null) {
    demoRsaJwkPair = generateRsaPssKeyPair();
  }
  return demoRsaJwkPair;
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
export async function runDemo(): Promise<DemoResult> {
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

  // ECDSA P-256 signing segment: the demo's earlier lines sign
  // with ed25519 (main line) and hmac-sha256 (gateway line),
  // but the library's NIST-curve line — `ecdsa-p256-sha256`,
  // RFC 9421 §3.3.4 — was never shown. A P-256 key pair from
  // `generateP256KeyPair` (the generator the ecdsa tests and
  // bench corpus use) signs the same fixed payment request
  // under the segment's own keyid and nonce, verification
  // passes, and the same one-byte body tamper as the main
  // line (amount 100 -> 101) is rejected because the covered
  // `content-digest` no longer matches the body. Outside the
  // printed lines the demo asserts the verified identity
  // (label, keyid, alg, nonce) and the tamper code equal the
  // hand-pinned DEMO_P256_* expectations — a mismatch throws
  // instead of printing a misleading segment. No key bytes
  // are printed.
  const p256KeyPair = generateP256KeyPair();
  const p256Signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P256_KEY_ID,
      alg: "ecdsa-p256-sha256",
      key: p256KeyPair.privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P256_NONCE,
    },
  );
  const p256Verification = verifyRequest(p256Signed, {
    key: p256KeyPair.publicKey,
    now: DEMO_CREATED + 60,
  });
  const p256TamperedVerification = verifyRequest(
    { ...p256Signed, body: DEMO_TAMPERED_BODY },
    { key: p256KeyPair.publicKey, now: DEMO_CREATED + 60 },
  );
  if (
    !p256Verification.ok ||
    p256Verification.label !== DEMO_P256_LABEL ||
    p256Verification.keyId !== DEMO_P256_KEY_ID ||
    p256Verification.alg !== DEMO_P256_ALG ||
    p256Verification.nonce !== DEMO_P256_NONCE ||
    p256TamperedVerification.ok ||
    p256TamperedVerification.code !== DEMO_P256_TAMPERED_CODE
  ) {
    throw new Error(
      `demo fixture broken: P-256 verification ` +
        `${p256Verification.ok}/${p256Verification.label}/${p256Verification.keyId}/` +
        `${p256Verification.alg}/${p256Verification.nonce} with tamper code ` +
        `${p256TamperedVerification.code}, instead of the pinned ` +
        `true/${DEMO_P256_LABEL}/${DEMO_P256_KEY_ID}/${DEMO_P256_ALG}/` +
        `${DEMO_P256_NONCE} with tamper code ${DEMO_P256_TAMPERED_CODE}`,
    );
  }

  // Content-Digest algorithm guard segment: the signer and
  // `contentDigest` pass every digest algorithm through
  // `assertContentDigestAlg` before any hashing runs — only
  // `sha-512` and `sha-256` can be emitted, so an unsupported
  // algorithm is a caller configuration error (thrown), never
  // a wire value. The demo runs the fixed corpus through the
  // guard directly: the two emittable algorithms pass, the
  // eight rejected values (unknown, empty, wrong-case,
  // trailing-space and non-string shapes) are each rejected.
  // Outside the printed lines the demo asserts the accepted
  // group all passed and every rejection message equals the
  // hand-pinned DEMO_DIGEST_GUARD_ERRORS — a mismatch throws
  // instead of printing a misleading segment. Rejected
  // values are printed only as their fixed labels.
  const digestGuardAccepted: Array<{ label: string; alg: string }> = [];
  for (const entry of DEMO_DIGEST_GUARD_ACCEPTED) {
    assertContentDigestAlg(entry.alg);
    digestGuardAccepted.push({ label: entry.label, alg: entry.alg });
  }
  const digestGuardRejections: Array<{
    label: string;
    alg: unknown;
    error: string;
  }> = [];
  for (const entry of DEMO_DIGEST_GUARD_REJECTED) {
    let error = "";
    try {
      assertContentDigestAlg(entry.alg);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    digestGuardRejections.push({
      label: entry.label,
      alg: entry.alg,
      error,
    });
  }
  if (
    digestGuardAccepted.length !== DEMO_DIGEST_GUARD_ACCEPTED.length ||
    digestGuardRejections.some(
      (r, i) => r.error !== DEMO_DIGEST_GUARD_ERRORS[i],
    )
  ) {
    throw new Error(
      `demo fixture broken: Content-Digest guard rejections ` +
        `${JSON.stringify(digestGuardRejections.map((r) => r.error))} ` +
        `instead of the pinned ${JSON.stringify(DEMO_DIGEST_GUARD_ERRORS)}`,
    );
  }

  // ReplayCache snapshot persistence segment: the replay
  // segment above keeps its cache inside one process, so a
  // restart would reopen its replay window — the one
  // cross-restart ability `ReplayCache` has was never
  // shown. A request signed with the segment's fixed nonce
  // verifies against the segment's own cache (same capacity
  // / TTL constants and pinned clock as the replay segment),
  // the cache is exported with `exportSnapshot()`, and a new
  // cache is rebuilt with `ReplayCache.restore()` — the
  // "restart". The same request verified against the
  // restored cache must be rejected with `NONCE_REPLAY`,
  // and a fresh-nonce request verifies against the restored
  // cache and is recorded only there. Outside the printed
  // lines the demo asserts the first verification passed,
  // the exported snapshot equals the hand-pinned
  // DEMO_REPLAY_SNAPSHOT_ENTRIES, the restored rejection
  // code equals the hand-pinned DEMO_REPLAY_SNAPSHOT_CODE
  // (the same snapshot shape and code
  // `test/replaySnapshot.test.ts` pins for its round-trip
  // case), and the original cache still holds only the
  // exported entry after the restored cache records the
  // fresh nonce — probed through a second, non-mutating
  // `exportSnapshot()` of the original. Only the entry
  // count, the fixed nonces and the first-seen instant are
  // printed, never key or signature bytes.
  const replaySnapshotCacheOptions = {
    maxEntries: DEMO_REPLAY_CACHE_MAX_ENTRIES,
    ttlSec: DEMO_REPLAY_CACHE_TTL_SEC,
    now: () => DEMO_CREATED + 60,
  };
  const replaySnapshotCache = new ReplayCache(replaySnapshotCacheOptions);
  const replaySnapshotSigned = signRequest(
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
      nonce: DEMO_REPLAY_SNAPSHOT_NONCE,
    },
  );
  const replaySnapshotFirstVerification = verifyRequest(replaySnapshotSigned, {
    key: publicKey,
    now: DEMO_CREATED + 60,
    replayCache: replaySnapshotCache,
  });
  const replaySnapshotExport = replaySnapshotCache.exportSnapshot();
  const replaySnapshotRestored = ReplayCache.restore(
    replaySnapshotExport,
    replaySnapshotCacheOptions,
  );
  const replaySnapshotReplayVerification = verifyRequest(replaySnapshotSigned, {
    key: publicKey,
    now: DEMO_CREATED + 60,
    replayCache: replaySnapshotRestored,
  });
  const replaySnapshotFreshSigned = signRequest(
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
      nonce: DEMO_REPLAY_SNAPSHOT_FRESH_NONCE,
    },
  );
  const replaySnapshotFreshVerification = verifyRequest(
    replaySnapshotFreshSigned,
    {
      key: publicKey,
      now: DEMO_CREATED + 60,
      replayCache: replaySnapshotRestored,
    },
  );
  const replaySnapshotRestoredSize = replaySnapshotRestored.size;
  const replaySnapshotOriginalExportAfter =
    replaySnapshotCache.exportSnapshot();
  const replaySnapshotOriginalSize = replaySnapshotCache.size;
  const snapshotEntriesMatch = (
    entries: ReplayCacheSnapshot["entries"],
  ): boolean =>
    entries.length === DEMO_REPLAY_SNAPSHOT_ENTRIES.length &&
    entries.every(
      (entry, i) =>
        entry[0] === DEMO_REPLAY_SNAPSHOT_ENTRIES[i][0] &&
        entry[1] === DEMO_REPLAY_SNAPSHOT_ENTRIES[i][1],
    );
  if (
    !replaySnapshotFirstVerification.ok ||
    replaySnapshotFirstVerification.nonce !== DEMO_REPLAY_SNAPSHOT_NONCE ||
    replaySnapshotExport.v !== 1 ||
    !snapshotEntriesMatch(replaySnapshotExport.entries) ||
    replaySnapshotReplayVerification.ok ||
    replaySnapshotReplayVerification.code !== DEMO_REPLAY_SNAPSHOT_CODE ||
    !replaySnapshotFreshVerification.ok ||
    replaySnapshotFreshVerification.nonce !==
      DEMO_REPLAY_SNAPSHOT_FRESH_NONCE ||
    replaySnapshotRestoredSize !== DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE ||
    replaySnapshotOriginalSize !== DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE ||
    !snapshotEntriesMatch(replaySnapshotOriginalExportAfter.entries)
  ) {
    throw new Error(
      `demo fixture broken: ReplayCache snapshot segment gave ` +
        `first=${replaySnapshotFirstVerification.ok}/${replaySnapshotFirstVerification.nonce}, ` +
        `export=${JSON.stringify(replaySnapshotExport)}, ` +
        `restored=${replaySnapshotReplayVerification.ok}/${replaySnapshotReplayVerification.code}, ` +
        `fresh=${replaySnapshotFreshVerification.ok}/${replaySnapshotFreshVerification.nonce}, ` +
        `sizes restored/original=${replaySnapshotRestoredSize}/${replaySnapshotOriginalSize}, ` +
        `original export after=${JSON.stringify(replaySnapshotOriginalExportAfter)}, ` +
        `instead of the pinned first=true/${DEMO_REPLAY_SNAPSHOT_NONCE}, ` +
        `export=${JSON.stringify({ v: 1, entries: DEMO_REPLAY_SNAPSHOT_ENTRIES })}, ` +
        `restored=false/${DEMO_REPLAY_SNAPSHOT_CODE}, ` +
        `fresh=true/${DEMO_REPLAY_SNAPSHOT_FRESH_NONCE}, ` +
        `sizes restored/original=${DEMO_REPLAY_SNAPSHOT_RESTORED_SIZE}/${DEMO_REPLAY_SNAPSHOT_ORIGINAL_SIZE}`,
    );
  }

  // ECDSA P-384 signing segment: the P-256 segment above
  // shows the narrower NIST curve, but the library's wider
  // curve — `ecdsa-p384-sha384`, RFC 9421 §3.3.5 — was
  // never shown. A P-384 key pair from
  // `generateP384KeyPair` (the generator the ecdsa tests
  // and bench corpus use) signs the same fixed payment
  // request under the segment's own keyid and nonce,
  // verification passes, and the same one-byte body tamper
  // as the main line (amount 100 -> 101) is rejected
  // because the covered `content-digest` no longer matches
  // the body. Its signatures are the 96-octet raw r||s
  // form (48 octets per limb), against the P-256 segment's
  // 64-octet form. Outside the printed lines the demo
  // asserts the verified identity (label, keyid, alg,
  // nonce) and the tamper code equal the hand-pinned
  // DEMO_P384_* expectations — a mismatch throws instead
  // of printing a misleading segment. No key bytes are
  // printed.
  const p384KeyPair = generateP384KeyPair();
  const p384Signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P384_KEY_ID,
      alg: "ecdsa-p384-sha384",
      key: p384KeyPair.privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P384_NONCE,
    },
  );
  const p384Verification = verifyRequest(p384Signed, {
    key: p384KeyPair.publicKey,
    now: DEMO_CREATED + 60,
  });
  const p384TamperedVerification = verifyRequest(
    { ...p384Signed, body: DEMO_TAMPERED_BODY },
    { key: p384KeyPair.publicKey, now: DEMO_CREATED + 60 },
  );
  if (
    !p384Verification.ok ||
    p384Verification.label !== DEMO_P384_LABEL ||
    p384Verification.keyId !== DEMO_P384_KEY_ID ||
    p384Verification.alg !== DEMO_P384_ALG ||
    p384Verification.nonce !== DEMO_P384_NONCE ||
    p384TamperedVerification.ok ||
    p384TamperedVerification.code !== DEMO_P384_TAMPERED_CODE
  ) {
    throw new Error(
      `demo fixture broken: P-384 verification ` +
        `${p384Verification.ok}/${p384Verification.label}/${p384Verification.keyId}/` +
        `${p384Verification.alg}/${p384Verification.nonce} with tamper code ` +
        `${p384TamperedVerification.code}, instead of the pinned ` +
        `true/${DEMO_P384_LABEL}/${DEMO_P384_KEY_ID}/${DEMO_P384_ALG}/` +
        `${DEMO_P384_NONCE} with tamper code ${DEMO_P384_TAMPERED_CODE}`,
    );
  }

  // Signature-Input parsing segment: every verification
  // above consumed the parsed parameters only inside
  // `verifyRequest`, but a receiver debugging an inbound
  // request reads the parse layer directly. The main
  // signed request's `signature-input` value is read back
  // raw with `getHeaderRaw` (no trimming or normalization)
  // and parsed with `parseSignatureInput` for the main
  // label. Outside the printed lines the demo asserts the
  // raw value, its printed preview, the parsed label,
  // every parsed parameter and the covered components
  // equal the hand-pinned DEMO_PARSE_* expectations — a
  // mismatch throws instead of printing a misleading
  // segment. A detached copy of the raw value with its
  // closing parenthesis removed is parsed too: the inner
  // list is unterminated, so the parser throws the pinned
  // error — the fail-closed shape a receiver sees on a
  // truncated header.
  const signatureInputRaw = getHeaderRaw(signed.headers, "signature-input");
  if (signatureInputRaw === undefined) {
    throw new Error(
      "demo fixture broken: main signed request carries no signature-input header",
    );
  }
  const signatureInputPreview = signatureInputRaw.slice(
    0,
    DEMO_PARSE_PREVIEW_CHARS,
  );
  const parsedSignatureInput = parseSignatureInput(
    signatureInputRaw,
    DEMO_PARSE_LABEL,
  );
  const tamperedInput = signatureInputRaw.slice(
    0,
    signatureInputRaw.indexOf(")"),
  );
  let parseTamperedError = "";
  try {
    parseSignatureInput(tamperedInput, DEMO_PARSE_LABEL);
  } catch (e) {
    parseTamperedError = e instanceof Error ? e.message : String(e);
  }
  if (
    signatureInputRaw !== DEMO_PARSE_RAW_INPUT ||
    signatureInputPreview !== DEMO_PARSE_RAW_PREVIEW ||
    parsedSignatureInput.label !== DEMO_PARSE_LABEL ||
    parsedSignatureInput.componentIds.length !==
      DEMO_COVERED_COMPONENTS.length ||
    parsedSignatureInput.componentIds.some(
      (c, i) => c !== DEMO_COVERED_COMPONENTS[i],
    ) ||
    parsedSignatureInput.params.created !== DEMO_PARSE_CREATED ||
    parsedSignatureInput.params.keyid !== DEMO_PARSE_KEY_ID ||
    parsedSignatureInput.params.alg !== DEMO_PARSE_ALG ||
    parsedSignatureInput.params.nonce !== DEMO_PARSE_NONCE ||
    parsedSignatureInput.params.expires !== undefined ||
    parseTamperedError !== DEMO_PARSE_TAMPERED_ERROR
  ) {
    throw new Error(
      `demo fixture broken: Signature-Input parsing gave ` +
        `raw=${JSON.stringify(signatureInputRaw)}, ` +
        `parsed=${JSON.stringify(parsedSignatureInput)}, ` +
        `tamper error=${JSON.stringify(parseTamperedError)}, ` +
        `instead of the pinned raw=${JSON.stringify(DEMO_PARSE_RAW_INPUT)}, ` +
        `label=${DEMO_PARSE_LABEL}, components=${JSON.stringify(DEMO_COVERED_COMPONENTS)}, ` +
        `created=${DEMO_PARSE_CREATED}, keyid=${DEMO_PARSE_KEY_ID}, ` +
        `alg=${DEMO_PARSE_ALG}, nonce=${DEMO_PARSE_NONCE}, ` +
        `tamper error=${JSON.stringify(DEMO_PARSE_TAMPERED_ERROR)}`,
    );
  }

  // ECDSA P-521 signing segment: the P-256 and P-384
  // segments above show the two narrower NIST curves, but
  // the library's widest curve — `ecdsa-p521-sha512`,
  // RFC 9421 §3.3.6 — was never shown. A P-521 key pair
  // from `generateP521KeyPair` (the generator the ecdsa
  // tests and bench corpus use) signs the same fixed
  // payment request under the segment's own keyid and
  // nonce, verification passes, and the same one-byte body
  // tamper as the main line (amount 100 -> 101) is rejected
  // because the covered `content-digest` no longer matches
  // the body. Its signatures are the 132-octet raw r||s
  // form (66 octets per limb), completing the ladder
  // against the P-256 segment's 64-octet form and the
  // P-384 segment's 96-octet form. Outside the printed
  // lines the demo asserts the verified identity (label,
  // keyid, alg, nonce) and the tamper code equal the
  // hand-pinned DEMO_P521_* expectations — a mismatch
  // throws instead of printing a misleading segment. No
  // key bytes are printed.
  const p521KeyPair = generateP521KeyPair();
  const p521Signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_P521_KEY_ID,
      alg: "ecdsa-p521-sha512",
      key: p521KeyPair.privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_P521_NONCE,
    },
  );
  const p521Verification = verifyRequest(p521Signed, {
    key: p521KeyPair.publicKey,
    now: DEMO_CREATED + 60,
  });
  const p521TamperedVerification = verifyRequest(
    { ...p521Signed, body: DEMO_TAMPERED_BODY },
    { key: p521KeyPair.publicKey, now: DEMO_CREATED + 60 },
  );
  if (
    !p521Verification.ok ||
    p521Verification.label !== DEMO_P521_LABEL ||
    p521Verification.keyId !== DEMO_P521_KEY_ID ||
    p521Verification.alg !== DEMO_P521_ALG ||
    p521Verification.nonce !== DEMO_P521_NONCE ||
    p521TamperedVerification.ok ||
    p521TamperedVerification.code !== DEMO_P521_TAMPERED_CODE
  ) {
    throw new Error(
      `demo fixture broken: P-521 verification ` +
        `${p521Verification.ok}/${p521Verification.label}/${p521Verification.keyId}/` +
        `${p521Verification.alg}/${p521Verification.nonce} with tamper code ` +
        `${p521TamperedVerification.code}, instead of the pinned ` +
        `true/${DEMO_P521_LABEL}/${DEMO_P521_KEY_ID}/${DEMO_P521_ALG}/` +
        `${DEMO_P521_NONCE} with tamper code ${DEMO_P521_TAMPERED_CODE}`,
    );
  }

  // Component-resolution segment: the signature-base segment
  // above prints the finished base, but a reader never sees
  // how one covered component becomes one base line. Each
  // covered component of the main signed request is resolved
  // with `resolveComponent` — the per-component resolver
  // `buildSignatureBase` applies — against the signed request
  // itself and the main line's fixed signature parameters:
  // the derived components resolve from the request target
  // (`@method` uppercased, `@authority` lowercased, `@path`
  // from the URL) and `content-digest` from its normalized
  // field value on the signed request. A detached illegal
  // component id (`content-digest` carrying the unsupported
  // `;zz` parameter) is resolved as well: the resolver throws
  // before producing any value, because an unsupported
  // parameter silently ignored would rebuild a different
  // base than the signer signed. Outside the printed lines
  // the demo asserts every resolved value and the rejection
  // message equal the hand-pinned DEMO_RESOLVE_* expectations
  // — a mismatch throws instead of printing a misleading
  // segment. Every input is a fixed demo constant.
  const resolveParams: SignatureParams = {
    created: DEMO_CREATED,
    keyid: DEMO_KEY_ID,
    alg: "ed25519",
    nonce: DEMO_NONCE,
  };
  const resolvedComponents = DEMO_RESOLVE_COMPONENTS.map(
    ({ component }) => ({
      component,
      value: resolveComponent(component, signed, resolveParams),
    }),
  );
  let resolveIllegalComponentError = "";
  try {
    resolveComponent(DEMO_RESOLVE_ILLEGAL_COMPONENT, signed, resolveParams);
  } catch (err) {
    resolveIllegalComponentError =
      err instanceof Error ? err.message : String(err);
  }
  if (
    resolvedComponents.some(
      (r, i) => r.value !== DEMO_RESOLVE_COMPONENTS[i].expected,
    ) ||
    resolveIllegalComponentError !== DEMO_RESOLVE_ILLEGAL_ERROR
  ) {
    throw new Error(
      `demo fixture broken: component resolution ` +
        `${JSON.stringify(resolvedComponents)} with illegal-component error ` +
        `${JSON.stringify(resolveIllegalComponentError)}, instead of the pinned ` +
        `${JSON.stringify(DEMO_RESOLVE_COMPONENTS)} with error ` +
        `${JSON.stringify(DEMO_RESOLVE_ILLEGAL_ERROR)}`,
    );
  }

  // Multi-value header combination segment: the inbound
  // segment above carries a multi-value field through the
  // Node adapter, but the combination rule itself — how
  // repeated field values become the single value a
  // signature-base line carries — was never shown. A fixed
  // request carries `DEMO_JOIN_HEADER` twice, as the padded
  // array `DEMO_JOIN_VALUES`; `joinHeaderValues` combines
  // it (each element trimmed, joined with ", " per
  // RFC 9421 §2.5) and the signer emits exactly that
  // combination as the field's wire value. A request signed
  // over the repeated field verifies; the same request with
  // the field replaced by the hand-pinned wrong combination
  // (a bare comma join, the space after the comma dropped)
  // is rejected with `SIGNATURE_MISMATCH`, because the
  // verifier rebuilds a different signature base from the
  // wrongly joined value. Outside the printed lines the
  // demo asserts the combination character for character,
  // the signer's emitted wire value, the verified identity
  // and the rejection code equal the hand-pinned
  // DEMO_JOIN_* expectations (the same combination shape
  // and code `test/multiValueHeaderWhitespace.test.ts` pins
  // for its own padded fixture). Every input is a fixed
  // demo constant.
  const joinedHeaderValue = joinHeaderValues(DEMO_JOIN_VALUES);
  const joinSigned = signRequest(
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
  const joinVerification = verifyRequest(joinSigned, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });
  const joinWrongVerification = verifyRequest(
    {
      ...joinSigned,
      headers: {
        ...joinSigned.headers,
        [DEMO_JOIN_HEADER]: DEMO_JOIN_WRONG_VALUE,
      },
    },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );
  if (
    joinedHeaderValue !== DEMO_JOIN_EXPECTED ||
    joinSigned.headers[DEMO_JOIN_HEADER] !== DEMO_JOIN_EXPECTED ||
    !joinVerification.ok ||
    joinVerification.label !== DEMO_JOIN_LABEL ||
    joinVerification.keyId !== DEMO_KEY_ID ||
    joinVerification.alg !== "ed25519" ||
    joinVerification.nonce !== DEMO_JOIN_NONCE ||
    joinWrongVerification.ok ||
    joinWrongVerification.code !== DEMO_JOIN_WRONG_CODE
  ) {
    throw new Error(
      `demo fixture broken: multi-value combination ` +
        `${JSON.stringify(joinedHeaderValue)} with wire value ` +
        `${JSON.stringify(joinSigned.headers[DEMO_JOIN_HEADER])}, verification ` +
        `${joinVerification.ok}/${joinVerification.label}/${joinVerification.keyId}/` +
        `${joinVerification.alg}/${joinVerification.nonce} and wrong-join code ` +
        `${joinWrongVerification.code}, instead of the pinned ` +
        `${JSON.stringify(DEMO_JOIN_EXPECTED)} with wire value ` +
        `${JSON.stringify(DEMO_JOIN_EXPECTED)}, verification ` +
        `true/${DEMO_JOIN_LABEL}/${DEMO_KEY_ID}/ed25519/` +
        `${DEMO_JOIN_NONCE} and wrong-join code ${DEMO_JOIN_WRONG_CODE}`,
    );
  }

  // Signature field parsing segment: the Signature-Input
  // parsing segment above shows how a receiver reads the
  // parameters, but the signature bytes themselves were
  // only ever consumed inside `verifyRequest`. Here the
  // main signed request's `signature` value is parsed with
  // `parseSignatureField` for the main label — the
  // byte-string member lookup a verifier performs before
  // the cryptographic check. Outside the printed lines the
  // demo asserts the extracted bytes equal, byte for byte,
  // the bytes the signer emitted: the expectation is
  // decoded independently here, by slicing the header's
  // single `label=:base64:` member and base64-decoding it
  // without the parser under test, and the extracted length
  // must equal the pinned ed25519 length. The same field
  // is parsed for a hand-pinned unknown label as well: the
  // parser throws the pinned not-present error — the
  // fail-closed shape a receiver sees on a label it did
  // not negotiate. Only the extracted length and a short
  // hexadecimal prefix are printed, never the full
  // signature; the main key pair is fresh on every run, so
  // the prefix differs between runs while its shape and
  // the rejection are stable.
  const signatureFieldValue = signed.headers["signature"];
  const signatureFieldBytes = parseSignatureField(
    signatureFieldValue,
    DEMO_SIGFIELD_LABEL,
  );
  const signatureFieldHexPrefix = signatureFieldBytes
    .subarray(0, DEMO_SIGFIELD_PREFIX_BYTES)
    .toString("hex");
  const signerEmittedPrefix = `${DEMO_SIGFIELD_LABEL}=:`;
  const signerEmittedBytes =
    signatureFieldValue.startsWith(signerEmittedPrefix) &&
    signatureFieldValue.endsWith(":")
      ? Buffer.from(
          signatureFieldValue.slice(signerEmittedPrefix.length, -1),
          "base64",
        )
      : Buffer.alloc(0);
  let signatureFieldUnknownError = "";
  try {
    parseSignatureField(signatureFieldValue, DEMO_SIGFIELD_UNKNOWN_LABEL);
  } catch (e) {
    signatureFieldUnknownError = e instanceof Error ? e.message : String(e);
  }
  if (
    signatureFieldBytes.length !== DEMO_SIGFIELD_BYTES ||
    !signatureFieldBytes.equals(signerEmittedBytes) ||
    signatureFieldHexPrefix !==
      signerEmittedBytes
        .subarray(0, DEMO_SIGFIELD_PREFIX_BYTES)
        .toString("hex") ||
    signatureFieldUnknownError !== DEMO_SIGFIELD_UNKNOWN_ERROR
  ) {
    throw new Error(
      `demo fixture broken: Signature field parsing gave ` +
        `${signatureFieldBytes.length} bytes with hex prefix ` +
        `${JSON.stringify(signatureFieldHexPrefix)} and unknown-label error ` +
        `${JSON.stringify(signatureFieldUnknownError)}, instead of the pinned ` +
        `${DEMO_SIGFIELD_BYTES} bytes byte-equal to the signer's emitted bytes ` +
        `with unknown-label error ${JSON.stringify(DEMO_SIGFIELD_UNKNOWN_ERROR)}`,
    );
  }

  // EC JWK key distribution segment: the JWK import segment
  // above covers only the ed25519 (OKP) form, but gateways
  // and webhook verifiers distribute EC keys as JWKs
  // (`kty: "EC"` + `crv` + `x`/`y`). One fresh key pair is
  // generated per NIST curve (generation is not printed),
  // each public key is exported with its curve's
  // `exportPublicKeyJwkP*` helper, carried through a JSON
  // stringify/parse round-trip exactly as it would cross
  // the wire, and read back with the matching
  // `importPublicKeyJwkP*` helper; the segment's request
  // for that curve is then signed with the fresh private
  // key and verified with the imported public key.
  // Outside the printed lines the demo asserts every
  // exported JWK's shape (kty, crv, both coordinate
  // lengths) and every verified identity (label, keyid,
  // alg, nonce) equal the hand-pinned DEMO_EC_JWK_CURVES
  // expectations. The segment's P-256 JWK is also fed to
  // the P-384 importer: it throws the pinned crv-mismatch
  // error — the per-curve helpers are deliberately
  // separate so a key can never be silently re-interpreted
  // on the wrong curve. Only kty/crv and the `x` length
  // are printed per curve, never key bytes, so the printed
  // lines are identical between runs even though the key
  // pairs themselves are fresh.
  const ecJwkSpecs = [
    {
      expected: DEMO_EC_JWK_CURVES[0]!,
      generate: generateP256KeyPair,
      exportJwk: exportPublicKeyJwkP256,
      importJwk: importPublicKeyJwkP256,
    },
    {
      expected: DEMO_EC_JWK_CURVES[1]!,
      generate: generateP384KeyPair,
      exportJwk: exportPublicKeyJwkP384,
      importJwk: importPublicKeyJwkP384,
    },
    {
      expected: DEMO_EC_JWK_CURVES[2]!,
      generate: generateP521KeyPair,
      exportJwk: exportPublicKeyJwkP521,
      importJwk: importPublicKeyJwkP521,
    },
  ] as const;
  const ecJwkExports: Array<
    P256PublicJwk | P384PublicJwk | P521PublicJwk
  > = [];
  const ecJwkSigned: SignedHttpRequest[] = [];
  const ecJwkVerifications: VerifyResult[] = [];
  for (const spec of ecJwkSpecs) {
    const pair = spec.generate();
    const exported = spec.exportJwk(pair.publicKey);
    const received = JSON.parse(JSON.stringify(exported)) as unknown;
    const imported = spec.importJwk(received);
    const curveSigned = signRequest(
      {
        method: "POST",
        url: "https://api.example.com/v1/payments",
        headers: { "content-type": "application/json" },
        body: DEMO_BODY,
      },
      {
        keyId: spec.expected.keyId,
        alg: spec.expected.alg,
        key: pair.privateKey,
        created: DEMO_CREATED,
        nonce: spec.expected.nonce,
      },
    );
    const curveVerification = verifyRequest(curveSigned, {
      key: imported,
      now: DEMO_CREATED + 60,
    });
    if (
      exported.kty !== "EC" ||
      exported.crv !== spec.expected.crv ||
      exported.x.length !== spec.expected.xLength ||
      exported.y.length !== spec.expected.yLength ||
      !curveVerification.ok ||
      curveVerification.label !== DEMO_EC_JWK_LABEL ||
      curveVerification.keyId !== spec.expected.keyId ||
      curveVerification.alg !== spec.expected.alg ||
      curveVerification.nonce !== spec.expected.nonce
    ) {
      throw new Error(
        `demo fixture broken: EC JWK ${spec.expected.crv} gave ` +
          `kty=${JSON.stringify(exported.kty)} crv=${JSON.stringify(exported.crv)} ` +
          `x=${exported.x.length} y=${exported.y.length} with verification ` +
          `${curveVerification.ok}/${curveVerification.label}/${curveVerification.keyId}/` +
          `${curveVerification.alg}/${curveVerification.nonce}, instead of the pinned ` +
          `kty="EC" crv="${spec.expected.crv}" x=${spec.expected.xLength} ` +
          `y=${spec.expected.yLength} with verification ` +
          `true/${DEMO_EC_JWK_LABEL}/${spec.expected.keyId}/${spec.expected.alg}/` +
          `${spec.expected.nonce}`,
      );
    }
    ecJwkExports.push(exported);
    ecJwkSigned.push(curveSigned);
    ecJwkVerifications.push(curveVerification);
  }
  let ecJwkMismatchError = "";
  try {
    importPublicKeyJwkP384(ecJwkExports[0]);
  } catch (e) {
    ecJwkMismatchError = e instanceof Error ? e.message : String(e);
  }
  if (ecJwkMismatchError !== DEMO_EC_JWK_MISMATCH_ERROR) {
    throw new Error(
      `demo fixture broken: EC JWK crv mismatch gave error ` +
        `${JSON.stringify(ecJwkMismatchError)}, instead of the pinned ` +
        `${JSON.stringify(DEMO_EC_JWK_MISMATCH_ERROR)}`,
    );
  }

  // RSA JWK key distribution segment: the JWK segments
  // above cover the ed25519 (OKP) and EC forms, but JWKS
  // documents most often carry RSA members (`kty: "RSA"`
  // + `n`/`e`). The segment's RSA public key (the pair is
  // generated once per process — see `rsaJwkPair`) is
  // exported with `exportPublicKeyJwkRsa`, carried
  // through a JSON stringify/parse round-trip exactly as
  // it would cross the wire, and read back with
  // `importPublicKeyJwkRsa`; the segment's request is
  // then signed with the pair's private key under
  // `rsa-pss-sha512` and verified with the imported
  // public key. Outside the printed lines the demo
  // asserts the exported JWK's shape (kty, the pinned
  // 342-character `n` length of a 2048-bit modulus, the
  // `AQAB` exponent) and the verified identity (label,
  // keyid, alg, nonce) equal the hand-pinned
  // DEMO_RSA_JWK_* expectations. The EC segment's P-256
  // JWK is also fed to the RSA importer: it throws the
  // pinned kty-mismatch error — the per-shape helpers
  // are deliberately separate so a key can never be
  // silently re-interpreted under the wrong key type.
  // Only the JWK's kty and `n`/`e` lengths are printed,
  // never the full modulus, so the printed lines are
  // identical between runs.
  const rsaJwkExported = exportPublicKeyJwkRsa(rsaJwkPair().publicKey);
  const rsaJwkReceived = JSON.parse(
    JSON.stringify(rsaJwkExported),
  ) as unknown;
  const rsaJwkImported = importPublicKeyJwkRsa(rsaJwkReceived);
  const rsaJwkSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_RSA_JWK_KEY_ID,
      alg: DEMO_RSA_JWK_ALG,
      key: rsaJwkPair().privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_RSA_JWK_NONCE,
    },
  );
  const rsaJwkVerification = verifyRequest(rsaJwkSigned, {
    key: rsaJwkImported,
    now: DEMO_CREATED + 60,
  });
  if (
    rsaJwkExported.kty !== "RSA" ||
    rsaJwkExported.n.length !== DEMO_RSA_JWK_N_LENGTH ||
    rsaJwkExported.e !== DEMO_RSA_JWK_E ||
    rsaJwkExported.e.length !== DEMO_RSA_JWK_E_LENGTH ||
    !rsaJwkVerification.ok ||
    rsaJwkVerification.label !== DEMO_RSA_JWK_LABEL ||
    rsaJwkVerification.keyId !== DEMO_RSA_JWK_KEY_ID ||
    rsaJwkVerification.alg !== DEMO_RSA_JWK_ALG ||
    rsaJwkVerification.nonce !== DEMO_RSA_JWK_NONCE
  ) {
    throw new Error(
      `demo fixture broken: RSA JWK gave ` +
        `kty=${JSON.stringify(rsaJwkExported.kty)} ` +
        `n=${rsaJwkExported.n.length} e=${JSON.stringify(rsaJwkExported.e)} ` +
        `with verification ` +
        `${rsaJwkVerification.ok}/${rsaJwkVerification.label}/` +
        `${rsaJwkVerification.keyId}/${rsaJwkVerification.alg}/` +
        `${rsaJwkVerification.nonce}, instead of the pinned ` +
        `kty="RSA" n=${DEMO_RSA_JWK_N_LENGTH} e="${DEMO_RSA_JWK_E}" ` +
        `with verification ` +
        `true/${DEMO_RSA_JWK_LABEL}/${DEMO_RSA_JWK_KEY_ID}/` +
        `${DEMO_RSA_JWK_ALG}/${DEMO_RSA_JWK_NONCE}`,
    );
  }
  let rsaJwkMismatchError = "";
  try {
    importPublicKeyJwkRsa(ecJwkExports[0]);
  } catch (e) {
    rsaJwkMismatchError = e instanceof Error ? e.message : String(e);
  }
  if (rsaJwkMismatchError !== DEMO_RSA_JWK_MISMATCH_ERROR) {
    throw new Error(
      `demo fixture broken: RSA JWK kty mismatch gave error ` +
        `${JSON.stringify(rsaJwkMismatchError)}, instead of the pinned ` +
        `${JSON.stringify(DEMO_RSA_JWK_MISMATCH_ERROR)}`,
    );
  }

  // JWKS refresh and rotation segment: the JWKS segment
  // above restores a snapshot and never fetches, so it
  // cannot show the moment a verifier picks up a key
  // rotation. This segment drives a JwksKeyStore through
  // refreshIfStale() with a counting fake fetch (a scripted
  // function — zero network, the configured endpoint is
  // never contacted) and an injected clock the segment
  // advances by hand between the demo's fixed instants.
  // The fake endpoint first serves only the pre-rotation
  // key: the initial refreshIfStale() (a never-refreshed
  // store is stale) fetches it, and a request signed under
  // the old keyid verifies through the store's resolver.
  // Probed again 60 seconds into the 120-second TTL, the
  // snapshot is fresh: refreshIfStale() returns false and
  // the fetch count does not move. The segment then flips
  // the fake endpoint to serve only the rotated key and
  // advances the clock past the TTL: refreshIfStale()
  // returns true, exactly one more fetch happens, a
  // request signed under the new keyid verifies, and the
  // pre-rotation request — its signature still valid — is
  // rejected with KEY_RESOLUTION_FAILED because the
  // retired keyid no longer resolves. Both segment key
  // pairs are fresh ed25519 pairs (generation is not
  // printed); outside the printed lines the demo asserts
  // every return value, fetch count and verified identity
  // equal the hand-pinned DEMO_JWKS_REFRESH_* expectations.
  const jwksRefreshOldPair = generateEd25519KeyPair();
  const jwksRefreshNewPair = generateEd25519KeyPair();
  let jwksRefreshRotated = false;
  let jwksRefreshFetchCalls = 0;
  let jwksRefreshNowSec = DEMO_CREATED;
  const jwksRefreshStore = new JwksKeyStore(DEMO_JWKS_URL, {
    fetchImpl: async () => {
      jwksRefreshFetchCalls++;
      const pair = jwksRefreshRotated
        ? jwksRefreshNewPair
        : jwksRefreshOldPair;
      const kid = jwksRefreshRotated
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
    now: () => jwksRefreshNowSec,
  });
  const jwksRefreshInitialRefreshed =
    await jwksRefreshStore.refreshIfStale();
  const jwksRefreshFetchCallsAfterLoad = jwksRefreshFetchCalls;
  const jwksRefreshOldSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_JWKS_REFRESH_OLD_KEY_ID,
      alg: "ed25519",
      key: jwksRefreshOldPair.privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_JWKS_REFRESH_OLD_NONCE,
    },
  );
  const jwksRefreshOldVerification = verifyRequest(jwksRefreshOldSigned, {
    keyResolver: jwksRefreshStore.resolve,
    now: DEMO_CREATED + 60,
  });
  jwksRefreshNowSec = DEMO_JWKS_REFRESH_FRESH_AT_SEC;
  const jwksRefreshFreshRefreshed =
    await jwksRefreshStore.refreshIfStale();
  const jwksRefreshFetchCallsAfterFresh = jwksRefreshFetchCalls;
  jwksRefreshRotated = true;
  jwksRefreshNowSec = DEMO_JWKS_REFRESH_STALE_AT_SEC;
  const jwksRefreshStaleRefreshed =
    await jwksRefreshStore.refreshIfStale();
  const jwksRefreshFetchCallsAfterRotation = jwksRefreshFetchCalls;
  const jwksRefreshNewSigned = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_JWKS_REFRESH_NEW_KEY_ID,
      alg: "ed25519",
      key: jwksRefreshNewPair.privateKey,
      created: DEMO_JWKS_REFRESH_STALE_AT_SEC,
      nonce: DEMO_JWKS_REFRESH_NEW_NONCE,
    },
  );
  const jwksRefreshNewVerification = verifyRequest(jwksRefreshNewSigned, {
    keyResolver: jwksRefreshStore.resolve,
    now: DEMO_JWKS_REFRESH_STALE_AT_SEC + 60,
  });
  const jwksRefreshRetiredVerification = verifyRequest(
    jwksRefreshOldSigned,
    {
      keyResolver: jwksRefreshStore.resolve,
      now: DEMO_CREATED + 60,
    },
  );
  if (
    jwksRefreshInitialRefreshed !== true ||
    jwksRefreshFetchCallsAfterLoad !==
      DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD ||
    !jwksRefreshOldVerification.ok ||
    jwksRefreshOldVerification.label !== DEMO_JWKS_REFRESH_LABEL ||
    jwksRefreshOldVerification.keyId !== DEMO_JWKS_REFRESH_OLD_KEY_ID ||
    jwksRefreshOldVerification.alg !== "ed25519" ||
    jwksRefreshOldVerification.nonce !== DEMO_JWKS_REFRESH_OLD_NONCE ||
    jwksRefreshFreshRefreshed !== false ||
    jwksRefreshFetchCallsAfterFresh !==
      DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD ||
    jwksRefreshStaleRefreshed !== true ||
    jwksRefreshFetchCallsAfterRotation !==
      DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION ||
    !jwksRefreshNewVerification.ok ||
    jwksRefreshNewVerification.label !== DEMO_JWKS_REFRESH_LABEL ||
    jwksRefreshNewVerification.keyId !== DEMO_JWKS_REFRESH_NEW_KEY_ID ||
    jwksRefreshNewVerification.alg !== "ed25519" ||
    jwksRefreshNewVerification.nonce !== DEMO_JWKS_REFRESH_NEW_NONCE ||
    jwksRefreshRetiredVerification.ok ||
    jwksRefreshRetiredVerification.code !==
      DEMO_JWKS_REFRESH_RETIRED_CODE
  ) {
    throw new Error(
      `demo fixture broken: JWKS refresh gave initial ` +
        `${jwksRefreshInitialRefreshed}/${jwksRefreshFetchCallsAfterLoad} with old verification ` +
        `${jwksRefreshOldVerification.ok}/${jwksRefreshOldVerification.ok ? jwksRefreshOldVerification.label : jwksRefreshOldVerification.code}/` +
        `${jwksRefreshOldVerification.ok ? jwksRefreshOldVerification.keyId : "-"}/` +
        `${jwksRefreshOldVerification.ok ? jwksRefreshOldVerification.nonce : "-"}, fresh ` +
        `${jwksRefreshFreshRefreshed}/${jwksRefreshFetchCallsAfterFresh}, stale ` +
        `${jwksRefreshStaleRefreshed}/${jwksRefreshFetchCallsAfterRotation} with new verification ` +
        `${jwksRefreshNewVerification.ok}/${jwksRefreshNewVerification.ok ? jwksRefreshNewVerification.label : jwksRefreshNewVerification.code}/` +
        `${jwksRefreshNewVerification.ok ? jwksRefreshNewVerification.keyId : "-"}/` +
        `${jwksRefreshNewVerification.ok ? jwksRefreshNewVerification.nonce : "-"} and retired ` +
        `${jwksRefreshRetiredVerification.ok}/${jwksRefreshRetiredVerification.ok ? "-" : jwksRefreshRetiredVerification.code}, instead of the pinned ` +
        `initial true/${DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD} with old verification ` +
        `true/${DEMO_JWKS_REFRESH_LABEL}/${DEMO_JWKS_REFRESH_OLD_KEY_ID}/` +
        `${DEMO_JWKS_REFRESH_OLD_NONCE}, fresh ` +
        `false/${DEMO_JWKS_REFRESH_CALLS_AFTER_LOAD}, stale ` +
        `true/${DEMO_JWKS_REFRESH_CALLS_AFTER_ROTATION} with new verification ` +
        `true/${DEMO_JWKS_REFRESH_LABEL}/${DEMO_JWKS_REFRESH_NEW_KEY_ID}/` +
        `${DEMO_JWKS_REFRESH_NEW_NONCE} and retired ` +
        `false/${DEMO_JWKS_REFRESH_RETIRED_CODE}`,
    );
  }

  // Header lookup segment: every earlier segment read
  // headers through a full sign/verify path, so the lookup
  // primitive those paths share was never shown on its own.
  // The segment's fixed record carries one field under a
  // mixed-case key as a padded two-element array and one
  // single string field. `getHeader` — the normalized read
  // the verifier itself uses — finds the multi-value field
  // under a differently-cased lookup name and returns its
  // canonical value (each element trimmed, joined with
  // ", " via `joinHeaderValues`); `getHeaderRaw` over the
  // same record returns the field exactly as stored, every
  // element's padding preserved — the raw read a `;bs`
  // component binds, and the difference between the two
  // reads is a classic signature-interop pitfall. A single
  // string value comes back exactly as stored from the
  // normalized read (only array values go through the
  // trimming combination), and a field the record does not
  // carry comes back `undefined` from both reads. Outside
  // the printed lines the demo asserts every result equals
  // the hand-pinned DEMO_GET_HEADER_* expectations. Every
  // input is a fixed demo constant.
  const getHeaderHeaders: Record<string, string | string[]> = {
    [DEMO_GET_HEADER_STORED_NAME]: [...DEMO_GET_HEADER_VALUES],
    [DEMO_GET_HEADER_SINGLE_STORED_NAME]: DEMO_GET_HEADER_SINGLE_VALUE,
  };
  const getHeaderValue = getHeader(
    getHeaderHeaders,
    DEMO_GET_HEADER_LOOKUP_NAME,
  );
  const getHeaderRawValue = getHeaderRaw(
    getHeaderHeaders,
    DEMO_GET_HEADER_LOOKUP_NAME,
  );
  const getHeaderSingleValue = getHeader(
    getHeaderHeaders,
    DEMO_GET_HEADER_SINGLE_LOOKUP_NAME,
  );
  const getHeaderMissingValue = getHeader(
    getHeaderHeaders,
    DEMO_GET_HEADER_MISSING_NAME,
  );
  const getHeaderRawMissingValue = getHeaderRaw(
    getHeaderHeaders,
    DEMO_GET_HEADER_MISSING_NAME,
  );
  if (
    getHeaderValue !== DEMO_GET_HEADER_EXPECTED ||
    getHeaderRawValue !== DEMO_GET_HEADER_RAW_EXPECTED ||
    getHeaderSingleValue !== DEMO_GET_HEADER_SINGLE_VALUE ||
    getHeaderMissingValue !== undefined ||
    getHeaderRawMissingValue !== undefined
  ) {
    throw new Error(
      `demo fixture broken: header lookup gave normalized ` +
        `${JSON.stringify(getHeaderValue)}, raw ` +
        `${JSON.stringify(getHeaderRawValue)}, single ` +
        `${JSON.stringify(getHeaderSingleValue)} and missing ` +
        `${JSON.stringify(getHeaderMissingValue)}/` +
        `${JSON.stringify(getHeaderRawMissingValue)}, instead of the pinned ` +
        `${JSON.stringify(DEMO_GET_HEADER_EXPECTED)}, raw ` +
        `${JSON.stringify(DEMO_GET_HEADER_RAW_EXPECTED)}, single ` +
        `${JSON.stringify(DEMO_GET_HEADER_SINGLE_VALUE)} and missing ` +
        `undefined/undefined`,
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
    "",
    "ECDSA P-256 signing: ecdsa-p256-sha256 signs the same fixed payment request with a P-256 key — the NIST curve line the ed25519 main line and the hmac-sha256 gateway line never showed",
    `P-256 Signature-Input: ${p256Signed.headers["signature-input"]}`,
    p256Verification.ok
      ? `P-256 verification: OK (label ${p256Verification.label}, keyid="${p256Verification.keyId}", alg="${p256Verification.alg}", nonce="${p256Verification.nonce}")`
      : `P-256 verification: FAILED (code ${p256Verification.code}: ${p256Verification.reason})`,
    p256TamperedVerification.ok
      ? "P-256 verification after tampering: OK (unexpected — tampering was not detected)"
      : `P-256 verification after tampering: FAILED (code ${p256TamperedVerification.code}: ${p256TamperedVerification.reason})`,
    "",
    "Content-Digest algorithm guard: assertContentDigestAlg enforces the emittable digest set before any hashing runs — only \"sha-512\" and \"sha-256\" pass, every other value is rejected as a caller configuration error",
    ...digestGuardAccepted.map(
      (a) =>
        `assertContentDigestAlg for ${a.label}: OK (emittable digest algorithm)`,
    ),
    ...digestGuardRejections.map(
      (r) =>
        `assertContentDigestAlg for ${r.label}: FAILED (${r.error})`,
    ),
    "",
    "ReplayCache snapshot persistence: exportSnapshot carries the seen nonces across a restart — ReplayCache.restore rebuilds the cache at startup, so a nonce seen before the restart is still a replay after it",
    replaySnapshotFirstVerification.ok
      ? `Replay snapshot, first verification of nonce "${DEMO_REPLAY_SNAPSHOT_NONCE}": OK (recorded in the segment's ReplayCache)`
      : `Replay snapshot, first verification of nonce "${DEMO_REPLAY_SNAPSHOT_NONCE}": FAILED (code ${replaySnapshotFirstVerification.code}: ${replaySnapshotFirstVerification.reason})`,
    `Exported ReplayCache snapshot: ${replaySnapshotExport.entries.length} entry in a v${replaySnapshotExport.v} snapshot (nonce "${DEMO_REPLAY_SNAPSHOT_NONCE}", first seen at ${DEMO_CREATED + 60})`,
    replaySnapshotReplayVerification.ok
      ? "Replay snapshot, same request against the restored cache: OK (unexpected — the restart reopened the replay window)"
      : `Replay snapshot, same request against the restored cache: FAILED (code ${replaySnapshotReplayVerification.code}: ${replaySnapshotReplayVerification.reason})`,
    replaySnapshotFreshVerification.ok
      ? `Replay snapshot, new request with nonce "${DEMO_REPLAY_SNAPSHOT_FRESH_NONCE}" against the restored cache: OK (a fresh nonce is not a replay — recorded only in the restored cache)`
      : `Replay snapshot, new request with nonce "${DEMO_REPLAY_SNAPSHOT_FRESH_NONCE}" against the restored cache: FAILED (code ${replaySnapshotFreshVerification.code}: ${replaySnapshotFreshVerification.reason})`,
    `Original ReplayCache after the restored cache recorded the fresh nonce: ${replaySnapshotOriginalSize} entry (restored cache: ${replaySnapshotRestoredSize} entries — the restore is detached, the original is unaffected)`,
    "",
    "ECDSA P-384 signing: ecdsa-p384-sha384 signs the same fixed payment request with a P-384 key — the wider NIST curve whose 96-byte raw signature the P-256 segment's 64-byte form never showed",
    `P-384 Signature-Input: ${p384Signed.headers["signature-input"]}`,
    p384Verification.ok
      ? `P-384 verification: OK (label ${p384Verification.label}, keyid="${p384Verification.keyId}", alg="${p384Verification.alg}", nonce="${p384Verification.nonce}")`
      : `P-384 verification: FAILED (code ${p384Verification.code}: ${p384Verification.reason})`,
    p384TamperedVerification.ok
      ? "P-384 verification after tampering: OK (unexpected — tampering was not detected)"
      : `P-384 verification after tampering: FAILED (code ${p384TamperedVerification.code}: ${p384TamperedVerification.reason})`,
    "",
    "Signature-Input parsing: parseSignatureInput exposes the parse layer a receiver debugs first — the raw header value, then the label, parameters and covered components the verifier rebuilds from it",
    `Raw Signature-Input (first ${DEMO_PARSE_PREVIEW_CHARS} of ${signatureInputRaw.length} chars): ${signatureInputPreview}…`,
    `Parsed ${parsedSignatureInput.label}: keyid="${parsedSignatureInput.params.keyid}", alg="${parsedSignatureInput.params.alg}", created=${parsedSignatureInput.params.created}, nonce="${parsedSignatureInput.params.nonce}"`,
    `Parsed covered components: ${parsedSignatureInput.componentIds.map((c) => `"${c}"`).join(" ")}`,
    `Tampered Signature-Input (closing parenthesis removed): FAILED (${parseTamperedError})`,
    "",
    "ECDSA P-521 signing: ecdsa-p521-sha512 signs the same fixed payment request with a P-521 key — the widest NIST curve, whose 132-byte raw signature completes the ladder the P-256 segment's 64-byte and the P-384 segment's 96-byte forms began",
    `P-521 Signature-Input: ${p521Signed.headers["signature-input"]}`,
    p521Verification.ok
      ? `P-521 verification: OK (label ${p521Verification.label}, keyid=\"${p521Verification.keyId}\", alg=\"${p521Verification.alg}\", nonce=\"${p521Verification.nonce}\")`
      : `P-521 verification: FAILED (code ${p521Verification.code}: ${p521Verification.reason})`,
    p521TamperedVerification.ok
      ? "P-521 verification after tampering: OK (unexpected — tampering was not detected)"
      : `P-521 verification after tampering: FAILED (code ${p521TamperedVerification.code}: ${p521TamperedVerification.reason})`,
    "",
    "Component resolution: resolveComponent turns each covered component into the exact value its signature-base line carries — derived components from the request target, header fields from the normalized field value",
    ...resolvedComponents.map((r) => `Resolve "${r.component}": ${r.value}`),
    `Resolve "${DEMO_RESOLVE_ILLEGAL_COMPONENT}": FAILED (${resolveIllegalComponentError})`,
    "",
    "Multi-value header combination: joinHeaderValues combines a repeated field's values into the single value its signature-base line carries — each element trimmed, the elements joined with \", \" (RFC 9421 §2.5), so signer, verifier and adapters can never disagree on the bytes",
    `Join "${DEMO_JOIN_HEADER}" values ${JSON.stringify(DEMO_JOIN_VALUES)}: ${joinedHeaderValue}`,
    joinVerification.ok
      ? `Multi-value verification: OK (label ${joinVerification.label}, keyid="${joinVerification.keyId}", alg="${joinVerification.alg}", nonce="${joinVerification.nonce}")`
      : `Multi-value verification: FAILED (code ${joinVerification.code}: ${joinVerification.reason})`,
    joinWrongVerification.ok
      ? `Multi-value verification with the wrong join "${DEMO_JOIN_WRONG_VALUE}" (space after the comma dropped): OK (unexpected — the wrong combination was not detected)`
      : `Multi-value verification with the wrong join "${DEMO_JOIN_WRONG_VALUE}" (space after the comma dropped): FAILED (code ${joinWrongVerification.code}: ${joinWrongVerification.reason})`,
    "",
    "Signature field parsing: parseSignatureField extracts the raw signature bytes for one label from the Signature field — the bytes a verifier feeds to the cryptographic check, decoded from their base64 byte-string wrapper",
    `Parsed Signature for label "${DEMO_SIGFIELD_LABEL}": ${signatureFieldBytes.length} bytes, hex prefix ${signatureFieldHexPrefix}… (only the prefix is printed — never the full signature)`,
    `Parsed Signature for unknown label "${DEMO_SIGFIELD_UNKNOWN_LABEL}": FAILED (${signatureFieldUnknownError})`,
    "",
    "EC JWK key distribution: exportPublicKeyJwkP256 / exportPublicKeyJwkP384 / exportPublicKeyJwkP521 ship each EC public key as a JWK (kty \"EC\", crv, x/y coordinates), a JSON wire round-trip carries it, and the matching importPublicKeyJwkP* reads it back — the EC key form gateways and webhook verifiers distribute most often",
    ...ecJwkExports.flatMap((jwk, i) => {
      const expected = DEMO_EC_JWK_CURVES[i]!;
      const v = ecJwkVerifications[i]!;
      return [
        `EC JWK ${jwk.crv}: kty="${jwk.kty}", crv="${jwk.crv}", x is ${jwk.x.length} base64url chars, y is ${jwk.y.length} base64url chars (the keys themselves are fresh per run; only their shapes are printed)`,
        v.ok
          ? `EC JWK ${expected.crv} round-trip verification: OK (label ${v.label}, keyid="${v.keyId}", alg="${v.alg}", nonce="${v.nonce}")`
          : `EC JWK ${expected.crv} round-trip verification: FAILED (code ${v.code}: ${v.reason})`,
      ];
    }),
    `EC JWK crv mismatch, P-256 JWK fed to importPublicKeyJwkP384: FAILED (${ecJwkMismatchError})`,
    "",
    "RSA JWK key distribution: exportPublicKeyJwkRsa ships the RSA public key as a JWK (kty \"RSA\", n/e), a JSON wire round-trip carries it, and importPublicKeyJwkRsa reads it back — the RSA member shape JWKS documents carry most often",
    `RSA JWK: kty="${rsaJwkExported.kty}", n is ${rsaJwkExported.n.length} base64url chars, e is ${rsaJwkExported.e.length} base64url chars ("${rsaJwkExported.e}") (the key itself is generated once per process; only its shape is printed — never the full modulus)`,
    rsaJwkVerification.ok
      ? `RSA JWK round-trip verification: OK (label ${rsaJwkVerification.label}, keyid="${rsaJwkVerification.keyId}", alg="${rsaJwkVerification.alg}", nonce="${rsaJwkVerification.nonce}")`
      : `RSA JWK round-trip verification: FAILED (code ${rsaJwkVerification.code}: ${rsaJwkVerification.reason})`,
    `RSA JWK kty mismatch, EC JWK (P-256) fed to importPublicKeyJwkRsa: FAILED (${rsaJwkMismatchError})`,
    "",
    "JWKS refresh and rotation: JwksKeyStore.refreshIfStale fetches only when the snapshot is stale — a counting fake JWKS fetch (zero network) and an injected clock show the store loading the pre-rotation key, refusing to re-fetch while fresh, then swapping in the rotated key once the TTL passes",
    `JWKS refresh initial load: refreshIfStale() returned ${jwksRefreshInitialRefreshed} (fetch count ${jwksRefreshFetchCallsAfterLoad})`,
    jwksRefreshOldVerification.ok
      ? `JWKS verification before rotation: OK (label ${jwksRefreshOldVerification.label}, keyid="${jwksRefreshOldVerification.keyId}", alg="${jwksRefreshOldVerification.alg}", nonce="${jwksRefreshOldVerification.nonce}")`
      : `JWKS verification before rotation: FAILED (code ${jwksRefreshOldVerification.code}: ${jwksRefreshOldVerification.reason})`,
    `JWKS refresh while fresh (${DEMO_JWKS_REFRESH_FRESH_AT_SEC - DEMO_CREATED}s into the ${DEMO_JWKS_REFRESH_TTL_SEC}s TTL): refreshIfStale() returned ${jwksRefreshFreshRefreshed} (fetch count still ${jwksRefreshFetchCallsAfterFresh})`,
    `JWKS refresh after rotation (clock past the ${DEMO_JWKS_REFRESH_TTL_SEC}s TTL, endpoint now serves only the rotated key): refreshIfStale() returned ${jwksRefreshStaleRefreshed} (fetch count ${jwksRefreshFetchCallsAfterRotation})`,
    jwksRefreshNewVerification.ok
      ? `JWKS verification after rotation: OK (label ${jwksRefreshNewVerification.label}, keyid="${jwksRefreshNewVerification.keyId}", alg="${jwksRefreshNewVerification.alg}", nonce="${jwksRefreshNewVerification.nonce}")`
      : `JWKS verification after rotation: FAILED (code ${jwksRefreshNewVerification.code}: ${jwksRefreshNewVerification.reason})`,
    jwksRefreshRetiredVerification.ok
      ? `JWKS verification of the retired keyid "${DEMO_JWKS_REFRESH_OLD_KEY_ID}" after rotation: OK (unexpected — the retired keyid was not rejected)`
      : `JWKS verification of the retired keyid "${DEMO_JWKS_REFRESH_OLD_KEY_ID}" after rotation: FAILED (code ${jwksRefreshRetiredVerification.code}: ${jwksRefreshRetiredVerification.reason})`,
    "",
    "Header lookup: getHeader is the normalized read the verifier itself uses — the lookup name's case need not match the stored key, multi-value fields come back trimmed and joined with \", \" (RFC 9421 §2.5), and a missing field comes back undefined — while getHeaderRaw returns the field exactly as stored, the raw read a ;bs component binds",
    `getHeader("${DEMO_GET_HEADER_LOOKUP_NAME}") over the stored "${DEMO_GET_HEADER_STORED_NAME}" values ${JSON.stringify(DEMO_GET_HEADER_VALUES)}: "${getHeaderValue}"`,
    `getHeaderRaw("${DEMO_GET_HEADER_LOOKUP_NAME}") over the same stored values: "${getHeaderRawValue}" (every element's padding preserved — the two reads differ exactly by the per-element trimming)`,
    `getHeader("${DEMO_GET_HEADER_SINGLE_LOOKUP_NAME}") over the stored "${DEMO_GET_HEADER_SINGLE_STORED_NAME}": "${getHeaderSingleValue}" (a single string value is returned exactly as stored)`,
    `getHeader("${DEMO_GET_HEADER_MISSING_NAME}"): ${getHeaderMissingValue} (no such field in the record — a missing header is undefined, never an empty string)`,
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
    p256Signed,
    p256Verification,
    p256TamperedVerification,
    digestGuardAccepted,
    digestGuardRejections,
    replaySnapshotSigned,
    replaySnapshotFirstVerification,
    replaySnapshotExport,
    replaySnapshotReplayVerification,
    replaySnapshotFreshVerification,
    replaySnapshotRestoredSize,
    replaySnapshotOriginalSize,
    p384Signed,
    p384Verification,
    p384TamperedVerification,
    signatureInputRaw,
    parsedSignatureInput,
    parseTamperedError,
    p521Signed,
    p521Verification,
    p521TamperedVerification,
    resolvedComponents,
    resolveIllegalComponentError,
    joinedHeaderValue,
    joinSigned,
    joinVerification,
    joinWrongVerification,
    signatureFieldBytes,
    signatureFieldHexPrefix,
    signatureFieldUnknownError,
    ecJwkExports,
    ecJwkSigned,
    ecJwkVerifications,
    ecJwkMismatchError,
    rsaJwkExport: rsaJwkExported,
    rsaJwkSigned,
    rsaJwkVerification,
    rsaJwkMismatchError,
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
    getHeaderHeaders,
    getHeaderValue,
    getHeaderRawValue,
    getHeaderSingleValue,
    getHeaderMissingValue,
    getHeaderRawMissingValue,
    lines,
  };
}

async function main(): Promise<void> {
  console.log((await runDemo()).lines.join("\n"));
}

// Run only when executed directly (`node dist/src/demo.js`), not when
// imported by tests.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  void main();
}
