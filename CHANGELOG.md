# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the version below is the version declared in `package.json`. Every entry
summarizes one or more commits in this repository's `git log`, grouped by
change type; no entry describes a feature that is not in the history.

## [Unreleased]

### Added

- Benchmark now covers the response-side replay-defense paths (backlog #1338): two new rows — `verifyResponse replayCache` measures the single-label response replay check over the same ed25519-signed settlement response as the `verifyResponse` row (same keys, same pinned `created`, same `@status` + content-digest coverage) with a pinned nonce: one measured op verifies the fixture twice against a fresh `ReplayCache` (first presentation ok with the nonce echoed, second rejected with exactly `NONCE_REPLAY` and the pinned reason), with the no-cache default, the nonce-less bypass (cache stays empty), the `requireNonce` + cache `MISSING_NONCE` rejection, and the tampered-status non-pollution pinned outside timing; `verifyAllResponseLabels replayCacheByLabel (2 labels)` measures the per-label form over the same dual-signed fixture as the `verifyAllResponseLabels` row (merchant ed25519 + gateway hmac-sha256, same bare nonce in both labels): one measured op verifies the dual twice against fresh per-label caches (first presentation ok in each store, second `NONCE_REPLAY` in both), with the shared-store contrast (one global cache passes the merchant and replay-rejects the gateway on first presentation), the unmapped-label global fallback, and the no-cache default pinned outside timing. In this run the new rows measured 2,553 ops/sec (391.68 µs/op) against 4,104 ops/sec for the same run's plain `verifyResponse` row, and 1,651 ops/sec (605.79 µs/op) against 3,910 ops/sec for the same run's plain `verifyAllResponseLabels` row — both slower as expected, since each measured op verifies twice (first presentation plus the replay rejection, the second call still paying full verification before the cache lookup). A mutation check confirms the bench self-check fails (exit 1) when the pinned `NONCE_REPLAY` reason is changed. The README Benchmarks table is refreshed from the same run (149 rows, 2026-11-23, Node v24.22.1, AMD EPYC 9D25).

- `JwksKeyStore.stats()` now reports repeated `kid`s (backlog #1335): a new `duplicateKids` counter counts how many times a `kid` repeats inside one fetched JWKS document or one restored snapshot — the same `kid` listed twice counts 1, three times counts 2 — while the later entry still wins and is the key served. The count is committed only when the document or snapshot is successfully installed (a failed refresh or restore leaves it untouched, like the other counters) and `clear()` resets it with the rest. Eleven new tests in `test/jwksDuplicateKidStats.test.ts` pin the behavior: a duplicate-kid refresh serves the later key (a signature under the new key verifies, one under the retired first key fails `SIGNATURE_MISMATCH`) and counts 1, triple repeats count 2, distinct kids count 0, counts accumulate across refreshes, unsigned and signed snapshot restores count the same way, an exported old snapshot still restores and verifies after a duplicate refresh, `clear()` zeroes the counter, and a refresh that fails on a later entry does not count the repeat it already saw. Test counts move 2540 → 2551.

- Response-side required-freshness tests (backlog #1331): twelve new tests in `test/responseRequireFreshness.test.ts` pin what the request side already covered in `test/requireFreshness.test.ts` and `test/requireCreatedExpiresByLabel.test.ts` but the response side only trusted to forwarding — `verifyResponse` under `requireCreated` / `requireExpires` rejects a hand-built dateless response signature with `MISSING_CREATED` / `MISSING_EXPIRES` (both missing reports `MISSING_CREATED` first), a fully-dated response passes both requirements, the gates stay off by default, a forged undated response still reports `SIGNATURE_MISMATCH` before any presence check, and `verifyResponseOrThrow` throws a `VerifyError` with the stable code; the per-label section drives `verifyAllResponseLabels` with `requireCreatedByLabel` / `requireExpiresByLabel` — a merchant gated on `created` (or `expires`) fails while an ungated gateway with the same missing field passes, a global `requireCreated: true` plus `requireCreatedByLabel: { merchant: false }` exempts only the mapped label while the unmapped gateway still falls back to the global, and both maps on the merchant fail it on `created` first while the gateway passes. The dateless response signatures are hand-built with the public `buildSignatureBase` + raw ed25519 primitives over the exact `RequestLike` shape `verifyResponse` synthesizes (empty method, the reserved `.invalid` URL, `@status` bound), since `signResponse` always emits `created`. A mutation check confirms the four per-label tests go red when the map pass-through is stripped from `verifyAllResponseLabels` (8 of 12 pass) while the single-label tests stay green. Test counts move 2528 → 2540.

- Benchmark now covers the private-JWK import/export and key self-description paths (backlog #1322): five new rows — `importPrivateKeyJwk (ed25519 + P-256)` imports two fixed private JWKs per call (ed25519 via `exportPrivateKeyJwk`, P-256 via `exportPrivateKeyJwkP256`, each through the JSON wire form), re-pinning the imported type and curve on every pass, with the full PKCS#8 DER round-trip equality and the wrong-curve export/import rejections asserted outside timing; `exportPrivateKeyJwkP256 (P-256)` exports one fixed P-256 private key per call against the pinned deterministic JWK, with the wrong-curve export rejections outside timing; and `describeKey`, `inferAlgFromKeyShape` and `algMatchesKeyShape` over one fixed key of each of the six supported shapes (ed25519, P-256, P-384, P-521, RSA-2048, a 32-byte HMAC secret), re-pinning hand-written descriptions, algorithms and a true/false match matrix on every pass, with the unmappable-shape inference rejection and the unknown-algorithm non-match outside timing. The Benchmarks table is refreshed from the same run (147 rows) and the run date moves to 2026-11-22. A mutation check confirms the bench goes red when a pinned expectation is broken (the P-256 `describeKey` description changed → bench exits 1 with the pinned mismatch). In this run the new rows measured ~8,929 ops/sec (import), ~79,044 ops/sec (export), and ~191,331 / ~211,697 / ~125,806 ops/sec (describe / infer / match).

- Direct unit tests for the exported input-guard helpers (backlog #1321): sixteen new tests in `test/inputGuardHelpers.test.ts` pin what was previously only covered indirectly through the `signRequest` / `verifyRequest` entry points — `assertCoveredComponentsShape` rejects a non-array list, non-string or empty entries (naming the index and the received type), and accepts a valid or empty list; `assertLabelShape` accepts RFC 9421 token labels and rejects commas, spaces, colons, slashes, non-letter starts, and a leading `*`, naming the caller (`signRequest` by default, `addSignature` / `addResponseSignature` when given); `assertNoDuplicateCoveredComponents` rejects exact, case, and quoting repeats (naming the repeated entry and the caller) while accepting `;req` as distinct from the bare component, different parameter values, and different parameter orders; `assertNoUnknownOptions` rejects a misspelled freshness key by name, counts an `undefined`-valued key as present, and ignores inherited keys; and `coveredComponentKey` folds base and parameter-name case, strips quotes, trims whitespace, keeps parameter values verbatim, and compares parameters in listed order. A mutation check confirms the tests go red when the base case-folding is dropped from `coveredComponentKey` (3 of 16 fail) and when the label token regex is widened to allow commas (1 of 16 fails). Test counts move 2486 → 2502.

- Behavior-level unit tests for the per-label `signature`-value length limit (backlog #1312): nine new tests in `test/maxSignatureLengthByLabel.test.ts` pin what was previously only configuration-validated — a tight per-label limit (`{ sig1: 50 }`) rejects only that label with `SIGNATURE_TOO_LARGE` (reason naming the mapped limit and the shared header's byte count) while the other label still verifies; a limit exactly equal to the shared `signature` header length lets both labels verify; an unmapped label falls back to the global `maxSignatureLength` (pinned at the boundary value); a global limit below the shared header length fires the pre-parse gate as a single synthetic result; two mapped labels are checked independently; a map entry for a label absent from the wire is inert; invalid limits (0, negative, non-integer, non-number) and a non-object map throw configuration errors; the single-label `verifyRequest` path with `maxSignatureLength` is pinned as equivalent to the per-label delegation; and `verifyAllLabelsOrThrow` throws the first failing label's `VerifyError` with the full per-label array attached as a detached `verifyResults`. One correction to the backlog sketch: the limit is measured against the whole shared `signature` header, not one label's base64 value — the per-label value arrives in `verifyRequest` as that label's `maxSignatureLength`, and the shared-header reading is already pinned by the #1309 demo and #1311 bench. A mutation check confirms the tests go red when the length comparison is changed from `>` to `>=` (4 of 9 fail) and when the per-label map lookup is dropped in favor of the global limit alone (4 of 9 fail). Test counts move 2477 → 2486.

- Benchmark now covers the per-label `signature`-value length limit (backlog #1311): a new `verifyAllLabels maxSignatureLengthByLabel (2 labels)` row promotes the per-label half that was only an outside-timing self-check inside the oversized signature-input row to its own measured path — the `maxSignatureInputLengthByLabel` twin had a measured row only for the input header. One measured op verifies the same dual-signed fixture (merchant ed25519 + gateway hmac, `created` pinned, verifier `now` injected) under `verifyAllLabels` with `maxSignatureLengthByLabel: { gateway: 100 }`, re-pinning on every pass that the merchant label still verifies while the gateway label is rejected with exactly `SIGNATURE_TOO_LARGE` and the pinned reason carrying the shared 155-byte `Signature` header's byte count; the boundary (a limit exactly equal to the shared header length lets both labels verify) is pinned outside timing. In this run it measured 5,991 ops/sec (166.93 µs/op) against 4,013 ops/sec for the same run's plain dual-label row — about 1.5x faster, the expected shape, since the rejected gateway label never pays its HMAC verification — and against 49,544 ops/sec for the same run's pre-parse oversized gate, which rejects before any parsing runs while this gate runs after parsing. A mutation check confirms the bench self-check fails (exit 1) when the pinned failure code is changed. The README Benchmarks table is refreshed from the same run (2026-11-21, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.

- Benchmark now covers the throwing response-verification entry points (backlog #1310): two new rows — `verifyResponseOrThrow (signed response, @status)` measures the throwing single-label path over the same ed25519-signed settlement response as the `verifyResponse` row (same keys, same pinned `created`, same `@status` + content-digest coverage), self-checking the returned identity (label, keyid, alg, `created`, covered components) on every measured pass, with the 200 -> 500 status tamper pinned outside timing to throw the pinned `SIGNATURE_MISMATCH` VerifyError; `verifyAllResponseLabelsOrThrow (tampered response, @status)` measures the throwing multi-label failure path over the same dual-signed fixture (merchant ed25519 + gateway hmac) with `@status` flipped 200 -> 500, so every call throws a `VerifyError` carrying the first failing label's `SIGNATURE_MISMATCH` code with the full per-label array attached as `verifyResults` (both labels fail, because both cover `@status`), re-pinned on every measured call with the throw count pinned to warmup + timed iterations. In this run the success row measured 5,573 ops/sec (179.43 µs/op) against 4,868 ops/sec for the same run's non-throwing `verifyResponse` row, and the tampered row measured 4,794 ops/sec (208.59 µs/op) against 4,522 ops/sec for the same run's non-throwing `verifyAllResponseLabels` row — both throwing rows land in the same band as their non-throwing twins. A mutation check confirms the bench self-check fails (exit 1) when the pinned first-failing label is changed. The README Benchmarks table is refreshed from the same run (2026-11-21, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new rows.

- The CLI demo now shows per-label header length limits end to end (backlog #1309): a new segment, placed right after the throwing multi-label verification segment, verifies the same dual-signed request three times with per-label limits — `maxSignatureInputLengthByLabel: { sig1: 50 }` rejects only `sig1` with `SIGNATURE_INPUT_TOO_LARGE` (the shared 245-byte `Signature-Input` header is over its own 50-byte limit) while the gateway label falls back to the 64 KiB default and still verifies, `maxSignatureLengthByLabel: { gateway: 100 }` rejects only the gateway label with `SIGNATURE_TOO_LARGE` (the shared 151-byte `Signature` header is over its own 100-byte limit) while the merchant `sig1` label still verifies, and limits exactly equal to the shared header lengths (245 and 151) let both labels verify, because a limit rejects only a strictly-over header. The shared header lengths are hand-pinned `DEMO_DUAL_SIGNATURE_INPUT_LENGTH` / `DEMO_DUAL_SIGNATURE_LENGTH` expectations (probed live before the segment was written, asserted before use), and the segment asserts every label and code against hand-pinned `DEMO_PER_LABEL_*` expectations. Two new demo tests pin the segment's `DemoResult` fields and its printed lines, re-derive all three outcomes independently with a fresh dual-signed fixture outside the demo, and confirm the lines are byte-identical between runs; the neighboring throwing multi-label lines test still expects the replay segment next. A mutation check confirms the demo test goes red when a pinned failure code is changed. The README demo section gains the demo pointer, and test counts move 2475 → 2477 (the two README test-count mentions were stale at 2473 and are corrected to 2477 in the same change).

- The CLI demo now shows explicit-type Structured Field canonicalization end to end (backlog #1308): a new segment, placed right after the trial-order canonicalization segment, runs the same two fixed values through `canonicalizeStructuredFieldValueAs` once per pinned type — `"a=1, b=2"` is a Dictionary (`a=1, b=2`) but fails closed as a List (`expected "," between list members (at offset 1)`) and as an Item (`trailing characters after item`), while `"007"` is not a Dictionary but canonicalizes to `7` as a List and as an Item — and cross-checks each against the trial-order `canonicalizeStructuredFieldValue` result, with an empty value shown refused for every pinned type (`empty value is not a valid Structured Field`). The segment asserts every outcome against hand-pinned `DEMO_SF_EXPLICIT_TYPE` / `DEMO_SF_EXPLICIT_TYPE_EMPTY_ERROR` expectations. Two new demo tests pin the segment's `DemoResult` fields and its printed lines, re-derive every outcome independently outside the demo, and confirm the lines are byte-identical between runs; the neighboring canonicalization lines test now expects the explicit-type segment next. A mutation check confirms the demo test goes red when a pinned `auto` expectation is changed. The README demo section gains the demo pointer, and test counts move 2473 → 2475.

- The CLI demo now shows key introspection end to end (backlog #1303): a new segment, placed right after the HMAC secret generation segment, runs `describeKey` over the demo's three signing keys — the main ed25519 private key, the P-256 private key and the freshly generated HMAC secret — and prints each shape verbatim (`an asymmetric ed25519 key`, `an asymmetric ec key (prime256v1)`, `a secret (symmetric) key`) next to the `inferAlgFromKeyShape` result for that shape (`ed25519`, `ecdsa-p256-sha256`, `hmac-sha256`), then shows a mismatched pairing refused: `algMatchesKeyShape("ed25519", HMAC secret)` is `false`, so a caller checks the pairing before signing instead of learning it from the sign-side fail-fast. Only shapes and algorithms are printed, never key bytes, so the segment is byte-identical between runs. The segment asserts every description, inferred alg and the mismatch verdict against hand-pinned `DEMO_KEY_INTROSPECTION_*` expectations. One new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives all three shapes independently with fresh keys outside the demo (including the true-pairing controls), and confirms the lines are byte-identical between runs; the neighboring HMAC secret generation lines test now expects the key-introspection segment next. A mutation check confirms the demo test goes red when a pinned inferred alg is changed. The README demo section gains the demo pointer, and test counts move 2472 → 2473.

- The CLI demo now shows the fetch-request adapter's scheme guard end to end (backlog #1302): a new segment hands `fromFetchRequest` an `ftp://` absolute URL — the same `ftp://api.example.com:8443/v1/charge` that `test/adapterScheme.test.ts` pins — and it is refused with the pinned configuration error (`fromFetchRequest: req.url scheme must be "http" or "https", got "ftp"`) before any signature is built, while the same path over `https://` adapts, signs with a fresh ed25519 key and verifies under the pinned keyid and nonce. No network is involved: both `Request` objects are constructed locally and never fetched. One new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives both halves independently outside the demo (a direct `fromFetchRequest` call throws the pinned message; the `https://` twin re-signed with a fresh key verifies), and confirms the lines are byte-identical between runs; the neighboring fetch-request lines test now expects the scheme-guard segment next. A mutation check confirms the demo test goes red when the pinned rejection is changed. The README demo section gains the demo pointer, and test counts move 2471 → 2472.

- Benchmark now covers the `fromFetchResponse` response-adapter path (backlog #1301): a new `fromFetchResponse (@status, loopback)` row measures the fetch-API twin of the `fromNodeResponse` row — the response-side normalization and verification a `fetch()` client runs on every gateway-signed settlement callback. A real loopback server signs one 200 response covering `@status` only with ed25519 (`created` pinned, verified at a fixed `now`); the bench fetches it once with the global `fetch`, reads the body with `arrayBuffer` outside timing, and re-measures only the client-side work (`fromFetchResponse` + `verifyRequest` requiring `@status`) over the captured live `Response` — re-measuring the network per iteration would time TCP loopback, not the adapter. No trailers are involved (a fetch `Response` carries none). Self-checks on every measured pass pin the adapted `@status` (200) and a successful verification, and outside timing the row pins the missing-status fail-fast and the 500-status replay as `SIGNATURE_MISMATCH`; a mutation check confirms the bench self-check fails when the verification expectation is inverted. In this run it measured 2,493 ops/sec (401.14 µs/op), against 2,722 ops/sec (367.37 µs/op) for the same run's `fromNodeResponse` row — about 9% slower per op even though the node row additionally binds the settlement trailer, the expected shape, since both rows pay one ed25519 verification and the gap is the fetch adapter's `Headers` normalization and status validation. The README Benchmarks table is refreshed from the same run (2026-11-21, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row. One prerequisite fix rides in the same change: the loopback response rows used to sign their responses with `signRequest`, which backlog #1283 now refuses for `@status` coverage, so they now sign with `signResponse` (and append the second label with `addResponseSignature`) — without this the bench itself fails at the first loopback row.

- The CLI demo now shows the per-curve private-key JWK exporters end to end (backlog #1300): a new segment exports one fresh key pair per curve — P-256, P-384, P-521 and RSA — with `exportPrivateKeyJwkP256` / `exportPrivateKeyJwkP384` / `exportPrivateKeyJwkP521` / `exportPrivateKeyJwkRsa`, carries each through a JSON wire round-trip, reads it back with the shared `importPrivateKeyJwk`, and asserts the re-export byte-identical member for member (`x`/`y`/`d` for the EC curves, the full CRT set `n`/`e`/`d`/`p`/`q`/`dp`/`dq`/`qi` for RSA) — the same generate -> export -> wire -> import loop as the ed25519 segment, per curve. One correction to the backlog's sketch: there are no per-curve `importPrivateKeyJwk*` functions — the single `importPrivateKeyJwk` dispatches on `kty`/`crv`, as the exporters' docstrings state — so the segment re-imports through it. Only each JWK's shape is printed (`kty`/`crv` for the EC curves, `kty` plus the 342-character `n` length for the 2048-bit RSA modulus), never any key material, and one new demo test pins the segment's `DemoResult` fields and its printed lines and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when a pinned curve is changed. The README demo section gains the demo pointer, and test counts move 2470 → 2471.

- Direct unit tests for `serializeSignatureParams`, the last assembly step of the signature-input string (backlog #1299): twelve new tests in `test/serializeSignatureParams.test.ts` pin the empty list (`()`), the empty list with params, a lone `@method`, the `;bs` position on `@query`, the `;sf` position on a header field and the `;name` position on `@query-param`, quote/backslash escaping in parameter values (including the demo corpus's escaped-nonce case), caller-order preservation across two components, canonical per-component parameter order regardless of input order (`;req` before `;tr`, `;req` before `;name`), the fixed six-parameter order (created, expires, keyid, alg, nonce, tag) under scrambled object keys, `;bs` vs `;sf` serializing distinctly, and a cross-check that the `@signature-params` line `buildSignatureBase` emits equals the serializer's output. One correction to the backlog's sketch: `@query-param;name="a";sf` is not a valid component id — `;name` and `;sf` are incompatible by design (`;name` selects a query parameter, `;sf` transforms a field value) — so that combination is pinned as a fail-closed throw instead of a serialization, and the `;sf` position is pinned on a header field. A mutation check confirms the tests go red when `;bs` is mis-serialized as `;sf`. Test counts move 2458 → 2470.

- The CLI demo now shows the throwing response-verification entry points end to end (backlog #1298): a new segment reuses the addResponseSignature segment's dual-signed loopback settlement response (merchant ed25519 via `signResponse`, gateway hmac-sha256 appended with `addResponseSignature`) and verifies the merchant label with `verifyResponseOrThrow` — the throwing twin of `verifyResponse`, returning the verified identity (label, keyid, alg, nonce, created, covered components) instead of a result object — then flips `@status` (`200` -> `500`) and calls `verifyAllResponseLabelsOrThrow`, which throws the first failing label's `VerifyError` (`merchant`, `SIGNATURE_MISMATCH`) with the full per-label array attached as `verifyResults`: both labels fail, because both signatures cover `@status`, so a bad gateway signature never hides the merchant verdict — and a `verifyAllResponseLabels` contrast pass on the same tampered response confirms the attachment equals the non-throwing outcome label for label. The throw shape was confirmed by a live probe before the segment was written. The segment asserts every outcome against hand-pinned `DEMO_ADD_RESPONSE_SIG_*` / `DEMO_GATEWAY_RESPONSE_TAMPER_CODE` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the pinned failure code is changed. The README demo section gains the demo pointer, and test counts move 2457 → 2458.

- Fail-closed unknown-option checks on every sign / verify entry point (backlog #1251): a shared `assertNoUnknownOptions(opts, allowed, caller)` in `src/sign.ts` runs first in `signRequest`, `verifyRequest`, `verifyAllLabels`, `signResponse`, `verifyResponse`, and `verifyAllResponseLabels`, each with its own allowlist (`SIGN_OPTION_KEYS` / `VERIFY_OPTION_KEYS` / `VERIFY_ALL_OPTION_KEYS`, exported from `src/index.ts`; the response-side lists are those plus `"request"`), throwing `invalid <caller> options: unknown option "<key>"` for any key the entry point never reads — a misspelled freshness key (`maxSignatureAge` for `maxSignatureAgeSec`, `requireNonces` for `requireNonce`) is rejected instead of silently disabling the safety check it names, and a key set to `undefined` still counts as present. `addSignature` / `addResponseSignature` inherit the check through delegation. The passthrough helpers scan at their own boundary too: `verifiedFetch` rejects an unknown top-level key before any network (its nested `sign` / `verify` objects are scanned by the entry points in the pre-flight dry runs), and `createVerifiedHandler` / `createVerifiedFetchHandler` reject an unknown top-level key at handler creation (nested options are scanned inside the creation-time dry runs). One internal delegation had to change: `verifyAllLabels` used to spread the whole `VerifyAllOptions` into the per-label `verifyRequest` call, which now rejects the per-label map keys — it picks only the `VerifyOptions` keys for the delegation base, with per-label overrides applied after. Fifteen new tests in `test/signVerifyUnknownOptions.test.ts` cover all six entry points (including the `VerifyAllOptions`-own unknown keys and the `undefined`-counts case), the full-known-keys sign/verify and dual-label round trips, the `OrThrow` / `addSignature` inheritance, and both helpers' top-level and nested rejections with zero fetch calls; a mutation check confirms the tests go red when the misspelled key is wrongly allowed. The README Error codes section documents the new plain-`Error` channel. Test counts move 2308 → 2323.

- Throwing response-verification twins (backlog #1250): `verifyResponseOrThrow(res, opts)` and `verifyAllResponseLabelsOrThrow(res, opts)` in `src/response.ts`, mirroring the request-side `verifyRequestOrThrow` / `verifyAllLabelsOrThrow` — the single-label one returns the verified identity (`label`, `keyid`, `alg`, `nonce`, `tag`, `created`, `expires`, `coveredComponents`) on success and throws a `VerifyError` carrying the stable `.code` on failure; the multi-label one returns the per-label `VerifyResult[]` in wire order when every label verifies and otherwise throws the first failing label's `VerifyError` with the full per-label array attached as `.verifyResults` (a detached copy, so a bad gateway co-signature never hides the merchant label that verified). An unsigned response returns `[]` without throwing, exactly as `verifyAllResponseLabels` does, and caller configuration errors (a bad `status`, a request-derived covered component) still throw a plain `Error`. Both are exported from `src/index.ts`; the README response-signing examples, feature list, and Error codes section document them. Ten new tests in `test/verifyResponseOrThrow.test.ts` cover the success identity with `tag`/`nonce` echo, `SIGNATURE_MISMATCH` / `BODY_DIGEST_MISMATCH` / `MISSING_SIGNATURE_INPUT` throws, the plain-`Error` status guard, both-labels-ok wire order, the one-bad-label throw with the full `verifyResults` attached and detached, the `MISSING_REQUIRED_LABEL` throw, and the unsigned `[]` case; a mutation check confirms the tests go red when the attached `verifyResults` is emptied. Test counts move 2298 → 2308.

- The CLI demo now shows the response-side required co-signatures check end to end (backlog #1249): a new segment reuses the addResponseSignature segment's dual-signed loopback settlement response (merchant ed25519 via `signResponse`, gateway hmac-sha256 appended with `addResponseSignature`) and verifies it with `verifyAllResponseLabels` under `requiredLabels: ["merchant", "gateway"]` — both labels ok — then strips the gateway label's member from both the `signature-input` and the `signature` headers (a new `stripResponseSignatureLabel` helper, the response-side twin of the request-side `stripSignatureLabel`) and re-verifies with the same `requiredLabels`: the merchant label still verifies while the gateway label comes back as a synthetic `MISSING_REQUIRED_LABEL` failure appended after the wire-order results, so a downgrade that drops a co-signature is a fail-closed policy failure instead of a silent absence (without `requiredLabels` the same stripped response would verify with only the merchant result). The synthetic-failure shape was confirmed by a live probe before the segment was written. The segment asserts every outcome against hand-pinned `DEMO_VERIFY_ALL_RESPONSE_LABELS_REQUIRED_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the pinned failure code is changed. The README demo section gains the demo pointer, and test counts move 2297 → 2298.

- The CLI demo now shows the `JwksKeyStore` `fetchTimeoutMs` pull timeout end to end (backlog #1246): a new segment drives a store with `fetchTimeoutMs: 500` against a real loopback `http` server that answers the first fetch with the one-key document and then hangs on every later request — the second `refresh()` fails with the pinned `JwksKeyStore: JWKS fetch timed out after 500ms` message while the seeded snapshot size, `lastRefreshedAt` and a verification through the kept snapshot are unchanged, with `stats()` counting one refresh, one refresh failure and one hit from the verification — and a second store with `fetchTimeoutMs: 5000` refreshes against the same server's always-answering path as the control, showing a fetch that finishes inside the deadline is unaffected. The segment asserts every count, size, timestamp and error message against hand-pinned `DEMO_JWKS_FETCH_TIMEOUT_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives both paths independently with stubbed default fetches (a never-resolving fetch aborted at the deadline, a fast fetch refreshing normally), and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the pinned timeout error is changed. The README demo section gains the demo pointer, and test counts move 2296 → 2297.

- The CLI demo now shows the private-key JWK export round-trip end to end (backlog #1245): the missing half of the private-key JWK import segment — a fresh `generateEd25519KeyPair()` is exported with `exportPrivateKeyJwk`, carried through a JSON wire round-trip and read back with `importPrivateKeyJwk`, and the re-imported key completes an ed25519 sign -> verify round-trip against the generated public half, closing the generate -> export -> wire -> import -> sign loop a KMS backup/restore closes without a PEM detour. The exported `x`/`d` are asserted byte-identical against a re-export of the re-imported key outside the print path, and a public key passed to the private exporter is shown rejected with the pinned caller-configuration error (the same refusal a symmetric secret or another algorithm hits). The segment asserts every outcome against hand-pinned `DEMO_PRIVATE_JWK_EXPORT_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives the whole loop independently with a fresh key pair, and confirms the lines are byte-identical between runs (only the JWK shape is printed, never the `d` or `x` bytes); a mutation check confirms the demo test goes red when the `d` byte-identity assertion is inverted. The README demo section gains the demo pointer, and test counts move 2295 → 2296.

- The CLI demo now shows HMAC secret generation and rotation end to end (backlog #1244): a new segment mints a fresh hmac-sha256 secret with `generateHmacSecret()` (32 bytes) and a fresh hmac-sha512 secret with `generateHmacSecret("hmac-sha512")` (64 bytes), wraps each with `secretKey`, and carries both through a sign -> verify round-trip — the key-management closed loop the demo's fixed gateway secret skips: mint, sign, verify, then rotate. Rotation mints a second hmac-sha256 secret that signs the same request and verifies under it, while the superseded secret fails the same signature with `SIGNATURE_MISMATCH`, so the old key stops verifying the moment the new key takes over; an explicit 16-byte generation is shown rejected with the same `assertHmacSecretLength` wording the sign/verify side uses for a weak key, cross-checked against the floor the oct-JWK segment pins (31 bytes there, 16 here). The segment asserts every length, outcome, label, code and nonce against hand-pinned `DEMO_HMAC_SECRET_GEN_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives the whole loop independently with freshly minted secrets, and confirms the lines are byte-identical between runs (only lengths and algorithms are printed, never the secret bytes); a mutation check confirms the demo test goes red when the pinned 32-byte expectation is changed. The README demo section gains the demo pointer, and test counts move 2294 → 2295.

- Benchmark now covers the `generate*KeyPair` key-generation path (backlog #1241): a new `generateKeyPairs (ed25519 + P-256)` row measures the key-pair provisioning a signer pays when it mints a fresh signing key for issuance or rotation — one `generateEd25519KeyPair()` call and one `generateP256KeyPair()` call per measured op, self-checking the public-key JWK `kty` / `crv` verbatim (`OKP` / `Ed25519`, `EC` / `P-256`) on every pass and freshness against the previous generation of the same tier (public coordinates differ). Outside timing the bench pins the P-384 / P-521 half (two consecutive generations of each differ in public coordinates with `kty` / `crv` pinned), and the two RSA generators are deliberately excluded from timing (a single RSA-2048 generation costs on the order of a few hundred milliseconds, so 3000 timed iterations would take on the order of ten minutes per generator). A mutation check confirms the row goes red when the pinned `OKP` expectation is changed. In this run it measured 8,862 ops/sec (112.84 µs/op), about 16x the same run's `JWK round-trip ed25519` row (144,699 ops/sec) — the expected shape, since the generation row mints fresh key material while the round-trip row only re-exports keys that already exist. The README Benchmarks table is refreshed from the same run (2026-11-18, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.

- The CLI demo now shows the `JwksKeyStore.refresh()` single-flight merge end to end (backlog #1240): a new closing segment drives eight concurrent `refresh()` calls through a counting fake fetch (zero network) and an injected clock pinned at the demo's fixed instant — the batch makes exactly one fetch, `stats().refreshes` steps to 1, `lastRefreshedAt` reads the pinned instant, and the scripted key resolves, so all eight waiters shared the one snapshot — and a serial `refresh()` afterwards fetches again (fetch count 2, refreshes 2), because only overlapping calls merge and a settled refresh is never cached. The segment asserts every count, timestamp and counter against hand-pinned `DEMO_JWKS_SINGLE_FLIGHT_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives the merge independently with a fresh key pair and a counting fake fetch, and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the pinned fetch count is changed. The README demo section gains the demo pointer, and test counts move 2293 → 2294.

- The CLI demo now shows multi-label response verification in one response entry-point call (backlog #1235): a new segment reuses the addResponseSignature segment's dual-signed loopback settlement response (merchant ed25519 via `signResponse`, gateway hmac-sha256 appended with `addResponseSignature`) and verifies both labels at once with `verifyAllResponseLabels`, the response-side twin of `verifyAllLabels`, with no request-shape adaptation first — then shows that tampering one body byte (the settlement amount `10000` -> `10001`) fails both labels with `BODY_DIGEST_MISMATCH`, because the digest check runs for every label whenever a `content-digest` header is present, so a body tamper has no per-label isolation (unlike the signature-byte tamper in the addResponseSignature segment, which fails only the gateway label). The both-fail shape was confirmed by a live probe before the segment was written. The segment asserts every outcome against hand-pinned `DEMO_VERIFY_ALL_RESPONSE_LABELS_*` expectations, and two new demo tests pin the segment's `DemoResult` fields and its printed lines and confirm the lines are byte-identical between runs; a mutation check confirms the demo fails closed when the tampered body is swapped back to the correct value. The README demo section gains the demo pointer, and test counts move 2291 → 2293.

- Benchmark now covers the `generateHmacSecret` key-generation path (backlog #1232): a new `generateHmacSecret (32 + 64 bytes)` row measures the fresh-secret provisioning a webhook issuer pays when it mints or rotates an HMAC signing secret — one `generateHmacSecret()` call (`hmac-sha256`, 32-byte default) and one `generateHmacSecret("hmac-sha512")` call (64-byte default) per measured op, self-checking each draw is a Buffer of exactly the pinned length on every pass. Outside timing the bench pins the explicit-length half (a 64-byte `hmac-sha256` secret keeps exactly 64 bytes), the freshness half (two consecutive draws differ in bytes for each algorithm), and the below-floor half (an explicit 16-byte length throws with the exact `assertHmacSecretLength` wording the sign/verify side uses for a weak key); a mutation check confirms the row goes red when the pinned 32-byte expectation is changed. In this run it measured 116,505 ops/sec (8.58 µs/op), about 2.1x the same run's `generateNonce` row (54,640 ops/sec) — the expected shape, since the secret row pays two CSPRNG draws and a floor check but no base64url encoding. The README Benchmarks table is refreshed from the same run (2026-11-18, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.

### Fixed

- `coveredComponentKey` rejects a non-string `entry` with a named `Error` instead of a bare `TypeError` (backlog #1381): the helper dereferenced its argument on the first line (`entry.trim()`), so a live probe showed `coveredComponentKey(null)` escaping as `TypeError: Cannot read properties of null (reading 'trim')` (and `coveredComponentKey(42)` as `TypeError: entry.trim is not a function`). The guard now runs first and throws e.g. `coveredComponentKey: "entry" must be a string, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly, following the `digest.ts` wording). The sign entry points were already safe — `assertCoveredComponentsShape` refuses a non-string list entry before the duplicate check runs — so this guard only fires for a caller that imports the helper directly (or for `assertNoDuplicateCoveredComponents`, which assumes the list shape was checked first); the parameter type widens from `string` to `unknown` to match. The helper JSDoc records the guard and the ordering. Six new tests in `test/coveredComponentKeyShape.test.ts` pin the exact wording for `null` / number / plain-object / array / `undefined` / boolean inputs, the unchanged legal normalization (case folding, quote stripping, whitespace trimming, parameter-name folding with values kept verbatim), the helper's named error surfacing through a direct `assertNoDuplicateCoveredComponents` call, the entry-point ordering (`signRequest` with a `null` covered entry still reports the list-shape error), and unchanged legal signing. A mutation check confirms 3 of 6 go red when the guard is disabled (the three passing are the guard-independent normalization/ordering/legal controls). Test counts move 2842 → 2848.

- `assertLabelShape` / `assertSignParamLength` reject a `null` sign-option string with a named `Error` instead of silently signing under the wrong label or throwing a bare `TypeError` (backlog #1380): the two failures were asymmetric — a live probe showed `signRequest(req, { key, alg: "hmac-sha256", label: null })` returning a request signed under `sig1` (the `?? "sig1"` fallback swallowed the `null`, and `LABEL_TOKEN_RE.test(null)` would have passed anyway because `null` coerces to the token-shaped string `"null"`), while `tag: null` / `nonce: null` / `keyId: null` each escaped as `TypeError: Cannot read properties of null (reading 'length')` from `assertSignParamLength`. `assertLabelShape` now checks `typeof label === "string"` first and throws the existing token-shape error (e.g. `signRequest: "label" must be an RFC 9421 token …, got "null"`), and `assertSignParamLength` checks `typeof value === "string"` first and throws e.g. `signRequest: "tag" must be a string, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly, following the `structuredFields.ts` / `components.ts` wording). The three label-resolution sites (`signRequestCore`, `addSignature`, `addResponseSignature`) now default to `"sig1"` only on `undefined`, so a `null` label reaches the guard instead of being swallowed; the append entry points keep their empty-string errors (the empty check only runs on strings, so a non-string label never throws a bare `TypeError` reading `.length`), and `label: 42` keeps its existing token error. `signResponse` inherits the fix through `signRequestCore` delegation. Each guard JSDoc records the rule. Fifteen new tests in `test/signOptionStringShape.test.ts` pin the exact wording for `null` / non-string `label` / `tag` / `nonce` / `keyId` on all four entry points, the unchanged `label: 42` and empty-label errors, and the unchanged legal signing (custom label/tag/nonce/keyId round-trip with the values echoed, omitted label still defaulting to `sig1`). A mutation check confirms 5 of 15 go red when the `assertSignParamLength` type check is removed and 4 of 15 go red when the `assertLabelShape` type check is removed (the remaining passing are the guard-independent rejection/legal controls). Test counts move 2827 → 2842.

- `serializeDictionaryMemberValue` / `canonicalizeStructuredFieldValue` / `canonicalizeStructuredFieldValueAs` reject a non-string `value` with a named `Error` instead of a bare `TypeError` (backlog #1379): the three Structured Field string helpers dereferenced `value` on their first line with no shape guard — a live probe showed all three escaping as `TypeError: Cannot read properties of null (reading 'replace')` for a `null` input, while the `digest` / `contentDigest` entry points already refused a non-string body with a named `"body" must be a string or a Buffer, got …` error. A local `assertStructuredFieldValueString` guard now runs first in each helper (it lives in `structuredFields.ts` because that module cannot import the shared `assertStringParam` from components.ts — components.ts imports this module), throwing e.g. `canonicalizeStructuredFieldValue: "value" must be a string, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly), so a number, plain object or array gets the same named rejection as `null`; the empty-value and invalid-field descriptive errors are unchanged, and the `;sf` / `;key` callers in components.ts pass already-normalized strings, so sign/verify behavior is unaffected. Each helper JSDoc records the guard. Twenty new tests in `test/structuredFieldShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` / number / plain-object / array inputs of all three helpers, the unchanged canonicalization outputs (dictionary member selection, trial-order and pinned-type paths), and the unchanged empty-value and invalid-value errors. A mutation check confirms 15 of 20 go red when the guard is disabled (the five passing are the guard-independent legal/error controls). Test counts move 2807 → 2827.

- `describeKey` / `algMatchesKeyShape` / `inferAlgFromKeyShape` / `assertRsaModulusLength` reject a `null` / non-`KeyObject` key with a named `Error` instead of a bare `TypeError` (backlog #1378): the four key-shape introspection helpers read a `KeyObject` field on their first line with no null guard — a live probe showed `describeKey(null)` / `inferAlgFromKeyShape(null)` escaping as `TypeError: Cannot read properties of null (reading 'type')` and `algMatchesKeyShape("ed25519", null)` / `assertRsaModulusLength(null, "probe")` as `TypeError: Cannot read properties of null (reading 'asymmetricKeyType')`, while the key exporters already refused a `null` key with a named `expected a … KeyObject, got null` error (backlog #1377) and the HMAC entry point `secretKey` did the same (backlog #1372). `algMatchesKeyShape`, `inferAlgFromKeyShape` and `assertRsaModulusLength` now guard with an `instanceof KeyObject` check (the exporter shape), throwing e.g. `inferAlgFromKeyShape: expected a KeyObject, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly; `assertRsaModulusLength` prefixes the message with its caller-supplied context instead of its own name), so a number, string or plain object gets the same named rejection as `null`. `describeKey` is the one deliberate exception: it formats the error message *about* a bad key, so it rejects only `null` / `undefined` (the inputs that cannot be read at all) and stays descriptive over anything else — a full `instanceof` guard there would have broken the existing pinned stub case in `test/algKeyShape.test.ts` (`{ type: "public" }` describing as `an asymmetric unknown key`), which exercises the `?? "unknown"` fallback; the existing shape semantics are otherwise unchanged (a wrong-shape real key still fails with the same `expected an RSA key` / modulus-floor wording, and the `describeKey` / inference wording for legal keys is byte-identical). Each entry JSDoc records the guard. Twelve new tests in `test/keyShapeHelpers.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` / number / plain-object inputs of all four helpers, the unchanged legal descriptions, pairings, inferences and RSA floor rejections. A mutation check confirms the `describeKey` null test goes red when that guard is removed (the eleven passing are the guard-independent controls). Test counts move 2795 → 2807.

- `exportPrivateKeyJwk` / `exportPublicKeyPem` / `exportPrivateKeyPem` / `exportSymmetricKeyJwk` reject a `null` / non-`KeyObject` key with a named `Error` instead of a bare `TypeError` (backlog #1377): the four remaining key exporters read a key field before any null check — a live probe showed `exportPrivateKeyJwk(null)` / `(undefined)` and `exportSymmetricKeyJwk(null)` / `(undefined)` escaping as `TypeError: Cannot read properties of null (reading 'type')`, and `exportPublicKeyPem(null)` / `(undefined)` and `exportPrivateKeyPem(null)` / `(undefined)` as `TypeError: Cannot read properties of null (reading 'export')`, with `exportPublicKeyPem(42)` / `exportPrivateKeyPem(42)` as `TypeError: key.export is not a function`, while the import side already refused a `null` JWK with a named error (`importPrivateKeyJwk: invalid JWK: expected a JWK object, got null`) and the two JWK exporters called with `42` already failed with their named `expected a … KeyObject` shape errors. A null guard now runs first in each JWK exporter, before the shape check, throwing e.g. `exportPrivateKeyJwk: expected an ed25519 private KeyObject, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly), and the PEM exporters guard with an `instanceof KeyObject` check (the `createVerifiedHandler` shape), throwing e.g. `exportPrivateKeyPem: expected a private KeyObject, got null`, so a number, string or plain object gets the same named rejection as `null`; a real `KeyObject` of the wrong kind still fails in node:crypto with its own error, unchanged. Each entry JSDoc records the guard and the export/import symmetry (the symmetric guard runs before the `alg` / `kid` checks). Twenty-four new tests in `test/exportKeyShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` inputs of all four exporters, the unchanged shape errors for a number input, the unchanged cross-type and node:crypto rejections, the guard-before-`alg` ordering, and the unchanged legal exports (deterministic re-export and PEM/JWK wire round-trips). A mutation check confirms 13 of 24 go red when the four guards are disabled (the eleven passing are the guard-independent rejection/legal controls). Test counts move 2771 → 2795.

- `fromNodeResponse` / `fromFetchResponse` reject a non-string `opts.method` / `opts.url` with a named `Error` instead of silently accepting it into the adapted `RequestLike` (backlog #1376): the two response adapters only checked the explicit pair for presence — a live probe showed `fromNodeResponse({ statusCode: 200, headers: {} }, undefined, { method: 42, url: "https://api.example.com/v1" })` returning `{ method: 42, ... }`, so the sign/verify side would only fail later with an unrelated message, while `status` / `statusCode` already had their integer-range named errors (#1352). A shared `assertMethodOrUrlString` guard now runs in the explicit-pair branch (before the "cannot determine the request" check), throwing e.g. `fromNodeResponse: opts.method must be a non-empty string, got 42` (a plain `Error`, never a `TypeError`); an empty string keeps its existing "cannot determine the request" error, and a bound `opts.request` is deliberately not re-checked (its method/url walk the `RequestLike` contract, and the explicit pair is ignored when a request is bound). Each adapter JSDoc and the two options interfaces record the rule and the ordering. Twenty-six new tests in `test/nodeHttpMethodShape.test.ts` pin the exact wording and the plain-`Error` shape for `42` / `{}` / `null` / `true` values of both fields on both adapters, the unchanged empty-string errors, the unchanged legal adaptation, the bound-request precedence over a bad explicit pair, and the sign → adapt with an explicit pair → verify round-trips. A mutation check confirms 16 of 26 go red when the guard is disabled (the ten passing are the guard-independent rejection/legal controls). Test counts move 2745 → 2771.

- `fromFetchResponse` / `fromFetchRequest` reject a `null` / non-object message, a non-iterable headers value, and (response side) a `null` / non-object `opts.request` with a named `Error` instead of a bare `TypeError` (backlog #1375): the two fetch adapters dereferenced their message before any shape check — a live probe showed `fromFetchResponse(null)` / `(undefined)` escaping as `TypeError: Cannot read properties of null (reading 'status')`, `fromFetchRequest(null)` / `(undefined)` as `TypeError: Cannot read properties of null (reading 'method')`, and `fromFetchResponse(okRes, undefined, { request: null })` as `TypeError: Cannot read properties of null (reading 'method')`, while `fromFetchResponse("x")` / `fromFetchRequest("x")` already failed with their named missing-status / missing-method errors and the Node adapters had the same gap closed in #1352. The shared `assertObjectParam` guard now runs first in both adapters (before the `method` / `status` fail-fast checks), with an `opts.request` guard on the response side, and a new fetch-flavoured headers guard: fetch headers are an iterable of `[name, value]` pairs (a real `Headers`, an array of pairs, any iterable), so the Node side's `assertObjectParam` does not fit — it rejects arrays, which are valid fetch headers — and a `null` / missing / record headers value now throws e.g. `fromFetchResponse: headers must be an iterable of [name, value] pairs` instead of the bare `TypeError: headers is not iterable` the `for...of` in `normalizeFetchHeaders` used to throw (a string headers value is rejected too: it is iterable, but its entries are characters, not pairs). Each entry JSDoc records the guard ordering and that `opts` itself stays deliberately unguarded (every `opts` read is optional-chained, so `null` opts behaves exactly like omitted opts). Thirty-one new tests in `test/nodeHttpFetchShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` / string / number / array inputs of both adapters, the headers guard for `null` / missing / record / string values, the `opts.request` guard, the unchanged missing-method / missing-status / non-integer-status errors, the unchanged legal adaptation (including literal pairs-array headers), and the sign → real fetch `Response` / `Request` → adapt → verify round-trips. A mutation check confirms 20 of 31 go red when the five guards are disabled (the eleven passing are the guard-independent rejection/legal controls). Test counts move 2714 → 2745.

- `exportPublicKeyJwkP256` / `exportPublicKeyJwkP384` / `exportPublicKeyJwkP521` / `exportPublicKeyJwkRsa` reject a `null` / `undefined` key with a named `Error` instead of a bare `TypeError` (backlog #1374): the four curve/RSA public-JWK exporters read a key field before any null check — a live probe showed `exportPublicKeyJwkP256(null)` / `(undefined)`, `exportPublicKeyJwkP384(null)` / `(undefined)` and `exportPublicKeyJwkP521(null)` / `(undefined)` escaping as `TypeError: Cannot read properties of null (reading 'asymmetricKeyDetails')`, and `exportPublicKeyJwkRsa(null)` / `(undefined)` as `TypeError: Cannot read properties of null (reading 'type')`, while the import side (`importPublicKeyJwkP256` and friends) already refused a `null` JWK with a named error (`importPublicKeyJwkP256: invalid JWK: expected a JWK object, got null`) and each exporter called with `42` already failed with its named `expected a … public KeyObject` shape error. A null guard now runs first in each exporter, before the shape check, throwing e.g. `exportPublicKeyJwkP256: expected a P-256 public KeyObject, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly), and each entry JSDoc records the guard and the export/import symmetry. Twenty new tests in `test/exportJwkCurvesShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` inputs of all four exporters, the unchanged shape errors for a number input, the unchanged cross-curve and private-key rejections, and the unchanged legal exports (deterministic re-export) and the P-256 export → JSON wire → import round-trip. A mutation check confirms 4 of 20 go red when the P-256 and RSA guards are disabled (the sixteen passing are the guard-independent rejection/legal controls). Test counts move 2694 → 2714.

- `exportPublicKeyJwk` rejects a `null` / `undefined` key with a named `Error` instead of a bare `TypeError` (backlog #1373): the ed25519 public-JWK exporter read `key.type` before any null check — a live probe showed `exportPublicKeyJwk(null)` / `(undefined)` escaping as `TypeError: Cannot read properties of null (reading 'type')`, while the import side (`importPublicKeyJwk`) already refused a `null` JWK with a named error (`importPublicKeyJwk: invalid JWK: expected a JWK object, got null`) and `exportPublicKeyJwk(42)` already failed with the named `expected an ed25519 public KeyObject` shape error. A null guard now runs first, before the shape check, throwing `exportPublicKeyJwk: expected an ed25519 public KeyObject, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly), and the entry JSDoc records the guard and the export/import symmetry. Eight new tests in `test/exportJwkShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` inputs, the unchanged shape errors for a number input, a private key, a P-256 public key and an HMAC secret, and the unchanged legal ed25519 export (exact JWK shape, deterministic re-export) and export → JSON wire → import → verify round-trip. A mutation check confirms 2 of 8 go red when the guard is disabled (the six passing are the guard-independent rejection/legal controls). Test counts move 2686 → 2694.

- `secretKey` rejects a `null` or non-string/non-`Buffer` secret with a named `Error` instead of a bare `TypeError` (backlog #1372): the HMAC key constructor took its bytes before any type check — a live probe showed `secretKey(null)` escaping as `TypeError: Cannot read properties of null (reading 'length')` and `secretKey(42)` / `secretKey({})` as node:crypto `TypeError`s from `createSecretKey`, while `secretKey(Buffer.alloc(0))` already failed with the named 32-byte floor error. A type guard now runs first, before the floor check, throwing `secretKey: hmac secret must be a string or a Buffer, got null` (a plain `Error`, never a `TypeError`, with `null` named explicitly per the `assertStringParam` convention), and the entry JSDoc records the guard. Twelve new tests in `test/secretKeyShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / `undefined` / number / object / boolean / 32-element-array inputs (the array case proves the guard fires before the floor check, which the array would otherwise pass on `.length`), the unchanged 32-byte floor errors for short strings, empty Buffers and 31-byte strings, the unchanged legal 32/64-byte string and Buffer paths (including the multibyte byte-count rule), and the unchanged hmac-sha256 sign → verify round-trip. A mutation check confirms 6 of 12 go red when the guard is disabled (the six passing are the guard-independent floor/legal controls). Test counts move 2674 → 2686.

- `verifiedFetch` rejects a `null` or non-string/non-`URL` input with a named `Error` instead of a bare `TypeError` (backlog #1355): the sign-and-verify fetch entry point guarded `opts` / `opts.sign` / `opts.verify` but not its first argument — a live probe showed `verifiedFetch(null, undefined, opts)` escaping as `TypeError: Cannot read properties of null (reading 'toString')` from the request build. An input guard now runs first, before the `opts` guards, throwing `verifiedFetch: input must be a string or URL, got null` (a plain `Error`, never a `TypeError`), with the entry JSDoc recording the ordering. Six new tests in `test/verifiedFetchShape.test.ts` pin the exact wording and the plain-`Error` shape for `null` / number / object / `undefined` / boolean / symbol inputs, the guard-before-`opts` ordering (a `null` input with `null` opts reports the input error, and the fetch is never called), the unchanged `opts` / `sign` / `verify` named errors, and the unchanged legal round-trips for both a string input and a `URL` input over an injected fetchImpl (zero network). A mutation check confirms the new tests go red when the guard is removed. Test counts move 2668 → 2674.

- `listSignatureLabels` / `parseSignatureInput` reject a `null` or non-string field value or label with a named `Error` instead of a bare `TypeError` (backlog #1354): the two exported structured-field parse helpers were the pair the #1344/#1352 guard rounds left unguarded — a live probe showed `listSignatureLabels(null)` escaping as `TypeError: Cannot read properties of null (reading 'length')`, `listSignatureLabels(42)` as `fieldValue.slice is not a function`, and `parseSignatureInput(validInput, null)` as `Cannot read properties of null (reading 'replace')` from `escapeRegExp`, while `parseSignatureInput(null, "sig1")` was even misreported as `signature "sig1" not present in Signature-Input` because `RegExp.exec` coerces `null` to the string `"null"`. A new shared `assertStringParam(caller, param, value)` guard (same family as `assertObjectParam`, exported from the package index) now runs first in both functions, throwing `"<fn>: "<param>" must be a string, got null"` — the `contentDigest` / `digest` `"must be a string, got …"` wording, with `null` named explicitly instead of reporting `typeof null` (`"object"`); the entry JSDoc records the ordering and the old misleading `"not present"` path. Twenty-two new tests in `test/structuredFieldParseShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for `null` / `undefined` / number / object / array field values and labels on both functions (plus a boxed-`String` object), the guard replacing the old misleading `"not present"` for a `null` field value, the unchanged legal dual-label parse (wire order, first-occurrence dedupe, components and params), the still-`"not present"` error for a genuinely absent label, the unchanged malformed-member error, and the shared helper pinned directly. A mutation check confirms 17 of 22 go red when the guards are disabled (the five passing are the guard-independent legal-behavior controls). Test counts move 2646 → 2668. Residual gap, same family, left for a follow-up item: `parseSignatureField` still dereferences a `null` label through the same `escapeRegExp` (a `null` field value there is already a named `"not present"` via `RegExp.exec`).

- `addSignature` / `addResponseSignature` reject a `null` or non-object signed message or options object with a named `Error` instead of a bare `TypeError` (backlog #1353): the two multi-party append entry points were the pair #1344 left unguarded — a live probe showed `addSignature(null, opts)` escaping as `TypeError: Cannot read properties of null (reading 'headers')` from the header scan and `addSignature(signed, null)` as `Cannot convert undefined or null to object` from `Object.keys(opts)` inside `assertNoUnknownOptions`, with the response side identical; a string `opts` was even misreported as an unknown option (`unknown option "0"`). The shared `assertObjectParam` guard now runs first in both functions (`"<fn>: signedReq/signedRes/opts must be an object"`), before `assertNoUnknownOptions` and the header scan, with an entry-named `headers` guard alongside (a `null` headers map escaped the same way from `Object.entries`); the entry JSDoc records the ordering. Twenty-one new tests in `test/addSignatureShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for `null` / `undefined` / string / number / array messages and `null` / string / number `opts` on both sides, the `null`-headers named error, the unchanged unsigned-message errors, and the unchanged legal append (merchant ed25519 + gateway hmac dual-sign still verifies both labels through `verifyAllLabels` / `verifyAllResponseLabels`, inputs unmutated). A mutation check confirms 17 of 21 go red when the guards are disabled (the four passing are the guard-independent legal-behavior controls). Test counts move 2625 → 2646.

- `fromNodeRequest` / `fromNodeResponse` reject a `null` or non-object request, response, or headers map with a named `Error` instead of a bare `TypeError` (backlog #1352): the two Node HTTP adapters were the one entry-point pair #1344 left unguarded — a live probe showed `fromNodeRequest(null)` escaping as `TypeError: Cannot read properties of null (reading 'method')` and `fromNodeResponse(null)` as `reading 'statusCode'`, and a `null` headers map on either side as `Cannot convert undefined or null to object` from `Object.entries` inside `normalizeHeaders`. The shared `assertObjectParam` guard now runs first in both adapters (`"<fn>: req/res must be an object"`), with entry-named `headers` guards before the `method` / `statusCode` fail-fast checks, a `trailers` guard inside `normalizeTrailers` (a `null` trailers map escaped the same way), and an `opts.request` guard on the response side (a `null` bound request used to throw `reading 'method'` when its fields were read); the entry JSDoc records the ordering. One deliberate non-change, checked by probe and pinned by test: `opts` itself stays unguarded — every `opts` read is optional-chained, so `null` opts behaves exactly like omitted opts, and there is no dereference gap to close there. Twenty-three new tests in `test/nodeHttpShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for `null` / string / number / array / `undefined` `req` and `res`, the `null` headers and trailers maps on both sides, the `null` / non-object `opts.request`, the unchanged missing-`method` / missing-`statusCode` errors, the `null`-opts-equals-omitted contract, and the unchanged legal adaptation and sign → adapt → verify round-trip. A mutation check confirms 16 of 23 go red when the guards are disabled (the seven passing are the guard-independent legal-behavior controls). Test counts move 2602 → 2625. Residual gaps, same family, left for follow-up items: `fromFetchResponse` / `fromFetchRequest` still dereference a `null` message with a bare `TypeError`, and `fromNodeResponse` silently accepts a non-string `opts.method` (e.g. `42`) into the adapted `RequestLike`.

- `verifyAllResponseLabels` rejects a `null` or non-object response or options object with a named `Error` instead of a bare `TypeError` (backlog #1351): the response-side multi-label entry point was the one #1344 deliberately left out of scope — it dereferenced `res.status` and `Object.keys(opts)` with no guard, so `verifyAllResponseLabels(null, {key})` escaped as `TypeError: Cannot read properties of null (reading 'status')` and a `null` `opts` as `Object.keys` on `null` inside `assertNoUnknownOptions`. The shared `assertObjectParam("verifyAllResponseLabels", "res" | "opts", …)` guard now runs first in `verifyAllResponseLabels`, before `assertNoUnknownOptions` and every other check, throwing `verifyAllResponseLabels: res/opts must be an object`; `verifyAllResponseLabelsOrThrow` inherits it through delegation, and the entry JSDoc records the ordering alongside the two existing configuration-error classes. A response with a `null` headers map already failed as the named `getHeader: headers must be an object` via #1344 and is unchanged. Twelve new tests in `test/verifyAllResponseLabelsShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for `null` / string / number / array / `undefined` `res` and `opts`, the guard-before-unknown-options ordering, the `null`-headers named error, the `OrThrow` inheritance, and the unchanged wire contract (dual-label round-trip verifies both labels through both variants, a malformed signature still returns `{ ok: false, code: "MALFORMED_SIGNATURE_INPUT" }`, a status tamper still fails both labels with `SIGNATURE_MISMATCH`). A mutation check confirms 7 of 12 go red when the guards are disabled (the five passing are the guard-independent legal-behavior controls). The README entry-point paragraph now counts six guarded sign/verify entry points. Test counts move 2590 → 2602.

- `ReplayCache` rejects a `null` or non-object options object with a named `Error` instead of a bare `TypeError` (backlog #1349): the constructor read `opts.maxEntries` with no guard on `opts` itself — the `= {}` default only covers `undefined` — so `new ReplayCache(null)` escaped as `TypeError: Cannot read properties of null (reading 'maxEntries')`, and a string or number `opts` was silently accepted with every field defaulted. The same shape of gap lived in the signed-restore entry points, which read `opts` before reaching the constructor: `restoreSignedSnapshot` dereferenced `opts.now` for the expiry check, and `restoreSignedSnapshotsByLabel` dereferenced `opts.expectedLabels`. A shared `assertObjectParam("ReplayCache", "opts", opts)` guard (the same helper backlog #1344 introduced for the sign/verify entry points) now runs first in the constructor, in `restoreSignedSnapshot`, and in `restoreSignedSnapshotsByLabel`, throwing `ReplayCache: opts must be an object`; `restore` / `fromSnapshot` inherit the guard through the constructor, and the `fromSignedSnapshot` / `fromSignedSnapshotsByLabel` aliases inherit it through the guarded statics. The guard sits before the secret validation in the signed paths, so a non-object `opts` wins over a bad secret. The `ReplayCacheOptions` JSDoc and the README replay-cache section document the rule. Fifteen new tests in `test/replayCacheOptsShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for `null` / string / number / array `opts` at all three guarded entry points, the `fromSnapshot` inheritance, the guard-before-secret ordering, and the unchanged legal construction and restores (defaults, custom `maxEntries` / `ttlSec` / injected clock, unsigned and signed snapshots, per-label maps). A mutation check confirms 10 of 15 go red when the guards are disabled (the five passing are the guard-independent legal-behavior controls). Test counts move 2575 → 2590.

- Sign/verify entry points reject a `null` or non-object request, response, or options object with a named `Error` instead of a bare `TypeError` (backlog #1344): a live probe showed all five entries escaping as `TypeError` — `verifyRequest(null, {key})` → `reading 'headers'`, `signRequest(null, {key})` → `reading 'body'`, `signResponse(null, {key})` → `reading 'status'`, and any entry with `null` options → `Object.keys` on `null` inside `assertNoUnknownOptions`. A shared `assertObjectParam(caller, param, value)` guard (new in `src/components.ts`, exported from the package index) now runs first in `signRequest`, `verifyRequest`, `verifyAllLabels`, `signResponse`, and `verifyResponse`, throwing `"<fn>: req/res/opts must be an object"`; the same guard sits in `getHeader` / `getHeaderRaw`, so a `null` headers map fails as `getHeader: headers must be an object` instead of `Cannot convert undefined or null to object`. The guard runs before `assertNoUnknownOptions` because the option checks dereference `opts` themselves, and the entry JSDoc records that ordering. One correction to the backlog sketch, found by a failing test: the sign side copies the headers map with `Object.entries` before any component resolution touches `getHeader`, so `signRequest` / `signResponse` carry an additional entry-named headers guard (`signRequest: headers must be an object`) — without it a `null` headers map still escaped as a bare `TypeError`. The throwing (`OrThrow`) variants inherit the guard through delegation, and a malformed wire signature is still a `{ ok: false, code }` result, never a throw (backlog #31). Twenty-four new tests in `test/entryShape.test.ts` pin the exact wording and the plain-`Error` (never `TypeError`) shape for all five entries × `null` req/res and `null` opts, the string/number/array variants, the `null` headers map on both sides, the `OrThrow` inheritance, the unchanged legal request/response round-trips, and the malformed-input contract. A mutation check confirms the tests go red when the guard is disabled (20 of 24 fail; the four passing are the guard-independent controls) and when only the `signRequest` headers guard is removed (exactly that one test fails). The README sign-side input-guards bullet documents the rule. Test counts move 2551 → 2575. Residual gap, same family, left for a follow-up item: `verifyAllResponseLabels` still dereferences a `null` response/options object with a bare `TypeError` (it was outside this item's five-entry scope).

- `memoizeKeyResolver` rejects a non-finite injected clock reading instead of silently degrading to a pass-through (backlog #1328): the factory only checked that `now` is a function and never validated what it returned, so a clock returning `NaN` made every `t < hit.expiresAt` comparison false — every lookup looked expired, the underlying resolver was called on every verify (a live probe showed two calls and `{ size: 1, hits: 0, misses: 2, evictions: 1 }` for two lookups of the same `keyid`, against one call and `{ size: 1, hits: 1, misses: 1, evictions: 0 }` under a good clock), and each lookup stored a `NaN`-timestamped entry. The impact was availability and observability, not signature acceptance: the memoizer silently stopped caching and hammered the keystore while inflating `evictions`. All clock reads now go through one `readClock()` closure — the lookup, `stats()`, and `clear()` — a non-finite value throws a configuration `Error` (`memoizeKeyResolver: clock must return a finite number of seconds since the epoch, got …`) before any cache state is read or changed, so a failed lookup leaves the cached entries and the counters exactly as they were, and `stats()` / `clear()` throw under a bad clock instead of reporting zero — the same shape as `ReplayCache`'s `resolveNow` (backlog #1288) and `JwksKeyStore`'s `readClock` (backlog #1291). The `MemoizeKeyResolverOptions.now` JSDoc and the `MemoizedKeyResolver` / `memoizeKeyResolver` docs record the finite-number contract, and the README memoizer section documents it. Ten new tests in `test/memoizeKeyResolverClock.test.ts` cover the `NaN` / `Infinity` / `-Infinity` / non-number readings with the exact error wording, the no-residue property (a failed lookup never calls the resolver and leaves no entry or counters), a cached entry surviving a bad-clock episode with counters unchanged, `stats()` / `clear()` throwing rather than reporting zero under a bad clock (and the entry surviving the failed clear), the unchanged TTL-boundary hit/miss counts under a good clock, and `verifyRequest` converging a bad clock to `VERIFICATION_ERROR` with zero keystore calls; a mutation check confirms the new tests go red when the guard is removed. Test counts move 2518 → 2528.

- `parseParamList` rejects malformed known signature-parameter values instead of silently normalizing them (backlog #1325): the old global-regex loop only recognized well-formed values and skipped the rest, so `created=1700000000.5` was truncated to `created: 1700000000`, `created=abc` / `created="1700000000"` / `keyid=123` / `alg=123` / `nonce=123` / `tag=123` vanished from the parsed parameters, and trailing garbage after the last parameter was ignored — a tampered `created` still verified `ok: true` in a live probe. The parser is now an anchored scan: every character of the parameter segment must be accounted for by a `;name=value` pair (or surrounding whitespace); `created`/`expires` must be bare `-?\d+` integers terminated by whitespace, `;`, `,` or end, `keyid`/`alg`/`nonce`/`tag` must be quoted strings, a missing value or a bare parameter without `=` is rejected, and unknown parameters are still ignored per RFC 9421 §2.4 but only as well-formed pairs. Malformed input throws `Error("malformed signature-input parameter ...")`, which `verifyRequest` / `verifyAllLabels` converge to `MALFORMED_SIGNATURE_INPUT` before any crypto runs (no new error code, following the #119 duplicate-parameter precedent); a bad label fails only that label. The `sign.ts` comment that described the verifier as silently truncating timestamps is rewritten to the new fail-closed behavior. Sixteen new tests in `test/parseParamMalformed.test.ts` cover the decimal `created`/`expires` rejections (asserting `MALFORMED_SIGNATURE_INPUT`, not `SIGNATURE_MISMATCH`, to prove pre-crypto rejection), the non-numeric / quoted-integer / unquoted-string rejections, trailing garbage, a missing value, a bare unknown parameter, the multi-label isolation, the still-ignored well-formed unknown parameters, the direct `parseSignatureInput` throw, and the whitespace / case-insensitive-name shapes that still parse; a mutation check confirms 3 of the 16 go red when the integer truncation guard is removed. The README fail-closed paragraph documents the rule. Test counts move 2502 → 2518.

- `JwksKeyStore` injected clock readings must be finite numbers (backlog #1291): the constructor only checked that `now` is a function and never validated what it returned, so a clock returning `NaN` made `isStale()`'s `clock() - lastRefreshAtSec >= ttlSec` comparison false forever — `refreshIfStale()` never re-fetched, `startAutoRefresh()` ticks never triggered a re-pull, and a rotated or revoked kid was trusted indefinitely; a `NaN` stored as `lastRefreshAtSec` did the same, and a `NaN` retry delay collapsed the `Retry-After` backoff to an immediate retry. All clock reads now go through one private `readClock()` helper — `isStale()`, both `lastRefreshAtSec` assignments in `fetchAndSwap()` (the 200 swap point and the 304 branch), the `Retry-After` HTTP-date branch, and the signed-snapshot restore fallback (whose explicit `now` override was already validated by `signedSnapshotRestoreNowSec`): a non-finite value throws a configuration `Error` (`JwksKeyStore: clock must return a finite number of seconds since the epoch, got …`) before any store state is read or changed, so a failed refresh leaves the old snapshot, the freshness timestamp, and the counters exactly as they were — no `NaN` timestamp is ever stored. The clock is read before the 304 counters move, so a failed 304 refresh is not counted as a 304 success. The `JwksKeyStoreOptions.now` JSDoc and the `isStale()` / `refresh()` / `retryAfterDelayMs()` docs record the finite-number contract. Eleven new tests in `test/jwksClockValidation.test.ts` cover `isStale()` / `refreshIfStale()` / `refresh()` / the 304 path / the `Retry-After` date path / `restoreSignedSnapshot` under a `NaN` clock, the `Infinity` and non-number readings, the no-fetch and no-residue properties (a failed refresh keeps the old snapshot verifying and the counters honest), the good-clock retry and TTL-boundary controls, and construction still succeeding with a bad clock while `isStale()` before the first refresh never reads it; a mutation check confirms 8 of the 11 go red when the guard is removed (the three passing are the controls). Test counts move 2446 → 2457.

- `ReplayCache` clock readings must be finite numbers (backlog #1288): `check()` / `has()` / `release()` read the explicit `now` argument (or the injected clock) without any finite-number check, and `size` / `exportSnapshot()` / `prune()` read the clock the same way — while the signed-snapshot path already rejected a non-finite `now`. A `NaN` reading made every `t - prev < ttlSec` comparison false, so a nonce already seen looked expired and was recorded again: the replay check silently stopped working, `prune(NaN)` never reclaimed expired entries, and a `NaN`-timestamped record left the replay window open until the next real-clock call. All clock reads now go through one private `resolveNow()` helper (explicit `now` wins, otherwise the injected clock): a non-finite value throws a configuration `Error` (`ReplayCache: now must be a finite number of seconds since the epoch, got …` for an explicit argument, `ReplayCache: clock must return a finite number …` for an injected clock) before any cache state is read or changed, so a failed call leaves no residue — no `NaN`-timestamped entry is ever recorded and the counters are untouched. `restore()` reads the new cache's clock through the same helper. The `ReplayCacheOptions.now` JSDoc and the `check()` / `has()` / `release()` / `size` / `exportSnapshot()` docs record the finite-number contract. Twelve new tests in `test/replayClockValidation.test.ts` cover `NaN` / `Infinity` / non-number explicit `now` on all three entry points, an injected clock returning `NaN` (construction still succeeds, the first call throws) or a non-number, the no-residue property (failed calls leave content and counters unchanged and a later good-clock `check` still reports the replay), `size` / `exportSnapshot` throwing instead of reporting 0 / an empty snapshot under a bad clock, and the unchanged legal-clock behavior; a mutation check confirms 11 of the 12 go red when the guard is removed (the twelfth is the legal-clock control). Test counts move 2434 → 2446.

- `ReplayCache.check` rejects non-string nonces (backlog #1286): `check()` only guarded the empty string while `has()` / `release()` already rejected any non-string nonce, so a JS caller passing `check(123)` silently recorded a numeric key and a later `check("123")` missed the replay — the cache and the caller disagreed about whether the nonce had been seen, and the replay check was bypassed for that nonce. `check()` now throws the same configuration `Error` (`ReplayCache: nonce must be a non-empty string`) as `has()` / `release()` for a non-string nonce; the empty-string error is unchanged, and a rejected nonce leaves no residue in the cache. The `check()` JSDoc and the `NonceStore` interface doc are synced. Eight new tests in `test/replayCheckNonceType.test.ts` cover the number / object / null / undefined rejections, the unchanged empty-string error, the no-residue property, the unchanged string hit/miss behavior, and the wording match with `has()` / `release()`; a mutation check confirms 6 of the 8 go red when the guard is removed. Test counts move 2426 → 2434.

- `signRequest` refuses to cover `@status` (backlog #1283): RFC 9421 §2.2.9 states `"@status"` MUST NOT be used in a request message, but the signer minted exactly that shape whenever a caller covered it on a request-shaped object — the `@status` resolver only checks that `target.status` is present, so `test/statusComponent.test.ts` even signed responses through `signRequest`. `signRequest` now fails fast with a plain configuration error (`signRequest: "@status" must not be covered in a request signature (RFC 9421 §2.2.9: ...); sign the response with signResponse instead`) before any base is built or crypto runs; the check matches by base name, so `"@STATUS"` and `"@status";req` are refused the same way. The signing core is now a shared `signRequestCore(req, opts, allowStatus)` — the request entry point passes `false`, `signResponse` passes `true` (the one place an `@status` signature may be minted), and `addSignature` / `addResponseSignature` inherit the split through their respective delegations. The verify side is unchanged: `verifyRequest` also carries response verification, so it still accepts a `@status` signature. Existing tests that signed response-shaped messages through `signRequest` are migrated to the response entry points (`statusComponent`, `bsComponent`, `signedCoveredComponents`, `setCookieComponent`, `reqComponent`, the `nodeHttpResponse*` family, and the demo's gateway fixtures, which now use `signResponse` / `addResponseSignature`); one stale regex in `reqComponent.test.ts` quoted the component as `"@method";req` while the error renders `"@method;req"` and is corrected. Eleven new tests in `test/signStatusRejected.test.ts` cover the bare / `;req` / case-variant rejections, `@status` among other components, `signResponse` still signing and verifying, `addSignature` inheriting the refusal, `addResponseSignature` still appending both labels, `verifyRequest` on a response-side `@status` signature unaffected, the unchanged no-`@status` request paths, and the error naming `signResponse`; a mutation check confirms 6 of the 11 go red when the guard is removed. The README sign-side input-guards bullet documents the refusal. Test counts move 2415 → 2426.

- A non-string/non-Buffer request body is now fail-closed on both sides of the digest binding (backlog #1280): `contentDigest()` previously passed its body straight to `Buffer.from`, so a JS caller signing with `body: 123` got a bare `TypeError` instead of the library's configuration-error wording — and `digest()` already rejected the same input, so the two digest helpers disagreed. Worse, `verifyRequest` never throws by contract, but its two body-binding checks (`content-digest` and legacy `Digest`) fed the body straight into `createHash().update()`, so the same malformed body escaped as a bare `TypeError` from the verifier. `contentDigest()` and `contentDigestAlgOf()` now reject a non-string/non-Buffer body (and a non-string value) with a plain configuration error in `digest()`'s wording, inherited by `signRequest` / `addSignature` through the auto-compute path; the verifier instead returns a `VERIFICATION_ERROR` failure (`body must be a string or a Buffer, got <typeof>`) from both digest checks, and `errors.ts` documents that code as covering this case. Twelve new tests in `test/nonStringBody.test.ts` cover the number/boolean/object/array bodies on the signing side (plain `Error`, never `TypeError`, message names the type), both digest checks on the verifying side (failure result, never a throw; `verifyRequestOrThrow` throws `VerifyError` with code `VERIFICATION_ERROR`), `contentDigestAlgOf(123)`, and the unchanged string / Buffer / undefined-body paths; a mutation check confirms the new tests go red when either guard is removed. Test counts move 2403 → 2415.

- `@query` binds `"?"` when the request has no query string (backlog #1277, breaking change): `resolveComponent` returned `url.search` verbatim, so a query-less request bound the empty string while RFC 9421 §2.2.7 directs the value to be the leading `?` character alone — a signature covering `@query` on such a request failed against any compliant implementation, and the empty-string value was pinned as correct by the golden base test. The `@query` branch now returns `"?"` when `url.search` is empty (a bare trailing `?` binds `?` the same way, since WHATWG URL reports it identically), while `@request-target` keeps its own rule of no trailing `?` when there is no query. Signatures minted under the old empty-string value no longer verify and must be re-signed. Three new tests in `test/queryComponent.test.ts` cover the bare-`?` golden base, the bare trailing `?` round trip, the unchanged `@request-target`, and the old-value signature now failing with `SIGNATURE_MISMATCH`; a mutation check confirms 3 of the 12 query tests go red when the branch is reverted to the empty string. Test counts move 2400 → 2403.

- `verifyAllLabelsOrThrow` attaches the full per-label array as `.verifyResults` on the thrown error (backlog #1274): the request-side throwing twin threw a `VerifyError` carrying only the first failing label's `code` / `label` / wire fields, while the response-side twin `verifyAllResponseLabelsOrThrow` (backlog #1250) already attached the whole array — so a gateway verifying a dual-signed request (one signature bad, one good) could not see which label had passed without re-running `verifyAllLabels`, and a webhook rejection log lost the passing co-signature. The throw now attaches `verifyResults: [...results]`, a detached copy in wire order, exactly as the response side does; `verifyRequestOrThrow` is unchanged (a single label has no array to attach). The `VerifyErrorOptions.verifyResults` doc now names the throwing twins instead of the non-throwing verifiers, and the README multi-label throwing section and Error codes section state the request/response parity. Eight new tests in `test/verifyAllLabelsOrThrowVerifyResults.test.ts` cover the two-label bad/good attachment with wire order and error-field agreement, both directions of the detached-copy check, the unchanged success return, the `MISSING_REQUIRED_LABEL` synthetic failure inside the attached array, the unsigned `[]` no-throw, the single-label failure, and the first-failing-label-wins order with both failures present; a mutation check confirms 5 of the 8 go red when the attachment is emptied. Test counts move 2392 → 2400.

- `signRequest` auto-computes the `content-digest` header for parameterized coverage too (backlog #1271): the digest auto-compute trigger compared the covered component id as a whole lowercased string, so `content-digest;bs`, `;sf`, and `;key="sha-512"` — all legal value-parameter forms that still bind this message's header — threw `covered header field "content-digest" is missing from the request` instead of signing, breaking the byte-level body binding a gateway asks for. The trigger now matches by component base name (the part before the first `;`, case-insensitively — a new `coversOwnContentDigest` helper in `src/sign.ts`, the same base-name idiom as the `requiredComponents` coverage check, backlog #1267), so the value parameters (`;bs`, `;sf`, `;key="…"`) trigger the computation exactly like the bare form; `;req` and `;tr` are excluded because they redirect the binding to the associated request and to the trailers, so a missing target keeps its existing fail-fast error — and an unsupported parameter still reports as unsupported — instead of silently minting a header the base ignores. `signResponse` / `addSignature` / `addResponseSignature` inherit the fix through delegation. Thirteen new tests in `test/contentDigestParamAutoDigest.test.ts` cover the `;bs` / `;sf` / `;key="sha-512"` round trips with the header pinned to the independently computed digest, the `;tr` / `;req` fail-fast boundaries, the `;req` attached-request round trip, the bodyless no-body error, the mixed-case `Content-Digest;BS` trigger, the body tamper failing with `BODY_DIGEST_MISMATCH`, the unchanged bare form, the response-side round trip, and the `sha-256` digest-alg option, and the unknown-parameter error surviving unmasked; a mutation check confirms 8 of the 13 go red when the trigger is reverted to the exact match. The README Body binding bullet documents the rule. Test counts move 2379 → 2392.

- Node / fetch request adapters reject a non-`http(s)` scheme (backlog #1270): `fromNodeRequest` took the effective scheme from `opts.scheme`, the `:scheme` pseudo-header, or the socket inference with no validation, so `opts.scheme: ""` built a `://host/path` URL (failing later inside `resolveComponent`'s `new URL()` with the wrong error) and `opts.scheme: "ftp"` or a `:scheme: ftp` pseudo-header built an `ftp://…` URL that `new URL` accepted and verified normally — the signing library would build and verify a signature base over a non-HTTP scheme. `fromFetchRequest` passed any absolute URL through verbatim after only a host check, so `ftp://host/path` flowed in the same way. A shared `assertHttpScheme(scheme, caller)` in `src/nodeHttp.ts` now runs before any URL is assembled in both adapters: the effective scheme must be `http` or `https` (case-insensitive), otherwise a plain configuration `Error` (`fromNodeRequest: scheme must be "http" or "https", got "<value>"` / `fromFetchRequest: req.url scheme must be "http" or "https", got "<value>"`) — an empty string, `ftp`, `javascript:`, and a non-string value from a JS caller are all rejected; an uppercase `HTTPS` option or URL is accepted and normalizes to `https`, and an explicit `{ scheme }` still wins over a bogus `:scheme` pseudo-header. `createVerifiedHandler` / `createVerifiedFetchHandler` inherit the check through the adapters (a bad scheme still surfaces as the handler's 400). Twelve new tests in `test/adapterScheme.test.ts` cover the empty / `ftp` / `javascript:` / pseudo-header / non-string rejections, both `ftp://` and `javascript:` fetch URLs, the uppercase `HTTPS://` acceptance with `@scheme` resolving to `https`, the uppercase option rebuild, the option-beats-pseudo-header precedence, and the unchanged `http` / `https` round trips; a mutation check confirms 10 of the 12 go red when the guard is bypassed. The README adapter sections document the scheme rule. Test counts move 2367 → 2379.

- `requiredComponents` now matches by component base name, with `;req` exact (backlog #1267): the coverage check compared the wire component id as a whole lowercased string, so it was wrong in both directions at once — a signature covering `"content-digest";bs` (a strictly stronger, byte-level body binding) was rejected against a `content-digest` requirement, while a signature covering only `"content-digest";req` passed it even though `;req` redirects the binding to the associated request and leaves this message's body unbound (reachable on the response path, where `verifyResponse` / `verifyAllResponseLabels` delegate to `verifyRequest` / `verifyAllLabels` with the triggering request attached). The comparison now splits each id into its base name and its `;req` flag (new `splitComponentIdForCoverage` helper in `src/verify.ts`, next to `coversWholeDigestField`): value parameters (`;bs`, `;sf`, `;key="…"`, `;tr`) no longer affect the decision, but a `;req` coverage only satisfies a `;req` requirement and a plain coverage only satisfies a plain requirement. `VerifyOptions.requiredComponents` and `VerifyAllOptions.requiredComponentsByLabel` JSDoc document the rule and the exception; `verifyAllLabels` inherits it through the shared `verifyRequest` path. Eleven new tests in `test/requiredComponentsParams.test.ts` cover the `;bs` / `;sf` / `;key="sha-512"` / `;tr` satisfactions, the `;req` misdirection and its reverse, the combined `;req;bs` form, the mixed-case variant, per-label isolation in `verifyAllLabels`, and the unchanged bare-entry behavior with the original reason wording; a mutation check confirms 4 of the 11 go red when the `;req` exactness is removed. The README Required components bullet documents the rule. Test counts move 2356 → 2367.

- `signRequest` rejects a malformed `coveredComponents` list (backlog #1264): the signer only checked that the list was non-empty, short, and duplicate-free, so a JS caller passing `"content-digest"` (not an array), `[123]`, `[null]`, or `[""]` crashed `covered.map((c) => c.toLowerCase())` — or the duplicate guard's `entry.trim()` — with a bare `TypeError` instead of a configuration error in the entry point's own words. A shared `assertCoveredComponentsShape(caller, covered)` (exported from `src/index.ts`) now runs before the empty-list, length, and duplicate checks in `signRequest`, throwing `signRequest: "coveredComponents" must be an array of component identifiers` for a non-array and `signRequest: coveredComponents[<i>] must be a non-empty string, got <typeof>` for a bad entry; `signResponse` runs the same guard with its own caller name before its duplicate check (its delegation to `signRequest` would otherwise arrive too late), and `addSignature` / `addResponseSignature` inherit it through delegation. An explicit `null` is rejected the same way — the default list is now resolved only when the option is `undefined`, instead of being swallowed by `??`. Sixteen new tests in `test/signCoveredComponentsShape.test.ts` cover the non-array string / object / null cases, the number / null / undefined / object / empty-string entries with their indices, the plain-`Error` (not `TypeError`) shape, the throw happening before any base is built or crypto runs (input request untouched), duplicates still reporting the original duplicate error, the `;bs` and `;req` parameterized round trips, and the response-side guard in its own words. The README sign-side input-guards bullet documents the rejection. Test counts move 2340 → 2356.

- `signRequest` rejects an empty-string `keyId` (backlog #1261): the signer checked `keyId` only against the 256-character length cap, so `keyId: ""` was written into `signature-input` as `keyid=""` — while the verifier treats an empty `keyid` exactly like a missing one and fails key resolution (`KEY_RESOLUTION_FAILED`), and the `expectedKeyId` binding can never match it, so the signer minted signatures its own verifier always refuses. The empty check now runs before the length check (`signRequest: "keyId" must not be an empty string; an empty keyid cannot be resolved`), the same fail-fast position and style as the `nonce` / `tag` empty-string checks; a whitespace-only `keyId` is non-empty and still signs, and `addSignature` inherits the rejection through delegation. Seven new tests in `test/signEmptyKeyId.test.ts` cover the empty-string rejection with the field named in the message, the whitespace-only sign, the exactly-256-characters sign, the 257-character length error surviving unmasked, the normal `keyId` round-trip with `VerifyResult.keyId` echoing it, the omitted-`keyId` path, and the `addSignature` inheritance. The README Optional `keyid` bullet documents the rejection. Test counts move 2333 → 2340.

- `signRequest` rejects negative `created` / `expires` timestamps (backlog #1258): `assertTimestamp` in `src/sign.ts` only checked `Number.isInteger`, so `signRequest({ created: -100 })` minted a signature with `created=-100` on the wire — and with no `expires`, the verifier's freshness checks never fire on it (the age check only runs when `maxSignatureAgeSec` is set), so it verified as a signature that never expires; `created: -5, expires: -5` slipped past the `expires < created` guard as equal. The shared assertion now also requires non-negative values (`signRequest: "<name>" must be a non-negative integer number of Unix seconds, got <value>`), covering both absolute timestamps and the `expiresInSec`-derived `expires` (resolved through the same assertion), while `created: 0` (the Unix epoch) stays legal. `signResponse`, `addSignature`, and `addResponseSignature` inherit the check through delegation. Ten new tests in `test/signNegativeTimestamps.test.ts` cover the negative `created` / `expires` / equal-pair / `expiresInSec` rejections, the exact error wording with field name and value, the plain-`Error` (not `TypeError`) shape, the `created: 0` sign-and-verify boundary, and the unaffected old paths (normal round-trip, `expires < created` still reports its original error). The README sign-side input-guards bullet documents the rejection. Test counts move 2323 → 2333.

## [0.2.0] - 2026-11-18

### Added

- Benchmark now covers the `memoizeKeyResolver(...).stats()` observability path (backlog #1225): a new `memoizeKeyResolver stats (3 keys)` row measures the detached four-counter snapshot a verifier's monitoring polls on every tick — one `stats()` call per measured op over a fixed-clock resolver primed outside timing (a pinned four-key store under a three-entry capacity, injected `now` frozen at the stats instant: three keys cached, three hits, two lookups of an unknown keyid that is never cached, and a fourth key whose insertion LRU-evicts the oldest entry), self-checking all four counters against the hand-pinned `{ size: 3, hits: 3, misses: 6, evictions: 1 }` on every pass, plus the underlying resolver call count against the miss count. Outside timing the bench pins the detached-copy half (a returned snapshot overwritten with 999s leaves a re-read unchanged), the empty-resolver half (all-zero stats), and the cleared-resolver half (clear() resets all four counters, size 0); a mutation check confirms the row goes red when the pinned hit count is changed. In this run it measured 4,375,232 ops/sec (0.23 µs/op), about the same as the same run's `JwksKeyStore.stats` row (4,327,693 ops/sec) and `ReplayCache.stats` row (4,231,765 ops/sec) — the expected shape, since all three readings are pure detached copies of a few counters. The README Benchmarks table is refreshed from the same run (2026-11-18, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- Benchmark now covers the `JwksKeyStore.stats()` observability path (backlog #1224): a new `JwksKeyStore.stats (3 keys)` row measures the detached six-counter snapshot a gateway's monitoring polls on every tick — one `stats()` call per measured op over a fixed store primed outside timing by a counting fake fetch (two 200s under remembered ETags, one failed 500 refresh and one 304, three pinned kids resolving and two unknown kids missing), self-checking all six counters against the hand-pinned `{ refreshes: 3, refreshFailures: 1, hits: 3, misses: 2, conditionalRefreshes: 2, notModified: 1 }` on every pass. Outside timing the bench pins the detached-copy half (a returned snapshot overwritten with 999s leaves a re-read unchanged) the empty-store half (all-zero stats), and the cleared-store half (clear() resets all six counters, size 0, lastRefreshedAt null); a mutation check confirms the row goes red when the pinned hit count is changed, and a second mutation check confirms the cleared-store probe goes red when its refreshes expectation is changed. In this run it measured 5,470,938 ops/sec (0.18 µs/op), about 4.1x the same run's `ReplayCache.stats` row — the expected shape, since a JWKS stats reading only copies six counters while a replay stats reading scans its map for live entries first. The README Benchmarks table is refreshed from the same run (2026-11-18, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- Benchmark now covers the oversized `signature-input` rejection path (backlog #1218): a new `verifyRequest oversized signature-input (rejected)` row measures the pre-parse length gate — one `verifyRequest` call per measured op over the shared fixture signed with a pinned ed25519 key and `created`, its `signature-input` header bloated past the default 65,536-byte limit by repeating the `"@path"` covered component inside the component list, self-checking the exact fail-closed result (`SIGNATURE_INPUT_TOO_LARGE` with the pinned reason carrying the oversized byte count) on every pass — plus a side-by-side `verifyRequest signature-input within limit` control row that verifies the same request whole at legal length. Outside timing the bench pins the per-label half: a dual-signed request under `verifyAllLabels` with `maxSignatureInputLengthByLabel: { sig1: 50 }` rejects only the over-limit label while the other still verifies; a mutation check confirms the rejection probe goes red when the oversized header is swapped back to legal length. In this run the rejection row measured 24,474 ops/sec (40.86 µs/op) against 2,495 ops/sec (400.76 µs/op) for the control row — about 9.8x faster, the expected short-circuit shape. The README Benchmarks table gains the rows from the same run (2026-11-17, Node v24.22.1, AMD EPYC 9D25) with prose paragraphs for the new rows.
- Benchmark now covers the throwing multi-label verification path (backlog #1217): a new `verifyAllLabelsOrThrow (2 labels)` row measures the throwing twin of the plain `verifyAllLabels` row — one `verifyAllLabelsOrThrow` call per measured op over the same dual-signed request (merchant `sig1` ed25519 with a pinned nonce, gateway hmac-sha256, `created` pinned), self-checking the returned `VerifyResult[]` on every pass (both labels ok, in wire order, each with its pinned label / keyid / alg and the merchant nonce). Outside timing the bench pins the tampered-body half: the same request with one body byte changed (amount 100 -> 101) throws the first failing label's `VerifyError` (`BODY_DIGEST_MISMATCH` for `sig1`, the first label in wire order, passing the `isVerifyError` guard), and the non-throwing `verifyAllLabels` contrast on the same tampered request reports both labels failing with that code, because the body-digest check runs for every label whenever a `content-digest` header is present, covered or not — the throwing call hides the second failure by surfacing only the first. In this run it measured 4,774 ops/sec (209.47 µs/op), slightly slower than the non-throwing row in the same run (5,144 ops/sec), which is the expected shape: the wrapper runs the same two verifications and only adds the per-result loop. The README Benchmarks table is refreshed from the same run (2026-11-17, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- The CLI demo now shows the JWKS auto-refresh loop end to end (backlog #1212): a new closing segment drives `JwksKeyStore.startAutoRefresh(60_000)` on a recording fake interval implementation — no real system timer is ever created and no tick is ever waited on — while the store fetches from a real loopback endpoint serving a one-key JWKS document: the timer is created at 60_000 ms and `unref()`d once, a second start while it runs is rejected with the pinned error, one manual tick refreshes the stale snapshot (`stats().refreshes` steps to 1, the scripted key resolves, `lastRefreshedAt` reads the pinned instant), a tick after `stop()` fetches nothing even once the injected clock has advanced 301s past the 300s TTL, and a restart followed by `clear()` stops the second timer, resets the stats counters, and leaves the restart's `stop()` a safe no-op. The segment asserts every count, size, timestamp and error message against hand-pinned `DEMO_JWKS_AUTO_REFRESH_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives the whole lifecycle independently with a fresh key pair and loopback endpoint, and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the fake tick never fires its callback. The README JWKS auto-refresh and demo sections gain the demo pointer, and test counts move 2289 → 2290.
- The CLI demo now shows the per-label structured-field types split (backlog #1209): a new closing segment judges the same `x-quota` field under `verifyAllLabels`' `structuredFieldTypesByLabel` map — a lone token `a` verifies under both labels when the merchant (`sig1`) registry reads it as a Dictionary and the gateway registry reads it as an Item, while a Dictionary-shaped `a=1` signed with no registry verifies under the same split map for the merchant label only and fails the gateway label closed with `SIGNATURE_BASE_BUILD_FAILED` (hand-pinned code and reason) — showing that a field's type is a per-label agreement and a mis-registered label is rejected alone. The segment asserts every outcome against hand-pinned `DEMO_SF_TYPES_BY_LABEL_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives both passes independently with fresh key pairs (including a reversed map that reverses which label fails), and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the mismatch expectation is changed. The README demo section and test counts move 2288 → 2289.
- Benchmark now covers the `JwksKeyStore.refresh` maxBodyBytes rejection path (backlog #1201): a new `JwksKeyStore.refresh (maxBodyBytes 128, loopback reject)` row measures the rejection a gateway pays when its JWKS endpoint serves an over-limit body — a store capped at `maxBodyBytes: 128` against a real loopback `http` server that serves the small pinned one-key document on the first request only (the priming refresh) and the oversized three-shape document on every later request, both with an honest Content-Length, so every measured refresh trips the Content-Length precheck and never reads the body (a recording stub sleep is injected and must stay at zero waits — the rejection is terminal for retries). Every measured pass self-checks the same pins: the refresh throws the exact Content-Length rejection carrying the endpoint URL, makes exactly one fetch, counts exactly one more `stats().refreshFailures` and no more `stats().refreshes`, leaves `lastRefreshedAt` unchanged, and the primed kid still resolves; outside timing the bench pins the lying-Content-Length half (an advertised 10-byte length over an over-cap body is still intercepted by the post-read byte check, with the same old-snapshot-kept pins). In this run it measured 6,544 ops/sec (152.82 µs/op). The README Benchmarks table is refreshed from the same run (2026-11-17, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- Structured Fields parsing/serialization now has fuzz coverage (backlog #1199): a new `test/structuredFieldsFuzz.test.ts` puts `canonicalizeStructuredFieldValue` (Dictionary → List → Item trial order), `canonicalizeStructuredFieldValueAs` (pinned type), and `serializeDictionaryMemberValue` through a deterministic 1,547-case corpus (fixed seed + mulberry32) of hand-built valid values across every SF type, truncations and byte-level mutations of those values, grammar-generated Dictionaries/Lists/Items/Inner Lists, hand-built malformed shapes, byte soup, and pathological sizes. Every case asserts the either/or contract: an accepted value is a sanitized fixed point (re-canonicalization is byte-identical, a Dictionary member re-derives identically from the canonicalized value or from a fresh `key=<member>` Dictionary), and a rejected value throws a plain `Error` with a clear prefix, never a TypeError/ReferenceError. A separate list of known-illegal values (uppercase percent-escapes, a Decimal Date, control characters and illegal escapes in Strings, over-long numbers, bad base64, nested Inner Lists) is asserted rejected by all five entry points, and a determinism test rebuilds the corpus from the same seed and compares outcome fingerprints. The timing guard follows the backlog #242 median pattern (50 ms budget, 20x catastrophic bound); this run measured a 0.016 ms median and a 60.3 ms worst single call per call, the latter well under the 1,000 ms catastrophic bound. Five new tests; the README test counts move 2283 → 2288.
- The CLI demo now shows the `;key` structured-field registry agreement (backlog #1194): a new registry segment judges the same Dictionary field three ways against the caller-supplied `structuredFieldTypes` registry — unregistered the `;key="b"` component round-trips, registered as a List the sign side throws the pinned refusal and the verify side converges on `SIGNATURE_BASE_BUILD_FAILED`, and registered as a Dictionary it behaves exactly as before — showing that `;sf` and `;key` agree on a field's type instead of silently parsing a List-registered field as a Dictionary. The segment asserts every outcome against hand-pinned `DEMO_KEY_REGISTRY_*` expectations, and one new demo test pins the segment's `DemoResult` fields and its printed lines, re-derives all three outcomes independently with a fresh key pair, and confirms the lines are byte-identical between runs; a mutation check confirms the demo test goes red when the List-registry expectation is changed.
- Benchmark now covers the `JwksKeyStore.refresh` Cache-Control max-age path (backlog #1197): a new `JwksKeyStore.refresh (Cache-Control max-age=60)` row measures the refresh a gateway pays when its JWKS publisher declares a short `max-age` — the store's default fetch against a real loopback `http` server stamping its 200 with `Cache-Control: max-age=60`, against a store configured with `ttlSec: 300` and an injected clock, so the effective TTL is `min(300, 60) = 60`. Every measured pass builds a fresh store, refreshes once, and re-proves the shortened TTL (fresh at the refresh instant, still fresh at +59s, stale at +61s) and that the pinned kid resolves; outside timing the bench pins the never-lengthens half (`max-age=3600` leaves the effective TTL at the configured 300). In this run it measured 4,983 ops/sec (200.70 µs/op). The README Benchmarks table gains the row from the same run (2026-11-16, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- Benchmark now covers the `JwksKeyStore.refresh` Retry-After path (backlog #1188): a new `JwksKeyStore.refresh (Retry-After 2s, 429/200)` row measures the rate-limited refresh a gateway pays when its JWKS endpoint answers 429 with `Retry-After: 2`, over a real loopback `http` server that rate-limits the first fetch of every refresh cycle and serves the pinned JWKS document on the retry (a stub sleep records the honoured 2000 ms wait without waiting, so no wall-clock wait is measured). Every measured pass self-checks that the refresh made exactly two fetches, recorded exactly one sleep of 2000 ms, counted exactly one `stats().refreshes`, and resolves the pinned kid; outside timing the bench pins the cap half of the contract (`Retry-After: 3600` waits exactly the default `fetchMaxRetryDelayMs` of 60,000 ms, never the hour the endpoint asked for). In this run it measured 1,956 ops/sec (511.37 µs/op). The README Benchmarks table is refreshed from the same run (2026-11-16, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- The CLI demo now shows the JWKS conditional refresh path end to end (backlog #1184): a new JWKS conditional refresh segment runs after the observability segment — a real loopback endpoint stamps its first 200 with a pinned ETag, the store's second refresh sends it back as `If-None-Match` and is answered 304 Not Modified with the same ETag, the snapshot's kid set is unchanged, `lastRefreshedAt` stays at the pinned instant, and a request signed under the kept key still verifies, with `stats()` counting the conditional path once on each side (`conditionalRefreshes` 1, `notModified` 1). The segment asserts every value against hand-pinned `DEMO_JWKS_CONDITIONAL_REFRESH_*` expectations, and the printed lines are byte-identical between runs (only the loopback port and the key pair are fresh per run). Two new demo tests pin the segment's `DemoResult` fields and its printed lines; a mutation check confirms the demo fails closed when the endpoint answers 200 both times (`notModified` 0 against the pinned 1).
- Benchmark now covers `buildJwksDocument` (backlog #1181): a new `buildJwksDocument (3 keys)` row measures the JWKS document build a signer runs on every key rotation, over a fixed three-shape entry list (ed25519, P-256, RSA under pinned kids, generated once outside timing). Every measured pass re-pins the whole built document (kid order, per-shape `kty`, EC `crv` P-256, no private `"d"` member); outside timing the assembled document is restored offline into a `JwksKeyStore` and all three kids resolve, and a duplicate-kid entry list is refused with the pinned message. In this run it measured 13,651 ops/sec (73.25 µs/op). The README Benchmarks table is refreshed from the same run (2026-11-16, Node v24.22.1, AMD EPYC 9D25) with a prose paragraph for the new row.
- `signRequest` now accepts opt-in `autoNonce: true` (backlog #1173): when set and no explicit `nonce` is passed, the signer generates a fresh UUID v4 (`crypto.randomUUID()`) for the signature and writes it into `signature-input` exactly as an explicit nonce would be — covered by the signature, echoed on `VerifyResult.nonce`, and recorded by the verifier's replay cache, so a second verification of the same request fails with `NONCE_REPLAY`. Passing both `autoNonce: true` and an explicit `nonce` is a configuration error (the two would name the same wire parameter). `autoNonce: false` (the default) leaves the wire exactly as before. `signResponse`, `addSignature`, and `addResponseSignature` inherit it through delegation, so each appended label gets its own fresh nonce. Twelve new tests in `test/signAutoNonce.test.ts`, including two signatures carrying different UUID v4 nonces, the mutual-exclusion error, the `ReplayCache` round-trip, tampering with the generated nonce failing with `SIGNATURE_MISMATCH`, and the `signResponse` / `addSignature` inheritance paths. The README Nonce section and SECURITY.md document the option and the fixed-nonce footgun it removes.
- `signRequest` and `signResponse` now accept `alg: "infer"` (backlog #1172): the signing algorithm is derived from the key's shape at signing time — secret → `hmac-sha256`, ed25519 → `ed25519`, P-256/P-384/P-521 → the matching `ecdsa-p*-*` algorithm, RSA → `rsa-pss-sha512` — through the new shared `inferAlgFromKeyShape` helper in `src/keys.ts`, the same mapping the verify side already applied under `algFallback: "infer"` (the verify side now delegates to it, with its pinned error message unchanged). The inferred value is written into `signature-input` exactly as an explicit alg would be, so the wire shape and `VerifyResult.alg` are identical to naming the algorithm outright; a secret key never infers `hmac-sha512`, and an unmappable key shape (e.g. secp256k1) is a configuration error thrown before the signature base is built. `addSignature` and `addResponseSignature` inherit it through delegation. Thirteen new tests in `test/signAlgInfer.test.ts`, including all six key shapes, byte-identical headers for explicit-vs-inferred hmac-sha256, the secp256k1 refusal, the `signResponse` path, verification under `algFallback: "infer"`, and a two-label `addSignature` round-trip. The README signing section documents the option.
- Response-side RFC 3230 `Digest` body binding is now covered by
  tests (backlog #1171): `verifyResponse` and
  `verifyAllResponseLabels` enforce the same Digest rules as the
  request side — a covered `digest` whose value does not match the
  body, is missing, is md5-only, or names an unknown algorithm fails
  with `BODY_DIGEST_MISMATCH`, while an uncovered Digest header is
  not checked. The binding itself already held through the shared
  verify path (a live probe confirmed it before these tests were
  written, so this entry adds regression coverage, not a new code
  path): twelve new tests in `test/responseDigest.test.ts`,
  including sha-256/sha-512 round-trips, dual `Digest` +
  `Content-Digest` coverage, the `digest;bs` form, and per-label
  isolation in `verifyAllResponseLabels`. The README response
  signing section documents the legacy-gateway usage.
- `JwksKeyStore.refresh()` now honours `Retry-After` on rate-limited
  JWKS endpoints (backlog #1170): HTTP 429 (Too Many Requests) is
  retryable — the one 4xx that says "try again later" rather than
  "the request is wrong" — and a 429 or 503 response carrying a
  `Retry-After` header is waited out for the header's delay, in
  either of its RFC 9110 §13.1.2 forms (delay-seconds, or an
  HTTP-date measured against the store's injected `now` clock),
  capped at the new `fetchMaxRetryDelayMs` option (default 60,000
  ms, one minute; a finite number >= 0, rejected at construction
  otherwise). A missing, unparseable, or negative `Retry-After`
  falls back to the fixed `fetchBackoffMs` instead of throwing, so
  a broken header never turns a recoverable retry into a hard
  failure. Every other 4xx stays terminal on the first attempt, the
  wait still goes through the injectable `sleepImpl`, `fetchRetries`
  is still the total-attempt cap, and `resolve()` keeps serving the
  old snapshot while a retry is waiting. Eleven new tests in
  `test/jwksRetryAfter.test.ts`, including the 2000 ms sleep on
  `Retry-After: 2`, the HTTP-date delay under an injected clock,
  the cap, the fixed-backoff fallback, the terminal 404, and the
  exhausted-retry snapshot preservation. The README JWKS section
  documents the behaviour.
- `JwksKeyStore` now sends conditional refreshes (backlog #1169):
  after a successful `refresh()` whose response carried an `ETag`,
  the store remembers the validator and sends it as `If-None-Match`
  on the next fetch, so a publisher that supports conditional
  requests can answer `304 Not Modified` instead of re-serving an
  unchanged key set. A 304 is a success, never an error and never
  retried: the body is never read (`json()` is not called), the
  snapshot is kept exactly as it was, and only `lastRefreshedAt`
  advances to the fetch time. A 200 replaces the snapshot as usual
  and updates the remembered `ETag` from its own response; a 200
  without an `ETag` (or with an empty one) clears the remembered
  validator, and `clear()` and both snapshot restores clear it too.
  `JwksFetchImpl` gains an optional second argument
  `{ headers?: Record<string, string> }` carrying the header; with
  no remembered `ETag` no second argument is passed, so legacy
  single-argument implementations keep working untouched. `stats()`
  gains `conditionalRefreshes` and `notModified` (the demo's pinned
  observability and clear-segment stats, and its printed `stats()`
  lines, now show all six counters). A 304 that lands over
  plaintext http is still rejected under `requireHttps`. Fifteen new
  tests in `test/jwksConditionalRefresh.test.ts`, including a 304
  that must not call `json()`, the effective-TTL freeze across a
  304, and the ETag reset on both restore paths. The README JWKS
  section documents the conditional refresh.
- `fromNodeRequest` now accepts HTTP/2 requests from Node's `http2`
  compatibility API (backlog #1168): a request there carries no `host`
  header — only the `:authority` pseudo-header — so the host falls back
  to `:authority` and the scheme to the `:scheme` pseudo-header (an h2c
  socket is never TLS, so without it the scheme would misread as
  `http`); an explicit `{ scheme }` option still wins over `:scheme`,
  and both host sources missing still fails fast with the original
  `cannot rebuild the request URL without a host header` error.
  Pseudo-headers are transport framing, not HTTP fields, so they are
  stripped from the normalized headers map (a covered component never
  resolves against `:method` / `:path` / `:authority` / `:scheme` as a
  header). The README Node http section documents the fallback. Eight
  new tests in `test/nodeHttpHttp2.test.ts`, including a real loopback
  h2c server whose signed `@method` / `@scheme` / `@authority` /
  `@path` request verifies end-to-end.
- The benchmark (`npm run bench`) now also measures
  `exportSignedSnapshotsByLabel` (backlog #1161) — the sealed
  multi-label snapshot path a multi-signature deployment runs to
  persist every label's replay cache at once: one measured op
  seals two fixed-clock caches (merchant and gateway, eight live
  nonces each at pinned `seenAt` values 80 to 10 seconds before
  the export instant, all live under the 3,600-second TTL) into
  HMAC-signed envelopes under one fixed secret, JSON round-trips
  the envelopes, restores both labels, and re-pins the whole pass
  (envelope version 1, 64-hex MAC, snapshot entries exactly the
  hand-pinned lists, eight entries per restored cache, every
  restored nonce still a replay, eight hits and zero misses per
  label). Outside timing the bench pins the fail-closed half
  (a tampered entry nonce or `seenAt` in one label rejects the
  whole batch with the pinned MAC-mismatch message, a wrong
  secret rejects the same way, input envelopes untouched),
  the partitioned namespaces after a good restore, and the
  empty-map round-trip. The README Benchmarks table was
  refreshed from the same run and gains the new row (~13,287
  ops/sec, Node v24.22.1 / AMD EPYC 9D25 shared host).
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.clear` + `keyIds` (backlog #1158) — the
  key-retirement path a gateway runs when a key is distrusted or
  rotated out: one measured op lists the three cached kids, clears
  the store, and lists again, over a store holding a fixed
  three-key set (ed25519, P-256 and RSA) fetched from a real
  loopback `http` server. The bench primes one store per op from a
  pool of WARMUP + ITERATIONS stores, since `clear()` is
  destructive and a reused store would time an empty path. Every
  measured pass self-checks the 3-to-0 flip (pre-clear list exactly
  the three pinned kids in document order at size 3, post-clear
  list empty at size 0). Outside timing the bench pins the served
  document's kid set, the pre-clear kid list / size / counters, the
  post-clear emptiness (`size` 0, `keyIds()` empty,
  `lastRefreshedAt` null, `isStale()` true, `resolve` undefined
  for every kid, all four counters zero), and that a `refresh()`
  afterwards re-fetches the same kids from the same endpoint. The
  README Benchmarks table was refreshed from the same run and gains
  the new row (~651,814 ops/sec, Node v24.22.1 / AMD EPYC 9D25
  shared host).
- The benchmark (`npm run bench`) now also measures
  `createVerifiedFetchHandler` (backlog #1150) — the in-process
  fetch receive path an edge / WinterCG webhook receiver runs:
  a fresh `Request` per op from one pre-signed settlement
  POST, body buffering under the default cap, `fromFetchRequest`
  adaptation, ed25519 verification, the 200 branch into the
  business handler, and the `signResponses` response signing the
  demo #1144 shows. No TCP and no loopback: the row prices the
  handler itself, unlike the loopback `createVerifiedHandler`
  rows. Every measured pass self-checks the 200 status, the exact
  settlement body, and the response signature headers present;
  a probe round trip verifies the response signature in-process
  (`verifyResponse`: label `sig1`, the pinned server keyid /
  `ed25519` / nonce / `created`, covered `@status
  content-digest`), a tampered-signature request is answered 401
  with the pinned `SIGNATURE_MISMATCH` code and never reaches
  the business handler, and the handler-call count after the
  timed loop equals 1 + WARMUP + ITERATIONS. The README
  Benchmarks table was refreshed from the same run and gains
  the new row (~3,432 ops/sec, Node v24.22.1 / AMD EPYC 9D25
  shared host).
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.release` (backlog #1149) — the single-nonce
  release path a gateway runs when a verified request's
  downstream write failed and the client retries the same
  request verbatim, which the existing `check` row never
  timed (it measures only the record-and-lookup direction).
  The fixture is a fixed batch of eight nonces under a
  fixed injected clock and a 3,600-second TTL. Every
  measured pass runs the check → release → has combination
  and self-checks the flip — the recording check reports
  first-seen, `release()` reports `true`, and the trailing
  `has()` reports `false` — and the bench pins the end
  state (`size` 0, zero hits, one miss per measured op
  including warmup, zero evictions). The unseen-nonce
  release returning `false`, the sibling untouched with
  `size` down by exactly one, the released nonce
  re-recording as first-seen, and the TTL-boundary expiry
  refusal are asserted outside timing. The README
  Benchmarks table was refreshed from the same run and
  gains the new row.
- `verifiedFetch` binary response bodies (backlog #1141):
  `VerifiedFetchOptions.responseBody?: "text" | "bytes"` (default
  `"text"`, backward compatible). In `"bytes"` mode the verified
  response body is returned as the raw `Buffer`, byte-for-byte with
  no UTF-8 decode — a signed binary receipt (a PDF statement, a
  protobuf settlement credential) no longer comes back mangled by
  lossy decoding. The content-digest verification runs over the
  exact raw bytes in both modes, so the option only changes what
  the caller receives, never what is verified; `maxBodyBytes` is
  enforced on the raw byte count in both modes. The returned body
  type is pinned to the mode by overloads (`"bytes"` returns
  `Buffer`, anything else `string`), and an illegal `responseBody`
  value throws a configuration error before any network happens.
  `test/verifiedFetchBinaryBody.test.ts` gains 9 tests (full
  0x00–0xFF round-trip, tampered body rejected with
  `BODY_DIGEST_MISMATCH`, default and explicit text mode unchanged,
  Buffer request body plus binary response, byte cap in bytes mode,
  empty binary body, illegal mode fail-fast with zero fetch calls,
  multi-label mode returning the raw `Buffer`); test count moves
  2195 → 2204.
- CLI demo gains a `ReplayCache.release` segment (backlog #1143):
  the demo now shows the single-nonce release #1138 added — a fresh
  cache records one pinned nonce, `has()` reports it tracked,
  `release()` forgets exactly that nonce, `has()` reports it gone,
  and the same nonce checks in as first-seen again, with `stats()`
  showing the size drop by one and the counters untouched; releasing
  a never-seen nonce returns `false` with the stats unchanged, and
  an illegal nonce (empty string, or a non-string) is rejected with
  a configuration error. Every outcome is asserted outside the
  printed lines against hand-pinned `DEMO_REPLAY_RELEASE_*`
  expectations, `DemoResult` gains the release fields, and the
  README demo narrative describes the segment. `test/demo.test.ts`
  gains 2 tests (segment outcomes + cross-check against a directly
  driven cache and through `verifyRequest`, printed-lines slice +
  determinism); test count moves 2204 → 2206.
- CLI demo gains a `createVerifiedFetchHandler` segment (backlog
  #1144): the demo now shows the fetch twin of the
  `createVerifiedHandler` segment #1047 added — no server and no
  network, the handler is called in-process with standard fetch
  `Request` objects (the same build-a-`Request`-from-a-signed-request
  shape the `verifiedFetch` tests use). A signed request reaches
  the business handler (200) and the response comes back signed
  under `signResponses` (verified in-process with `verifyResponse`
  against the segment key); a request with one base64 character of
  its signature flipped is answered 401 with
  `SIGNATURE_MISMATCH` before the business handler runs; and an
  unsigned request whose 108-byte body exceeds the segment's
  64-byte `maxBodyBytes` is answered 413 with `BODY_TOO_LARGE`
  before any verification runs. Every outcome is asserted outside
  the printed lines against hand-pinned
  `DEMO_VERIFIED_FETCH_HANDLER_*` expectations (body sizes 29 and
  108 bytes measured, not guessed), `DemoResult` gains the segment
  fields, and the README demo narrative describes the segment.
  `test/demo.test.ts` gains 2 tests (segment outcomes + cross-check
  against a directly driven handler, printed-lines slice +
  determinism); test count moves 2206 → 2208.
- `ReplayCache.release(nonce, now?)` (backlog #1138): a single-nonce
  release for the replay cache — the missing half of the "verified
  but never executed" retry story. When a verified request's
  downstream processing fails (e.g. the business write to the
  database fails after the signature verified) and the caller wants
  the client to retry the *same* request verbatim, `release()` forgets
  exactly that nonce: it returns `true` when the nonce was seen within
  the TTL and is now forgotten, `false` when it was unseen or already
  expired (in which case nothing changes — the expired entry is left
  for the next recording `check()` to reclaim, exactly as a `has()`
  probe leaves it). After a release `has()` reports `false` and a
  later `check()` records the nonce as first-seen; `stats().size`
  drops by one while hits/misses/evictions are untouched (a release
  is neither a hit, a miss, nor an eviction); sibling nonces keep
  their LRU recency; and a later `exportSnapshot()` no longer
  contains the released nonce. The TTL boundary matches `check()` (a
  nonce seen exactly `ttlSec` ago counts as expired and is not
  released), an explicit `now` (unix seconds) is accepted like
  `check()`/`has()`, and an empty or non-string nonce throws a
  configuration error, the same caliber as `has()`. The JSDoc states
  the safety boundary explicitly: release reopens the replay window
  for exactly that nonce, so only release a nonce whose request was
  *never executed* — releasing one after its request ran lets the
  same signed request run twice — and the library never releases
  anything on its own. `test/replayCacheRelease.test.ts` gains 11
  tests (release true + has false, unseen release false + no state
  change, post-release check first-seen, expired release false at
  the TTL boundary via injected and explicit clocks, counters
  untouched except size, no sibling LRU refresh, snapshot excludes
  the released nonce, invalid-nonce throws, release after clear
  false, re-record after release leaves siblings intact), and the
  test count moves 2184 → 2195.
- `createVerifiedFetchHandler(verifyOpts, handler, opts?)` (backlog
  #1136): the fetch-API twin of `createVerifiedHandler` — the same
  buffer→adapt→verify→401 loop for WinterCG / edge runtimes, returning
  `(req: Request) => Promise<Response>`. It streams the request body
  through the reader up to `maxBodyBytes` (default
  `DEFAULT_MAX_BODY_BYTES`, 1 MiB; past the cap it cancels the reader
  and answers 413 before any verification runs, so the key resolver is
  never called), adapts it with `fromFetchRequest`, and verifies it
  with `verifyRequest` (or `verifyAllLabels` when opt-in, every label
  must pass, an unsigned request is a 401 `MISSING_SIGNATURE_INPUT`).
  A verification failure is answered 401 with exactly `{ error, code }`
  and the business handler is never called; a request that cannot be
  adapted is answered 400 `MALFORMED_REQUEST`. Opt-in `signResponse` /
  `signResponses` sign the handler's `Response` bound to the request it
  just verified (same options and creation-time dry-run validation as
  the Node handler, with `createVerifiedFetchHandler:`-prefixed error
  messages); a signing failure, or a business handler that throws, is
  answered 500 `INTERNAL_ERROR` with nothing unsigned returned. Honest
  limits (README + SECURITY.md): TLS is still the caller's job, the
  body is held in memory up to the cap, a fetch `Request` carries no
  trailers so a covered `;tr` component cannot verify through this
  handler, and the request body stream is consumed by verification.
  `test/nodeHttpVerifiedFetchHandler.test.ts` gains 18 tests (signed
  POST pass with `VerifyResult`, unsigned/tampered/wrong-key/expired
  401s, 401 body shape, over-cap 413 with zero resolver calls,
  exactly-at-cap pass, creation-time `maxBodyBytes`/`verifyOpts`/
  mutual-exclusion/`requiredLabels` validation, single- and dual-label
  response signing verified via `verifyResponse` /
  `verifyAllResponseLabels`, multi-label verification with an aggregate
  result, stripped co-signature 401, handler-throw 500, malformed 400,
  consumed-body pin), and the test count moves 2166 → 2184.
- CLI demo fetch-request segment (backlog #1131): the demo now covers
  the fetch-API inbound direction — the same signed payment request
  (`DEMO_BODY`, `@method`/`@authority`/`@path`/`content-digest`/
  `content-type` covered) is sent with the global `fetch()` to a
  real loopback server, which rebuilds a standard fetch `Request`
  from the wire message, adapts it with `fromFetchRequest(req, body)`
  and verifies it with `verifyRequest` (label/keyid/alg/nonce
  pinned). A one-byte body tamper (amount `100` -> `101`) through
  the same adapted path is rejected with `BODY_DIGEST_MISMATCH`, and
  the same message rebuilt under a different authority is rejected
  with `SIGNATURE_MISMATCH` (the covered `@authority` binds the
  exact URL). `DemoResult` gains `fetchRequestRequest`,
  `fetchRequestVerification` and `fetchRequestTamperedVerification`;
  `test/demo.test.ts` gains 4 tests (segment assertions, printed
  lines, byte-identical output across runs, authority binding with
  a re-sign round-trip), and the test count moves 2162 → 2166.
- `ReplayCache.has(nonce, now?)` (backlog #1128): a read-only probe
  for the replay cache — reports whether the nonce was already seen
  within the TTL without recording anything. An unseen nonce stays
  unseen (a later `check()` still sees it as first-seen), a seen
  nonce's LRU recency is not refreshed, expired entries report as
  unseen without triggering reclamation, and the `stats()` counters
  are untouched. The TTL boundary matches `check()` (a nonce seen
  exactly `ttlSec` ago counts as expired). An empty or non-string
  nonce throws a configuration error, the same caliber as `check()`.
  `test/replayCacheHas.test.ts` gains 10 tests (seen/unseen,
  probe-does-not-record, TTL boundary via injected and explicit
  clocks, stats untouched, invalid-nonce throws, clear resets,
  no LRU refresh, expired probe triggers no reclamation, size
  unchanged), and the test count moves 2152 → 2162.
- `fromFetchRequest(req, body)` (backlog #1125): the inbound fetch-API
  twin of `fromNodeRequest` — normalizes a fetch-style server's
  `Request` (undici / WinterCG / edge runtime) into a `RequestLike`
  (`FetchRequestLike`: method/url/headers, headers as a `Headers`
  instance or an entries iterable), so `verifyRequest` plugs straight
  into verifying signed requests where there is no
  `IncomingMessage`. The absolute `Request.url` passes through
  verbatim (port included, so a covered `@authority` binds exactly
  what the signer signed); an origin-form path is rebuilt as
  `http://<host><path>` from the `host` header, the `fromNodeRequest`
  convention. Fail-fast on a missing method/url, on an absolute URL
  with no host (checked against the raw string, because WHATWG URL
  parsing would silently promote the first path segment of
  `https:///v1/charge` to host `v1`), on an unparseable absolute URL,
  and on an origin-form path with no `host` header. Headers normalize
  with the same conventions as `fromNodeRequest` (lowercased names,
  multi-value fields joined with `", "`); the body is read by the
  caller and passed in as `string | Buffer | Uint8Array` (a
  `Uint8Array` is copied into a `Buffer`, `req.body` is never
  consumed), and the result never gains a `trailers` field.
  `test/nodeHttpFetchRequest.test.ts` gains 13 tests (real `Request`
  sign → adapt → verify round-trip, minimal-double round-trip,
  multi-value normalization parity with a covered header, host:port
  preservation, missing method/url/host and unparseable-URL throws,
  origin-form rebuild + verify, string/Buffer passthrough and
  `Uint8Array` copy, `Headers`-instance vs entries-array parity,
  `req.body` never consumed), and the test count moves 2139 → 2152.
- Benchmark gains a multi-label `verifiedFetch` end-to-end row
  (backlog #1122): the same loopback settlement response, now
  dual-signed (merchant ed25519 via `signResponse`, gateway
  hmac-sha256 via `addResponseSignature`), is verified in a single
  `verifiedFetch` call with `verify.verifyAllLabels`
  (`requiredLabels: ["merchant", "gateway"]`, per-label keys) — one
  full sign → fetch → dual-verify round trip per measured op, with
  both labels' identities (label / keyid / alg / nonce /
  `@status content-digest`) self-checked on every pass, and a
  tampered-body delivery pinned outside timing to fail with
  `BODY_DIGEST_MISMATCH`. In the 2026-11-14 run it measured ~648.9
  ops/sec (1541.12 µs/op) against ~766.9 ops/sec (1303.87 µs/op)
  for the single-label row. The Benchmarks table is refreshed with
  the same run (123 rows, Node v24.22.1 on linux/x64, AMD EPYC
  9D25); the test count is unchanged at 2139 (bench-only change).
- `CreateVerifiedHandlerOptions.signResponses` (backlog #1121):
  multi-label response signing — the signing twin of the
  `verifyAllLabels` verify mode. One entry per label, in wire
  order: the first is signed with `signResponse`, each later entry
  appended with `addResponseSignature`, every entry bound to the
  just-verified request (covered `;req` components resolve against
  it). Mutually exclusive with `signResponse` (both set throws at
  creation); an empty array throws, and a repeated label (an
  omitted label counts as `"sig1"`) throws at creation too. Each
  entry is validated at creation by the same dry-run sign as
  `signResponse`, and a failure in any label at request time is
  answered 500 `INTERNAL_ERROR` with nothing on the wire —
  including labels that signed fine. `test/
  nodeHttpVerifiedHandlerSignResponses.test.ts` gains 11 tests
  (loopback dual-label re-sign verified via
  `verifyAllResponseLabels`, per-label `;req` independence,
  single-label regression, 401 never re-signed, second-label
  failure → 500 with no bytes, mutual-exclusion / empty-array /
  duplicate-label / invalid-entry creation throws, tampered body
  fails both labels, wrong key fails only its label), and the test
  count moves 2128 → 2139.
- Demo gains a multi-label `verifiedFetch` segment (backlog #1119):
  the same loopback settlement response, now dual-signed (merchant
  ed25519 via `signResponse`, gateway hmac-sha256 via
  `addResponseSignature`), is verified in a single `verifiedFetch`
  call with `verify.verifyAllLabels` (`requiredLabels: ["merchant",
  "gateway"]`, per-label keys) — the client twin of the
  `addResponseSignature` segment, so both co-signatures are checked
  in the one call that signs the request and fetches the response.
  `DemoResult` gains `verifiedFetchMultiLabelStatus` /
  `verifiedFetchMultiLabelBody` /
  `verifiedFetchMultiLabelVerification` (the aggregate: `ok`, empty
  `label`, per-label results in `perLabelResults`) /
  `verifiedFetchMultiLabelVerifications` (wire order: merchant,
  gateway). `test/demo.test.ts` gains 3 tests (per-label field
  assertions, printed lines and placement between the single-label
  verified-fetch and allowed-algs segments, byte-identical output
  across runs), and the test count moves 2125 → 2128.
- `SignOptions.expiresInSec` (backlog #1117): relative expiry — the wire
  `expires` is exactly `created + expiresInSec` (explicit `created`, or
  the defaulted now), so "valid for five minutes" is `expiresInSec: 300`
  instead of a hand-computed `now + 300`. Must be a positive integer and
  is mutually exclusive with `expires` (both set is a configuration
  error). The wire value stays the absolute `expires` parameter, so
  verifiers need no change; `signResponse`, `addSignature`, and
  `addResponseSignature` inherit it through delegation.
- `verifiedFetch` supports `AbortSignal` (backlog #1112):
  `VerifiedFetchInit` gains `signal?: AbortSignal`, forwarded to the
  fetch implementation — the default global `fetch` and any injected
  `fetchImpl` receive it (`VerifiedFetchFn`'s init gains the same
  field). A signal already aborted throws `verifiedFetch: request
  aborted` before any network happens (the `verifiedFetch` wording
  of the `webhook delivery aborted` shape `deliverSettlementWebhook`
  uses, #112); an abort while the fetch is in flight passes the
  fetch's own abort error through untouched, never wrapped as a
  verification failure; an abort while the response body streams
  cancels the reader and throws the signal's abort reason — a
  cancelled read resolving `done: true` cannot let a partial body
  through to verification. A non-`AbortSignal` value is a
  configuration error, thrown before any network happens.
  `test/verifiedFetchAbortSignal.test.ts` gains 10 tests (pre-abort
  fail-fast with zero fetch calls, in single- and multi-label mode;
  illegal signal values; non-aborted signal round-trip over an
  injected `fetchImpl`, which receives the exact signal object;
  in-flight abort of a hung `fetchImpl`; body-stream abort cancelling
  the reader; abort winning over a bad signature so verification
  never runs on a partial body; default-fetch pass-through against a
  hung loopback server, and a normal default-fetch round-trip with a
  live signal), and the test count moves 2102 → 2112.

- Benchmark gains a `verifiedFetch` end-to-end row (backlog #1107):
  one `verifiedFetch` call per op over a loopback server (a POST
  with a JSON settlement instruction, signed with a fixed client
  ed25519 key; the gateway re-signs the same settlement response
  with its own ed25519 key, `now` pinned to the signature's
  `created` + 60s) prices the whole client round trip — request
  signing + fetch + response verification. Every measured pass
  pins the 200 status, the exact settlement body, and the
  verification identity (label `sig1`, pinned gateway keyid /
  `ed25519` / nonce, covered `@status content-digest`); a delivery
  whose body was flipped after signing is pinned outside timing to
  throw `VerifyError` with `BODY_DIGEST_MISMATCH`. Real run
  (2026-11-13, Node v24.22.1, linux/x64, AMD EPYC 9D25):
  `verifiedFetch (signed POST, loopback)` ~470.5 ops/sec
  (2125.49 µs/op); the Benchmarks table is refreshed from the same
  run (121 → 122 rows). Numbers are machine-local, not guarantees.

- CLI demo gains a `verifiedFetch` segment (backlog #1106): the
  loopback settlement response is now also exercised through the
  client one-call helper — one `verifiedFetch` call per
  round-trip (a GET with no body, a POST with a JSON settlement
  instruction) signs the request, fetches it, and verifies the
  signed response, so no step can be skipped; each response
  verifies under the pinned gateway keyid with its own nonce
  (`demo-verified-fetch-get-nonce-1` / `demo-verified-fetch-post-nonce-1`),
  and the fixture also asserts each request arrived signed and
  the POST carried a `content-digest` header. `DemoResult`
  gains `verifiedFetchGetStatus` / `verifiedFetchGetBody` /
  `verifiedFetchGetVerification` and the POST counterparts.
  `test/demo.test.ts` gains 3 tests (GET + POST round-trip
  fields with label/keyid/alg/nonce pinned, the printed lines
  between the fetch-adapter and allowed-algs segments, and
  byte-identical output across runs), and the test count moves
  2099 → 2102.

- `verifiedFetch` verifies multi-label responses (backlog #1105):
  `verify.verifyAllLabels` (exactly the `VerifyAllResponseOptions`
  the response API takes, minus `request`, which the helper still
  anchors to the request it just signed) verifies every signature
  on the response with `verifyAllResponseLabels` in the same one
  call — the merchant-ed25519 / gateway-hmac settlement flow,
  mirroring the `createVerifiedHandler` multi-label mode (#1090).
  Fail-closed: every label must pass; the first failing label's
  code / reason / label is thrown as the `VerifyError`, with the
  full per-label array attached to the error as `verifyResults`
  (`VerifyError` gains the optional `verifyResults` field) and to
  a successful result as `verifyResults`, with `verifyResult` as
  the aggregate (`ok: true`, empty `label`, `perLabelResults`,
  exactly as `createVerifiedHandler` reports it). An unsigned
  response throws `MISSING_SIGNATURE_INPUT`, never passes
  vacuously; `requiredLabels` names the labels that must be
  present (a stripped co-signature is a synthetic
  `MISSING_REQUIRED_LABEL` failure). Illegal label policies —
  empty / duplicate / non-string `requiredLabels`, no key source,
  or a verification option left on the outer `verify` object —
  throw before any network happens, via a pre-flight dry run over
  a synthetic signed response mirroring the handler's. Without
  `verifyAllLabels`, the single-label behavior is unchanged.
  `test/verifiedFetchMultiLabel.test.ts` gains 11 tests
  (loopback dual-sign round-trip, one bad label failing the whole
  call with the other label's result visible on the error, missing
  required label, unsigned response, single-label default
  unchanged, four fail-fast policy cases, `;req` binding success
  and mismatch), and the test count moves 2088 → 2099.

- Optional `expiresAt` expiry on both signed snapshot envelopes
  (backlog #1104), mirroring the dataquest (#1076) and escrow
  (#1103) envelopes: `ReplayCacheSignedSnapshotEnvelope` and
  `JwksSignedSnapshotEnvelope` gain an optional `expiresAt`
  (canonical ISO-8601 UTC string), set via
  `exportSignedSnapshot(secret, { expiresAt })` or
  `{ maxAgeMs, now }` (`ReplayCacheSignedSnapshotExportOptions` /
  `JwksSignedSnapshotExportOptions`; `expiresAt` and `maxAgeMs` are
  mutually exclusive, `now` without `maxAgeMs` is a configuration
  error). The timestamp sits inside the MAC coverage (MAC over
  `{ expiresAt, snapshot }` when present, over the snapshot alone
  otherwise, so pre-expiry envelopes still verify byte-identically),
  and restore rejects an expired envelope after the MAC verifies and
  before any snapshot parsing (`now > expiresAt` is expired,
  restoring at exactly `expiresAt` still succeeds; a non-canonical
  `expiresAt` fails the envelope before the MAC is computed). The
  restore clock is injectable — `ReplayCache` reuses the
  `ReplayCacheOptions.now` seconds clock, `JwksKeyStore` takes an
  optional `JwksSignedSnapshotRestoreOptions.now` (default the
  store's own clock) — and a failed restore leaves the current
  snapshot untouched; the per-label by-label restore stays atomic,
  so one expired label rejects the whole batch.
  `test/signedSnapshotExpiry.test.ts` gains 14 tests (both families:
  legacy no-expiry restore, future-expiry round-trip, inclusive
  boundary, tampered `expiresAt` → MAC mismatch, illegal `expiresAt`
  and option misuse at export, `maxAgeMs` resolution, expiry-before-
  parsing with a MAC-valid malformed snapshot, by-label atomic
  rejection with the valid label unaffected, JWKS store untouched on
  expired restore), and the test count moves 2074 → 2088.
- RFC 3230 `Digest` legacy gateway interop (backlog #1100):
  `digest(body, alg)` emits a `Digest` header value in the same
  `alg=:base64:` rendering as `contentDigest` (sha-256/sha-512 only;
  the `alg` is required so the caller names the algorithm the peer
  expects, and illegal body input or an unsupported algorithm throws).
  On the verify side, a signature covering `digest` now binds the body
  through the Digest value exactly like `content-digest`: a missing
  header, an md5/unknown algorithm, or a value that does not match the
  body fails with `BODY_DIGEST_MISMATCH` (sha-512 preferred when both
  entries are present). An uncovered Digest header is not checked — the
  binding only applies when `digest` is covered — and the classic bare
  `SHA-256=base64` form is not accepted (fail-closed). Content-Digest
  stays the preferred binding; Digest exists only for legacy gateways
  that still send it. `test/digest.test.ts` gains 19 tests (sha-256 /
  sha-512 golden values verbatim, sign→verify round-trips for both
  algorithms, tampered body, signer-emitted wrong digest, post-sign
  header swap → `SIGNATURE_MISMATCH`, dual Digest + Content-Digest
  coverage, covered-but-missing header, md5 and unknown-algorithm
  fail-closed, uncovered-Digest scope, no-body behavior, multi-entry
  sha-512 preference, illegal input). README gains the Digest
  explanation in "What it implements", Limitations, and
  Interoperability, and the test count moves 2055 → 2074.
- `generateHmacSecret(alg?, bytes?)` HMAC secret generator (backlog
  #1099): mints a fresh CSPRNG-drawn `Buffer` at exactly the
  per-algorithm floor by default — 32 bytes for `hmac-sha256`, 64 for
  `hmac-sha512` (RFC 2104 §3) — so webhook/gateway callers no longer
  hand-roll `crypto.randomBytes` and count bytes themselves. An explicit
  `bytes` only ever goes longer: a below-floor length throws with exactly
  the same wording `assertHmacSecretLength` uses on the sign/verify
  side, and non-integer / negative / NaN lengths fail fast. Wrap the
  result with `secretKey()` before passing it to `signRequest` /
  `verifyRequest`.
- `createVerifiedHandler` supports multi-label verification (backlog
  #1090): opt-in `CreateVerifiedHandlerOptions.verifyAllLabels`
  (exactly `VerifyAllOptions` minus `label` — per-label `keys` /
  `keyResolvers` / `candidateKeysByLabel` / `expectedKeyIds` /
  `expectedTags` / `requiredLabels` and the rest work as
  `verifyAllLabels` documents them). When set, the wrapper verifies
  with `verifyAllLabels` instead of `verifyRequest`: every label must
  pass before the business handler runs — with `requiredLabels` set, a
  missing required label is a 401 `MISSING_REQUIRED_LABEL`; without
  it, every label present on the wire must pass, and a request
  carrying no signature at all is a 401 `MISSING_SIGNATURE_INPUT`
  (an empty result set never passes vacuously). A failure is answered
  401 with exactly `{ error: "signature verification failed", code }`,
  where `code` is the first failing label's code, the same body shape
  as the single-label path. The business handler receives an aggregate
  `VerifyResult` (`ok: true`, empty `label`) whose new
  `perLabelResults` field carries each label's own `VerifyResult` in
  wire order, for logging and audit per signer. The first argument
  `verifyOpts` is still required and still validated at creation, but
  is not consulted per request while this option is set. The
  multi-label options are validated at handler-creation time by a dry
  run over a synthetic signed request — an unsigned dry run cannot
  reach the per-label map checks, because `verifyAllLabels` returns
  early for a request with no `signature-input` header — so a bad
  per-label key, resolver, candidate list, or pin throws
  `createVerifiedHandler: invalid verifyAllLabels: …` when the handler
  is built, never on the first live request; an empty
  `requiredLabels` array is rejected the same way (omit the field to
  require every label on the wire). `test/
  nodeHttpVerifiedHandlerMultiLabel.test.ts` gains 12 tests (loopback
  dual-signed round-trip with per-label results, tampered gateway
  signature → 401, tampered body → 401 `BODY_DIGEST_MISMATCH`,
  missing required label → 401, unsigned request → 401 with and
  without `requiredLabels`, `requiredLabels` subset pass, per-label
  keyid pin mismatch → 401, wrong-key merchant signature → 401,
  four creation-time configuration errors, single-label regression,
  and 401 answers never signed while 200 answers are). README gains
  a multi-label handler section; SECURITY.md gains the honest limits
  (multi-signature is not key distribution, two labels are not proof
  of two signers, a label left out of `requiredLabels` is never
  checked).

- Client one-call `verifiedFetch(input, init?, opts)` (backlog #1087):
  signs the request (`opts.sign`, the `signRequest` options), fetches
  it (`opts.fetchImpl`, defaulting to the global `fetch`), reads the
  response body under `opts.maxBodyBytes` (default
  `DEFAULT_MAX_BODY_BYTES`, 1 MiB, the same value as
  `createVerifiedHandler` — the stream reader is cancelled as soon as
  the cap is passed, so an unbounded body cannot be buffered; the
  `arrayBuffer()` fallback for doubles without a stream reads fully
  and then enforces the cap), adapts it with `fromFetchResponse`, and
  verifies it with `verifyResponse` — returning `{ response, body,
  verifyResult }` and throwing `VerifyError` on a failed verification
  (the response API itself still returns wire failures; this helper
  is the caller's explicit opt-in to the throwing entry point). The
  response is anchored to the request just signed, so a peer covering
  a `;req` component binds its signature to that request; a
  caller-supplied `verify.request` is a configuration error. Invalid
  sign/verify configuration (including a verifier with no key source,
  and key+resolver together) throws before any network happens, via
  the `signRequest` call and a pre-flight dry-run verification over a
  synthetic unsigned response. A non-2xx response is still verified
  and returned, never rejected on status alone; fetch-layer errors
  pass through untouched. The body is returned as a UTF-8 string —
  binary bodies are out of scope. `test/verifiedFetch.test.ts` gains
  14 tests (loopback POST/GET round-trips with label/keyid/alg/
  covered-components pinned, `;req` binding, tampered body →
  `BODY_DIGEST_MISMATCH`, wrong key → `SIGNATURE_MISMATCH`, unsigned
  response → `MISSING_SIGNATURE_INPUT`, non-2xx returned verified,
  oversized body rejected over both the stream and the `arrayBuffer()`
  fallback, zero-network injected-`fetchImpl` round-trip, and four
  fail-fast configuration errors with zero fetch calls); a mutation
  run with the `VerifyError` throw disabled turns the three
  failure-mode tests red, and one with the cap checks disabled turns
  the `arrayBuffer()` cap test red and hangs the stream cap test on
  its never-ending stream (the cap is the only bound). README gains
  a client section and a "What it implements" entry; SECURITY.md
  gains the honest limits (no TLS replacement, binary bodies out of
  scope, cap rejects rather than truncates).

- `createVerifiedHandler` validates `verifyOpts` at creation time
  (backlog #1077): after the `maxBodyBytes` check, a dry-run
  `verifyRequest` over a synthetic unsigned request exercises every
  configuration check the verifier runs (key selection, candidate
  lists, freshness windows, header limits, required components,
  allowed algorithms, Structured Field types, clock options), and a
  verifier with no key source at all is rejected explicitly (the
  unsigned dry run cannot reach the check `verifyRequest` only throws
  after a signature header parses). A misconfiguration throws
  `createVerifiedHandler: invalid verifyOpts: …` when the handler is
  built, never as a 500 `INTERNAL_ERROR` on the first live request;
  the per-request 500 remains only as defense-in-depth (e.g. if the
  caller mutates the `verifyOpts` object after creation). The dry run
  has no side effects: it never calls the key resolver and never
  fetches. `test/verifiedHandlerVerifyOptions.test.ts` gains 20 tests
  (17 creation-time rejections, a counting-resolver zero-calls-at-
  creation test, a JWKS no-fetch test, and a 200/401/401 loopback
  behavior test); a mutation run with the validation disabled turns
  17 of the 20 red. Per-label maps are out of scope by construction:
  they belong to `VerifyAllOptions`, which this handler never calls.

- CLI demo signing-side guard rejection segment (backlog #1070):
  the demo closes with the sign-side twin of its verify-side
  rejections — the same fixed payment request is signed three
  ways that must all be refused (`alg: "none"`, a 257-character
  tag, 65 covered components), each refusal printed with the
  guard's exact message and asserted outside the printed lines
  against hand-pinned `DEMO_SIGN_GUARD_ERRORS`, the input
  request's headers shown byte-identical after the refusals, and
  the same request signed the legal way with ed25519 printed
  verifying. `DemoResult` gains `signGuardRejections`,
  `signGuardRequestHeadersUnchanged`, `signGuardControlSigned`
  and `signGuardControlVerification`. `test/demo.test.ts` gains
  two tests (segment values + cross-check against `signRequest`
  called directly, byte-exact closing lines + determinism), and
  the verified-handler test's "closes the demo" assertion now
  points at the guard segment. Two guard short-circuit
  mutations (unknown-alg check, tag cap) were verified to turn
  the new demo tests red.

- CLI demo `createVerifiedHandler` end-to-end segment (backlog
  #1047): the demo closes with a real loopback `http` server running
  `createVerifiedHandler` — a `signRequest`-signed POST reaches the
  business handler (200), a POST with one base64 character of its
  signature flipped is answered 401 with `SIGNATURE_MISMATCH`, and
  an unsigned POST is answered 401 with `MISSING_SIGNATURE_INPUT`,
  both 401s before the business handler ever runs. Only the
  statuses and failure codes are printed, never signature bytes or
  the port, so the segment is byte-identical between runs.
  `DemoResult` gains the five verdict fields and the README demo
  prose gains a paragraph for the segment.

- End-to-end `createVerifiedHandler` benchmark rows (backlog #1027):
  `benchmarkCreateVerifiedHandler` and
  `benchmarkCreateVerifiedHandlerUnsigned` over a loopback `http`
  server (one ed25519 key, `maxBodyBytes` default, `now` pinned to
  the signature's `created` + 60s, request signed once outside
  timing). Each measured op is one full HTTP round trip: the signed
  row sends a pre-signed POST and pins the 200 status plus exactly
  one business-handler call per delivery (1 + 200 warmup + 3000
  timed), the unsigned row sends the same body with no signature
  headers and pins 401 with the handler never called. In this run
  the signed row measured ~1,441 ops/sec (693.79 µs/op) and the
  unsigned row ~3,350 ops/sec (298.53 µs/op) — the unsigned path is
  about 2.3× faster because it rejects before any cryptography,
  while the signed path pays a fresh TCP connection plus the full
  verify. README Benchmarks table refreshed from the same run
  (Node v24.22.1, shared host) and a prose paragraph added for the
  new rows.

- Private-key JWK exporters (backlog #1026): `exportPrivateKeyJwk`
  (ed25519), `exportPrivateKeyJwkP256` / `P384` / `P521`, and
  `exportPrivateKeyJwkRsa` — one exporter per key family, each returning
  exactly the shape `importPrivateKeyJwk` accepts (`{ kty, crv, x, y, d }`
  for EC, `{ kty, n, e, d, p, q, dp, dq, qi }` for RSA, no extra
  members), so generate → export → wire round-trip → import → sign
  closes without a PEM detour. Fail-closed in reverse: a public key, a
  symmetric secret, a wrong-curve key, or an RSA key below the 2048-bit
  floor is refused at export, and the original `KeyObject` keeps working
  after export. `test/exportPrivateKeyJwk.test.ts` gains 13 tests (five
  family round-trips with `x`/`d` byte-identical to node:crypto's own
  export, RSA serving both `rsa-pss-sha512` and `rsa-v1_5-sha256`,
  byte-identical re-export after import, deterministic double export,
  public-key / curve-mismatch / cross-family / `oct` refusals, 1024-bit
  RSA refused at export, original key still signs). A dropped-floor
  mutation was verified to turn exactly the weak-RSA test red. Private
  JWKs are secret material by design: trusted migration / backup only,
  never logged, never published (`buildJwksDocument` still refuses
  private keys).

- Opt-in response signing for the verified handler (backlog #1025):
  `CreateVerifiedHandlerOptions.signResponse` (a
  `VerifiedHandlerSignResponseOptions` — exactly the `signResponse`
  options, minus `request`) makes `createVerifiedHandler` sign the
  business handler's response before sending it, with the request it
  just verified attached as `request`, so a covered `;req` component
  (e.g. `@method;req`) binds the signature to that request. The
  wrapper buffers the response in full (`writeHead` / `write` /
  `flushHeaders` held, not sent) and flushes the signed headers and
  body in one go on `end`; a signing failure at request time is
  answered 500 `INTERNAL_ERROR` with nothing unsigned on the wire,
  and the wrapper's own 400/401/413/500 rejections are never signed.
  The options are validated at handler-creation time by a dry-run
  sign (bad key shape, alg, or label throws when the handler is
  built), forgiving only a covered header the handler sets per
  response. `test/nodeHttpVerifiedHandlerSignResponse.test.ts` gains
  14 tests (loopback `http.createServer`): signed response verifies
  via `verifyResponse` with label/keyid/alg pinned, `;req` binding
  fails verification against a different method or path, no
  `signResponse` means no signature headers, 401/413 rejections
  carry no signature, creation-time throws for a public key, a
  non-KeyObject key, an unknown alg, a swapped RSA/ed25519 pair and
  illegal labels, custom label and `coveredComponents` take effect,
  hmac-sha256 round-trip, `write()`-streamed handler still signed, a
  covered header the handler never sets answers 500, tampered body
  and wrong key fail verification. A dropped-`request` mutation was
  verified to turn exactly the `;req` test red.

- CLI demo JWKS publishing segment (backlog #1023): `src/demo.ts`
  gains the publish half of the JWKS loop the demo previously only
  showed from the consumption side — a new `fetchJwksPublishedDocument`
  helper generates an ed25519 pair and a P-256 pair, assembles their
  public halves with `buildJwksDocument`, serves the document from a
  real loopback `http` server at `/.well-known/jwks.json`, and a plain
  `JwksKeyStore` fetches it once and resolves both kids; one request
  signed with each private key verifies through the store's resolver.
  The segment runs before the JWKS resolution segment, asserts the
  document shape (two keys, pinned kids in order, no private
  material), the fetch count, the store size and both verified
  identities, and prints only kids, key types and outcomes — never
  key material — so its lines are byte-identical between runs.
  `test/demo.test.ts` gains two tests (structure + printed lines,
  ordering and double-run determinism).

- Benchmark row for the single-call `verifyAllResponseLabels`
  dual-label response path (backlog #1022): `bench/bench.ts` gains
  `benchmarkVerifyAllResponseLabels`, reusing the
  `benchmarkAddResponseSignature` dual-signed fixture — the merchant
  signs the settlement response with `signResponse` (ed25519) and
  the gateway appends its hmac-sha256 label with
  `addResponseSignature`, both with `created` pinned — and every
  measured pass verifies both labels in one `verifyAllResponseLabels`
  call, pinning each label's alg / keyid / covered components in wire
  order; a flipped gateway-signature byte is pinned outside timing to
  fail exactly the gateway label with `SIGNATURE_MISMATCH` while the
  merchant label still verifies. The new row measured ~5,063 ops/sec
  (197.51 µs/op) in this run, slightly faster than the two-call
  `addResponseSignature + verifyResponse` row (~4,872 ops/sec), as
  expected for a single call that parses the `signature-input` header
  once instead of once per label. The README Benchmarks table was
  refreshed from the same run (Node v24.22.1, shared host).

- Node `http` signature-verifying handler `createVerifiedHandler`
  (backlog #1016): a standard `http.RequestListener` that closes the
  loop the adapters left open — it streams the request body into
  memory (default cap 1 MiB, `DEFAULT_MAX_BODY_BYTES`, configurable
  via `CreateVerifiedHandlerOptions.maxBodyBytes`), adapts it with
  `fromNodeRequest`, verifies it with the `VerifyOptions` given at
  creation, and only then calls `handler(req, res, result)` with the
  raw Node pair and the `VerifyResult` (`result.ok` is always true
  there). A verification failure is answered 401 with exactly
  `{ error: "signature verification failed", code }` — the
  `VerifyResult.code`, no `reason`, no stack, no key material — and
  the business handler is never called; a body past the cap is
  answered 413 `{ error: "request body too large", code:
  "BODY_TOO_LARGE" }` before any verification runs (the key resolver
  is never called) and the socket is closed once the 413 is flushed.
  A request that cannot be adapted gets 400 `MALFORMED_REQUEST`, a
  misconfigured `verifyOpts` gets 500 `INTERNAL_ERROR`, and a stream
  error mid-body gets 500 `BODY_READ_FAILED` — all without verifying.
  A non-positive or non-integer `maxBodyBytes` throws a configuration
  `Error` at creation time; a body exactly at the cap still verifies.
  New types `VerifiedRequestHandler` and
  `CreateVerifiedHandlerOptions` are exported. 10 new tests in
  `test/nodeHttpVerifiedHandler.test.ts` (loopback `http.createServer`
  end-to-end).
- JWKS publishing via `buildJwksDocument` (backlog #1015): the
  publishing half of `JwksKeyStore`'s consuming half — it assembles
  a `{ keys: [...] }` JWKS document from public keys plus their
  `kid`s (ed25519 / P-256 / P-384 / P-521 / RSA, reusing the
  `exportPublicKeyJwk*` helpers), so a signer serving
  `/.well-known/jwks.json` never hand-assembles the document and
  mistypes a `kty`/`crv` or forgets a `kid`. Fail-fast at build
  time: `kid` must be a non-empty string and unique across the
  document, a symmetric secret key is refused (a JWKS publishes
  public keys only), and so is a private key (pass the public
  half); unsupported key shapes throw a configuration error. The
  document never carries private material (no `"d"` member). New
  types `JwksDocument`, `JwksDocumentEntry` and `JwksDocumentKey`
  are exported. 14 new tests in `test/buildJwksDocument.test.ts`.
- `memoizeKeyResolver` cache observability (backlog #1014): the
  returned resolver is now a callable object (still directly usable
  as a `VerifyOptions.keyResolver`) carrying `.stats()` — a detached
  `{ size, hits, misses, evictions }` snapshot in the same shape as
  `ReplayCacheStats` — and `.clear()` (empties the cache and resets
  every counter). `evictions` counts both routes out of the cache:
  expired entries reclaimed on read or while making room, and
  least-recently-used entries evicted from a full cache, so a caller
  can tell whether the cache is absorbing lookups and whether a
  stream of one-off `keyid`s is driving evictions. New types
  `MemoizedKeyResolver` and `MemoizeKeyResolverStats` are exported.
  8 new tests in `test/memoizeKeyResolverStats.test.ts`.
- Opt-in `JwksKeyStore` auto-refresh (backlog #1008):
  `startAutoRefresh(intervalMs, { onError, setIntervalImpl })`
  calls `refreshIfStale()` on a timer, so a long-lived gateway
  verifier picks up key rotation without a hand-written polling
  loop. The timer is `unref()`d (it never holds the process open),
  a failed tick never throws — it goes to `onError` when one is
  given and is silently swallowed otherwise (a throwing `onError`
  is swallowed too) — and the call returns an idempotent `stop()`
  (`clear()` stops the timer as well). Starting a second
  auto-refresh while one runs is a fail-fast configuration error.
  Auto-refresh fetches count in `stats()` exactly like manual
  ones. 13 new tests in `test/jwksAutoRefresh.test.ts`.
- Private-key JWK import demo segment (backlog #1005): the CLI
  demo closes with an `importPrivateKeyJwk` segment — a fixed
  ed25519 private JWK (demo-only) is carried through a JSON wire
  round-trip, read back with `importPrivateKeyJwk`, and the
  imported key completes an ed25519 sign -> verify round-trip
  against the public half derived from it, the asymmetric half of
  JWK key distribution for KMS-exported signing keys. A copy with
  its `d` member stripped is shown rejected at import with the
  pinned missing-member error. Only the JWK's shape is printed,
  never the `d` or `x` bytes. 2 new tests in
  `test/demo.test.ts`.
- Multi-label response verification (backlog #1002):
  `verifyAllResponseLabels(res, opts)` verifies every label on a
  signed response and returns one `VerifyResult` per label in wire
  order — the response-side twin of `verifyAllLabels`, for the
  multi-party settlement flow `addResponseSignature` documents
  (merchant ed25519 signs, gateway hmac appends). `requiredLabels`
  missing from the wire are reported as synthetic
  `MISSING_REQUIRED_LABEL` failures; `@status` still binds the
  status code and `;req` components still resolve against the
  attached triggering request (`request` option); the per-label
  option maps (`keys`, `keyResolvers`, `expectedKeyIds`, …) behave
  exactly as in `verifyAllLabels`, since the implementation
  delegates to it through the `RequestLike` synthesis
  `verifyResponse` uses (now shared as `responseToRequestLike`).
  A request-derived component without `;req`, or a `;req`
  component with no request attached, throws a configuration
  error — checked for every label. 12 new tests in
  `test/verifyAllResponseLabels.test.ts`.
- Cached kid listing for key-rotation audit (backlog #1000):
  `JwksKeyStore.keyIds()` returns the kids of the current snapshot in
  snapshot order as a fresh array (empty before the first refresh and
  after `clear()`; a JWKS document listing the same kid twice lists
  it once, last entry wins) — so a caller can check whether a retired
  kid has left the cache, or a new kid has been fetched, without
  probing `resolve()` kid by kid. 8 new tests in
  `test/jwksKeyIds.test.ts`.
- Single-key JWKS fallback for keyid-less signatures (backlog #996):
  `JwksKeyStore.resolveOnlyKey()` returns the cached key only when
  the snapshot holds exactly one key, and `VerifyOptions.singleKeyFallback`
  (the store instance, opt-in) lets `verifyRequest` try that key for a
  signature carrying no `keyid` — multi-key and empty snapshots never
  fall back, and keyid-carrying signatures resolve exactly as before.
  Fail-fast pairing: `keyResolver` must be that store's `resolve`
  (a non-JWKS resolver, a static `key`, or `candidateKeys` alongside
  the opt-in throws a configuration error); `verifyAllLabels` applies
  the same rule per label. 16 new tests in
  `test/singleKeyFallback.test.ts`, including a mutation check
  (breaking `resolveOnlyKey` fails 6 of them).
- `importPrivateKeyJwk` private JWK import (backlog #989): one
  function dispatching on `kty` imports a private key from a JWK
  object — `OKP` / `Ed25519` (`d` + `x`), `EC` / `P-256` / `P-384` /
  `P-521` (`d` + `x` + `y`), `RSA` with the full CRT set
  (`n` / `e` / `d` / `p` / `q` / `dp` / `dq` / `qi`), and `oct`
  (`k`, same canonical-`k` check and per-`alg` secret floor as
  `importSymmetricKeyJwk`) — so a KMS-exported private JWK no
  longer has to be converted to PEM first. Fail-closed throughout:
  a public JWK (no `"d"`) is refused, `use` must be `"sig"` when
  present, `key_ops` must include `"sign"` when present, and an RSA
  key below the 2048-bit floor is refused at import. 20 new tests
  in `test/importPrivateKeyJwk.test.ts`, including a mutation check
  (flipping the `use` gate makes the key-use test fail).
- `;key` consults the `structuredFieldTypes` registry (backlog
  #985): `resolveComponent`'s `;key` branch now looks the field up
  in the same per-field registry `;sf` uses before parsing it as a
  Dictionary. A field registered as `"dictionary"` behaves exactly
  as before and an unregistered field keeps the Dictionary parse,
  but a field registered as `"list"` or `"item"` fails closed and
  names the registered type — fail-fast on the sign side and with
  `SIGNATURE_BASE_BUILD_FAILED` on the verify side (including
  `verifyRequestOrThrow` and per-label registries in
  `verifyAllLabels`) — instead of silently parsing the value as a
  Dictionary. The `;sf` and `;key` parameters now agree on what
  type a field is. 11 new tests in `test/keyRegistry.test.ts`,
  including a mutation check (disabling the registry gate makes 8
  of the 11 tests fail).
- `JwksKeyStore` follows `Cache-Control: max-age` (backlog #983):
  after a successful `refresh()` the snapshot's effective TTL is
  `min(ttlSec, max-age)` — a publisher declaring `max-age=60` retires
  its keys after 60 seconds instead of the configured 300, while a
  publisher declaring `max-age=3600` is still re-fetched every 300
  seconds (a publisher may shorten the TTL, never lengthen it).
  `store.effectiveTtlSec` exposes the TTL the current snapshot is
  actually fresh for, and `isStale()` / `refreshIfStale()` judge
  staleness against it. A missing or malformed `max-age` leaves
  `ttlSec` in force, a failed refresh never moves the effective TTL,
  a later refresh re-derives it from its own header, and restored
  snapshots (no cache headers in the snapshot format) always use
  `ttlSec`. `Expires` is not consulted — only `max-age`. 11 new tests
  in `test/jwksCacheControl.test.ts`, including a mutation check
  (parser forced to return `null` makes the max-age tests fail).
- CLI demo JWKS body-limit segment (backlog #980): the demo now covers
  the `JwksKeyStore` `maxBodyBytes` cap end to end — a store capped at
  128 bytes with a clock pinned to the demo's fixed instant refreshes a
  healthy one-key document (119 bytes), rejects an oversized two-key
  document (228 bytes, no `Content-Length`) with the pinned
  received-bytes error before parsing, and rejects a response whose
  `Content-Length` claims 999999 bytes before reading the body at all
  (the fake fetch counts `text()` calls to prove it). After both
  failures the snapshot still holds the one scripted key, `resolve()`
  still returns it, `lastRefreshedAt` still reads the healthy refresh
  instant, and a request signed with the scripted key still verifies
  through the store's resolver. New `DemoResult` fields
  (`jwksMaxBodyError` / `jwksMaxBodyContentLengthError` /
  `jwksMaxBodyFetchCalls` / `jwksMaxBodyTextCalls` / `jwksMaxBodySize` /
  `jwksMaxBodyResolved` / `jwksMaxBodyLastRefreshedAt` /
  `jwksMaxBodyVerification`) and 3 new tests in `test/demo.test.ts`,
  asserting the pinned constants, an independent reproduction of the
  same three refreshes outside `runDemo()`, and the byte-exact printed
  lines.
- CLI demo fetch-adapter segment (backlog #977): the demo now covers
  the fetch-side receive path — the same loopback settlement response
  the gateway segments serve, signed with `signResponse` and fetched
  with the global `fetch()`, read with `arrayBuffer()`, adapted with
  `fromFetchResponse` and verified with `verifyResponse`, so the
  webhook-receiver shape (a callback arriving as a fetch `Response`)
  is shown end to end. Tampering one body byte (the settlement amount
  `10000` -> `10001`) through the same adapted path is rejected with
  `BODY_DIGEST_MISMATCH`. New `DemoResult` fields
  (`fetchResponseRequest` / `fetchResponseVerification` /
  `fetchResponseTamperedVerification`) and 1 new test in
  `test/demo.test.ts`, asserting the adapted structure, the pinned
  keyid/alg/nonce, the `@status content-digest` coverage, and the
  byte-exact printed lines.
- Verify-side signature header length limits (backlog #976):
  `VerifyOptions` gains `maxSignatureInputLength` /
  `maxSignatureLength` (each default 65,536 bytes; must be a positive
  integer), enforced fail-closed before any parsing — an oversized
  `signature-input` header returns `SIGNATURE_INPUT_TOO_LARGE` and an
  oversized `signature` header `SIGNATURE_TOO_LARGE`, without the
  parser ever running over them. Length is measured in UTF-8 bytes on
  the joined header value the parser would see (multi-value fields
  after joining, non-ASCII in bytes not characters). `VerifyAllOptions`
  gains the per-label maps `maxSignatureInputLengthByLabel` /
  `maxSignatureLengthByLabel` (the global/default bound gates
  pre-parse before the header is split into labels, a tighter
  per-label bound then applies inside `verifyRequest`); `verifyResponse`
  gates before its own guard parse too. The defaults are calibrated on
  measured headers (2026-11-08): a single-label ed25519 signature over
  four components is 97 bytes, seven components 138 bytes, a two-label
  ed25519 header 197 bytes, and an RSA-PSS signature value 351 bytes —
  the 64 KiB default is more than 180x the largest. 17 new tests in
  `test/verifyHeaderLimits.test.ts`, covering request, response, and
  multi-label paths.
- `JwksKeyStore` response body limit (backlog #973): the new
  `maxBodyBytes` option (default `1_048_576`, 1 MiB; must be a positive
  integer) caps how much a JWKS endpoint may make `refresh()` swallow
  into memory before shape validation — previously `fetchAndSwap`
  called `res.json()` with no size bound anywhere in the fetch path.
  Enforcement is two-layer, before any parse: a `Content-Length`
  precheck rejects an over-limit body without reading it, and the body
  is then read as text and its UTF-8 byte length checked before
  `JSON.parse`. An over-limit response throws
  `JwksKeyStore: JWKS response from <url> exceeds the <max> byte body
  limit (...)`, leaves the previous snapshot and freshness timestamp
  untouched, and is terminal for retries. `JwksFetchResponse` gains
  optional `text()` and `headers` members (the native `Response`
  always provides both, so the default fetch gets both layers); a
  custom `fetchImpl` whose response offers only `json()` cannot be
  measured, so the limit is documented as unenforced there and the
  document is parsed via `json()` exactly as before. The 1 MiB
  default is calibrated on measured bodies: a three-key JWKS document
  is 645 bytes, 100 ed25519 keys 9,800 bytes, 20 RSA-2048 keys 7,860
  bytes (2026-11-08) — roughly 100x headroom over a 100-key rotation
  set. 14 new tests in `test/jwksMaxBody.test.ts`, including loopback
  coverage of both layers on the default fetch and a mutation check
  (weakening the post-read check turns 7 of them red).
- Two new JWKS refresh benchmark rows (backlog #969): a serial
  `JwksKeyStore.refresh` row over a real loopback `http` server
  serving a fixed three-shape JWKS document (ed25519 / P-256 / RSA)
  through the store's default fetch — one measured op builds a fresh
  store and refreshes it once, self-checking that all three pinned
  kids resolve with exactly one `stats().refreshes` and zero
  failures — and a `JwksKeyStore.refreshIfStale` row on a fresh
  snapshot, self-checking that the call reports no refresh, fetches
  nothing, and still resolves the pinned kid. The stale
  `refreshIfStale` row this item also contemplated already existed
  (added after the item was written), so no duplicate row was added.
  In the 2026-11-07 run the loopback row measured ~774.2 ops/sec
  (~1291.66 µs/op) and the fresh row ~3,181,964 ops/sec (~0.31
  µs/op); the README Benchmarks table was refreshed from the same
  run (118 rows).
- `JwksKeyStore.clear()` (backlog #964): drops the cached key snapshot
  and the freshness timestamp at once (`size` 0, `lastRefreshedAt`
  `null`, `isStale()` `true`) and resets the `stats()` counters to
  zero — the `ReplayCache.clear()` semantics, applied to this store.
  After it, every `resolve()` returns `undefined` and verification
  fails closed with `KEY_RESOLUTION_FAILED`, until a `refresh()`
  re-fetches or a snapshot is restored into the cleared store; a
  refresh already in flight still installs its snapshot when it
  settles. `npm run demo` shows the whole sequence in its JWKS clear
  segment (verify, clear, rejected verification, re-fetch,
  re-verification).
- Fetch response adapter (backlog #961):
  `fromFetchResponse(res, body, opts?)` (plus the `FetchResponseLike`
  / `FromFetchResponseOptions` types) normalizes a `fetch()`
  `Response` into a `RequestLike`, the fetch-API twin of
  `fromNodeResponse`: `res.status` bound via `@status` (missing or
  non-integer statuses fail fast, same boundary rule), header names
  lowercased and multi-value fields joined with `", "` (a real
  `Headers` instance, or any iterable of `[name, value]` pairs),
  `opts.request` attached as `RequestLike.request` for covered `;req`
  binding or an explicit `opts.method` + `opts.url` pair instead.
  The body is read by the caller and passed in as
  `string | Buffer | Uint8Array` — the adapter never consumes
  `res.body`, and a `Uint8Array` body is copied into a `Buffer`.
  A fetch `Response` carries no trailers, so the resulting
  `RequestLike` never gains a `trailers` field and `;tr` components
  cannot verify through this adapter.
- Per-label signed replay-cache snapshots (backlog #952):
  `exportSignedSnapshotsByLabel(caches, secret)` exports one
  HMAC-SHA256 envelope per label of a `replayCacheByLabel` map, and
  `ReplayCache.restoreSignedSnapshotsByLabel(envelopes, secret,
  opts)` (plus the `fromSignedSnapshotsByLabel` alias) MAC-verifies
  and restores every label atomically — any label failing rejects
  the whole batch and installs nothing. `opts.expectedLabels`
  optionally pins the label set: an unknown/extra label (including
  a copied envelope filed under a label the deployment never had —
  the MAC covers a label's snapshot, not its name) or a missing
  expected label fails the restore. The unsigned per-label snapshot
  stays trusted configuration only, like the single-cache one.
- Demo gains a per-label ReplayCache signed snapshot segment (backlog
  #958): two requests — one per label (`merchant`, `gateway`), each
  with its own fixed nonce — verify against their own caches, and the
  pair is exported with `exportSignedSnapshotsByLabel`, crossed over a
  JSON wire round-trip, and restored together with
  `ReplayCache.restoreSignedSnapshotsByLabel` pinned to the two labels
  with `expectedLabels`. Each label's request still replays against
  its own restored cache, the merchant nonce is fresh under the
  gateway cache, a fresh nonce verifies against the restored merchant
  cache, and a rewritten gateway envelope rejects the whole batch
  with a MAC mismatch while the good restore stays usable. Only the
  envelope versions and the entry counts are printed, never the secret
  or the MACs; `DemoResult` gains the segment's shape fields,
  verifications and the pinned rejection message, and the demo
  fail-fasts on all of them. Zero network, zero randomness: the
  segment is byte-identical between runs.
- Demo gains an HMAC `oct` JWK key-distribution segment (backlog
  #944): a fixed 32-byte HMAC secret is exported with
  `exportSymmetricKeyJwk` (HS256 + kid `hmac-key-1`), read back
  through a JSON wire round-trip with `importSymmetricKeyJwk`, and
  the imported key completes an hmac-sha256 sign -> verify
  round-trip under the exported kid — the symmetric half of JWK key
  distribution, for gateway key rotation over JWKS. A 31-byte secret
  is shown rejected at export and a 16-byte `k` JWK at import, both
  by the per-alg secret floor the sign/verify paths enforce. Only
  the JWK's shape (kty/kid/alg and the 43-character `k` length) is
  printed, never the secret bytes; `DemoResult` gains the segment's
  shape fields, verification and both pinned rejection messages,
  and the demo fail-fasts on all of them. Zero network, zero
  randomness: the segment is byte-identical between runs.
- Demo gains a required co-signatures segment (backlog #942): the
  dual-signed request (merchant `sig1` + gateway) is verified with
  `verifyAllLabels` under `requiredLabels: ["sig1", "gateway"]`
  (both labels ok), then the gateway label's members are stripped
  from the `signature-input` and `signature` headers and the same
  call reports the merchant label still ok while the gateway label
  comes back as a synthetic `MISSING_REQUIRED_LABEL` failure — a
  downgrade that drops a co-signature is a fail-closed policy
  failure, not a silent absence. `DemoResult` gains
  `requiredLabelsVerification` /
  `requiredLabelsStrippedVerification`; the demo fail-fasts on both
  results and the new tests pin the printed lines and the
  byte-identical slice. Zero network, zero randomness: the section
  reuses the in-process dual-signed request.
- `JwksKeyStore.refresh()` skips entries that declare a non-signing
  purpose (backlog #940): a JWKS entry whose `use` is present and is
  not `"sig"` (RFC 7517 §4.2 — e.g. `use: "enc"`), or whose
  `key_ops` is present and does not list `"verify"` (§4.3), is not a
  verification key and is now skipped, like kid-less entries, while
  its siblings still import — before this, such an entry was imported
  and `resolve()` could hand an encryption key to a verifier.
  Entries declaring neither field are kept (both are optional in a
  JWKS document), a malformed value (non-string `use`, non-array
  `key_ops`) is likewise skipped rather than coerced, and a skipped
  entry never shadows a later same-`kid` signing entry. Snapshot
  restore is unchanged (a snapshot carries no `use` / `key_ops`).
  New `test/jwks.test.ts` entries (8 tests) cover the `use: "enc"`
  skip with a verifying sibling, `use: "sig"` kept, `key_ops`
  without `"verify"` skipped (including empty and malformed values),
  `key_ops` with `"verify"` kept, neither-field entries kept, the
  same-`kid` non-shadowing case, the skipped kid resolving to
  `KEY_RESOLUTION_FAILED`, and an all-non-signing document refreshing
  to an empty snapshot.
  (backlog #939): a shared `assertNoDuplicateCoveredComponents`
  guard (exported, with its `coveredComponentKey` normalizer) runs
  before the signature base is built and before any crypto —
  `["@method", "@method"]` threw nothing before and minted a base
  with the `@method` line twice, which the verifier rebuilds
  identically and accepts. The comparison lowercases the base and
  parameter names and strips surrounding quotes, and the parameter
  suffix counts: `"@method"` + `"@METHOD"` and `"@method";req` +
  `"@METHOD";REQ` are rejected, while `"@method"` + `"@method";req`
  stays legal — `;req` reroutes the component to the associated
  request, so the two bind different values (the coexistence the
  `reqComponent` "same base" test pins). `addSignature` /
  `addResponseSignature` inherit the guard through `signRequest` /
  `signResponse`; the verify side is unchanged, so a foreign
  signature minted over a duplicated list still verifies. New
  `test/duplicateCoveredComponent.test.ts` (9 tests) covers the
  exact / case-variant / quoted / same-parameter-case-variant
  rejections, the `;req` non-duplicate, the clean-list round-trip,
  both append paths, and the unchanged verify behavior.

- Benchmark row for the `addResponseSignature` dual-label
  response path (backlog #938): `bench/bench.ts` gains
  `benchmarkAddResponseSignature`, the response-side mirror of
  `benchmarkMultiLabel` — the merchant signs the settlement
  response with `signResponse` (ed25519) and the gateway appends
  its hmac-sha256 label with `addResponseSignature`, both with
  `created` pinned, and every measured pass verifies both labels
  per label with `verifyResponse` (no loopback adapter), pinning
  each label's alg / keyid / covered components; a flipped
  gateway-signature byte is pinned outside timing to fail exactly
  the gateway label with `SIGNATURE_MISMATCH` while the merchant
  label still verifies. The new row measured ~5,306 ops/sec
  (188.47 µs/op) in this run, close to the request-side
  `verifyAllLabels (2 labels)` row, as expected for a path whose
  cost is dominated by the ed25519 merchant verification. The
  README Benchmarks table was refreshed from the same run (Node
  v24.22.1, shared host).

- `signRequest` / `signResponse` fail fast on an algorithm/key-type
  mismatch (backlog #936): the shape predicate behind the verify
  side's `algFallback: "infer"` check (`verify.ts`
  `assertAlgMatchesKeyShape`) moved to `keys.ts` as the shared
  `algMatchesKeyShape` / `describeKey` (both exported), and
  `signRequest` calls it before building the signature base or
  touching any crypto — an RSA key paired with `alg: "ed25519"`
  (or any other swapped pair, including a P-256 key on the P-384
  curve) now throws `signRequest: alg "…" is incompatible with the
  key (…)` instead of a cryptic node:crypto error.
  `signResponse`, `addSignature`, and `addResponseSignature`
  inherit the check through `signRequest`. New
  `test/algKeyMismatch.test.ts` cases (14) cover every alg ×
  wrong-key pairing, the RSA `rsa-v1_5-sha256` positive control,
  all eight correct pairings round-tripping, the check firing
  before base building, and all three inherited paths. One
  existing `test/rsaV15.test.ts` expectation was updated to the
  new uniform sign-side message (the verify-side wording is
  unchanged).

- Demo gains an `addResponseSignature` multi-party response
  segment (backlog #929): `src/demo.ts` signs the loopback
  settlement response with `signResponse` (merchant label,
  ed25519) and appends the gateway label with
  `addResponseSignature` (hmac-sha256, a different key), then
  adapts it with `fromNodeResponse` and verifies both labels
  with `verifyAllLabels`; tampering the gateway label's
  signature bytes fails only that label. `DemoResult` gains
  `addResponseSignatureResponseRequest` /
  `addResponseSignatureResponseVerification` /
  `addResponseSignatureResponseTamperedVerification`. New
  `test/demo.test.ts` cases (2) pin the segment's structure
  and byte-identical printed lines across runs.
- `;sf` supports the RFC 9651 Date and Display String types
  (backlog #926): `src/structuredFields.ts` adds `parseDate` (`@` +
  an integer number of seconds, §3.3.7 — a negative delta is a valid
  pre-epoch timestamp per the RFC, and a Decimal Date fails closed)
  and `parseDisplayString` (`%` + a double-quoted run, §3.3.8 —
  percent-escapes take lowercase hex only, the accumulated bytes
  must decode as strict UTF-8, and there are no backslash escapes),
  with strict serialization (Date as canonical `@<int>`; Display
  String re-encoded per §4.1.11, percent-encoding `%`, DQUOTE, and
  bytes outside printable ASCII with lowercase hex). No registry
  change was needed: the type is determined by the first character,
  so the Dictionary → List → Item trial order and
  `canonicalizeStructuredFieldValueAs` cover the new types, and
  `;key` member selection serializes Date and Display String members
  strictly too. A foreign signer covering a Date or Display String
  header with `;sf` previously failed with
  `SIGNATURE_BASE_BUILD_FAILED` even when the signature was valid.
  New `test/structuredFieldDateDisplayString.test.ts` (19 cases)
  pins the shape: Date round-trip and canonical form, negative Dates,
  Dates in Dictionaries/Lists/Inner Lists/parameters, invalid Dates
  (decimal, non-numeric, empty, 16-digit), Display String ASCII and
  non-ASCII round-trips, DQUOTE/backslash via `%22`/`%5c`, uppercase
  and malformed percent-escapes rejected, non-UTF-8 bytes rejected,
  raw non-ASCII/control characters rejected, backslash-literal
  behaviour, RFC 8941 core types unaffected, and `;sf` sign→verify
  round-trips for Date, Display String, and a Date Dictionary member
  via `;key`, plus a tampered Date failing with
  `SIGNATURE_MISMATCH`.
  (backlog #923): labels that must be present on the request for
  multi-party verification to pass — every required label that never
  appears on the wire is appended as a synthetic failure (`{ ok: false,
  code: "MISSING_REQUIRED_LABEL", label }`, new failure code) after
  the wire-order results, in `requiredLabels` order, including when
  the request carries no `signature-input` header at all (which
  otherwise yields `[]` and would pass a bare
  `results.every((r) => r.ok)` check). An empty list means "no
  check"; duplicate or empty-string entries are a configuration
  error, validated before any verification runs, even for unsigned
  requests. A present-but-failing label keeps its real failure code
  with no synthetic entry. New `test/requiredLabels.test.ts` (12
  cases) pins the shape: both labels present, stripped gateway label,
  unsigned request, empty list, duplicate/empty/non-array/non-string
  configuration errors (including on unsigned requests), present-but-
  failing label, synthetic-entry ordering, `verifyRequest` path
  unaffected, and `verifyAllLabelsOrThrow` throwing
  `MISSING_REQUIRED_LABEL`.
- HMAC-signed `ReplayCache` snapshot envelope (backlog #920): new
  `ReplayCacheSignedSnapshotEnvelope` (`{ v: 1, snapshot, mac }`) in
  `src/replay.ts`, mirroring the JWKS signed snapshot format —
  `exportSignedSnapshot(secret)` (HMAC-SHA256 hex over the snapshot's
  canonical JSON; the secret is never written into the envelope) and
  `static restoreSignedSnapshot(envelope, secret, opts?)` (verifies
  the MAC with a constant-time comparison before parsing the snapshot;
  a tampered entry, a tampered `seenAt`, or a wrong secret is rejected
  and installs nothing, and a MAC-valid but structurally broken
  snapshot still fails the strict snapshot validation), plus the
  `fromSignedSnapshot` alias. The unsigned `exportSnapshot()` /
  `restore()` path is unchanged and remains trusted-configuration
  only. New `test/replaySignedSnapshot.test.ts` (14 cases) pins the
  shape: signed JSON round-trip with replay still reported
  (`NONCE_REPLAY`) end-to-end through `verifyRequest`, tampered entry
  / `seenAt` / wrong secret all rejected, empty and non-string secrets
  fail fast on both sides, key-reordered JSON still verifies (canonical
  MAC) while reordered entries fail it, MAC-valid malformed snapshots
  rejected, Buffer secrets equivalent to the same string secret, and
  expired entries excluded from the signed snapshot.
- Throwing multi-label verification (backlog #914): new
  `verifyAllLabelsOrThrow(req, opts)` in `src/verify.ts` returns the
  per-label success results when every label verifies and otherwise
  throws a `VerifyError` carrying the first failing label's stable
  `code` and `label` (plus the wire fields `keyId` / `alg` / `nonce` /
  `tag` / `created` / `expires` the failure result reported, mirroring
  `verifyRequestOrThrow`); an unsigned request returns `[]` without
  throwing, exactly as `verifyAllLabels` does, and caller
  configuration errors (mutually exclusive key options) still throw a
  plain `Error`. New `test/verifyAllLabelsOrThrow.test.ts` (10 cases)
  pins the shape: both-label success with `coveredComponents`, a
  tampered label throwing `SIGNATURE_MISMATCH` for that label, an
  expired label throwing `EXPIRED`, a replayed nonce throwing
  `NONCE_REPLAY` on the second verify, first-failure-wins across two
  differently failing labels, malformed `signature-input` throwing
  `MALFORMED_SIGNATURE_INPUT`, and the `[]` / config-error paths.
- Response-side `content-digest` sha-256 coverage (backlog #906): new
  `test/responseContentDigestSha256.test.ts` (8 cases) pins that
  `signResponse` / `verifyResponse` inherit the request-side digest
  semantics — `contentDigestAlg: "sha-256"` emits the sha-256 wire
  shape and verifies end-to-end, a tampered body reports
  `BODY_DIGEST_MISMATCH`, a hand-built dual-algorithm header
  (sha-512 + sha-256) verifies with sha-512 preferred (a tampered
  sha-256 entry still verifies, a tampered sha-512 entry reports
  `BODY_DIGEST_MISMATCH`), a sha-256-only header verifies via the
  fallback, and a body-less (`@status`-only) response carries no
  digest and verifies. No source change: the forwarding already
  behaved correctly; this round adds the missing response-side proof.
- Response-side `algFallback: "infer"` coverage (backlog #905): new
  `test/responseAlgFallback.test.ts` (10 cases) pins that
  `verifyResponse` enforces `VerifyOptions.algFallback` exactly as
  `verifyRequest` does — hand-built response signatures that omit the
  optional `alg` parameter verify under `algFallback: "infer"` for
  both ed25519 and hmac-sha256 (with `alg`, `keyId`, and `created`
  echoed back), the same hmac wire fails with `VERIFICATION_ERROR`
  without the opt-in and with an explicit `algFallback: false` (the
  legacy default is ed25519), an ed25519 wire without `alg` still
  verifies without the opt-in (the default IS ed25519), a wrong key
  or secret still reports `SIGNATURE_MISMATCH` rather than being
  masked by the inference, and body-less (`@status`-only) responses
  follow the same infer/default split. No source change: the
  forwarding already behaved correctly; this round adds the missing
  response-side proof.
- Response-side multi-party signing (backlog #904): new
  `addResponseSignature(signedRes, opts)` in `src/response.ts` mirrors
  `addSignature` for responses — the second signature base is built
  over the unsigned response (existing `signature-input` / `signature`
  headers stripped), the label must be unique, appending to an
  unsigned response fails fast, the wire `content-digest` algorithm
  wins over `opts.contentDigestAlg` (a contradictory choice, or a
  digest algorithm this library cannot emit, is a configuration
  error), `;req` components are covered when the triggering request
  is passed as `opts.request`, and the input response is never
  mutated. New `test/addResponseSignature.test.ts` (13 cases) pins
  merchant (ed25519) + gateway (hmac) dual labels verifying per label
  through `verifyResponse` and together through `fromNodeResponse` +
  `verifyAllLabels`, a real loopback server dual-signing a response
  verified by an `http.get` client, label collision / empty label /
  unsigned-input errors, digest-algorithm conflict and un-emittable
  algorithm errors, a tampered gateway label leaving the merchant
  label intact, a body-less `@status`-only double signing round-trip
  with status tampering failing both labels, input immutability,
  wire label order with a stable content-digest, and `;req` binding
  for both labels (a swapped request fails both).
- Response-side `structuredFieldTypes` type-registry coverage (backlog
  #900): new `test/responseStructuredFieldTypes.test.ts` (9 cases) pins
  that `verifyResponse` enforces `VerifyOptions.structuredFieldTypes`
  exactly as `verifyRequest` does — a registered List header
  (`x-scopes: "read", "write"`) and a registered Dictionary header
  (`scope=read, level=2`) each round-trip through `signResponse` /
  `verifyResponse` with `@status` covered alongside, the sign side
  throws when a Dictionary-shaped value is registered as a List, the
  verify side fails closed with `SIGNATURE_BASE_BUILD_FAILED` when a
  signature minted without a registry is verified under a mismatched
  List registry, an unregistered `;sf` field keeps the default trial
  order next to a registered one, registry field names match
  case-insensitively, a malformed registry (unknown type name,
  non-object, empty field name) is a configuration error on both
  sides, a forgery still reports `SIGNATURE_MISMATCH` rather than
  being masked by the registry, and a body-less (`@status`-only)
  response with a `;sf` header verifies the same way. No source
  change: the forwarding already behaved correctly; this round adds
  the missing response-side proof.
- Response-side `clockSkewToleranceSec` / `expiredToleranceSec`
  clock-tolerance coverage (backlog #899): new
  `test/responseClockTolerance.test.ts` (10 cases) pins that
  `verifyResponse` enforces both clock-tolerance options exactly as
  `verifyRequest` does — a future `created` inside the default 60s
  skew verifies, one second past it fails with `CREATED_IN_FUTURE`
  (reason pins the clock-skew wording), exactly at the default skew
  boundary verifies (the check is a strict `>`), the same future
  signature verifies under a wide tolerance and fails under a tight
  one, an expired signature inside the `expiredToleranceSec` grace
  verifies, one second past the grace fails with `EXPIRED`, exactly
  at the grace boundary verifies, the default grace of 0 rejects an
  expired signature one second past `expires`, a forgery still
  reports `SIGNATURE_MISMATCH` rather than being masked by either
  tolerance, and body-less (`@status`-only) responses follow the
  same skew and grace rules. No source change: the forwarding already
  behaved correctly; this round adds the missing response-side proof.
- Response-side `maxSignatureAgeSec` age-cap coverage (backlog #898):
  new `test/responseMaxSignatureAge.test.ts` (8 cases) pins that
  `verifyResponse` enforces `VerifyOptions.maxSignatureAgeSec` exactly
  as `verifyRequest` does — a response signature inside the 300s cap
  verifies, one second past it fails with `SIGNATURE_TOO_OLD`
  (reason pins the measured age), exactly at the cap verifies (the
  check is a strict `>`), a hand-built response signature with no
  `created` bypasses the age check entirely, a bogus window (negative,
  NaN, Infinity, non-number) throws a configuration error, a forged
  old signature still reports `SIGNATURE_MISMATCH` rather than being
  masked by the age check, a body-less (`@status`-only) response is
  aged the same way, and with the cap unset an old response signature
  still verifies for backwards compatibility. No source change: the
  forwarding already behaved correctly; this round adds the missing
  response-side proof.
- Response-side `memoizeKeyResolver` cache coverage (backlog #897):
  new `test/responseMemoizeKeyResolver.test.ts` (8 cases) pins that
  a `memoizeKeyResolver`-wrapped resolver passed to `verifyResponse`
  survives the response path's fresh internal RequestLike rebuild —
  the same keyid verified twice costs one underlying call, different
  keyids have independent entries, a throwing resolver is not cached
  (a retry re-invokes it and then verifies), an unknown keyid is
  never cached, TTL expiry re-invokes the resolver, a cache hit does
  not extend the TTL, a cache-hit result matches the direct resolver
  result field for field, and a body-less (`@status`-only) response
  is cached the same way. No source change: the forwarding already
  behaved correctly; this round adds the missing response-side proof.
- Response-side presence-gate and keyid-binding coverage (backlog #896):
  new `test/responsePresenceBinding.test.ts` (11 cases) pins that
  `verifyResponse` enforces `VerifyOptions.requireTag`,
  `requireNonce`, and `expectedKeyId` exactly as `verifyRequest`
  does — an untagged response is rejected with `MISSING_TAG`, a
  nonce-less response with `MISSING_NONCE`, a wrong keyid and a
  keyid-less signature with `KEYID_MISMATCH`, a fully conforming
  signature passes all three gates with tag, nonce, and keyid
  echoed, the same batch verifies with all gates off, a forged
  signature still reports `SIGNATURE_MISMATCH` rather than being
  masked by a policy gate, and a body-less (`@status`-only)
  response is gated the same way. No source change: the forwarding
  already behaved correctly; this round adds the missing
  response-side proof.
- Response-side `candidateKeys` rotation coverage (backlog #895):
  new `test/responseCandidateKeys.test.ts` (10 cases) pins that
  `verifyResponse` walks a `VerifyOptions.candidateKeys` rotation
  list exactly as `verifyRequest` does — a signature minted with
  the second candidate verifies with its keyid, alg, and covered
  components pinned, a first-candidate hit verifies with its own
  keyid, no matching candidate reports `SIGNATURE_MISMATCH` (not
  `KEY_RESOLUTION_FAILED`), an empty list and non-KeyObject entries
  throw configuration errors naming the offending index, `key` +
  `candidateKeys` and `keyResolver` + `candidateKeys` together
  throw the mutual-exclusion configuration error, an old key still
  in the list keeps verifying during the rotation window while the
  same key removed from the list is rejected, and a body-less
  (`@status`-only) response walks the list the same way. No source
  change: the forwarding already behaved correctly; this round
  adds the missing response-side proof.
- Response-side `keyResolver` gateway coverage (backlog #894):
  new `test/responseKeyResolver.test.ts` (9 cases) pins that
  `verifyResponse` resolves a response signature's keyid through
  `VerifyOptions.keyResolver` exactly as `verifyRequest` does —
  both rotating keyids verify, an unknown keyid reports
  `KEY_RESOLUTION_FAILED`, a keyid-less signature reports the same
  code, a resolver returning the wrong key still reports
  `SIGNATURE_MISMATCH`, `key` + `keyResolver` together throws the
  mutual-exclusion configuration error, a throwing resolver
  surfaces `VERIFICATION_ERROR` without escaping, a retired keyid
  is rejected while the new keyid verifies, and a body-less
  (`@status`-only) response resolves the same way. No source
  change: the forwarding already behaved correctly; this round
  adds the missing response-side proof.
- Signed-snapshot benchmark rows (backlog #891): `bench/bench.ts`
  now measures `JwksKeyStore.exportSignedSnapshot` and
  `JwksKeyStore.restoreSignedSnapshot` (JSON round-trip) over a
  pinned three-shape store (ed25519 / P-256 / RSA) and fixed
  secret — export ~8,105 ops/sec (123.38 µs/op), restore
  ~7,280 ops/sec (137.35 µs/op) on this run. Every measured call
  re-pins the envelope (version, fetch time, kid order, per-shape
  `kty`, public-only JWK fields, 64-hex MAC, no secret in the
  persisted JSON) or the restore contract (size, original fetch
  time, pinned-kid resolution); the full three-shape
  `verifyRequest` round-trip over the restored keys and the
  tampered-envelope / wrong-secret rejections (old store
  untouched, re-exported envelope identical) are pinned outside
  timing. The README Benchmarks table is refreshed from this
  run (113 rows, 2026-11-05); mutation check (expected restored
  size forced wrong) fails the bench self-check, restored to
  full green.
- Per-label `;sf` type registries for `verifyAllLabels` (backlog
  #886): `VerifyAllOptions.structuredFieldTypesByLabel` maps a
  signature label to its own field-name → type registry, validated
  per label with the same rules as the global
  `structuredFieldTypes`; a mapped registry replaces the global one
  for that label (not merged), unmapped labels fall back to the
  global registry, and a malformed map or registry throws a caller
  configuration error naming the label. New
  `test/structuredFieldTypesByLabel.test.ts` (12 cases) pins the
  routing both ways on one shared field, the replacement (not
  union) semantics, the empty-registry case, the global fallback,
  case-insensitive field matching, and the malformed-map errors;
  mutation check (forcing the global registry for every label)
  turns 6 of the 12 cases red, restored to full green.
- Response-side nonce replay-cache tests (backlog #883): new
  `test/responseReplayCache.test.ts` pins that `verifyResponse`
  inherits the request-side `replayCache` semantics through its
  `verifyRequest` delegation — first verification passes and
  records the nonce, a second verification returns `NONCE_REPLAY`,
  failed verifications (tampered status, wrong key) never pollute
  the cache, nonce-less responses bypass the cache, no cache
  configured keeps the old accept-twice behaviour, distinct nonces
  are tracked independently, and a nonce is reusable after its TTL
  expires. Note recorded in the test file: no
  `verifyResponseOrThrow` exists (the response API returns wire
  failures, never throws them), so the backlog item's OrThrow
  clause is covered by its result-code equivalent.
- Benchmark rows for `verifyResponse` × `allowedAlgs` (backlog
  #880): the same ed25519 response fixture as the plain
  `verifyResponse` row, measured twice — a hitting whitelist
  (`["ed25519"]`, full ed25519 verification, ~3,953 ops/sec /
  252.98 µs/op in this run) and a missing whitelist
  (`["hmac-sha256"]`, pre-cryptographic `ALG_NOT_ALLOWED`
  rejection, ~107,566 ops/sec / 9.30 µs/op, about 27.2× the hit
  throughput) — each row self-checking every measured pass and
  pinning the opposite half plus the no-whitelist default
  outside timing, with the README Benchmarks table refreshed
  from the same run (Node v24.22.1 / AMD EPYC 9D25 shared host).
- CLI demo response-signing segment (backlog #868): the demo now
  shows the direct `signResponse` / `verifyResponse` entry points
  (not the loopback gateway segment, which signs through
  `signRequest` and adapts with `fromNodeResponse`) — the same
  ed25519 key pair signs a settlement response with `@status`
  plus `content-digest` covered by default and verifies, and a
  200 -> 500 status tamper is rejected with
  `SIGNATURE_MISMATCH`; `DemoResult` carries the signed response
  and both verifications, and the demo tests pin the new output
  lines and their byte-identical double-run output. README test
  count updated to the real 1385.
- Benchmark rows for `signResponse` / `verifyResponse` (backlog
  #865): one ed25519 fixture signed outside timing with `created`
  pinned, measured as a sign row and a verify row, each
  self-checked per iteration (`@status` plus `content-digest`
  covered; verify pins ok / alg / keyid / covered components)
  with a 200 -> 500 status tamper pinned `SIGNATURE_MISMATCH`
  outside timing; zero network, so the rows isolate the wrapper
  cost from the loopback `fromNodeResponse` rows. README
  Benchmarks table refreshed from one real run.
- `signResponse` / `verifyResponse` accept an opt-in `request` option
  (backlog #861): with the triggering request attached on both sides,
  a covered `;req` component resolves against it, binding the
  response signature to that request so a gateway callback cannot be
  transplanted onto another request; a `;req` component with no
  request attached is still a configuration error, and a
  request-derived component without `;req` is always rejected (it
  would resolve against the response itself, which has no method or
  URL — cover the `;req` form instead). A response `;req` component
  reads the triggering request itself, not the request's signature
  values.
- `signResponse` / `verifyResponse` response signing entry points
  (backlog #854): thin wrappers over `signRequest` / `verifyRequest`
  (zero new cryptography) taking the response shape directly
  (`{ status, headers, body? }`), covering `@status` by default
  (plus `content-digest` when a body is present); the sign side
  returns a response shape with `coveredComponents` echoed, the
  verify side returns the plain `VerifyResult`. Response components
  only: a covered request-derived component (`@method`, `@scheme`,
  `@authority`, `@path`, `@query`, `@query-param`, `@target-uri`,
  `@request-target`) or a `;req` component with no request attached
  is a caller configuration error pointing at the request-side API,
  never a fabricated method or URL (the opt-in `request` exception
  arrived later, backlog #861, see the entry above).
- `VerifyOptions.allowedAlgs` verification algorithm whitelist (backlog
  #851): when set, only signatures whose algorithm is in the list
  verify — any other algorithm fails with the new `ALG_NOT_ALLOWED`
  error code, checked before any cryptographic work (a wire `alg`
  outside the list is rejected after header parsing, before the
  signature base is rebuilt or any key is resolved; an alg-less
  signature is judged by its effective algorithm — the legacy
  `ed25519` default, or the key-shape inference under
  `algFallback: "infer"`). An empty list, a non-array, or an entry
  naming an unimplemented algorithm is a caller configuration error
  (throw); unset means the previous behavior (every implemented
  algorithm accepted). `VerifyAllOptions.allowedAlgsByLabel` applies
  the same rule per label (a mapped list replaces the global list
  for that label; unmapped labels fall back to it), and a rejected
  attempt never reaches the nonce replay cache. `src/verify.ts`
  gains the option, the per-label map, and both validators;
  `src/errors.ts` gains the code; the README error-code table and
  feature list document it; `test/allowedAlgs.test.ts` adds 17
  cases (whitelist pass / wire rejection / backwards-compatible
  unconfigured pass / multi-alg list / four configuration-error
  shapes / alg-less legacy and infer judgments / per-label
  independence, fallback, replace-not-union, and malformed-map
  errors / `verifyRequestOrThrow` code / nonce-cache non-pollution).
- CLI demo JWKS signed snapshot restart segment (backlog
  #848): the demo now shows the #842 HMAC envelope's
  restart story — a store refreshes once through a counting
  fake fetch, exports with `exportSignedSnapshot()` (only
  the envelope version and key count are printed, never
  the secret or the MAC), round-trips the envelope through
  JSON text, and cold-starts a new store with
  `restoreSignedSnapshot()` over a fetch that throws if
  called, so the unchanged fetch count proves the restore
  performed no network access. A detached envelope copy
  with one key rewritten is rejected with the pinned MAC
  mismatch message, and verification through the restored
  store still passes afterwards, proving the failed
  restore left the good snapshot untouched.
- Benchmark `;sf` type-registry group (backlog #845):
  `bench/bench.ts` measures the fixed eight-value
  `SF_REGISTRY_FIXTURE` corpus (each value carrying its registered
  type) under both routes — the default Dictionary → List → Item
  trial order and the direct `canonicalizeStructuredFieldValueAs`
  parse — with both routes self-checked outside timing against
  hand-pinned RFC 8941 §4 serializations and a wrong registered
  type failing closed, so a corrupted registry entry aborts the
  bench run instead of timing a wrong result. The README
  Benchmarks table is refreshed from one real run on 2026-11-03
  (trial order over the registry corpus ~16,826 ops/sec, registry
  direct ~87,755 ops/sec, machine-local numbers, not guarantees).
- `JwksKeyStore` snapshot opt-in HMAC signed envelope (backlog
  #842): `exportSignedSnapshot(secret)` wraps the snapshot in
  `{ v: 1, snapshot, mac }`, where `mac` is HMAC-SHA256 (hex) over
  the canonical JSON of the snapshot (object keys sorted
  recursively, array order preserved) under the caller's secret,
  and `restoreSignedSnapshot(envelope, secret)` rejects a tampered
  key, a tampered `fetchedAtSec`, or a wrong secret with the old
  snapshot untouched — authenticity is checked before snapshot
  parsing, so a MAC-valid but malformed snapshot still fails on
  validation and never partially installs. An envelope with an
  unknown field (including a smuggled `secret`), a version other
  than `1`, or a malformed `mac` is rejected; an empty secret is a
  caller-configuration error on both sides; the secret is never
  written into the envelope, and the envelope is integrity
  protection only, not encryption. The unsigned
  `exportSnapshot()` / `restore()` paths are unchanged, and the two
  forms do not cross-accept. `src/jwks.ts` gains the exported
  `JwksSignedSnapshotEnvelope` type, `src/index.ts` exports it, and
  `test/jwksSignedSnapshot.test.ts` adds 12 cases (signed
  round-trip through JSON persistence verifying all three key
  types, Buffer secret, key-order-insensitive canonical JSON,
  tampered key/timestamp/mac and wrong secret rejected with the old
  store untouched, unknown-field and version/mac-shape rejections,
  empty-secret rejections, MAC-valid malformed snapshot failing
  closed, unsigned-path regression and non-cross-acceptance, and
  export-before-refresh plus no refresh-counter movement on a
  failed signed restore). The README snapshot section, Limitations,
  and SECURITY.md now describe the signed envelope alongside the
  unchanged unsigned trusted-configuration semantics, and both
  test-count mentions move 1328 → 1340.

- Per-field `;sf` type registry (backlog #839): `SignOptions` and
  `VerifyOptions` gain optional `structuredFieldTypes` (a field name
  → `"dictionary" | "list" | "item"` map, matched case-insensitively).
  A registered field is parsed only as its registered type, so a
  Dictionary-shaped value registered as a List fails fast on the sign
  side and with `SIGNATURE_BASE_BUILD_FAILED` on the verify side
  instead of being rescued by the default Dictionary → List → Item
  trial order; unregistered fields keep that trial order unchanged.
  An empty field name, a case-duplicate key, or an unknown type name
  is a caller configuration error on both sides (thrown before any
  crypto runs, and for `verifyAllLabels` before the per-label walk).
  The registry is caller configuration, never wire data, and it
  applies to `;sf` only: `;bs` (raw bytes) and `;key` (one Dictionary
  member) keep their own rules, `;sf` combined with either still
  fails closed, and `verifyAllLabels` applies the same registry to
  every label (there is no per-label registry map). `src/
  structuredFields.ts` gains `canonicalizeStructuredFieldValueAs`
  and the exported `StructuredFieldType` type; `buildSignatureBase`
  and `resolveComponent` accept the registry via
  `ResolveComponentOptions`. `test/structuredFieldTypes.test.ts`
  adds 14 cases (registered dictionary/list/item round-trips,
  sign- and verify-side fail-closed mismatches, unregistered-field
  trial order, case-insensitive keys, illegal registries on both
  sides, `;req;sf` and `;tr;sf` combinations, unchanged `;key`/`;bs`
  paths, per-label independent reporting in `verifyAllLabels`,
  direct `buildSignatureBase` use, and no registry leakage into
  `signature-input`). The README `;sf` section and Limitations now
  describe the opt-in registry instead of the old "no registry"
  claim, and both test-count mentions move 1314 → 1328.

- `JwksKeyStore` with `requireHttps: true` now intercepts a fetch
  redirected from https to http (backlog #836): `JwksFetchResponse`
  gains an optional `url` (the final URL after redirects, populated
  by the default fetch from the native `Response.url`), and
  `fetchAndSwap` throws
  `JwksKeyStore: JWKS fetch redirected to insecure http: <url>` before
  parsing anything from the downgraded response, leaving the previous
  snapshot and `lastRefreshedAt` untouched and counting one refresh
  failure. A custom `fetchImpl` that reports no final `url` cannot be
  checked on this path and passes through unchecked — documented as a
  limitation, not treated as verified. `test/jwksHttpsRedirect.test.ts`
  adds 8 cases: http redirect rejected with an empty snapshot and one
  refresh failure, redirect failure over a prior good snapshot leaving
  it and its timestamp untouched, https final URL passing, no-url
  custom impl passing (honest exemption), guard-off and explicit
  `requireHttps: false` passing, uppercase HTTP final URL intercepted,
  and the construction-time http rejection regression. The README JWKS
  section, SECURITY.md, and the CLI demo's requireHttps line are
  rewritten from the old "construction-time only" claim to the new
  redirect-interception semantics.

- CLI demo gains a closing request-target override segment
  (backlog #833): the same URL is signed four times — default
  origin-form, explicit absolute-form, authority-form and
  asterisk-form `RequestLike.requestTarget` overrides — and each
  form's `@request-target` base line is printed verbatim with its
  verification, plus a tampered override (asterisk-form signed,
  `/v1/refunds` presented) rejected with `SIGNATURE_MISMATCH`.
  `DemoResult` gains `requestTargetForms`,
  `requestTargetVerifications` and `requestTargetTamperVerification`;
  the `;bs` segment's lines test now expects the request-target
  segment to follow it, and `test/demo.test.ts` adds 2 cases
  (structure plus byte-exact closing lines with determinism).
  No source-code change: the override feature (#617) was already
  implemented and library-tested, the demo had never shown it.

- `JwksKeyStore` validates a JWKS entry's declared `alg` against its
  key family (backlog #830): `src/jwks.ts` gains `assertJwkEntryAlg`,
  run in `fetchAndSwap` before import — OKP only accepts `EdDSA`,
  P-256 only `ES256`, P-384 only `ES384`, P-521 only `ES512`, and RSA
  only `PS512` or `RS256`; a mismatch or a non-string `alg` makes
  `refresh()` throw and leaves the previous snapshot untouched, while
  an entry with no `alg` is unchecked and snapshot restore is
  unaffected (snapshots carry no `alg`). `test/jwksAlg.test.ts` adds
  12 cases: correct `alg` for all five families (plus RSA `RS256`),
  one mismatch per family with the old snapshot untouched, non-string
  `alg`, missing-`alg` regression, snapshot-restore round-trip,
  kid-less mismatched entries still skipped, and unknown `kty`
  still failing as unsupported. The README JWKS section documents
  the mapping table and the missing-`alg` limitation.

- Test coverage pinning duplicate signature-input label first-wins
  semantics (backlog #827): `test/duplicateLabel.test.ts` adds 10
  cases and changes no source code — `listSignatureLabels` returns a
  duplicate label once, `parseSignatureInput`/`parseSignatureField`
  return the first member's components, params and signature bytes,
  `verifyAllLabels` and `verifyRequest` return a single verdict
  decided by the first member, corrupting or retargeting only the
  second member leaves the verdict unchanged, corrupting the first
  member fails with `SIGNATURE_MISMATCH`, a third occurrence still
  converges to one result, and `addSignature` still refuses a
  duplicate label at sign time. The README multi-signature section
  now states the full first-wins rule explicitly: a duplicate label
  on the wire is not rejected, and the later occurrence is never
  verified.

- Benchmark row for `verifyAllLabels` x `;key` x `JwksKeyStore`
  per-label resolvers (backlog #822): `bench/bench.ts` gains
  `benchmarkVerifyAllJwksKeyComponents`, measuring `verifyAllLabels`
  with each label resolving through its own offline-restored
  `JwksKeyStore` (snapshot restore, fetch throws if called, zero
  network) while covering its own dictionary member (merchant
  `x-dict;key="b"`, gateway `x-dict;key="c"`, per-label selection
  as #817 records). One measured op verifies the fresh dual
  (both labels ok, each keyid echoed, each covered list including
  its own `;key` member). Outside timing, tampering either
  label's selected member fails only that label with
  `SIGNATURE_MISMATCH`, editing only unselected members still
  verifies both labels, and a merchant store whose snapshot holds
  only the rotated kid fails only the merchant label exactly
  `KEY_RESOLUTION_FAILED` with the pinned reason while the
  gateway label still verifies. The README Benchmarks table is
  refreshed from this run's real output (103 rows, 2026-11-02,
  Node v24.22.1), with the new row at ~3,045 ops/sec
  (328.40 µs/op). No source change: the combination was
  unmeasured on the bench side, not unimplemented.

- Test coverage for `verifyAllLabels` mixed per-label key sources
  (backlog #795): `test/verifyAllLabelsJwksCandidateKeys.test.ts`
  adds 4 cases — a dual-signed request verifies with the merchant
  label resolved through an offline-restored `JwksKeyStore` and the
  gateway label verified against its own `candidateKeysByLabel`
  rotation list (old + new HMAC secrets, with `keyId`/`alg` echoed
  per label); the gateway still verifies with its old secret during
  the rotation window; after a merchant rotation refresh retires
  `merchant-key-1`, only the merchant label fails with
  `KEY_RESOLUTION_FAILED` while the gateway label still verifies
  (no silent fallback to the rotated key); and pairing a resolver
  with candidate keys on the same label throws the
  mutual-exclusion configuration error. No source change: the
  combination was untested, not unimplemented.

- Test coverage for `;sf` structured-field components x
  `JwksKeyStore` key discovery (backlog #794):
  `test/sfComponentJwks.test.ts` adds 5 cases — a dictionary
  component (`a=1, b=2;x=1`) covered with `;sf` verifies through
  an offline-restored `JwksKeyStore` (key resolved by `kid`, with
  `keyId`/`alg` echoed); re-spacing the dictionary wire value in
  either direction still verifies, because `;sf` signs the strict
  serialization, not the raw bytes; tampering a member value
  (`b=2` -> `b=3`) or a parameter (`x=1` -> `x=2`) fails with
  `SIGNATURE_MISMATCH`; after a rotation refresh retires the kid,
  the same signature fails with `KEY_RESOLUTION_FAILED`, never a
  silent fallback to the new key; and a snapshot past its TTL
  still resolves and verifies with zero fetches attempted
  (stale-but-serving). No source change: the combination was
  untested, not unimplemented.

- Test coverage for `verifyAllLabels` x trailers x
  `replayCacheByLabel` (backlog #793):
  `test/verifyAllLabelsTrailersReplayCache.test.ts` adds 5 cases —
  a dual-signed response verifies both labels through
  `fromNodeResponse`, each binding its own `;tr` trailer and
  recording its nonce in its own store (exactly 1 entry each);
  re-presenting the same response replays on both labels with
  `NONCE_REPLAY`; reusing only one label's nonce fails only that
  label; tampering one trailer fails only that label with
  `SIGNATURE_MISMATCH` while the other label still verifies, and
  the failed presentation is never recorded (a corrected
  re-presentation then passes the tampered label but replays the
  other); and tampering the other trailer is symmetric. No
  source change: the combination was untested, not
  unimplemented.

- Test coverage for `JwksKeyStore` fetch retries x `requireHttps`
  (backlog #785): `test/jwksFetchRetryHttps.test.ts` adds 3 cases
  — an `http:` endpoint with `requireHttps: true` and
  `fetchRetries: 3` is rejected at construction with the
  `requireHttps` error before any fetch is attempted (0 fetches,
  no backoff sleep: the rejection is terminal, never retried;
  this corrects the backlog's "fetch exactly 1" premise, since
  #554 ships `requireHttps` as a construction-time check, not a
  refresh-time one); an `https:` endpoint answering 500, 500,
  then 200 succeeds on the third fetch with `fetchRetries: 2`
  and two recorded backoff sleeps; and an `https:` endpoint
  answering persistent 500 exhausts its retries after exactly
  3 fetches and throws while the previously seeded snapshot,
  `lastRefreshedAt`, and refresh counters stay untouched. No
  source change: the combination was untested, not
  unimplemented.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  expected tags per label (backlog #784):
  `test/nodeHttpResponseVerifyAllLabelsExpectedTags.test.ts`
  adds 7 cases — a dual-signed response verifies both labels
  through `fromNodeResponse`, each pinned to its own
  `expectedTags` entry; one label's tag mismatch fails only
  that label with `TAG_MISMATCH`; a tagless label fails only
  itself with `TAG_MISMATCH` when the map pins it; tags
  swapped between labels fail both labels with
  `TAG_MISMATCH` (a cross-protocol transplant is rejected by
  the pins, not the signatures, since tag pinning is checked
  after crypto verification); adapter and direct paths agree
  on a mixed pass/fail pair; a label absent from the map
  stays unchecked through the adapter when no global
  `expectedTag` is set; and the global `expectedTag`
  fallback applies through the adapter to labels the map
  does not name. No source change: the combination was
  untested, not unimplemented.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  keyid pinning per label (backlog #783):
  `test/nodeHttpResponseVerifyAllLabelsKeyidPinning.test.ts` adds
  5 cases — a dual-signed response verifies both labels through
  `fromNodeResponse`, each pinned to its own `expectedKeyIds`
  entry; a label re-signed under a rotated kid fails only that
  label with `KEYID_MISMATCH` (the pin, not the signature,
  rejects it, since pinning is checked after crypto
  verification); a wrong pin on one label fails only that
  label; a label missing from the pin map stays unchecked on
  both the adapter and the direct path, even after its kid
  rotates; and the global `expectedKeyId` fallback applies
  through the adapter to labels the map does not name. No
  source change: the combination was untested, not
  unimplemented.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  `replayCacheByLabel` (backlog #782):
  `test/nodeHttpResponseVerifyAllLabelsReplayCache.test.ts` adds
  4 cases — a dual-signed response first verifies both labels
  through `fromNodeResponse` and records the shared nonce in each
  label's own store; re-presenting the same response replays on
  both labels with `NONCE_REPLAY`; reusing only the merchant
  nonce fails only that label while the gateway label with a
  fresh nonce still verifies; and a re-signed response over a
  new body is first-seen only with fresh nonces, since replay
  identity is the nonce, not the body. No source change: the
  combination was untested, not unimplemented.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  trailers x JwksKeyStore (backlog #781):
  `test/nodeHttpResponseVerifyAllLabelsTrailersJwks.test.ts` adds
  4 cases — a dual-signed response verifies both labels through
  `fromNodeResponse`, the merchant label covering `@status` +
  `x-checksum;tr` and resolved from its own offline-restored
  JwksKeyStore while the gateway label covers `@status` only
  from its own store; a tampered trailer fails only the merchant
  label with `SIGNATURE_MISMATCH`; a rotation that retires the
  merchant kid fails only that label with
  `KEY_RESOLUTION_FAILED`; and the same pair verifies through
  `rawTrailers`. No source change: the combination was untested,
  not unimplemented; it is the response-side mirror of the
  request-side four-way coverage.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  JwksKeyStore (backlog #780):
  `test/nodeHttpResponseVerifyAllLabelsJwks.test.ts` adds 4 cases —
  a dual-signed response verifies both labels through
  `fromNodeResponse`, each label resolved from its own
  offline-restored JwksKeyStore; a rotation that retires one kid
  fails only that label with `KEY_RESOLUTION_FAILED`; a label
  minted over a different body fails alone with
  `SIGNATURE_MISMATCH` (signing-history divergence); and a
  post-signing body swap fails both content-digest labels with
  `BODY_DIGEST_MISMATCH`, because the verifier's body check runs
  whenever a wire content-digest header is present — the
  per-label isolation form is the divergence case, not the swap.
  No source change: the combination was untested, not
  unimplemented; it is the response-side mirror of the #759
  request-side JWKS coverage.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` x
  trailers (backlog #777):
  `test/nodeHttpResponseVerifyAllLabelsTrailers.test.ts` adds 5 cases —
  a dual-signed response whose trailer label covers `@status` +
  `x-checksum;tr` and whose plain label covers `@status` only
  verifies both labels through `fromNodeResponse`, with a
  mixed-case trailer name lowercased by the adapter; a tampered
  trailer fails only the trailer label with `SIGNATURE_MISMATCH`;
  a missing trailer fails only the trailer label with
  `SIGNATURE_BASE_BUILD_FAILED`; the same pair verifies through
  `rawTrailers`; and each label is checked against its own key.
  No source change: the combination was untested, not
  unimplemented; it is the response-side mirror of the #757
  request-side trailers coverage.

- Test coverage for `verifyAllLabels` x `replayCacheByLabel` x
  sha-512 content-digest (backlog #775):
  `test/verifyAllLabelsReplayCacheDigest.test.ts` adds 4 cases — a
  dual-signed request whose two labels share one sha-512
  `Content-Digest` header verifies both labels, each label
  recording the shared nonce in its own `ReplayCache`; a body swap
  after signing fails both labels with `BODY_DIGEST_MISMATCH`
  (not `SIGNATURE_MISMATCH`) and records nothing in either cache;
  a nonce pre-seeded in only the merchant store replays only the
  merchant label while the gateway label still verifies; and after
  a digest failure the true message still verifies and records
  both nonces. No source change: the combination was untested, not
  unimplemented; it is the replay-cache counterpart of the #767
  digest coverage and the digest counterpart of the #643
  per-label replay coverage.

- Benchmark row for `fromNodeRequest` x `verifyAllLabels` x
  trailers (backlog #773): `bench/bench.ts` adds
  `benchmarkFromNodeRequestVerifyAllLabelsTrailers` — a real
  loopback dual-signed POST (trailer label covering `@method` +
  `x-checksum;tr`, plain label covering `@method` only) whose
  trailer travels as a genuine HTTP trailer (chunked request +
  `addTrailers`, mixed-case name, so the measured pass also pays
  the adapter's lowercasing and raw-trailer precedence); every
  measured pass re-adapts the captured live request and pins
  both labels ok with their pinned keyids, the trailer label's
  `x-checksum;tr` coverage, and the plain label not claiming
  trailer coverage. Asserted outside timing: a forged trailer
  fails only the trailer label with `SIGNATURE_MISMATCH` while
  the plain label still verifies, and a request received without
  its trailers fails only the trailer label with
  `SIGNATURE_BASE_BUILD_FAILED` while the plain label still
  verifies. The README Benchmarks table is refreshed from this
  run. No source change: the combination was benched, not
  unimplemented; it is the bench variant of the #757 test
  coverage and the combination of the dual-label request row
  and the single-label trailer row.

- Test coverage for `verifyAllLabels` x `fromNodeRequest` x
  trailers x `JwksKeyStore` (backlog #769):
  `test/nodeHttpRequestVerifyAllLabelsTrailersJwks.test.ts` adds 4
  cases — a dual-signed request received through `fromNodeRequest`
  verifies both labels, each key resolved from its own
  offline-restored `JwksKeyStore`, with the merchant label binding
  `@method` + `x-checksum;tr` and the gateway plain label covering
  `@method` only; a tampered trailer fails only the merchant label
  with `SIGNATURE_MISMATCH` while the gateway label still verifies;
  a refresh that retires the merchant kid fails only the trailer
  label with `KEY_RESOLUTION_FAILED` while the gateway label still
  verifies; and the mirror retirement of the gateway kid fails
  only the plain label while the merchant trailer label still
  verifies. No source change: the combination was untested, not
  unimplemented; it is the trailer counterpart of the #759 JWKS
  coverage and the JWKS counterpart of the #757 trailer coverage.

- Test coverage for `verifyAllLabels` x `JwksKeyStore` x
  sha-256-only content-digest (backlog #767):
  `test/verifyAllLabelsJwksSha256Digest.test.ts` adds 4 cases — a
  dual-signed request whose signatures each resolve from their own
  offline-restored `JwksKeyStore` verifies both labels over the
  shared sha-256-only `Content-Digest` header (sha-512 absent, so
  the sha-256 fallback path is exercised, not the sha-512 path
  pinned in #751); a body swap after signing fails both labels
  with `BODY_DIGEST_MISMATCH` (not `SIGNATURE_MISMATCH`); a
  refresh that retires the merchant kid fails that label with
  `KEY_RESOLUTION_FAILED` while the gateway sha-256 label still
  verifies; and the combined retired-kid plus body-swap case
  keeps both codes exactly as in the single-failure cases, so a
  neighbour's key failure does not change the other label's
  digest failure code. No source change: the combination was
  untested, not unimplemented; it is the sha-256 counterpart of
  the #751 sha-512 coverage and the JWKS counterpart of the #730
  sha-256 fallback coverage.

- Test coverage for `verifyAllLabels` x `JwksKeyStore` x
  `expiredToleranceSecByLabel` (backlog #762):
  `test/verifyAllLabelsJwksExpiredToleranceByLabel.test.ts` adds 4
  cases — a dual-signed request whose signatures both expired 60s
  ago, each label's key resolved from its own offline-restored
  `JwksKeyStore`, verifies merchant `EXPIRED` at a 0s tolerance
  while gateway passes at 120s; expiry exactly at a 60s per-label
  tolerance passes through the JWKS resolvers; a JWKS refresh that
  re-publishes both signing kids leaves both tolerance verdicts
  unchanged (refresh does not reset the tolerance clock); and a
  refresh that retires the merchant kid fails that label with
  `KEY_RESOLUTION_FAILED` even at a generous 120s tolerance while
  the gateway label still passes. No source change: the combination
  was untested, not unimplemented; it is the tolerance counterpart
  of the `verifyAllLabelsJwksKeyResolvers` coverage and the JWKS
  counterpart of the `expiredToleranceSecByLabel` coverage.

- Test coverage for `verifyAllLabels` x `fromNodeRequest` x
  `JwksKeyStore` (backlog #759):
  `test/nodeHttpRequestVerifyAllLabelsJwks.test.ts` adds 4 cases —
  a dual-signed request adapted with `fromNodeRequest`, one label
  covering `@method` and the business header `x-event-type` and the
  other covering only `@method`, verifies both labels with each
  label's key resolved from its own offline-restored `JwksKeyStore`
  (snapshot restore, zero real network, fetch stub throws if ever
  called); a rotated merchant store retires the old kid so only the
  merchant label fails with `KEY_RESOLUTION_FAILED` while the
  gateway label still verifies; a mismatched gateway store key fails
  only the gateway label with `SIGNATURE_MISMATCH`; and a tampered
  `x-event-type` wire value fails only the covering merchant label
  while the gateway label still verifies. No source change: the
  combination was untested, not unimplemented; it is the JWKS
  counterpart of the #747 dual-signed request coverage and the
  adapter counterpart of the `verifyAllLabelsJwksKeyResolvers`
  coverage.

- Test coverage for `verifyAllLabels` x `fromNodeRequest` x
  trailers (backlog #757):
  `test/nodeHttpRequestVerifyAllLabelsTrailers.test.ts` adds 5 cases —
  a dual-signed request adapted with `fromNodeRequest`, one label
  covering `@method` and `x-checksum;tr` and the other covering
  only `@method`, verifies both labels with their own keyids and
  covered components; a tampered trailer fails only the trailer
  label with `SIGNATURE_MISMATCH` while the plain label still
  verifies; a missing trailer fails only the trailer label with
  `SIGNATURE_BASE_BUILD_FAILED` while the plain label still
  verifies; the same dual verifies through the `rawTrailers` path;
  and a rotated trailer key fails only the trailer label while the
  plain label still verifies. No source change: the combination was
  untested, not unimplemented; it is the trailer counterpart of
  the #747 dual-signed request coverage and the multi-label
  counterpart of the single-label `nodeHttpTrailers` coverage.

- Benchmark for `verifyAllLabels` x `JwksKeyStore` x
  `replayCacheByLabel` (backlog #753): `bench/bench.ts` adds
  `benchmarkVerifyAllJwksReplayCacheByLabel` — a dual-label fixture
  signed outside timing with `created` pinned, the same bare nonce
  in both labels, and each party's public key in its own
  offline-restored `JwksKeyStore`; each measured op verifies the
  dual twice against fresh per-label `ReplayCache` instances
  (first call both labels ok with their pinned keyids and each
  cache holding exactly one entry, second call both labels
  `NONCE_REPLAY` with neither cache growing), with a
  merchant-replay-only split, a rotated-merchant-key
  `KEY_RESOLUTION_FAILED` half, and cross-kid isolation pinned
  outside timing. The new row measures ~1,456 ops/sec
  (686.60 µs/op) on this run (Node v24.22.1); the README
  Benchmarks table is refreshed from the same run (99 → 100
  rows) and the intro list gains per-label JWKS key-resolution
  plus replay-cache verification. No source change: the
  combination was unmeasured, not unimplemented; it is the
  bench variant of the #742 test combination and the three-way
  counterpart of the `JwksKeyStore` and `replayCacheByLabel`
  rows.

- Benchmark for `fromNodeRequest` x `verifyAllLabels` dual-signed
  requests (backlog #752): `bench/bench.ts` adds
  `benchmarkFromNodeRequestVerifyAllLabels` — a real loopback server
  receives one dual-signed POST (merchant first, gateway appended),
  buffers the body, and answers 200; each measured op re-adapts the
  captured live request with `fromNodeRequest` and verifies both
  labels with `verifyAllLabels`, self-checked every pass against
  both labels ok with their pinned keyids, with a tampered gateway
  signature pinned outside timing to fail only that label with
  `SIGNATURE_MISMATCH` while merchant still verifies. The new row
  measures ~3,038 ops/sec (329.12 µs/op) on this run (Node v24.22.1);
  the README Benchmarks table is refreshed from the same run
  (98 → 99 rows) and the intro list gains dual-label request
  verification. No source change: the combination was unmeasured,
  not unimplemented; it is the bench variant of the #747 test
  coverage and the request-side mirror of the #743 dual-signed
  response row.

- Test coverage for `verifyAllLabels` x content-digest x
  `JwksKeyStore` per-label resolvers (backlog #751):
  `test/verifyAllLabelsContentDigestJwks.test.ts` adds 6 cases —
  dual labels each resolve through their own offline-restored
  `JwksKeyStore` and both cover `content-digest`; a body swapped
  after signing fails both labels as `BODY_DIGEST_MISMATCH` (not a
  key failure); a gateway label minted over a different body's
  digest fails alone with `SIGNATURE_MISMATCH` while merchant
  still verifies; a merchant key rotated out of its store fails
  alone with `KEY_RESOLUTION_FAILED` while the gateway digest
  label still verifies; a stale gateway snapshot still resolves
  with no fetch attempted and its digest label still verifies;
  and a sha-256-only dual via per-label stores verifies via the
  sha-256 fallback. No source change: the combination was
  untested, not unimplemented; it is the three-way counterpart
  of the #730 content-digest and #733/#742 JWKS coverage.

- Test coverage for `verifyAllLabels` x `fromNodeRequest`
  dual-signed requests (backlog #747):
  `test/nodeHttpRequestVerifyAllLabels.test.ts` adds 6 cases — a
  dual-signed request verifies both labels through the adapter with
  each label's pinned keyid echoed, a real loopback server receives a
  dual-signed POST and verifies both labels after buffering the body,
  a tampered gateway signature fails only the gateway label with
  `SIGNATURE_MISMATCH` while merchant still verifies, a gateway label
  minted over a different body fails alone the same way (the wire
  carries a single `content-digest` header, so per-label divergence
  is built in signing history, as in the #730 case), each label is
  checked against its own key (a stranger gateway key fails only the
  gateway label), and the single-label `verifyRequest` control path
  through the adapter is unchanged. No source change: the combination
  was untested, not unimplemented; the request side is the symmetric
  counterpart of the #737 `fromNodeResponse` coverage.

- Benchmark row for `fromNodeResponse` x `verifyAllLabels`
  dual-signed responses (backlog #743): `bench/bench.ts` gains
  `benchmarkFromNodeResponseVerifyAllLabels`, measuring the
  client-side `fromNodeResponse` + `verifyAllLabels` path over one
  real loopback-signed 200 settlement response (merchant first,
  gateway appended, each label covering `@status` only, exactly as
  the #737 test signs it). One measured op adapts the captured
  live response and verifies both labels, re-pinning both results
  ok, in wire order, with each label's pinned keyid echoed.
  Asserted outside timing: the captured dual-signed response
  verifies both labels, and a divergent pair (merchant signed over
  status 200, gateway over status 500, wire headers merged as the
  #737 test merges them) fails only the gateway label with
  `SIGNATURE_MISMATCH` while merchant still verifies. The README
  Benchmarks table is refreshed from this run's real output (98
  rows, 2026-10-30, Node v24.22.1), with the new row at ~1,366
  ops/sec (732.06 µs/op); the P-384 / P-521 notes under the table
  are re-based on this run's numbers too. No source change: the
  combination was unmeasured on the bench side, not unimplemented.

- Test coverage for `verifyAllLabels` x `replayCacheByLabel` x
  `JwksKeyStore` per-label resolvers (backlog #742):
  `test/verifyAllLabelsReplayCacheJwks.test.ts` adds 6 cases — a
  dual-signed request resolves each label through its own
  offline-restored `JwksKeyStore` and records the same bare nonce
  once per label (cross-kid isolation re-pinned); re-verifying the
  same request replays in each label's own store; a nonce pre-seeded
  in only the merchant store replays for merchant but stays fresh
  for gateway; a merchant kid rotated out by a stubbed refresh
  fails only that label with `KEY_RESOLUTION_FAILED` while gateway
  still verifies, records nothing for merchant, and on a second
  attempt gateway replays while merchant still fails resolution; a
  stale gateway snapshot still resolves, records, and replays; and
  per-label replay TTLs (60s merchant, 3600s gateway) expire
  independently under per-label resolvers. Pure test addition: no
  source change, since the combination was untested, not
  unimplemented. Zero real network throughout.

- Test coverage for `verifyAllLabels` x `fromNodeResponse` dual-signed
  responses (backlog #737): `test/nodeHttpResponseVerifyAllLabels.test.ts`
  adds 6 cases — a dual-signed response verifies both labels through
  the adapter (each keyid echoed, `@status` in both covered lists), a
  real loopback server dual-signs a response verified end-to-end by
  an `http.get` client, a label minted over a different status fails
  alone with `SIGNATURE_MISMATCH` while the other label still
  verifies, a wrong per-label key fails only that label, a bound
  request is attached and a `;req` component binds for both labels,
  and a status-less dual-signed response still fails fast in the
  adapter. Pure test addition: no source change, since the
  combination was untested, not unimplemented.


- Benchmark row for `verifyAllLabels` x content-digest
  (backlog #736): `bench/bench.ts` gains
  `benchmarkVerifyAllContentDigest`, measuring `verifyAllLabels`
  with both labels covering `content-digest` over the one wire
  sha-512 digest header the first signature minted (the appended
  second signature keeps that header, it mints no second one).
  One measured op verifies the dual-label fixture and re-pins
  both results ok, each keyid echoed, and `content-digest` in
  both labels' covered lists. The two tamper dimensions are
  asserted outside timing, exactly as the #730 tests pin them:
  a body swap fails both labels exactly `BODY_DIGEST_MISMATCH`
  with the pinned reason, and a digest-header swap to another
  body's digest fails both labels exactly `SIGNATURE_MISMATCH`
  with the pinned reason. The README Benchmarks table is
  refreshed from this run's real output (97 rows, 2026-10-30,
  Node v24.22.1), with the new row at ~2,565 ops/sec
  (389.90 µs/op). No source change: the combination was
  unmeasured on the bench side, not unimplemented.

- Benchmark row for `verifyAllLabels` x `JwksKeyStore` per-label
  resolvers (backlog #733): `bench/bench.ts` gains
  `benchmarkVerifyAllJwksKeyStores`, measuring `verifyAllLabels`
  with each label resolving through its own offline-restored
  `JwksKeyStore` (snapshot restore, fetch throws if called, zero
  network). One measured op verifies three duals: the fresh dual
  (both labels ok, each keyid echoed); the rotated dual, verified
  against a merchant store whose snapshot holds only the rotated
  kid (merchant exactly `KEY_RESOLUTION_FAILED` with the pinned
  reason while the gateway still verifies); and the stale dual,
  verified against a gateway store past its 300s TTL (clock pinned
  1000s past the fetch time, `isStale()` re-pinned true on every
  pass) that still resolves. The cross-kid isolation half
  (neither store resolves the other party's kid) is asserted
  outside timing. The README Benchmarks table is refreshed from
  this run's real output (96 rows, 2026-10-30, Node v24.22.1),
  with the new row at ~1,185 ops/sec (843.94 µs/op). No source
  change: the combination was unmeasured on the bench side, not
  unimplemented.

- `verifyAllLabels` x content-digest covered-component coverage
  (backlog #730): `test/verifyAllLabelsContentDigest.test.ts` adds 8
  cases combining the two previously separate surfaces — a dual
  sha-512 dual-label request verifying with `content-digest` in
  both labels' covered lists; a post-signing body swap failing
  both labels exactly `BODY_DIGEST_MISMATCH` (not masked as a
  signature failure); a digest-header swap failing both labels
  exactly `SIGNATURE_MISMATCH` (crypto is checked before the body
  binding); a label minted over a different body's digest failing
  alone with `SIGNATURE_MISMATCH` while the other label verifies
  (the wire header is shared, so per-label divergence is built in
  signing history); a sha-256-only dual verifying via the
  sha-256 fallback; a both-algorithms header whose sha-512 entry
  is of another body failing both labels `BODY_DIGEST_MISMATCH`
  even though its sha-256 entry matches (sha-512 wins); an
  `addSignature`-appended second label covering the same wire
  digest and verifying; and a label not covering
  `content-digest` still failing `BODY_DIGEST_MISMATCH` on a body
  swap, since the verifier checks the body against the wire
  digest whenever the header is present. Pure test addition: no
  source change, since the combination was untested, not
  unimplemented.

- `verifyAllLabels` x per-label age window + per-label replay cache
  coverage (backlog #727):
  `test/replayCacheByLabelMaxAgeByLabel.test.ts` adds 6 cases
  combining the two previously separate surfaces — fresh dual-label
  verification recording into each label's own store; re-verification
  replaying in both labels; a seen nonce past the merchant 60s
  window reporting `SIGNATURE_TOO_OLD` (age checked before the
  replay cache) while the gateway label reports `NONCE_REPLAY`,
  with the age failure leaving the merchant store's counters
  untouched; the window boundary being inclusive (`>` not `>=`)
  with one second past it aging out only the tight label; a replay
  in one label not failing the other; and an age failure recording
  nothing, so the same nonce verifies fresh later. Pure test
  addition: no source change, since the combination was untested,
  not unimplemented.

- `verifyAllLabels` x `JwksKeyStore` per-label resolver coverage
  (backlog #724): `test/verifyAllLabelsJwksKeyResolvers.test.ts` adds
  4 cases combining the two previously separate surfaces — each label
  resolving through its own offline-restored `JwksKeyStore` (passed
  by reference as `store.resolve`, with keyid echo and cross-kid
  isolation); a rotation refresh retiring the merchant kid so that
  label fails exactly `KEY_RESOLUTION_FAILED` while the gateway
  label still verifies; a stale-but-serving snapshot past its TTL
  that still resolves with no fetch attempted; and a third label
  absent from the `keyResolvers` map falling back to the global
  `keyResolver`. Pure test addition: no source change, since the
  combination was untested, not unimplemented.

- Benchmark row for per-label candidate keys x per-label freshness
  window verification (backlog #721): `bench/bench.ts` gains
  `benchmarkVerifyAllCandidateKeysMaxAgeByLabel`, measuring
  `verifyAllLabels` with the merchant label mapped to both
  `candidateKeysByLabel` ([old, new] rotation) and
  `maxSignatureAgeSecByLabel` (300s tight window) and the gateway
  label mapped to a single-element candidate list (the static-key
  equivalent, since `candidateKeysByLabel` is mutually exclusive
  with `keys` — the correction backlog #712 recorded) and a 7200s
  wide window. One measured op verifies five duals: the in-window
  new-key dual (both labels ok, each keyid echoed, the merchant
  found at the second candidate); the in-window old-key dual
  (both labels ok, proving list membership survives the tight
  window); the merchant-expired dual (merchant exactly
  `SIGNATURE_TOO_OLD` with the pinned 3600s/300 reason while the
  gateway still verifies); the both-expired dual (both labels
  exactly `SIGNATURE_TOO_OLD` with their pinned 8000s reasons);
  and the in-window retired-key dual (merchant exactly
  `SIGNATURE_MISMATCH` while the gateway still verifies). The
  swapped-window isolation half, the key-source-but-no-window
  acceptance half, and the illegal shapes (empty candidate list,
  negative window, `candidateKeysByLabel` + `keys` mutual
  exclusion) are asserted outside timing. The README Benchmarks
  table is refreshed from this run's real output (95 rows,
  2026-10-30, Node v24.22.1), with the new row at ~436.0 ops/sec
  (2293.77 µs/op). No source change: the combination was
  unmeasured on the bench side, not unimplemented.
- Combination test for per-label replay cache x per-label tag
  requirement (backlog #718): `test/replayCacheByLabelRequireTag.test.ts`
  adds 6 cases for `verifyAllLabels` with the merchant label on its
  own replay store (`replayCacheByLabel`) and requiring a tag
  (`requireTagByLabel`) and the gateway label with neither — a tagged
  first-seen nonce passes both labels and echoes tag + nonce, the
  same nonce replayed with its tag intact fails exactly
  `NONCE_REPLAY` while the gateway still verifies, a tag-less
  merchant fails exactly `MISSING_TAG` (and an empty-string tag
  counts as missing) without entering the cache so the same nonce
  passes once tagged, the gateway reusing the merchant's nonce —
  before or after the merchant records it — is never affected by
  the merchant store, and a forged merchant signature (wrong key,
  with or without a tag) reports `SIGNATURE_MISMATCH` (crypto
  precedes the tag check, which precedes the cache). No source
  change: the combination was untested, not unimplemented.

- Combination test for per-label key resolvers x per-label nonce
  requirement (backlog #715): `test/keyResolversRequireNonceByLabel.test.ts`
  adds 10 cases for `verifyAllLabels` with the merchant label resolving
  through a rotating keystore (`keyResolvers`, old + current keyids)
  and requiring a nonce (`requireNonceByLabel`) and the gateway label
  verifying against a static key (`keys`) with no nonce requirement —
  the nonce-carrying merchant through either rotation key passes, a
  nonce-less merchant fails exactly `MISSING_NONCE` while the gateway
  still verifies, a rotated-out merchant keyid fails exactly
  `KEY_RESOLUTION_FAILED` while the gateway still verifies, a
  merchant that is both unresolvable and nonce-less reports
  `KEY_RESOLUTION_FAILED` (resolution precedes the nonce check), a
  forged nonce-less merchant reports `SIGNATURE_MISMATCH` (crypto
  precedes the nonce check), and a nonce on the unrequired gateway is
  tolerated and echoed. Illegal combination shapes (non-function
  resolver entry, non-boolean nonce-map entry, the same label in both
  `keys` and `keyResolvers`) throw configuration errors naming the
  label. No source change: the combination was untested, not
  unimplemented.

- Combination test for per-label candidate keys x per-label freshness
  window (backlog #712): `test/candidateKeysByLabelMaxAgeByLabel.test.ts`
  adds 7 cases for `verifyAllLabels` with the merchant label on a
  single fixed key and a tight 300s window and the gateway label on a
  rotating [old, new] HMAC secret list and a wide 7200s window — the
  new key in-window and the old key inside the rotation window both
  pass; a 1h-old signature fails the merchant label with exactly
  `SIGNATURE_TOO_OLD` while the gateway still passes; out-of-window
  signatures are rejected for both labels whichever rotation key
  signed them; a retired key is rejected with `SIGNATURE_MISMATCH`
  even inside the window; and swapped windows prove neither label's
  window leaks into the other. Illegal combination shapes (empty
  candidate list, negative window, candidate keys mixed with `keys`)
  throw configuration errors naming the label. No source change: the
  combination was untested, not unimplemented.

- Benchmark row for per-label keyid pinning x nonce requirement
  verification (backlog #709): `bench/bench.ts` gains
  `benchmarkVerifyAllExpectedKeyIdsRequireNonceByLabel`, measuring
  `verifyAllLabels` with the merchant label mapped to both
  `expectedKeyIds` and `requireNonceByLabel` and the gateway label
  mapped only to `expectedKeyIds` — the combination test (#702)
  pins, so neither map joins the `keys`/`keyResolver`/`candidateKeys`
  mutual-exclusion rules and no configuration error fires. One
  measured op verifies three duals: the pinned nonce-carrying dual
  (both labels ok, merchant nonce returned, each keyid echoed at its
  pinned value); the pinned nonce-less-merchant dual (merchant exactly
  `MISSING_NONCE` with the pinned reason while the gateway still
  verifies); and the wrong-keyid nonce-carrying dual (merchant exactly
  `KEYID_MISMATCH` with the pinned reason while the gateway still
  verifies). The unmapped-label fallback to the global `expectedKeyId`
  with no nonce requirement, the wrong-global-pin fallback half, the
  same nonce-less dual's acceptance with no option passed, and an
  explicit `merchant: false` map entry are asserted outside timing.
  The README Benchmarks table is refreshed from this run's real
  output (94 rows, 2026-10-29, Node v24.22.1), with the new row at
  ~198.3 ops/sec (5042.56 µs/op). No source change: the combination
  was untested on the bench side, not unimplemented.
- Combination test for per-label key resolvers x tag requirement
  (backlog #705): `test/keyResolversRequireTagByLabel.test.ts`
  adds 8 cases for `verifyAllLabels` with each label resolving
  through its own keystore (`keyResolvers`) and carrying its own
  application tag (`requireTagByLabel` + `expectedTags`) — both
  labels pass with tags and keyids echoed, a merchant replaying
  the gateway tag (and symmetrically a gateway replaying the
  merchant tag) fails exactly `TAG_MISMATCH` while the other label
  still verifies, a tag-less merchant under presence-only options
  fails exactly `MISSING_TAG`, a key rotated out of either
  keystore fails exactly `KEY_RESOLUTION_FAILED` while the other
  label still verifies, a label absent from both maps falls back
  to the global `keyResolver` with no tag requirement, and a
  label that is both unresolvable and wrongly tagged reports the
  resolution failure (resolution precedes the tag checks). Source
  unchanged: the combination was previously untested, not
  unimplemented. Test count moves 1104 → 1112.
- Combination test for per-label keyid pinning x nonce requirement
  (backlog #702): `test/expectedKeyIdsRequireNonceByLabel.test.ts`
  adds 8 cases for `verifyAllLabels` with the merchant label pinned
  (`expectedKeyIds`) and nonce-required (`requireNonceByLabel`) and
  the gateway label pinned but nonce-free — both labels pass, a
  nonce-less merchant fails exactly `MISSING_NONCE`, a wrong-keyid
  merchant fails exactly `KEYID_MISMATCH`, a merchant violating
  both reports the keyid code (keyid check precedes the nonce
  check), simultaneous per-label failures keep their own codes, an
  empty-string nonce counts as missing, and labels absent from both
  maps fall back to the global `expectedKeyId` with no nonce
  requirement. Source unchanged: the combination was previously
  untested, not unimplemented. Test count moves 1096 → 1104.
- Benchmark row for per-label candidate-keys x tag-presence
  verification (backlog #692): `bench/bench.ts` gains
  `benchmarkVerifyAllCandidateKeysRequireTagByLabel`, measuring
  `verifyAllLabels` with the merchant label mapped to a
  `candidateKeysByLabel` rotation list [old, new] and the gateway
  label resolving through the disjoint `keys` map, under a global
  `requireTag: true` with an explicit per-label opt-out
  (`requireTagByLabel: { gateway: false }`) for the tag-less legacy
  gateway — the disjoint key sources the combination test (#618)
  pins, so no mutual-exclusion error fires. One measured op
  verifies four duals: the new-key tagged dual (both labels ok,
  merchant tag returned, merchant key found at the second
  candidate); the old-key tagged dual (both labels ok inside the
  rotation window); the new-key tag-less-merchant dual (merchant
  exactly `MISSING_TAG` with the pinned reason while the gateway
  still verifies); and the retired-key tagged dual (merchant
  exactly `SIGNATURE_MISMATCH` while the gateway still verifies,
  proving a tag cannot rescue a key the rotation list no longer
  contains). The opt-in default, an explicit `merchant: false`
  map entry, and the global flag rejecting the tag-less gateway
  when the opt-out is dropped are asserted outside timing. The
  README Benchmarks table is refreshed from this run's real
  output (93 rows, 2026-10-29), with the new row at ~101.2
  ops/sec (9879.20 µs/op). No source change: the combination was
  untested on the bench side, not unimplemented.

- Benchmark row for per-label nonce-presence x freshness-window
  verification (backlog #691): `bench/bench.ts` gains
  `benchmarkVerifyAllRequireNonceMaxAgeByLabel`, measuring
  `verifyAllLabels` with the merchant label mapped to both
  `requireNonceByLabel` and `maxSignatureAgeSecByLabel` (60s window)
  and the gateway label mapped to neither (3600s window). One
  measured op verifies four duals: the fresh nonce-carrying dual
  (both labels ok, merchant nonce returned); the fresh
  nonce-less-merchant dual (merchant exactly `MISSING_NONCE` with
  the pinned reason while the gateway still verifies); the old
  nonce-carrying dual (merchant exactly `SIGNATURE_TOO_OLD` with
  the pinned reason while the gateway still verifies); and the old
  nonce-less-merchant dual (merchant exactly `SIGNATURE_TOO_OLD`,
  pinning that the age check precedes the nonce-presence check,
  the precedence backlog #642 tested). The opt-in default and an
  explicit `merchant: false` map entry are asserted outside timing.
  The README Benchmarks table is refreshed from this run's real
  output (92 rows, 2026-10-29), with the new row at ~761.1
  ops/sec (1313.94 µs/op). No source change: the combination was
  untested on the bench side, not unimplemented.

- Orthogonal-combination tests for per-label algorithm fallback x
  candidate keys (backlog #690):
  `test/algFallbackByLabelCandidateKeysByLabel.test.ts` pins
  `verifyAllLabels` with the merchant label mapped to both an
  `algFallbackByLabel` strategy and a `candidateKeysByLabel` rotation
  list, and the gateway label mapped to neither — a pairing the
  existing per-label tests never made. The fallback is inferred per
  candidate inside the rotation walk: a no-`alg` P-256 merchant wire
  passes on the second candidate (after the ed25519 candidate
  mismatches) and reports `ecdsa-p256-sha256`, and passes on the
  first candidate when the list order is reversed; a retired P-256
  wire with both dimensions exhausted reports `SIGNATURE_MISMATCH`
  while the gateway passes; the same new-key wire under a strict
  merchant never infers and fails against every candidate; an infer
  walk advances past a mismatching secret candidate to the real
  ed25519 key, while the strict walk stops at the secret candidate's
  `VERIFICATION_ERROR` and never tries the real key, pinning that
  only `SIGNATURE_MISMATCH` advances the walk. No source change:
  the combination was untested, not unimplemented. The README test
  count moves 1090 → 1096.

- Orthogonal-combination tests for per-label candidate keys x required
  nonce (backlog #689):
  `test/candidateKeysByLabelRequireNonceByLabel.test.ts` pins
  `verifyAllLabels` with the merchant label mapped to both a rotating
  candidate-key list and a nonce requirement, and the gateway label
  mapped to neither — a pairing the existing per-label tests never
  made. A rotated merchant key carrying a nonce verifies while the
  nonce-less static gateway passes; a nonce-less merchant signature
  from a valid rotated key reports `MISSING_NONCE` while the gateway
  passes; the old rotation key with a nonce still verifies; a retired
  key carrying a nonce reports `SIGNATURE_MISMATCH`, so the nonce
  dimension cannot mask a key failure; and a forged nonce-less
  merchant signature from a retired key reports `SIGNATURE_MISMATCH`
  rather than `MISSING_NONCE`, pinning that the cryptographic check
  runs before the nonce presence check. Global true plus a mapped
  `false` gateway leaves only the merchant checked. No source change:
  the combination was untested, not unimplemented. The README test
  count moves 1084 → 1090.

- Per-label candidate-keys plus key-id-pinning benchmark (backlog #688):
  `bench/bench.ts` gains `benchmarkVerifyAllCandidateKeysExpectedKeyIds`,
  measuring `verifyAllLabels` with `candidateKeysByLabel` (merchant:
  [old, new]) combined with `expectedKeyIds` (merchant: new-kid,
  gateway: gateway-kid) and the gateway resolving through `keys` — the
  disjoint per-label key sources the combination test (#627) pins. One
  measured op verifies four dual-label fixtures: the new-key dual
  (both labels ok, keyids echoing their pins, merchant found at the
  second candidate), the old-key dual re-pinned to the old key's keyid
  (both labels ok), the wrong-kid dual (merchant `KEYID_MISMATCH`
  with the pinned reason, gateway ok), and the retired-key dual
  re-pinned to the retired key's keyid (merchant `SIGNATURE_MISMATCH`,
  gateway ok). No-pinning acceptance, the global `expectedKeyId`
  fallback (and its wrong-global failure mode), and the same-label
  `candidateKeysByLabel` + `keys` mutual-exclusion error are pinned
  outside timing. The README Benchmarks table is refreshed from this
  run (new row: ~446.0 ops/sec, 2241.96 µs/op, Node v24.22.1 / AMD
  EPYC 9D25 shared host). No test count change: the bench adds no
  tests.

- Per-label dual-required freshness-existence benchmark (backlog #678):
  `bench/bench.ts` gains `benchmarkVerifyAllRequireCreatedExpiresByLabel`,
  measuring `verifyAllLabels` with `requireCreatedByLabel` /
  `requireExpiresByLabel` both mapped `true` on the merchant label and the
  gateway label mapped on neither (globals unset) — one measured op
  verifies four dual-label fixtures: the fully dated dual, the
  no-created-merchant dual (`MISSING_CREATED`), the no-expires-merchant
  dual (`MISSING_EXPIRES`), and the undated-gateway dual (both labels
  ok). A both-missing merchant dual reporting `MISSING_CREATED` first,
  no-option acceptance of all undated duals, and explicit `false` map
  entries letting them through are pinned outside timing. The README
  Benchmarks table is refreshed from this run (new row: ~793.7 ops/sec,
  1259.86 µs/op, Node v24.22.1 / AMD EPYC 9D25 shared host). No test
  count change: the bench adds no tests.

- Orthogonal-combination tests for per-label required created x
  maximum signature age (backlog #677):
  `test/requireCreatedMaxAgeByLabel.test.ts` pins `verifyAllLabels`
  with the merchant label mapped to both time checks
  (`requireCreatedByLabel` plus a narrow
  `maxSignatureAgeSecByLabel` window) and the gateway label mapped
  to neither — a pairing the existing per-label freshness tests
  never made. A merchant signature missing `created` reports
  `MISSING_CREATED` while a gateway signature missing the same
  field passes; a 1-hour-old merchant signature against a 300s
  window reports `SIGNATURE_TOO_OLD` while the same-age gateway
  signature passes; an undated merchant signature under both maps
  reports `MISSING_CREATED` first, never `SIGNATURE_TOO_OLD`
  (the age check bypasses undated signatures and the presence
  check runs first, so the two dimensions cannot be violated at
  once); a fresh merchant and an undated gateway both pass; a
  forged undated merchant signature still reports
  `SIGNATURE_MISMATCH`, pinning that the cryptographic check runs
  before the presence checks; global true plus mapped false on
  the gateway leaves only the merchant checked; and the 300s
  window boundary is inclusive under the combination (exactly
  300s old passes, 301s old fails). No source change: the
  combination was untested, not unimplemented. The README test
  count moves 1077 → 1084.

- Orthogonal-combination tests for per-label required created x
  required expires (backlog #675):
  `test/requireCreatedExpiresByLabel.test.ts` pins `verifyAllLabels`
  with the merchant label mapped to both requirements and the
  gateway label mapped to neither — a pairing the existing
  per-label freshness tests never made (they pair one requirement
  per label). A merchant signature missing only `created` reports
  `MISSING_CREATED` while a gateway signature missing the same
  field passes; missing only `expires` is the mirror image with
  `MISSING_EXPIRES`; missing both reports `MISSING_CREATED` first
  (the global pair's check order); a fully dated merchant and a
  fully undated gateway both pass; a forged merchant signature
  missing both still reports `SIGNATURE_MISMATCH`, pinning that
  the cryptographic check runs before the presence checks; and
  global true plus mapped false on the gateway on both axes
  leaves only the merchant checked. No source change: the
  combination was untested, not unimplemented. The README test
  count moves 1071 → 1077.

- Benchmark `;tr` trailer verification row (backlog #673):
  `bench/bench.ts` adds `benchmarkVerifyNodeRequestTrailer`, the
  request-side mirror of the `fromNodeResponse` adapt+verify row —
  one measured op adapts a Node-shaped incoming double carrying
  a mixed-case `x-checksum` trailer and verifies a signature
  covering `x-checksum;tr` alongside `@method`/`@authority`/`@path`
  (200 warmup + 3000 timed iterations, the per-label bench caliber),
  asserting the adapted trailer value and a passing verification
  on every pass; self-checks outside timing pin a forged trailer
  (`SIGNATURE_MISMATCH`), a dropped trailer failing closed
  (`SIGNATURE_BASE_BUILD_FAILED`), and raw trailers beating a stale
  parsed-trailers object. The row measured ~6,436 ops/sec
  (~155.37 µs/op) in this run, and the README Benchmarks table is
  refreshed wholesale from that same run (88 rows → 89 rows, the
  new row included) with a prose note for the new row.

- CLI demo `;bs` byte-sequence segment (backlog #670): `src/demo.ts`
  closes with a section signing `x-charge-ref: "ch_42, settled "`
  while covering `x-charge-ref;bs` — the original request verifies,
  the rebuilt signature base contains the pinned byte-sequence line
  `"x-charge-ref";bs: :Y2hfNDIsIHNldHRsZWQg:`, a one-byte change
  fails with `SIGNATURE_MISMATCH`, and stripping the trailing space
  (which plain normalization would erase) also fails with
  `SIGNATURE_MISMATCH`; the segment states honestly that `;bs`
  changes only the serialization, not where the value comes from.
  The README test count moves 1069 → 1071.

- CLI demo `@query-param` segment (backlog #667): `src/demo.ts`
  closes with a section signing `?a=1&b=2` while covering only
  `@query-param;name="a"` — the original request verifies, changing
  only the unbound `b` still verifies, and changing the bound `a`
  fails with `SIGNATURE_MISMATCH`; the segment states the exact-match,
  no-normalization limitation honestly. The README test count moves
  1067 → 1069.

- Orthogonal-combination tests for per-label expiry tolerance x
  maximum signature age (backlog #664):
  `test/expiredMaxAgeByLabel.test.ts` pins `verifyAllLabels` with
  the merchant label mapped to a 0s expiry tolerance and a 60s
  maximum age and the gateway label mapped to a 120s tolerance and
  a 3600s window: a signature expired 60s ago reports `EXPIRED`
  for the merchant and passes for the gateway — even though the
  merchant also violates its 60s age window, pinning that the
  expiry check runs before the maximum-age check; a 300s-old but
  unexpired signature reports `SIGNATURE_TOO_OLD` for the merchant
  only; fresh signatures pass both labels; a gateway-only expiry
  failure does not mask a passing merchant; expiry exactly at the
  gateway tolerance and age exactly at the merchant window both
  still pass (strict-greater comparisons). The README test count
  moves 1061 → 1067.

- Orthogonal-combination tests for per-label clock skew x required
  components (backlog #663): `test/clockSkewRequiredComponentsByLabel.test.ts`
  pins `verifyAllLabels` with the merchant label mapped to a 5s clock
  tolerance and an `@path` coverage requirement and the gateway label
  mapped to a 300s tolerance and a `content-digest` requirement, both
  signatures 120s in the future: a future-created merchant signature
  missing `@path` reports `MISSING_REQUIRED_COMPONENT` (the policy
  gate runs before the clock window), the same signature with
  components complete reports `CREATED_IN_FUTURE`, each label reports
  its own dimension with no cross-label masking, a missing component
  beats a bad signature (gate before cryptography), and a bad
  signature beats the clock code (clock window after cryptography).
  The README test count moves 1056 → 1061.

- Orthogonal-combination tests for per-label replay cache x nonce
  requirement (backlog #662): `test/replayCacheByLabelRequireNonceByLabel.test.ts`
  requirement (backlog #662): `test/replayCacheByLabelRequireNonceByLabel.test.ts`
  pins `verifyAllLabels` with the merchant label mapped to its own
  `ReplayCache` and to `requireNonceByLabel: true` while the gateway
  label is mapped to neither: the same nonce passes both labels on
  first presentation and then replays only for the merchant; the
  gateway's nonce reuse never pollutes the merchant store; a
  nonce-less (or empty-string) merchant signature reports
  `MISSING_NONCE` — never `NONCE_REPLAY`, since there is no nonce to
  look up — and pollutes nothing, so a later well-formed nonce still
  passes; a forged merchant signature reports `SIGNATURE_MISMATCH`
  ahead of both checks and records nothing; and a mapped
  `requireNonceByLabel: false` relaxes a global requirement for the
  gateway alone while the merchant store still binds. The README
  test count moves 1049 → 1056.

- CLI demo section for per-label maximum signature age (backlog #661):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `maxSignatureAgeSecByLabel` over a dual ed25519 fixture whose
  merchant and gateway signatures are both 300s old: the merchant
  label alone fails with `SIGNATURE_TOO_OLD` under its 60s window
  while the gateway label verifies under its 3600s window,
  proving one global window cannot split them. The same fixture
  re-verified under a global `maxSignatureAgeSec` of 3600s plus a
  merchant-only map still fails the merchant label under its
  mapped window while the gateway label verifies by falling back
  to the global window, proving an unmapped label falls back to
  the global window rather than skipping the age check. The demo
  asserts every outcome, code, reason and keyid and fails
  (non-zero exit) if any fixture breaks;
  `test/demo.test.ts` gains two tests pinning the same shapes
  and the printed lines (the per-label replay-cache segment's
  closing-lines assertion now points at the new closing segment).
  The README test count moves 1047 → 1049.

- Benchmark row for per-label replay cache (backlog #660):
  `bench/bench.ts` now measures `verifyAllLabels` with
  `replayCacheByLabel` over a dual ed25519 fixture whose merchant and
  gateway signatures carry the same bare nonce string: one measured op
  verifies the dual twice against fresh per-label caches (first call
  records the nonce in each store, both labels ok; second call is
  replay-rejected in both stores with `NONCE_REPLAY`), with the
  shared-global-cache contrast, the unmapped-label global fallback,
  and the no-cache default asserted outside timing. The README
  Benchmarks table is refreshed from this run (new row
  ~565.6 ops/sec, Node v24.22.1, shared host).

- CLI demo section for per-label replay cache (backlog #659):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `replayCacheByLabel` over a dual ed25519 fixture whose
  merchant and gateway signatures carry the same bare nonce
  string (each party mints nonces in its own namespace): the
  merchant store is pre-seeded with that nonce before the dual
  verification, so the merchant label alone fails with
  `NONCE_REPLAY` (its second presentation) while the gateway
  label passes (its first presentation in its own store),
  proving the stores partition the nonce namespace per label
  rather than sharing one bare-nonce namespace. The same
  fixture re-verified under a single shared global
  `replayCache` with no map passes the merchant label and
  fails the gateway label with `NONCE_REPLAY`, proving the
  shared contract is unchanged and that a label with no map
  entry falls back to the global store. The demo asserts
  every outcome, code, reason, keyid and nonce and fails
  (non-zero exit) if any fixture breaks;
  `test/demo.test.ts` gains two tests pinning the same
  shapes and the printed lines (the per-label algorithm
  fallback segment's closing-lines assertion now points at
  the new closing segment). The README test count moves
  1045 → 1047.
- CLI demo section for per-label algorithm fallback (backlog #658):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `algFallbackByLabel` over a dual-label fixture with neither
  signature carrying an `alg` parameter (a foreign-signer shape,
  hand-built because `signRequest` always emits `alg`): a fresh
  P-256 merchant key pair plus a fixed 32-byte HMAC gateway
  secret, verified under a global `algFallback: "infer"` plus
  `algFallbackByLabel: { merchant: "infer", gateway: false }`,
  so the merchant label verifies as `ecdsa-p256-sha256` by
  inference while the gateway label alone fails with
  `VERIFICATION_ERROR` (the legacy default for a missing `alg`
  is `ed25519`, which the crypto layer rejects against a secret
  key). The same fixture re-verified under the global `"infer"`
  alone verifies both labels, proving a mapped `false`
  overrides the global strategy rather than being ignored,
  with a segment note that inference is key-shape inference
  only (an RSA key infers `rsa-pss-sha512`, never
  `rsa-v1_5-sha256`). The demo asserts every outcome, code,
  reason and algorithm and fails (non-zero exit) if any
  fixture breaks; `test/demo.test.ts` gains two tests pinning
  the same shapes and the printed lines (the per-label
  required components segment's closing-lines assertion now
  points at the new closing segment). The README test count
  moves 1043 → 1045.
- CLI demo section for per-label required components (backlog #657):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `requiredComponentsByLabel` over a dual ed25519 fixture
  (both signatures covering `@method` and `@path` only):
  the merchant label verifies against its `@method`/`@path`
  requirement while the gateway label alone fails with
  `MISSING_REQUIRED_COMPONENT` against its
  `@method`/`content-digest` requirement, with a segment note
  that a coverage check runs before any crypto work, so a
  missing component is a policy rejection, not an
  authenticity verdict. The same fixture re-verified under a
  global `content-digest` requirement plus a per-label map
  (merchant to `@method`/`@path`, gateway to `[]`) verifies
  both labels, proving a mapped list replaces the global list
  rather than unioning with it, and that `[]` switches the
  check off for that label outright. The demo asserts every
  outcome, code, reason and keyid and fails (non-zero exit)
  if any fixture breaks; `test/demo.test.ts` gains two tests
  pinning the same shapes and the printed lines (the
  per-label expired tolerance segment's closing-lines
  assertion now points at the new closing segment). The
  README test count moves 1041 → 1043.
- CLI demo section for per-label expired tolerance (backlog #656):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `expiredToleranceSecByLabel` over a dual ed25519 fixture
  (merchant tolerance 0s, gateway tolerance 120s, both signatures
  expired 60s before the verifier clock): the merchant label
  alone fails with `EXPIRED` while the gateway label
  still verifies, with a segment note that a grace period only
  widens the verifier-side past-expires window and never
  changes the signature itself, and that expired tolerance and
  clock-skew tolerance are two independent windows on the same
  verify chain. The demo asserts every outcome, code, reason
  and keyid and fails (non-zero exit) if any fixture breaks;
  `test/demo.test.ts` gains two tests pinning the same shapes
  and the printed lines (the per-label clock-skew segment's
  closing-lines assertion now points at the new closing
  segment). The README test count moves 1039 → 1041.
- CLI demo section for per-label clock-skew tolerance (backlog #655):
  `src/demo.ts` now demonstrates `verifyAllLabels` with
  `clockSkewToleranceSecByLabel` over a dual ed25519 fixture
  (merchant tolerance 5s, gateway tolerance 300s, both signatures
  created 120s ahead of the verifier clock): the merchant label
  alone fails with `CREATED_IN_FUTURE` while the gateway label
  still verifies, with a segment note that a tolerance only
  widens the verifier-side created/freshness window and never
  changes the signature itself. The demo asserts every outcome,
  code, reason and keyid and fails (non-zero exit) if any fixture
  breaks; `test/demo.test.ts` gains two tests pinning the same
  shapes and the printed lines. The README test count moves
  1037 → 1039.
- Orthogonal test coverage for per-label clock-skew tolerance combined
  with per-label expired tolerance (backlog #654):
  `test/clockSkewExpiredToleranceByLabel.test.ts` pins a dual-label
  fixture (merchant strict on both windows — clock skew 5s, expired
  tolerance 0s; gateway loose on both — 300s and 120s) and asserts
  a future-created dual splits on the clock dimension only
  (`CREATED_IN_FUTURE` for the merchant, gateway passes) even with
  the expired map configured, an expired dual splits on the expiry
  dimension only (`EXPIRED` for the merchant, gateway passes) even
  with the clock map configured, a single call violating both
  dimensions (merchant future-created, gateway expired beyond its
  grace) reports each label's own code with no cross-label masking,
  and swapped strictness flips both splits (the maps follow the
  label, not the position). A single minted signature cannot
  violate both windows at once — `signRequest` refuses
  `expires < created` — so the both-violated case is pinned at the
  call level, not the single-signature level. The README test count
  moves 1033 → 1037.
- CLI demo section for per-label application-tag pinning (backlog #648):
  `src/demo.ts` now demonstrates `verifyAllLabels` with `expectedTags`
  over a dual ed25519 fixture (merchant tag
  `payment-initiation-v1`, gateway tag `settlement-webhook-v1`):
  both labels pass under the fully matching map with each tag
  reported back, the gateway label alone fails with `TAG_MISMATCH`
  under a wrong per-label pin while the merchant label still
  verifies, and a label missing from the map falls back to the
  global `expectedTag`. The demo asserts every outcome, code,
  reason and tag and fails (non-zero exit) if any fixture breaks;
  `test/demo.test.ts` gains two tests pinning the same shapes and
  the printed lines. The README test count moves 1031 → 1033.
- Benchmark row for per-label algorithm-inference strategies (backlog #647):
  `bench` now measures `verifyAllLabels` with `algFallbackByLabel`
  over a dual-label fixture signed outside timing with `created`
  pinned and the verifier's `now` injected — both signatures carry
  no `alg` parameter (the foreign-signer shape of
  `test/algFallbackByLabel.test.ts`): the merchant label (P-256 key,
  mapped `"infer"`) verifies with the inferred `ecdsa-p256-sha256`
  algorithm while the gateway label (HMAC secret, mapped `false`)
  is exactly `VERIFICATION_ERROR`, so the row pays the per-label map
  resolution and the key-shape inference for each label. The reversed
  split (P-256 merchant strict is exactly `SIGNATURE_MISMATCH`
  while the gateway infers `hmac-sha256`), the mapped-`false`-
  overrides-global half, the unmapped-label global-fallback halves
  in both directions, and the no-option default (both labels fail)
  are asserted outside timing. The README Benchmarks table is
  refreshed from this run, including the new row at 5,840 ops/sec
  (171.24 µs/op), and the per-label algorithm-inference path is
  documented there.
- Benchmark row for per-label component-coverage lists (backlog #646):
  `bench` now measures `verifyAllLabels` with
  `requiredComponentsByLabel` over a dual ed25519 fixture signed
  outside timing with `created` pinned and the verifier's `now`
  injected (merchant must cover `content-digest`, gateway must cover
  `@query`, request carrying `?ref=abc`) — each measured op verifies
  the split dual, merchant exactly `MISSING_REQUIRED_COMPONENT`
  with the pinned reason while the gateway label still verifies, so
  the row pays the per-label map resolution and the
  pre-cryptographic coverage check for each label. The reverse split,
  the replace-not-union half (a mapped list replaces the global list,
  including a mapped `[]` disabling the check for that label while
  the unmapped label still falls back to the global list), the
  gateway-only-map fallback in the other direction, and the no-option
  default (both labels verify, since the check is opt-in) are
  asserted outside timing. The README Benchmarks table is refreshed
  from this run, including the new row at 3,731 ops/sec
  (268.01 µs/op), and the per-label component-coverage path is
  documented there.
- Benchmark row for per-label expiry-grace tolerances (backlog #645):
  `bench` now measures `verifyAllLabels` with
  `expiredToleranceSecByLabel` over a dual ed25519 fixture signed
  outside timing with `created` pinned 3600s before the injected
  `now` and `expires` pinned 60s before it (merchant tolerance 0s,
  gateway tolerance 120s) — each measured op verifies the split dual,
  merchant exactly `EXPIRED` with the pinned reason while the gateway
  label still verifies, so the row pays the per-label map resolution
  and the expiry comparison for each label. The exact-tolerance
  boundary (both labels at 60s pass), the unmapped-label global
  fallback (merchant-only map under a wide global, gateway-only map
  under a narrow global) and the no-option default (both labels fail
  under the 0s default) are asserted outside timing. The README
  Benchmarks table is refreshed from this run, including the new row
  at 3,133 ops/sec (319.20 µs/op), and the per-label expiry-grace
  path is documented there.
- Benchmark row for per-label clock-skew tolerances (backlog #644):
  `bench` now measures `verifyAllLabels` with
  `clockSkewToleranceSecByLabel` over a dual ed25519 fixture signed
  outside timing with `created` pinned 120s ahead of the injected
  `now` (merchant tolerance 5s, gateway tolerance 300s) — each
  measured op verifies the split dual, merchant exactly
  `CREATED_IN_FUTURE` with the pinned reason while the gateway
  label still verifies, so the row pays the per-label map
  resolution and the future-created comparison for each label.
  The unmapped-label global fallback (merchant-only map under a
  wide global, gateway-only map under a narrow global) and the
  no-option default (both labels fail under the 60s default) are
  asserted outside timing. The README Benchmarks table is
  refreshed from this run, including the new row at ~1,700
  ops/sec (588.41 µs/op), and the per-label clock-skew path is
  documented there.
- Per-label nonce replay stores for multi-party signatures (backlog
  #643): `VerifyAllOptions.replayCacheByLabel` maps a signature label
  to its own `NonceStore`, checked in `verifyAllLabels` in place of
  the global `replayCache` for that label only; unmapped labels fall
  back to the global store, and with no global store an unmapped label
  is never replay-checked. A malformed map or a store value without a
  `check` function fails fast as a caller configuration error
  (validated for the whole map, including labels absent from the
  request). `test/replayCacheByLabel.test.ts` (11 cases) pins the
  same bare nonce passing in both labels in one call and replaying
  in each label's own store on re-verification, a nonce pre-seen by
  the merchant store still passing in the gateway store, the global
  fallback, the no-global bypass, both fail-fast shapes, failed
  verifications polluting neither store, the unchanged shared-store
  contract without the map, per-label TTLs (60s vs 3600s), the
  stable `NONCE_REPLAY` code from `verifyRequestOrThrow`, and an
  absent-label map entry being ignored. The README test count moves
  1020 → 1031, and the per-label replay stores section plus the
  shared-cache contract note are updated (partitioning is opt-in
  only; it does not change the default one-nonce-per-label
  contract).
- Orthogonal test coverage for per-label freshness windows combined
  with per-label nonce requirements (backlog #642):
  `test/maxSignatureAgeByLabelRequireNonceByLabel.test.ts` pins a
  dual-label fixture (merchant window 60s with
  `requireNonceByLabel: { merchant: true }`, gateway window 3600s
  with no nonce requirement) and asserts a fresh nonce-less
  merchant fails `MISSING_NONCE` while the gateway passes, an old
  nonce-carrying merchant fails `SIGNATURE_TOO_OLD` while the
  gateway inside its window passes, an old AND nonce-less
  merchant fails `SIGNATURE_TOO_OLD` (the age check runs before
  the nonce check in `verifyRequest` — this corrects the backlog
  wording, which read as old-and-nonce-less implying
  `MISSING_NONCE`), a fresh nonce-carrying dual passes with
  nonces and keyids echoed, and a forged old nonce-less
  merchant still reports `SIGNATURE_MISMATCH`. The README test
  count moves 1015 → 1020.
- Orthogonal test coverage for per-label key resolvers combined with
  per-label keyid pinning (backlog #641):
  `test/keyResolversExpectedKeyIds.test.ts` pins a dual-label
  fixture (each label with its own resolver and its own pin) and
  asserts the consistent dual passes with both keyids echoed, a
  resolver that follows a rotation to an unpinned keyid fails
  `KEYID_MISMATCH` while the other label still passes, a resolver
  that maps a pinned keyid to the wrong public key fails
  `SIGNATURE_MISMATCH` (crypto runs before the pin check, so the
  pin is never reached — this clarifies the backlog wording, which
  could be read as wrong-key implying `KEYID_MISMATCH`), an
  unresolvable keyid fails `KEY_RESOLUTION_FAILED` before any pin
  check, a label unmapped in `keyResolvers` falls back to the
  global `keyResolver` while its pin still holds, and a label
  unmapped in `expectedKeyIds` passes on resolution plus crypto
  alone. The README test count moves 1009 → 1015.
- Orthogonal test coverage for per-label keyid pinning combined with
  per-label tag presence (backlog #640):
  `test/expectedKeyIdsRequireTagByLabel.test.ts` pins a dual-label
  fixture (both keyids pinned, only the merchant label required to
  carry a `tag`) and asserts the pinned dual passes with both keyids
  echoed, a tag-less merchant with a correctly pinned keyid fails
  `MISSING_TAG` (not a keyid error), a keyid mismatch on either
  label fails `KEYID_MISMATCH` while the other label still passes,
  and a label unmapped in the tag map falls back to the global
  (unset) tag rule. The README test count moves 1004 → 1009.
- Benchmark row for the JWKS https-only endpoint rule (backlog #639):
  `bench` now measures `JwksKeyStore` with `requireHttps: true`
  over an https endpoint restored offline — each measured op
  resolves the pinned kid against that store, so the row measures
  the same per-request resolve cost as the plain `resolve` row
  (the rule is construction-time only and `resolve` never
  consults it). The http-endpoint rejection (pinned error,
  zero fetches) and the https-endpoint construction (zero
  fetches) are asserted outside timing. The README Benchmarks
  table is refreshed from this run, including the new row,
  and the endpoint-rule path is documented there.
- Benchmark row for per-label freshness windows (backlog #638):
  `bench` now measures `verifyAllLabels` with
  `maxSignatureAgeSecByLabel` over a dual ed25519 fixture signed
  outside timing with `created` pinned 120s before the injected
  `now` — each measured op verifies the split dual (the merchant
  label, 60s window, is exactly `SIGNATURE_TOO_OLD` with the
  pinned reason while the gateway label, 3600s window, still
  verifies, proving one label's staleness never blocks the other
  label's verdict). The fallback halves (an unmapped label
  falling back to the global `maxSignatureAgeSec`, matching and
  mismatching) and the opt-in default are asserted outside
  timing. The README Benchmarks table is refreshed from this
  run, including the new row, and the per-label
  freshness-window path is documented there.
- Benchmark row for per-label tag pinning (backlog #637):
  `bench` now measures `verifyAllLabels` with `expectedTags` over a
  dual ed25519 fixture signed outside timing with `created` pinned —
  each measured op verifies the fully pinned dual (both labels ok,
  each tag echoed at its pinned value) and the
  differently-tagged-gateway dual (merchant still ok while the
  gateway label is exactly `TAG_MISMATCH` with the pinned reason,
  proving the failure is the tag value rather than a signature
  error). The fallback halves (an unmapped label falling back to
  the global `expectedTag`, matching and mismatching) and the
  opt-in default are asserted outside timing. The README
  Benchmarks table is refreshed from this run, including the new
  row, and the per-label tag-pinning path is documented there.
- Per-label `alg` fallback strategies for `verifyAllLabels` (backlog
  #636): `VerifyAllOptions.algFallbackByLabel` maps a signature label
  to its own `algFallback` value, falling back to the global strategy
  for unmapped labels — a merchant signature from a foreign signer
  that omits the optional `alg` parameter can now be inferred from
  the key shape while a gateway signature on the same request keeps
  the strict legacy default, without one global switch being too lax
  or too strict. A mapped value overrides the global one in both
  directions (`"infer"` enables inference for that label only, and
  `false` keeps that label strict even when the global strategy is
  `"infer"`), and each value must be exactly `"infer"` or `false`,
  otherwise a caller configuration error (throw). The README
  multi-party section documents the option with a merchant-`infer` /
  gateway-`false` example, and `test/algFallbackByLabel.test.ts`
  covers the split verdicts in both directions, fallback to the
  global strategy (and to the legacy default), the global strategy
  applying to both labels without the map, fail-fast on malformed
  maps and values (including a mapped `false` staying valid), and
  the unchanged single-label `verifyRequest` global path.
- Per-label component-coverage policies for `verifyAllLabels`
  (backlog #635): `VerifyAllOptions.requiredComponentsByLabel` maps a
  signature label to its own `requiredComponents` list, falling back
  to the global list for unmapped labels — a merchant signature that
  must cover `content-digest` and a gateway signature that must cover
  `@query` can now be verified on the same request without one global
  list being too lax or too strict. A mapped list replaces the global
  list for that label (it is not unioned with it, so `[]` disables the
  check for that label), each list follows the global list's rules (an
  array of non-empty strings, otherwise a caller configuration error),
  and a missing component reuses `MISSING_REQUIRED_COMPONENT` at the
  same fail-fast-before-crypto position. The README multi-party section
  documents the option with a content-digest/`@query` example, and
  `test/requiredComponentsByLabel.test.ts` covers the split verdicts
  in both directions, case-insensitivity, fallback to the global list,
  replace-not-union (including `[]` disabling), the global list
  applying to both labels without the map, fail-fast on malformed maps
  and lists, and the unchanged single-label `verifyRequest` path.
- Per-label expiry tolerances for `verifyAllLabels` (backlog
  #633): `VerifyAllOptions.expiredToleranceSecByLabel` maps a
  signature label to its own `expiredToleranceSec`, falling back to
  the global tolerance (default 0s) for unmapped labels — a merchant
  signer whose signatures must die on time and a gateway signer that
  needs a wider grace period for clock lag and retries can now be
  verified on the same request without one global window being too
  lax or too strict. Each map value must be a non-negative finite
  number (zero is the strict default, so it is a valid per-label
  value), otherwise a caller configuration error (throw). The README
  multi-party section documents the option with a 0s/120s example,
  and `test/expiredToleranceSecByLabel.test.ts` covers the split
  verdict (60s-expired: merchant `EXPIRED`, gateway ok), the
  exact-boundary pass and one-second-over failure, fallback to the
  global tolerance and to the 0s default, fail-fast on
  negative/non-finite/non-numeric values, and the unchanged
  single-label `verifyRequest` global path.
- Per-label clock-skew tolerances for `verifyAllLabels` (backlog
  #631): `VerifyAllOptions.clockSkewToleranceSecByLabel` maps a
  signature label to its own `clockSkewToleranceSec`, falling back to
  the global tolerance (default 60s) for unmapped labels — a merchant
  signer on a tight clock and a gateway signer on a drifting clock can
  now be verified on the same request without one global window being
  too lax or too strict. Each map value must be a positive finite
  number, otherwise a caller configuration error (throw). The README
  multi-party section documents the option with a 5s/300s example, and
  `test/clockSkewToleranceSecByLabel.test.ts` covers the split
  verdict (120s skew: merchant `CREATED_IN_FUTURE`, gateway ok), the
  exact-boundary pass, fallback to the global tolerance and to the
  60s default, and fail-fast on non-positive/non-finite/non-numeric
  values.
- Benchmark section for `verifyAllLabels` with `expectedKeyIds` plus the
  global `requireTag` (backlog #629): `benchmarkVerifyAllExpectedKeyIdsRequireTag`
  in `bench/bench.ts` verifies three dual-label fixtures per measured op
  (fully tagged dual both ok with pinned keyids echoed; merchant-untagged
  dual merchant exactly `MISSING_TAG` while the gateway still verifies;
  wrong-gateway-keyid dual gateway exactly `KEYID_MISMATCH` while the
  merchant still verifies) with the opt-in halves pinned outside timing
  (no-option and explicit `requireTag: false` let the untagged dual
  through; no keyid pins let the wrong-keyid dual through). The README
  Benchmarks table is refreshed from this run (new row: ~211.4 ops/sec,
  4731.06 µs/op) with a matching prose paragraph. A scratch-copy mutation
  run (pinned tag reason altered) fails exactly at this section's
  outside-timing self-check, proving the guard bites.
- Orthogonal-combination tests for `verifyAllLabels` with
  `candidateKeysByLabel` and `expectedKeyIds` (backlog #627):
  `test/candidateKeysByLabelExpectedKeyIds.test.ts` pins a dual-label
  gateway where the merchant label rotates ed25519 keys and the
  gateway label uses one static key — the rotated merchant key
  verifies with its keyid echoing the pinned value, the old merchant
  key still verifies inside the rotation window when re-pinned to its
  own keyid, a merchant or gateway keyid mismatch fails exactly
  `KEYID_MISMATCH` (not a rotation error), a key removed from the
  rotation list fails `SIGNATURE_MISMATCH` even when its keyid is
  pinned, a label missing from the pin map falls back to the global
  `expectedKeyId` (and a global mismatch fails only that label),
  and with no pinning configured rotation alone does not pin.
- Benchmark section for `verifyAllLabels` with `requireCreatedByLabel` /
  `requireExpiresByLabel` (backlog #622): `benchmarkVerifyAllRequireFreshnessByLabel`
  in `bench/bench.ts` verifies three hand-built dual-label fixtures per measured
  op (fully dated dual both ok; no-created merchant exactly `MISSING_CREATED`
  while the gateway still verifies; no-expires gateway exactly `MISSING_EXPIRES`
  while the merchant still verifies) with the globals left unset, plus the
  no-option and explicit-`false` opt-in halves outside timing. The README
  Benchmarks table is refreshed from this run (new row: ~195.3 ops/sec,
  5120.31 µs/op) with a matching prose paragraph.
- The CLI demo (`npm run demo`) now closes with a per-label
  required-freshness segment (backlog #621): two hand-built
  dual-label fixtures (a merchant signature carrying `expires`
  but no `created` paired with a fully dated gateway signature,
  and a fully dated merchant signature paired with a gateway
  signature carrying `created` but no `expires`) verified with
  `requireCreatedByLabel: { merchant: true }` /
  `requireExpiresByLabel: { gateway: true }` and the globals
  left unset — the no-created merchant label fails exactly
  `MISSING_CREATED` while the gateway label still verifies, the
  no-expires gateway label fails exactly `MISSING_EXPIRES`
  while the merchant label still verifies — and each fixture
  re-verified with its global explicitly false plus the map
  entry true, pinning that a mapped true overrides a global
  false. `DemoResult` gains the segment's signed requests and
  verification results, and the demo tests gain two cases
  pinning the segment end-to-end (970 tests in total). Every
  clock in the segment is injected, so the printed lines are
  byte-identical between runs.
- Orthogonal-combination tests for `verifyAllLabels` with
  `candidateKeysByLabel` and the global `requireTag` (backlog #618):
  `test/candidateKeysByLabelRequireTag.test.ts` pins a dual-label
  gateway where the merchant label rotates ed25519 keys and the
  gateway label uses one static key — the rotated merchant key with
  a tag verifies while the tag-less gateway still passes (via an
  explicit `requireTagByLabel: { gateway: false }` opt-out of the
  global flag), a valid rotated merchant key without a tag fails
  exactly `MISSING_TAG` (not a key error), the old merchant key
  still verifies inside the rotation window, a key removed from
  the list fails `SIGNATURE_MISMATCH`, a forged tag-less merchant
  signature reports `SIGNATURE_MISMATCH` (crypto before tag
  presence), and dropping the gateway opt-out makes the global
  flag reject the tag-less gateway too — so the gateway pass is
  the explicit override, not a silent exemption.
- `RequestLike.requestTarget`: an explicit request-target override
  for the `@request-target` derived component (backlog #617). When
  set, that exact string — the absolute-form URI, the
  authority-form (`host[:port]`), or the asterisk-form (`*`) as a
  proxy or gateway saw it on the request line — becomes the
  component value instead of the origin-form reconstruction from
  `url`; when unset, the origin form applies unchanged. An empty
  string is a caller configuration error (fail-fast on the sign
  side, `SIGNATURE_BASE_BUILD_FAILED` on the verify side). The
  override is carried through `signRequest` and `addSignature` so a
  signed message verifies without the caller re-attaching it, and
  resolves against the associated request under `;req`;
  `fromNodeRequest` never sets it — an override is always the
  caller's explicit choice. Covered by 8 new tests in
  `test/requestTargetOverride.test.ts` (three forms round-tripping,
  tamper rejection, empty-string rejection on both sides, unset
  origin-form behavior, `;req` override).
- The benchmark (`npm run bench`) gains a `verifyAllLabels
  requireTagByLabel (2 labels)` row: one measured op verifies two
  dual-label fixtures with `requireTagByLabel: { merchant: true }` and
  no global `requireTag` — the tag-carrying dual (both labels ok, the
  merchant tag returned, the tag-less gateway still ok by falling back
  to the unset global) and the tag-less-merchant dual (merchant exactly
  `MISSING_TAG` with the pinned reason while the gateway label still
  verifies) — with the tag-less dual verifying with no option passed,
  an explicit `merchant: false` map entry letting it through, and a
  differently-tagged merchant fixture still verifying (presence, never
  value), all pinned outside timing. The README Benchmarks table is
  refreshed from the same real run, including the new row (~565.4
  ops/sec).
- The benchmark (`npm run bench`) gains a `verifyRequest requireTag`
  row: one measured op verifies a pinned ed25519 fixture carrying the
  pinned tag with `requireTag: true`, re-pinning that the result is ok
  and the returned tag is the pinned value — with the tag-less fixture
  under the option returning exactly `MISSING_TAG` with the pinned
  reason, a differently-tagged fixture still verifying (requireTag
  checks presence, never value), and the tag-less fixture verifying
  with no option passed, all pinned outside timing. The README
  Benchmarks table is refreshed from the same real run, including the
  new row (~4,103 ops/sec).
- The benchmark (`npm run bench`) gains a `JwksKeyStore.refresh
  (fetchRetries 2, 500/500/200)` row: one measured op is one `refresh()`
  with `fetchRetries: 2` over a counting fake fetch scripted 500, 500,
  200 — exactly three fetches, exactly two recorded sleeps of the
  pinned 250ms backoff (a stub sleep, so no wall-clock backoff is
  measured), exactly one `stats().refreshes`, and the pinned kid
  resolving afterwards — with the terminal-4xx case (one fetch, zero
  sleeps, pinned HTTP 404 error) and the exhausted-retries case
  (three fetches, two sleeps, pinned HTTP 500 error, exactly one
  `stats().refreshFailures`) pinned outside timing. The README
  Benchmarks table is refreshed from the same real run, including the
  new row (~32,006 ops/sec).
- The benchmark (`npm run bench`) gains a `verifyAllLabels
  candidateKeysByLabel (2 labels)` row: one measured op verifies three
  dual-label fixtures with `candidateKeysByLabel: { merchant: [merchant
  key], gateway: [old secret, new secret] }` and no global
  `candidateKeys` — the new-secret dual (both labels ok, the gateway
  found at the second candidate), the old-secret dual (both labels ok
  inside the rotation window), and the swapped-merchant-list dual
  (merchant exactly `SIGNATURE_MISMATCH` while the gateway label still
  verifies, proving each label tries only its own candidate list) —
  with the unmapped-label fallback to the global `candidateKeys` and
  the `candidateKeysByLabel` + `keys` mutual-exclusion error pinned
  outside timing. The README Benchmarks table is refreshed from the
  same real run, including the new row (~1,406 ops/sec).
- The benchmark (`npm run bench`) gains a `verifyAllLabels
  requireNonceByLabel (2 labels)` row: one measured op verifies two
  dual-label fixtures with `requireNonceByLabel: { merchant: true }`
  and the global `requireNonce` unset — the nonce-carrying dual (both
  labels ok, merchant nonce returned) and the nonce-less-merchant dual
  (merchant exactly `MISSING_NONCE` with the pinned reason while the
  unmapped gateway label still verifies by falling back to the unset
  global) — with the no-option acceptance and an explicit
  `merchant: false` map entry pinned outside timing. The README
  Benchmarks table is refreshed from the same real run, including the
  new row (~1,417 ops/sec).
- The CLI demo (`npm run demo`) gains a per-label candidate keys
  segment: a dual-label request carries a merchant ed25519 signature
  and a gateway hmac-sha256 signature, verified with
  `candidateKeysByLabel: { merchant: [merchant key], gateway:
  [old secret, new secret] }` — the gateway label verifies via the
  second candidate when signed with the new secret and via the first
  when signed with the old secret, and swapping the merchant list
  for an unrelated key fails only the merchant label with
  `SIGNATURE_MISMATCH` while the gateway label still verifies,
  proving each label tries only its own candidate list. The segment
  asserts every outcome, label, keyid, alg, code and reason against
  hand-pinned expectations, so a broken fixture fails the demo with
  a non-zero exit.
- The CLI demo (`npm run demo`) gains a per-label nonce
  requirement segment: a dual-label request carries a merchant
  signature that must carry a nonce and a gateway signature that
  historically carries none, verified with
  `requireNonceByLabel: { merchant: true }` and the global
  `requireNonce` unset — the nonce-less merchant label is
  rejected with `MISSING_NONCE`, the unmapped gateway label
  falls back to the unset global and verifies, and the same
  merchant signature re-signed with a nonce verifies alongside
  it. The segment asserts every outcome, label, code, reason and
  reported nonce against hand-pinned expectations, so a broken
  fixture fails the demo with a non-zero exit.
- The CLI demo (`npm run demo`) gains a JWKS requireHttps segment:
  a real loopback `http` server serves the scripted key's JWKS
  document, and a `JwksKeyStore` built over that plaintext endpoint
  with `requireHttps: true` is rejected at construction with the
  pinned configuration error before any fetch is attempted (the
  loopback server records zero requests). A store over an `https:`
  endpoint URL with the same option constructs cleanly — the
  construction check passes for `https:`, and no fetch is attempted
  at construction, so no local TLS fixture is faked. A store over
  the same loopback endpoint with the option off refreshes, resolves
  the scripted keyid, and records exactly one fetch. The segment
  asserts every outcome against hand-pinned expectations, so a
  broken fixture fails the demo with a non-zero exit.
- The CLI demo (`npm run demo`) gains a required-tag segment: the
  same request signed with no tag is rejected with `MISSING_TAG`
  under `requireTag: true` and verifies with the option unset, and
  the same request signed with a tag verifies under the option —
  the presence counterpart to the application-tag segment's
  `expectedTag` value pin, with `requireTagByLabel` as the
  per-label form. The segment asserts every outcome, code,
  reason and reported tag against hand-pinned expectations, so a
  broken fixture fails the demo with a non-zero exit.
- `verifyAllLabels` accepts a `requireTagByLabel` map: a label in the
  map is checked against its own `requireTag` boolean, any other label
  falls back to the global `requireTag` (unset means no existence
  check for it). A missing tag reuses the global `MISSING_TAG` code —
  no new code is introduced — and the check position is the same as
  the global one (after the cryptographic check, before the window
  checks), so forgeries still report `SIGNATURE_MISMATCH`. A
  non-boolean map value is a caller configuration error (throw), and
  the map never joins the key-selection mutual-exclusion rules. It is
  orthogonal to `requireNonceByLabel`: each map drives only its own
  existence check, so a merchant signature that must carry a tag and
  a gateway signature that historically carries none can be verified
  in one call with independent per-label verdicts.
- The benchmark (`npm run bench`) now also measures
  `fromNodeResponse` + `verifyRequest` over a loopback-signed
  gateway settlement response: a real `http` server on loopback
  (no external network) signs a 200 response covering `@status`,
  the bound request's `@method` (`;req`), and a settlement
  trailer (`;tr`), and the measured op adapts that live response
  and verifies it with `@status` required, re-pinning the
  adapted status (200), the carried-over trailer, and a
  successful verification on every pass. The timed loop
  re-measures only the client-side adapt + verify work over the
  one captured response — re-measuring the network per
  iteration would time TCP loopback, not the adapter. Outside
  timing, a missing `statusCode` fails fast with the adapter's
  pinned message and transplanting the response onto a request
  with a different method breaks the `;req` binding with a pinned
  `SIGNATURE_MISMATCH`. On this run the new row measured
  ~3,590 ops/sec (278.58 µs/op). The README Benchmarks table
  was refreshed in full from this run (73 rows, 2026-10-25).

- `verifyAllLabels` accepts a per-label nonce-existence map
  `requireNonceByLabel`: a label in the map is checked against its
  own boolean, any other label falls back to the global `requireNonce`
  (unset means no existence check for it), and a mapped value overrides
  the global flag in both directions. A missing nonce reuses the global
  error code (`MISSING_NONCE`); no new code, and the check position
  matches the global one (after the cryptographic check, before the
  replay cache), so forgeries still report `SIGNATURE_MISMATCH` and a
  nonce-less label never reaches the cache. A non-boolean map value is
  a caller configuration error naming the label, and like the freshness
  requirements an existence requirement never joins the key-selection
  mutual-exclusion rules. The map only overrides the existence
  requirement: the replay cache stays shared across labels (one nonce
  per label). 12 new tests in `test/requireNonceByLabel.test.ts`.

- `SignedHttpRequest` echoes `coveredComponents`: exactly the list
  `signRequest` wrote into `signature-input` (the explicit option, or
  the default set when omitted), in signature order, as a detached
  copy — the sign-side mirror of `VerifyResult.coveredComponents`, so
  the two sides compare item for item without a second header parse.
  `addSignature` echoes the appended signature's own list, not a merge
  with the first signature's. 11 new tests in
  `test/signedCoveredComponents.test.ts`.

- The CLI demo gains a JWKS fetch retries segment: a `JwksKeyStore`
  with `fetchRetries: 2` over a counting fake fetch scripted 500, 500,
  200 succeeds on the third attempt with two recorded sleeps and a
  one-key snapshot, while a second store with the same retry budget
  pointed at a 404 endpoint fails with the pinned HTTP 404 message
  after exactly one fetch and zero sleeps — a 4xx response is
  terminal, never retried. 2 new tests in `test/demo.test.ts`.

- `verifyAllLabels` accepts per-label freshness-existence maps
  `requireCreatedByLabel` and `requireExpiresByLabel`: a label in a map
  is checked against its own boolean, any other label falls back to
  the global `requireCreated` / `requireExpires` (unset means no
  existence check for it), and a mapped value overrides the global
  flag in both directions. Missing parameters reuse the global error
  codes (`MISSING_CREATED` / `MISSING_EXPIRES`); no new codes, and the
  check position matches the global one (after the cryptographic
  check, before the window checks), so forgeries still report
  `SIGNATURE_MISMATCH`. A non-boolean map value is a caller
  configuration error naming the label, and like the freshness window
  an existence requirement never joins the key-selection
  mutual-exclusion rules. 12 new tests in
  `test/requireFreshnessByLabel.test.ts`.

- `VerifyOptions.requireTag` (default `false`, backwards compatible):
  a signature carrying no `tag` — or an empty-string one, treated as
  missing since `signRequest` refuses to mint one — fails with the new
  error code `MISSING_TAG`. Checked alongside
  `requireCreated`/`requireExpires`, after the cryptographic check and
  before the window checks, so forgeries still report
  `SIGNATURE_MISMATCH`; in `verifyAllLabels` it applies independently
  per label, and a signature that also fails a pinned `expectedTag`
  still reports `TAG_MISMATCH`. 10 new tests in
  `test/requireTag.test.ts`.

- `VerifyResult` now carries `coveredComponents`: the covered component
  identifiers parsed from `signature-input`, in signature-input order,
  as seen on the wire — reported on every `verifyRequest` /
  `verifyWithKey` return point that already carries the wire fields
  (success and failure alike), so a webhook receiver can audit exactly
  which components a signature claimed to cover without re-parsing the
  header. Absent (`undefined`) only when the component list could not
  be parsed at all (missing or malformed `signature-input`); never
  fabricated, and always a detached copy. `verifyRequestOrThrow`
  returns the same field on success; `verifyAllLabels` reports each
  label's own list. 11 new tests in
  `test/verifyResultCoveredComponents.test.ts` (plus the updated
  `demo.test.ts` shape assertion for the throwing-verification
  segment).

- `JwksKeyStore` accepts opt-in fetch retries: `fetchRetries`
  (default `0`, single attempt as before), `fetchBackoffMs` (default
  `1000`, fixed delay between attempts), and `sleepImpl` (default
  `setTimeout`-based, injectable so tests can record delays without
  waiting). Only transient failures are retried — network errors and
  HTTP 5xx; a 4xx response, a malformed JWKS document, and a
  `fetchTimeoutMs` abort are terminal, and on exhaustion `refresh()`
  throws the last attempt's error unchanged. The previous snapshot
  and `lastRefreshedAt` stay untouched until an attempt fully
  succeeds, and `stats()` counts one `refresh()` call once however
  many attempts it made. 9 new tests in
  `test/jwksFetchRetry.test.ts`.

- `verifyAllLabels` accepts a per-label freshness-window map
  `maxSignatureAgeSecByLabel`: a label in the map is checked against
  its own window, any other label falls back to the global
  `maxSignatureAgeSec` (unset means no age check for it) — so a
  merchant signature with a short window and a gateway signature with
  a long one can share one request. Each value is validated per label
  with the global window's rules (non-negative finite number, else a
  configuration error naming the label); a window is not key
  selection, so it never joins the `keys`/`keyResolver`/`candidateKeys`
  mutual-exclusion rules. 9 new tests in
  `test/maxSignatureAgeSecByLabel.test.ts`.

- `VerifyResult` now carries the wire timestamps `created` / `expires`
  (Unix seconds, `undefined` when the signer omitted them), in the same
  "as seen on the wire" spirit as `nonce` / `tag`: every `verifyRequest`
  and `verifyWithKey` return point (success and failure alike) reports
  the parsed values, so a webhook receiver can log the claimed signing
  instant or run a custom age window without re-parsing
  `signature-input`. A tampered timestamp is reported as tampered
  (`SIGNATURE_MISMATCH` with the tampered value), because the failure is
  about authenticity, not about what was sent. `verifyRequestOrThrow`
  returns the same two fields on success and carries them on the thrown
  `VerifyError`; `verifyAllLabels` reports each label's own pair.
  12 new tests in `test/verifyResultTimestamps.test.ts` (plus the
  updated `demo.test.ts` shape assertion for the throwing-verification
  segment).

- `JwksKeyStore` accepts an opt-in `requireHttps: true`: a plaintext `http:`
  endpoint URL is then rejected at construction with
  `JwksKeyStore: \`requireHttps\` requires https: for the JWKS endpoint,
  got "http:"` — before any fetch is attempted (proved by a counting
  `fetchImpl` that sees zero calls). Whatever the endpoint serves becomes
  a verification key, and over plaintext a path attacker could substitute
  the entire key set, so this is the production posture when the endpoint
  is on the public internet. Non-boolean values throw a configuration
  error; `http:` stays allowed by default (loopback development, tests),
  and the check is construction-time only — it does not intercept a fetch
  that is later redirected from https to http (documented honestly on the
  option, in the README JWKS section and in SECURITY.md). Check order is
  URL validity → protocol whitelist → https enforcement. 8 new tests in
  `test/jwksHttps.test.ts`.

- CLI demo closes with a signed-response segment: a real loopback `http`
  server plays the payment gateway, signing its settlement response's
  `@status` with a gateway ed25519 key, and the client's `http.get`
  callback buffers the body, normalizes the response with
  `fromNodeResponse(res, body, { request })` and verifies with
  `requiredComponents: ["@status"]` — the client-side mirror of the
  inbound `fromNodeRequest` demo. A second pass flips the adapted status
  200 -> 500 (the way a downgraded settlement would look on the wire)
  and is rejected with `SIGNATURE_MISMATCH`. All outcomes are asserted
  outside the printed lines against hand-pinned constants; only the
  loopback port (never printed) and the key pair are fresh per run, so
  the segment's printed lines are byte-identical between runs.

- `JwksKeyStore` accepts an opt-in `fetchTimeoutMs` (positive integer,
  milliseconds): the default fetch is performed as
  `globalThis.fetch(url, { signal })` with an `AbortController` that
  aborts at the deadline, so a hung JWKS endpoint can no longer leave
  `refresh()` unsettled forever (and stall every waiter merged by the
  single-flight mechanism — key rotation is the path that must keep
  working during an outage). On expiry `refresh()` throws
  `JwksKeyStore: JWKS fetch timed out after Nms`; the previous snapshot
  and `lastRefreshedAt` are untouched (fail-closed) and the failure is
  counted in `stats().refreshFailures`. Non-integer/zero/negative/NaN
  values throw at construction. The timeout applies to the default
  fetch only — a custom `fetchImpl` never receives an abort signal and
  must implement its own timeout if it needs one (documented honestly
  on the option and in the README JWKS section). Unset by default, so
  no configuration change is zero behavior change.

- `JwksKeyStore` now imports NIST P-384 and P-521 JWKs: the EC branch of
  JWKS/snapshot import dispatches by `crv` (`P-256` / `P-384` / `P-521`,
  via the pre-existing `importPublicKeyJwkP384` / `importPublicKeyJwkP521`
  helpers), so a gateway publishing `ecdsa-p384-sha384` /
  `ecdsa-p521-sha512` keys no longer makes `refresh()` throw. Unsupported
  or missing `crv` values fail `refresh()` with an explicit
  `unsupported EC crv ...` error and leave the previous snapshot
  untouched. `exportSnapshot()` likewise dispatches EC keys by their
  node:crypto named curve (`prime256v1` / `secp384r1` / `secp521r1`), so
  fetched P-384/P-521 keys survive a snapshot round-trip (previously
  export of a store holding them threw); snapshots carrying them restore
  back onto the right importers. The class JSDoc and README JWKS
  sections now document the five supported JWK shapes.

- `verifyAllLabels` now accepts a per-label `candidateKeysByLabel` map
  (label→`KeyObject[]`) for multi-party key rotation: the merchant and
  the payment gateway rotate their webhook HMAC secrets on independent
  schedules, so each label gets its own ordered rotation list, tried in
  order with the same first-full-pass semantics as the global
  `candidateKeys`. A label missing from the map falls back to the global
  `candidateKeys`; a per-label list is never tried against another
  label, so a merchant candidate cannot widen the gateway's rotation
  surface. Each list is validated per label with the same rules as the
  global option (non-empty array of KeyObjects; a malformed map or list
  throws a configuration error naming the label), and it is mutually
  exclusive with that label's `key`/`keys` and
  `keyResolver`/`keyResolvers` — combining them throws. The README
  multi-label and key-rotation sections document the pattern with a
  merchant-fixed-key + gateway-mid-rollover example.

- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requiredComponents` — the
  component-coverage policy form a receiver runs to refuse a
  cryptographically valid signature that covers none of the
  components it needs (a payment-gateway verifier typically
  wants `content-digest` and `@path` covered), which the
  existing verify rows never timed (they pass no requirement,
  so the pre-cryptographic coverage check was never a
  measured cost). One measured op verifies a pinned ed25519
  fixture (signed outside timing with `coveredComponents`
  `@method`, `@path`, `content-digest`) with exactly those
  three components required and re-pins that the result is
  ok — the measured steady state is the accepting path.
  Outside timing the rejecting and boundary halves are
  asserted once: one missing required component returns
  exactly the pinned `MISSING_REQUIRED_COMPONENT` code with
  the pinned singular-form reason, two missing give the
  pinned plural-form reason, case-mismatched requirement
  names (`Content-Digest`, `@PATH`) still match, the same
  fixture verifies with the option unset (the check is
  opt-in and the default is unchanged), and an empty-string
  entry throws the pinned configuration error. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `verifyRequest requiredComponents`
  row (~4,321 ops/sec on this run).

- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `replayCache` — the replay-defense
  verify form a receiver uses to refuse an already-seen
  request (nonce replay protection), which the existing
  verify rows never timed (they pass no cache, so the
  post-cryptographic cache consultation was never a
  measured cost). One measured op verifies a pinned
  ed25519 fixture (signed outside timing with `created`
  and `nonce` pinned) twice against a fresh
  `ReplayCache` sharing the verifier's injected clock:
  the first verify records the nonce and is ok, the
  second is rejected with exactly the pinned
  `NONCE_REPLAY` code and reason — the measured steady
  state is the replay-rejecting path. Outside timing
  the bypassing and non-polluting halves are asserted:
  the same fixture verifies twice without a cache, a
  nonce-less signature verifies twice under a cache
  (nonce-less signatures bypass the cache entirely),
  and a forged signature (tampered bytes) returns
  `SIGNATURE_MISMATCH` without polluting the cache —
  the cryptographic check runs before the cache
  consultation. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `verifyRequest replayCache` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requireCreated` — the
  created-presence verify form a receiver uses to refuse
  signatures with no bounded age, which the existing
  verify rows never timed (they set no requirement, so
  the post-cryptographic `created === undefined`
  presence check was never a measured cost). The fixture
  is a hand-built no-`created` ed25519 signature minted
  outside timing with `buildSignatureBase` +
  `signatureInputValue` + a raw ed25519 sign (the shape
  `test/requireFreshness.test.ts` uses, because
  `signRequest` always emits `created`); every measured
  pass re-pins that the result is exactly
  `MISSING_CREATED` with the pinned reason — the
  measured steady state is the rejecting path. The
  same signature's acceptance without the option, a
  dated fixture's acceptance under the requirement,
  and a forged (tampered signature bytes) no-`created`
  signature's `SIGNATURE_MISMATCH` result (the
  cryptographic check runs before the presence check)
  are asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the `verifyRequest requireCreated` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expectedTag` — the
  application-tag-pinning verify form a receiver uses
  for cross-protocol replay protection (RFC 9421
  §2.3), which the existing verify rows never timed
  (they set no expectation, so the post-cryptographic
  `tag === expectedTag` comparison was never a
  measured cost). The fixture is one ed25519 signature
  minted outside timing with `created` pinned and
  `tag` pinned to `"payment-webhook-v1"`, verified
  with the matching `expectedTag` at an injected
  `now` equal to `created`; every measured pass
  re-pins that the result is ok and the returned
  `tag` equals the pinned value. The same signature
  under a different `expectedTag`, a fixture signed
  with no `tag` at all (`got no tag` reason shape),
  and the unchanged default behaviour without the
  option are asserted outside timing with pinned
  `TAG_MISMATCH` codes and reasons. The README
  Benchmarks table was refreshed wholesale from one
  real run and now carries the `verifyRequest
  expectedTag` row.
- The CLI demo (`npm run demo`) now closes with a
  per-label key resolver segment: two fresh ed25519
  key pairs mint a dual-label fixture (`merchant` via
  `signRequest`, `gateway` appended via
  `addSignature`), showing `verifyAllLabels`'
  `keyResolvers` option — both labels verify through
  their own keystore resolvers, the gateway label
  alone is rejected with `KEY_RESOLUTION_FAILED` and
  its pinned reason when its resolver returns
  `undefined` (its key id rotated out of the gateway
  keystore) while the merchant label still verifies,
  a label missing from the map falls back to the
  global `keyResolver`, and a non-function map value
  throws the pinned configuration error before any
  verification runs. `DemoResult` gains the segment's
  dual-signed request, three per-label result arrays
  and the thrown configuration error, and the demo
  tests gain two cases pinning the segment
  end-to-end (750 tests in total). Every fixture is
  fixed — injected clock, no network, no randomness
  in the printed lines.
- The CLI demo (`npm run demo`) now closes with a
  per-label keyid pinning segment: two fresh ed25519
  key pairs mint a dual-label fixture (`merchant` via
  `signRequest`, `gateway` appended via
  `addSignature`), showing `verifyAllLabels`'
  `expectedKeyIds` option — both labels verify under
  a fully matching map, the gateway label alone is
  rejected with `KEYID_MISMATCH` and its pinned
  reason under a wrong per-label pin while the
  merchant label still verifies, a label missing
  from the map falls back to the global
  `expectedKeyId` (the matching fallback verifying
  both labels, the empty-map fallback failing the
  gateway label against the merchant global pin),
  and an empty-string map value throws the pinned
  configuration error before any verification runs.
  `DemoResult` gains the segment's dual-signed
  request, four per-label result arrays and the
  thrown configuration error, and the demo tests
  gain two cases pinning the segment end-to-end
  (748 tests in total). Every fixture is fixed —
  injected clock, no network, no randomness in the
  printed lines.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `algFallback: "infer"` — the
  algorithm-inference verify form a receiver uses for
  foreign signers that omit the optional `alg`
  parameter, which the existing verify rows never
  timed (their fixtures always carry `alg` on the
  wire). The fixture is the RFC 9421 Appendix B.2.5
  wire value verbatim (no `alg` parameter) verified
  against its pinned shared secret at an injected
  `now` equal to the vector's `created` instant.
  Every measured pass re-pins that the result is ok
  and that the inferred `alg` and the returned
  `keyId` equal their pinned values. The same wire's
  `VERIFICATION_ERROR` result without the opt-in, a
  wire `alg` contradicting the key's shape throwing
  the pinned configuration error, and a secp256k1 key
  shape with no supported mapping throwing the
  pinned cannot-infer configuration error are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run
  and now carries the `verifyRequest algFallback
  (infer)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expiredToleranceSec` — the
  expiry-grace verify form a receiver uses to accept a
  signature that expired moments ago, which the
  existing verify rows never timed (they rely on the
  default zero grace against fixtures that have not
  expired). The fixture is an ed25519 request signed
  outside timing with `created` pinned one hour before
  and `expires` pinned 30 seconds before the
  verifier's injected `now`, verified under a
  120-second grace. Every measured pass re-pins that
  the result is ok. The narrow-grace `EXPIRED` result
  (pinned code and reason), the acceptance exactly at
  the grace boundary, the rejection under the default
  zero grace and a hand-built born-expired signature's
  `INVALID_TIME_WINDOW` result inside a wide grace are
  asserted outside timing. The README Benchmarks table
  was refreshed wholesale from one real run and now
  carries the `verifyRequest expiredToleranceSec
  (120s grace)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyAllLabels` with `keyResolvers` — the
  per-label key-resolution verify form a multi-party
  receiver uses when each signer's keyids live in a
  separate keystore (the merchant's and the gateway's
  own resolvers), which the existing multi-label
  verify row never timed (it passes static keys, so
  the per-label resolver lookups were never a
  measured cost). The fixture is a dual-label
  ed25519 request signed outside timing with
  `created` pinned under two pinned keyids, each
  belonging to its own resolver, verified with a
  fully resolving `keyResolvers` map. Every measured
  pass re-pins that both results are ok, in wire
  order, and that each returned `keyId` equals its
  label's pinned value. The one-label unresolved
  result (exactly `KEY_RESOLUTION_FAILED` with the
  pinned reason, the other label still verifying),
  the global-`keyResolver` fallback for a label
  missing from the map, the non-function map value's
  pinned configuration error and the
  `keyResolvers`-with-`keys` mutual-exclusion
  configuration error are asserted outside timing.
  The README Benchmarks table was refreshed
  wholesale from one real run and now carries the
  `verifyAllLabels keyResolvers (2 labels)` row.
- The benchmark (`npm run bench`) now also measures
  `verifyAllLabels` with `expectedKeyIds` — the
  per-label key-id binding verify form a multi-party
  receiver uses to pin each signer's key
  independently (key-confusion defense), which the
  existing multi-label verify row never timed (it
  passes no pins, so the per-label pin resolution
  and keyid comparisons were never a measured
  cost). The fixture is a dual-label ed25519
  request signed outside timing with `created`
  pinned under two pinned keyids, verified with a
  fully matching `expectedKeyIds` map. Every
  measured pass re-pins that both results are ok,
  in wire order, and that each returned `keyId`
  equals its label's pinned value. The one-label
  mismatched-pin result (exactly `KEYID_MISMATCH`
  with the pinned reason, the other label still
  verifying), the global-`expectedKeyId` fallback
  for a label missing from the map (both the
  matching and the mismatching halves) and the
  empty-string map value's pinned configuration
  error are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from
  one real run and now carries the
  `verifyAllLabels expectedKeyIds (2 labels)` row.
- The CLI demo (`npm run demo`) now closes with a
  required-nonce segment: one key pair mints a
  nonce-carrying signature via `signRequest` and two
  hand-built signatures via the public signature-base
  primitives (no nonce at all, and an empty-string
  nonce — the wire shapes a foreign signer sends),
  showing `verifyRequest`'s `requireNonce` option —
  the nonce-carrying signature verifies, both
  hand-built ones are rejected after the
  cryptographic check with `MISSING_NONCE` and its
  pinned reason (an empty-string nonce counts as
  missing), and the same nonce-less signature
  verified with no option set shows the default (no
  check is made, so the replay-cache bypass the
  option closes stays visible). `DemoResult` gains
  the segment's three signed requests and four
  verification results, and the demo tests gain two
  cases pinning the segment end-to-end (746 tests
  in total). Every fixture is fixed — no network,
  no wall clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `expectedKeyId` — the key-id
  binding verify form a receiver uses to pin the
  expected signer key (key-confusion defense), which
  the existing verify rows never timed (they pass no
  pin, so the post-cryptographic keyid comparison was
  never a measured cost). The fixture is one ed25519
  request signed outside timing with `created` pinned
  under a pinned keyid, verified with a matching
  `expectedKeyId`. Every measured pass re-pins that
  the result is ok and its returned `keyId` equals
  the pinned value. The mismatched-pin result
  (exactly `KEYID_MISMATCH` with the pinned reason),
  the hand-built no-`keyid` result (the same code
  with the `got no keyid` reason shape) and that same
  signature's acceptance without the option are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the `verifyRequest expectedKeyId` row.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `clockSkewToleranceSec` — the
  clock-skew verify form a receiver uses to tolerate a
  signer whose clock runs ahead, which the existing
  verify rows never timed (they rely on the 60-second
  default against fixtures that are not dated in the
  future, so a caller-pinned future-`created` window
  was never a measured cost). The fixture is one
  ed25519 request signed outside timing with `created`
  pinned 30 seconds ahead of the verifier's injected
  `now`, verified under a 120-second tolerance. Every
  measured pass re-pins that the result is ok. The
  narrow-tolerance result (exactly
  `CREATED_IN_FUTURE` with the pinned reason), the
  exact-boundary acceptance (the comparison is a
  strict `>`) and the no-option acceptance (the
  60-second default covers the 30-second skew) are
  asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and
  now carries the
  `verifyRequest clockSkewToleranceSec (120s)` row.
- The CLI demo (`npm run demo`) now closes with a
  required-components segment: one key pair signs the
  same fixed payment request fully covered
  (`@method`, `@path`, `content-digest`) and covering
  only `@method`, showing `verifyRequest`'s
  `requiredComponents` coverage policy — the fully
  covered signature verifies, the narrow one is
  rejected before any cryptographic work with
  `MISSING_REQUIRED_COMPONENT` and its pinned reason,
  differently-cased required names still pass, a
  malformed list containing an empty string throws
  the pinned configuration error verbatim, and the
  narrow signature verified with no option set shows
  the default (no check is made). `DemoResult` gains
  the segment's two signed requests, four verification
  results and the thrown message, and the demo tests
  gain two cases pinning the segment end-to-end (744
  tests in total). Every fixture is fixed — no
  network, no wall clock.
- The CLI demo (`npm run demo`) now closes with an
  alg-fallback segment: the RFC 9421 Appendix B.2.5
  hmac-sha256 wire value — whose signature-input carries
  no `alg` parameter — is verified against its pinned
  shared secret with `algFallback: "infer"` (the
  algorithm is inferred from the secret key's shape and
  reported as `hmac-sha256`) and without the opt-in
  (the legacy `ed25519` default fails with
  `VERIFICATION_ERROR`), and the two caller
  configuration errors print verbatim: a wire
  `alg="ed25519"` paired with a secret key, and the
  no-`alg` wire paired with a secp256k1 key whose shape
  has no supported mapping. `DemoResult` gains the
  segment's wire request, two verification results and
  the two thrown messages, and the demo tests gain two
  cases pinning the segment end-to-end (742 tests in
  total). Every fixture is fixed — no network, no wall
  clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `requireExpires` — the
  expiry-presence verify form a receiver uses to
  refuse a signature that carries no `expires` and so
  has no bounded lifetime, which the existing verify
  rows never timed (they pass no requirement, so the
  post-cryptographic presence check was never a
  measured cost). The fixture is one ed25519 request
  signed outside timing with `created` and `expires`
  both pinned, verified at an injected `now` equal to
  `created`. Every measured pass re-pins that the
  result is ok. The hand-built no-`expires` result
  (exactly `MISSING_EXPIRES` with the pinned reason)
  and that same signature's acceptance without the
  option are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one
  real run and now carries the
  `verifyRequest requireExpires` row.
- The CLI demo (`npm run demo`) now closes with an
  application-tag segment: one key pair signs the same
  fixed request with the pinned tag
  (`payment-webhook-v1`), with another protocol's tag
  (`admin-api-v1`) and with no tag, showing
  `verifyRequest`'s `expectedTag` pin — the matching
  tag verifies, the other tag and the missing tag are
  each rejected with `TAG_MISMATCH` and its pinned
  reason, and the same tagged signature verified with
  no `expectedTag` pinned shows the default (no check
  is made). `DemoResult` gains the segment's three
  signed requests and four verification results, and
  the demo tests gain two cases pinning the segment
  end-to-end (740 tests in total). Every fixture is
  fixed — no network, no wall clock.
- The CLI demo (`npm run demo`) now closes with a Node
  trailers segment: three fixed mock
  `IncomingMessage`-shaped objects show
  `fromNodeRequest`'s trailer normalization — a parsed
  `trailers` object normalized to lowercase keys with
  multi-value fields trimmed and joined, a non-empty
  `rawTrailers` winning over a stale parsed object
  (duplicate raw names merged), and a message with no
  trailers gaining no `trailers` field at all — and a
  request whose `x-checksum` trailer is bound via a
  `;tr` covered component completes a sign ->
  `fromNodeRequest` -> verify round-trip.
  `DemoResult` gains the segment's three normalized
  requests, its signed request and its verification
  result, and the demo tests gain two cases pinning
  the segment end-to-end (738 tests in total). Every
  fixture is fixed — no network, no wall clock.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` with `maxSignatureAgeSec` — the
  age-capped verify form a receiver uses to bound how
  long a signed message stays replayable when it
  carries `created` but no `expires`, which the
  existing verify rows never timed (they pass no cap,
  so the age computation and its strict `>` boundary
  check were never a measured cost). The fixture is
  one ed25519 request signed outside timing with
  `created` pinned, verified at an injected `now`
  60 seconds later under a 300-second cap. Every
  measured pass re-pins that the result is ok. The
  past-cap result (exactly `SIGNATURE_TOO_OLD` with
  the pinned reason) and the no-`created` bypass (a
  hand-built undated signature still verifies at the
  past-cap instant) are asserted outside timing. The
  README Benchmarks table was refreshed wholesale
  from one real run and now carries the
  `verifyRequest maxSignatureAgeSec (300s cap)` row.
  The bench performs zero network I/O and no
  wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `verifyRequest` through a `keyResolver` — the
  keyid→key resolution verify form a gateway runs while
  its keys rotate by keyid, which the existing verify rows
  never timed (they all pass a static `key`, and the
  `memoizeKeyResolver` rows time the resolver cache itself
  rather than a full verification through a resolver). The
  fixture is a plain Map keystore holding two pinned
  ed25519 public keys (generated once outside timing)
  under two pinned kids, with one signed fixture request
  per kid signed outside timing with `created` pinned and
  the verifier's `now` injected at the same instant.
  Every measured pass verifies both fixtures through the
  resolver and re-pins that each result is ok and each
  returned `keyId` equals its pinned kid. The
  unknown-keyid result (exactly `KEY_RESOLUTION_FAILED`
  carrying the unknown kid and the pinned reason) and the
  `key` + `keyResolver` mutual-exclusion configuration
  error are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `verifyRequest keyResolver
  (2 keyids)` row. The bench performs zero network I/O
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.restoreSnapshot` — the snapshot-restore
  path a gateway runs at cold start to rebuild its key
  store from the persisted envelope in an existing store
  object, which the existing `exportSnapshot` row never
  timed (it measures only the serialize direction, and
  the static `restore` construction behind the `resolve`
  rows was never itself a measured op). The fixture
  envelope is a pinned three-key set (ed25519 / P-256 /
  RSA, generated once outside timing) exported outside
  timing from a source store refreshed once through a
  counting fake fetch at a pinned fetch time under a
  120-second TTL; the target store is primed through its
  own counting fake fetch with a different single key at
  the instant exactly one TTL later. Every measured pass
  restores the envelope and re-pins that the pinned kid
  resolves, that `stats()` is identical before and after
  the restore (restoring resets no counters), and that
  `isStale()` counts from the envelope's original fetch
  time — so the just-restored store is already stale at
  the boundary instant. The corrupt-envelope rejections
  (an unsupported version and an empty kid, each with its
  pinned full message) and the fail-closed
  unchanged-store assertions are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `restore` row.
  The bench performs zero network I/O and no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a clock
  tolerance segment: a signature created 120 seconds in
  the future verifies under a wide
  `clockSkewToleranceSec` (180 seconds) and is rejected
  with `CREATED_IN_FUTURE` under a narrow one (90), while
  the no-option defaults are pinned by a 30-second-future
  signature verifying and the 120-second-future one
  failing (default skew 60); a signature 30 seconds past
  its `expires` verifies under a wide
  `expiredToleranceSec` grace (60 seconds) and is
  rejected with `EXPIRED` under a narrow grace (20),
  while a signature just 1 second past `expires` fails
  with no option passed (default grace 0 — strict).
  `DemoResult` gains the segment's three signed requests
  and seven verification results, the demo tests gain two
  cases pinning the segment end-to-end (736 tests in
  total), and every clock in the segment is injected —
  no network, no wall clock, no randomness in the
  printed lines.
- The CLI demo (`npm run demo`) now closes with a maximum
  signature age segment: one ed25519 signature pinned at
  the demo's fixed `created` instant with no `expires` is
  verified under the opt-in `maxSignatureAgeSec` cap
  (300 seconds) at three injected instants — inside the
  cap (verifies), exactly at the cap (verifies: the age
  check is a strict `>`), and one second past it
  (rejected with `SIGNATURE_TOO_OLD`) — and a hand-built
  signature carrying no `created` at all (only `expires`,
  `keyid` and `alg`) still verifies at the past-cap
  instant, because a signature with no `created` bypasses
  the age check entirely (orthogonal to
  `requireCreated`). `DemoResult` gains the segment's
  signed requests and four verification results, the demo
  tests gain two cases pinning the segment end-to-end
  (734 tests in total), and every clock in the segment is
  injected — no network, no wall clock, no randomness in
  the printed lines.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.fromSnapshot` — the snapshot-restore path a
  single-process verifier runs at startup to rebuild its
  replay cache from the persisted snapshot, which the
  existing `exportSnapshot` row never timed (it measures
  only the serialize direction). The fixture is a pinned
  envelope exported outside timing from a fixed-clock
  source cache holding four live nonces under a
  3,600-second TTL. Every measured pass restores the
  envelope, re-pins the rebuilt cache's `size` and zeroed
  `stats()` counters, and re-checks every restored nonce —
  each must still report a replay. The expired-at-restore
  drop (a clock advanced past the oldest entry's TTL drops
  exactly that entry) and the corrupt-envelope rejections
  (unsupported version, malformed entry) are asserted
  outside timing. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `restore` row. The bench performs zero network I/O
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.refresh` single-flight merging — the
  concurrent refresh path a gateway hits at cold start /
  rotation time, which the existing serial
  `refreshIfStale` row never timed. The fixture is a
  one-key store (ed25519, generated once outside timing)
  primed once and made stale by advancing its injected
  clock exactly to the 120-second TTL boundary; a counting
  fake fetch serves one pinned JWKS document and resolves
  on a microtask tick. Every measured batch launches
  eight concurrent `refresh()` calls and re-pins that the
  fetch count and `stats().refreshes` each advanced by
  exactly one and that the pinned kid resolves; a
  shared-failure batch (all eight waiters receiving the
  same rejection from exactly one fetch) and the
  failure-not-cached retry are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the second `refresh`
  row. The bench performs zero network I/O and no
  wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `resolveComponent` — the per-component resolution every
  sign and verify pays once per covered component — which
  the existing `buildSignatureBase` row only ever timed
  bundled with the `@signature-params` serialization.
  The fixture is a fixed eighteen-case corpus over one
  pinned request (query string, status, trailers and an
  associated request attached): ten derived components,
  two plain header fields and six parameterized forms
  (`;bs`, `;sf`, `;key="…"`, `;tr`, and `;req` on both a
  derived component and a header field). Every measured
  pass re-pins each case's resolved value against the
  hand-written expectation, and the unsupported-parameter
  rejection is asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `resolve` row. The bench
  performs zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.stats()` — the observability snapshot a
  verifier's monitoring polls on every tick (live entries
  counted against the injected clock, plus the detached
  hits / misses / evictions counters) — which the existing
  `check` and `exportSnapshot` rows never timed (the check
  row reads `stats()` only once, as a post-run self-check).
  The fixture is a fixed-clock cache (capacity 6, TTL 100
  seconds) whose construction is pinned end to end: one
  entry LRU-evicted during construction and one entry
  exactly at its TTL boundary at the stats instant
  (expired but still in the map), with five live entries.
  Every measured pass re-pins the snapshot against the
  hand-written expectation `{ size: 5, hits: 1, misses: 7,
  evictions: 1 }`, where `size` counts only the live
  entries; the detached-copy semantics and the empty-cache
  all-zero reading are asserted outside timing. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `stats` row. The bench performs
  zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures the
  ed25519 JWK round trip — the generic `exportPublicKeyJwk` →
  JSON stringify/parse → `importPublicKeyJwk` path for the
  library's default algorithm, in the OKP JWK shape a JWKS
  document actually distributes for ed25519 — which the
  existing per-curve JWK rows (P-256 / P-384 / P-521 /
  RSA-2048) and the ed25519 PEM row never timed. The row
  reuses the shared JWK round-trip helper (extended with an
  optional per-export shape check): every measured pass
  re-pins the exported JWK item by item (`kty` OKP, `crv`
  Ed25519, a non-empty `x`, and no private `d` field), and
  outside timing the re-imported public key must verify a
  signature made with the original private key. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `roundtrip` row. The bench
  performs zero network I/O and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.refreshIfStale` on a stale snapshot — the
  refresh direction a gateway pays when its key snapshot
  ages out (stale check against the injected clock, one
  fetch, JWK import and kid-index rebuild), which the
  existing `resolve` and `exportSnapshot` rows never
  timed. The store's injected clock is advanced by
  exactly its 120-second TTL before every measured call
  (stale under the `>=` rule), a counting fake fetch
  serves one pinned JWKS document (zero network), and
  every measured pass self-checks that the call reported
  a refresh, that the fetch count advanced by exactly
  one, and that the pinned kid resolves afterwards; the
  not-stale case (returns false, fetch count unmoved) is
  asserted outside timing. An async measurement helper
  (`measureAsync`) was added for promise-returning paths.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `refresh` row.
- The CLI demo (`npm run demo`) now closes with a
  ReplayCache clear segment: a fresh `ReplayCache` under
  the demo's fixed clock records one pinned nonce (a
  miss) and reports its repeat as a replay (a hit), then
  `clear()` is called and the emptied state is printed —
  `size` 0 and `stats()` all zero — after which the same
  nonce checks in as fresh again and the counters
  re-accumulate from zero. Earlier replay demo segments
  showed the cache recording, snapshotting and reporting
  its counters, but never the explicit reset a gateway
  runs at key rotation or for test isolation instead of
  waiting for TTL expiry. `DemoResult` carries the three
  check outcomes, the pre-clear stats, the post-clear
  size and stats, and the post-recheck stats, and the
  demo tests pin the fields and the printed lines. The
  clock is injected; the segment performs zero network
  I/O.
- The benchmark (`npm run bench`) now also measures
  `ReplayCache.exportSnapshot` — the snapshot export a
  single-process verifier runs to persist its tracked
  nonces before a restart (live entries filtered against
  the injected clock and assembled into the detached
  `{ v: 1, entries }` envelope) — over a fixed-clock cache
  whose map holds four recorded nonces: one already
  expired under the TTL and three live nonces at pinned
  `seenAt` values. Every measured pass re-pins the whole
  exported snapshot: version 1, exactly the live-entry
  count, every entry item by item (nonce and `seenAt`,
  first and last included), and the expired nonce absent;
  the detached-copy semantics and the empty-cache export
  (`{ v: 1, entries: [] }`) are asserted outside timing.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `export` row.
  The bench performs zero network I/O and no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a
  ReplayCache observability segment: a small
  `ReplayCache` (capacity 3, 100-second TTL) under an
  injected clock is driven through a pinned script — two
  fresh nonces (misses), a repeat of the first (a hit),
  a third fresh nonce filling the cache, a fourth whose
  insertion evicts the least recently seen entry, and,
  after the clock advances past the TTL, a fifth whose
  insertion reclaims one expired entry — and `stats()`
  (`{ size, hits, misses, evictions }`) is printed after
  every step with each reading hand-pinned. A returned
  snapshot overwritten with 999s is shown to leave the
  cache unchanged: `stats()` hands out a detached copy,
  never a view. Earlier replay demo segments used a
  cache without ever presenting its observability
  counters, the health view a gateway operator watches.
  `DemoResult` carries the six check outcomes, the
  per-step stats and the post-mutation stats, and the
  demo tests pin the fields and the printed lines.
  Every clock is injected; the segment performs zero
  network I/O.
- The CLI demo (`npm run demo`) now closes with a JWKS
  observability segment: a `JwksKeyStore` is driven
  through one `refresh()` over a counting fake fetch
  (zero network) under an injected clock, and its
  observability surface is printed at three pinned
  instants — before any refresh (`lastRefreshedAt`
  `null`, `isStale()` `true`), at the fetch instant
  (`lastRefreshedAt` pinned, `isStale()` `false` inside
  the 120-second TTL), and at exactly the TTL boundary
  (`isStale()` `true` under the `>=` rule). At the
  boundary a request signed under the pinned keyid
  still verifies through the stale snapshot, a direct
  resolve of the pinned keyid is a hit and a direct
  resolve of an unknown keyid is a miss, and the final
  `stats()` is printed with every field pinned
  (`{ refreshes: 1, refreshFailures: 0, hits: 2,
  misses: 1 }` — the boundary verification contributes
  the first hit). Earlier JWKS demo segments each read
  one slice of store state, so the combined health view
  an operator watches was invisible to demo readers.
  `DemoResult` carries the before/after/boundary reads,
  the fetch count, the signed request and its
  verification, both resolve outcomes and the final
  stats, and the demo tests pin the fields and the
  printed lines. Every clock is injected and no key
  material is printed.
- The benchmark (`npm run bench`) now also measures
  `JwksKeyStore.exportSnapshot` — the snapshot export a
  gateway runs to persist its key store before a restart
  (each key re-exported through the JWK exporter for its
  type and assembled into the `{ v: 1, fetchedAtSec, keys }`
  envelope) — over an offline-restored store holding the
  three supported key shapes (ed25519, P-256 and RSA, one
  freshly generated key pair per shape, generated once
  outside timing) under hand-pinned kids at a pinned
  `fetchedAtSec`. Every measured pass re-pins the whole
  exported envelope: version, fetch time, exactly the
  three pinned kids in restore order, the per-shape `kty`
  dispatch (the EC entry naming P-256), and public-only
  JWK material with no `"d"` member; a never-refreshed
  store's export refusal is asserted outside timing with
  the pinned full message. The README Benchmarks table
  was refreshed wholesale from one real run and now
  carries the `export` row. The bench performs zero
  network I/O and no wall-clock assertions.
- The CLI demo (`npm run demo`) now closes with a JWKS
  snapshot persistence segment: a `JwksKeyStore` is
  refreshed once through a counting fake fetch (zero
  network) under an injected clock, its snapshot is
  exported with `exportSnapshot()` (only the version,
  the original `fetchedAtSec` and the key count are
  printed — never JWK material), the snapshot crosses a
  JSON text round-trip, and `JwksKeyStore.restore()`
  cold-starts a new store from it with the fetch count
  unchanged, its freshness still counting from the
  original fetch. A detached copy of the snapshot with
  private `"d"` material mixed into its key is fed to
  the restored store's `restoreSnapshot()` and printed
  rejected with the full fail-closed message; a request
  signed under the snapshotted keyid is verified through
  the restored store only after that rejection, so the
  passing verification proves the failed restore left
  the good snapshot untouched. A never-refreshed store's
  `exportSnapshot()` is printed refused outright.
  Earlier JWKS demo segments restored a hand-built
  snapshot or fetched live, so the persisted cold-start
  path — and both of its refusal surfaces — was
  invisible to demo readers. `DemoResult` carries the
  exported snapshot, both fetch counts, the restored
  store's size and freshness timestamp, the signed
  request, its verification and both error messages,
  and the demo tests pin the fields and the printed
  lines. Every clock is injected and no key material is
  printed, so the segment's printed lines are identical
  between runs.
- The CLI demo (`npm run demo`) now closes with an RSA
  v1_5 signing segment: the same fixed payment request
  is signed under `rsa-v1_5-sha256` (RSASSA-PKCS1-v1_5,
  RFC 9421 §3.3.2 — the legacy-interop algorithm) with
  an RSA key pair from `generateRsaV15KeyPair`, generated
  once per process, and its `Signature-Input` is printed
  (algorithm and keyid, never key bytes). The same
  request is signed a second time with the same key and
  the two signatures are shown byte-identical — v1_5 is
  deterministic, unlike RSA-PSS — verification is
  printed passing with its label / keyid / alg / nonce
  identity, and the same request with its body tampered
  by one byte is printed rejected with
  `BODY_DIGEST_MISMATCH`. Every earlier RSA demo segment
  signed with RSA-PSS or only guarded RSA keys, so an
  actual v1_5 signing — and its determinism — was
  invisible to demo readers. Outside the printed lines
  the demo asserts the verified identity, the
  byte-identity of the two signatures and the tamper
  rejection code against hand-pinned expectations.
  `DemoResult` carries both signed requests, the
  determinism verdict and both verification results,
  and the demo tests pin the fields and the printed
  lines. Only the determinism verdict is printed, never
  the signature bytes, so the segment's printed lines
  are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  signature-input value construction segment: the main
  line's covered components and fixed parameters are run
  through `signatureInputValue` — the low-level builder
  `signRequest` uses for one label's `Signature-Input`
  member (`label=` plus the serialized inner list and
  parameters) — and the built value is printed and
  asserted, outside the printed lines, to equal both a
  hand-pinned expectation and the main signed request's
  actual `signature-input` header byte for byte. A second
  call under a different label, over a shorter covered
  set and with all six parameter slots set (expires,
  nonce and tag included), is printed as well, its
  parameters serializing in the fixed
  created/expires/keyid/alg/nonce/tag order. Every
  earlier demo segment consumed the finished header, so
  how one label's member is built was invisible to demo
  readers. `DemoResult` carries both built values, and
  the demo tests pin the fields and the printed lines.
  Every input is a fixed constant, so the segment's
  printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  normalized header lookup segment: a fixed header record
  — one field stored under a mixed-case key as a padded
  two-element array, one single string field — is read
  with `getHeader`, the normalized lookup the verifier
  itself uses (the lookup name's case need not match the
  stored key, a multi-value field comes back trimmed and
  joined with ", ", a single string value comes back
  exactly as stored, and a missing field comes back
  `undefined`), and the same record is read with
  `getHeaderRaw` so the two results print side by side:
  the raw read preserves every element's padding, which
  is exactly the difference that makes the two reads easy
  to confuse and exactly why only the raw read may feed a
  `;bs` component. Every earlier demo segment read
  headers only through a full sign/verify path (the
  parsing segments used `getHeaderRaw` alone), so the
  normalized lookup — and its contrast with the raw read
  — was invisible to demo readers. Outside the printed
  lines the demo asserts every lookup result equals the
  hand-pinned expectations. `DemoResult` carries the
  fixture record and all five lookup results, and the
  demo tests pin the fields and the printed lines. Every
  input is a fixed constant, so the segment's printed
  lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a JWKS
  refresh and rotation segment: a `JwksKeyStore` over a
  counting fake JWKS fetch (zero network) and an injected
  clock is driven through `refreshIfStale()` — the first
  call loads the pre-rotation key (fetch count 1) and a
  request signed under the old keyid verifies through the
  store; a second call 60 seconds into the 120-second TTL
  returns `false` and fetches nothing; past the TTL, with
  the fake endpoint serving only the rotated key, a third
  call returns `true` (fetch count 2), a request signed
  under the rotated keyid verifies, and the retired
  keyid's still-valid signature is rejected with
  `KEY_RESOLUTION_FAILED` because its keyid no longer
  resolves. Every earlier JWKS demo segment restored a
  snapshot and never fetched, so the stale-refresh /
  rotation pick-up — the moment a verifier starts
  trusting a new key and stops trusting the retired one —
  was invisible to demo readers. Outside the printed
  lines the demo asserts every return value, fetch count
  and verified identity equal the hand-pinned
  expectations. `DemoResult` carries the three
  return values, the fetch counts after each probe, both
  signed requests and all three verifications, and the
  demo tests pin the fields and the printed lines.
  Because `refreshIfStale()` is asynchronous, `runDemo()`
  is now `async` (returning `Promise<DemoResult>`) and
  the demo's entry point awaits it; every demo test
  awaits it in turn. Both segment key pairs are fresh
  ed25519 pairs and the clock is injected, so the
  segment's printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with an RSA
  JWK key distribution segment: the RSA public key is
  exported with `exportPublicKeyJwkRsa` (only the JWK's
  `kty` and the `n`/`e` lengths are printed — never the
  full modulus), read back through a JSON wire
  round-trip with `importPublicKeyJwkRsa`, and
  completes an `rsa-pss-sha512` sign -> verify
  round-trip, printed passing. Every earlier JWK
  segment covered only the ed25519 (`kty: "OKP"`) and
  EC (`kty: "EC"`) forms, so the RSA form
  (`kty: "RSA"` + `n`/`e`) — the member shape JWKS
  documents carry most often — was invisible to demo
  readers on its own. The EC segment's P-256 JWK fed
  to the RSA importer is printed rejected with the
  importer's exact kty-mismatch error. Outside the
  printed lines the demo asserts the JWK's shape
  (kty, the 342-character `n` length of a 2048-bit
  modulus and the `AQAB` exponent) and the verified
  identity equal the hand-pinned expectations.
  `DemoResult` carries the exported JWK, the signed
  request, the verification and the mismatch message,
  and the demo tests pin the fields and the printed
  lines. The RSA key pair is generated once per
  process (like the RSA guard segment's keys); only
  the JWK shape and the round-trip semantics are
  asserted, so the segment's printed lines are
  identical between runs.
- The CLI demo (`npm run demo`) now closes with an EC
  JWK key distribution segment: one fresh key pair is
  generated per NIST curve (P-256, P-384, P-521), each
  public key is exported with its curve's
  `exportPublicKeyJwkP*` helper (only the JWK's
  `kty`/`crv` and `x` length are printed), read back
  through a JSON wire round-trip with the matching
  `importPublicKeyJwkP*` helper, and completes a
  sign -> verify round-trip under its curve's RFC 9421
  algorithm, printed passing. Every earlier JWK segment
  covered only the ed25519 (`kty: "OKP"`) form, so the
  EC form (`kty: "EC"` + `crv` + `x`/`y`) — the key
  shape gateways and webhook verifiers distribute most
  often — was invisible to demo readers. A P-256 JWK
  fed to the P-384 importer is printed rejected with
  the importer's exact crv-mismatch error. Outside the
  printed lines the demo asserts every JWK's shape
  (kty, crv and both coordinate lengths: 43 / 64 / 88
  base64url chars) and every verified identity equal
  the hand-pinned expectations. `DemoResult` carries
  the exported JWKs, the signed requests, the
  verifications and the mismatch message, and the demo
  tests pin the fields and the printed lines. The key
  pairs are fresh on every run; only the JWK shapes
  and the round-trip semantics are asserted, so the
  segment's printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  Signature field parsing segment: the main signed
  request's `signature` value is parsed with
  `parseSignatureField` for the main label, and the
  extracted bytes' length (64 bytes, the ed25519 length)
  and a short hexadecimal prefix are printed — never the
  full signature. The same field is then parsed for a
  hand-pinned unknown label, which is printed rejected
  with the parser's exact `not present in Signature
  field` error. Every earlier segment showed the
  Signature-Input parse layer or consumed the signature
  bytes only inside verification, so how a verifier gets
  the raw bytes it feeds to the cryptographic check was
  invisible to demo readers. Outside the printed lines
  the demo asserts the extracted bytes equal, byte for
  byte, the bytes the signer emitted (decoded
  independently from the header's base64 member), that
  their length equals the pinned ed25519 length, and
  that the unknown-label rejection equals the pinned
  message (the same message shape the parser suites pin
  for their own absent labels). `DemoResult` carries the
  extracted bytes, their hex prefix and the rejection
  message, and the demo tests pin the fields and the
  printed lines. The main key pair is fresh on every
  run, so the printed prefix differs between runs while
  its shape and the rejection line are identical; every
  other input is a fixed demo constant.
- The CLI demo (`npm run demo`) now closes with a
  multi-value header combination segment: a fixed request
  carrying one field twice (a padded two-element array) is
  combined with `joinHeaderValues` and the combination is
  printed — each element trimmed, the elements joined with
  ", " per RFC 9421 §2.5, which is also the wire value the
  signer emits for the field. A request signed over the
  repeated field is printed verifying, and the same request
  with the field replaced by the wrong combination (a bare
  comma join, the space after the comma dropped) is printed
  rejected with `SIGNATURE_MISMATCH`, because the verifier
  rebuilds a different signature base from the wrongly
  joined value. Every earlier segment consumed the
  combination only inside sign/verify or the Node adapter,
  so the combination rule itself — the multi-value
  interop pitfall — was invisible to demo readers. Outside
  the printed lines the demo asserts the combination
  character for character, the signer's emitted wire
  value, the verified identity and the rejection code
  equal the hand-pinned expectations (the same combination
  shape and code
  `test/multiValueHeaderWhitespace.test.ts` pins for its
  own padded fixture). `DemoResult` carries the
  combination, the signed request and both verification
  results, and the demo tests pin the fields and the
  printed lines. Every input is a fixed demo constant, so
  the segment is byte-identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  component-resolution segment: each covered component of
  the main signed request is run through `resolveComponent`
  — the per-component resolver `buildSignatureBase` applies
  — and printed as component -> resolved value (`@method`
  uppercased and `@authority` lowercased from the request
  target, `@path` from the URL, and the `content-digest`
  field's normalized value), and a detached illegal
  component id (`content-digest` carrying the unsupported
  `;zz` parameter) is printed rejected with the resolver's
  exact unsupported-parameter error. Every earlier segment
  showed the finished signature base or consumed resolution
  only inside sign/verify, so how one covered component
  becomes one base line — quoted-field, `;sf` / `;bs` /
  `;tr` and the other parameter semantics included — was
  invisible to demo readers. Outside the printed lines the
  demo asserts every resolved value and the rejection
  message equal the hand-pinned expectations (the same
  values the signature-base segment's printed lines carry,
  and the same `;zz` rejection shape
  `test/reqComponent.test.ts` pins on the sign side).
  `DemoResult` carries the resolved pairs and the rejection
  message, and the demo tests pin the fields and the
  printed lines. To make the segment possible,
  `resolveComponent` is now also exported from the package
  entry point (it was previously reachable only inside
  `src/components.ts`). Every input is a fixed demo
  constant, so the segment is byte-identical between runs.
- The benchmark (`npm run bench`) now also measures
  `signRequest` end to end — one complete signing of the
  shared fixture (signature-base construction, the ed25519
  cryptography and the `signature-input` / `signature`
  header serialization) as a standalone
  `signRequest (ed25519, end-to-end)` row. The fixture is
  fixed (`created=1700000000`, `keyid="bench-key"`,
  `alg="ed25519"`, one ed25519 key pair generated once
  outside timing), and every measured pass re-pins the
  output shape — both signature headers present, the full
  `signature-input` value and the single label `sig1`
  equal to hand-written expectations, the `content-digest`
  header equal to the pinned fixture digest, and the
  signature a single member decoding to 64 bytes — while
  outside timing the signed request is asserted to verify
  with the pinned identity (label / keyid / alg) and the
  same request with its body tampered by one byte
  (amount 100 -> 101) is rejected with
  `BODY_DIGEST_MISMATCH`. The per-algorithm scenario rows
  also time `signRequest`, but they discard the output
  unchecked, so this is the first checked total for the
  sign side. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the new
  `sign` row. The bench performs zero network I/O and no
  wall-clock assertions, and never prints key or
  signature bytes.
- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-521 signing segment: the same fixed payment request is
  signed under `ecdsa-p521-sha512` with a P-521 key pair
  from `generateP521KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments show the ed25519 main line,
  the hmac-sha256 gateway line and the P-256 / P-384
  curves, so the widest NIST curve — whose signatures are
  the 132-octet raw r‖s form of RFC 9421 §3.3.6 (66 octets
  per limb), completing the ladder against the P-256
  segment's 64-octet form and the P-384 segment's 96-octet
  form — was invisible to demo readers. Outside the
  printed lines the demo asserts the verified identity
  (label, keyid, alg, nonce) and the tamper rejection
  code equal the hand-pinned expectations (the same
  identity and code `test/ecdsaP521.test.ts` pins for its
  round-trip and tampered-body cases). `DemoResult`
  carries the signed request and both verifications, and
  the demo tests pin the fields, the 132-octet wire
  length and the printed lines. The P-521 key pair is
  fresh on every run, so the signature bytes differ
  between runs while every printed line is identical.

- The CLI demo (`npm run demo`) now closes with a
  Signature-Input parsing segment: the main signed
  request's `signature-input` value is read back raw with
  `getHeaderRaw` and printed truncated to a pinned
  72-character preview, then parsed with
  `parseSignatureInput` for the main label — the parsed
  label, keyid, alg, created and covered components are
  printed. Every earlier demo segment consumed the parsed
  parameters only inside `verifyRequest`, so the parse
  layer a receiver debugs first on an inbound request was
  invisible to demo readers. Outside the printed lines
  the demo asserts the raw value and every parsed field
  equal the hand-pinned expectations (the same parse
  shape the bench parser fixture pins for its own
  inputs), and a detached copy of the raw value with its
  closing parenthesis removed is asserted to throw the
  pinned `malformed Signature-Input: unterminated inner
  list` error — the fail-closed shape a receiver sees on
  a truncated header — whose rejection is printed.
  `DemoResult` carries the raw value, the parse result
  and the tamper error, and the demo tests pin the
  fields and the printed lines. The segment performs
  zero network I/O, and its printed lines are identical
  between runs.

- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-384 signing segment: the same fixed payment request is
  signed under `ecdsa-p384-sha384` with a P-384 key pair
  from `generateP384KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments show the ed25519 main line,
  the hmac-sha256 gateway line and the narrower P-256
  curve, so the wider NIST curve — whose signatures are
  the 96-octet raw r‖s form of RFC 9421 §3.3.5 (48 octets
  per limb), against the P-256 segment's 64-octet form —
  was invisible to demo readers. Outside the printed
  lines the demo asserts the verified identity (label,
  keyid, alg, nonce) and the tamper rejection code equal
  the hand-pinned expectations (the same identity and
  code `test/ecdsaP384.test.ts` pins for its round-trip
  and tampered-body cases). `DemoResult` carries the
  signed request and both verifications, and the demo
  tests pin the fields, the 96-octet wire length and the
  printed lines. No key bytes are printed, the segment
  performs zero network I/O, and its printed lines are
  identical between runs.

- The CLI demo (`npm run demo`) now closes with a
  ReplayCache snapshot persistence segment: a request
  signed with a fixed nonce verifies against a
  `ReplayCache` on the demo's fixed clock, the cache is
  exported with `exportSnapshot()`, and a new cache is
  rebuilt with `ReplayCache.restore()` — the restart.
  The same request verified against the restored cache
  is rejected with `NONCE_REPLAY`, and a fresh-nonce
  request verifies against the restored cache and is
  recorded only there. The demo's earlier replay segment
  shows the cache rejecting a second presentation inside
  one process, and its JWKS segment restores a *key*
  store from a snapshot, but the replay cache's own
  cross-restart persistence — the only way its seen
  nonces survive a restart — was invisible to demo
  readers. Outside the printed lines the demo asserts
  the exported snapshot equals the hand-pinned v1 entry
  (the segment nonce at the fixed verify instant), the
  restored rejection code equals the hand-pinned
  `NONCE_REPLAY` expectation (the same snapshot shape
  and code `test/replaySnapshot.test.ts` pins for its
  round-trip case), and the original cache still holds
  only the exported entry after the restored cache
  records the fresh nonce. `DemoResult` carries the
  signed request, both caches' verifications, the
  exported snapshot and both entry counts, and the demo
  tests pin the fields and the printed lines. Only the
  entry count, the fixed nonces and the first-seen
  instant are printed, the segment performs zero network
  I/O, and its printed lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with a
  Content-Digest algorithm guard segment: fixed values are
  run through `assertContentDigestAlg` — the two emittable
  algorithms (`sha-512`, the default, and `sha-256`) pass,
  while a fixed rejected corpus (unknown algorithms
  `sha-1` / `md5`, the empty string, wrong-case spellings
  `SHA-512` / `Sha-256`, a trailing-space spelling
  `sha-512 `, and the non-string values `undefined` /
  `null`) is rejected. The demo's earlier segments emit
  sha-512 / sha-256 `Content-Digest` headers and identify
  their algorithms on the read side with
  `contentDigestAlgOf`, but never showed this write-side
  fail-closed guard, so an unsupported digest algorithm
  being blocked before any hashing was invisible to demo
  readers. Outside the printed lines the demo asserts the
  accepted group all passed and every rejection message
  equals the hand-pinned expectations (the same messages
  `src/digest.ts` builds and the bench corpus /
  contentDigestAlg suite pin). `DemoResult` carries the
  accepted cases and the rejections, and the demo tests
  pin the fields and the printed lines. Each rejected
  value is printed only as a fixed printable label, the
  segment performs zero network I/O, and its printed
  lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with an ECDSA
  P-256 signing segment: the same fixed payment request is
  signed under `ecdsa-p256-sha256` with a P-256 key pair
  from `generateP256KeyPair` — the generator the library's
  ecdsa tests and bench corpus use — its `Signature-Input`
  is printed, verification passes, and the same request
  with its body tampered by one byte (amount 100 -> 101)
  is rejected with `BODY_DIGEST_MISMATCH`, because the
  covered `content-digest` no longer matches the body.
  The demo's earlier segments sign and verify with
  ed25519 and hmac-sha256 only, so the NIST-curve
  algorithm line — supported since the ecdsa-p256-sha256
  work and measured in the bench — was invisible to demo
  readers. Outside the printed lines the demo asserts
  the verified identity (label `sig1`, the segment's
  keyid, alg and nonce) and the tamper rejection code
  equal the hand-pinned expectations (the same identity
  and code `test/ecdsaP256.test.ts` pins for its
  round-trip and tampered-body cases). `DemoResult`
  carries the signed request and both verification
  results, and the demo tests pin the fields, the raw
  64-octet r||s wire form, and the printed lines. The
  segment prints only the `Signature-Input` (algorithm
  and keyid), never key or signature bytes, performs
  zero network I/O, and its printed lines are identical
  between runs even though the P-256 key pair itself is
  fresh per run.

- The CLI demo (`npm run demo`) now closes with an RSA
  modulus-length guard segment: fixed-shape keys are run
  through `assertRsaModulusLength` under a fixed caller
  context (`assertRsaModulusLength demo`) — an RSA public
  key exactly at the 2048-bit floor passes, while a
  1024-bit RSA public key (below the floor) and the main
  line's ed25519 public key (not an RSA key at all) are
  rejected. The demo's earlier segments sign and verify
  with RSA keys but never showed this setup-time guard, so
  a weak or wrong-type RSA key being blocked at the
  boundary was invisible to readers. Outside the printed
  lines the demo asserts the accepted case passed and
  both rejection messages equal the hand-pinned
  expectations (the same messages `src/keys.ts` builds
  from `MIN_RSA_MODULUS_BITS` and the bench corpus /
  rsaV15 suite pin). `DemoResult` carries the accepted
  case and the rejections, and the demo tests pin the
  fields and the printed lines. The RSA key pairs are
  generated once per process (only their types and
  modulus lengths matter), the segment prints only key
  types and modulus lengths, never key bytes, performs
  zero network I/O, and its printed lines are identical
  between runs.

- The CLI demo (`npm run demo`) now closes with an HMAC
  secret-length guard segment: fixed secrets built from a
  fixed fill byte (only their lengths matter) are run through
  `assertHmacSecretLength` — a 32-byte secret passes for
  `hmac-sha256` and a 64-byte secret passes for
  `hmac-sha512` (exactly each algorithm's RFC 2104 floor),
  while a secret one byte below each floor (31 bytes for
  sha256, 63 bytes for sha512) is rejected. The demo's
  earlier segments sign and verify with HMAC keys but never
  showed this setup-time guard, so a weak gateway secret
  being blocked at the boundary was invisible to readers.
  Outside the printed lines the demo asserts the accepted
  group all passed and both rejection messages equal the
  hand-pinned expectations (the same messages `src/keys.ts`
  builds from `MIN_HMAC_SECRET_BYTES` /
  `MIN_HMAC_SHA512_SECRET_BYTES` and the keyLength /
  hmacSha512 suites pin). `DemoResult` carries the accepted
  cases and the rejections, and the demo tests pin the
  fields and the printed lines. The segment prints only
  algorithm names and byte lengths, never key bytes,
  performs zero network I/O, and its printed lines are
  identical between runs.

- The CLI demo (`npm run demo`) now closes with a key-resolver
  memoization segment: a counting resolver over a fixed two-key
  store (the main demo key plus a fresh second keypair) is
  wrapped with `memoizeKeyResolver` — TTL at the library
  default of 300 seconds, the wrapper's injected clock pinned
  to the demo's fixed verify instant so no entry can expire
  mid-segment — and passed as `keyResolver` to
  `verifyRequest`. The main signed request verifies twice
  under the same keyid while the underlying resolver is
  called only once (the second verification is served from
  the cache), and a request signed under a second keyid then
  verifies and advances the underlying call count to two —
  the per-keyid cache shape a gateway in front of a remote
  keystore relies on, which the demo's earlier resolver
  segments (JWKS store, thumbprint pinning) never showed for
  a plain resolver. Outside the printed lines the demo
  asserts all three verifications passed and both call
  counts equal the hand-pinned expectations (1 after the
  repeat, 2 after the second keyid — the same counts
  `test/memoizeKeyResolver.test.ts` pins for its counting
  store). `DemoResult` carries the three verifications and
  both counts, and the demo tests pin the fields and the
  printed lines. The segment prints only keyids and counts,
  never key bytes, performs zero network I/O, and its
  printed lines are identical between runs.

- The CLI demo (`npm run demo`) now closes with a JWK
  public-key import segment: the main line's ed25519 public
  key is exported with `exportPublicKeyJwk`, carried through
  a JSON stringify/parse round-trip exactly as it would
  cross the wire to a gateway, and read back with
  `importPublicKeyJwk` — the inbound half of JWK key
  distribution, which the demo's thumbprint segment (export
  only) never showed and its PEM round-trip segment covers
  only for the PEM format. The main signed request verifies
  with the imported key, and a detached copy of the JWK
  whose `x` coordinate has its first character flipped —
  still a well-formed 32-byte value, so the import succeeds
  — is rejected at verification with `SIGNATURE_MISMATCH`.
  Outside the printed lines the demo asserts the
  imported-key verification, the tampered copy's rejection
  against the hand-pinned code (the rejection shape
  `test/jwk.test.ts` pins for an imported key), and that
  the tamper copy left the exported JWK untouched.
  `DemoResult` carries the exported JWK and both
  verifications, and the demo tests pin the fields and the
  printed lines. Only the exported JWK's shape is printed
  (never the key bytes), the segment performs zero network
  I/O, and no assertion depends on the fresh key's value.
- The CLI demo (`npm run demo`) now closes with a
  nonce-generation segment: `generateNonce()` (the default
  16-byte draw) and `generateNonce(32)` produce fresh
  replay-protection nonces, both printed with their shapes
  (22 / 43 base64url characters, decoding to 16 / 32 bytes),
  and the short nonce signs a fresh request whose verification
  prints the nonce parsed back out. Every earlier segment
  signs with a hand-written nonce constant; this segment
  shows the standard CSPRNG entry point a real signer uses
  instead, since a predictable nonce makes the replay cache
  meaningless. Outside the printed lines the demo asserts
  both shapes against hand-pinned expectations (character
  lengths, decoded byte lengths, base64url alphabet — the
  same shapes `test/generateNonce.test.ts` pins), that the
  two draws differ, and that the parsed-back nonce equals
  the signed one character for character. `DemoResult`
  carries the two nonces, the signed request and its
  verification, and the demo tests pin the fields and the
  printed lines. The segment performs zero network I/O; the
  nonce values are random per run (like the key pair), so
  no assertion depends on their values — only their shapes
  and the sign → verify round-trip are pinned.
- The benchmark (`npm run bench`) now also measures the
  PEM round trip — `exportPublicKeyPem` +
  `exportPrivateKeyPem` on one fixed ed25519 key pair (the
  same shape the CLI demo's PEM segment round-trips,
  generated once outside timing), re-imported with
  `importPublicKey` / `importPrivateKey` — the
  serialization-plus-reparse cost of handing keys over as
  PEM files (SPKI public / PKCS#8 private), the standard
  encoding for gateways, KMS tooling and peer verifiers,
  which the per-curve JWK round-trip rows do not cover.
  Every measured pass asserts both PEM first lines equal
  the hand-pinned type headers and that the re-imported
  public key's JWK thumbprint equals the original's;
  outside timing, the re-imported keys must additionally
  complete a sign → verify over the shared fixture. The
  README Benchmarks table was refreshed wholesale from
  one real run (on a heavily loaded shared host, so the
  absolute numbers are depressed versus earlier tables —
  they remain machine-local measurements, not
  guarantees) and now carries the `PEM round-trip
  ed25519` row. The bench performs zero network I/O and
  no wall-clock assertions; the key pair is random per
  run but no assertion depends on its value.
- The CLI demo (`npm run demo`) now identifies the digest
  algorithm of its already-emitted `Content-Digest` headers
  with `contentDigestAlgOf`, right after the sha-256 segment:
  the main line's header is identified as `sha-512` and the
  sha-256 peer line's as `sha-256`, while a pinned
  sha-1-shaped value (`sha-1=:abc=:`) comes back `undefined`
  — the fail-closed shape a caller must reject, since this
  library cannot emit sha-1. Outside the printed lines the
  demo asserts all three identifications equal the
  hand-pinned expectations. `DemoResult` carries the three
  identification results, and the demo tests pin the fields
  and the printed lines. The segment performs zero network
  I/O and its printed lines are identical between runs.
- The CLI demo (`npm run demo`) now enumerates the dual-signed
  request's signature labels right after the multi-party signing
  segment: `listSignatureLabels` is called over the merged
  `Signature-Input` value and the labels are printed in wire
  order (`sig1`, `gateway` — 2 labels), the enumerate-first
  entry point a receiver uses before verifying each label.
  Outside the printed lines the demo asserts the enumerated
  labels equal the hand-pinned expectation in set and order
  (the same two-label wire-order shape the benchmark pins as
  `PARSER_EXPECTED_LABELS`). `DemoResult` carries the
  enumerated labels, and the demo tests pin the field and the
  printed lines. The segment performs zero network I/O and
  its printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a
  throwing-verification segment: the main signed request is
  verified with `verifyRequestOrThrow`, which returns the
  verified identity (label `sig1`, the demo keyid, `ed25519`,
  the demo nonce) instead of a result object, and the same
  request with the body tampered by one byte (amount 100 ->
  101) is verified again — the call throws a `VerifyError`
  whose stable code is printed. Outside the printed lines the
  demo asserts the returned identity and the thrown code equal
  the hand-pinned expectations (`BODY_DIGEST_MISMATCH`, the
  same code the returning `verifyRequest` reports for that
  tamper) and that the caught error passes the `isVerifyError`
  guard. `DemoResult` carries the returned identity, the
  caught error and the guard result, and the demo tests pin
  all three. The segment performs zero network I/O and its
  printed lines are identical between runs.
- The CLI demo (`npm run demo`) now closes with a PEM key
  round-trip segment: the main line's ed25519 key pair is
  exported with `exportPublicKeyPem` / `exportPrivateKeyPem`,
  only the first line of each PEM (its type header — SPKI
  `-----BEGIN PUBLIC KEY-----` for the public key, PKCS#8
  `-----BEGIN PRIVATE KEY-----` for the private key, both
  hand-pinned) is printed, the PEM texts are imported back
  with `importPublicKey` / `importPrivateKey`, and the
  imported keys complete a fresh sign -> verify round-trip
  over the same fixed request. Outside the printed lines the
  demo asserts the round-trip verification passed and that
  both PEM headers equal the pinned expectations. The segment
  performs zero network I/O; its printed lines are identical
  between runs even though the key pair itself is fresh.
- The benchmark (`npm run bench`) now also measures
  `assertContentDigestAlg` — the content-digest algorithm
  guard every sign/verify that selects a digest algorithm
  pays before any hashing runs (only `sha-512` and
  `sha-256` can be emitted; anything else is a caller
  configuration error) — as one pass over a fixed ten-case
  corpus per measured call: the two emittable algorithms
  (both pass), unknown algorithms (`sha-1` and `md5`),
  the empty string, two wrong-case spellings, a
  trailing-space spelling, and the non-string values
  `undefined` and `null` (all eight illegal shapes throw
  the pinned full configuration-error message). Eight of
  the ten cases throw and are caught inside the measured
  pass — the fail-closed rejection is part of the steady
  state a caller pays. Every expected pass/throw outcome
  is hand-pinned in the bench from the guard's documented
  contract (matching the rejections the contentDigestAlg
  test suite pins independently), never derived from the
  implementation at bench time, self-checked exhaustively
  outside timing, and re-pinned on every measured pass.
  The README Benchmarks table was refreshed wholesale
  from one real run and now carries the third `guard`
  row. The bench performs zero network I/O, zero
  randomness, and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `signatureInputValue` — the full `Signature-Input` field
  value a signer builds once per label (`label=` plus the
  serialized inner list and parameters) — as one pass over
  a fixed four-case corpus per measured call: a bare
  single-component value with an empty parameter set (the
  value renders as the bare inner list — the function
  builds a value, it does not look one up, so there is no
  missing-label / undefined outcome), the shared four
  components under the label `sig1` with created + keyid +
  alg, a second label, `merchant`, over the same four
  components with all six parameters set, and a `gateway`
  value with parameterized component ids and an escaped
  nonce. Every expected string is hand-pinned in the bench
  from the function's contract (matching values pinned
  independently in the golden, multi-label and nonce test
  suites), never derived from the implementation at bench
  time, self-checked exhaustively outside timing —
  including the dual-label join of the golden and merchant
  values (joined with ", ", the merge the multi-label
  tests build) against a hand-pinned full header literal —
  and re-pinned on every measured pass. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the second `serialize` row. The
  bench performs zero network I/O, zero randomness, and
  no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `assertRsaModulusLength` — the RSA modulus-length guard
  every `rsa-v1_5-sha256` sign/verify pays before any RSA
  operation runs (the modulus must be at least
  `MIN_RSA_MODULUS_BITS` = 2048 bits, and the key must be
  an RSA key at all) — as one pass over a fixed seven-case
  corpus per measured call: a 2048-bit RSA public and
  private key at exactly the floor (both pass), a 1024-bit
  RSA public and private key below the floor (both throw
  the pinned modulus message the rsaV15 suite pins for the
  same weak pair on both sides), and three wrong-shape
  keys (an ed25519 public key, a P-256 public key and a
  symmetric secret, each throwing the pinned
  expected-an-RSA-key message for its shape). Five of the
  seven cases throw and are caught inside the measured
  pass — the fail-closed rejection is part of the steady
  state a caller pays. Every expected pass/throw
  outcome, including the exact full throw message under
  the bench's fixed caller context, is hand-pinned in
  the bench from the guard's documented contract, never
  derived from the implementation at bench time,
  self-checked exhaustively outside timing, and
  re-pinned on every measured pass. All keys are
  generated once at bench start; the timed region
  generates no keys. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the second `guard` row. The bench performs zero
  network I/O, zero key generation inside timing, and
  no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `assertHmacSecretLength` — the per-algorithm HMAC
  secret-length guard every HMAC sign/verify pays before any
  MAC runs (RFC 2104: the key SHOULD be at least as long as
  the hash output, so hmac-sha256 requires at least 32 bytes
  and hmac-sha512 at least 64) — as one pass over a fixed
  ten-case corpus per measured call: for each algorithm an
  empty secret, one byte below its floor, exactly at its
  floor, and far above it, plus the cross-algorithm pair a
  63-byte secret that passes for hmac-sha256 and a 32-byte
  secret that passes for hmac-sha256 but is rejected for
  hmac-sha512. Six of the ten cases throw and are caught
  inside the measured pass — the fail-closed rejection is
  part of the steady state a caller pays. Every expected
  pass/throw outcome, including the exact floor and byte
  count in each throw message, is hand-pinned in the bench
  from the guard's documented contract (matching the
  messages the keyLength and hmacSha512 suites pin
  independently), never derived from the implementation at
  bench time, self-checked exhaustively outside timing, and
  re-pinned on every measured pass. The secrets are built
  once at bench start from a fixed fill — only their lengths
  matter. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the `guard`
  row. The bench performs zero network I/O, zero randomness
  and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `contentDigestAlgOf` — the digest-algorithm identification
  a signer appending a second signature pays to pin itself
  to the existing wire Content-Digest value — as one pass
  over a fixed ten-case corpus per measured call: both
  emittable algorithms alone (the pinned wire values of the
  shared fixture body), mixed two-algorithm values in both
  orders (the helper reads only the prefix before the first
  `=`, so a mixed value resolves to its first entry — the
  signer-side pinning contract, not the verifier's
  whole-value sha-512-preferring body check), unknown
  algorithms (sha-1, sha-384), and malformed shapes (an
  uppercase prefix, a leading space, a bare algorithm name
  with no `=`, and the empty string), whose expected result
  is `undefined` — the fail-closed shape a caller turns
  into an explicit rejection. Every expected result is
  hand-pinned in the bench from the helper's documented
  contract, never derived from the implementation at bench
  time, self-checked outside timing, and re-pinned on every
  measured pass. `contentDigestAlgOf` is now also exported
  from the package entry point (it was previously internal
  to the signing path). The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `identify` row. The bench performs zero network I/O,
  zero randomness and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `joinHeaderValues` — the multi-value header combination
  every canonical lookup, signer-side fold and Node-adapter
  fold pays for a repeated header field (RFC 9421 §2.5:
  trim each element, join with ", ") — as one pass over a
  fixed nine-case corpus per measured call: an empty array,
  a single padded value, plain and whitespace-padded
  multi-value arrays (spaces and tabs), and empty-element
  cases (a lone empty string, two whitespace-only elements,
  an empty element in the middle of real values, and an
  empty first element). Empty elements are not dropped —
  they still contribute their separator — and every
  expected combination is hand-pinned in the bench from
  the helper's documented contract (the non-empty pins
  match the multi-value-header test suite), never derived
  from the implementation at bench time, and re-pinned on
  every measured pass. The README Benchmarks table was
  refreshed wholesale from one real run and now carries
  the `join` row. The bench performs zero network I/O,
  zero randomness and no wall-clock assertions.
- The CLI demo (`npm run demo`) now closes with a
  signature-params serialization segment: five fixed (covered
  components, parameters) cases — an empty component list
  carrying the RFC 9421 §B.2.1 parameters, the shared four
  covered components with created + keyid + alg, the same four
  with all six parameters set, four parameterized component ids
  (`;req` / `;tr` / `;name=` / `;key=`), and a nonce whose quote
  and backslash characters must serialize escaped — are run
  through `serializeSignatureParams` and printed as name ->
  serialized pairs, showing how the inner list and the parameters
  in fixed order (created, expires, keyid, alg, nonce, tag)
  assemble into the `@signature-params` line a verifier rebuilds
  byte-for-byte. Every expectation is hand-pinned from the
  serializer's contract, matching the bench corpus and the
  values pinned in the Appendix B, golden,
  parameterized-component and nonce test suites; the segment
  performs zero network I/O and is byte-identical between runs.
- The benchmark (`npm run bench`) now also measures
  `getHeader` / `getHeaderRaw` — the case-insensitive header
  lookup every covered-component resolution pays on the
  signer and the verifier — as one pass over a fixed
  nine-name lookup set against one fixed multi-header
  fixture per measured call (9 names × both helpers = 18
  lookups): mixed-case single strings, a duplicated header
  name under two casings (the first match in insertion order
  must win), and multi-value fields with padded elements, on
  which the canonical form (trimmed, joined with ", ") and
  the raw form (joined untrimmed, the form a `;bs` component
  binds) must differ. Every expected value is hand-pinned in
  the bench from the two helpers' documented contracts and
  re-pinned on every measured pass; missing and
  undefined-valued headers returning `undefined` from both
  helpers are asserted outside timing. The README Benchmarks
  table was refreshed wholesale from one real run and now
  carries the `lookup` row. The bench performs zero network
  I/O, zero randomness and no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures
  `generateNonce` — the nonce generation an anti-replay
  signer pays on every request — as one pass over the two
  fixed byte tiers per measured call: the default 16 bytes
  (128 bits, exercised through the no-argument default) and
  32 bytes (256 bits). The random source is the system
  CSPRNG (`node:crypto` `randomBytes`), so the numbers
  include entropy-source cost. Self-checks assert morphology
  only, on every measured call — exact length (22 base64url
  characters for 16 bytes, 43 for 32, the lengths pinned in
  the generateNonce test suite) and the base64url-only
  character set — and never a specific value. The README
  Benchmarks table was refreshed wholesale from one real
  run and now carries the `generate` row. The bench
  performs zero network I/O and makes no wall-clock
  assertions; the only randomness is the function under
  test itself.
- The CLI demo (`npm run demo`) now closes with a
  dictionary-member extraction segment: one fixed multi-member
  Dictionary value is run through
  `serializeDictionaryMemberValue` once per fixed key (an Integer
  member, a member with parameters, a Decimal member, a Byte
  Sequence member, an Inner List member and a bare key) and each
  extraction is printed as a key -> serialized-value pair, showing
  the member value without its Dictionary key (parameters still
  attached) that a `;key` covered component contributes to the
  signature base. A missing key's `not present` rejection is
  printed as one line. Every expectation is hand-pinned from the
  RFC 8941 §4.1.2 rules, matching the values pinned in the
  `;key` / `;sf` component tests and the bench corpus; the
  segment performs zero network I/O and is byte-identical
  between runs.
- The benchmark (`npm run bench`) now also measures
  `serializeSignatureParams` — the inner-list-plus-parameters
  serialization every sign and verify pays before any
  cryptography runs — as one pass over a fixed five-case corpus
  per measured call: an empty component list carrying the
  RFC 9421 §B.2.1 parameters, the shared four covered
  components with created + keyid + alg, the same four with all
  six parameters set, four parameterized component ids
  (`;req` / `;tr` / `;name=` / `;key=`), and a nonce whose quote
  and backslash characters must serialize escaped. Every
  expected string is hand-pinned in the bench from the
  serializer's contract, matching values pinned independently
  in the Appendix B, golden, parameterized-component and nonce
  test suites, and every measured pass re-pins every case's
  result. `serializeSignatureParams` is also now re-exported
  from the package entry point alongside `signatureInputValue`
  (it was previously only reachable through the components
  module). The README Benchmarks table was refreshed wholesale
  from one real run and now carries the `serialize` row. The
  bench performs zero network I/O and makes no wall-clock
  assertions.
- The CLI demo (`npm run demo`) now closes with a structured-field
  canonicalization segment: three fixed field values (a Dictionary
  with a Decimal member, an Integer Item with leading zeros, a
  Dictionary Byte Sequence member) are run through
  `canonicalizeStructuredFieldValue` and printed as raw ->
  canonical pairs, showing the form a verifier actually compares
  for a `;sf` covered component (Decimals gain three fractional
  digits, leading-zero Integers collapse, Byte Sequences are
  re-encoded). Every expectation is hand-pinned from the RFC 8941
  §4 rules, matching the values pinned in the `;sf` component
  tests and the bench corpus; the segment performs zero network
  I/O and is byte-identical between runs.
- The benchmark (`npm run bench`) now also measures
  `serializeDictionaryMemberValue` — the single-member extraction
  every `;key` covered component pays on the signer and the
  verifier — as one pass over a fixed six-key set against one
  fixed multi-member Dictionary value (an Integer member, a
  member with parameters, a Decimal member, a Byte Sequence
  member, an Inner List member and a bare key) per measured
  call. Every expected serialization is hand-pinned in the bench
  from the RFC 8941 §4.1.2 rules, a missing key's throw is
  asserted outside timing, and every measured pass re-pins
  every entry's result. The README Benchmarks table was
  refreshed wholesale from one real run and now carries the
  `extract` row. The bench performs zero network I/O and makes
  no wall-clock assertions.
- The CLI demo (`npm run demo`) now also prints a signature-base
  segment right after the main line's verification: the RFC 9421
  §2.5 signature base of the main `sig1` signature — the exact
  string that was signed — rebuilt with `buildSignatureBase` over
  the request's actual covered components (`@method`, `@authority`,
  `@path`, `content-digest`), followed by a line mapping each base
  line to its covered component. The base carries no key or
  signature bytes and every input is a fixed demo constant, so the
  segment is byte-identical between runs; it performs zero
  network I/O.
- The benchmark (`npm run bench`) now also measures
  `verifyRequestOrThrow` — the throwing verify wrapper a
  middleware-style caller uses — as two separate rows over a
  fixed ed25519 fixture: the success path (result unwrapping
  over one valid request) and the failure path over the same
  request with one signature byte flipped, where every measured
  call catches a `VerifyError` asserted via `isVerifyError` to
  carry the pinned `SIGNATURE_MISMATCH` code, so the exception-
  construction cost is priced separately. Self-checks run
  outside timing and on every measured call. The README
  Benchmarks table was refreshed wholesale from one real run
  and now carries the `verify` / `throw` rows. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The CLI demo (`npm run demo`) now also closes with a JWK
  thumbprint segment: the demo public key is exported as a JWK, its
  RFC 7638 `jwkThumbprint` is printed, and a request signed with
  that thumbprint as its `keyid` verifies with `expectedKeyId`
  pinned to the same thumbprint, showing the fingerprint-as-keyid
  binding. The segment performs zero network I/O; the thumbprint
  is derived from the demo's fresh key, so it differs between runs
  like the signature itself.
- The benchmark (`npm run bench`) now also measures
  `canonicalizeStructuredFieldValue` — the parse-then-strictly-
  reserialize step every `;sf` covered component pays on the
  signer and the verifier — as one pass over a fixed six-value
  corpus (Dictionary / List / Item shapes, a Decimal member, a
  leading-zero Integer, and a Byte Sequence member) per measured
  call. Every expected serialization is hand-pinned in the bench
  from the RFC 8941 §4 rules and re-pinned on every measured
  pass. The README Benchmarks table was refreshed wholesale from
  one real run and now carries the `canon` row. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The benchmark (`npm run bench`) now also measures the three
  standalone signature parsers a gateway pre-screen calls
  directly — `listSignatureLabels`, `parseSignatureInput` and
  `parseSignatureField` — each as its own row over a fixed
  hand-written dual-label fixture (`merchant` / `gateway`
  members, written out literally in the bench, not produced by
  `signRequest`). Self-checks outside timing pin both members'
  label list, component lists, every parameter and both decoded
  byte strings, plus a hand-pinned malformed set that must all
  throw; every measured call re-pins the core of its result.
  The README Benchmarks table was refreshed wholesale from one
  real run and now carries the three `parse` rows. The bench
  performs zero network I/O and makes no wall-clock assertions.
- The CLI demo (`npm run demo`) now also shows an inbound
  normalization segment: a request signed against a host-with-port
  URL (with `@scheme` and a multi-value `x-trace-hops` header
  covered) is rebuilt from a mock Node `IncomingMessage`-shaped
  object — mixed-case header names, the multi-value header still an
  array, an encrypted socket — through `fromNodeRequest`, the
  normalized method/URL/headers are printed, and the result
  verifies; rebuilding the same wire request with the wrong scheme
  (`http`) is rejected with `SIGNATURE_MISMATCH`. The segment starts
  no server and performs zero network I/O.
- The CLI demo (`npm run demo`) now also shows a sha-256
  Content-Digest segment: the same fixed demo request is re-signed
  with `contentDigestAlg: "sha-256"` for a peer that only accepts
  sha-256 digests, the main line's sha-512 and the peer line's
  sha-256 `Content-Digest` headers are printed side by side on the
  same body, the sha-256 signature verifies, and the same one-byte
  body tamper as the main line is rejected with
  `BODY_DIGEST_MISMATCH`. The segment performs zero network I/O and
  uses the demo's fixed key id, `created` and nonce.
- The benchmark (`npm run bench`) now also measures the per-curve
  JWK export/import round trip: for each of P-256, P-384, P-521 and
  RSA (2048-bit, the library default; its JWK is shared by both RSA
  algorithms), one freshly generated public key (generated outside
  timing) is exported with `exportPublicKeyJwk*`, pushed through a
  JSON stringify/parse round trip, and re-imported with
  `importPublicKeyJwk*` on every measured call. Self-checks outside
  timing require the re-imported key's SPKI DER — produced by
  node:crypto directly, independently of the JWK helpers — to equal
  the original's byte-for-byte. The bench performs zero network I/O.
  The README Benchmarks table was refreshed wholesale from one real
  run and now carries the four `roundtrip` rows.
- The CLI demo (`npm run demo`) now closes with a JWKS key-resolution
  segment: a `JwksKeyStore` is restored offline from a v1 snapshot
  carrying only the demo key's public JWK (`fetchedAtSec` and the
  store clock are pinned to the demo's fixed instants, and the
  configured `fetchImpl` throws if it is ever called, so the segment
  performs zero network I/O), the demo's signed request verifies
  through `keyResolver: (kid) => store.resolve(kid)`, and a request
  signed under an unknown `keyid` is rejected with
  `KEY_RESOLUTION_FAILED`, showing the production gateway
  key-discovery path the earlier segments bypassed by passing a key
  directly.

- The benchmark (`npm run bench`) now also measures the
  `fromNodeRequest` inbound-normalization path: a fixed mock
  `IncomingRequestLike` (seven header entries including a multi-value
  header and an `undefined` entry, trailers in both Node forms, the
  shared 31-byte body) is normalized on every measured call, with
  self-checks outside timing pinning the result field by field
  against a hand-written expected `RequestLike`, the
  parsed-trailers-object form, `rawTrailers` precedence, and the
  no-trailers shape. No real server is started; the bench performs
  zero network I/O. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the `normalize` row.
- The CLI demo (`npm run demo`) now closes with a replay-protection
  segment: the demo's signed request is verified twice against an
  opt-in `ReplayCache` (fixed injected clock, capacity 100, TTL
  3600s) — the first presentation passes, the identical second
  presentation is rejected with `NONCE_REPLAY` — and a request
  signed with a different nonce still verifies, showing that the
  cache rejects repeats, not new nonces.
- The benchmark (`npm run bench`) now also measures the
  `ecdsa-p521-sha512` sign/verify path: the algorithm loop gains the
  P-521 member with the same fixture caliber as the existing
  P-256 / P-384 paths (one fresh `generateP521KeyPair()` pair per
  scenario, outside the timed loops; signatures are the raw r‖s
  form, 132 bytes total), closing the drift left when the algorithm
  itself landed. The README Benchmarks table was refreshed
  wholesale from one real run and now carries the two P-521 rows.
- The benchmark (`npm run bench`) now also measures the
  `ecdsa-p384-sha384` sign/verify path: the algorithm loop gains the
  P-384 member with the same fixture caliber as the existing P-256
  path (one fresh `generateP384KeyPair()` pair per scenario, outside
  the timed loops), closing the drift between the implemented
  algorithm list and the benchmark loop. The README Benchmarks table
  was refreshed wholesale from one real run and now carries the two
  P-384 rows.
- `ecdsa-p521-sha512` signature algorithm (RFC 9421 §3.3.6): NIST
  P-521 with SHA-512, signatures in the raw r‖s form with each integer
  padded to 66 octets (132 octets total) — the highest-strength tier of
  the existing ECDSA support, with the three EC limb widths (32 / 48 /
  66 octets) pinned separately on both sides so a signature from one
  curve never verifies as another's. Includes `generateP521KeyPair()`,
  the `exportPublicKeyJwkP521` / `importPublicKeyJwkP521` JWK helpers
  (`crv: "P-521"`, private material refused, P-256 / P-384 JWKs
  refused), and a `secp521r1` → `ecdsa-p521-sha512` mapping under
  `algFallback: "infer"`. With this, every signature algorithm RFC 9421
  registers is implemented; the unsupported-algorithm tests now pin
  `ed448` (not registered in RFC 9421) instead.
- The benchmark (`npm run bench`) now also measures the
  `jwkThumbprint` key-derivation path: one measured call derives the
  RFC 7638 thumbprint of each of the three exported public JWK shapes
  (ed25519 / P-256 / RSA) over a fixed fixture whose keys come from
  RFC 8032 §7.1, the P-256 generator point, and the RFC 7638 §3.1
  example. Self-checks outside timing pin every shape to an
  independently computed expected thumbprint — the RSA one is the
  value published in RFC 7638 §3.1.
- The CLI demo (`npm run demo`) now also shows the multi-party
  payments flow: after the single-signature script, a payment gateway
  appends a second signature with `addSignature` (label `gateway`,
  hmac-sha256 under a labelled demo-only secret, additionally covering
  `content-type`), the merged `Signature-Input` / `Signature` headers
  are printed, and `verifyAllLabels` verifies both labels. Tampering
  `content-type` then fails only the gateway label
  (`SIGNATURE_MISMATCH`) while the merchant `sig1` label still
  verifies.
- `ecdsa-p384-sha384` signature algorithm (RFC 9421 §3.3.5): NIST
  P-384 with SHA-384, signatures in the raw r‖s form with each integer
  padded to 48 octets (96 octets total) — the P-384 twin of the
  existing `ecdsa-p256-sha256` support, with the two limb widths pinned
  separately on both sides so a signature from one curve never verifies
  as the other. Includes `generateP384KeyPair()`, the
  `exportPublicKeyJwkP384` / `importPublicKeyJwkP384` JWK helpers
  (`crv: "P-384"`, private material refused, P-256 JWKs refused), and a
  `secp384r1` → `ecdsa-p384-sha384` mapping under
  `algFallback: "infer"`.
- `jwkThumbprint(jwk)`: the RFC 7638 JWK Thumbprint (SHA-256 over the
  lexicographic canonical JSON of the required members only, base64url)
  for the three public JWK shapes this library exports (OKP, EC, RSA),
  so both sides of a JWKS distribution derive the same stable `keyid`
  for the same key. Extra members (`kid`/`alg`/`use`) are ignored;
  private JWKs (`"d"` present), missing/empty required members, and
  unsupported `kty` values throw. Verified against the RFC 7638 §3.1
  official example, whose published thumbprint is reproduced exactly.
- RFC 9421 Appendix B.2.2 official test vector (rsa-pss-sha512,
  selective coverage): the published signature base — covering only
  `@authority`, `content-digest`, and `@query-param;name="Pet"`,
  with `created`/`keyid`/`tag` parameters — matches byte-for-byte,
  the published 256-octet signature verifies with node:crypto alone
  under RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it
  verifies end-to-end through `verifyRequest` (via
  `algFallback: "infer"`, since the vector carries no `alg`
  parameter), returning the tag. The selective-coverage boundary is
  pinned: tampering a covered component fails, changing uncovered
  components still verifies.
- RFC 9421 Appendix B.2.1 official test vector (rsa-pss-sha512,
  minimal coverage): the published signature base — a single
  `@signature-params` line over an empty covered-components list with
  `created`/`keyid`/`nonce` — matches byte-for-byte, the published
  256-octet signature verifies with node:crypto alone under
  RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it verifies
  end-to-end through `verifyRequest` (via `algFallback: "infer"`,
  since the vector carries no `alg` parameter), returning the nonce.
- RFC 9421 Appendix B.2.3 official test vector (rsa-pss-sha512, full
  coverage): the published signature base matches byte-for-byte, the
  published 256-octet signature verifies with node:crypto alone under
  RSASSA-PSS (SHA-512, MGF1-SHA-512, 64-byte salt), and it verifies
  end-to-end through `verifyRequest` (via `algFallback: "infer"`,
  since the vector carries no `alg` parameter).
- `JwksKeyStore.stats()` observability: detached `{ refreshes,
  refreshFailures, hits, misses }` counters for the store's lifetime —
  refreshes counted once per actual fetch (single-flight merges count
  once), every `resolve()` counted as one hit or miss, and snapshot
  export/restore does not reset the counts.
- The benchmark now also measures the key-resolution hot path:
  `JwksKeyStore.resolve` hits on an offline-restored store (zero
  network), and `memoizeKeyResolver` cache hits and misses (unknown
  keyids, which are never cached), with self-checks on the underlying
  resolver call counts.
- The benchmark now also measures the malformed-input rejection path:
  `verifyRequest` rotating over a 566-case corpus of malformed
  `signature-input` / `signature` values, generated deterministically
  with the parser fuzz test's fixed-seed approach and self-checked to
  always return `{ ok: false, code }` and never throw.
- `fromNodeRequest` now populates `RequestLike.trailers` from a Node
  `IncomingMessage` (`rawTrailers` when present, else `trailers`;
  names lowercased, multi-values joined like headers), so RFC 9421
  `;tr` covered components verify on a real server. Messages without
  trailers produce no `trailers` field, as before.
- The `@request-target` derived component (RFC 9421 §2.2.5): the
  request target in origin form — the path plus, when present, `?`
  and the query — reconstructed from `RequestLike.url` as
  `pathname + search`, so it never contains the scheme or authority
  and a URL fragment never participates. Because `RequestLike` only
  carries an absolute URL, the absolute-form, authority-form, and
  asterisk-form request targets of §2.2.5 cannot be represented and
  are not produced.
- A `package.json` `exports` map for the package root, pointing at
  the built `dist/src` entry with `types`, `import`, and `default`
  conditions (alongside the existing `main` field).
- The benchmark now also measures the replay-detection hot path:
  `ReplayCache.check` hits against a cache prefilled with 1,000
  nonces under a deterministic fake clock (zero network), rotating
  over the whole prefilled set so the LRU recency refresh is
  exercised across entries, with self-checks on the stats counters.
- The benchmark now also measures the `verifyRequest` × `allowedAlgs`
  whitelist path (backlog #860): the same RSA-PSS fixture shape in
  two rows — a hitting whitelist (`["rsa-pss-sha512"]`, full RSA-PSS
  verification, ~15,602 ops/sec / 64.10 µs/op in this run) and a
  missing whitelist (`["ed25519"]`, pre-cryptographic
  `ALG_NOT_ALLOWED` rejection, ~195,686 ops/sec / 5.11 µs/op, about
  12.5× the hit throughput) — each row self-checking every measured
  pass and pinning the opposite half outside timing, with the README
  Benchmarks table refreshed from the same run (Node v24.22.1 /
  AMD EPYC 9D25 shared host).

### Changed

- **Breaking:** `ecdsa-p256-sha256` now uses the signature encoding
  RFC 9421 §3.3.4 actually defines — the raw concatenation of r and s,
  each padded to 32 octets (64 octets total, via node:crypto's
  `dsaEncoding: "ieee-p1363"`) — instead of DER. Signatures this
  library mints are now interoperable with spec-conformant peers, and
  the official Appendix B.2.4 vector verifies end-to-end. DER-encoded
  ECDSA signatures minted by earlier versions of this library are no
  longer accepted, and there is deliberately no DER fallback: this is
  a demo, and silently accepting two encodings would hide exactly the
  interop bug this fix removes.
- `JwksKeyStore` refreshes are now single-flight: concurrent
  `refresh()` / stale `refreshIfStale()` calls share one in-flight
  fetch and its atomic snapshot replacement instead of each fetching;
  a settled refresh is never reused and a failure is never cached.
- `tsconfig.json` now enables `exactOptionalPropertyTypes` (backlog
  #1021, pilot in this repo only): optional properties no longer
  accept an explicit `undefined` assignment, so "field omitted" and
  "field set to `undefined`" are distinct at the type level. This is a
  small type-level breaking change for callers that pass an explicit
  `undefined` for a config option (`SignOptions.tag` / `nonce` /
  `created` / `expires` / `keyId` / `label` / `coveredComponents` /
  `contentDigestAlg` / `structuredFieldTypes`,
  `VerifyOptions.expectedKeyId` / `replayCache` / `key` and the rest):
  omit the field instead. Runtime behavior is unchanged — the library
  already treated an explicit `undefined` exactly like an omitted
  field everywhere. Message and result shapes (`RequestLike`,
  `SignedHttpRequest`, `HttpResponseLike`, `VerifyResult`,
  `VerifyErrorOptions`, the Node `http` adapter `Like` types) genuinely
  carry `undefined` at runtime, so their optional fields are annotated
  `| undefined` and still accept it. The new
  `test/exactOptionalPropertyTypes.test.ts` pins both sides with
  `@ts-expect-error` cases (a regressed type makes the suite go red)
  and one runtime case.

### Tests

- Independent RFC 9421 Appendix vectors added: B.2.6 (ed25519) and
  B.2.4 (ecdsa-p256-sha256) both verify end-to-end (B.2.4 after the
  §3.3.4 encoding fix below; its signature base also reproduces
  byte-for-byte).
- The sha-256 `Content-Digest` path is cross-checked against values
  produced outside this library: hardcoded vectors derived with
  OpenSSL (`openssl dgst -sha256`) plus the published RFC 9530
  Appendix D value for `{"hello": "world"}`. A live OpenSSL
  re-check runs when an `openssl` binary is available and is
  explicitly skipped — never silently passed — when it is not.
- A test executes the README Quickstart's first TypeScript block
  against the built entry point, so a renamed export, a changed
  sign/verify signature, or a stale import path in the first code a
  new reader runs fails the suite. The later Quickstart fragments
  are illustrative snippets and are not executed.
- The parser fuzz timing assertions are de-flaked: the per-call
  50ms wall-clock budget (which failed once at 52.2ms under a
  parallel full-suite run for sub-millisecond work) is now asserted
  on the corpus median against the same 50ms budget, plus a 1000ms
  catastrophic single-case bound, so a systematic slowdown still
  fails while scheduler/GC pauses no longer do.
- The Appendix B.2.5 (hmac-sha256) vector is now verified end-to-end
  through `verifyRequest` — the last Appendix B vector without a
  published-signature end-to-end case. The test assembles the
  published request, `signature-input`, and signature wire values
  and verifies them with `algFallback: "infer"` (B.2.5 is the only
  Appendix B vector whose signature-input omits `alg`, which is the
  case that opt-in exists for), asserting `ok` and the inferred
  `hmac-sha256` algorithm; a tampered `@authority` fails with
  `SIGNATURE_MISMATCH`; and the same vector without the opt-in
  fails with `VERIFICATION_ERROR` (the historical ed25519 default),
  pinning why the fallback stays opt-in.

### Documentation

- `CONTRIBUTING.md`: setup, the honesty hard rules contributions
  are held to, and the pre-submit checks.
- Corrected the `SECURITY.md` content-digest signing claim: body
  binding signs with `sha-512` by default, or `sha-256` when
  `SignOptions.contentDigestAlg` is set to `"sha-256"` (the earlier
  text said signing emitted `sha-512` only).
- Corrected the `package.json` description and keywords to match
  the supported algorithms: the description now lists all six
  (`ed25519`, `hmac-sha256`, `hmac-sha512`, `ecdsa-p256-sha256`,
  `rsa-pss-sha512`, `rsa-v1_5-sha256`) instead of only the first
  two.
- A README "FAQ (honest)" section collecting the positioning
  answers previously scattered across Limitations,
  Interoperability, and SECURITY.md: production use, subset scope,
  third-party interop status, Content-Digest algorithm preference,
  JWKS network behavior, replay limits, and key management. It
  restates existing documented facts only and adds no new claims.

### Fixed

- The default `JwksKeyStore` fetch now forwards the conditional-request init (backlog #1184): the no-timeout default used to be `(u) => globalThis.fetch(u)`, which dropped the second argument carrying `If-None-Match` — so a remembered `ETag` never reached the endpoint on the default path, the endpoint always re-served the document, and `notModified` stayed 0 while `conditionalRefreshes` still counted 1 (the timeout path already forwarded the header, so the bug only showed without `fetchTimeoutMs`). The default is now `(u, init) => globalThis.fetch(u, init)`, and a new loopback regression test in `test/jwksConditionalRefresh.test.ts` proves the default fetch sends `If-None-Match` on the second refresh, is answered 304, and keeps the snapshot with `stats()` `{ refreshes: 2, refreshFailures: 0, hits: 2, misses: 0, conditionalRefreshes: 1, notModified: 1 }` — the test fails against the old one-argument default. No behavior change for stores without a remembered `ETag` (no init is passed at all) or for custom `fetchImpl` implementations.
- `addSignature` / `addResponseSignature` now name themselves in the
  malformed-label error (backlog #1084): both append entry points
  check the label shape with `assertLabelShape(label, caller)` right
  after the empty check, so `"bad label"` / `"a,b"` throw
  `addSignature: "label" must be an RFC 9421 token …` (resp.
  `addResponseSignature: …`) instead of falling through to the
  delegated `signRequest` and reporting `signRequest: …`. The
  rejection itself is unchanged (still before any crypto, still
  before the no-signature-headers and duplicate checks); only the
  attribution is fixed. `assertLabelShape` is exported with an
  optional caller parameter (default `"signRequest"`, so `signRequest`
  / `signResponse` behavior is unchanged) and re-exported from the
  package entry point. `test/appendLabelShape.test.ts` gains 12 tests
  (both malformed labels at both entry points with the caller named
  and `signRequest` absent, legal-label appends still verify on both
  sides, duplicate legal labels still hit the duplicate check first,
  empty-label wording unchanged, shape check before the
  no-signature-headers check); the `labelShape.test.ts` append case
  now pins the new attribution. A mutation run with the caller
  argument dropped turns 7 of the new tests red.

- Response `status` is now validated against the registered HTTP
  status-code range 100-599 (backlog #1080): `assertStatus`
  (`signResponse` / `verifyResponse` / `verifyAllResponseLabels`)
  and both response adapters (`fromNodeResponse`,
  `fromFetchResponse`) reject a non-integer or out-of-range status
  with the range named in the error (e.g. `… got 999 (expected
  100-599)`). Previously only the integer check ran, so 0, 99, 600
  and 999 could be signed and verified and `@status` bound a
  meaningless value; 600-999 are undefined codes (RFC 9110 §15).
  The existing error wording is kept verbatim with the range
  appended, so existing message assertions still match.
  `test/responseStatusRange.test.ts` gains 7 tests (rejection at all
  four entry points for 0/99/600/999, 100/599 sign→verify round-trips
  including `verifyAllResponseLabels`, and 100/599 pass-through in
  both adapters); a mutation run with the range check removed turns
  the new tests red.

- `parseSignatureInput` now finds the inner list's closing
  parenthesis with a quote-aware scan (backlog #1071): the first
  `)` outside a quoted string, with backslash escapes skipped, instead
  of a naive `indexOf(")")`. Previously a `)` inside a quoted value —
  e.g. a header field named `x-a)b` or a `;name="a)b"` parameter —
  truncated the component list, so the verifier rejected its own
  signer's output (or a foreign header) as
  `MALFORMED_SIGNATURE_INPUT`, while `listSignatureLabels` parsed
  the same value correctly. A `)` in a `;name` value still cannot be
  minted by this signer for `@query-param` (a literal `)` is not a
  percent-encoded name, so the resolve step refuses it with
  `SIGNATURE_BASE_BUILD_FAILED`); the parse fix means such a header
  is now rejected semantically instead of mis-parsed. 11 new tests in
  `test/parseSignatureInputQuotedParen.test.ts` (three `;name` paren
  shapes, escaped quote / backslash, an `x-a)b` sign/verify
  round-trip plus tamper to `SIGNATURE_MISMATCH`, semantic-vs-malformed
  rejection, unterminated-list regression, multi-label agreement with
  `listSignatureLabels`, a `)` inside a quoted `;tag`). A
  short-circuit mutation (restoring the naive scan) was verified to
  turn 8 of the 11 new tests red.

- `signRequest` now rejects over-long signing parameters (backlog
  #1066): a `tag` / `nonce` / `keyid` longer than 256 characters
  (`MAX_TAG_LENGTH` / `MAX_NONCE_LENGTH` / `MAX_KEY_ID_LENGTH`,
  exported from the package entry point) and a covered-components
  list longer than 64 (`MAX_COVERED_COMPONENTS`, the same bound the
  verify-side parser already applied) are configuration errors,
  thrown before the signature base is built or any crypto runs, with
  the input request left untouched. Previously the signer would mint
  signatures its own verifier refuses (a 65-component list fails at
  parse time with `MALFORMED_SIGNATURE_INPUT`) or bloated with a
  caller bug pasted into a label field. The 256-character caps are
  deliberately sign-side only: RFC 9421 sets no per-field length
  limit, so a validly signed longer tag, nonce, or keyid from another
  implementation still verifies — the 64 KiB `signature-input` cap
  bounds total header size on the verify side instead. `addSignature`
  / `signResponse` inherit the guards through `signRequest`. 13 new
  tests in `test/signParamLimits.test.ts` (over-long tag/nonce/keyId
  rejections with input untouched, at-the-limit 256-character
  round-trips, 65-component rejection with the parser's wording,
  64-component round-trip, known-alg/wrong-key wording unchanged,
  `addSignature` inheritance, and hand-minted 300-character
  tag/nonce/keyId signatures that verify — pinning the deliberate
  verify-side asymmetry).

- `signRequest` now rejects an unknown `alg` as `unsupported alg`
  (backlog #1058): it previously fell through to the key-shape
  predicate, so the classic downgrade value `"none"` (and any other
  unknown name, e.g. `"ed448"`) was misreported as `alg "…" is
  incompatible with the key` — and the `unsupported alg` branch at
  the end of the crypto dispatch could never be reached by an unknown
  value. An explicit `isSupportedAlg` guard now runs before the shape
  check, so unknown names fail in their own words before the signature
  base is built or any crypto runs, the input request is left
  untouched, and `addSignature` / `signResponse` inherit the guard
  through `signRequest`. The dispatch's final `else` stays as the
  exhaustiveness guard (unreachable today; it exists so a future
  algorithm added to `SignAlg` without a branch fails loudly and so
  TypeScript accepts the signature as definitely assigned), and the
  stale `algMatchesKeyShape` comment that claimed unknown values
  "still fail with `unsupported alg` in the dispatch below" now states
  the real flow. Algorithm names are matched exactly on both sides —
  a miscased `"ED25519"` is unsupported, not ed25519 — and the verify
  side keeps returning `UNSUPPORTED_ALG` for unknown wire values. 10
  new tests in `test/signUnknownAlg.test.ts` (sign-side `"none"` /
  `"ed448"` / `""` / `"ED25519"` rejections with input untouched,
  `"none"` with an HMAC key, known-alg/key-mismatch wording
  unchanged, `addSignature` inheritance, ed25519 round-trip control,
  verify-side `"none"` / `"ED25519"` → `UNSUPPORTED_ALG`); the
  `createVerifiedHandler` unknown-alg case in
  `test/nodeHttpVerifiedHandlerSignResponse.test.ts` now expects the
  corrected message.
- The verifier now rejects a repeated covered component (backlog
  #1001): `parseComponentIds` in `src/components.ts` previously only
  pushed identifiers, so `("@method" "@method" "@path")` was accepted
  and the signature base carried the same line twice — the signer
  already refused to mint that shape (`signRequest`'s
  `assertNoDuplicateCoveredComponents`), but a foreign or hand-built
  signature could still verify. The parse layer now throws on the
  duplicate and on a list longer than the new exported cap
  `MAX_COVERED_COMPONENTS` (64), and `verifyRequest` converges both
  to `MALFORMED_SIGNATURE_INPUT` before any crypto runs (per label in
  `verifyAllLabels`, and through `verifyResponse`'s delegation). The
  duplicate rule mirrors the sign side's `coveredComponentKey`
  (base lowercased, parameter names lowercased in listed order,
  values verbatim), so `"@method"` + `"@method";req` is still not a
  duplicate (`;req` reroutes the binding) and parameter order
  variants are distinct entries on both sides. The README's
  sign-side guards sentence (which claimed the verifier would
  rebuild and accept the duplicated base), Limitations, the
  interop-hazards list, and the `MALFORMED_SIGNATURE_INPUT` error
  table row now state the rejection. 14 new tests in
  `test/duplicateCoveredComponents.test.ts`.
- `fromNodeResponse` now rejects a non-integer `res.statusCode` at the
  adapter boundary (backlog #931): it previously checked only for a
  missing status, so a string `"200"` slipped through and verified as
  status 200 (`@status` resolution stringifies whatever it is given)
  while `signResponse` / `verifyResponse` reject non-integer statuses
  outright. A non-integer status now throws a descriptive
  configuration `Error` (`res.statusCode must be an integer HTTP
  status code, got …`); floats, `NaN`, booleans and `null` are refused
  the same way instead of surfacing as an opaque
  `SIGNATURE_MISMATCH`. New `test/nodeHttpResponse.test.ts` cases (6)
  pin the five rejections and an integer-404 end-to-end verification.
- RSA JWK import now enforces the 2048-bit modulus floor (backlog
  #917): `importPublicKeyJwkRsa` in `src/keys.ts` calls
  `assertRsaModulusLength` after node:crypto accepts the JWK, so a
  1024-bit or degenerate (e.g. all-zero) RSA modulus is refused at
  import with an `invalid JWK: RSA modulus must be at least 2048
  bits, got N bits` error instead of being parked until a verify
  happens to use it. `JwksKeyStore.refresh()` inherits the check, so
  a JWKS document containing a sub-floor RSA entry fails the whole
  refresh atomically and the previous snapshot stays untouched. New
  `test/rsaJwk.test.ts` cases (verbatim 1024-bit rejection, JSON-wire
  variant, all-zero and tiny moduli, 2048/3072-bit import-and-verify)
  and `test/jwks.test.ts` cases (1024-bit entry refresh failure with
  old snapshot intact, mixed-document atomicity plus recovery,
  all-zero-modulus entry refresh failure) pin the behavior; the
  `RsaPublicJwk` caveat and the README JWK section now state the
  floor is enforced at import (modulus primality remains unchecked).
- The README Limitations section no longer says `;sf` covers "the
  RFC 8941 core types only" (backlog #988): the parser has supported
  the RFC 9651 Date and Display String types since backlog #926, and
  the `;sf` section and the FAQ already said so — only Limitations
  lagged behind. It now reads "covers the RFC 9651 types (including
  Date and Display String)". The `;sf` + Date / Display String
  sign→verify round-trips were verified to already exist in
  `test/structuredFieldDateDisplayString.test.ts`; the one gap was a
  tamper case for Display String, so one new test pins a tampered
  Display String value failing with `SIGNATURE_MISMATCH`.

### Fixed

- `verifyRequest` now validates the global clock options (backlog
  #1074): `now` must be a non-negative integer number of Unix
  seconds (the same integer discipline the signing side enforces on
  `created`/`expires`), `clockSkewToleranceSec` must be a positive
  finite number, and `expiredToleranceSec` must be a non-negative
  finite number — the same rules the per-label maps already
  enforced. Previously a NaN `now` (e.g. derived from a failed
  `Date.parse` in a webhook receiver) silently disabled every
  freshness check, since all comparisons against NaN are false, and
  a NaN tolerance disabled its own check the same way; a negative
  skew or tolerance silently rejected legal signatures. Bogus
  values now throw a configuration `Error` before any header is
  read and before any crypto runs. `verifyResponse` and
  `verifyAllResponseLabels` inherit the check through delegation,
  and `verifyAllLabels` through its per-label `verifyRequest`
  calls; the per-label maps are still validated independently. 22
  new tests in `test/verifyClockOptions.test.ts`. A short-circuit
  mutation (disabling the new assertion) was verified to turn 19
  of the 22 new tests red.

## [0.1.0]

The only version declared in `package.json`. Entries cover the commit
history from the initial commit (2026-10-02) through 2026-10-11.

### Added

- RFC 9421 HTTP message signing and verification demo (ed25519 and
  hmac-sha256), with RFC 9530 `Content-Digest` body binding.
- Typed verification errors with stable failure codes, a configurable
  expiry grace period (`expiredToleranceSec`), and `requireCreated` /
  `requireExpires` / `maxSignatureAgeSec` verification options.
- Replay protection: `nonce` signature parameter support, a secure
  `generateNonce()` helper, `VerifyOptions.requireNonce`, a pluggable
  `NonceStore` interface with an in-memory `ReplayCache` implementation
  (including observability counters and snapshot export/restore for
  restart persistence).
- Multi-signature support: `addSignature` for appending a second party's
  signature, and `verifyAllLabels` batch verification returning per-label
  results (with per-label key resolvers and per-label keyid pinning) so
  one bad label does not block the others.
- Key handling: `expectedKeyId` keyid pinning, a keyid-to-key resolver,
  `memoizeKeyResolver` with TTL caching and an LRU `maxEntries` bound,
  JWK public-key import/export (ed25519, P-256, and RSA per RFC 7518
  §6.3), and a `JwksKeyStore` for JWKS network key discovery with
  `refreshIfStale()` and snapshot export/restore.
- Additional signature algorithms: ecdsa-p256-sha256, rsa-pss-sha512,
  hmac-sha512, and rsa-v1_5-sha256, plus an opt-in `algFallback: "infer"`
  mode for a missing `alg` parameter, and enforcement of a minimum
  32-byte HMAC secret length.
- RFC 9421 component coverage: `@query`, `@status`, and `@query-param`
  (with `;name`) derived components, and the `;req`, `;sf`, `;bs`,
  `;key`, and `;tr` component parameters; `requiredComponents`
  enforcement of covered components; the `tag` signature parameter with
  `expectedTag` pinning; optional `keyId` in `signRequest`.
- Content-Digest options: `SignOptions.contentDigestAlg` emitting a
  sha-256 digest, and accepting sha-256 as a fallback when no sha-512
  digest is present.
- A Node `http` request adapter for webhook receivers, a benchmark
  script (`npm run bench`) measuring real sign/verify throughput, and
  a CLI demo (`npm run demo`) showing a sign/verify round-trip with
  tamper rejection.

### Fixed

- Reject signatures whose `expires` precedes `created`, duplicate
  signature-input parameters, empty-string nonces, and signature labels
  that are not valid RFC 9421 tokens.
- Unify multi-value header whitespace normalization, and preserve the
  response status through `addSignature`.
- Fail fast on invalid `signRequest` configuration instead of producing
  an unverifiable signature.
- Correct the package entry points and README quickstart imports, which
  pointed at a nonexistent `dist/index.js`.

### Tests

- Negative verification cases (clock skew, missing covered header, wrong
  HMAC key, unsupported algorithm, sha-512 body binding) and
  content-digest edge cases (multiple digest algorithms, tampered
  digest header, digest/body mismatch).
- An independent RFC 9421 Appendix B.2.5 interop golden vector, and a
  parser fuzz suite for the signature-input/signature parsers.

### Documentation

- An honest interoperability status section and `SECURITY.md` describing
  the demo scope and which assumptions do not carry to production.
- Corrections to stale README and `SECURITY.md` claims (algorithm
  coverage, `verifyAllLabels`, key resolver, parser fuzz, test counts,
  and the `MISSING_CONTENT_DIGEST` error description).

### CI and packaging

- GitHub Actions workflows running the test suite on push and pull
  requests (Node 20/22), and publishing to GitHub Packages as
  `@toniadreal/rfc9421-signing-demo` on Node 22.
- An MIT `LICENSE` file.
