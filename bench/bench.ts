/**
 * Local micro-benchmark for the RFC 9421 signing demo.
 *
 * Measures real, locally-observed sign/verify throughput for each
 * algorithm in the benchmark loop below (ed25519, hmac-sha256,
 * hmac-sha512, ecdsa-p256-sha256, ecdsa-p384-sha384,
 * ecdsa-p521-sha512, rsa-pss-sha512,
 * rsa-v1_5-sha256) on the machine that
 * runs it, plus a multi-party scenario (merchant ed25519 + gateway
 * hmac-sha256 dual labels via verifyAllLabels) and the key-resolution
 * hot path a gateway verifier hits on every request: `JwksKeyStore.resolve`
 * (Map hit on an offline-restored snapshot, zero network) and
 * `memoizeKeyResolver` cache hits / misses, plus the endpoint-rule
 * path a gateway runs when it hardens its JWKS endpoint against
 * plaintext downgrade: `JwksKeyStore` with `requireHttps: true` over
 * an https endpoint restored offline (the http-endpoint construction
 * rejection with its pinned error and zero fetches, and the
 * https-endpoint construction performing no fetch, both asserted
 * outside timing), self-checked on every measured pass (the pinned
 * kid resolves), plus the snapshot-export
 * path a gateway runs to persist its key store for a cold start:
 * `JwksKeyStore.exportSnapshot` over an offline-restored store holding
 * the three supported key shapes (ed25519 / P-256 / RSA, pinned kids
 * and a pinned `fetchedAtSec` — see JWKS_EXPORT_* below), self-checked
 * on every measured pass against the hand-pinned envelope (version,
 * fetch time, kid order, per-shape `kty`, public-only JWK fields with
 * no `"d"`), with a never-refreshed store's export refusal asserted
 * outside timing, plus the snapshot-restore path a gateway runs at
 * cold start: `JwksKeyStore.restoreSnapshot` restoring a pinned
 * three-shape envelope (exported outside timing from a source store
 * refreshed once through a counting fake fetch) into an existing
 * target store primed through its own counting fake fetch,
 * self-checked on every measured pass (the pinned kid resolves
 * after the restore, `stats()` is identical before and after it —
 * restoring resets no counters — and `isStale()` counts from the
 * envelope's original fetch time, so an envelope exactly at its
 * TTL boundary in the target's clock restores stale), with the
 * corrupt-envelope rejections (unsupported version, malformed
 * kid) and the fail-closed unchanged-store assertions outside
 * timing, plus the key-resolution verify path a gateway runs
 * on every request whose keys rotate by keyid: `verifyRequest`
 * with a `keyResolver` over a pinned two-keyid Map keystore
 * (two ed25519 fixtures signed outside timing with `created`
 * pinned, the verifier's `now` injected at the same instant),
 * self-checked on every measured pass (both results ok and
 * each returned `keyId` equal to its pinned value), with the
 * unknown-keyid `KEY_RESOLUTION_FAILED` result and the
 * `key` + `keyResolver` mutual-exclusion configuration error
 * asserted outside timing, plus the maximum-signature-age
 * verify path a receiver runs to bound replayability of
 * long-lived signed messages: `verifyRequest` with
 * `maxSignatureAgeSec` over one ed25519 fixture signed
 * outside timing with `created` pinned (the verifier's
 * `now` injected 60 seconds later, inside the 300-second
 * cap — see MAX_AGE_* below), self-checked on every
 * measured pass (the result is ok), with the past-cap
 * `SIGNATURE_TOO_OLD` result (pinned code and reason) and
 * the no-`created` bypass (a hand-built undated signature
 * still verifies at the past-cap instant) asserted
 * outside timing, plus the expiry-presence verify path a
 * receiver runs to refuse signatures with no bounded
 * lifetime: `verifyRequest` with `requireExpires` over one
 * ed25519 fixture signed outside timing with `created` and
 * `expires` both pinned (the verifier's `now` injected at
 * the `created` instant — see REQUIRE_EXPIRES_* below),
 * self-checked on every measured pass (the result is ok),
 * with the hand-built no-`expires` signature's pinned
 * `MISSING_EXPIRES` result (code and reason) and that same
 * signature's acceptance without the option asserted
 * outside timing, plus the created-presence verify path a
 * receiver runs to refuse undated signatures:
 * `verifyRequest` with `requireCreated` over a hand-built
 * no-`created` signature (built with `buildSignatureBase`
 * + `signatureInputValue` + a raw ed25519 sign, the shape
 * `test/requireFreshness.test.ts` uses, because
 * `signRequest` always emits `created` — see
 * REQUIRE_CREATED_* below), self-checked on every
 * measured pass (the result is exactly the pinned
 * `MISSING_CREATED` code and reason), with that same
 * signature's acceptance without the option, a dated
 * fixture's acceptance under the requirement, and a
 * forged no-`created` signature's pinned
 * `SIGNATURE_MISMATCH` result (the crypto check runs
 * first) asserted outside timing, plus the
 * application-tag-pinning verify
 * path a receiver runs for cross-protocol replay
 * protection: `verifyRequest` with `expectedTag` over one
 * ed25519 fixture signed outside timing with `created`
 * pinned and `tag` pinned to one application protocol
 * (the verifier's `now` injected at the `created` instant —
 * see EXPECTED_TAG_* below), self-checked on every
 * measured pass (the result is ok and the returned `tag`
 * equals the pinned value), with the same signature's
 * pinned `TAG_MISMATCH` result (code and reason) under a
 * different expectation, the no-`tag` signature's pinned
 * `TAG_MISMATCH` (`got no tag`) result, and that same
 * signature's acceptance without the option asserted
 * outside timing, plus the replay-defense verify
 * path a receiver runs to refuse already-seen
 * requests: `verifyRequest` with `replayCache` over
 * one ed25519 fixture signed outside timing with
 * `created` pinned and a pinned `nonce` (the
 * verifier's `now` injected at the `created`
 * instant, and the cache shares that injected
 * instant — see REPLAY_CACHE_* below), self-checked
 * on every measured pass (each measured op verifies
 * the fixture once against a fresh cache — the
 * nonce is recorded and the result is ok — then
 * verifies again and re-pins exactly the pinned
 * `NONCE_REPLAY` code and reason), with that same
 * fixture's double acceptance without a cache, a
 * nonce-less signature's double acceptance under a
 * cache, and a forged signature's non-polluting
 * `SIGNATURE_MISMATCH` result asserted outside
 * timing, plus the nonce-presence verify path a
 * receiver runs to refuse nonce-less signatures before
 * they ever reach the replay store: `verifyRequest` with
 * `requireNonce` over one ed25519 fixture signed outside
 * timing with `created` pinned and `nonce` pinned (the
 * verifier's `now` injected at the `created` instant —
 * see REQUIRE_NONCE_* below), self-checked on every
 * measured pass (the result is ok and the returned
 * `nonce` equals the pinned value), with a nonce-less
 * signature's pinned `MISSING_NONCE` result (code and
 * reason) and that same signature's acceptance without
 * the option asserted outside timing, plus the clock-skew
 * verify path a
 * receiver runs to tolerate a signer clock running ahead:
 * `verifyRequest` with `clockSkewToleranceSec` over one
 * ed25519 fixture signed outside timing with `created`
 * pinned 30 seconds ahead of the verifier's injected
 * `now` (see CLOCK_SKEW_* below), self-checked on every
 * measured pass (the result is ok under a 120-second
 * tolerance), with the same fixture's pinned
 * `CREATED_IN_FUTURE` result (code and reason) under a
 * 10-second tolerance, its acceptance exactly at the
 * tolerance boundary (the comparison is strict `>`), and
 * its acceptance with no option passed (the 60-second
 * default covers the 30-second skew) asserted outside
 * timing, plus the expired-grace verify path a receiver
 * runs to accept a just-expired signature inside a
 * caller-pinned grace window: `verifyRequest` with
 * `expiredToleranceSec` over one ed25519 fixture signed
 * outside timing with `expires` pinned 30 seconds before
 * the verifier's injected `now` (see
 * EXPIRED_TOLERANCE_* below), self-checked on every
 * measured pass (the result is ok under a 120-second
 * grace), with the same fixture's pinned `EXPIRED`
 * result (code and reason) under a 10-second grace, its
 * acceptance exactly at the grace boundary (the
 * comparison is strict `>`), its rejection under the
 * default zero grace, and a hand-built born-expired
 * signature's pinned `INVALID_TIME_WINDOW` result
 * inside a wide grace asserted outside timing, plus the key-id binding verify path a
 * receiver runs to pin the expected signer key:
 * `verifyRequest` with `expectedKeyId` over one
 * ed25519 fixture signed outside timing with `created`
 * pinned under a pinned keyid (see EXPECTED_KEY_ID_*
 * below), self-checked on every measured pass (the
 * result is ok and its returned `keyId` equals the
 * pinned value), with the mismatched pin's pinned
 * `KEYID_MISMATCH` result (code and reason), the
 * hand-built no-keyid signature's `KEYID_MISMATCH`
 * result with the `got no keyid` reason shape, and
 * that signature's acceptance with no option passed
 * asserted outside timing, plus the per-label key-id
 * binding verify path a multi-party receiver runs to
 * pin each signer's key independently:
 * `verifyAllLabels` with `expectedKeyIds` over a dual
 * ed25519 fixture signed outside timing with `created`
 * pinned under two pinned keyids (see
 * EXPECTED_KEY_IDS_* below), self-checked on every
 * measured pass (both results are ok, in wire order,
 * and each returned `keyId` equals its label's pinned
 * value), with one label's mismatched pin returning
 * the pinned `KEYID_MISMATCH` result (code and
 * reason) while the other label still verifies, a
 * label missing from the map falling back to the
 * global `expectedKeyId` (both the matching and the
 * mismatching fallback halves), and an empty-string
 * map value throwing the pinned configuration error
 * asserted outside timing, plus the per-label key-resolution
 * verify path a multi-party receiver runs when each
 * signer's keyids live in a separate keystore:
 * `verifyAllLabels` with `keyResolvers` over a dual
 * ed25519 fixture signed outside timing with `created`
 * pinned under two pinned keyids, each belonging to
 * its own resolver (see KEY_RESOLVERS_ALL_* below),
 * self-checked on every measured pass (both results
 * are ok, in wire order, and each returned `keyId`
 * equals its label's pinned value), with one label's
 * resolver returning `undefined` giving that label
 * the pinned `KEY_RESOLUTION_FAILED` result while
 * the other label still verifies, a label missing
 * from the map falling back to the global
 * `keyResolver`, a non-function map value throwing
 * the pinned configuration error, and `keyResolvers`
 * combined with `keys` throwing the pinned
 * mutual-exclusion configuration error asserted
 * outside timing, plus the per-label nonce-presence
 * verify path a multi-party receiver runs when only
 * one signer must carry a nonce: `verifyAllLabels`
 * with `requireNonceByLabel` over a dual ed25519
 * fixture signed outside timing with `created`
 * pinned (merchant with a pinned nonce, gateway
 * without one — see REQUIRE_NONCE_BY_LABEL_* below),
 * self-checked on every measured pass (one measured
 * op verifies both the nonce-carrying dual, both
 * labels ok with the merchant nonce returned, and
 * the nonce-less-merchant dual, merchant exactly
 * `MISSING_NONCE` with the pinned reason while the
 * unmapped gateway label still verifies by falling
 * back to the unset global), with that same
 * nonce-less dual's acceptance with no option
 * passed asserted outside timing, plus the per-label candidate-keys verify
 * path a multi-party receiver runs when each signer rotates keys on its
 * own schedule: `verifyAllLabels` with `candidateKeysByLabel` over a dual
 * fixture signed outside timing with `created` pinned (merchant ed25519
 * fixed key, gateway hmac-sha256 rotation window — see
 * CANDIDATE_KEYS_BY_LABEL_* below), self-checked on every measured pass
 * (one measured op verifies three duals: the new-secret dual, both
 * labels ok with the gateway found at the second candidate; the
 * old-secret dual, both labels ok inside the rotation window; and the
 * swapped-merchant-list dual, merchant exactly `SIGNATURE_MISMATCH`
 * while the gateway label still verifies, proving each label tries only
 * its own candidate list), with the unmapped gateway label falling back
 * to the global `candidateKeys` and the `candidateKeysByLabel` + `keys`
 * mutual-exclusion configuration error asserted outside timing, plus
 * the per-label tag-presence verify path a multi-party receiver runs
 * when only one signer must carry a tag: `verifyAllLabels` with
 * `requireTagByLabel` over a dual ed25519 fixture signed outside timing
 * with `created` pinned (merchant with a pinned tag, gateway without
 * one — see REQUIRE_TAG_BY_LABEL_* below), self-checked on every
 * measured pass (one measured op verifies both the tag-carrying dual,
 * both labels ok with the merchant tag returned, and the
 * tag-less-merchant dual, merchant exactly `MISSING_TAG` with the
 * pinned reason while the unmapped gateway label still verifies by
 * falling back to the unset global), with that same tag-less dual's
 * acceptance with no option passed, an explicit `merchant: false`
 * map entry letting it through, and a differently-tagged merchant
 * fixture still verifying asserted outside timing, plus
 * the per-label tag-pinning verify path a multi-party
 * receiver runs when each signer must bind its signature
 * to its own application protocol: `verifyAllLabels` with
 * `expectedTags` over a dual ed25519 fixture signed
 * outside timing with `created` pinned (merchant tag
 * pinned to one protocol, gateway tag pinned to another
 * — see EXPECTED_TAGS_* below), self-checked on every
 * measured pass (one measured op verifies both the
 * fully pinned dual, both labels ok with each tag
 * echoed at its pinned value, and the
 * differently-tagged-gateway dual, merchant still ok
 * while the gateway label is exactly `TAG_MISMATCH`
 * with the pinned reason, proving the failure is the
 * tag value and not a signature error), with a label
 * missing from the map falling back to the global
 * `expectedTag` (both the matching and the mismatching
 * fallback halves) and the same dual's acceptance with
 * no option passed asserted outside timing, plus
 * the per-label freshness-window verify path a multi-party
 * receiver runs when each signer must bound its own signature
 * differently: `verifyAllLabels` with
 * `maxSignatureAgeSecByLabel` over a dual ed25519 fixture
 * signed outside timing with `created` pinned 120s before
 * the injected `now` (merchant window 60s, gateway window
 * 3600s — see MAX_AGE_BY_LABEL_* below), self-checked on
 * every measured pass (one measured op verifies the split
 * dual, merchant exactly `SIGNATURE_TOO_OLD` with the
 * pinned reason while the gateway label still verifies),
 * with a label missing from the map falling back to the
 * global `maxSignatureAgeSec` (both the matching and the
 * mismatching fallback halves) and the same dual's
 * acceptance with no option passed asserted outside
 * timing, plus
 * the per-label clock-skew verify path a multi-party
 * receiver runs when each signer clock may run ahead by
 * a different amount: `verifyAllLabels` with
 * `clockSkewToleranceSecByLabel` over a dual ed25519
 * fixture signed outside timing with `created` pinned
 * 120s ahead of the injected `now` (merchant tolerance
 * 5s, gateway tolerance 300s — see
 * CLOCK_SKEW_BY_LABEL_* below), self-checked on every
 * measured pass (one measured op verifies the split
 * dual, merchant exactly `CREATED_IN_FUTURE` with the
 * pinned reason while the gateway label still verifies),
 * with a label missing from the map falling back to the
 * global `clockSkewToleranceSec` (both directions: the
 * merchant-only map with a wide global, and the
 * gateway-only map with a narrow global) and the same
 * dual's rejection under no option passed (the 60s
 * default covers neither 120s-ahead label) asserted
 * outside timing, plus
 * the per-label expiry-grace verify path a multi-party
 * receiver runs when each signer must tolerate a different
 * grace window past `expires`: `verifyAllLabels` with
 * `expiredToleranceSecByLabel` over a dual ed25519
 * fixture signed outside timing with `created` pinned
 * 3600s before the injected `now` and `expires` pinned
 * 60s before it (merchant tolerance 0s, gateway
 * tolerance 120s — see EXPIRED_TOLERANCE_BY_LABEL_*
 * below), self-checked on every measured pass (one
 * measured op verifies the split dual, merchant
 * exactly `EXPIRED` with the pinned reason while the
 * gateway label still verifies), with the exact-tolerance
 * boundary (both labels at 60s pass, since the check
 * is strict-greater), a label missing from the map
 * falling back to the global `expiredToleranceSec`
 * (both directions: the merchant-only map with a wide
 * global, and the gateway-only map with a narrow
 * global) and the same dual's rejection under no option
 * passed (the 0s default covers neither 60s-expired
 * label) asserted outside timing, plus
 * the per-label required-freshness verify path a multi-party
 * receiver runs when each signer must bound its own signature
 * differently: `verifyAllLabels` with `requireCreatedByLabel`
 * / `requireExpiresByLabel` over hand-built dual fixtures
 * signed outside timing with `created` / `expires` pinned
 * (merchant mapped created-required, gateway mapped
 * expires-required, globals unset — see
 * REQUIRE_FRESHNESS_BY_LABEL_* below), self-checked on every
 * measured pass (one measured op verifies three duals: the
 * fully dated dual, both labels ok; the no-created-merchant
 * dual, merchant exactly `MISSING_CREATED` with the pinned
 * reason while the gateway label still verifies; and the
 * no-expires-gateway dual, gateway exactly `MISSING_EXPIRES`
 * with the pinned reason while the merchant label still
 * verifies), with both undated duals' acceptance with no
 * option passed and explicit `false` map entries letting them
 * through asserted outside timing, plus
 * the per-label dual-required freshness-existence verify path a multi-party
 * receiver runs when one signer must carry both timestamps while the other
 * carries neither: `verifyAllLabels` with `requireCreatedByLabel` /
 * `requireExpiresByLabel` both mapped `true` on the merchant label and the
 * gateway label mapped on neither, globals unset (see
 * REQUIRE_CREATED_EXPIRES_BY_LABEL_* below), self-checked on every
 * measured pass (one measured op verifies four duals: the fully dated dual,
 * both labels ok; the no-created-merchant dual, merchant exactly
 * `MISSING_CREATED` with the pinned reason while the fully dated gateway
 * label still verifies; the no-expires-merchant dual, merchant exactly
 * `MISSING_EXPIRES` with the pinned reason while the fully dated gateway
 * label still verifies; and the undated-gateway dual, both labels ok,
 * proving the gateway's unmapped state leaks in neither direction), with
 * the both-missing merchant dual reporting `MISSING_CREATED` first, all
 * undated duals' acceptance with no option passed, and explicit `false`
 * map entries letting them through asserted outside timing, plus
 * the algorithm-inference verify path a
 * receiver runs for foreign signers that omit the optional
 * `alg` parameter: `verifyRequest` with
 * `algFallback: "infer"` over the RFC 9421 Appendix B.2.5
 * no-`alg` wire value verbatim against its pinned shared
 * secret (see ALG_FALLBACK_* below), self-checked on every
 * measured pass (the result is ok and the inferred `alg`
 * and returned `keyId` equal their pinned values), with
 * the same wire's pinned `VERIFICATION_ERROR` result
 * without the opt-in (the legacy `ed25519` default is
 * tried against the secret key), a wire `alg` that
 * contradicts the key's shape throwing the pinned
 * configuration error, and a secp256k1 key shape with no
 * supported mapping throwing the pinned cannot-infer
 * configuration error asserted outside timing, plus the refresh path a gateway runs when its
 * snapshot ages out: `JwksKeyStore.refreshIfStale` over a store
 * whose injected clock is advanced exactly to its TTL boundary
 * before every measured call (a counting fake fetch serves one
 * pinned JWKS document — zero network), self-checked on every
 * measured pass (the call must report a refresh, the fetch count
 * must advance by exactly one, and the pinned kid must resolve
 * afterwards), with the not-stale no-fetch case asserted outside
 * timing, plus the concurrent refresh path a gateway hits at cold
 * start / rotation time: `JwksKeyStore.refresh` single-flight
 * merging over eight concurrent calls on a stale store (a counting
 * fake fetch serves one pinned JWKS document, resolving on a
 * microtask tick — zero network), self-checked on every measured
 * batch (the fetch count and `stats().refreshes` must each advance
 * by exactly one per batch of eight, and the pinned kid must
 * resolve afterwards), with a shared-failure batch (all eight
 * waiters receive the same rejection from exactly one fetch) and
 * the failure-not-cached retry asserted outside timing, plus the
 * fetch-retry refresh path a gateway runs when its JWKS endpoint is
 * briefly sick: `JwksKeyStore.refresh` with `fetchRetries: 2` over a
 * counting fake fetch scripted 500, 500, 200 (a stub sleep records
 * the two fixed backoffs without waiting — zero network, zero wall
 * clock), self-checked on every measured pass (each refresh makes
 * exactly three fetches, records exactly two sleeps of the pinned
 * backoff, counts exactly one `stats().refreshes`, and the pinned
 * kid resolves afterwards), with the terminal-4xx case (one fetch,
 * zero sleeps, pinned HTTP 404 error) and the exhausted-retries
 * case (three fetches, two sleeps, pinned HTTP 500 error, exactly
 * one `stats().refreshFailures`) asserted outside timing, plus the key-management
 * derivation a JWKS publisher runs for every key at publish/rotation
 * time: `jwkThumbprint` (RFC 7638) over a fixed three-shape fixture
 * (ed25519 / P-256 / RSA public JWKs, one derivation per shape per
 * measured call, self-checked outside timing against independently
 * pinned thumbprints — the RSA one is the RFC 7638 §3.1 published
 * value), plus the replay-detection
 * hot path a verifier with `requireNonce` hits on every request:
 * `ReplayCache.check` hits against a cache prefilled with 1,000 nonces
 * under a deterministic fake clock (zero network, zero wall clock for
 * the cache itself), plus the snapshot-export path a single-process
 * verifier runs to carry its tracked nonces across a restart:
 * `ReplayCache.exportSnapshot` over a fixed-clock cache holding three
 * live nonces and one already-expired nonce (see REPLAY_EXPORT_*
 * below), self-checked on every measured pass against the hand-pinned
 * live entries (version, live-entry count, first/last entries item by
 * item, expired nonce absent), with the detached-copy and empty-cache
 * exports asserted outside timing, plus the observability snapshot
 * path a verifier's monitoring polls on every tick:
 * `ReplayCache.stats()` over a fixed-clock cache whose map holds
 * six recorded nonces — one LRU-evicted during construction, one
 * exactly at its TTL boundary at the stats instant (expired but
 * still in the map) and five live (see REPLAY_STATS_* below) —
 * self-checked on every measured pass against the hand-pinned
 * `{ size, hits, misses, evictions }` snapshot (size counts only
 * the live entries), with the detached-copy and empty-cache
 * readings asserted outside timing, plus the snapshot-restore
 * path a single-process verifier runs at startup to rebuild its
 * replay cache from the persisted snapshot:
 * `ReplayCache.fromSnapshot` over a pinned envelope exported from
 * a fixed-clock source cache holding four live nonces (see
 * REPLAY_RESTORE_* below), self-checked on every measured pass
 * against the hand-pinned expectations (the restored cache's
 * `size` and zeroed `stats()` counters, and every restored nonce
 * still reporting a replay on `check`), with the expired-at-
 * restore drop and the corrupt-envelope rejections (wrong
 * version, malformed entry) asserted outside timing, plus the malformed-input rejection path:
 * `verifyRequest` over a fixed-seed corpus of malformed
 * signature-input / signature values (the parser rejection traffic a
 * verification gateway faces), self-checked to always return
 * `{ ok: false, code }` and never throw, plus the standalone body-hash
 * primitive every signed/verified request pays for: `contentDigest`
 * over the shared 31-byte fixture body, measured separately for
 * sha-512 and sha-256 and self-checked outside timing against
 * independently pinned digest values (see DIGEST_EXPECTED below), so
 * the cost of hashing a body is visible apart from the asymmetric
 * signing it is normally bundled into, plus the inbound
 * normalization every gateway request pays before verification even
 * starts: `fromNodeRequest` over a fixed mock `IncomingRequestLike`
 * (no real server, zero network on this path), self-checked outside timing
 * against a hand-pinned expected `RequestLike` (see NODE_FIXTURE
 * below), plus the response-side normalization and verification a
 * client pays on every gateway-signed settlement callback:
 * `fromNodeResponse` over one real loopback `http` response signed
 * by a live server (loopback only, no external network; see RESP_*
 * below), self-checked on every measured pass (adapted `@status`
 * pinned 200, settlement trailer pinned, verification ok), with the
 * missing-status fail-fast and the transplanted-request
 * `SIGNATURE_MISMATCH` asserted outside timing, plus the
 * key-distribution round trip a JWKS publisher /
 * verifier pays for every key: `exportPublicKeyJwk*` →
 * JSON stringify/parse → `importPublicKeyJwk*` for each of P-256,
 * P-384, P-521 and RSA (one freshly generated key pair per shape,
 * generated outside timing; the RSA pair is the library's 2048-bit
 * default and its JWK is shared by both RSA algorithms),
 * self-checked outside timing by comparing the re-imported public
 * key's SPKI DER byte-for-byte against the original's — an
 * independent node:crypto encoding, not the JWK helpers' own
 * output, plus the same round trip for the library's default
 * algorithm: `exportPublicKeyJwk` → JSON stringify/parse →
 * `importPublicKeyJwk` over one fixed ed25519 key pair (generated
 * once outside timing), self-checked on every measured pass
 * against the hand-pinned OKP JWK shape (`kty` OKP, `crv`
 * Ed25519, a non-empty `x` and no private `d` field — the shape
 * a JWKS document actually distributes for ed25519), with a full
 * sign → verify over the re-imported public key asserted
 * outside timing (see the ed25519 JWK round-trip section below),
 * plus the PEM (SPKI / PKCS#8) round trip a signer /
 * verifier pays when keys are handed over as PEM files — the
 * standard encoding for gateways, KMS tooling and peer verifiers:
 * `exportPublicKeyPem` + `exportPrivateKeyPem` on one fixed
 * ed25519 key pair (the same shape the CLI demo's PEM segment
 * uses, generated once outside timing), re-imported with
 * `importPublicKey` / `importPrivateKey`, self-checked on every
 * measured pass — both PEM first lines must equal the hand-pinned
 * type headers and the re-imported public key's JWK thumbprint
 * must equal the original's — with a full sign → verify over the
 * re-imported keys asserted outside timing (see PEM_* below), so
 * the serialization-plus-reparse cost of the PEM form is visible
 * apart from the JWK round-trip rows above that cover the JSON
 * form, plus the pure string-building step every sign/verify pays
 * before any cryptography runs: `buildSignatureBase` over the
 * shared fixture request with the fixed covered set
 * `@method @authority @path content-digest`, self-checked outside
 * timing against a hand-written expected base text (see
 * BASE_EXPECTED below), so the cost of resolving covered
 * components and serializing the signature base is visible apart
 * from the algorithm costs it is normally bundled into, plus the
 * end-to-end signing step a signer actually calls: `signRequest`
 * over the shared fixture with one fixed ed25519 key pair
 * (generated once outside timing, `created` pinned — see
 * SIGNREQ_* below), self-checked on every measured pass (both
 * signature headers present, the label and the full
 * `signature-input` value hand-pinned, the signature a 64-byte
 * ed25519 value) with a full `verifyRequest` pass and a
 * tampered-body rejection asserted outside timing, so the total
 * sign cost (base building + cryptography + header
 * serialization) has one checked row of its own apart from the
 * per-algorithm scenario rows, whose sign calls discard their
 * output unchecked, plus the
 * three standalone parsers a gateway pre-screen calls directly —
 * `listSignatureLabels`, `parseSignatureInput` and
 * `parseSignatureField` — over a fixed hand-written dual-label
 * fixture (see PARSER_* below), self-checked outside timing
 * against hand-pinned parse shapes and a hand-pinned malformed
 * set that must all throw, so the pure parsing cost before any
 * cryptography is visible apart from the end-to-end verify paths
 * that bundle it, plus the strict Structured Field canonicalization
 * every `;sf` covered component pays on both sides:
 * `canonicalizeStructuredFieldValue` over a fixed six-value corpus
 * (Dictionary / List / Item shapes, decimal and leading-zero integer
 * boundaries, and a Byte Sequence member — see SF_FIXTURE below),
 * self-checked on every measured pass against hand-pinned expected
 * serializations, so the parse-then-reserialize cost of the `;sf`
 * path is visible apart from the end-to-end `;sf` verify total that
 * bundles it, plus the throwing verify wrapper a middleware-style
 * caller actually uses: `verifyRequestOrThrow`, measured as two
 * separate rows — the success path (result unwrapping) over one
 * fixed valid ed25519 request and the failure path (VerifyError
 * construction carrying the pinned `SIGNATURE_MISMATCH` code) over
 * the same request with one signature byte flipped, each
 * self-checked on every measured call (see ORTHROW_* below), so the
 * cost difference between the result-object and throwing APIs —
 * including exception construction on failure — is visible, plus
 * the single-member extraction every `;key` covered component
 * pays: `serializeDictionaryMemberValue` over one fixed
 * multi-member Dictionary value and a fixed six-key set (see
 * DICT_MEMBER_* below), self-checked on every measured pass
 * against hand-pinned expected serializations with the
 * missing-key throw asserted outside timing, so the
 * parse-whole-dictionary-then-extract-one-member cost is visible
 * apart from the whole-value canonicalization above, plus the
 * signature-parameter serialization every sign/verify pays before
 * any cryptography runs: `serializeSignatureParams` over a fixed
 * five-case corpus (see SIG_PARAMS_* below) spanning zero to four
 * covered components, plain and parameterized component ids, and
 * parameter sets from three members up to all six, self-checked
 * on every measured pass against hand-pinned expected strings, so
 * the inner-list-plus-parameters cost is visible apart from the
 * `buildSignatureBase` row that bundles it with component
 * resolution, plus the nonce generation an anti-replay signer
 * pays on every request: `generateNonce` at the two fixed byte
 * tiers (the default 16 bytes and 32 bytes, one generation per
 * tier per measured call, see NONCE_* below), self-checked on
 * every measured call only for the shape the generateNonce test
 * pins — exact length (22 / 43 base64url characters) and
 * base64url-only characters, never a specific value — so the
 * CSPRNG-plus-encoding cost is visible as the fixed per-request
 * overhead it is (the random source is the system CSPRNG via
 * node:crypto, so the numbers include entropy-source cost), plus
 * the case-insensitive header lookup every covered-component
 * resolution pays on the signer and the verifier: `getHeader`
 * (canonical form — multi-value elements trimmed and joined
 * with ", ") and `getHeaderRaw` (raw form — elements joined
 * untrimmed, the form a `;bs` component binds) over a fixed
 * multi-header fixture (see HEADER_* below), self-checked on
 * every measured pass against hand-pinned expected values for
 * both forms, with missing and undefined-valued headers
 * asserted outside timing, so the per-component scan-and-fold
 * cost is visible apart from the end-to-end sign/verify paths
 * that bundle it, plus the multi-value header combination every
 * canonical lookup and signer-side fold pays: `joinHeaderValues`
 * over a fixed multi-value corpus (see JOIN_* below) spanning
 * empty, single-value, multi-value, whitespace-padded and
 * empty-element cases, self-checked on every measured pass
 * against hand-pinned expected combinations — the trim-each-
 * element-then-join-with-", " step (RFC 9421 §2.5) that turns a
 * repeated header on a proxy chain into the one canonical
 * string both sides sign, visible apart from the lookup rows
 * above that bundle it with the case-insensitive scan, plus the
 * digest-algorithm identification a signer appending a second
 * signature pays before it can pin itself to the wire value:
 * `contentDigestAlgOf` over a fixed ten-case corpus (see
 * DIGEST_ALG_* below) spanning both emittable algorithms, both
 * orders of a mixed two-algorithm value, unknown algorithms,
 * and malformed shapes, self-checked on every measured pass
 * against hand-pinned expected results — including the
 * `undefined` fail-closed outcome for every value whose first
 * `=`-prefix is not exactly `sha-512` or `sha-256` — so the
 * prefix-scan cost is visible apart from the digest hashing
 * and the end-to-end paths that bundle it, plus the HMAC
 * secret-length guard every HMAC sign/verify pays before any
 * MAC runs: `assertHmacSecretLength` over a fixed ten-case
 * corpus (see HMAC_GUARD_* below) spanning, for each algorithm,
 * an empty secret, one byte below the floor, exactly at the
 * floor, and far above it — plus the 32-byte secret that passes
 * for hmac-sha256 but fails for hmac-sha512 — self-checked on
 * every measured pass against hand-pinned pass/throw outcomes
 * (including the exact floor and byte count in each throw
 * message), so the fail-closed key-length check is visible
 * apart from the HMAC sign/verify rows that bundle it, plus
 * the RSA modulus-length guard every rsa-v1_5-sha256
 * sign/verify pays before any RSA operation runs:
 * `assertRsaModulusLength` over a fixed seven-case corpus
 * (see RSA_GUARD_* below) spanning a 2048-bit RSA pair at
 * exactly the floor (public and private, both pass), a
 * 1024-bit RSA pair below the floor (public and private,
 * both throw the pinned modulus message), and three
 * wrong-shape keys (ed25519, P-256 and a symmetric secret,
 * each throwing the pinned expected-an-RSA-key message) —
 * all keys generated once at bench start, never inside the
 * timed region — self-checked on every measured pass
 * against hand-pinned pass/throw outcomes, so the
 * fail-closed modulus check is visible apart from the RSA
 * sign/verify rows that bundle it, plus the full
 * `Signature-Input` field-value building every signer pays
 * once per label: `signatureInputValue` over a fixed
 * four-case corpus (see SIG_INPUT_* below) spanning a bare
 * single-component value with no parameters, the golden
 * four-component value, a second label carrying all six
 * parameters, and parameterized component ids with an
 * escaped nonce — self-checked on every measured pass
 * against hand-pinned expected strings, with the
 * dual-label header join (the two single-label values
 * joined with ", ", the merge the multi-label tests pin)
 * asserted outside timing. Note the function builds the
 * field value (`label=` plus the serialized parameters);
 * it does not look a label up in a request, so there is
 * no missing-label / undefined outcome to pin — an empty
 * parameter set renders as the bare inner list, plus the
 * content-digest algorithm guard every sign/verify that
 * selects a digest algorithm pays before any hashing runs:
 * `assertContentDigestAlg` over a fixed ten-case corpus
 * (see DIGEST_GUARD_* below) spanning the two emittable
 * algorithms (sha-512 and sha-256, both pass) and eight
 * illegal shapes (sha-1, md5, the empty string, two
 * wrong-case spellings, a trailing-space spelling, and the
 * non-string values undefined and null, each throwing the
 * pinned full configuration-error message) — self-checked
 * on every measured pass against hand-pinned pass/throw
 * outcomes, so the fail-fast configuration check is visible
 * apart from the digest hashing and sign/verify rows that
 * bundle it, plus the per-component resolution every sign
 * and verify pays once per covered component:
 * `resolveComponent` over a fixed eighteen-case corpus
 * (see RESOLVE_* below) spanning derived components
 * (`@method` / `@scheme` / `@authority` / `@path` /
 * `@query` / `@request-target` / `@target-uri` /
 * `@query-param;name="…"` / `@created` / `@status`), plain
 * header fields, and the parameterized forms (`;bs` /
 * `;sf` / `;key="…"` / `;tr` / `;req` on both a derived
 * component and a header field), self-checked on every
 * measured pass against hand-pinned expected values, with
 * the unsupported-parameter rejection asserted outside
 * timing, so the cost of turning one covered component
 * into its signature-base value is visible apart from the
 * `buildSignatureBase` row that bundles it with the
 * `@signature-params` serialization, plus the
 * component-coverage policy check a receiver runs before
 * any cryptography: `verifyRequest` with
 * `requiredComponents` over one ed25519 fixture signed
 * outside timing covering exactly `@method`, `@path`
 * and `content-digest`, self-checked on every measured
 * pass (the result is ok with all three required —
 * see REQUIRED_COMPONENTS_* below), with the
 * one-missing-component rejection's pinned
 * `MISSING_REQUIRED_COMPONENT` code and singular reason,
 * the two-missing-components plural reason,
 * case-insensitive requirement matching, the opt-in
 * default-off behaviour, and the malformed-entry
 * configuration error asserted outside timing.
 * Numbers
 * vary with hardware — do not treat them as guaranteed throughput.
 *
 * Run: `npm run bench`
 */
import {
  createHmac,
  createSecretKey,
  createSign,
  generateKeyPairSync,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import { cpus } from "node:os";
import { createServer, get, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addSignature,
  assertContentDigestAlg,
  assertHmacSecretLength,
  assertRsaModulusLength,
  buildSignatureBase,
  canonicalizeStructuredFieldValue,
  contentDigest,
  contentDigestAlgOf,
  exportPrivateKeyPem,
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  exportPublicKeyPem,
  fromNodeRequest,
  fromNodeResponse,
  generateEd25519KeyPair,
  generateNonce,
  generateP256KeyPair,
  generateP384KeyPair,
  generateP521KeyPair,
  generateRsaPssKeyPair,
  generateRsaV15KeyPair,
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
  JwksKeyStore,
  joinHeaderValues,
  jwkThumbprint,
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
  signatureInputValue,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  type ContentDigestAlg,
  type IncomingRequestLike,
  type JwksFetchImpl,
  type RequestLike,
  type SignatureParams,
  type SignAlg,
  type SignedHttpRequest,
} from "../src/index.js";

const ITERATIONS = 3000;
const WARMUP = 200;

const fixture = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ amount: 100, currency: "USD" }),
};

function measure(fn: () => void, iterations: number): number {
  for (let i = 0; i < WARMUP; i++) fn(); // warmup: JIT, key caching
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) fn();
  const elapsedSec = Number(process.hrtime.bigint() - start) / 1e9;
  return iterations / elapsedSec;
}

/** Async twin of {@link measure} for paths that return a promise. */
async function measureAsync(
  fn: () => Promise<void>,
  iterations: number,
): Promise<number> {
  for (let i = 0; i < WARMUP; i++) await fn(); // warmup: JIT, key caching
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) await fn();
  const elapsedSec = Number(process.hrtime.bigint() - start) / 1e9;
  return iterations / elapsedSec;
}

function benchmarkScenario(alg: SignAlg): { signOps: number; verifyOps: number } {
  let signKey: Parameters<typeof signRequest>[1]["key"];
  let verifyKey: Parameters<typeof verifyRequest>[1]["key"];

  if (alg === "ed25519") {
    const { publicKey, privateKey } = generateEd25519KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "ecdsa-p256-sha256") {
    const { publicKey, privateKey } = generateP256KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "ecdsa-p384-sha384") {
    // Same fixture caliber as the P-256 path above: one fresh key pair
    // (generateP384KeyPair) generated once per scenario, outside the
    // timed loops; only sign/verify calls are measured.
    const { publicKey, privateKey } = generateP384KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "ecdsa-p521-sha512") {
    // Same fixture caliber as the P-256 / P-384 paths above: one fresh
    // key pair (generateP521KeyPair) generated once per scenario,
    // outside the timed loops; only sign/verify calls are measured.
    // P-521 signatures are raw r||s with each limb padded to 66 bytes
    // (132 bytes total, RFC 9421 §3.3.6).
    const { publicKey, privateKey } = generateP521KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "rsa-pss-sha512") {
    const { publicKey, privateKey } = generateRsaPssKeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else if (alg === "rsa-v1_5-sha256") {
    const { publicKey, privateKey } = generateRsaV15KeyPair();
    signKey = privateKey;
    verifyKey = publicKey;
  } else {
    // Per-algorithm HMAC floors (RFC 2104 §3): hmac-sha256 → ≥ 32 bytes,
    // hmac-sha512 → ≥ 64 bytes. secretKey() enforces the 32-byte floor;
    // the 64-byte secret here also satisfies it, so the same helper works.
    const secret = secretKey(Buffer.alloc(alg === "hmac-sha512" ? 64 : 32, 0x42));
    signKey = secret;
    verifyKey = secret;
  }

  // A fresh request object per sign call: signRequest does not mutate its
  // input, and re-signing the same object is the honest steady-state cost.
  const signOpts = { keyId: "bench-key", alg, key: signKey };
  const signOps = measure(() => {
    signRequest(fixture, signOpts);
  }, ITERATIONS);

  const signed: SignedHttpRequest = signRequest(fixture, signOpts);
  const verifyOpts = { key: verifyKey };
  const verifyOps = measure(() => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok) throw new Error(`benchmark self-check failed: ${r.reason}`);
  }, ITERATIONS);

  return { signOps, verifyOps };
}

/**
 * The canonical multi-party scenario from test/addSignature.test.ts:
 * the merchant signs the request with its ed25519 key, then the payment
 * gateway appends its own hmac-sha256 signature under a second label.
 * Measures the steady-state throughput of verifyAllLabels (both labels
 * verified independently per call).
 */
function benchmarkMultiLabel(): number {
  const { publicKey: merchantPublic, privateKey: merchantPrivate } =
    generateEd25519KeyPair();
  const gatewaySecret = secretKey("gateway-shared-secret-32-bytes-0!");

  const merchantSigned = signRequest(fixture, {
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
  });
  const dual = addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "hmac-sha256",
    key: gatewaySecret,
    label: "gateway",
  });

  return measure(() => {
    const results = verifyAllLabels(dual, {
      key: merchantPublic,
      keys: { gateway: gatewaySecret },
    });
    if (results.length !== 2 || results.some((r) => !r.ok)) {
      throw new Error(
        `benchmark self-check failed: ${JSON.stringify(results)}`,
      );
    }
  }, ITERATIONS);
}

/**
 * Build a JwksKeyStore entirely offline, as the backlog requires: the
 * store is restored from a snapshot of one freshly generated ed25519
 * key, and its fetch implementation throws if it is ever called — the
 * key-resolution benchmarks below perform zero network I/O.
 */
function offlineJwksStore(): JwksKeyStore {
  const { publicKey } = generateEd25519KeyPair();
  const snapshot = {
    v: 1 as const,
    fetchedAtSec: 1_700_000_000,
    keys: [{ ...exportPublicKeyJwk(publicKey), kid: "bench-key" }],
  };
  return JwksKeyStore.restore(
    snapshot,
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        throw new Error("benchmark must not fetch (offline store)");
      },
      now: () => 1_700_000_000,
    },
  );
}

/**
 * Pinned shape of the `JwksKeyStore.exportSnapshot` benchmark store:
 * the three key shapes the store supports (ed25519 / P-256 / RSA),
 * one freshly generated key pair per shape (generated once, outside
 * timing), restored offline under these kids at this fetch time.
 * The exported envelope must reproduce these literals exactly on
 * every pass — never values derived from `exportSnapshot` itself.
 */
const JWKS_EXPORT_FETCHED_AT_SEC = 1_700_000_000;
const JWKS_EXPORT_KIDS = [
  "bench-export-ed25519",
  "bench-export-p256",
  "bench-export-rsa",
] as const;
const JWKS_EXPORT_KTYS = ["OKP", "EC", "RSA"] as const;

/**
 * Build the three-shape JwksKeyStore for the export benchmark,
 * entirely offline like {@link offlineJwksStore}: restored from a
 * hand-built snapshot, with a fetch implementation that throws if
 * it is ever called — the export benchmark performs zero network I/O.
 */
function offlineJwksExportStore(): JwksKeyStore {
  const ed25519 = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const rsa = generateRsaPssKeyPair();
  const snapshot = {
    v: 1 as const,
    fetchedAtSec: JWKS_EXPORT_FETCHED_AT_SEC,
    keys: [
      { ...exportPublicKeyJwk(ed25519.publicKey), kid: JWKS_EXPORT_KIDS[0] },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: JWKS_EXPORT_KIDS[1] },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: JWKS_EXPORT_KIDS[2] },
    ],
  };
  return JwksKeyStore.restore(
    snapshot,
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        throw new Error("benchmark must not fetch (offline store)");
      },
      now: () => JWKS_EXPORT_FETCHED_AT_SEC,
    },
  );
}

/**
 * Pin one exported snapshot against the hand-written envelope
 * expectation: version 1, the pinned fetch time, exactly the three
 * pinned kids in restore order, the per-shape `kty` dispatch
 * (OKP / EC / RSA, the EC entry naming P-256), and public-only JWK
 * material — no entry may carry a private `"d"` member.
 */
function assertJwksExportSnapshot(
  snapshot: ReturnType<JwksKeyStore["exportSnapshot"]>,
): void {
  if (snapshot.v !== 1)
    throw new Error(
      `benchmark self-check failed: exportSnapshot v ${String(snapshot.v)} (expected 1)`,
    );
  if (snapshot.fetchedAtSec !== JWKS_EXPORT_FETCHED_AT_SEC)
    throw new Error(
      `benchmark self-check failed: exportSnapshot fetchedAtSec ${snapshot.fetchedAtSec} ` +
        `(expected ${JWKS_EXPORT_FETCHED_AT_SEC})`,
    );
  if (snapshot.keys.length !== JWKS_EXPORT_KIDS.length)
    throw new Error(
      `benchmark self-check failed: exportSnapshot exported ${snapshot.keys.length} keys ` +
        `(expected ${JWKS_EXPORT_KIDS.length})`,
    );
  for (let i = 0; i < JWKS_EXPORT_KIDS.length; i++) {
    const key = snapshot.keys[i]!;
    if (key.kid !== JWKS_EXPORT_KIDS[i])
      throw new Error(
        `benchmark self-check failed: exportSnapshot keys[${i}].kid ${JSON.stringify(key.kid)} ` +
          `(expected ${JSON.stringify(JWKS_EXPORT_KIDS[i])})`,
      );
    if (key.kty !== JWKS_EXPORT_KTYS[i])
      throw new Error(
        `benchmark self-check failed: exportSnapshot keys[${i}].kty ${JSON.stringify(key.kty)} ` +
          `(expected ${JSON.stringify(JWKS_EXPORT_KTYS[i])})`,
      );
    if ("d" in key)
      throw new Error(
        `benchmark self-check failed: exportSnapshot keys[${i}] carries private "d" material`,
      );
  }
  const ecCrv = (snapshot.keys[1] as { crv?: unknown }).crv;
  if (ecCrv !== "P-256")
    throw new Error(
      `benchmark self-check failed: exportSnapshot EC crv ${JSON.stringify(ecCrv)} (expected "P-256")`,
    );
}

/**
 * `JwksKeyStore.exportSnapshot` steady state: every measured call
 * re-exports the three-shape store and re-pins the whole envelope
 * (see {@link assertJwksExportSnapshot}) — the per-key JWK export
 * dispatch plus envelope assembly a gateway pays when it persists
 * its key store before a restart. Outside timing, the same pin runs
 * once exhaustively, and a never-refreshed store's export must be
 * refused with the pinned full message (there is no meaningful
 * `fetchedAtSec` for keys that were never fetched).
 */
function benchmarkJwksExportSnapshot(store: JwksKeyStore): number {
  assertJwksExportSnapshot(store.exportSnapshot());
  const fresh = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: async () => {
        throw new Error("benchmark must not fetch (offline store)");
      },
      now: () => JWKS_EXPORT_FETCHED_AT_SEC,
    },
  );
  let refusal: string | undefined;
  try {
    fresh.exportSnapshot();
  } catch (err) {
    refusal = err instanceof Error ? err.message : String(err);
  }
  if (
    refusal !==
    "JwksKeyStore: cannot export a snapshot before a successful refresh() " +
      "(no keys have been fetched yet)"
  )
    throw new Error(
      `benchmark self-check failed: unrefreshed exportSnapshot refusal ${JSON.stringify(refusal)}`,
    );
  return measure(() => {
    assertJwksExportSnapshot(store.exportSnapshot());
  }, ITERATIONS);
}

/**
 * Pinned shape of the `JwksKeyStore.restoreSnapshot` benchmark:
 * a source store refreshed once through a counting fake fetch
 * (three keys, one per supported shape, generated once outside
 * timing) at this fetch instant under a 120-second TTL, and a
 * target store primed through its own counting fake fetch at the
 * instant exactly one TTL after the source fetch — so in the
 * target's clock the exported envelope sits exactly at its
 * staleness boundary (`isStale()` uses `>=` semantics).
 */
const JWKS_RESTORE_FETCHED_AT_SEC = 1_700_000_000;
const JWKS_RESTORE_TTL_SEC = 120;
const JWKS_RESTORE_KIDS = [
  "bench-restore-jwks-ed25519",
  "bench-restore-jwks-p256",
  "bench-restore-jwks-rsa",
] as const;
const JWKS_RESTORE_KTYS = ["OKP", "EC", "RSA"] as const;
/** Kid of the target store's own primed key, replaced by a restore. */
const JWKS_RESTORE_TARGET_KID = "bench-restore-target-key";

/**
 * Pin one restore-source envelope against the hand-written
 * expectation: version 1, the pinned fetch time, exactly the
 * three pinned kids in document order, the per-shape `kty`
 * dispatch (OKP / EC / RSA, the EC entry naming P-256), and
 * public-only JWK material — no entry may carry a private `"d"`.
 */
function assertJwksRestoreSnapshot(
  snapshot: ReturnType<JwksKeyStore["exportSnapshot"]>,
): void {
  if (snapshot.v !== 1)
    throw new Error(
      `benchmark self-check failed: restoreSnapshot envelope v ${String(snapshot.v)} (expected 1)`,
    );
  if (snapshot.fetchedAtSec !== JWKS_RESTORE_FETCHED_AT_SEC)
    throw new Error(
      `benchmark self-check failed: restoreSnapshot envelope fetchedAtSec ${snapshot.fetchedAtSec} ` +
        `(expected ${JWKS_RESTORE_FETCHED_AT_SEC})`,
    );
  if (snapshot.keys.length !== JWKS_RESTORE_KIDS.length)
    throw new Error(
      `benchmark self-check failed: restoreSnapshot envelope carries ${snapshot.keys.length} keys ` +
        `(expected ${JWKS_RESTORE_KIDS.length})`,
    );
  for (let i = 0; i < JWKS_RESTORE_KIDS.length; i++) {
    const key = snapshot.keys[i]!;
    if (key.kid !== JWKS_RESTORE_KIDS[i])
      throw new Error(
        `benchmark self-check failed: restoreSnapshot envelope keys[${i}].kid ${JSON.stringify(key.kid)} ` +
          `(expected ${JSON.stringify(JWKS_RESTORE_KIDS[i])})`,
      );
    if (key.kty !== JWKS_RESTORE_KTYS[i])
      throw new Error(
        `benchmark self-check failed: restoreSnapshot envelope keys[${i}].kty ${JSON.stringify(key.kty)} ` +
          `(expected ${JSON.stringify(JWKS_RESTORE_KTYS[i])})`,
      );
    if ("d" in key)
      throw new Error(
        `benchmark self-check failed: restoreSnapshot envelope keys[${i}] carries private "d" material`,
      );
  }
  const ecCrv = (snapshot.keys[1] as { crv?: unknown }).crv;
  if (ecCrv !== "P-256")
    throw new Error(
      `benchmark self-check failed: restoreSnapshot envelope EC crv ${JSON.stringify(ecCrv)} (expected "P-256")`,
    );
}

/**
 * `JwksKeyStore.restoreSnapshot` steady state: every measured
 * call restores the pinned three-shape envelope into the primed
 * target store and re-pins the restore contract — the pinned
 * kid resolves afterwards, `stats()` is identical before and
 * after the restore (the counters are not part of a snapshot
 * and restoring resets none of them), the freshness timestamp
 * is the envelope's original fetch time, and `isStale()` counts
 * from that time, so at the target clock's TTL-boundary instant
 * the just-restored store is already stale. Outside timing, the
 * full contract is pinned once exhaustively (all three kids
 * resolve, the target's primed kid no longer does, the restored
 * store re-exports the identical envelope), and two corrupt
 * envelopes — an unsupported version and an empty kid — are
 * rejected with the pinned full messages while leaving the
 * store's keys, freshness and counters exactly as they were
 * (restore is fail-closed, never partially applied). Both
 * stores fetch only through counting fake fetches: the bench
 * performs zero network I/O and no wall-clock assertions.
 */
async function benchmarkJwksRestoreSnapshot(): Promise<number> {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const rsa = generateRsaPssKeyPair();
  const sourceDoc = {
    keys: [
      { ...exportPublicKeyJwk(ed.publicKey), kid: JWKS_RESTORE_KIDS[0] },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: JWKS_RESTORE_KIDS[1] },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: JWKS_RESTORE_KIDS[2] },
    ],
  };
  let sourceFetches = 0;
  const sourceFetch: JwksFetchImpl = async () => {
    sourceFetches++;
    return { ok: true, status: 200, json: async () => sourceDoc };
  };
  const source = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: sourceFetch,
      ttlSec: JWKS_RESTORE_TTL_SEC,
      now: () => JWKS_RESTORE_FETCHED_AT_SEC,
    },
  );
  await source.refresh();
  if (sourceFetches !== 1)
    throw new Error(
      `benchmark self-check failed: source store made ${sourceFetches} fetches (expected 1)`,
    );
  const snapshot = source.exportSnapshot();
  assertJwksRestoreSnapshot(snapshot);

  const targetPair = generateEd25519KeyPair();
  const targetDoc = {
    keys: [
      { ...exportPublicKeyJwk(targetPair.publicKey), kid: JWKS_RESTORE_TARGET_KID },
    ],
  };
  let targetFetches = 0;
  const targetFetch: JwksFetchImpl = async () => {
    targetFetches++;
    return { ok: true, status: 200, json: async () => targetDoc };
  };
  const targetNow = JWKS_RESTORE_FETCHED_AT_SEC + JWKS_RESTORE_TTL_SEC;
  const target = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    { fetchImpl: targetFetch, ttlSec: JWKS_RESTORE_TTL_SEC, now: () => targetNow },
  );
  await target.refresh();
  if (targetFetches !== 1 || target.isStale())
    throw new Error(
      "benchmark self-check failed: primed target store did not fetch exactly once or is stale at its own fetch instant",
    );
  if (target.resolve(JWKS_RESTORE_TARGET_KID) === undefined)
    throw new Error(
      "benchmark self-check failed: primed target store does not resolve its own kid",
    );
  if (target.resolve("bench-restore-unknown") !== undefined)
    throw new Error(
      "benchmark self-check failed: primed target store resolves an unknown kid",
    );
  const primedStats = target.stats();
  if (
    primedStats.refreshes !== 1 ||
    primedStats.refreshFailures !== 0 ||
    primedStats.hits !== 1 ||
    primedStats.misses !== 1
  )
    throw new Error(
      `benchmark self-check failed: primed target stats ${JSON.stringify(primedStats)} ` +
        "(expected refreshes 1, refreshFailures 0, hits 1, misses 1)",
    );

  // Outside timing: one restore pins the whole contract.
  target.restoreSnapshot(snapshot);
  if (JSON.stringify(target.stats()) !== JSON.stringify(primedStats))
    throw new Error(
      `benchmark self-check failed: restoreSnapshot changed stats ${JSON.stringify(target.stats())} ` +
        `(expected ${JSON.stringify(primedStats)})`,
    );
  if (target.size !== JWKS_RESTORE_KIDS.length)
    throw new Error(
      `benchmark self-check failed: restored size ${target.size} (expected ${JWKS_RESTORE_KIDS.length})`,
    );
  if (target.lastRefreshedAt !== JWKS_RESTORE_FETCHED_AT_SEC)
    throw new Error(
      `benchmark self-check failed: restored lastRefreshedAt ${target.lastRefreshedAt} ` +
        `(expected ${JWKS_RESTORE_FETCHED_AT_SEC})`,
    );
  if (!target.isStale())
    throw new Error(
      "benchmark self-check failed: restored store is not stale at the TTL boundary of the original fetch time",
    );
  for (const kid of JWKS_RESTORE_KIDS) {
    if (target.resolve(kid) === undefined)
      throw new Error(
        `benchmark self-check failed: restored store does not resolve ${kid}`,
      );
  }
  if (target.resolve(JWKS_RESTORE_TARGET_KID) !== undefined)
    throw new Error(
      "benchmark self-check failed: restored store still resolves the replaced target kid",
    );
  if (JSON.stringify(target.exportSnapshot()) !== JSON.stringify(snapshot))
    throw new Error(
      "benchmark self-check failed: restored store does not re-export the identical envelope",
    );

  // Outside timing: corrupt envelopes are rejected, store unchanged.
  const statsBeforeCorrupt = target.stats();
  const badVersion = JSON.parse(JSON.stringify(snapshot)) as Record<string, unknown>;
  badVersion["v"] = 2;
  let versionError: string | undefined;
  try {
    target.restoreSnapshot(badVersion);
  } catch (err) {
    versionError = err instanceof Error ? err.message : String(err);
  }
  if (
    versionError !==
    "JwksKeyStore: invalid snapshot: unsupported snapshot version 2 (expected 1)"
  )
    throw new Error(
      `benchmark self-check failed: wrong-version restore error ${JSON.stringify(versionError)}`,
    );
  const badKid = JSON.parse(JSON.stringify(snapshot)) as {
    keys: Array<Record<string, unknown>>;
  };
  badKid.keys[0]!["kid"] = "";
  let kidError: string | undefined;
  try {
    target.restoreSnapshot(badKid);
  } catch (err) {
    kidError = err instanceof Error ? err.message : String(err);
  }
  if (
    kidError !==
    "JwksKeyStore: invalid snapshot: keys[0]: kid must be a non-empty string " +
      "(snapshot restore is fail-closed: unlike refresh(), kid-less entries are not skipped)"
  )
    throw new Error(
      `benchmark self-check failed: empty-kid restore error ${JSON.stringify(kidError)}`,
    );
  if (
    JSON.stringify(target.stats()) !== JSON.stringify(statsBeforeCorrupt) ||
    target.size !== JWKS_RESTORE_KIDS.length ||
    target.lastRefreshedAt !== JWKS_RESTORE_FETCHED_AT_SEC ||
    JSON.stringify(target.exportSnapshot()) !== JSON.stringify(snapshot)
  )
    throw new Error(
      "benchmark self-check failed: a rejected restoreSnapshot changed the store",
    );
  if (sourceFetches !== 1 || targetFetches !== 1)
    throw new Error(
      "benchmark self-check failed: restore path performed a fetch (restores are offline)",
    );

  return measure(() => {
    const before = target.stats();
    target.restoreSnapshot(snapshot);
    const after = target.stats();
    if (
      after.refreshes !== before.refreshes ||
      after.refreshFailures !== before.refreshFailures ||
      after.hits !== before.hits ||
      after.misses !== before.misses
    )
      throw new Error(
        `benchmark self-check failed: restoreSnapshot changed stats ${JSON.stringify(before)} -> ${JSON.stringify(after)}`,
      );
    if (target.size !== JWKS_RESTORE_KIDS.length)
      throw new Error(
        `benchmark self-check failed: restored size ${target.size} (expected ${JWKS_RESTORE_KIDS.length})`,
      );
    if (target.lastRefreshedAt !== JWKS_RESTORE_FETCHED_AT_SEC)
      throw new Error(
        `benchmark self-check failed: restored lastRefreshedAt ${target.lastRefreshedAt} ` +
          `(expected ${JWKS_RESTORE_FETCHED_AT_SEC})`,
      );
    if (!target.isStale())
      throw new Error(
        "benchmark self-check failed: restored store is not stale at the TTL boundary of the original fetch time",
      );
    if (target.resolve(JWKS_RESTORE_KIDS[0]) === undefined)
      throw new Error(
        "benchmark self-check failed: restored store does not resolve the pinned kid",
      );
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` keyResolver benchmark:
 * two ed25519 key pairs (generated once, outside timing) held
 * in a plain Map keystore under these kids, and one signed
 * fixture request per kid over the shared bench fixture, both
 * signed outside timing with `created` pinned at this instant
 * — the verifier's injected `now`, so no wall clock is read.
 */
const KEY_RESOLVER_CREATED = 1_700_000_000;
const KEY_RESOLVER_KIDS = [
  "bench-resolver-key-1",
  "bench-resolver-key-2",
] as const;
const KEY_RESOLVER_UNKNOWN_KID = "bench-resolver-unknown";

/**
 * `verifyRequest` through a `keyResolver` steady state: the
 * keyid→key resolution form a gateway uses while its keys
 * rotate — every measured call first resolves the signature's
 * claimed `keyid` through the pinned Map resolver and only
 * then runs the cryptographic check, the cost the static-`key`
 * verify rows above never pay as a separate step. One measured
 * op verifies both pinned fixtures (one per keyid) and
 * re-pins both results: each must be ok and each returned
 * `keyId` must equal the kid that fixture was signed under.
 * Outside timing, the fail-closed half is pinned once: a
 * fixture signed under an unknown kid returns exactly
 * `{ ok: false, code: "KEY_RESOLUTION_FAILED" }` carrying
 * that kid and the pinned reason, and passing a static `key`
 * together with the resolver throws the pinned
 * mutual-exclusion configuration error. Zero network, zero
 * randomness in the measured assertions, no wall clock (the
 * verifier clock is the pinned `created` instant).
 */
function benchmarkVerifyKeyResolver(): number {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    [KEY_RESOLVER_KIDS[0], k1.publicKey],
    [KEY_RESOLVER_KIDS[1], k2.publicKey],
  ]);
  const keyResolver = (id: string) => store.get(id);
  const signed1 = signRequest(fixture, {
    keyId: KEY_RESOLVER_KIDS[0],
    alg: "ed25519",
    key: k1.privateKey,
    created: KEY_RESOLVER_CREATED,
  });
  const signed2 = signRequest(fixture, {
    keyId: KEY_RESOLVER_KIDS[1],
    alg: "ed25519",
    key: k2.privateKey,
    created: KEY_RESOLVER_CREATED,
  });
  const verifyOpts = { keyResolver, now: KEY_RESOLVER_CREATED };
  const assertResolved = (
    signed: SignedHttpRequest,
    kid: string,
    where: string,
  ): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest via keyResolver (${where}) gave ${JSON.stringify(r)}`,
      );
    if (r.keyId !== kid)
      throw new Error(
        `benchmark self-check failed: verifyRequest via keyResolver (${where}) returned keyId ${JSON.stringify(r.keyId)} (expected ${JSON.stringify(kid)})`,
      );
  };

  // Outside timing: both keyids verify through the resolver.
  assertResolved(signed1, KEY_RESOLVER_KIDS[0], "outside timing");
  assertResolved(signed2, KEY_RESOLVER_KIDS[1], "outside timing");

  // Outside timing: an unknown keyid fails closed.
  const unknownSigned = signRequest(fixture, {
    keyId: KEY_RESOLVER_UNKNOWN_KID,
    alg: "ed25519",
    key: k1.privateKey,
    created: KEY_RESOLVER_CREATED,
  });
  const unknown = verifyRequest(unknownSigned, verifyOpts);
  if (
    unknown.ok ||
    unknown.code !== "KEY_RESOLUTION_FAILED" ||
    unknown.keyId !== KEY_RESOLVER_UNKNOWN_KID ||
    unknown.reason !==
      `keyid "${KEY_RESOLVER_UNKNOWN_KID}" could not be resolved to a key`
  )
    throw new Error(
      `benchmark self-check failed: unknown keyid result ${JSON.stringify(unknown)} ` +
        `(expected KEY_RESOLUTION_FAILED for ${KEY_RESOLVER_UNKNOWN_KID})`,
    );

  // Outside timing: key + keyResolver together is a caller
  // configuration error, not a verification failure.
  let conflict: string | undefined;
  try {
    verifyRequest(signed1, {
      key: k1.publicKey,
      keyResolver,
      now: KEY_RESOLVER_CREATED,
    });
  } catch (err) {
    conflict = err instanceof Error ? err.message : String(err);
  }
  if (
    conflict !==
    "verifyRequest: `key`, `keyResolver`, and `candidateKeys` are mutually exclusive — pass exactly one"
  )
    throw new Error(
      `benchmark self-check failed: key+keyResolver conflict ${JSON.stringify(conflict)}`,
    );

  return measure(() => {
    assertResolved(signed1, KEY_RESOLVER_KIDS[0], "measured pass");
    assertResolved(signed2, KEY_RESOLVER_KIDS[1], "measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` maxSignatureAgeSec
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a dated fixture signed outside timing with
 * `created` pinned at this instant and no `expires`, a
 * 300-second age cap, and the verifier's injected `now`
 * 60 seconds after `created` — inside the cap, so the
 * measured steady state is the accepting path.
 */
const MAX_AGE_CREATED = 1_700_000_000;
const MAX_AGE_SEC = 300;
const MAX_AGE_KID = "bench-max-age-key-1";
const MAX_AGE_WITHIN_AT_SEC = MAX_AGE_CREATED + 60;
const MAX_AGE_TOO_OLD_AT_SEC = MAX_AGE_CREATED + MAX_AGE_SEC + 1;
const MAX_AGE_NO_CREATED_EXPIRES = MAX_AGE_CREATED + 3600;
const MAX_AGE_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];

/**
 * `verifyRequest` with `maxSignatureAgeSec` steady state:
 * the age-cap form a receiver uses to bound how long a
 * signed message stays replayable when it carries
 * `created` but no `expires` — every measured call runs
 * the age computation (`now - created`) and the strict
 * `>` boundary check the plain verify rows above never
 * pay, because they pass no cap. One measured op verifies
 * the one pinned dated fixture at the within-cap instant
 * and re-pins that the result is ok. Outside timing, the
 * rejecting and bypass halves are pinned once: the same
 * fixture at one second past the cap returns exactly
 * `{ ok: false, code: "SIGNATURE_TOO_OLD" }` with the
 * pinned reason, and a hand-built signature carrying no
 * `created` at all (only `expires`, `keyid`, `alg` —
 * built with `buildSignatureBase` + `signatureInputValue`
 * + a raw ed25519 sign, the shape
 * `test/signatureMaxAge.test.ts` uses) still verifies at
 * that past-cap instant, because a signature with no
 * `created` bypasses the age check entirely. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyMaxSignatureAge(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: MAX_AGE_KID,
    alg: "ed25519",
    key: privateKey,
    created: MAX_AGE_CREATED,
  });
  const verifyOpts = {
    key: publicKey,
    now: MAX_AGE_WITHIN_AT_SEC,
    maxSignatureAgeSec: MAX_AGE_SEC,
  };
  const assertWithinCap = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with maxSignatureAgeSec (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the dated fixture verifies inside the cap.
  assertWithinCap("outside timing");

  // Outside timing: one second past the cap the same
  // fixture is rejected as too old, with the pinned reason.
  const tooOld = verifyRequest(signed, {
    key: publicKey,
    now: MAX_AGE_TOO_OLD_AT_SEC,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  if (
    tooOld.ok ||
    tooOld.code !== "SIGNATURE_TOO_OLD" ||
    tooOld.reason !==
      `signature is too old: created ${MAX_AGE_TOO_OLD_AT_SEC - MAX_AGE_CREATED}s ago, older than maxSignatureAgeSec=${MAX_AGE_SEC}`
  )
    throw new Error(
      `benchmark self-check failed: past-cap result ${JSON.stringify(tooOld)} ` +
        `(expected SIGNATURE_TOO_OLD at age ${MAX_AGE_TOO_OLD_AT_SEC - MAX_AGE_CREATED}s)`,
    );

  // Outside timing: a signature with no `created` bypasses
  // the age check entirely, even at the past-cap instant.
  const noCreatedParams: SignatureParams = {
    keyid: MAX_AGE_KID,
    alg: "ed25519",
    expires: MAX_AGE_NO_CREATED_EXPIRES,
  };
  const noCreatedRequest: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const noCreatedBase = buildSignatureBase(
    MAX_AGE_COVERED_COMPONENTS,
    noCreatedRequest,
    noCreatedParams,
  );
  const noCreatedSig = edSign(
    null,
    Buffer.from(noCreatedBase, "utf8"),
    privateKey,
  );
  const noCreatedSigned: SignedHttpRequest = {
    method: noCreatedRequest.method,
    url: noCreatedRequest.url,
    headers: {
      "signature-input": signatureInputValue(
        "sig1",
        MAX_AGE_COVERED_COMPONENTS,
        noCreatedParams,
      ),
      signature: `sig1=:${noCreatedSig.toString("base64")}:`,
    },
  };
  const noCreated = verifyRequest(noCreatedSigned, {
    key: publicKey,
    now: MAX_AGE_TOO_OLD_AT_SEC,
    maxSignatureAgeSec: MAX_AGE_SEC,
  });
  if (!noCreated.ok)
    throw new Error(
      `benchmark self-check failed: no-created bypass gave ${JSON.stringify(noCreated)}`,
    );

  return measure(() => {
    assertWithinCap("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` requireExpires
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing with `created`
 * and `expires` both pinned (a 600-second lifetime), and
 * the verifier's injected `now` at the `created` instant —
 * inside the lifetime, so the measured steady state is the
 * accepting path.
 */
const REQUIRE_EXPIRES_CREATED = 1_700_000_000;
const REQUIRE_EXPIRES_EXPIRES = REQUIRE_EXPIRES_CREATED + 600;
const REQUIRE_EXPIRES_KID = "bench-require-expires-key-1";
const REQUIRE_EXPIRES_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];

/**
 * `verifyRequest` with `requireExpires` steady state: the
 * expiry-presence form a receiver uses to refuse a
 * signature with no bounded lifetime — every measured call
 * runs the post-cryptographic `expires === undefined`
 * presence check the plain verify rows above never pay,
 * because they pass no such requirement. One measured op
 * verifies the one pinned dated fixture with
 * `requireExpires: true` and re-pins that the result is
 * ok. Outside timing, the rejecting and default halves are
 * pinned once: a hand-built signature carrying `created`
 * but no `expires` (built with `buildSignatureBase` +
 * `signatureInputValue` + a raw ed25519 sign, the shape
 * `test/requireFreshness.test.ts` uses, because
 * `signRequest` always emits `created` and a third-party
 * signer may omit `expires`) returns exactly
 * `{ ok: false, code: "MISSING_EXPIRES" }` with the pinned
 * reason under `requireExpires: true`, and the same
 * signature still verifies with the option unset, because
 * the requirement is opt-in. Zero network, zero randomness
 * in the measured assertions, no wall clock (every verify
 * instant is injected).
 */
function benchmarkVerifyRequireExpires(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: REQUIRE_EXPIRES_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_EXPIRES_CREATED,
    expires: REQUIRE_EXPIRES_EXPIRES,
  });
  const verifyOpts = {
    key: publicKey,
    now: REQUIRE_EXPIRES_CREATED,
    requireExpires: true,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with requireExpires (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the dated fixture verifies under the
  // requirement.
  assertAccepted("outside timing");

  // Outside timing: a hand-built signature with no
  // `expires` is rejected with the pinned code and reason.
  const noExpiresParams: SignatureParams = {
    keyid: REQUIRE_EXPIRES_KID,
    alg: "ed25519",
    created: REQUIRE_EXPIRES_CREATED,
  };
  const noExpiresRequest: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const noExpiresBase = buildSignatureBase(
    REQUIRE_EXPIRES_COVERED_COMPONENTS,
    noExpiresRequest,
    noExpiresParams,
  );
  const noExpiresSig = edSign(
    null,
    Buffer.from(noExpiresBase, "utf8"),
    privateKey,
  );
  const noExpiresSigned: SignedHttpRequest = {
    method: noExpiresRequest.method,
    url: noExpiresRequest.url,
    headers: {
      "signature-input": signatureInputValue(
        "sig1",
        REQUIRE_EXPIRES_COVERED_COMPONENTS,
        noExpiresParams,
      ),
      signature: `sig1=:${noExpiresSig.toString("base64")}:`,
    },
  };
  const missing = verifyRequest(noExpiresSigned, {
    key: publicKey,
    now: REQUIRE_EXPIRES_CREATED,
    requireExpires: true,
  });
  if (
    missing.ok ||
    missing.code !== "MISSING_EXPIRES" ||
    missing.reason !==
      "signature carries no `expires` timestamp but requireExpires is set"
  )
    throw new Error(
      `benchmark self-check failed: no-expires result ${JSON.stringify(missing)} ` +
        `(expected MISSING_EXPIRES)`,
    );

  // Outside timing: without the option the same
  // no-`expires` signature verifies — the requirement is
  // opt-in and the default behaviour is unchanged.
  const defaulted = verifyRequest(noExpiresSigned, {
    key: publicKey,
    now: REQUIRE_EXPIRES_CREATED,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: no-expires default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` requireCreated
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a hand-built signature with no `created`
 * parameter (built with `buildSignatureBase` +
 * `signatureInputValue` + a raw ed25519 sign — the shape
 * `test/requireFreshness.test.ts` uses, because
 * `signRequest` always emits `created` and a third-party
 * signer may omit it), and the verifier's injected `now`
 * — so the measured steady state is the rejecting path:
 * the post-cryptographic `created === undefined` presence
 * check the plain verify rows above never pay, because
 * they pass no such requirement.
 */
const REQUIRE_CREATED_NOW = 1_700_000_000;
const REQUIRE_CREATED_KID = "bench-require-created-key-1";
const REQUIRE_CREATED_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];
const REQUIRE_CREATED_CODE = "MISSING_CREATED";
const REQUIRE_CREATED_REASON =
  "signature carries no `created` timestamp but requireCreated is set";

/**
 * `verifyRequest` with `requireCreated` steady state: the
 * created-presence form a receiver uses to refuse
 * signatures with no bounded age — every measured call
 * runs the post-cryptographic `created === undefined`
 * presence check the plain verify rows above never pay,
 * because they set no requirement. One measured op
 * verifies the one pinned hand-built no-`created`
 * fixture with `requireCreated: true` and re-pins that
 * the result is exactly `{ ok: false, code:
 * "MISSING_CREATED" }` with the pinned reason.
 * Outside timing, the accepting and ordering halves are
 * pinned once: the same no-`created` signature still
 * verifies with the option unset (the requirement is
 * opt-in), a dated `signRequest` fixture verifies under
 * `requireCreated: true`, and a forged (tampered
 * signature bytes) no-`created` signature returns
 * `SIGNATURE_MISMATCH` — the cryptographic check runs
 * before the presence check, so a forgery is never
 * mistaken for a policy violation. Zero network, zero
 * randomness in the measured assertions, no wall clock
 * (every verify instant is injected).
 */
function benchmarkVerifyRequireCreated(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const noCreatedParams: SignatureParams = {
    keyid: REQUIRE_CREATED_KID,
    alg: "ed25519",
  };
  const noCreatedRequest: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const noCreatedBase = buildSignatureBase(
    REQUIRE_CREATED_COVERED_COMPONENTS,
    noCreatedRequest,
    noCreatedParams,
  );
  const noCreatedSig = edSign(
    null,
    Buffer.from(noCreatedBase, "utf8"),
    privateKey,
  );
  const noCreatedSigned: SignedHttpRequest = {
    method: noCreatedRequest.method,
    url: noCreatedRequest.url,
    headers: {
      "signature-input": signatureInputValue(
        "sig1",
        REQUIRE_CREATED_COVERED_COMPONENTS,
        noCreatedParams,
      ),
      signature: `sig1=:${noCreatedSig.toString("base64")}:`,
    },
  };
  const verifyOpts = {
    key: publicKey,
    now: REQUIRE_CREATED_NOW,
    requireCreated: true,
  };
  const assertRejected = (where: string): void => {
    const r = verifyRequest(noCreatedSigned, verifyOpts);
    if (
      r.ok ||
      r.code !== REQUIRE_CREATED_CODE ||
      r.reason !== REQUIRE_CREATED_REASON
    )
      throw new Error(
        `benchmark self-check failed: verifyRequest with requireCreated (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the hand-built no-`created` fixture
  // is rejected with the pinned code and reason.
  assertRejected("outside timing");

  // Outside timing: without the option the same
  // no-`created` signature verifies — the requirement is
  // opt-in and the default behaviour is unchanged.
  const defaulted = verifyRequest(noCreatedSigned, {
    key: publicKey,
    now: REQUIRE_CREATED_NOW,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: no-created default gave ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: a dated signature still verifies
  // under the requirement.
  const dated = signRequest(noCreatedRequest, {
    keyId: REQUIRE_CREATED_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_CREATED_NOW,
  });
  const datedResult = verifyRequest(dated, verifyOpts);
  if (!datedResult.ok)
    throw new Error(
      `benchmark self-check failed: dated fixture under requireCreated gave ${JSON.stringify(datedResult)}`,
    );

  // Outside timing: a forged no-`created` signature
  // (signature bytes tampered) is reported as
  // SIGNATURE_MISMATCH — the cryptographic check runs
  // before the presence check.
  const tamperedBytes = Buffer.from(noCreatedSig);
  tamperedBytes[tamperedBytes.length - 1] ^= 0xff;
  const forged: SignedHttpRequest = {
    method: noCreatedRequest.method,
    url: noCreatedRequest.url,
    headers: {
      ...noCreatedSigned.headers,
      signature: `sig1=:${tamperedBytes.toString("base64")}:`,
    },
  };
  const forgedResult = verifyRequest(forged, verifyOpts);
  if (forgedResult.ok || forgedResult.code !== "SIGNATURE_MISMATCH")
    throw new Error(
      `benchmark self-check failed: forged no-created result ${JSON.stringify(forgedResult)} ` +
        `(expected SIGNATURE_MISMATCH)`,
    );

  return measure(() => {
    assertRejected("measured pass");
  }, ITERATIONS);
}
const EXPECTED_TAG_VALUE = "payment-webhook-v1";
const EXPECTED_TAG_OTHER = "refund-webhook-v1";
const EXPECTED_TAG_CREATED = 1_700_000_000;
const EXPECTED_TAG_KID = "bench-expected-tag-key-1";

/**
 * `verifyRequest` with `expectedTag` steady state: the
 * application-tag-pinning form a receiver uses for
 * cross-protocol replay protection (RFC 9421 §2.3) — every
 * measured call runs the post-cryptographic
 * `tag === expectedTag` comparison the plain verify rows
 * above never pay, because they set no expectation. One
 * measured op verifies the one pinned tagged fixture with
 * the matching `expectedTag` and re-pins that the result
 * is ok and the returned `tag` equals the pinned value.
 * Outside timing, the rejecting and default halves are
 * pinned once: the same signature under a different
 * `expectedTag` returns exactly
 * `{ ok: false, code: "TAG_MISMATCH" }` with the pinned
 * `tag mismatch: expected "<expected>", got "<actual>"`
 * reason, a fixture signed with no `tag` at all under the
 * same expectation returns `TAG_MISMATCH` with the pinned
 * `got no tag` reason shape, and the same tagged signature
 * still verifies with the option unset, because the
 * requirement is opt-in. Zero network, zero randomness in
 * the measured assertions, no wall clock (every verify
 * instant is injected).
 */
function benchmarkVerifyExpectedTag(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: EXPECTED_TAG_KID,
    alg: "ed25519",
    key: privateKey,
    created: EXPECTED_TAG_CREATED,
    tag: EXPECTED_TAG_VALUE,
  });
  const verifyOpts = {
    key: publicKey,
    now: EXPECTED_TAG_CREATED,
    expectedTag: EXPECTED_TAG_VALUE,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok || r.tag !== EXPECTED_TAG_VALUE)
      throw new Error(
        `benchmark self-check failed: verifyRequest with expectedTag (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the tagged fixture verifies under the
  // matching expectation.
  assertAccepted("outside timing");

  // Outside timing: a different expectedTag is rejected
  // with the pinned code and reason.
  const mismatch = verifyRequest(signed, {
    key: publicKey,
    now: EXPECTED_TAG_CREATED,
    expectedTag: EXPECTED_TAG_OTHER,
  });
  if (
    mismatch.ok ||
    mismatch.code !== "TAG_MISMATCH" ||
    mismatch.reason !==
      `tag mismatch: expected "${EXPECTED_TAG_OTHER}", got "${EXPECTED_TAG_VALUE}"`
  )
    throw new Error(
      `benchmark self-check failed: tag-mismatch result ${JSON.stringify(mismatch)} ` +
        `(expected TAG_MISMATCH)`,
    );

  // Outside timing: a signature with no tag at all is
  // rejected with the pinned `no tag` reason shape.
  const untagged = signRequest(fixture, {
    keyId: EXPECTED_TAG_KID,
    alg: "ed25519",
    key: privateKey,
    created: EXPECTED_TAG_CREATED,
  });
  const noTag = verifyRequest(untagged, {
    key: publicKey,
    now: EXPECTED_TAG_CREATED,
    expectedTag: EXPECTED_TAG_VALUE,
  });
  if (
    noTag.ok ||
    noTag.code !== "TAG_MISMATCH" ||
    noTag.reason !==
      `tag mismatch: expected "${EXPECTED_TAG_VALUE}", got no tag`
  )
    throw new Error(
      `benchmark self-check failed: no-tag result ${JSON.stringify(noTag)} ` +
        `(expected TAG_MISMATCH)`,
    );

  // Outside timing: without the option the same tagged
  // signature verifies — the requirement is opt-in and the
  // default behaviour is unchanged.
  const defaulted = verifyRequest(signed, {
    key: publicKey,
    now: EXPECTED_TAG_CREATED,
  });
  if (!defaulted.ok || defaulted.tag !== EXPECTED_TAG_VALUE)
    throw new Error(
      `benchmark self-check failed: tagged default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` replayCache
 * benchmark: one ed25519 key pair (generated once,
 * outside timing), a fixture signed outside timing
 * with `created` pinned and `nonce` pinned, and the
 * cache sharing the verifier's injected clock — the
 * measured steady state is the replay-rejecting path.
 */
const REPLAY_CACHE_NOW = 1_700_000_000;
const REPLAY_CACHE_KID = "bench-replay-cache-key-1";
const REPLAY_CACHE_NONCE = "bench-replay-nonce-1";
const REPLAY_CACHE_CODE = "NONCE_REPLAY";
const REPLAY_CACHE_REASON = `nonce replay detected: "${REPLAY_CACHE_NONCE}" was already seen`;

/**
 * `verifyRequest` with `replayCache` steady state: the
 * replay-defense form a receiver runs to refuse a
 * request whose signature is valid but was already
 * seen — every measured op consults the cache the
 * plain verify rows above never pay, because they
 * pass no cache. One measured op verifies the one
 * pinned nonced fixture twice against a fresh
 * `ReplayCache` sharing the verifier's injected
 * clock: the first verify records the nonce and is
 * ok, the second is rejected with exactly the pinned
 * `NONCE_REPLAY` code and reason. Outside timing,
 * the bypassing and non-polluting halves are pinned
 * once: without a cache the same fixture verifies
 * twice (both ok), a nonce-less signature verifies
 * twice under a cache (nonce-less signatures bypass
 * the cache entirely), and a forged signature
 * (signature bytes tampered) with a cache returns
 * `SIGNATURE_MISMATCH` — the cryptographic check
 * runs before the cache consultation, so a forgery
 * never pollutes the cache, and the unmodified
 * fixture still verifies (and is then
 * replay-rejected) afterwards. Zero network, zero
 * randomness in the measured assertions, no wall
 * clock (every verify instant is injected; the
 * cache's own clock is that same pinned instant).
 */
function benchmarkVerifyReplayCache(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: REPLAY_CACHE_KID,
    alg: "ed25519",
    key: privateKey,
    created: REPLAY_CACHE_NOW,
    nonce: REPLAY_CACHE_NONCE,
  });

  const verifyWithCache = (cache: ReplayCache) =>
    verifyRequest(signed, {
      key: publicKey,
      now: REPLAY_CACHE_NOW,
      replayCache: cache,
    });

  const assertReplayed = (cache: ReplayCache, where: string): void => {
    const r = verifyWithCache(cache);
    if (r.ok || r.code !== REPLAY_CACHE_CODE || r.reason !== REPLAY_CACHE_REASON)
      throw new Error(
        `benchmark self-check failed: verifyRequest with replayCache (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: without a cache the same fixture
  // verifies twice — replay defense is opt-in and the
  // default behaviour is unchanged.
  const uncachedFirst = verifyRequest(signed, {
    key: publicKey,
    now: REPLAY_CACHE_NOW,
  });
  const uncachedSecond = verifyRequest(signed, {
    key: publicKey,
    now: REPLAY_CACHE_NOW,
  });
  if (!uncachedFirst.ok || !uncachedSecond.ok)
    throw new Error(
      `benchmark self-check failed: uncached fixture gave ${JSON.stringify(uncachedFirst)} / ${JSON.stringify(uncachedSecond)}`,
    );

  // Outside timing: a nonce-less signature verifies
  // twice under a cache — nonce-less signatures
  // bypass the replay cache entirely.
  const nonceLess = signRequest(fixture, {
    keyId: REPLAY_CACHE_KID,
    alg: "ed25519",
    key: privateKey,
    created: REPLAY_CACHE_NOW,
  });
  const nonceLessCache = new ReplayCache({ now: () => REPLAY_CACHE_NOW });
  const verifyNonceLess = () =>
    verifyRequest(nonceLess, {
      key: publicKey,
      now: REPLAY_CACHE_NOW,
      replayCache: nonceLessCache,
    });
  if (!verifyNonceLess().ok || !verifyNonceLess().ok)
    throw new Error(
      `benchmark self-check failed: nonce-less fixture under cache did not verify twice`,
    );

  // Outside timing: a forged signature (signature
  // bytes tampered) with a cache returns
  // SIGNATURE_MISMATCH — the cryptographic check runs
  // before the cache consultation, so a forgery never
  // pollutes the cache; the unmodified fixture still
  // verifies and is then replay-rejected afterwards.
  const poisonedCache = new ReplayCache({ now: () => REPLAY_CACHE_NOW });
  const sigField = signed.headers["signature"];
  const sigMatch = /^sig1=:(.+):$/.exec(sigField);
  if (!sigMatch)
    throw new Error(
      `benchmark self-check failed: unexpected signature header shape ${JSON.stringify(sigField)}`,
    );
  const raw = Buffer.from(sigMatch[1], "base64");
  raw[raw.length - 1] ^= 0xff;
  const forged: SignedHttpRequest = {
    method: signed.method,
    url: signed.url,
    headers: {
      ...signed.headers,
      signature: `sig1=:${raw.toString("base64")}:`,
    },
  };
  const forgedResult = verifyRequest(forged, {
    key: publicKey,
    now: REPLAY_CACHE_NOW,
    replayCache: poisonedCache,
  });
  if (forgedResult.ok || forgedResult.code !== "SIGNATURE_MISMATCH")
    throw new Error(
      `benchmark self-check failed: forged result ${JSON.stringify(forgedResult)} ` +
        `(expected SIGNATURE_MISMATCH)`,
    );
  if (!verifyWithCache(poisonedCache).ok)
    throw new Error(
      `benchmark self-check failed: fixture after forgery was rejected (cache was polluted)`,
    );
  assertReplayed(poisonedCache, "replay after unpolluted first verify");

  return measure(() => {
    const cache = new ReplayCache({ now: () => REPLAY_CACHE_NOW });
    const first = verifyWithCache(cache);
    if (!first.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with replayCache (measured first pass) gave ${JSON.stringify(first)}`,
      );
    assertReplayed(cache, "measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` requireNonce
 * benchmark: one ed25519 key pair (generated once,
 * outside timing), a fixture signed outside timing
 * with `created` pinned and `nonce` pinned, and the
 * verifier's injected `now` at the `created` instant —
 * so the measured steady state is the accepting path
 * with the nonce-presence check included.
 */
const REQUIRE_NONCE_NOW = 1_700_000_000;
const REQUIRE_NONCE_KID = "bench-require-nonce-key-1";
const REQUIRE_NONCE_VALUE = "bench-require-nonce-1";
const REQUIRE_NONCE_CODE = "MISSING_NONCE";
const REQUIRE_NONCE_REASON =
  "signature carries no `nonce` but requireNonce is set";

/**
 * `verifyRequest` with `requireNonce` steady state: the
 * nonce-presence form a receiver runs to refuse signatures
 * that carry no (non-empty) nonce before they ever reach
 * the replay store — every measured call runs the
 * post-cryptographic `nonce === undefined || nonce === ""`
 * presence check the plain verify rows above never pay,
 * because they set no requirement. One measured op
 * verifies the one pinned nonced fixture with
 * `requireNonce: true` and re-pins that the result is ok
 * and the returned `nonce` equals the pinned value.
 * Outside timing, the rejecting half is pinned once: a
 * nonce-less signature under the option returns exactly
 * `{ ok: false, code: "MISSING_NONCE" }` with the pinned
 * reason — so the measured path cannot be an empty one —
 * and the same nonce-less signature still verifies with
 * the option unset, because the requirement is opt-in.
 * (A forged nonce-less signature reports
 * `SIGNATURE_MISMATCH`, not `MISSING_NONCE` — the
 * cryptographic check runs first — pinned in
 * `test/requireNonce.test.ts`, not repeated here.) Zero
 * network, zero randomness in the measured assertions, no
 * wall clock (every verify instant is injected).
 */
function benchmarkVerifyRequireNonce(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: REQUIRE_NONCE_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_NONCE_NOW,
    nonce: REQUIRE_NONCE_VALUE,
  });
  const verifyOpts = {
    key: publicKey,
    now: REQUIRE_NONCE_NOW,
    requireNonce: true,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok || r.nonce !== REQUIRE_NONCE_VALUE)
      throw new Error(
        `benchmark self-check failed: verifyRequest with requireNonce (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the nonced fixture verifies under the
  // requirement and the returned nonce is the pinned value.
  assertAccepted("outside timing");

  // Outside timing: a nonce-less signature under the option
  // is rejected with the pinned code and reason.
  const nonceLess = signRequest(fixture, {
    keyId: REQUIRE_NONCE_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_NONCE_NOW,
  });
  const missing = verifyRequest(nonceLess, {
    key: publicKey,
    now: REQUIRE_NONCE_NOW,
    requireNonce: true,
  });
  if (
    missing.ok ||
    missing.code !== REQUIRE_NONCE_CODE ||
    missing.reason !== REQUIRE_NONCE_REASON
  )
    throw new Error(
      `benchmark self-check failed: nonce-less result ${JSON.stringify(missing)} ` +
        `(expected MISSING_NONCE)`,
    );

  // Outside timing: without the option the same
  // nonce-less signature verifies — the requirement is
  // opt-in and the default behaviour is unchanged.
  const defaulted = verifyRequest(nonceLess, {
    key: publicKey,
    now: REQUIRE_NONCE_NOW,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: nonce-less default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` requireTag
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing carrying the
 * pinned `tag`, and the measured presence check — every
 * measured call verifies the tagged fixture with
 * `requireTag: true` and re-pins that the result is ok
 * and the returned tag is the pinned value. Outside
 * timing, the rejecting and default halves are pinned
 * once: the same request signed without a tag under the
 * option returns exactly `{ ok: false, code: "MISSING_TAG" }`
 * with the pinned reason, a differently-tagged fixture
 * still verifies (requireTag checks presence, never
 * value), and with no option passed the tag-less fixture
 * verifies because the requirement is opt-in. Zero
 * network, zero randomness in the measured assertions, no
 * wall clock (every verify instant is injected).
 */
const REQUIRE_TAG_NOW = 1_700_000_000;
const REQUIRE_TAG_KID = "bench-require-tag-key-1";
const REQUIRE_TAG_VALUE = "bench-require-tag-1";
const REQUIRE_TAG_OTHER_VALUE = "bench-require-tag-other";
const REQUIRE_TAG_CODE = "MISSING_TAG";
const REQUIRE_TAG_REASON =
  "signature carries no `tag` but requireTag is set";

function benchmarkVerifyRequireTag(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: REQUIRE_TAG_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_TAG_NOW,
    tag: REQUIRE_TAG_VALUE,
  });
  const verifyOpts = {
    key: publicKey,
    now: REQUIRE_TAG_NOW,
    requireTag: true,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok || r.tag !== REQUIRE_TAG_VALUE)
      throw new Error(
        `benchmark self-check failed: verifyRequest with requireTag (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the tagged fixture verifies under the
  // requirement and the returned tag is the pinned value.
  assertAccepted("outside timing");

  // Outside timing: a tag-less signature under the option
  // is rejected with the pinned code and reason.
  const tagLess = signRequest(fixture, {
    keyId: REQUIRE_TAG_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_TAG_NOW,
  });
  const missing = verifyRequest(tagLess, {
    key: publicKey,
    now: REQUIRE_TAG_NOW,
    requireTag: true,
  });
  if (
    missing.ok ||
    missing.code !== REQUIRE_TAG_CODE ||
    missing.reason !== REQUIRE_TAG_REASON
  )
    throw new Error(
      `benchmark self-check failed: tag-less result ${JSON.stringify(missing)} ` +
        `(expected MISSING_TAG)`,
    );

  // Outside timing: requireTag checks presence, never
  // value — a differently-tagged fixture still verifies
  // and echoes its own tag.
  const otherTagged = signRequest(fixture, {
    keyId: REQUIRE_TAG_KID,
    alg: "ed25519",
    key: privateKey,
    created: REQUIRE_TAG_NOW,
    tag: REQUIRE_TAG_OTHER_VALUE,
  });
  const other = verifyRequest(otherTagged, {
    key: publicKey,
    now: REQUIRE_TAG_NOW,
    requireTag: true,
  });
  if (!other.ok || other.tag !== REQUIRE_TAG_OTHER_VALUE)
    throw new Error(
      `benchmark self-check failed: differently-tagged result ${JSON.stringify(other)}`,
    );

  // Outside timing: without the option the same
  // tag-less signature verifies — the requirement is
  // opt-in and the default behaviour is unchanged.
  const defaulted = verifyRequest(tagLess, {
    key: publicKey,
    now: REQUIRE_TAG_NOW,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: tag-less default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` clockSkewToleranceSec
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing with `created`
 * pinned 30 seconds ahead of the verifier's injected `now`,
 * and the measured tolerance of 120 seconds — wide enough
 * to accept that skew, so the measured steady state is the
 * accepting path.
 */
const CLOCK_SKEW_NOW = 1_700_000_000;
const CLOCK_SKEW_CREATED = CLOCK_SKEW_NOW + 30;
const CLOCK_SKEW_TOLERANCE_SEC = 120;
const CLOCK_SKEW_NARROW_SEC = 10;
const CLOCK_SKEW_KID = "bench-clock-skew-key-1";

/**
 * `verifyRequest` with `clockSkewToleranceSec` steady
 * state: the future-`created` tolerance form a receiver
 * uses to accept signatures from a signer whose clock runs
 * ahead — every measured call runs the
 * `created > now + skew` future check with a caller-pinned
 * tolerance the plain verify rows above never pay, because
 * they rely on the 60-second default against fixtures that
 * are not dated in the future. One measured op verifies
 * the one pinned future-dated fixture with
 * `clockSkewToleranceSec: 120` and re-pins that the result
 * is ok. Outside timing, the rejecting, boundary and
 * default halves are pinned once: the same fixture under
 * a 10-second tolerance returns exactly
 * `{ ok: false, code: "CREATED_IN_FUTURE" }` with the
 * pinned reason, at exactly the boundary
 * (`clockSkewToleranceSec` equal to the 30-second skew,
 * so `created === now + skew`) the same fixture still
 * verifies because the comparison is strict `>`, and with
 * no option passed the same fixture verifies because the
 * 60-second default covers the 30-second skew. Zero
 * network, zero randomness in the measured assertions, no
 * wall clock (every verify instant is injected).
 */
function benchmarkVerifyClockSkewTolerance(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: CLOCK_SKEW_KID,
    alg: "ed25519",
    key: privateKey,
    created: CLOCK_SKEW_CREATED,
  });
  const verifyOpts = {
    key: publicKey,
    now: CLOCK_SKEW_NOW,
    clockSkewToleranceSec: CLOCK_SKEW_TOLERANCE_SEC,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with clockSkewToleranceSec (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the future-dated fixture verifies
  // under the wide tolerance.
  assertAccepted("outside timing");

  // Outside timing: under a narrow 10-second tolerance the
  // same fixture is rejected as created in the future,
  // with the pinned code and reason.
  const future = verifyRequest(signed, {
    key: publicKey,
    now: CLOCK_SKEW_NOW,
    clockSkewToleranceSec: CLOCK_SKEW_NARROW_SEC,
  });
  if (
    future.ok ||
    future.code !== "CREATED_IN_FUTURE" ||
    future.reason !== "signature created in the future (clock skew)"
  )
    throw new Error(
      `benchmark self-check failed: narrow-tolerance result ${JSON.stringify(future)} ` +
        `(expected CREATED_IN_FUTURE)`,
    );

  // Outside timing: exactly at the boundary
  // (`created === now + skew`) the same fixture still
  // verifies — the future check is a strict `>`.
  const boundary = verifyRequest(signed, {
    key: publicKey,
    now: CLOCK_SKEW_NOW,
    clockSkewToleranceSec: CLOCK_SKEW_CREATED - CLOCK_SKEW_NOW,
  });
  if (!boundary.ok)
    throw new Error(
      `benchmark self-check failed: boundary result ${JSON.stringify(boundary)}`,
    );

  // Outside timing: with no option passed the same fixture
  // verifies — the 60-second default covers the 30-second
  // skew, so the default behaviour is unchanged.
  const defaulted = verifyRequest(signed, {
    key: publicKey,
    now: CLOCK_SKEW_NOW,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: default-skew result ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` expiredToleranceSec
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing with `created`
 * pinned one hour before and `expires` pinned 30 seconds
 * before the verifier's injected `now`, and the measured
 * grace of 120 seconds — wide enough to accept that
 * expiry, so the measured steady state is the accepting
 * path.
 */
const EXPIRED_TOLERANCE_NOW = 1_700_000_000;
const EXPIRED_TOLERANCE_CREATED = EXPIRED_TOLERANCE_NOW - 3_600;
const EXPIRED_TOLERANCE_EXPIRES = EXPIRED_TOLERANCE_NOW - 30;
const EXPIRED_TOLERANCE_GRACE_SEC = 120;
const EXPIRED_TOLERANCE_NARROW_SEC = 10;
const EXPIRED_TOLERANCE_KID = "bench-expired-tolerance-key-1";
const EXPIRED_TOLERANCE_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];
const BORN_EXPIRED_CREATED = EXPIRED_TOLERANCE_NOW + 100;
const BORN_EXPIRED_EXPIRES = EXPIRED_TOLERANCE_NOW;

/**
 * `verifyRequest` with `expiredToleranceSec` steady
 * state: the expiry-grace form a receiver uses to accept
 * a signature that expired moments ago (clock drift,
 * in-flight requests) — every measured call runs the
 * `now > expires + tolerance` expiry check with a
 * caller-pinned grace the plain verify rows above never
 * pay, because they rely on the default zero grace
 * against fixtures that have not expired. One measured
 * op verifies the one pinned expired fixture with
 * `expiredToleranceSec: 120` and re-pins that the result
 * is ok. Outside timing, the rejecting, boundary,
 * default and born-expired halves are pinned once: the
 * same fixture under a 10-second grace returns exactly
 * `{ ok: false, code: "EXPIRED" }` with the pinned
 * reason, at exactly the boundary
 * (`now === expires + tolerance`) the same fixture still
 * verifies because the comparison is strict `>`, with
 * no option passed the same fixture is rejected because
 * the default grace is zero, and a hand-built signature
 * whose `expires` precedes its `created` returns
 * exactly `INVALID_TIME_WINDOW` with the pinned reason
 * even inside the wide grace — the grace can extend a
 * lifetime, it cannot resurrect a signature that was
 * expired at birth. Zero network, zero randomness in
 * the measured assertions, no wall clock (every verify
 * instant is injected).
 */
function benchmarkVerifyExpiredTolerance(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: EXPIRED_TOLERANCE_KID,
    alg: "ed25519",
    key: privateKey,
    created: EXPIRED_TOLERANCE_CREATED,
    expires: EXPIRED_TOLERANCE_EXPIRES,
  });
  const verifyOpts = {
    key: publicKey,
    now: EXPIRED_TOLERANCE_NOW,
    expiredToleranceSec: EXPIRED_TOLERANCE_GRACE_SEC,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with expiredToleranceSec (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the expired fixture verifies under
  // the wide grace.
  assertAccepted("outside timing");

  // Outside timing: under a narrow 10-second grace the
  // same fixture is rejected as expired, with the pinned
  // code and reason.
  const expired = verifyRequest(signed, {
    key: publicKey,
    now: EXPIRED_TOLERANCE_NOW,
    expiredToleranceSec: EXPIRED_TOLERANCE_NARROW_SEC,
  });
  if (
    expired.ok ||
    expired.code !== "EXPIRED" ||
    expired.reason !== "signature expired"
  )
    throw new Error(
      `benchmark self-check failed: narrow-grace result ${JSON.stringify(expired)} ` +
        `(expected EXPIRED)`,
    );

  // Outside timing: exactly at the boundary
  // (`now === expires + tolerance`) the same fixture
  // still verifies — the expiry check is a strict `>`.
  const boundary = verifyRequest(signed, {
    key: publicKey,
    now: EXPIRED_TOLERANCE_EXPIRES + EXPIRED_TOLERANCE_GRACE_SEC,
    expiredToleranceSec: EXPIRED_TOLERANCE_GRACE_SEC,
  });
  if (!boundary.ok)
    throw new Error(
      `benchmark self-check failed: boundary result ${JSON.stringify(boundary)}`,
    );

  // Outside timing: with no option passed the same
  // fixture is rejected — the default grace is zero, so
  // the default behaviour is unchanged.
  const defaulted = verifyRequest(signed, {
    key: publicKey,
    now: EXPIRED_TOLERANCE_NOW,
  });
  if (defaulted.ok || defaulted.code !== "EXPIRED")
    throw new Error(
      `benchmark self-check failed: default-grace result ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: a hand-built signature whose
  // `expires` precedes its `created` is rejected with
  // INVALID_TIME_WINDOW even inside the wide grace.
  // `signRequest` refuses to mint such a signature, so
  // it is built by hand from the public signature-base
  // primitives, the shape a foreign signer would send.
  const bornReq: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const bornParams: SignatureParams = {
    keyid: EXPIRED_TOLERANCE_KID,
    alg: "ed25519",
    created: BORN_EXPIRED_CREATED,
    expires: BORN_EXPIRED_EXPIRES,
  };
  const bornBase = buildSignatureBase(
    EXPIRED_TOLERANCE_COVERED_COMPONENTS,
    bornReq,
    bornParams,
  );
  const bornSig = edSign(null, Buffer.from(bornBase, "utf8"), privateKey);
  const bornExpired: SignedHttpRequest = {
    method: bornReq.method,
    url: bornReq.url,
    headers: {
      "signature-input": signatureInputValue(
        "sig1",
        EXPIRED_TOLERANCE_COVERED_COMPONENTS,
        bornParams,
      ),
      signature: `sig1=:${bornSig.toString("base64")}:`,
    },
  };
  const born = verifyRequest(bornExpired, {
    key: publicKey,
    now: EXPIRED_TOLERANCE_NOW + 50,
    expiredToleranceSec: EXPIRED_TOLERANCE_GRACE_SEC,
  });
  if (
    born.ok ||
    born.code !== "INVALID_TIME_WINDOW" ||
    born.reason !==
      `signature expires (${BORN_EXPIRED_EXPIRES}) is earlier than its created (${BORN_EXPIRED_CREATED}): the signature was already expired at birth`
  )
    throw new Error(
      `benchmark self-check failed: born-expired result ${JSON.stringify(born)} ` +
        `(expected INVALID_TIME_WINDOW)`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` expectedKeyId
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing with `created`
 * pinned under a pinned keyid, and the verifier's injected
 * `now` at the `created` instant.
 */
const EXPECTED_KEY_ID_CREATED = 1_700_000_000;
const EXPECTED_KEY_ID_KID = "bench-expected-key-id-key-1";
const EXPECTED_KEY_ID_WRONG = "bench-expected-key-id-key-2";
const EXPECTED_KEY_ID_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];

/**
 * `verifyRequest` with `expectedKeyId` steady state: the
 * key-id binding form a receiver uses to pin the expected
 * signer key (key-confusion defense) — every measured call
 * runs the post-cryptographic keyid comparison the plain
 * verify rows above never pay, because they pass no pin.
 * One measured op verifies the one pinned fixture with a
 * matching `expectedKeyId` and re-pins that the result is
 * ok and its returned `keyId` equals the pinned value.
 * Outside timing, the rejecting and default halves are
 * pinned once: a mismatched pin returns exactly
 * `{ ok: false, code: "KEYID_MISMATCH" }` with the pinned
 * reason, a hand-built signature carrying no `keyid`
 * (built with `buildSignatureBase` + `signatureInputValue`
 * + a raw ed25519 sign, the shape
 * `test/keyidBinding.test.ts` uses) returns the same code
 * with the `got no keyid` reason shape, and that same
 * no-keyid signature still verifies with the option unset,
 * because the pin is opt-in. Zero network, zero randomness
 * in the measured assertions, no wall clock (every verify
 * instant is injected).
 */
function benchmarkVerifyExpectedKeyId(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: EXPECTED_KEY_ID_KID,
    alg: "ed25519",
    key: privateKey,
    created: EXPECTED_KEY_ID_CREATED,
  });
  const verifyOpts = {
    key: publicKey,
    now: EXPECTED_KEY_ID_CREATED,
    expectedKeyId: EXPECTED_KEY_ID_KID,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok || r.keyId !== EXPECTED_KEY_ID_KID)
      throw new Error(
        `benchmark self-check failed: verifyRequest with expectedKeyId (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the pinned fixture verifies under the
  // matching pin.
  assertAccepted("outside timing");

  // Outside timing: a mismatched pin is rejected with the
  // pinned code and reason.
  const mismatched = verifyRequest(signed, {
    key: publicKey,
    now: EXPECTED_KEY_ID_CREATED,
    expectedKeyId: EXPECTED_KEY_ID_WRONG,
  });
  if (
    mismatched.ok ||
    mismatched.code !== "KEYID_MISMATCH" ||
    mismatched.reason !==
      `keyid mismatch: expected "${EXPECTED_KEY_ID_WRONG}", got "${EXPECTED_KEY_ID_KID}"` ||
    mismatched.keyId !== EXPECTED_KEY_ID_KID
  )
    throw new Error(
      `benchmark self-check failed: mismatched-pin result ${JSON.stringify(mismatched)} ` +
        `(expected KEYID_MISMATCH)`,
    );

  // Outside timing: a hand-built signature with no
  // `keyid` is rejected with the pinned code and the
  // `got no keyid` reason shape.
  const noKeyIdParams: SignatureParams = {
    alg: "ed25519",
    created: EXPECTED_KEY_ID_CREATED,
  };
  const noKeyIdRequest: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: {},
  };
  const noKeyIdBase = buildSignatureBase(
    EXPECTED_KEY_ID_COVERED_COMPONENTS,
    noKeyIdRequest,
    noKeyIdParams,
  );
  const noKeyIdSig = edSign(
    null,
    Buffer.from(noKeyIdBase, "utf8"),
    privateKey,
  );
  const noKeyIdSigned: SignedHttpRequest = {
    method: noKeyIdRequest.method,
    url: noKeyIdRequest.url,
    headers: {
      "signature-input": signatureInputValue(
        "sig1",
        EXPECTED_KEY_ID_COVERED_COMPONENTS,
        noKeyIdParams,
      ),
      signature: `sig1=:${noKeyIdSig.toString("base64")}:`,
    },
  };
  const noKeyId = verifyRequest(noKeyIdSigned, {
    key: publicKey,
    now: EXPECTED_KEY_ID_CREATED,
    expectedKeyId: EXPECTED_KEY_ID_KID,
  });
  if (
    noKeyId.ok ||
    noKeyId.code !== "KEYID_MISMATCH" ||
    noKeyId.reason !==
      `keyid mismatch: expected "${EXPECTED_KEY_ID_KID}", got no keyid` ||
    noKeyId.keyId !== undefined
  )
    throw new Error(
      `benchmark self-check failed: no-keyid result ${JSON.stringify(noKeyId)} ` +
        `(expected KEYID_MISMATCH)`,
    );

  // Outside timing: without the option the same
  // no-keyid signature verifies — the pin is opt-in and
  // the default behaviour is unchanged.
  const defaulted = verifyRequest(noKeyIdSigned, {
    key: publicKey,
    now: EXPECTED_KEY_ID_CREATED,
  });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: no-keyid default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` expectedKeyIds
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), a dual-label fixture signed outside
 * timing with `created` pinned under two pinned keyids
 * (merchant / gateway, the canonical multi-party labels),
 * and the verifier's injected `now` at the `created`
 * instant.
 */
const EXPECTED_KEY_IDS_CREATED = 1_700_000_000;
const EXPECTED_KEY_IDS_MERCHANT_KID =
  "bench-expected-key-ids-merchant-1";
const EXPECTED_KEY_IDS_GATEWAY_KID =
  "bench-expected-key-ids-gateway-7";
const EXPECTED_KEY_IDS_GATEWAY_WRONG =
  "bench-expected-key-ids-gateway-other";

/**
 * `verifyAllLabels` with `expectedKeyIds` steady state:
 * the per-label key-id binding form a multi-party
 * receiver uses to pin each signer's key independently
 * (key-confusion defense when the merchant and the
 * gateway use different key ids) — every measured call
 * runs the per-label pin resolution and the
 * post-cryptographic keyid comparison for both labels,
 * which the plain `verifyAllLabels` row above never
 * pays, because it passes no pins. One measured op
 * verifies the dual-label fixture with a fully matching
 * `expectedKeyIds` map and re-pins that both results
 * are ok, in wire order, and that each returned
 * `keyId` equals its label's pinned value. Outside
 * timing, the rejecting and fallback halves are pinned
 * once: one label pinned wrong returns exactly
 * `{ ok: false, code: "KEYID_MISMATCH" }` with the
 * pinned reason while the other label still verifies,
 * a label missing from the map falls back to the
 * global `expectedKeyId` (matching fallback verifies
 * both labels; an empty map makes the gateway label
 * fail against the merchant global pin with the
 * pinned code and reason), and an empty-string map
 * value throws the pinned configuration error. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllExpectedKeyIds(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: EXPECTED_KEY_IDS_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_KEY_IDS_CREATED,
  });
  const dual = addSignature(merchantSigned, {
    keyId: EXPECTED_KEY_IDS_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_KEY_IDS_CREATED,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: EXPECTED_KEY_IDS_CREATED,
    expectedKeyIds: {
      merchant: EXPECTED_KEY_IDS_MERCHANT_KID,
      gateway: EXPECTED_KEY_IDS_GATEWAY_KID,
    },
  };
  const assertAccepted = (where: string): void => {
    const results = verifyAllLabels(dual, verifyOpts);
    if (
      results.length !== 2 ||
      results[0].label !== "merchant" ||
      !results[0].ok ||
      results[0].keyId !== EXPECTED_KEY_IDS_MERCHANT_KID ||
      results[1].label !== "gateway" ||
      !results[1].ok ||
      results[1].keyId !== EXPECTED_KEY_IDS_GATEWAY_KID
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedKeyIds (${where}) gave ${JSON.stringify(results)}`,
      );
  };

  // Outside timing: the pinned fixture verifies under
  // the fully matching per-label pins.
  assertAccepted("outside timing");

  // Outside timing: a wrong pin on the gateway label
  // rejects only that label with the pinned code and
  // reason; the merchant label still verifies.
  const mismatched = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_KEY_IDS_CREATED,
    expectedKeyIds: {
      merchant: EXPECTED_KEY_IDS_MERCHANT_KID,
      gateway: EXPECTED_KEY_IDS_GATEWAY_WRONG,
    },
  });
  if (
    mismatched.length !== 2 ||
    mismatched[0].label !== "merchant" ||
    !mismatched[0].ok ||
    mismatched[1].label !== "gateway" ||
    mismatched[1].ok ||
    mismatched[1].code !== "KEYID_MISMATCH" ||
    mismatched[1].reason !==
      `keyid mismatch: expected "${EXPECTED_KEY_IDS_GATEWAY_WRONG}", got "${EXPECTED_KEY_IDS_GATEWAY_KID}"` ||
    mismatched[1].keyId !== EXPECTED_KEY_IDS_GATEWAY_KID
  )
    throw new Error(
      `benchmark self-check failed: mismatched-pin result ${JSON.stringify(mismatched)} ` +
        `(expected KEYID_MISMATCH on gateway only)`,
    );

  // Outside timing: a label missing from the map falls
  // back to the global `expectedKeyId` — here the
  // merchant label is unpinned per label and the
  // global pin matches it, so both labels verify.
  const fallbackOk = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_KEY_IDS_CREATED,
    expectedKeyId: EXPECTED_KEY_IDS_MERCHANT_KID,
    expectedKeyIds: { gateway: EXPECTED_KEY_IDS_GATEWAY_KID },
  });
  if (
    fallbackOk.length !== 2 ||
    fallbackOk.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: global-fallback result ${JSON.stringify(fallbackOk)}`,
    );

  // Outside timing: with an empty map the same global
  // pin applies to every label, so the gateway label
  // fails it with the pinned code and reason while the
  // merchant label still verifies.
  const fallbackMismatch = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_KEY_IDS_CREATED,
    expectedKeyId: EXPECTED_KEY_IDS_MERCHANT_KID,
    expectedKeyIds: {},
  });
  if (
    fallbackMismatch.length !== 2 ||
    !fallbackMismatch[0].ok ||
    fallbackMismatch[1].ok ||
    fallbackMismatch[1].code !== "KEYID_MISMATCH" ||
    fallbackMismatch[1].reason !==
      `keyid mismatch: expected "${EXPECTED_KEY_IDS_MERCHANT_KID}", got "${EXPECTED_KEY_IDS_GATEWAY_KID}"` ||
    fallbackMismatch[1].keyId !== EXPECTED_KEY_IDS_GATEWAY_KID
  )
    throw new Error(
      `benchmark self-check failed: global-fallback mismatch result ${JSON.stringify(fallbackMismatch)} ` +
        `(expected KEYID_MISMATCH on gateway only)`,
    );

  // Outside timing: an empty-string map value is a
  // caller configuration error with the pinned full
  // message, thrown before any verification runs.
  let configError: unknown;
  try {
    verifyAllLabels(dual, {
      keys,
      now: EXPECTED_KEY_IDS_CREATED,
      expectedKeyIds: { merchant: "" },
    });
  } catch (e) {
    configError = e;
  }
  if (
    !(configError instanceof Error) ||
    configError.message !==
      'verifyAllLabels: `expectedKeyIds["merchant"]` must be a non-empty string, got ""'
  )
    throw new Error(
      `benchmark self-check failed: empty-string pin gave ${String(configError)} ` +
        `(expected the pinned configuration error)`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` keyResolvers
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing) held in two separate pinned Map
 * keystores, a dual-label fixture signed outside
 * timing with `created` pinned under two pinned keyids
 * (merchant / gateway, each belonging to its own
 * resolver), and the verifier's injected `now` at the
 * `created` instant.
 */
const KEY_RESOLVERS_ALL_CREATED = 1_700_000_000;
const KEY_RESOLVERS_ALL_MERCHANT_KID =
  "bench-key-resolvers-merchant-1";
const KEY_RESOLVERS_ALL_GATEWAY_KID =
  "bench-key-resolvers-gateway-7";

/**
 * `verifyAllLabels` with `keyResolvers` steady state:
 * the per-label key-resolution form a multi-party
 * receiver uses when the merchant's and the gateway's
 * keyids live in separate keystores — every measured
 * call runs the per-label resolver lookup for both
 * labels, which the plain `verifyAllLabels` row above
 * never pays, because it passes static keys, and which
 * the single-label `verifyRequest keyResolver` row
 * pays for only one label. One measured op verifies
 * the dual-label fixture with a fully resolving
 * `keyResolvers` map and re-pins that both results
 * are ok, in wire order, and that each returned
 * `keyId` equals its label's pinned value. Outside
 * timing, the fail-closed, fallback and configuration
 * halves are pinned once: one label's resolver
 * returning `undefined` gives that label exactly
 * `{ ok: false, code: "KEY_RESOLUTION_FAILED" }`
 * with the pinned reason while the other label still
 * verifies, a label missing from the map falls back
 * to the global `keyResolver`, a non-function map
 * value throws the pinned configuration error, and
 * `keyResolvers` combined with `keys` throws the
 * pinned mutual-exclusion configuration error. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllKeyResolvers(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: KEY_RESOLVERS_ALL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: KEY_RESOLVERS_ALL_CREATED,
  });
  const dual = addSignature(merchantSigned, {
    keyId: KEY_RESOLVERS_ALL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: KEY_RESOLVERS_ALL_CREATED,
  });
  const merchantStore = new Map<string, KeyObject>([
    [KEY_RESOLVERS_ALL_MERCHANT_KID, merchantPublic],
  ]);
  const gatewayStore = new Map<string, KeyObject>([
    [KEY_RESOLVERS_ALL_GATEWAY_KID, gatewayPublic],
  ]);
  const merchantResolver = (id: string) => merchantStore.get(id);
  const gatewayResolver = (id: string) => gatewayStore.get(id);
  const verifyOpts = {
    now: KEY_RESOLVERS_ALL_CREATED,
    keyResolvers: {
      merchant: merchantResolver,
      gateway: gatewayResolver,
    },
  };
  const assertAccepted = (where: string): void => {
    const results = verifyAllLabels(dual, verifyOpts);
    if (
      results.length !== 2 ||
      results[0].label !== "merchant" ||
      !results[0].ok ||
      results[0].keyId !== KEY_RESOLVERS_ALL_MERCHANT_KID ||
      results[1].label !== "gateway" ||
      !results[1].ok ||
      results[1].keyId !== KEY_RESOLVERS_ALL_GATEWAY_KID
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with keyResolvers (${where}) gave ${JSON.stringify(results)}`,
      );
  };

  // Outside timing: the pinned fixture verifies through
  // its two per-label resolvers.
  assertAccepted("outside timing");

  // Outside timing: the gateway resolver returning
  // `undefined` (its kid rotated out of that keystore)
  // fails only the gateway label closed, with the
  // pinned code and reason; the merchant label still
  // verifies through its own resolver.
  const unresolved = verifyAllLabels(dual, {
    now: KEY_RESOLVERS_ALL_CREATED,
    keyResolvers: {
      merchant: merchantResolver,
      gateway: () => undefined,
    },
  });
  if (
    unresolved.length !== 2 ||
    unresolved[0].label !== "merchant" ||
    !unresolved[0].ok ||
    unresolved[1].label !== "gateway" ||
    unresolved[1].ok ||
    unresolved[1].code !== "KEY_RESOLUTION_FAILED" ||
    unresolved[1].reason !==
      `keyid "${KEY_RESOLVERS_ALL_GATEWAY_KID}" could not be resolved to a key` ||
    unresolved[1].keyId !== KEY_RESOLVERS_ALL_GATEWAY_KID
  )
    throw new Error(
      `benchmark self-check failed: unresolved-resolver result ${JSON.stringify(unresolved)} ` +
        `(expected KEY_RESOLUTION_FAILED on gateway only)`,
    );

  // Outside timing: a label missing from the map falls
  // back to the global `keyResolver` — here the gateway
  // label is unmapped and the global resolver holds
  // only the gateway key, so both labels verify (the
  // merchant through its per-label resolver, the
  // gateway through the fallback).
  const globalStore = new Map<string, KeyObject>([
    [KEY_RESOLVERS_ALL_GATEWAY_KID, gatewayPublic],
  ]);
  const fallback = verifyAllLabels(dual, {
    now: KEY_RESOLVERS_ALL_CREATED,
    keyResolver: (id: string) => globalStore.get(id),
    keyResolvers: { merchant: merchantResolver },
  });
  if (
    fallback.length !== 2 ||
    fallback.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: global-fallback result ${JSON.stringify(fallback)}`,
    );

  // Outside timing: a non-function map value is a
  // caller configuration error with the pinned full
  // message, thrown before any verification runs.
  let configError: unknown;
  try {
    verifyAllLabels(dual, {
      now: KEY_RESOLVERS_ALL_CREATED,
      keyResolvers: {
        merchant: "not-a-function" as never,
      },
    });
  } catch (e) {
    configError = e;
  }
  if (
    !(configError instanceof Error) ||
    configError.message !==
      'verifyAllLabels: `keyResolvers["merchant"]` must be a function, got string'
  )
    throw new Error(
      `benchmark self-check failed: non-function resolver gave ${String(configError)} ` +
        `(expected the pinned configuration error)`,
    );

  // Outside timing: `keyResolvers` combined with
  // `keys` is a caller configuration error with the
  // pinned mutual-exclusion message.
  let conflictError: unknown;
  try {
    verifyAllLabels(dual, {
      now: KEY_RESOLVERS_ALL_CREATED,
      keys: { merchant: merchantPublic, gateway: gatewayPublic },
      keyResolvers: {
        merchant: merchantResolver,
        gateway: gatewayResolver,
      },
    });
  } catch (e) {
    conflictError = e;
  }
  if (
    !(conflictError instanceof Error) ||
    conflictError.message !==
      "verifyAllLabels: `keys`/`key` is mutually exclusive with `keyResolver`/`keyResolvers` — pass one or the other"
  )
    throw new Error(
      `benchmark self-check failed: keys+keyResolvers conflict gave ${String(conflictError)} ` +
        `(expected the pinned mutual-exclusion error)`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` requireNonceByLabel
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), two dual-label fixtures signed outside
 * timing with `created` pinned under two pinned keyids
 * (merchant / gateway, the canonical multi-party labels),
 * and the verifier's injected `now` at the `created`
 * instant. The merchant label is mapped `true` in
 * `requireNonceByLabel` and the global `requireNonce`
 * is left unset, so the gateway label — missing from
 * the map — falls back to no requirement.
 */
const REQUIRE_NONCE_BY_LABEL_CREATED = 1_700_000_000;
const REQUIRE_NONCE_BY_LABEL_MERCHANT_KID =
  "bench-require-nonce-by-label-merchant-1";
const REQUIRE_NONCE_BY_LABEL_GATEWAY_KID =
  "bench-require-nonce-by-label-gateway-1";
const REQUIRE_NONCE_BY_LABEL_VALUE = "bench-require-nonce-by-label-1";
const REQUIRE_NONCE_BY_LABEL_CODE = "MISSING_NONCE";
const REQUIRE_NONCE_BY_LABEL_REASON =
  "signature carries no `nonce` but requireNonce is set";

/**
 * `verifyAllLabels` with `requireNonceByLabel` steady
 * state: the per-label nonce-presence form a multi-party
 * receiver uses when only one signer must carry a nonce
 * (the merchant signature must carry one; the gateway
 * signature historically carries none) — every measured
 * call runs the per-label map resolution and the
 * post-cryptographic presence check for the mapped
 * label, which the plain `verifyAllLabels` row above
 * never pays, because it passes no requirement. One
 * measured op verifies two dual-label fixtures: the
 * nonce-carrying dual (both labels ok, merchant nonce
 * returned) and the nonce-less-merchant dual (merchant
 * exactly `MISSING_NONCE` with the pinned reason while
 * the unmapped gateway label still verifies, proving
 * the gateway falls back to the unset global rather
 * than inheriting the merchant's map entry). Outside
 * timing, the opt-in half is pinned once: the same
 * nonce-less dual verifies with no option passed, and
 * an explicit `merchant: false` map entry likewise
 * lets the nonce-less merchant label through. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllRequireNonceByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantWithNonceSigned = signRequest(fixture, {
    keyId: REQUIRE_NONCE_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REQUIRE_NONCE_BY_LABEL_CREATED,
    nonce: REQUIRE_NONCE_BY_LABEL_VALUE,
  });
  const dualWithNonce = addSignature(merchantWithNonceSigned, {
    keyId: REQUIRE_NONCE_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRE_NONCE_BY_LABEL_CREATED,
  });
  const merchantWithoutNonceSigned = signRequest(fixture, {
    keyId: REQUIRE_NONCE_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REQUIRE_NONCE_BY_LABEL_CREATED,
  });
  const dualWithoutNonce = addSignature(merchantWithoutNonceSigned, {
    keyId: REQUIRE_NONCE_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRE_NONCE_BY_LABEL_CREATED,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REQUIRE_NONCE_BY_LABEL_CREATED,
    requireNonceByLabel: { merchant: true },
  };
  const assertDual = (where: string): void => {
    const accepted = verifyAllLabels(dualWithNonce, verifyOpts);
    if (
      accepted.length !== 2 ||
      accepted[0].label !== "merchant" ||
      !accepted[0].ok ||
      accepted[0].nonce !== REQUIRE_NONCE_BY_LABEL_VALUE ||
      accepted[1].label !== "gateway" ||
      !accepted[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireNonceByLabel (${where}, nonce-carrying dual) gave ${JSON.stringify(accepted)}`,
      );
    const rejected = verifyAllLabels(dualWithoutNonce, verifyOpts);
    if (
      rejected.length !== 2 ||
      rejected[0].label !== "merchant" ||
      rejected[0].ok ||
      rejected[0].code !== REQUIRE_NONCE_BY_LABEL_CODE ||
      rejected[0].reason !== REQUIRE_NONCE_BY_LABEL_REASON ||
      rejected[1].label !== "gateway" ||
      !rejected[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireNonceByLabel (${where}, nonce-less-merchant dual) gave ${JSON.stringify(rejected)}`,
      );
  };

  // Outside timing: both fixtures self-check under the
  // per-label requirement before any timing starts.
  assertDual("outside timing");

  // Outside timing: with no option the same nonce-less
  // dual verifies — the requirement is opt-in and the
  // default behaviour is unchanged.
  const defaulted = verifyAllLabels(dualWithoutNonce, {
    keys,
    now: REQUIRE_NONCE_BY_LABEL_CREATED,
  });
  if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: nonce-less default gave ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: an explicit `merchant: false` map
  // entry likewise lets the nonce-less merchant label
  // through — the map entry, not the label name, drives
  // the check.
  const optedOut = verifyAllLabels(dualWithoutNonce, {
    keys,
    now: REQUIRE_NONCE_BY_LABEL_CREATED,
    requireNonceByLabel: { merchant: false },
  });
  if (optedOut.length !== 2 || optedOut.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: nonce-less merchant:false gave ${JSON.stringify(optedOut)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` candidateKeysByLabel
 * benchmark: one fixed ed25519 key pair for the merchant
 * (generated once, outside timing), two 32-byte HMAC
 * secrets for the gateway rotation window (old + new,
 * fixed byte fills, no randomness), a third unrelated
 * ed25519 key pair whose public key stands in for a
 * swapped merchant list, and three dual-label fixtures
 * signed outside timing with `created` pinned under
 * two pinned keyids (merchant / gateway, the canonical
 * multi-party labels) and the verifier's injected
 * `now` at the `created` instant. The merchant label
 * is mapped to its single fixed key and the gateway
 * label to its `[old, new]` rotation list; no global
 * `candidateKeys` is set for the measured pass, so
 * every label resolves through the map alone.
 */
const CANDIDATE_KEYS_BY_LABEL_CREATED = 1_700_000_000;
const CANDIDATE_KEYS_BY_LABEL_MERCHANT_KID =
  "bench-candidate-keys-by-label-merchant-1";
const CANDIDATE_KEYS_BY_LABEL_GATEWAY_KID =
  "bench-candidate-keys-by-label-gateway-1";
const CANDIDATE_KEYS_BY_LABEL_MISMATCH_CODE = "SIGNATURE_MISMATCH";

/**
 * `verifyAllLabels` with `candidateKeysByLabel` steady
 * state: the per-label rotation form a multi-party
 * receiver uses when each signer rotates keys on its
 * own schedule (the merchant key is fixed while the
 * gateway rolls its HMAC secret, the Stripe-style
 * rollover scenario) — every measured call runs the
 * per-label map resolution and the ordered candidate
 * walk for both labels, which the plain
 * `verifyAllLabels` row above never pays, because it
 * passes a single fixed key per label. One measured
 * op verifies three dual-label fixtures: the
 * new-secret dual (both labels ok, the gateway found
 * at the second candidate, proving the walk actually
 * reaches past the stale entry); the old-secret dual
 * (both labels ok, proving the rotation window still
 * accepts the outgoing secret); and the
 * swapped-merchant-list dual (merchant exactly
 * `SIGNATURE_MISMATCH` while the gateway label still
 * verifies, proving each label tries only its own
 * candidate list — a pooled list would let the
 * merchant failure leak, or the gateway success
 * depend on the merchant's entry). Outside timing,
 * the fallback and configuration halves are pinned
 * once: the same new-secret dual verifies when the
 * gateway label is missing from the map and the
 * rotation list is passed as the global
 * `candidateKeys` instead, and combining
 * `candidateKeysByLabel` with `keys` throws the
 * pinned mutual-exclusion configuration error. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllCandidateKeysByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: unrelatedPublic } = generateEd25519KeyPair();
  const gatewayOld = secretKey(Buffer.alloc(32, 0xaa));
  const gatewayNew = secretKey(Buffer.alloc(32, 0xbb));
  const merchantSigned = signRequest(fixture, {
    keyId: CANDIDATE_KEYS_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: CANDIDATE_KEYS_BY_LABEL_CREATED,
  });
  const dualNew = addSignature(merchantSigned, {
    keyId: CANDIDATE_KEYS_BY_LABEL_GATEWAY_KID,
    alg: "hmac-sha256",
    key: gatewayNew,
    label: "gateway",
    created: CANDIDATE_KEYS_BY_LABEL_CREATED,
  });
  const dualOld = addSignature(merchantSigned, {
    keyId: CANDIDATE_KEYS_BY_LABEL_GATEWAY_KID,
    alg: "hmac-sha256",
    key: gatewayOld,
    label: "gateway",
    created: CANDIDATE_KEYS_BY_LABEL_CREATED,
  });
  const verifyOpts = {
    candidateKeysByLabel: {
      merchant: [merchantPublic],
      gateway: [gatewayOld, gatewayNew],
    },
    now: CANDIDATE_KEYS_BY_LABEL_CREATED,
  };
  const swappedOpts = {
    candidateKeysByLabel: {
      merchant: [unrelatedPublic],
      gateway: [gatewayOld, gatewayNew],
    },
    now: CANDIDATE_KEYS_BY_LABEL_CREATED,
  };
  const assertDual = (where: string): void => {
    const rotated = verifyAllLabels(dualNew, verifyOpts);
    if (
      rotated.length !== 2 ||
      rotated[0].label !== "merchant" ||
      !rotated[0].ok ||
      rotated[1].label !== "gateway" ||
      !rotated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysByLabel (${where}, new-secret dual) gave ${JSON.stringify(rotated)}`,
      );
    const windowed = verifyAllLabels(dualOld, verifyOpts);
    if (
      windowed.length !== 2 ||
      windowed[0].label !== "merchant" ||
      !windowed[0].ok ||
      windowed[1].label !== "gateway" ||
      !windowed[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysByLabel (${where}, old-secret dual) gave ${JSON.stringify(windowed)}`,
      );
    const isolated = verifyAllLabels(dualNew, swappedOpts);
    if (
      isolated.length !== 2 ||
      isolated[0].label !== "merchant" ||
      isolated[0].ok ||
      isolated[0].code !== CANDIDATE_KEYS_BY_LABEL_MISMATCH_CODE ||
      isolated[1].label !== "gateway" ||
      !isolated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysByLabel (${where}, swapped-merchant-list dual) gave ${JSON.stringify(isolated)}`,
      );
  };

  // Outside timing: all three fixtures self-check under
  // the per-label map before any timing starts.
  assertDual("outside timing");

  // Outside timing: a label missing from the map falls
  // back to the global `candidateKeys` — the gateway
  // verifies off the global rotation list while the
  // merchant still resolves through its map entry.
  const fallback = verifyAllLabels(dualNew, {
    candidateKeys: [gatewayOld, gatewayNew],
    candidateKeysByLabel: { merchant: [merchantPublic] },
    now: CANDIDATE_KEYS_BY_LABEL_CREATED,
  });
  if (fallback.length !== 2 || fallback.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: candidateKeysByLabel global fallback gave ${JSON.stringify(fallback)}`,
    );

  // Outside timing: combining `candidateKeysByLabel`
  // with `keys` throws the pinned mutual-exclusion
  // configuration error instead of silently picking
  // one key source.
  let exclusionError: unknown;
  try {
    verifyAllLabels(dualNew, {
      keys: { merchant: merchantPublic },
      candidateKeysByLabel: {
        merchant: [merchantPublic],
        gateway: [gatewayOld, gatewayNew],
      },
      now: CANDIDATE_KEYS_BY_LABEL_CREATED,
    });
  } catch (e) {
    exclusionError = e;
  }
  if (
    !(exclusionError instanceof Error) ||
    exclusionError.message !==
      "verifyAllLabels: `candidateKeysByLabel`/`candidateKeys` is mutually exclusive with `keys`/`key` and `keyResolver`/`keyResolvers` — pass one or the other"
  )
    throw new Error(
      `benchmark self-check failed: candidateKeysByLabel + keys did not throw the pinned error, got ${exclusionError instanceof Error ? JSON.stringify(exclusionError.message) : String(exclusionError)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` requireTagByLabel
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), two dual-label fixtures signed outside
 * timing with `created` pinned under two pinned keyids
 * (merchant / gateway, the canonical multi-party labels),
 * and the verifier's injected `now` at the `created`
 * instant. The merchant label is mapped `true` in
 * `requireTagByLabel` and the global `requireTag`
 * is left unset, so the gateway label — missing from
 * the map — falls back to no requirement.
 */
const REQUIRE_TAG_BY_LABEL_CREATED = 1_700_000_000;
const REQUIRE_TAG_BY_LABEL_MERCHANT_KID =
  "bench-require-tag-by-label-merchant-1";
/**
 * Pinned shape of the `verifyAllLabels` candidateKeysByLabel x
 * expectedKeyIds benchmark: three ed25519 key pairs for the
 * merchant rotation (old / new / retired, generated once,
 * outside timing), one ed25519 pair for the static gateway,
 * dual-label fixtures signed outside timing with `created`
 * pinned (merchant new / old / retired keys, plus a
 * wrong-kid new-key variant), and the verifier's injected
 * `now` at the `created` instant. The merchant label is
 * mapped in `candidateKeysByLabel` to [old, new] and in
 * `expectedKeyIds` to the new key's keyid; the gateway
 * label resolves through `keys` and is pinned in
 * `expectedKeyIds` to its static keyid — the disjoint
 * per-label key sources the combination test (#627)
 * pins, so no mutual-exclusion error fires.
 */
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED = 1_700_000_000;
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_OLD_KID =
  "bench-candidate-keys-expected-key-ids-merchant-old";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID =
  "bench-candidate-keys-expected-key-ids-merchant-new";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_RETIRED_KID =
  "bench-candidate-keys-expected-key-ids-merchant-retired";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_WRONG_KID =
  "bench-candidate-keys-expected-key-ids-merchant-wrong";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID =
  "bench-candidate-keys-expected-key-ids-gateway-1";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_WRONG_KID =
  "bench-candidate-keys-expected-key-ids-gateway-wrong";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_KEYID_MISMATCH_CODE =
  "KEYID_MISMATCH";
const CANDIDATE_KEYS_EXPECTED_KEY_IDS_SIGNATURE_MISMATCH_CODE =
  "SIGNATURE_MISMATCH";

/**
 * `verifyAllLabels` with `candidateKeysByLabel` /
 * `expectedKeyIds` combined: the per-label rotation-plus-
 * pinning form a multi-party receiver uses when the
 * merchant rotates keys on its own schedule while each
 * label's keyid is pinned to the key that actually
 * signed (the merchant's new key and the gateway's
 * static key) — every measured call runs the per-label
 * map resolutions, the ordered candidate walk for the
 * merchant, and the post-cryptographic pin checks for
 * both labels, which neither single-map row above pays
 * in full, because each passes only one of the two
 * maps. One measured op verifies four dual-label
 * fixtures: the new-key dual (both labels ok, each
 * returned `keyId` echoing its pinned value, the
 * merchant found at the second candidate, proving the
 * walk actually reaches past the stale entry); the
 * old-key dual re-pinned to the old key's keyid (both
 * labels ok, proving list membership — not the pin
 * value — decides the crypto walk); the wrong-kid
 * dual (merchant exactly `KEYID_MISMATCH` with the
 * pinned reason while the gateway label still
 * verifies, proving the pin check, not the rotation
 * walk, fails it); and the retired-key dual re-pinned
 * to the retired key's keyid (merchant exactly
 * `SIGNATURE_MISMATCH` while the gateway label still
 * verifies, proving a pin cannot rescue a key the
 * rotation list no longer contains). Outside timing,
 * the opt-in and fallback halves are pinned once: the
 * new-key dual verifies with no pinning configured
 * (rotation alone does not pin); a gateway label
 * missing from the map falls back to the global
 * `expectedKeyId` (both labels ok, and a wrong global
 * fails only the gateway label); and combining
 * `candidateKeysByLabel` with `keys` on the same label
 * throws the pinned mutual-exclusion configuration
 * error instead of silently picking one key source.
 * Zero network, zero randomness in the measured
 * assertions, no wall clock (every verify instant is
 * injected).
 */
function benchmarkVerifyAllCandidateKeysExpectedKeyIds(): number {
  const { publicKey: merchantOldPublic, privateKey: merchantOldPrivate } =
    generateEd25519KeyPair();
  const { publicKey: merchantNewPublic, privateKey: merchantNewPrivate } =
    generateEd25519KeyPair();
  const { privateKey: merchantRetiredPrivate } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantNewSigned = signRequest(fixture, {
    keyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID,
    alg: "ed25519",
    key: merchantNewPrivate,
    label: "merchant",
    created: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  const merchantOldSigned = signRequest(fixture, {
    keyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_OLD_KID,
    alg: "ed25519",
    key: merchantOldPrivate,
    label: "merchant",
    created: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  const merchantRetiredSigned = signRequest(fixture, {
    keyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_RETIRED_KID,
    alg: "ed25519",
    key: merchantRetiredPrivate,
    label: "merchant",
    created: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  const merchantWrongKidSigned = signRequest(fixture, {
    keyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_WRONG_KID,
    alg: "ed25519",
    key: merchantNewPrivate,
    label: "merchant",
    created: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  const gatewaySigned = {
    keyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID,
    alg: "ed25519" as const,
    key: gatewayPrivate,
    label: "gateway",
    created: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  };
  const dualNew = addSignature(merchantNewSigned, gatewaySigned);
  const dualOld = addSignature(merchantOldSigned, gatewaySigned);
  const dualRetired = addSignature(merchantRetiredSigned, gatewaySigned);
  const dualWrongKid = addSignature(merchantWrongKidSigned, gatewaySigned);
  const verifyOpts = {
    candidateKeysByLabel: {
      merchant: [merchantOldPublic, merchantNewPublic],
    },
    keys: { gateway: gatewayPublic },
    expectedKeyIds: {
      merchant: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID,
      gateway: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID,
    },
    now: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  };
  const rePinnedOldOpts = {
    ...verifyOpts,
    expectedKeyIds: {
      merchant: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_OLD_KID,
      gateway: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID,
    },
  };
  const rePinnedRetiredOpts = {
    ...verifyOpts,
    expectedKeyIds: {
      merchant: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_RETIRED_KID,
      gateway: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID,
    },
  };
  const assertDual = (where: string): void => {
    const rotated = verifyAllLabels(dualNew, verifyOpts);
    if (
      rotated.length !== 2 ||
      rotated[0].label !== "merchant" ||
      !rotated[0].ok ||
      rotated[0].keyId !==
        CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID ||
      rotated[1].label !== "gateway" ||
      !rotated[1].ok ||
      rotated[1].keyId !== CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysExpectedKeyIds (${where}, new-key dual) gave ${JSON.stringify(rotated)}`,
      );
    const windowed = verifyAllLabels(dualOld, rePinnedOldOpts);
    if (
      windowed.length !== 2 ||
      windowed[0].label !== "merchant" ||
      !windowed[0].ok ||
      windowed[0].keyId !==
        CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_OLD_KID ||
      windowed[1].label !== "gateway" ||
      !windowed[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysExpectedKeyIds (${where}, old-key dual) gave ${JSON.stringify(windowed)}`,
      );
    const mismatched = verifyAllLabels(dualWrongKid, verifyOpts);
    if (
      mismatched.length !== 2 ||
      mismatched[0].label !== "merchant" ||
      mismatched[0].ok ||
      mismatched[0].code !==
        CANDIDATE_KEYS_EXPECTED_KEY_IDS_KEYID_MISMATCH_CODE ||
      mismatched[0].reason !==
        `keyid mismatch: expected "${CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID}", got "${CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_WRONG_KID}"` ||
      mismatched[0].keyId !==
        CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_WRONG_KID ||
      mismatched[1].label !== "gateway" ||
      !mismatched[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysExpectedKeyIds (${where}, wrong-kid dual) gave ${JSON.stringify(mismatched)}`,
      );
    const retired = verifyAllLabels(dualRetired, rePinnedRetiredOpts);
    if (
      retired.length !== 2 ||
      retired[0].label !== "merchant" ||
      retired[0].ok ||
      retired[0].code !==
        CANDIDATE_KEYS_EXPECTED_KEY_IDS_SIGNATURE_MISMATCH_CODE ||
      retired[1].label !== "gateway" ||
      !retired[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with candidateKeysExpectedKeyIds (${where}, retired-key dual) gave ${JSON.stringify(retired)}`,
      );
  };

  // Outside timing: all four fixtures self-check under
  // the combined maps before any timing starts.
  assertDual("outside timing");

  // Outside timing: with no pinning configured the
  // new-key dual verifies and the returned keyids echo
  // the signing keys — pinning is opt-in, rotation
  // alone does not pin.
  const unpinned = verifyAllLabels(dualNew, {
    candidateKeysByLabel: {
      merchant: [merchantOldPublic, merchantNewPublic],
    },
    keys: { gateway: gatewayPublic },
    now: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  if (
    unpinned.length !== 2 ||
    unpinned.some((r) => !r.ok) ||
    unpinned[0].keyId !==
      CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID ||
    unpinned[1].keyId !== CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID
  )
    throw new Error(
      `benchmark self-check failed: candidateKeysExpectedKeyIds no-pinning gave ${JSON.stringify(unpinned)}`,
    );

  // Outside timing: a gateway label missing from the
  // map falls back to the global `expectedKeyId` — the
  // merchant keeps its own pin and both labels verify.
  const fallbackOk = verifyAllLabels(dualNew, {
    candidateKeysByLabel: {
      merchant: [merchantOldPublic, merchantNewPublic],
    },
    keys: { gateway: gatewayPublic },
    expectedKeyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID,
    expectedKeyIds: {
      merchant: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID,
    },
    now: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  if (fallbackOk.length !== 2 || fallbackOk.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: candidateKeysExpectedKeyIds global fallback gave ${JSON.stringify(fallbackOk)}`,
    );

  // Outside timing: a wrong global pin fails only the
  // unpinned gateway label with the pinned code and
  // reason while the merchant label still verifies.
  const fallbackMismatch = verifyAllLabels(dualNew, {
    candidateKeysByLabel: {
      merchant: [merchantOldPublic, merchantNewPublic],
    },
    keys: { gateway: gatewayPublic },
    expectedKeyId: CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_WRONG_KID,
    expectedKeyIds: {
      merchant: CANDIDATE_KEYS_EXPECTED_KEY_IDS_MERCHANT_NEW_KID,
    },
    now: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
  });
  if (
    fallbackMismatch.length !== 2 ||
    !fallbackMismatch[0].ok ||
    fallbackMismatch[1].ok ||
    fallbackMismatch[1].code !==
      CANDIDATE_KEYS_EXPECTED_KEY_IDS_KEYID_MISMATCH_CODE ||
    fallbackMismatch[1].reason !==
      `keyid mismatch: expected "${CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_WRONG_KID}", got "${CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID}"` ||
    fallbackMismatch[1].keyId !==
      CANDIDATE_KEYS_EXPECTED_KEY_IDS_GATEWAY_KID
  )
    throw new Error(
      `benchmark self-check failed: candidateKeysExpectedKeyIds global-fallback mismatch gave ${JSON.stringify(fallbackMismatch)}`,
    );

  // Outside timing: combining `candidateKeysByLabel`
  // with `keys` on the same label throws the pinned
  // mutual-exclusion configuration error instead of
  // silently picking one key source.
  let exclusionError: unknown;
  try {
    verifyAllLabels(dualNew, {
      keys: { merchant: merchantNewPublic },
      candidateKeysByLabel: {
        merchant: [merchantOldPublic, merchantNewPublic],
      },
      now: CANDIDATE_KEYS_EXPECTED_KEY_IDS_CREATED,
    });
  } catch (e) {
    exclusionError = e;
  }
  if (
    !(exclusionError instanceof Error) ||
    exclusionError.message !==
      "verifyAllLabels: `candidateKeysByLabel`/`candidateKeys` is mutually exclusive with `keys`/`key` and `keyResolver`/`keyResolvers` — pass one or the other"
  )
    throw new Error(
      `benchmark self-check failed: candidateKeysExpectedKeyIds + keys did not throw the pinned error, got ${exclusionError instanceof Error ? JSON.stringify(exclusionError.message) : String(exclusionError)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

const REQUIRE_TAG_BY_LABEL_GATEWAY_KID =
  "bench-require-tag-by-label-gateway-1";
const REQUIRE_TAG_BY_LABEL_VALUE = "bench-require-tag-by-label-1";
const REQUIRE_TAG_BY_LABEL_OTHER_VALUE = "bench-require-tag-by-label-other";
const REQUIRE_TAG_BY_LABEL_CODE = "MISSING_TAG";
const REQUIRE_TAG_BY_LABEL_REASON =
  "signature carries no `tag` but requireTag is set";

/**
 * `verifyAllLabels` with `requireTagByLabel` steady
 * state: the per-label tag-presence form a multi-party
 * receiver uses when only one signer must bind its
 * signature to an application protocol (the merchant
 * signature must carry a tag; the gateway signature
 * historically carries none) — every measured call
 * runs the per-label map resolution and the
 * post-cryptographic presence check for the mapped
 * label, which the plain `verifyAllLabels` row above
 * never pays, because it passes no requirement. One
 * measured op verifies two dual-label fixtures: the
 * tag-carrying dual (both labels ok, merchant tag
 * returned, gateway without a tag still ok because
 * it falls back to the unset global) and the
 * tag-less-merchant dual (merchant exactly
 * `MISSING_TAG` with the pinned reason while the
 * unmapped gateway label still verifies, proving
 * the gateway falls back to the unset global rather
 * than inheriting the merchant's map entry). Outside
 * timing, the opt-in halves are pinned once: the same
 * tag-less dual verifies with no option passed, an
 * explicit `merchant: false` map entry likewise lets
 * the tag-less merchant label through, and a
 * differently-tagged merchant fixture still verifies
 * (requireTag checks presence, never value). Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllRequireTagByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantWithTagSigned = signRequest(fixture, {
    keyId: REQUIRE_TAG_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
    tag: REQUIRE_TAG_BY_LABEL_VALUE,
  });
  const dualWithTag = addSignature(merchantWithTagSigned, {
    keyId: REQUIRE_TAG_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
  });
  const merchantWithoutTagSigned = signRequest(fixture, {
    keyId: REQUIRE_TAG_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
  });
  const dualWithoutTag = addSignature(merchantWithoutTagSigned, {
    keyId: REQUIRE_TAG_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REQUIRE_TAG_BY_LABEL_CREATED,
    requireTagByLabel: { merchant: true },
  };
  const assertDual = (where: string): void => {
    const accepted = verifyAllLabels(dualWithTag, verifyOpts);
    if (
      accepted.length !== 2 ||
      accepted[0].label !== "merchant" ||
      !accepted[0].ok ||
      accepted[0].tag !== REQUIRE_TAG_BY_LABEL_VALUE ||
      accepted[1].label !== "gateway" ||
      !accepted[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireTagByLabel (${where}, tag-carrying dual) gave ${JSON.stringify(accepted)}`,
      );
    const rejected = verifyAllLabels(dualWithoutTag, verifyOpts);
    if (
      rejected.length !== 2 ||
      rejected[0].label !== "merchant" ||
      rejected[0].ok ||
      rejected[0].code !== REQUIRE_TAG_BY_LABEL_CODE ||
      rejected[0].reason !== REQUIRE_TAG_BY_LABEL_REASON ||
      rejected[1].label !== "gateway" ||
      !rejected[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireTagByLabel (${where}, tag-less-merchant dual) gave ${JSON.stringify(rejected)}`,
      );
  };

  // Outside timing: both fixtures self-check under the
  // per-label requirement before any timing starts.
  assertDual("outside timing");

  // Outside timing: with no option the same tag-less
  // dual verifies — the requirement is opt-in and the
  // default behaviour is unchanged.
  const defaulted = verifyAllLabels(dualWithoutTag, {
    keys,
    now: REQUIRE_TAG_BY_LABEL_CREATED,
  });
  if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: tag-less default gave ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: an explicit `merchant: false` map
  // entry likewise lets the tag-less merchant label
  // through — the map entry, not the label name, drives
  // the check.
  const optedOut = verifyAllLabels(dualWithoutTag, {
    keys,
    now: REQUIRE_TAG_BY_LABEL_CREATED,
    requireTagByLabel: { merchant: false },
  });
  if (optedOut.length !== 2 || optedOut.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: tag-less merchant:false gave ${JSON.stringify(optedOut)}`,
    );

  // Outside timing: requireTag checks presence, never
  // value — a differently-tagged merchant fixture still
  // verifies and echoes its own tag.
  const merchantOtherTagSigned = signRequest(fixture, {
    keyId: REQUIRE_TAG_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
    tag: REQUIRE_TAG_BY_LABEL_OTHER_VALUE,
  });
  const dualOtherTag = addSignature(merchantOtherTagSigned, {
    keyId: REQUIRE_TAG_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRE_TAG_BY_LABEL_CREATED,
  });
  const otherTagged = verifyAllLabels(dualOtherTag, verifyOpts);
  if (
    otherTagged.length !== 2 ||
    otherTagged[0].label !== "merchant" ||
    !otherTagged[0].ok ||
    otherTagged[0].tag !== REQUIRE_TAG_BY_LABEL_OTHER_VALUE ||
    otherTagged[1].label !== "gateway" ||
    !otherTagged[1].ok
  )
    throw new Error(
      `benchmark self-check failed: differently-tagged dual gave ${JSON.stringify(otherTagged)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` expectedTags
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), two dual-label fixtures signed outside
 * timing with `created` pinned under two pinned keyids
 * (merchant / gateway, the canonical multi-party labels),
 * and the verifier's injected `now` at the `created`
 * instant. The merchant label is pinned to one
 * application protocol and the gateway label to another
 * in `expectedTags`, so each label's tag is checked
 * against its own expectation.
 */
const EXPECTED_TAGS_CREATED = 1_700_000_000;
const EXPECTED_TAGS_MERCHANT_KID = "bench-expected-tags-merchant-1";
const EXPECTED_TAGS_GATEWAY_KID = "bench-expected-tags-gateway-1";
const EXPECTED_TAGS_MERCHANT_VALUE = "bench-expected-tags-payment-v1";
const EXPECTED_TAGS_GATEWAY_VALUE = "bench-expected-tags-settlement-v1";
const EXPECTED_TAGS_GATEWAY_OTHER_VALUE = "bench-expected-tags-admin-v1";
const EXPECTED_TAGS_MISMATCH_CODE = "TAG_MISMATCH";

/**
 * `verifyAllLabels` with `expectedTags` steady
 * state: the per-label tag-pinning form a multi-party
 * receiver uses when each signer must bind its
 * signature to its own application protocol (the
 * merchant signature belongs to the payment protocol,
 * the gateway signature to the settlement protocol) —
 * every measured call runs the per-label map
 * resolution and the post-cryptographic
 * `tag === expectedTag` comparison for each label,
 * which the plain `verifyAllLabels` row above never
 * pays, because it passes no expectation. One
 * measured op verifies two dual-label fixtures: the
 * fully pinned dual (both labels ok, each tag echoed
 * at its pinned value) and the
 * differently-tagged-gateway dual (merchant still ok
 * while the gateway label is exactly `TAG_MISMATCH`
 * with the pinned reason and its carried tag echoed,
 * proving the failure is the tag value rather than a
 * signature error and that one label's failure never
 * blocks the other label's verdict). Outside timing,
 * the fallback halves are pinned once: a label
 * missing from the map falls back to the global
 * `expectedTag` (the matching fallback passes and the
 * mismatching fallback fails exactly on the merchant
 * label while the mapped gateway label still
 * verifies), and the same dual verifies with no
 * option passed — the pinning is opt-in and the
 * default behaviour is unchanged. Zero network, zero
 * randomness in the measured assertions, no wall
 * clock (every verify instant is injected).
 */
function benchmarkVerifyAllExpectedTags(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: EXPECTED_TAGS_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_TAGS_CREATED,
    tag: EXPECTED_TAGS_MERCHANT_VALUE,
  });
  const dual = addSignature(merchantSigned, {
    keyId: EXPECTED_TAGS_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_TAGS_CREATED,
    tag: EXPECTED_TAGS_GATEWAY_VALUE,
  });
  const gatewayOtherTagSigned = signRequest(fixture, {
    keyId: EXPECTED_TAGS_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_TAGS_CREATED,
    tag: EXPECTED_TAGS_MERCHANT_VALUE,
  });
  const dualGatewayOtherTag = addSignature(gatewayOtherTagSigned, {
    keyId: EXPECTED_TAGS_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_TAGS_CREATED,
    tag: EXPECTED_TAGS_GATEWAY_OTHER_VALUE,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: EXPECTED_TAGS_CREATED,
    expectedTags: {
      merchant: EXPECTED_TAGS_MERCHANT_VALUE,
      gateway: EXPECTED_TAGS_GATEWAY_VALUE,
    },
  };
  const assertDual = (where: string): void => {
    const accepted = verifyAllLabels(dual, verifyOpts);
    if (
      accepted.length !== 2 ||
      accepted[0].label !== "merchant" ||
      !accepted[0].ok ||
      accepted[0].tag !== EXPECTED_TAGS_MERCHANT_VALUE ||
      accepted[1].label !== "gateway" ||
      !accepted[1].ok ||
      accepted[1].tag !== EXPECTED_TAGS_GATEWAY_VALUE
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedTags (${where}, fully pinned dual) gave ${JSON.stringify(accepted)}`,
      );
    const mismatched = verifyAllLabels(dualGatewayOtherTag, verifyOpts);
    if (
      mismatched.length !== 2 ||
      mismatched[0].label !== "merchant" ||
      !mismatched[0].ok ||
      mismatched[0].tag !== EXPECTED_TAGS_MERCHANT_VALUE ||
      mismatched[1].label !== "gateway" ||
      mismatched[1].ok ||
      mismatched[1].code !== EXPECTED_TAGS_MISMATCH_CODE ||
      mismatched[1].reason !==
        `tag mismatch: expected "${EXPECTED_TAGS_GATEWAY_VALUE}", got "${EXPECTED_TAGS_GATEWAY_OTHER_VALUE}"` ||
      mismatched[1].tag !== EXPECTED_TAGS_GATEWAY_OTHER_VALUE
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedTags (${where}, differently-tagged-gateway dual) gave ${JSON.stringify(mismatched)}`,
      );
  };

  // Outside timing: both fixtures self-check under the
  // per-label pinning before any timing starts.
  assertDual("outside timing");

  // Outside timing: a label missing from the map falls
  // back to the global `expectedTag` — the matching
  // fallback passes on both labels.
  const fallbackMatch = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_TAGS_CREATED,
    expectedTags: { gateway: EXPECTED_TAGS_GATEWAY_VALUE },
    expectedTag: EXPECTED_TAGS_MERCHANT_VALUE,
  });
  if (
    fallbackMatch.length !== 2 ||
    fallbackMatch.some((r) => !r.ok) ||
    fallbackMatch[0].tag !== EXPECTED_TAGS_MERCHANT_VALUE ||
    fallbackMatch[1].tag !== EXPECTED_TAGS_GATEWAY_VALUE
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (match) gave ${JSON.stringify(fallbackMatch)}`,
    );

  // Outside timing: the same fallback with a global
  // expectation the merchant tag does not meet fails
  // exactly on the merchant label while the mapped
  // gateway label still verifies.
  const fallbackMismatch = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_TAGS_CREATED,
    expectedTags: { gateway: EXPECTED_TAGS_GATEWAY_VALUE },
    expectedTag: EXPECTED_TAGS_GATEWAY_OTHER_VALUE,
  });
  if (
    fallbackMismatch.length !== 2 ||
    fallbackMismatch[0].label !== "merchant" ||
    fallbackMismatch[0].ok ||
    fallbackMismatch[0].code !== EXPECTED_TAGS_MISMATCH_CODE ||
    fallbackMismatch[1].label !== "gateway" ||
    !fallbackMismatch[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (mismatch) gave ${JSON.stringify(fallbackMismatch)}`,
    );

  // Outside timing: with no option the same dual
  // verifies — the pinning is opt-in and the default
  // behaviour is unchanged.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: EXPECTED_TAGS_CREATED,
  });
  if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: pinned dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels`
 * maxSignatureAgeSecByLabel benchmark: two ed25519 key
 * pairs (generated once, outside timing), one dual-label
 * fixture signed outside timing with `created` pinned
 * 120s before the verifier's injected `now` under two
 * pinned keyids (merchant / gateway, the canonical
 * multi-party labels), and per-label freshness windows
 * (merchant 60s, gateway 3600s) in
 * `maxSignatureAgeSecByLabel`, so the same-age
 * signatures split: the merchant signature is stale
 * under its own window while the gateway signature is
 * fresh under its own.
 */
const MAX_AGE_BY_LABEL_CREATED = 1_700_000_000;
const MAX_AGE_BY_LABEL_NOW = MAX_AGE_BY_LABEL_CREATED + 120;
const MAX_AGE_BY_LABEL_MERCHANT_KID = "bench-max-age-by-label-merchant-1";
const MAX_AGE_BY_LABEL_GATEWAY_KID = "bench-max-age-by-label-gateway-1";
const MAX_AGE_BY_LABEL_MERCHANT_WINDOW = 60;
const MAX_AGE_BY_LABEL_GATEWAY_WINDOW = 3600;
const MAX_AGE_BY_LABEL_MISMATCH_CODE = "SIGNATURE_TOO_OLD";

/**
 * `verifyAllLabels` with `maxSignatureAgeSecByLabel`
 * steady state: the per-label freshness-window form a
 * multi-party receiver uses when each signer must bound
 * its own signature differently (the merchant signature
 * is only trusted for a minute, the gateway signature
 * for an hour) — every measured call runs the
 * per-label map resolution and the post-cryptographic
 * age comparison for each label, which the plain
 * `verifyAllLabels` row above never pays, because it
 * passes no window. One measured op verifies the split
 * dual: the merchant label is exactly
 * `SIGNATURE_TOO_OLD` with the pinned reason and the
 * gateway label still verifies, proving one label's
 * staleness never blocks the other label's verdict.
 * Outside timing, the fallback halves are pinned once:
 * a label missing from the map falls back to the global
 * `maxSignatureAgeSec` (the matching fallback passes on
 * both labels and the mismatching fallback fails
 * exactly on the unmapped gateway label while the
 * mapped merchant label still verifies), and the same
 * dual verifies with no option passed — the window is
 * opt-in and the default behaviour is unchanged. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllMaxSignatureAgeSecByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: MAX_AGE_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: MAX_AGE_BY_LABEL_CREATED,
  });
  const dual = addSignature(merchantSigned, {
    keyId: MAX_AGE_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: MAX_AGE_BY_LABEL_CREATED,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: MAX_AGE_BY_LABEL_NOW,
    maxSignatureAgeSecByLabel: {
      merchant: MAX_AGE_BY_LABEL_MERCHANT_WINDOW,
      gateway: MAX_AGE_BY_LABEL_GATEWAY_WINDOW,
    },
  };
  const assertDual = (where: string): void => {
    const split = verifyAllLabels(dual, verifyOpts);
    if (
      split.length !== 2 ||
      split[0].label !== "merchant" ||
      split[0].ok ||
      split[0].code !== MAX_AGE_BY_LABEL_MISMATCH_CODE ||
      split[0].reason !==
        `signature is too old: created 120s ago, older than maxSignatureAgeSec=${MAX_AGE_BY_LABEL_MERCHANT_WINDOW}` ||
      split[1].label !== "gateway" ||
      !split[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with maxSignatureAgeSecByLabel (${where}, split dual) gave ${JSON.stringify(split)}`,
      );
  };

  // Outside timing: the split dual self-checks under the
  // per-label windows before any timing starts.
  assertDual("outside timing");

  // Outside timing: a label missing from the map falls
  // back to the global `maxSignatureAgeSec` — the
  // matching fallback passes on both labels.
  const fallbackMatch = verifyAllLabels(dual, {
    keys,
    now: MAX_AGE_BY_LABEL_NOW,
    maxSignatureAgeSecByLabel: {
      merchant: MAX_AGE_BY_LABEL_GATEWAY_WINDOW,
    },
    maxSignatureAgeSec: MAX_AGE_BY_LABEL_GATEWAY_WINDOW,
  });
  if (
    fallbackMatch.length !== 2 ||
    fallbackMatch.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (match) gave ${JSON.stringify(fallbackMatch)}`,
    );

  // Outside timing: the same fallback with a global
  // window the gateway age does not meet fails exactly
  // on the unmapped gateway label while the mapped
  // merchant label still verifies.
  const fallbackMismatch = verifyAllLabels(dual, {
    keys,
    now: MAX_AGE_BY_LABEL_NOW,
    maxSignatureAgeSecByLabel: {
      merchant: MAX_AGE_BY_LABEL_GATEWAY_WINDOW,
    },
    maxSignatureAgeSec: MAX_AGE_BY_LABEL_MERCHANT_WINDOW,
  });
  if (
    fallbackMismatch.length !== 2 ||
    fallbackMismatch[0].label !== "merchant" ||
    !fallbackMismatch[0].ok ||
    fallbackMismatch[1].label !== "gateway" ||
    fallbackMismatch[1].ok ||
    fallbackMismatch[1].code !== MAX_AGE_BY_LABEL_MISMATCH_CODE ||
    fallbackMismatch[1].reason !==
      `signature is too old: created 120s ago, older than maxSignatureAgeSec=${MAX_AGE_BY_LABEL_MERCHANT_WINDOW}`
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (mismatch) gave ${JSON.stringify(fallbackMismatch)}`,
    );

  // Outside timing: with no option the same dual
  // verifies — the window is opt-in and the default
  // behaviour is unchanged.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: MAX_AGE_BY_LABEL_NOW,
  });
  if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: split dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels`
 * clockSkewToleranceSecByLabel benchmark: two ed25519 key
 * pairs (generated once, outside timing), one dual-label
 * fixture signed outside timing with `created` pinned
 * 120s ahead of the verifier's injected `now` under two
 * pinned keyids (merchant / gateway, the canonical
 * multi-party labels), and per-label clock-skew
 * tolerances (merchant 5s, gateway 300s) in
 * `clockSkewToleranceSecByLabel`, so the same-ahead
 * signatures split: the merchant signature is too far
 * in the future under its own tolerance while the
 * gateway signature is within its own.
 */
const CLOCK_SKEW_BY_LABEL_NOW = 1_700_000_000;
const CLOCK_SKEW_BY_LABEL_CREATED = CLOCK_SKEW_BY_LABEL_NOW + 120;
const CLOCK_SKEW_BY_LABEL_MERCHANT_KID =
  "bench-clock-skew-by-label-merchant-1";
const CLOCK_SKEW_BY_LABEL_GATEWAY_KID =
  "bench-clock-skew-by-label-gateway-1";
const CLOCK_SKEW_BY_LABEL_MERCHANT_TOLERANCE = 5;
const CLOCK_SKEW_BY_LABEL_GATEWAY_TOLERANCE = 300;
const CLOCK_SKEW_BY_LABEL_MISMATCH_CODE = "CREATED_IN_FUTURE";
const CLOCK_SKEW_BY_LABEL_MISMATCH_REASON =
  "signature created in the future (clock skew)";

/**
 * `verifyAllLabels` with `clockSkewToleranceSecByLabel`
 * steady state: the per-label clock-skew form a
 * multi-party receiver uses when each signer clock may
 * run ahead by a different amount (the merchant clock
 * is trusted to stay within seconds, the gateway clock
 * may drift minutes) — every measured call runs the
 * per-label map resolution and the post-cryptographic
 * future-created comparison for each label, which the
 * plain `verifyAllLabels` row above never pays, because
 * it passes no tolerance map. One measured op verifies
 * the split dual: the merchant label is exactly
 * `CREATED_IN_FUTURE` with the pinned reason and the
 * gateway label still verifies, proving one label's
 * clock discipline never blocks the other label's
 * verdict. Outside timing, the fallback halves are
 * pinned once: a label missing from the map falls back
 * to the global `clockSkewToleranceSec` (the
 * merchant-only map under a wide global passes the
 * unmapped gateway while failing the mapped merchant,
 * and the gateway-only map under a narrow global fails
 * the unmapped merchant while passing the mapped
 * gateway), and the same dual under no option fails
 * on both labels — the 60s default is narrower than
 * the 120s skew, so the tolerance map is opt-in in
 * effect even though the default itself is non-zero.
 * Zero network, zero randomness in the measured
 * assertions, no wall clock (every verify instant is
 * injected).
 */
function benchmarkVerifyAllClockSkewToleranceSecByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: CLOCK_SKEW_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: CLOCK_SKEW_BY_LABEL_CREATED,
  });
  const dual = addSignature(merchantSigned, {
    keyId: CLOCK_SKEW_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: CLOCK_SKEW_BY_LABEL_CREATED,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: CLOCK_SKEW_BY_LABEL_NOW,
    clockSkewToleranceSecByLabel: {
      merchant: CLOCK_SKEW_BY_LABEL_MERCHANT_TOLERANCE,
      gateway: CLOCK_SKEW_BY_LABEL_GATEWAY_TOLERANCE,
    },
  };
  const assertDual = (where: string): void => {
    const split = verifyAllLabels(dual, verifyOpts);
    if (
      split.length !== 2 ||
      split[0].label !== "merchant" ||
      split[0].ok ||
      split[0].code !== CLOCK_SKEW_BY_LABEL_MISMATCH_CODE ||
      split[0].reason !== CLOCK_SKEW_BY_LABEL_MISMATCH_REASON ||
      split[1].label !== "gateway" ||
      !split[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with clockSkewToleranceSecByLabel (${where}, split dual) gave ${JSON.stringify(split)}`,
      );
  };

  // Outside timing: the split dual self-checks under the
  // per-label tolerances before any timing starts.
  assertDual("outside timing");

  // Outside timing: a label missing from the map falls
  // back to the global `clockSkewToleranceSec` — the
  // merchant-only map under a wide global fails exactly
  // on the mapped merchant while the unmapped gateway
  // passes on the global tolerance.
  const fallbackMerchantOnly = verifyAllLabels(dual, {
    keys,
    now: CLOCK_SKEW_BY_LABEL_NOW,
    clockSkewToleranceSecByLabel: {
      merchant: CLOCK_SKEW_BY_LABEL_MERCHANT_TOLERANCE,
    },
    clockSkewToleranceSec: CLOCK_SKEW_BY_LABEL_GATEWAY_TOLERANCE,
  });
  if (
    fallbackMerchantOnly.length !== 2 ||
    fallbackMerchantOnly[0].label !== "merchant" ||
    fallbackMerchantOnly[0].ok ||
    fallbackMerchantOnly[0].code !==
      CLOCK_SKEW_BY_LABEL_MISMATCH_CODE ||
    fallbackMerchantOnly[0].reason !==
      CLOCK_SKEW_BY_LABEL_MISMATCH_REASON ||
    fallbackMerchantOnly[1].label !== "gateway" ||
    !fallbackMerchantOnly[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (merchant-only map) gave ${JSON.stringify(fallbackMerchantOnly)}`,
    );

  // Outside timing: the same fallback in the other
  // direction — the gateway-only map under a narrow
  // global fails exactly on the unmapped merchant while
  // the mapped gateway passes on its own tolerance.
  const fallbackGatewayOnly = verifyAllLabels(dual, {
    keys,
    now: CLOCK_SKEW_BY_LABEL_NOW,
    clockSkewToleranceSecByLabel: {
      gateway: CLOCK_SKEW_BY_LABEL_GATEWAY_TOLERANCE,
    },
    clockSkewToleranceSec: CLOCK_SKEW_BY_LABEL_MERCHANT_TOLERANCE,
  });
  if (
    fallbackGatewayOnly.length !== 2 ||
    fallbackGatewayOnly[0].label !== "merchant" ||
    fallbackGatewayOnly[0].ok ||
    fallbackGatewayOnly[0].code !==
      CLOCK_SKEW_BY_LABEL_MISMATCH_CODE ||
    fallbackGatewayOnly[0].reason !==
      CLOCK_SKEW_BY_LABEL_MISMATCH_REASON ||
    fallbackGatewayOnly[1].label !== "gateway" ||
    !fallbackGatewayOnly[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (gateway-only map) gave ${JSON.stringify(fallbackGatewayOnly)}`,
    );

  // Outside timing: with no option the same dual fails
  // on both labels — the 60s default tolerance covers
  // neither 120s-ahead signature.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: CLOCK_SKEW_BY_LABEL_NOW,
  });
  if (
    defaulted.length !== 2 ||
    defaulted.some((r) => r.ok) ||
    defaulted.some((r) => r.code !== CLOCK_SKEW_BY_LABEL_MISMATCH_CODE)
  )
    throw new Error(
      `benchmark self-check failed: split dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels`
 * expiredToleranceSecByLabel benchmark: two ed25519 key
 * pairs (generated once, outside timing), one dual-label
 * fixture signed outside timing with `created` pinned
 * 3600s before the verifier's injected `now` and
 * `expires` pinned 60s before it under two pinned
 * keyids (merchant / gateway, the canonical multi-party
 * labels), and per-label expiry-grace tolerances
 * (merchant 0s, gateway 120s) in
 * `expiredToleranceSecByLabel`, so the same-expired
 * signatures split: the merchant signature is already
 * past `expires` under its own tolerance while the
 * gateway signature is still within its own grace.
 */
const EXPIRED_TOLERANCE_BY_LABEL_NOW = 1_700_000_000;
const EXPIRED_TOLERANCE_BY_LABEL_CREATED =
  EXPIRED_TOLERANCE_BY_LABEL_NOW - 3600;
const EXPIRED_TOLERANCE_BY_LABEL_EXPIRES =
  EXPIRED_TOLERANCE_BY_LABEL_NOW - 60;
const EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_KID =
  "bench-expired-tolerance-by-label-merchant-1";
const EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_KID =
  "bench-expired-tolerance-by-label-gateway-1";
const EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_TOLERANCE = 0;
const EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_TOLERANCE = 120;
const EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_CODE = "EXPIRED";
const EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_REASON = "signature expired";

/**
 * `verifyAllLabels` with `expiredToleranceSecByLabel`
 * steady state: the per-label expiry-grace form a
 * multi-party receiver uses when each signer must be
 * granted a different grace window past `expires`
 * (the merchant grace is zero — an expired merchant
 * signature is dead at once — while the gateway grace
 * absorbs clock lag and retries) — every measured call
 * runs the per-label map resolution and the
 * post-cryptographic expiry comparison for each label,
 * which the plain `verifyAllLabels` row above never
 * pays, because it passes no tolerance map. One
 * measured op verifies the split dual: the merchant
 * label is exactly `EXPIRED` with the pinned reason
 * and the gateway label still verifies, proving one
 * label's expiry never blocks the other label's
 * verdict. Outside timing, the boundary and fallback
 * halves are pinned once: both labels at exactly 60s
 * tolerance pass (the expiry check is strict-greater,
 * so `now` equal to `expires + tolerance` is still
 * live); a label missing from the map falls back to
 * the global `expiredToleranceSec` (the merchant-only
 * map under a wide global passes the unmapped gateway
 * while failing the mapped merchant, and the
 * gateway-only map under a narrow global fails the
 * unmapped merchant while passing the mapped gateway);
 * and the same dual under no option fails on both
 * labels — the 0s default grace covers neither
 * 60s-expired signature. Zero network, zero randomness
 * in the measured assertions, no wall clock (every
 * verify instant is injected).
 */
function benchmarkVerifyAllExpiredToleranceSecByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPIRED_TOLERANCE_BY_LABEL_CREATED,
    expires: EXPIRED_TOLERANCE_BY_LABEL_EXPIRES,
  });
  const dual = addSignature(merchantSigned, {
    keyId: EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPIRED_TOLERANCE_BY_LABEL_CREATED,
    expires: EXPIRED_TOLERANCE_BY_LABEL_EXPIRES,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: EXPIRED_TOLERANCE_BY_LABEL_NOW,
    expiredToleranceSecByLabel: {
      merchant: EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_TOLERANCE,
      gateway: EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_TOLERANCE,
    },
  };
  const assertDual = (where: string): void => {
    const split = verifyAllLabels(dual, verifyOpts);
    if (
      split.length !== 2 ||
      split[0].label !== "merchant" ||
      split[0].ok ||
      split[0].code !== EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_CODE ||
      split[0].reason !== EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_REASON ||
      split[1].label !== "gateway" ||
      !split[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expiredToleranceSecByLabel (${where}, split dual) gave ${JSON.stringify(split)}`,
      );
  };

  // Outside timing: the split dual self-checks under the
  // per-label tolerances before any timing starts.
  assertDual("outside timing");

  // Outside timing: expiry exactly at the tolerance
  // still passes — the check is strict-greater, so
  // `now` equal to `expires + tolerance` is live.
  const boundary = verifyAllLabels(dual, {
    keys,
    now: EXPIRED_TOLERANCE_BY_LABEL_NOW,
    expiredToleranceSecByLabel: { merchant: 60, gateway: 60 },
  });
  if (
    boundary.length !== 2 ||
    boundary.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: exact-tolerance boundary gave ${JSON.stringify(boundary)}`,
    );

  // Outside timing: a label missing from the map falls
  // back to the global `expiredToleranceSec` — the
  // merchant-only map under a wide global fails exactly
  // on the mapped merchant while the unmapped gateway
  // passes on the global tolerance.
  const fallbackMerchantOnly = verifyAllLabels(dual, {
    keys,
    now: EXPIRED_TOLERANCE_BY_LABEL_NOW,
    expiredToleranceSecByLabel: {
      merchant: EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_TOLERANCE,
    },
    expiredToleranceSec: EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_TOLERANCE,
  });
  if (
    fallbackMerchantOnly.length !== 2 ||
    fallbackMerchantOnly[0].label !== "merchant" ||
    fallbackMerchantOnly[0].ok ||
    fallbackMerchantOnly[0].code !==
      EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_CODE ||
    fallbackMerchantOnly[0].reason !==
      EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_REASON ||
    fallbackMerchantOnly[1].label !== "gateway" ||
    !fallbackMerchantOnly[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (merchant-only map) gave ${JSON.stringify(fallbackMerchantOnly)}`,
    );

  // Outside timing: the same fallback in the other
  // direction — the gateway-only map under a narrow
  // global fails exactly on the unmapped merchant while
  // the mapped gateway passes on its own tolerance.
  const fallbackGatewayOnly = verifyAllLabels(dual, {
    keys,
    now: EXPIRED_TOLERANCE_BY_LABEL_NOW,
    expiredToleranceSecByLabel: {
      gateway: EXPIRED_TOLERANCE_BY_LABEL_GATEWAY_TOLERANCE,
    },
    expiredToleranceSec: EXPIRED_TOLERANCE_BY_LABEL_MERCHANT_TOLERANCE,
  });
  if (
    fallbackGatewayOnly.length !== 2 ||
    fallbackGatewayOnly[0].label !== "merchant" ||
    fallbackGatewayOnly[0].ok ||
    fallbackGatewayOnly[0].code !==
      EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_CODE ||
    fallbackGatewayOnly[0].reason !==
      EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_REASON ||
    fallbackGatewayOnly[1].label !== "gateway" ||
    !fallbackGatewayOnly[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (gateway-only map) gave ${JSON.stringify(fallbackGatewayOnly)}`,
    );

  // Outside timing: with no option the same dual fails
  // on both labels — the 0s default grace covers
  // neither 60s-expired signature.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: EXPIRED_TOLERANCE_BY_LABEL_NOW,
  });
  if (
    defaulted.length !== 2 ||
    defaulted.some((r) => r.ok) ||
    defaulted.some((r) => r.code !== EXPIRED_TOLERANCE_BY_LABEL_MISMATCH_CODE)
  )
    throw new Error(
      `benchmark self-check failed: split dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels`
 * requiredComponentsByLabel benchmark: two ed25519 key
 * pairs (generated once, outside timing), one request
 * with a query string (`?ref=abc`, so `@query` resolves
 * to a non-empty value), and a per-label component
 * list (merchant must cover `content-digest`, gateway
 * must cover `@query`) in
 * `requiredComponentsByLabel`, so the same dual-label
 * fixture splits: the merchant signature covering only
 * `@method` and `@path` fails its own list while the
 * gateway signature covering `@method`, `@path` and
 * `@query` still verifies. The request and both
 * signatures are built outside timing with `created`
 * pinned, and every verify instant is injected, so the
 * measured op is pure per-label coverage policy plus
 * verification — no wall clock, no network.
 */
const REQUIRED_COMPONENTS_BY_LABEL_CREATED = 1_700_000_000;
const REQUIRED_COMPONENTS_BY_LABEL_NOW = 1_700_000_000;
const REQUIRED_COMPONENTS_BY_LABEL_REQUEST = {
  ...fixture,
  url: "https://api.example.com/v1/payments?ref=abc",
};
const REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_KID =
  "bench-required-components-by-label-merchant-1";
const REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_KID =
  "bench-required-components-by-label-gateway-1";
const REQUIRED_COMPONENTS_BY_LABEL_MAP = {
  merchant: ["content-digest"],
  gateway: ["@query"],
};
const REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE =
  "MISSING_REQUIRED_COMPONENT";
const REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_REASON =
  'signature does not cover required component: "content-digest"';
const REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_REASON =
  'signature does not cover required component: "@query"';

/**
 * `verifyAllLabels` with `requiredComponentsByLabel`
 * steady state: the per-label component-coverage form
 * a multi-party receiver uses when each signer must
 * bind a different part of the request (the merchant
 * must bind the body digest, the gateway must bind
 * the query string) — every measured call runs the
 * per-label map resolution and the pre-cryptographic
 * coverage check for each label, which the plain
 * `verifyRequest requiredComponents` row never pays,
 * because it checks one signature against one global
 * list. One measured op verifies the split dual: the
 * merchant label is exactly
 * `MISSING_REQUIRED_COMPONENT` with the pinned reason
 * and the gateway label still verifies, proving one
 * label's missing coverage never blocks the other
 * label's verdict. Outside timing, the reverse split
 * (merchant covering the digest, gateway missing
 * `@query`), the replace-not-union half (a mapped
 * list replaces the global list, so the merchant
 * mapped to `["@method"]` passes under a global
 * `content-digest` requirement while the unmapped
 * gateway falls back to that global list and fails),
 * the empty-list half (a mapped `[]` disables the
 * check for that label even under the same global
 * list, while the unmapped gateway still fails on
 * it), the gateway-only-map fallback in the other
 * direction, and the no-option default (both labels
 * verify, since the coverage check is opt-in) are
 * pinned once. Zero network, zero randomness in the
 * measured assertions, no wall clock (every verify
 * instant is injected).
 */
function benchmarkVerifyAllRequiredComponentsByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(
    REQUIRED_COMPONENTS_BY_LABEL_REQUEST,
    {
      keyId: REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      key: merchantPrivate,
      label: "merchant",
      created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
      coveredComponents: ["@method", "@path"],
    },
  );
  const dual = addSignature(merchantSigned, {
    keyId: REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
    coveredComponents: ["@method", "@path", "@query"],
  });
  const merchantCoveredSigned = signRequest(
    REQUIRED_COMPONENTS_BY_LABEL_REQUEST,
    {
      keyId: REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      key: merchantPrivate,
      label: "merchant",
      created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
      coveredComponents: ["@method", "@path", "content-digest"],
    },
  );
  const reverseDual = addSignature(merchantCoveredSigned, {
    keyId: REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
    coveredComponents: ["@method", "@path"],
  });
  const neitherCoveredSigned = signRequest(
    REQUIRED_COMPONENTS_BY_LABEL_REQUEST,
    {
      keyId: REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      key: merchantPrivate,
      label: "merchant",
      created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
      coveredComponents: ["@method", "@path"],
    },
  );
  const neitherCoveredDual = addSignature(neitherCoveredSigned, {
    keyId: REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REQUIRED_COMPONENTS_BY_LABEL_CREATED,
    coveredComponents: ["@method", "@path"],
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REQUIRED_COMPONENTS_BY_LABEL_NOW,
    requiredComponentsByLabel: REQUIRED_COMPONENTS_BY_LABEL_MAP,
  };
  const assertDual = (where: string): void => {
    const split = verifyAllLabels(dual, verifyOpts);
    if (
      split.length !== 2 ||
      split[0].label !== "merchant" ||
      split[0].ok ||
      split[0].code !==
        REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE ||
      split[0].reason !==
        REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_REASON ||
      split[1].label !== "gateway" ||
      !split[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requiredComponentsByLabel (${where}, split dual) gave ${JSON.stringify(split)}`,
      );
  };

  // Outside timing: the split dual self-checks under the
  // per-label lists before any timing starts.
  assertDual("outside timing");

  // Outside timing: the reverse split — the merchant
  // covering the digest passes while the gateway
  // missing `@query` fails exactly on its own list.
  const reversed = verifyAllLabels(reverseDual, verifyOpts);
  if (
    reversed.length !== 2 ||
    reversed[0].label !== "merchant" ||
    !reversed[0].ok ||
    reversed[1].label !== "gateway" ||
    reversed[1].ok ||
    reversed[1].code !==
      REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE ||
    reversed[1].reason !==
      REQUIRED_COMPONENTS_BY_LABEL_GATEWAY_REASON
  )
    throw new Error(
      `benchmark self-check failed: reverse split gave ${JSON.stringify(reversed)}`,
    );

  // Outside timing: a mapped list replaces the global
  // list rather than unioning with it — the merchant
  // mapped to `["@method"]` passes even though the
  // global list demands `content-digest`, which it
  // does not cover, while the unmapped gateway falls
  // back to the global list and fails on it.
  const replaced = verifyAllLabels(neitherCoveredDual, {
    keys,
    now: REQUIRED_COMPONENTS_BY_LABEL_NOW,
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { merchant: ["@method"] },
  });
  if (
    replaced.length !== 2 ||
    replaced[0].label !== "merchant" ||
    !replaced[0].ok ||
    replaced[1].label !== "gateway" ||
    replaced[1].ok ||
    replaced[1].code !==
      REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE ||
    replaced[1].reason !==
      REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_REASON
  )
    throw new Error(
      `benchmark self-check failed: mapped-list-replaces-global gave ${JSON.stringify(replaced)}`,
    );

  // Outside timing: a mapped `[]` disables the check
  // for that label outright — the merchant passes
  // under the same global `content-digest` requirement
  // while the unmapped gateway still falls back to it
  // and fails.
  const emptied = verifyAllLabels(neitherCoveredDual, {
    keys,
    now: REQUIRED_COMPONENTS_BY_LABEL_NOW,
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { merchant: [] },
  });
  if (
    emptied.length !== 2 ||
    emptied[0].label !== "merchant" ||
    !emptied[0].ok ||
    emptied[1].label !== "gateway" ||
    emptied[1].ok ||
    emptied[1].code !==
      REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE ||
    emptied[1].reason !==
      REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_REASON
  )
    throw new Error(
      `benchmark self-check failed: mapped-empty-list gave ${JSON.stringify(emptied)}`,
    );

  // Outside timing: the same fallback in the other
  // direction — the gateway-only map under a global
  // `content-digest` requirement passes the mapped
  // gateway (it covers `@query`) while the unmapped
  // merchant falls back to the global list and fails
  // on the digest it does not cover.
  const fallbackGatewayOnly = verifyAllLabels(dual, {
    keys,
    now: REQUIRED_COMPONENTS_BY_LABEL_NOW,
    requiredComponents: ["content-digest"],
    requiredComponentsByLabel: { gateway: ["@query"] },
  });
  if (
    fallbackGatewayOnly.length !== 2 ||
    fallbackGatewayOnly[0].label !== "merchant" ||
    fallbackGatewayOnly[0].ok ||
    fallbackGatewayOnly[0].code !==
      REQUIRED_COMPONENTS_BY_LABEL_MISMATCH_CODE ||
    fallbackGatewayOnly[0].reason !==
      REQUIRED_COMPONENTS_BY_LABEL_MERCHANT_REASON ||
    fallbackGatewayOnly[1].label !== "gateway" ||
    !fallbackGatewayOnly[1].ok
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback (gateway-only map) gave ${JSON.stringify(fallbackGatewayOnly)}`,
    );

  // Outside timing: with no option the same split dual
  // verifies on both labels — the coverage check is
  // opt-in and the default behaviour is unchanged.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: REQUIRED_COMPONENTS_BY_LABEL_NOW,
  });
  if (
    defaulted.length !== 2 ||
    defaulted.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: split dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels`
 * algFallbackByLabel benchmark: a P-256 merchant key
 * pair and an HMAC gateway secret (generated once,
 * outside timing), one request, and a per-label
 * algorithm-fallback map (merchant `"infer"`,
 * gateway `false`) in `algFallbackByLabel`, so the
 * same dual-label fixture splits: the merchant
 * signature carries no `alg` parameter (a foreign
 * signer, same shape as `test/algFallbackByLabel.test.ts`)
 * and passes only because its label infers
 * `ecdsa-p256-sha256` from the P-256 key, while the
 * gateway signature (also no `alg`) fails under its
 * strict label because the legacy default means
 * `ed25519`, which the crypto layer rejects against
 * a secret key. Both signatures are built outside
 * timing with `created` pinned, and every verify
 * instant is injected, so the measured op is pure
 * per-label fallback resolution plus verification —
 * no wall clock, no network.
 */
const ALG_FALLBACK_BY_LABEL_CREATED = 1_700_000_000;
const ALG_FALLBACK_BY_LABEL_NOW = 1_700_000_000;
const ALG_FALLBACK_BY_LABEL_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
];
const ALG_FALLBACK_BY_LABEL_MERCHANT_KID =
  "bench-alg-fallback-by-label-merchant-1";
const ALG_FALLBACK_BY_LABEL_GATEWAY_KID =
  "bench-alg-fallback-by-label-gateway-1";
const ALG_FALLBACK_BY_LABEL_MAP: Record<string, "infer" | false> = {
  merchant: "infer",
  gateway: false,
};
const ALG_FALLBACK_BY_LABEL_GATEWAY_CODE = "VERIFICATION_ERROR";
const ALG_FALLBACK_BY_LABEL_MERCHANT_ALG = "ecdsa-p256-sha256";
const ALG_FALLBACK_BY_LABEL_GATEWAY_ALG = "hmac-sha256";
const ALG_FALLBACK_BY_LABEL_STRICT_MERCHANT_CODE = "SIGNATURE_MISMATCH";

/**
 * `verifyAllLabels` with `algFallbackByLabel` steady
 * state: the per-label algorithm-inference form a
 * multi-party receiver uses when each foreign signer
 * omits the optional `alg` parameter and only one of
 * them may be inferred (the merchant's P-256 key
 * implies its algorithm; the gateway's HMAC key must
 * stay strict so a missing `alg` never silently
 * resolves) — every measured call runs the per-label
 * map resolution and the key-shape inference for
 * each label, which the plain `verifyRequest
 * algFallback` row never pays, because it infers one
 * signature under one global strategy. One measured
 * op verifies the split dual: the merchant label
 * verifies with the inferred `ecdsa-p256-sha256`
 * algorithm while the gateway label is exactly
 * `VERIFICATION_ERROR`, proving one label's strict
 * rejection never blocks the other label's verdict.
 * Outside timing, the reversed split (merchant
 * strict, gateway inferred — the P-256 merchant is
 * exactly `SIGNATURE_MISMATCH` under the legacy
 * `ed25519` default while the gateway verifies as
 * `hmac-sha256`), the mapped-`false`-overrides-global
 * half (both labels mapped `false` under a global
 * `"infer"` still fail with exactly the strict
 * codes, since `??` only falls back on a missing
 * entry, never on `false`), the unmapped-label
 * global-fallback halves (a merchant-only strict
 * map under a global `"infer"` lets the unmapped
 * gateway infer, and a merchant-only infer map with
 * no global leaves the unmapped gateway on the
 * legacy default), and the no-option default (both
 * labels fail, since neither infers) are pinned once.
 * Zero network, zero randomness in the measured
 * assertions, no wall clock (every verify instant is
 * injected).
 */
function benchmarkVerifyAllAlgFallbackByLabel(): number {
  const { publicKey: merchantPublic, privateKey: merchantPrivate } =
    generateP256KeyPair();
  const gatewaySecret = secretKey(Buffer.alloc(32, 0x47));
  const requestWithDigest = {
    ...fixture,
    headers: {
      ...fixture.headers,
      "content-digest": contentDigest(fixture.body),
    },
  };
  const buildLabel = (
    keyId: string,
    label: string,
    key: KeyObject,
  ): SignedHttpRequest => {
    const params = {
      created: ALG_FALLBACK_BY_LABEL_CREATED,
      keyid: keyId,
    }; // no alg, ever — the foreign-signer shape
    const base = buildSignatureBase(
      ALG_FALLBACK_BY_LABEL_COVERED_COMPONENTS,
      requestWithDigest,
      params,
    );
    // A spec-conformant foreign P-256 signer emits the
    // raw r||s value RFC 9421 §3.3.4 defines
    // (node:crypto's ieee-p1363 encoding), never DER.
    const sig =
      key.type === "secret"
        ? createHmac("sha256", key).update(base, "utf8").digest()
        : createSign("sha256")
            .update(base, "utf8")
            .sign({ key, dsaEncoding: "ieee-p1363" });
    return {
      method: fixture.method,
      url: fixture.url,
      body: fixture.body,
      headers: {
        // The covered `content-digest` component must be
        // present on the wire, not just in the base.
        ...requestWithDigest.headers,
        "signature-input": signatureInputValue(
          label,
          ALG_FALLBACK_BY_LABEL_COVERED_COMPONENTS,
          params,
        ),
        signature: `${label}=:${sig.toString("base64")}:`,
      },
    };
  };
  const merchantSigned = buildLabel(
    ALG_FALLBACK_BY_LABEL_MERCHANT_KID,
    "merchant",
    merchantPrivate,
  );
  const gatewaySigned = buildLabel(
    ALG_FALLBACK_BY_LABEL_GATEWAY_KID,
    "gateway",
    gatewaySecret,
  );
  const dual = {
    ...merchantSigned,
    headers: {
      ...merchantSigned.headers,
      "signature-input": `${merchantSigned.headers["signature-input"]}, ${gatewaySigned.headers["signature-input"]}`,
      signature: `${merchantSigned.headers["signature"]}, ${gatewaySigned.headers["signature"]}`,
    },
  };
  const keys = { merchant: merchantPublic, gateway: gatewaySecret };
  const verifyOpts = {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
    algFallbackByLabel: ALG_FALLBACK_BY_LABEL_MAP,
  };
  const assertDual = (where: string): void => {
    const split = verifyAllLabels(dual, verifyOpts);
    if (
      split.length !== 2 ||
      split[0].label !== "merchant" ||
      !split[0].ok ||
      split[0].alg !== ALG_FALLBACK_BY_LABEL_MERCHANT_ALG ||
      split[1].label !== "gateway" ||
      split[1].ok ||
      split[1].code !== ALG_FALLBACK_BY_LABEL_GATEWAY_CODE
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with algFallbackByLabel (${where}, split dual) gave ${JSON.stringify(split)}`,
      );
  };

  // Outside timing: the split dual self-checks under
  // the per-label map before any timing starts.
  assertDual("outside timing");

  // Outside timing: the reversed split — the merchant
  // strict under the legacy default fails as a plain
  // mismatch (the crypto layer returns false for the
  // wrong key type) while the gateway infers
  // `hmac-sha256` and verifies.
  const reversed = verifyAllLabels(dual, {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
    algFallbackByLabel: { merchant: false, gateway: "infer" },
  });
  if (
    reversed.length !== 2 ||
    reversed[0].label !== "merchant" ||
    reversed[0].ok ||
    reversed[0].code !==
      ALG_FALLBACK_BY_LABEL_STRICT_MERCHANT_CODE ||
    reversed[1].label !== "gateway" ||
    !reversed[1].ok ||
    reversed[1].alg !== ALG_FALLBACK_BY_LABEL_GATEWAY_ALG
  )
    throw new Error(
      `benchmark self-check failed: reversed split gave ${JSON.stringify(reversed)}`,
    );

  // Outside timing: a mapped `false` overrides a
  // global `"infer"` — `??` falls back only on a
  // missing entry, never on `false` — so both labels
  // still fail with exactly the strict codes.
  const strict = verifyAllLabels(dual, {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
    algFallback: "infer",
    algFallbackByLabel: { merchant: false, gateway: false },
  });
  if (
    strict.length !== 2 ||
    strict[0].label !== "merchant" ||
    strict[0].ok ||
    strict[0].code !==
      ALG_FALLBACK_BY_LABEL_STRICT_MERCHANT_CODE ||
    strict[1].label !== "gateway" ||
    strict[1].ok ||
    strict[1].code !== ALG_FALLBACK_BY_LABEL_GATEWAY_CODE
  )
    throw new Error(
      `benchmark self-check failed: mapped-false-overrides-global gave ${JSON.stringify(strict)}`,
    );

  // Outside timing: an unmapped label falls back to
  // the global strategy — a merchant-only strict map
  // under a global `"infer"` lets the unmapped
  // gateway infer and verify.
  const gatewayFallback = verifyAllLabels(dual, {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
    algFallback: "infer",
    algFallbackByLabel: { merchant: false },
  });
  if (
    gatewayFallback.length !== 2 ||
    gatewayFallback[0].label !== "merchant" ||
    gatewayFallback[0].ok ||
    gatewayFallback[0].code !==
      ALG_FALLBACK_BY_LABEL_STRICT_MERCHANT_CODE ||
    gatewayFallback[1].label !== "gateway" ||
    !gatewayFallback[1].ok ||
    gatewayFallback[1].alg !== ALG_FALLBACK_BY_LABEL_GATEWAY_ALG
  )
    throw new Error(
      `benchmark self-check failed: unmapped-gateway global fallback gave ${JSON.stringify(gatewayFallback)}`,
    );

  // Outside timing: the same fallback in the other
  // direction — a merchant-only infer map with no
  // global leaves the unmapped gateway on the legacy
  // default, so it fails exactly as the strict label
  // does while the merchant verifies.
  const merchantFallback = verifyAllLabels(dual, {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
    algFallbackByLabel: { merchant: "infer" },
  });
  if (
    merchantFallback.length !== 2 ||
    merchantFallback[0].label !== "merchant" ||
    !merchantFallback[0].ok ||
    merchantFallback[0].alg !==
      ALG_FALLBACK_BY_LABEL_MERCHANT_ALG ||
    merchantFallback[1].label !== "gateway" ||
    merchantFallback[1].ok ||
    merchantFallback[1].code !== ALG_FALLBACK_BY_LABEL_GATEWAY_CODE
  )
    throw new Error(
      `benchmark self-check failed: unmapped-merchant global fallback gave ${JSON.stringify(merchantFallback)}`,
    );

  // Outside timing: with no option the same split
  // dual fails on both labels — neither infers under
  // the legacy default.
  const defaulted = verifyAllLabels(dual, {
    keys,
    now: ALG_FALLBACK_BY_LABEL_NOW,
  });
  if (
    defaulted.length !== 2 ||
    defaulted[0].label !== "merchant" ||
    defaulted[0].ok ||
    defaulted[0].code !==
      ALG_FALLBACK_BY_LABEL_STRICT_MERCHANT_CODE ||
    defaulted[1].label !== "gateway" ||
    defaulted[1].ok ||
    defaulted[1].code !== ALG_FALLBACK_BY_LABEL_GATEWAY_CODE
  )
    throw new Error(
      `benchmark self-check failed: split dual default gave ${JSON.stringify(defaulted)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

const REPLAY_CACHE_BY_LABEL_CREATED = 1_700_000_000;
const REPLAY_CACHE_BY_LABEL_MERCHANT_KID =
  "bench-replay-cache-by-label-merchant-1";
const REPLAY_CACHE_BY_LABEL_GATEWAY_KID =
  "bench-replay-cache-by-label-gateway-1";
const REPLAY_CACHE_BY_LABEL_NONCE = "bench-replay-cache-by-label-1";
const REPLAY_CACHE_BY_LABEL_CODE = "NONCE_REPLAY";
const REPLAY_CACHE_BY_LABEL_REASON =
  `nonce replay detected: "${REPLAY_CACHE_BY_LABEL_NONCE}" was already seen`;

/**
 * `verifyAllLabels` with `replayCacheByLabel` steady
 * state: the per-label replay-defense form a multi-party
 * receiver runs when each signer mints nonces in its own
 * namespace — the same bare nonce string in both labels
 * must pass on first presentation and replay-reject on
 * second presentation in each label's own store, which
 * the single shared `replayCache` row above never pays,
 * because it consults one store for every label. One
 * measured op verifies the dual twice against fresh
 * per-label caches: the first call records the nonce in
 * each store (both labels ok), the second call is
 * replay-rejected in both stores with exactly the pinned
 * `NONCE_REPLAY` code and reason — the cryptographic
 * check runs before the cache consultation, so the
 * second call still pays full verification per label
 * plus the cache lookup, exactly the path a receiver
 * runs to refuse a replayed multi-party request.
 * Outside timing, the shared-store contrast is pinned
 * once: the same dual under one global `replayCache`
 * passes the merchant label and replay-rejects the
 * gateway label on its very first call (the #643
 * contract — one bare-nonce namespace cannot serve two
 * signers); the unmapped-label fallback is pinned
 * once (a merchant-only map over a global cache passes
 * both labels first and replay-rejects both second,
 * the gateway via the global store); and the no-cache
 * default is pinned once (both labels verify twice,
 * replay defense is opt-in). Zero network, zero
 * randomness in the measured assertions, no wall clock
 * (every verify instant is injected; each cache's own
 * clock is that same pinned instant).
 */
function benchmarkVerifyAllReplayCacheByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantSigned = signRequest(fixture, {
    keyId: REPLAY_CACHE_BY_LABEL_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: REPLAY_CACHE_BY_LABEL_CREATED,
    nonce: REPLAY_CACHE_BY_LABEL_NONCE,
  });
  const dual = addSignature(merchantSigned, {
    keyId: REPLAY_CACHE_BY_LABEL_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: REPLAY_CACHE_BY_LABEL_CREATED,
    nonce: REPLAY_CACHE_BY_LABEL_NONCE,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REPLAY_CACHE_BY_LABEL_CREATED,
  };
  const assertPair = (where: string): void => {
    const merchantCache = new ReplayCache({
      now: () => REPLAY_CACHE_BY_LABEL_CREATED,
    });
    const gatewayCache = new ReplayCache({
      now: () => REPLAY_CACHE_BY_LABEL_CREATED,
    });
    const first = verifyAllLabels(dual, {
      ...verifyOpts,
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    });
    if (
      first.length !== 2 ||
      first[0].label !== "merchant" ||
      !first[0].ok ||
      first[1].label !== "gateway" ||
      !first[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with replayCacheByLabel (${where}, first presentation) gave ${JSON.stringify(first)}`,
      );
    const second = verifyAllLabels(dual, {
      ...verifyOpts,
      replayCacheByLabel: { merchant: merchantCache, gateway: gatewayCache },
    });
    if (
      second.length !== 2 ||
      second[0].label !== "merchant" ||
      second[0].ok ||
      second[0].code !== REPLAY_CACHE_BY_LABEL_CODE ||
      second[0].reason !== REPLAY_CACHE_BY_LABEL_REASON ||
      second[1].label !== "gateway" ||
      second[1].ok ||
      second[1].code !== REPLAY_CACHE_BY_LABEL_CODE ||
      second[1].reason !== REPLAY_CACHE_BY_LABEL_REASON
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with replayCacheByLabel (${where}, second presentation) gave ${JSON.stringify(second)}`,
      );
  };

  // Outside timing: the per-label pair self-checks
  // before any timing starts.
  assertPair("outside timing");

  // Outside timing: the shared-store contrast — one
  // global cache cannot serve two signers sharing a
  // bare nonce: the merchant passes, the gateway
  // replay-rejects on the very first call.
  const sharedCache = new ReplayCache({
    now: () => REPLAY_CACHE_BY_LABEL_CREATED,
  });
  const shared = verifyAllLabels(dual, {
    ...verifyOpts,
    replayCache: sharedCache,
  });
  if (
    shared.length !== 2 ||
    shared[0].label !== "merchant" ||
    !shared[0].ok ||
    shared[1].label !== "gateway" ||
    shared[1].ok ||
    shared[1].code !== REPLAY_CACHE_BY_LABEL_CODE ||
    shared[1].reason !== REPLAY_CACHE_BY_LABEL_REASON
  )
    throw new Error(
      `benchmark self-check failed: shared-cache contrast gave ${JSON.stringify(shared)}`,
    );

  // Outside timing: an unmapped label falls back to
  // the global cache — a merchant-only map over a
  // global store passes both labels first and
  // replay-rejects both second (the gateway via the
  // global store).
  const merchantOnlyCache = new ReplayCache({
    now: () => REPLAY_CACHE_BY_LABEL_CREATED,
  });
  const globalCache = new ReplayCache({
    now: () => REPLAY_CACHE_BY_LABEL_CREATED,
  });
  const fallbackFirst = verifyAllLabels(dual, {
    ...verifyOpts,
    replayCache: globalCache,
    replayCacheByLabel: { merchant: merchantOnlyCache },
  });
  const fallbackSecond = verifyAllLabels(dual, {
    ...verifyOpts,
    replayCache: globalCache,
    replayCacheByLabel: { merchant: merchantOnlyCache },
  });
  if (
    fallbackFirst.length !== 2 ||
    fallbackFirst.some((r) => !r.ok) ||
    fallbackSecond.length !== 2 ||
    fallbackSecond.some(
      (r) =>
        r.ok ||
        r.code !== REPLAY_CACHE_BY_LABEL_CODE ||
        r.reason !== REPLAY_CACHE_BY_LABEL_REASON,
    )
  )
    throw new Error(
      `benchmark self-check failed: unmapped-label global fallback gave ${JSON.stringify(fallbackFirst)} / ${JSON.stringify(fallbackSecond)}`,
    );

  // Outside timing: with no cache the same dual
  // verifies twice — replay defense is opt-in and the
  // default behaviour is unchanged.
  const defaultFirst = verifyAllLabels(dual, verifyOpts);
  const defaultSecond = verifyAllLabels(dual, verifyOpts);
  if (
    defaultFirst.length !== 2 ||
    defaultFirst.some((r) => !r.ok) ||
    defaultSecond.length !== 2 ||
    defaultSecond.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-cache default gave ${JSON.stringify(defaultFirst)} / ${JSON.stringify(defaultSecond)}`,
    );

  return measure(() => {
    assertPair("measured pass");
  }, ITERATIONS);
}

const EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED = 1_700_000_000;
const EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID =
  "bench-expected-keyids-require-tag-merchant-1";
const EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID =
  "bench-expected-keyids-require-tag-gateway-1";
const EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_WRONG =
  "bench-expected-keyids-require-tag-gateway-wrong";
const EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE =
  "bench-expected-keyids-require-tag-1";
const EXPECTED_KEY_IDS_REQUIRE_TAG_MISSING_CODE = "MISSING_TAG";
const EXPECTED_KEY_IDS_REQUIRE_TAG_MISSING_REASON =
  "signature carries no `tag` but requireTag is set";

/**
 * `verifyAllLabels` with `expectedKeyIds` plus the global
 * `requireTag` steady state: the combined keyid-pinning
 * and application-tag form a multi-party receiver uses
 * when every signer must both be the expected key and
 * bind its signature to the application protocol — the
 * merchant and gateway labels are each pinned to their
 * own keyid and the global tag requirement applies to
 * both labels (there is no per-label tag map here, so
 * the gateway cannot slip through untagged the way it
 * does under `requireTagByLabel: { merchant: true }`).
 * Every measured call runs both the per-label keyid
 * resolution and the post-cryptographic tag-presence
 * check for each label, which neither the plain
 * `expectedKeyIds` row (no tag requirement) nor the
 * `requireTagByLabel` row (gateway unmapped) ever
 * pays. One measured op verifies three dual-label
 * fixtures signed outside timing with `created`
 * pinned: the fully tagged dual (both labels ok, each
 * returned `keyId` equal to its pinned value and each
 * tag echoed); the merchant-untagged dual (merchant
 * exactly `MISSING_TAG` with the pinned reason and
 * its keyid still echoed — the failure is the missing
 * tag, not a keyid error — while the tagged gateway
 * label still verifies); and the wrong-gateway-keyid
 * dual (gateway exactly `KEYID_MISMATCH` with the
 * pinned reason while the merchant label still
 * verifies, proving the pin reads the carried keyid).
 * Outside timing, the opt-in halves are pinned once:
 * the merchant-untagged dual verifies with no option
 * passed, an explicit global `requireTag: false`
 * likewise lets it through, and the wrong-keyid dual
 * verifies when no keyid pins are configured. Zero
 * network, zero randomness in the measured assertions,
 * no wall clock (every verify instant is injected).
 */
function benchmarkVerifyAllExpectedKeyIdsRequireTag(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const merchantTaggedSigned = signRequest(fixture, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    tag: EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE,
  });
  const dualWithTag = addSignature(merchantTaggedSigned, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    tag: EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE,
  });
  const merchantUntaggedSigned = signRequest(fixture, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
  });
  const dualMerchantUntagged = addSignature(merchantUntaggedSigned, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    tag: EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE,
  });
  const merchantTaggedForWrongKid = signRequest(fixture, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID,
    alg: "ed25519",
    key: merchantPrivate,
    label: "merchant",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    tag: EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE,
  });
  const dualWrongGatewayKid = addSignature(merchantTaggedForWrongKid, {
    keyId: EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_WRONG,
    alg: "ed25519",
    key: gatewayPrivate,
    label: "gateway",
    created: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    tag: EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE,
  });
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    expectedKeyIds: {
      merchant: EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID,
      gateway: EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID,
    },
    requireTag: true,
  };
  const assertTriple = (where: string): void => {
    const accepted = verifyAllLabels(dualWithTag, verifyOpts);
    if (
      accepted.length !== 2 ||
      accepted[0].label !== "merchant" ||
      !accepted[0].ok ||
      accepted[0].keyId !==
        EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID ||
      accepted[0].tag !== EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE ||
      accepted[1].label !== "gateway" ||
      !accepted[1].ok ||
      accepted[1].keyId !== EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID ||
      accepted[1].tag !== EXPECTED_KEY_IDS_REQUIRE_TAG_VALUE
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedKeyIds + requireTag (${where}, tagged dual) gave ${JSON.stringify(accepted)}`,
      );
    const untagged = verifyAllLabels(dualMerchantUntagged, verifyOpts);
    if (
      untagged.length !== 2 ||
      untagged[0].label !== "merchant" ||
      untagged[0].ok ||
      untagged[0].code !== EXPECTED_KEY_IDS_REQUIRE_TAG_MISSING_CODE ||
      untagged[0].reason !== EXPECTED_KEY_IDS_REQUIRE_TAG_MISSING_REASON ||
      untagged[0].keyId !==
        EXPECTED_KEY_IDS_REQUIRE_TAG_MERCHANT_KID ||
      untagged[1].label !== "gateway" ||
      !untagged[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedKeyIds + requireTag (${where}, merchant-untagged dual) gave ${JSON.stringify(untagged)}`,
      );
    const mismatched = verifyAllLabels(dualWrongGatewayKid, verifyOpts);
    if (
      mismatched.length !== 2 ||
      mismatched[0].label !== "merchant" ||
      !mismatched[0].ok ||
      mismatched[1].label !== "gateway" ||
      mismatched[1].ok ||
      mismatched[1].code !== "KEYID_MISMATCH" ||
      mismatched[1].reason !==
        `keyid mismatch: expected "${EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_KID}", got "${EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_WRONG}"` ||
      mismatched[1].keyId !== EXPECTED_KEY_IDS_REQUIRE_TAG_GATEWAY_WRONG
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with expectedKeyIds + requireTag (${where}, wrong-gateway-keyid dual) gave ${JSON.stringify(mismatched)}`,
      );
  };

  // Outside timing: all three fixtures self-check under
  // the combined options before any timing starts.
  assertTriple("outside timing");

  // Outside timing: with no option the same
  // merchant-untagged dual verifies — the global tag
  // requirement is opt-in and the default behaviour is
  // unchanged.
  const defaulted = verifyAllLabels(dualMerchantUntagged, {
    keys,
    now: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
  });
  if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: merchant-untagged default gave ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: an explicit global `requireTag:
  // false` likewise lets the merchant-untagged dual
  // through — the flag, not the label name, drives the
  // check.
  const optedOut = verifyAllLabels(dualMerchantUntagged, {
    keys,
    now: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    requireTag: false,
  });
  if (optedOut.length !== 2 || optedOut.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: merchant-untagged requireTag:false gave ${JSON.stringify(optedOut)}`,
    );

  // Outside timing: with no keyid pins configured the
  // wrong-gateway-keyid dual verifies under the global
  // tag requirement (both labels carry a tag) — keyid
  // pinning is opt-in, and the tag check alone does not
  // reject a merely unexpected keyid.
  const unpinned = verifyAllLabels(dualWrongGatewayKid, {
    keys,
    now: EXPECTED_KEY_IDS_REQUIRE_TAG_CREATED,
    requireTag: true,
  });
  if (unpinned.length !== 2 || unpinned.some((r) => !r.ok))
    throw new Error(
      `benchmark self-check failed: wrong-keyid unpinned gave ${JSON.stringify(unpinned)}`,
    );

  return measure(() => {
    assertTriple("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` requireFreshnessByLabel
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), hand-built dual-label fixtures (built
 * with `buildSignatureBase` + `signatureInputValue` + a
 * raw ed25519 sign, the shape `test/requireFreshness.test.ts`
 * uses, because `signRequest` always emits both timestamps),
 * and the verifier's injected `now` at the `created`
 * instant. The merchant label is mapped `true` in
 * `requireCreatedByLabel` and the gateway label is mapped
 * `true` in `requireExpiresByLabel`, and both globals are
 * left unset, so each map entry drives only its own label.
 */
const REQUIRE_FRESHNESS_BY_LABEL_CREATED = 1_700_000_000;
const REQUIRE_FRESHNESS_BY_LABEL_EXPIRES =
  REQUIRE_FRESHNESS_BY_LABEL_CREATED + 600;
const REQUIRE_FRESHNESS_BY_LABEL_MERCHANT_KID =
  "bench-require-freshness-by-label-merchant-1";
const REQUIRE_FRESHNESS_BY_LABEL_GATEWAY_KID =
  "bench-require-freshness-by-label-gateway-1";
const REQUIRE_FRESHNESS_BY_LABEL_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];
const REQUIRE_FRESHNESS_BY_LABEL_MISSING_CREATED_CODE = "MISSING_CREATED";
const REQUIRE_FRESHNESS_BY_LABEL_MISSING_CREATED_REASON =
  "signature carries no `created` timestamp but requireCreated is set";
const REQUIRE_FRESHNESS_BY_LABEL_MISSING_EXPIRES_CODE = "MISSING_EXPIRES";
const REQUIRE_FRESHNESS_BY_LABEL_MISSING_EXPIRES_REASON =
  "signature carries no `expires` timestamp but requireExpires is set";

/**
 * `verifyAllLabels` with `requireCreatedByLabel` /
 * `requireExpiresByLabel` steady state: the per-label
 * freshness-existence form a multi-party receiver uses
 * when each signer must bound its own signature differently
 * (the merchant signature must carry a `created` timestamp
 * so its age is auditable; the gateway signature must carry
 * an `expires` timestamp so its lifetime is bounded) —
 * every measured call runs the per-label map resolution and
 * the post-cryptographic presence check for each mapped
 * label, which the plain `verifyAllLabels` row above never
 * pays, because it passes no requirement. One measured op
 * verifies three dual-label fixtures: the fully dated dual
 * (both labels ok); the no-created-merchant dual (merchant
 * exactly `MISSING_CREATED` with the pinned reason while the
 * fully dated gateway label still verifies, proving the
 * merchant's map entry does not leak into the gateway); and
 * the no-expires-gateway dual (gateway exactly
 * `MISSING_EXPIRES` with the pinned reason while the fully
 * dated merchant label still verifies, proving the
 * gateway's map entry does not leak into the merchant).
 * Outside timing, the opt-in halves are pinned once: both
 * undated duals verify with no option passed, and explicit
 * `merchant: false` / `gateway: false` map entries likewise
 * let them through — the map entries, not the label names,
 * drive the checks. Zero network, zero randomness in the
 * measured assertions, no wall clock (every verify instant
 * is injected).
 */
function benchmarkVerifyAllRequireFreshnessByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const buildLabel = (
    params: SignatureParams,
    label: string,
    privateKey: KeyObject,
  ): SignedHttpRequest => {
    const base = buildSignatureBase(
      REQUIRE_FRESHNESS_BY_LABEL_COVERED_COMPONENTS,
      fixture,
      params,
    );
    const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
    return {
      method: fixture.method,
      url: fixture.url,
      headers: {
        "signature-input": signatureInputValue(
          label,
          REQUIRE_FRESHNESS_BY_LABEL_COVERED_COMPONENTS,
          params,
        ),
        signature: `${label}=:${sig.toString("base64")}:`,
      },
    };
  };
  const merge = (
    a: SignedHttpRequest,
    b: SignedHttpRequest,
  ): SignedHttpRequest => ({
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  });
  const merchantDated = buildLabel(
    {
      keyid: REQUIRE_FRESHNESS_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      created: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
      expires: REQUIRE_FRESHNESS_BY_LABEL_EXPIRES,
    },
    "merchant",
    merchantPrivate,
  );
  const gatewayDated = buildLabel(
    {
      keyid: REQUIRE_FRESHNESS_BY_LABEL_GATEWAY_KID,
      alg: "ed25519",
      created: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
      expires: REQUIRE_FRESHNESS_BY_LABEL_EXPIRES,
    },
    "gateway",
    gatewayPrivate,
  );
  const merchantNoCreated = buildLabel(
    {
      keyid: REQUIRE_FRESHNESS_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      expires: REQUIRE_FRESHNESS_BY_LABEL_EXPIRES,
    },
    "merchant",
    merchantPrivate,
  );
  const gatewayNoExpires = buildLabel(
    {
      keyid: REQUIRE_FRESHNESS_BY_LABEL_GATEWAY_KID,
      alg: "ed25519",
      created: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
    },
    "gateway",
    gatewayPrivate,
  );
  const dualDated = merge(merchantDated, gatewayDated);
  const dualNoCreated = merge(merchantNoCreated, gatewayDated);
  const dualNoExpires = merge(merchantDated, gatewayNoExpires);
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
    requireCreatedByLabel: { merchant: true },
    requireExpiresByLabel: { gateway: true },
  };
  const assertDual = (where: string): void => {
    const dated = verifyAllLabels(dualDated, verifyOpts);
    if (
      dated.length !== 2 ||
      dated[0].label !== "merchant" ||
      !dated[0].ok ||
      dated[1].label !== "gateway" ||
      !dated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireFreshnessByLabel (${where}, dated dual) gave ${JSON.stringify(dated)}`,
      );
    const noCreated = verifyAllLabels(dualNoCreated, verifyOpts);
    if (
      noCreated.length !== 2 ||
      noCreated[0].label !== "merchant" ||
      noCreated[0].ok ||
      noCreated[0].code !==
        REQUIRE_FRESHNESS_BY_LABEL_MISSING_CREATED_CODE ||
      noCreated[0].reason !==
        REQUIRE_FRESHNESS_BY_LABEL_MISSING_CREATED_REASON ||
      noCreated[1].label !== "gateway" ||
      !noCreated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireFreshnessByLabel (${where}, no-created-merchant dual) gave ${JSON.stringify(noCreated)}`,
      );
    const noExpires = verifyAllLabels(dualNoExpires, verifyOpts);
    if (
      noExpires.length !== 2 ||
      noExpires[0].label !== "merchant" ||
      !noExpires[0].ok ||
      noExpires[1].label !== "gateway" ||
      noExpires[1].ok ||
      noExpires[1].code !==
        REQUIRE_FRESHNESS_BY_LABEL_MISSING_EXPIRES_CODE ||
      noExpires[1].reason !==
        REQUIRE_FRESHNESS_BY_LABEL_MISSING_EXPIRES_REASON
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireFreshnessByLabel (${where}, no-expires-gateway dual) gave ${JSON.stringify(noExpires)}`,
      );
  };

  // Outside timing: all three fixtures self-check under
  // the per-label requirements before any timing starts.
  assertDual("outside timing");

  // Outside timing: with no option both undated duals
  // verify — the requirements are opt-in and the default
  // behaviour is unchanged.
  const defaultedNoCreated = verifyAllLabels(dualNoCreated, {
    keys,
    now: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
  });
  if (
    defaultedNoCreated.length !== 2 ||
    defaultedNoCreated.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-created default gave ${JSON.stringify(defaultedNoCreated)}`,
    );
  const defaultedNoExpires = verifyAllLabels(dualNoExpires, {
    keys,
    now: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
  });
  if (
    defaultedNoExpires.length !== 2 ||
    defaultedNoExpires.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-expires default gave ${JSON.stringify(defaultedNoExpires)}`,
    );

  // Outside timing: explicit `false` map entries likewise
  // let both undated duals through — the map entries, not
  // the label names, drive the checks.
  const optedOutNoCreated = verifyAllLabels(dualNoCreated, {
    keys,
    now: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
    requireCreatedByLabel: { merchant: false },
  });
  if (
    optedOutNoCreated.length !== 2 ||
    optedOutNoCreated.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-created merchant:false gave ${JSON.stringify(optedOutNoCreated)}`,
    );
  const optedOutNoExpires = verifyAllLabels(dualNoExpires, {
    keys,
    now: REQUIRE_FRESHNESS_BY_LABEL_CREATED,
    requireExpiresByLabel: { gateway: false },
  });
  if (
    optedOutNoExpires.length !== 2 ||
    optedOutNoExpires.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-expires gateway:false gave ${JSON.stringify(optedOutNoExpires)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyAllLabels` requireCreatedExpiresByLabel
 * benchmark: two ed25519 key pairs (generated once,
 * outside timing), hand-built dual-label fixtures (built
 * with `buildSignatureBase` + `signatureInputValue` + a
 * raw ed25519 sign, the shape `test/requireFreshness.test.ts`
 * uses, because `signRequest` always emits both timestamps),
 * and the verifier's injected `now` at the `created`
 * instant. The merchant label is mapped `true` in both
 * `requireCreatedByLabel` and `requireExpiresByLabel` and
 * the gateway label is mapped in neither, and both globals
 * are left unset, so the merchant must carry both
 * timestamps while the gateway must carry neither.
 */
const REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED = 1_700_000_000;
const REQUIRE_CREATED_EXPIRES_BY_LABEL_EXPIRES =
  REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED + 600;
const REQUIRE_CREATED_EXPIRES_BY_LABEL_MERCHANT_KID =
  "bench-require-created-expires-by-label-merchant-1";
const REQUIRE_CREATED_EXPIRES_BY_LABEL_GATEWAY_KID =
  "bench-require-created-expires-by-label-gateway-1";
const REQUIRE_CREATED_EXPIRES_BY_LABEL_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
];
const REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_CODE =
  "MISSING_CREATED";
const REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_REASON =
  "signature carries no `created` timestamp but requireCreated is set";
const REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_EXPIRES_CODE =
  "MISSING_EXPIRES";
const REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_EXPIRES_REASON =
  "signature carries no `expires` timestamp but requireExpires is set";

/**
 * `verifyAllLabels` with `requireCreatedByLabel` /
 * `requireExpiresByLabel` both mapped on one label: the
 * per-label dual-required freshness-existence form a
 * multi-party receiver uses when one signer must carry
 * both timestamps while the other carries neither (the
 * merchant signature must carry `created` so its age is
 * auditable and `expires` so its lifetime is bounded; the
 * gateway signature is under no presence requirement) —
 * every measured call runs the per-label map resolution
 * and the post-cryptographic presence checks for the
 * mapped label, which the plain `verifyAllLabels` row
 * above never pays, because it passes no requirement.
 * One measured op verifies four dual-label fixtures: the
 * fully dated dual (both labels ok); the
 * no-created-merchant dual (merchant exactly
 * `MISSING_CREATED` with the pinned reason while the
 * fully dated gateway label still verifies, proving the
 * merchant's created map entry does not leak into the
 * gateway); the no-expires-merchant dual (merchant
 * exactly `MISSING_EXPIRES` with the pinned reason while
 * the fully dated gateway label still verifies, proving
 * the merchant's expires map entry does not leak into
 * the gateway); and the undated-gateway dual (both
 * labels ok, proving the gateway's unmapped state passes
 * under the same options). Outside timing, the opt-in
 * halves are pinned once: a both-missing merchant dual
 * reports `MISSING_CREATED` first (the created check
 * runs before the expires check, so the two dimensions
 * cannot be violated at once); all undated duals verify
 * with no option passed; and explicit `false` map entries
 * likewise let them through — the map entries, not the
 * label names, drive the checks. Zero network, zero
 * randomness in the measured assertions, no wall clock
 * (every verify instant is injected).
 */
function benchmarkVerifyAllRequireCreatedExpiresByLabel(): number {
  const {
    publicKey: merchantPublic,
    privateKey: merchantPrivate,
  } = generateEd25519KeyPair();
  const { publicKey: gatewayPublic, privateKey: gatewayPrivate } =
    generateEd25519KeyPair();
  const buildLabel = (
    params: SignatureParams,
    label: string,
    privateKey: KeyObject,
  ): SignedHttpRequest => {
    const base = buildSignatureBase(
      REQUIRE_CREATED_EXPIRES_BY_LABEL_COVERED_COMPONENTS,
      fixture,
      params,
    );
    const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
    return {
      method: fixture.method,
      url: fixture.url,
      headers: {
        "signature-input": signatureInputValue(
          label,
          REQUIRE_CREATED_EXPIRES_BY_LABEL_COVERED_COMPONENTS,
          params,
        ),
        signature: `${label}=:${sig.toString("base64")}:`,
      },
    };
  };
  const merge = (
    a: SignedHttpRequest,
    b: SignedHttpRequest,
  ): SignedHttpRequest => ({
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  });
  const merchantDated = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      created: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
      expires: REQUIRE_CREATED_EXPIRES_BY_LABEL_EXPIRES,
    },
    "merchant",
    merchantPrivate,
  );
  const gatewayDated = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_GATEWAY_KID,
      alg: "ed25519",
      created: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
      expires: REQUIRE_CREATED_EXPIRES_BY_LABEL_EXPIRES,
    },
    "gateway",
    gatewayPrivate,
  );
  const merchantNoCreated = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      expires: REQUIRE_CREATED_EXPIRES_BY_LABEL_EXPIRES,
    },
    "merchant",
    merchantPrivate,
  );
  const merchantNoExpires = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
      created: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    },
    "merchant",
    merchantPrivate,
  );
  const merchantUndated = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_MERCHANT_KID,
      alg: "ed25519",
    },
    "merchant",
    merchantPrivate,
  );
  const gatewayUndated = buildLabel(
    {
      keyid: REQUIRE_CREATED_EXPIRES_BY_LABEL_GATEWAY_KID,
      alg: "ed25519",
    },
    "gateway",
    gatewayPrivate,
  );
  const dualDated = merge(merchantDated, gatewayDated);
  const dualNoCreated = merge(merchantNoCreated, gatewayDated);
  const dualNoExpires = merge(merchantNoExpires, gatewayDated);
  const dualMerchantUndated = merge(merchantUndated, gatewayDated);
  const dualGatewayUndated = merge(merchantDated, gatewayUndated);
  const keys = { merchant: merchantPublic, gateway: gatewayPublic };
  const verifyOpts = {
    keys,
    now: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    requireCreatedByLabel: { merchant: true },
    requireExpiresByLabel: { merchant: true },
  };
  const assertDual = (where: string): void => {
    const dated = verifyAllLabels(dualDated, verifyOpts);
    if (
      dated.length !== 2 ||
      dated[0].label !== "merchant" ||
      !dated[0].ok ||
      dated[1].label !== "gateway" ||
      !dated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireCreatedExpiresByLabel (${where}, dated dual) gave ${JSON.stringify(dated)}`,
      );
    const noCreated = verifyAllLabels(dualNoCreated, verifyOpts);
    if (
      noCreated.length !== 2 ||
      noCreated[0].label !== "merchant" ||
      noCreated[0].ok ||
      noCreated[0].code !==
        REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_CODE ||
      noCreated[0].reason !==
        REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_REASON ||
      noCreated[1].label !== "gateway" ||
      !noCreated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireCreatedExpiresByLabel (${where}, no-created-merchant dual) gave ${JSON.stringify(noCreated)}`,
      );
    const noExpires = verifyAllLabels(dualNoExpires, verifyOpts);
    if (
      noExpires.length !== 2 ||
      noExpires[0].label !== "merchant" ||
      noExpires[0].ok ||
      noExpires[0].code !==
        REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_EXPIRES_CODE ||
      noExpires[0].reason !==
        REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_EXPIRES_REASON ||
      noExpires[1].label !== "gateway" ||
      !noExpires[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireCreatedExpiresByLabel (${where}, no-expires-merchant dual) gave ${JSON.stringify(noExpires)}`,
      );
    const gatewayUndated = verifyAllLabels(dualGatewayUndated, verifyOpts);
    if (
      gatewayUndated.length !== 2 ||
      gatewayUndated[0].label !== "merchant" ||
      !gatewayUndated[0].ok ||
      gatewayUndated[1].label !== "gateway" ||
      !gatewayUndated[1].ok
    )
      throw new Error(
        `benchmark self-check failed: verifyAllLabels with requireCreatedExpiresByLabel (${where}, undated-gateway dual) gave ${JSON.stringify(gatewayUndated)}`,
      );
  };

  // Outside timing: all four fixtures self-check under
  // the per-label requirements before any timing starts.
  assertDual("outside timing");

  // Outside timing: a both-missing merchant dual reports
  // MISSING_CREATED first — the created check runs before
  // the expires check — while the gateway label still
  // verifies.
  const merchantUndatedResult = verifyAllLabels(
    dualMerchantUndated,
    verifyOpts,
  );
  if (
    merchantUndatedResult.length !== 2 ||
    merchantUndatedResult[0].label !== "merchant" ||
    merchantUndatedResult[0].ok ||
    merchantUndatedResult[0].code !==
      REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_CODE ||
    merchantUndatedResult[0].reason !==
      REQUIRE_CREATED_EXPIRES_BY_LABEL_MISSING_CREATED_REASON ||
    merchantUndatedResult[1].label !== "gateway" ||
    !merchantUndatedResult[1].ok
  )
    throw new Error(
      `benchmark self-check failed: both-missing merchant gave ${JSON.stringify(merchantUndatedResult)}`,
    );

  // Outside timing: with no option all undated duals
  // verify — the requirements are opt-in and the default
  // behaviour is unchanged.
  for (const [name, dual] of [
    ["no-created", dualNoCreated],
    ["no-expires", dualNoExpires],
    ["merchant-undated", dualMerchantUndated],
    ["gateway-undated", dualGatewayUndated],
  ] as const) {
    const defaulted = verifyAllLabels(dual, {
      keys,
      now: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    });
    if (defaulted.length !== 2 || defaulted.some((r) => !r.ok))
      throw new Error(
        `benchmark self-check failed: ${name} default gave ${JSON.stringify(defaulted)}`,
      );
  }

  // Outside timing: explicit `false` map entries likewise
  // let all undated duals through — the map entries, not
  // the label names, drive the checks.
  const optedOutNoCreated = verifyAllLabels(dualNoCreated, {
    keys,
    now: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    requireCreatedByLabel: { merchant: false },
  });
  if (
    optedOutNoCreated.length !== 2 ||
    optedOutNoCreated.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-created merchant:false gave ${JSON.stringify(optedOutNoCreated)}`,
    );
  const optedOutNoExpires = verifyAllLabels(dualNoExpires, {
    keys,
    now: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    requireExpiresByLabel: { merchant: false },
  });
  if (
    optedOutNoExpires.length !== 2 ||
    optedOutNoExpires.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: no-expires merchant:false gave ${JSON.stringify(optedOutNoExpires)}`,
    );
  const optedOutUndated = verifyAllLabels(dualMerchantUndated, {
    keys,
    now: REQUIRE_CREATED_EXPIRES_BY_LABEL_CREATED,
    requireCreatedByLabel: { merchant: false },
    requireExpiresByLabel: { merchant: false },
  });
  if (
    optedOutUndated.length !== 2 ||
    optedOutUndated.some((r) => !r.ok)
  )
    throw new Error(
      `benchmark self-check failed: merchant-undated both:false gave ${JSON.stringify(optedOutUndated)}`,
    );

  return measure(() => {
    assertDual("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` algFallback
 * benchmark: the RFC 9421 Appendix B.2.5 hmac-sha256
 * wire value verbatim — its signature-input carries
 * `created` and `keyid` but no `alg` (`alg` is optional
 * per RFC 9421 §2.3) — verified against the §B.1.5
 * pinned shared secret, with the verifier's injected
 * `now` at the vector's own `created` instant, so no
 * wall clock is read.
 */
const ALG_FALLBACK_NOW = 1_618_884_473;
const ALG_FALLBACK_LABEL = "sig-b25";
const ALG_FALLBACK_KID = "test-shared-secret";
const ALG_FALLBACK_SECRET_B64 =
  "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBt" +
  "bmHhIDi6pcl8jsasjlTMtDQ==";
const ALG_FALLBACK_SIGNATURE_INPUT = `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`;
const ALG_FALLBACK_SIGNATURE_B64 =
  "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=";
const ALG_FALLBACK_INFERRED_ALG = "hmac-sha256";
const ALG_FALLBACK_INCOMPATIBLE_ERROR =
  'verifyRequest: wire alg "ed25519" is incompatible with the configured key (a secret (symmetric) key) — pass a matching key or remove the algFallback "infer" opt-in';
const ALG_FALLBACK_UNINFERRABLE_ERROR =
  'verifyRequest: algFallback "infer" cannot infer an algorithm for an asymmetric ec key (secp256k1) — supported key shapes are secret keys (hmac-sha256), ed25519 keys, P-256 (prime256v1) EC keys, P-384 (secp384r1) EC keys, P-521 (secp521r1) EC keys, and RSA keys (rsa-pss-sha512)';
const ALG_FALLBACK_ED_CREATED = 1_700_000_000;
const ALG_FALLBACK_ED_KID = "bench-alg-fallback-ed25519";

/**
 * `verifyRequest` with `algFallback: "infer"` steady
 * state: the algorithm-inference form a receiver uses
 * for foreign signers that omit the optional `alg`
 * parameter — every measured call runs the key-shape
 * inference the plain verify rows above never pay,
 * because their fixtures always carry `alg` on the
 * wire. One measured op verifies the pinned B.2.5
 * no-`alg` fixture with `algFallback: "infer"` and
 * re-pins that the result is ok and that the inferred
 * `alg` and the returned `keyId` equal their pinned
 * values. Outside timing, the default and
 * configuration-error halves are pinned once: the
 * same wire with no opt-in returns exactly
 * `{ ok: false, code: "VERIFICATION_ERROR" }` (only
 * the code is pinned — the reason carries the crypto
 * layer's own message, the same half the CLI demo
 * pins), a wire `alg="ed25519"` verified under the
 * opt-in against a secret key throws the pinned
 * incompatible-key configuration error, and the same
 * no-`alg` wire verified under the opt-in against a
 * secp256k1 key — a shape with no supported mapping —
 * throws the pinned cannot-infer configuration
 * error. Zero network, zero randomness in the
 * measured assertions, no wall clock (the verifier
 * clock is the vector's pinned `created` instant;
 * the secp256k1 key pair is generated once outside
 * timing and only its shape is ever asserted).
 */
function benchmarkVerifyAlgFallback(): number {
  const wire: RequestLike = {
    method: "POST",
    url: "http://example.com/foo?param=Value&Pet=dog",
    headers: {
      date: "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type": "application/json",
      "signature-input": ALG_FALLBACK_SIGNATURE_INPUT,
      signature: `${ALG_FALLBACK_LABEL}=:${ALG_FALLBACK_SIGNATURE_B64}:`,
    },
  };
  const secret = secretKey(Buffer.from(ALG_FALLBACK_SECRET_B64, "base64"));
  const verifyOpts = {
    key: secret,
    label: ALG_FALLBACK_LABEL,
    now: ALG_FALLBACK_NOW,
    algFallback: "infer" as const,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(wire, verifyOpts);
    if (
      !r.ok ||
      r.alg !== ALG_FALLBACK_INFERRED_ALG ||
      r.keyId !== ALG_FALLBACK_KID ||
      r.label !== ALG_FALLBACK_LABEL
    )
      throw new Error(
        `benchmark self-check failed: verifyRequest with algFallback (${where}) gave ${JSON.stringify(r)} ` +
          `(expected ok with inferred alg ${JSON.stringify(ALG_FALLBACK_INFERRED_ALG)})`,
      );
  };

  // Outside timing: the no-alg B.2.5 wire verifies
  // under the opt-in, with the algorithm inferred
  // from the secret key's shape.
  assertAccepted("outside timing");

  // Outside timing: with no opt-in the same wire
  // keeps the legacy behavior — the `ed25519` default
  // is tried against the secret key and the crypto
  // layer rejects the shape.
  const defaulted = verifyRequest(wire, {
    key: secret,
    label: ALG_FALLBACK_LABEL,
    now: ALG_FALLBACK_NOW,
  });
  if (defaulted.ok || defaulted.code !== "VERIFICATION_ERROR")
    throw new Error(
      `benchmark self-check failed: no-opt-in result ${JSON.stringify(defaulted)} ` +
        `(expected VERIFICATION_ERROR)`,
    );

  // Outside timing: a wire `alg` that contradicts the
  // configured key's shape is a caller configuration
  // error with the pinned full message, not a
  // verification failure.
  const { privateKey: edPrivate } = generateEd25519KeyPair();
  const edSigned = signRequest(fixture, {
    keyId: ALG_FALLBACK_ED_KID,
    alg: "ed25519",
    key: edPrivate,
    created: ALG_FALLBACK_ED_CREATED,
  });
  let incompatibleError: string | undefined;
  try {
    verifyRequest(edSigned, {
      key: secret,
      now: ALG_FALLBACK_ED_CREATED,
      algFallback: "infer",
    });
  } catch (err) {
    incompatibleError = err instanceof Error ? err.message : String(err);
  }
  if (incompatibleError !== ALG_FALLBACK_INCOMPATIBLE_ERROR)
    throw new Error(
      `benchmark self-check failed: incompatible-alg error ${JSON.stringify(incompatibleError)} ` +
        `(expected the pinned configuration error)`,
    );

  // Outside timing: a key shape with no supported
  // mapping (secp256k1) throws the pinned cannot-infer
  // configuration error.
  const { publicKey: k1Public } = generateKeyPairSync("ec", {
    namedCurve: "secp256k1",
  });
  let uninferrableError: string | undefined;
  try {
    verifyRequest(wire, {
      key: k1Public,
      label: ALG_FALLBACK_LABEL,
      now: ALG_FALLBACK_NOW,
      algFallback: "infer",
    });
  } catch (err) {
    uninferrableError = err instanceof Error ? err.message : String(err);
  }
  if (uninferrableError !== ALG_FALLBACK_UNINFERRABLE_ERROR)
    throw new Error(
      `benchmark self-check failed: uninferrable-key error ${JSON.stringify(uninferrableError)} ` +
        `(expected the pinned configuration error)`,
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `verifyRequest` requiredComponents
 * benchmark: one ed25519 key pair (generated once, outside
 * timing), a fixture signed outside timing covering exactly
 * the components a payment-gateway verifier wants covered —
 * `@method`, `@path` and `content-digest` — and a
 * `requiredComponents` list pinning those three, so the
 * measured steady state is the accepting path: the
 * pre-cryptographic coverage check the plain verify rows
 * above never pay, because they pass no such requirement.
 * The requirement check runs before any cryptography — a
 * missing component is a policy violation, not an
 * authenticity verdict — and comparison is case-insensitive,
 * matching the `cid.toLowerCase()` convention of
 * `resolveComponent`.
 */
const REQUIRED_COMPONENTS_KID = "bench-required-components-key-1";
const REQUIRED_COMPONENTS_COVERED: string[] = [
  "@method",
  "@path",
  "content-digest",
];
const REQUIRED_COMPONENTS_PINNED: string[] = [
  "@method",
  "@path",
  "content-digest",
];
const REQUIRED_COMPONENTS_CODE = "MISSING_REQUIRED_COMPONENT";
const REQUIRED_COMPONENTS_MISSING_ONE_REASON =
  'signature does not cover required component: "@authority"';
const REQUIRED_COMPONENTS_MISSING_TWO_REASON =
  'signature does not cover required components: "@authority", "@scheme"';
const REQUIRED_COMPONENTS_BAD_ENTRY_ERROR =
  'verifyRequest: `requiredComponents` entries must be non-empty strings, got ""';

/**
 * `verifyRequest` with `requiredComponents` steady state: the
 * coverage-policy form a receiver uses to refuse a
 * cryptographically valid signature that covers none of the
 * components it needs — every measured call runs the
 * pre-cryptographic component-coverage check and re-pins
 * that the fully-covered fixture is ok. Outside timing, the
 * rejecting and boundary halves are pinned once: one
 * missing required component returns exactly
 * `{ ok: false, code: "MISSING_REQUIRED_COMPONENT" }` with
 * the pinned singular-form reason, two missing give the
 * pinned plural-form reason, case-mismatched requirement
 * names (`Content-Digest`, `@PATH`) still match the
 * covered components, the same fixture verifies with the
 * option unset (the check is opt-in and the default is
 * unchanged), and an empty-string entry throws the pinned
 * configuration error. Zero network, zero randomness in
 * the measured assertions, no wall clock (the fixture
 * carries no lifetime parameters and the option is
 * clock-independent).
 */
function benchmarkVerifyRequiredComponents(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(fixture, {
    keyId: REQUIRED_COMPONENTS_KID,
    alg: "ed25519",
    key: privateKey,
    coveredComponents: REQUIRED_COMPONENTS_COVERED,
  });
  const verifyOpts = {
    key: publicKey,
    requiredComponents: REQUIRED_COMPONENTS_PINNED,
  };
  const assertAccepted = (where: string): void => {
    const r = verifyRequest(signed, verifyOpts);
    if (!r.ok)
      throw new Error(
        `benchmark self-check failed: verifyRequest with requiredComponents (${where}) gave ${JSON.stringify(r)}`,
      );
  };

  // Outside timing: the fully-covered fixture verifies
  // under the requirement.
  assertAccepted("outside timing");

  // Outside timing: one missing required component is
  // rejected with the pinned code and the singular-form
  // reason.
  const missingOne = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: [...REQUIRED_COMPONENTS_PINNED, "@authority"],
  });
  if (
    missingOne.ok ||
    missingOne.code !== REQUIRED_COMPONENTS_CODE ||
    missingOne.reason !== REQUIRED_COMPONENTS_MISSING_ONE_REASON
  )
    throw new Error(
      `benchmark self-check failed: missing-one result ${JSON.stringify(missingOne)} ` +
        "(expected MISSING_REQUIRED_COMPONENT)",
    );

  // Outside timing: two missing required components give
  // the plural-form reason.
  const missingTwo = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: [...REQUIRED_COMPONENTS_PINNED, "@authority", "@scheme"],
  });
  if (
    missingTwo.ok ||
    missingTwo.code !== REQUIRED_COMPONENTS_CODE ||
    missingTwo.reason !== REQUIRED_COMPONENTS_MISSING_TWO_REASON
  )
    throw new Error(
      `benchmark self-check failed: missing-two result ${JSON.stringify(missingTwo)} ` +
        "(expected MISSING_REQUIRED_COMPONENT)",
    );

  // Outside timing: case-mismatched requirement names
  // still match — the comparison is case-insensitive.
  const caseMismatched = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["Content-Digest", "@PATH"],
  });
  if (!caseMismatched.ok)
    throw new Error(
      `benchmark self-check failed: case-mismatched requiredComponents gave ${JSON.stringify(caseMismatched)}`,
    );

  // Outside timing: without the option the same fixture
  // verifies — the requirement is opt-in and the default
  // behaviour is unchanged.
  const defaulted = verifyRequest(signed, { key: publicKey });
  if (!defaulted.ok)
    throw new Error(
      `benchmark self-check failed: requiredComponents default gave ${JSON.stringify(defaulted)}`,
    );

  // Outside timing: an empty-string entry is a caller
  // configuration error and throws the pinned message.
  let badEntryError: string | undefined;
  try {
    verifyRequest(signed, {
      key: publicKey,
      requiredComponents: ["@method", ""],
    });
  } catch (err) {
    badEntryError = err instanceof Error ? err.message : String(err);
  }
  if (badEntryError !== REQUIRED_COMPONENTS_BAD_ENTRY_ERROR)
    throw new Error(
      `benchmark self-check failed: bad-entry error ${JSON.stringify(badEntryError)} ` +
        "(expected the pinned configuration error)",
    );

  return measure(() => {
    assertAccepted("measured pass");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `JwksKeyStore.refreshIfStale` benchmark store:
 * one ed25519 key (generated once, outside timing) published under
 * this kid by the counting fake fetch, a 120-second TTL, and an
 * injected clock starting at this instant. Every measured call
 * advances the clock by exactly the TTL — `isStale()` uses `>=`
 * semantics, so the snapshot is stale at the boundary — and must
 * therefore fetch exactly once.
 */
const JWKS_REFRESH_T0_SEC = 1_700_000_000;
const JWKS_REFRESH_TTL_SEC = 120;
const JWKS_REFRESH_KID = "bench-refresh-key";

/**
 * `JwksKeyStore.refreshIfStale` on a stale snapshot: the refresh
 * direction the resolve/export rows never pay — stale check against
 * the injected clock, one fetch of the pinned JWKS document (fake
 * fetch, zero network), JWK import and index rebuild by kid.
 * Outside timing, the not-stale case is pinned first: a fresh
 * snapshot's `refreshIfStale()` returns false and the fetch count
 * does not move. Every measured call then self-checks that it
 * refreshed (returned true), that the fetch count advanced by
 * exactly one, that the store is fresh again at the advanced
 * instant, and that the pinned kid resolves; after the measured
 * run the total fetch count must equal priming + warmup + timed
 * calls exactly.
 */
async function benchmarkJwksRefreshIfStale(): Promise<number> {
  const { publicKey } = generateEd25519KeyPair();
  const doc = {
    keys: [{ ...exportPublicKeyJwk(publicKey), kid: JWKS_REFRESH_KID }],
  };
  let fetchCalls = 0;
  const fetchImpl: JwksFetchImpl = async () => {
    fetchCalls++;
    return { ok: true, status: 200, json: async () => doc };
  };
  let t = JWKS_REFRESH_T0_SEC;
  const store = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    { fetchImpl, ttlSec: JWKS_REFRESH_TTL_SEC, now: () => t },
  );
  // Prime: a never-refreshed store is stale, so this fetches once.
  if ((await store.refreshIfStale()) !== true || fetchCalls !== 1)
    throw new Error(
      "benchmark self-check failed: priming refreshIfStale did not fetch exactly once",
    );
  // Outside timing: while fresh, refreshIfStale must not fetch.
  if ((await store.refreshIfStale()) !== false || fetchCalls !== 1)
    throw new Error(
      "benchmark self-check failed: fresh refreshIfStale fetched or reported a refresh",
    );
  if (store.resolve(JWKS_REFRESH_KID) === undefined)
    throw new Error(
      "benchmark self-check failed: primed store does not resolve the pinned kid",
    );
  const ops = await measureAsync(async () => {
    t += JWKS_REFRESH_TTL_SEC; // exactly at the >= boundary: stale
    const before = fetchCalls;
    if ((await store.refreshIfStale()) !== true)
      throw new Error(
        "benchmark self-check failed: stale refreshIfStale reported no refresh",
      );
    if (fetchCalls !== before + 1)
      throw new Error(
        `benchmark self-check failed: stale refreshIfStale made ${fetchCalls - before} fetches (expected 1)`,
      );
    if (store.isStale())
      throw new Error(
        "benchmark self-check failed: store still stale after refreshIfStale",
      );
    if (store.resolve(JWKS_REFRESH_KID) === undefined)
      throw new Error(
        "benchmark self-check failed: refreshed store does not resolve the pinned kid",
      );
  }, ITERATIONS);
  if (fetchCalls !== 1 + WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: refresh path made ${fetchCalls} fetches (expected ${1 + WARMUP + ITERATIONS})`,
    );
  if (store.stats().refreshes !== fetchCalls)
    throw new Error(
      `benchmark self-check failed: stats().refreshes ${store.stats().refreshes} (expected ${fetchCalls})`,
    );
  return ops;
}

/**
 * Pinned shape of the `JwksKeyStore.refresh` single-flight benchmark
 * store: one ed25519 key (generated once, outside timing) published
 * under this kid by the counting fake fetch, a 120-second TTL, an
 * injected clock starting at this instant, and this many concurrent
 * `refresh()` callers per measured batch.
 */
const JWKS_SINGLE_FLIGHT_T0_SEC = 1_700_000_000;
const JWKS_SINGLE_FLIGHT_TTL_SEC = 120;
const JWKS_SINGLE_FLIGHT_KID = "bench-single-flight-key";
const JWKS_SINGLE_FLIGHT_CONCURRENCY = 8;

/**
 * `JwksKeyStore.refresh` single-flight merging: the concurrent
 * direction the serial `refreshIfStale` row never pays — when a
 * gateway cold-starts or a rotation lands, many waiters call
 * `refresh()` at once and must share one fetch instead of
 * stampeding the JWKS endpoint. The store is primed once outside
 * timing, then its injected clock is advanced exactly to the TTL
 * boundary so the snapshot is stale when the measured batches
 * start. The counting fake fetch serves one pinned JWKS document
 * and resolves on a microtask tick (zero network, zero wall
 * clock). Every measured batch launches the pinned eight
 * concurrent `refresh()` calls and awaits them all, self-checking
 * that the fetch count advanced by exactly one, that
 * `stats().refreshes` advanced by exactly one, and that the
 * pinned kid resolves afterwards. Outside timing, a separate
 * failing store pins the shared-failure half of the contract:
 * one batch of eight waiters all receive the same rejection
 * object from exactly one fetch (counted once in
 * `stats().refreshFailures`), and the next `refresh()` after the
 * failure fetches again and succeeds — a failure is never cached.
 */
async function benchmarkJwksConcurrentRefresh(): Promise<number> {
  const { publicKey } = generateEd25519KeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwk(publicKey), kid: JWKS_SINGLE_FLIGHT_KID },
    ],
  };
  let fetchCalls = 0;
  const fetchImpl: JwksFetchImpl = async () => {
    fetchCalls++;
    await Promise.resolve(); // microtask tick, not a timer
    return { ok: true, status: 200, json: async () => doc };
  };
  let t = JWKS_SINGLE_FLIGHT_T0_SEC;
  const store = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    { fetchImpl, ttlSec: JWKS_SINGLE_FLIGHT_TTL_SEC, now: () => t },
  );
  // Prime: the first refresh fetches the pinned document once.
  await store.refresh();
  if (fetchCalls !== 1)
    throw new Error(
      "benchmark self-check failed: priming refresh did not fetch exactly once",
    );
  if (store.resolve(JWKS_SINGLE_FLIGHT_KID) === undefined)
    throw new Error(
      "benchmark self-check failed: primed store does not resolve the pinned kid",
    );
  // Stale construction: exactly at the >= TTL boundary.
  t += JWKS_SINGLE_FLIGHT_TTL_SEC;
  if (!store.isStale())
    throw new Error(
      "benchmark self-check failed: store is not stale at the TTL boundary",
    );
  // Outside timing: a shared failure reaches every waiter once.
  let failCalls = 0;
  let failFetch = true;
  const failFetchImpl: JwksFetchImpl = async () => {
    failCalls++;
    await Promise.resolve(); // microtask tick, not a timer
    if (failFetch) return { ok: false, status: 500, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => doc };
  };
  const failStore = new JwksKeyStore(
    "https://gateway.example.com/.well-known/jwks.json",
    {
      fetchImpl: failFetchImpl,
      ttlSec: JWKS_SINGLE_FLIGHT_TTL_SEC,
      now: () => t,
    },
  );
  const settled = await Promise.allSettled(
    Array.from({ length: JWKS_SINGLE_FLIGHT_CONCURRENCY }, () =>
      failStore.refresh(),
    ),
  );
  if (failCalls !== 1)
    throw new Error(
      `benchmark self-check failed: failing batch made ${failCalls} fetches (expected 1)`,
    );
  const firstReason: unknown =
    settled[0]?.status === "rejected" ? settled[0].reason : undefined;
  if (
    !(firstReason instanceof Error) ||
    settled.some(
      (outcome) => outcome.status !== "rejected" || outcome.reason !== firstReason,
    )
  )
    throw new Error(
      "benchmark self-check failed: failing batch did not give every waiter the same rejection",
    );
  if (
    failStore.stats().refreshFailures !== 1 ||
    failStore.stats().refreshes !== 0
  )
    throw new Error(
      "benchmark self-check failed: failing batch was not counted exactly once",
    );
  // A settled failure is never cached: the next refresh fetches again.
  failFetch = false;
  await failStore.refresh();
  if (failCalls !== 1 + 1 || failStore.stats().refreshes !== 1)
    throw new Error(
      "benchmark self-check failed: refresh after a shared failure did not fetch again and succeed",
    );
  if (failStore.resolve(JWKS_SINGLE_FLIGHT_KID) === undefined)
    throw new Error(
      "benchmark self-check failed: retried store does not resolve the pinned kid",
    );
  const ops = await measureAsync(async () => {
    const beforeFetches = fetchCalls;
    const beforeRefreshes = store.stats().refreshes;
    await Promise.all(
      Array.from({ length: JWKS_SINGLE_FLIGHT_CONCURRENCY }, () =>
        store.refresh(),
      ),
    );
    if (fetchCalls !== beforeFetches + 1)
      throw new Error(
        `benchmark self-check failed: concurrent batch made ${fetchCalls - beforeFetches} fetches (expected 1)`,
      );
    if (store.stats().refreshes !== beforeRefreshes + 1)
      throw new Error(
        `benchmark self-check failed: concurrent batch counted ${store.stats().refreshes - beforeRefreshes} refreshes (expected 1)`,
      );
    if (store.resolve(JWKS_SINGLE_FLIGHT_KID) === undefined)
      throw new Error(
        "benchmark self-check failed: concurrent batch does not resolve the pinned kid",
      );
  }, ITERATIONS);
  if (fetchCalls !== 1 + WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: single-flight path made ${fetchCalls} fetches (expected ${1 + WARMUP + ITERATIONS})`,
    );
  if (store.stats().refreshes !== fetchCalls || store.stats().refreshFailures !== 0)
    throw new Error(
      `benchmark self-check failed: stats() ${JSON.stringify(store.stats())} (expected refreshes ${fetchCalls}, refreshFailures 0)`,
    );
  return ops;
}

/**
 * Pinned shape of the `JwksKeyStore.refresh` fetch-retry benchmark:
 * one ed25519 key (generated once, outside timing) published under
 * this kid, a retry budget of two (`fetchRetries: 2`) with a pinned
 * fixed backoff, and a stub sleep that records each requested delay
 * without waiting — so the measured cost is the retry loop itself
 * (three fetch attempts, JWK import, snapshot swap), never a real
 * wall-clock backoff, and zero network throughout.
 *
 * Outside timing, three halves of the retry contract are pinned
 * once: the scripted 500, 500, 200 refresh succeeds on the third
 * attempt with exactly two sleeps of the pinned backoff and the
 * pinned kid resolving afterwards; the terminal-4xx refresh fails
 * with the pinned HTTP 404 error after exactly one fetch and zero
 * sleeps (a 4xx is never retried); and the always-500 refresh
 * exhausts its budget with exactly three fetches, two sleeps, the
 * pinned HTTP 500 error, and exactly one `stats().refreshFailures`
 * (retries never multiply the counters). Every measured refresh
 * then re-pays the full scripted cycle — the measured store's fake
 * fetch answers 500, 500, 200 per refresh, keyed off the running
 * fetch count modulo three — and self-checks that it made exactly
 * three fetches, recorded exactly two sleeps of the pinned backoff,
 * counted exactly one `stats().refreshes`, and resolves the pinned
 * kid; after the measured run the totals must equal the scripted
 * cycle times warmup plus timed calls exactly.
 */
const JWKS_FETCH_RETRIES_KID = "bench-fetch-retries-key";
const JWKS_FETCH_RETRIES_RETRIES = 2;
const JWKS_FETCH_RETRIES_BACKOFF_MS = 250;
const JWKS_FETCH_RETRIES_URL =
  "https://gateway.example.com/.well-known/jwks.json";
const JWKS_FETCH_RETRIES_404_ERROR =
  `JwksKeyStore: JWKS fetch failed: HTTP 404 from ${JWKS_FETCH_RETRIES_URL}`;
const JWKS_FETCH_RETRIES_500_ERROR =
  `JwksKeyStore: JWKS fetch failed: HTTP 500 from ${JWKS_FETCH_RETRIES_URL}`;

async function benchmarkJwksFetchRetries(): Promise<number> {
  const { publicKey } = generateEd25519KeyPair();
  const doc = {
    keys: [
      { ...exportPublicKeyJwk(publicKey), kid: JWKS_FETCH_RETRIES_KID },
    ],
  };

  // Outside timing: the scripted 500, 500, 200 refresh pins the retry
  // count (three fetches, two sleeps) and the final snapshot.
  let scriptedCalls = 0;
  const scriptedSleeps: number[] = [];
  const scriptedStore = new JwksKeyStore(JWKS_FETCH_RETRIES_URL, {
    fetchImpl: async () => {
      scriptedCalls++;
      if (scriptedCalls <= 2)
        return { ok: false, status: 500, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => doc };
    },
    fetchRetries: JWKS_FETCH_RETRIES_RETRIES,
    fetchBackoffMs: JWKS_FETCH_RETRIES_BACKOFF_MS,
    sleepImpl: async (ms: number) => {
      scriptedSleeps.push(ms);
    },
  });
  await scriptedStore.refresh();
  if (
    scriptedCalls !== 3 ||
    scriptedSleeps.length !== 2 ||
    scriptedSleeps.some((ms) => ms !== JWKS_FETCH_RETRIES_BACKOFF_MS) ||
    scriptedStore.resolve(JWKS_FETCH_RETRIES_KID) === undefined ||
    scriptedStore.stats().refreshes !== 1 ||
    scriptedStore.stats().refreshFailures !== 0
  )
    throw new Error(
      `benchmark self-check failed: scripted fetch-retries refresh gave ${scriptedCalls} fetches with sleeps ${JSON.stringify(scriptedSleeps)} and stats ${JSON.stringify(scriptedStore.stats())} (expected 3 fetches, 2 sleeps of ${JWKS_FETCH_RETRIES_BACKOFF_MS}ms, refreshes 1, refreshFailures 0)`,
    );

  // Outside timing: a 4xx response is terminal — one fetch, zero
  // sleeps, the pinned HTTP 404 error, counted once as a failure.
  let notFoundCalls = 0;
  const notFoundSleeps: number[] = [];
  const notFoundStore = new JwksKeyStore(JWKS_FETCH_RETRIES_URL, {
    fetchImpl: async () => {
      notFoundCalls++;
      return { ok: false, status: 404, json: async () => ({}) };
    },
    fetchRetries: JWKS_FETCH_RETRIES_RETRIES,
    fetchBackoffMs: JWKS_FETCH_RETRIES_BACKOFF_MS,
    sleepImpl: async (ms: number) => {
      notFoundSleeps.push(ms);
    },
  });
  let notFoundError = "";
  try {
    await notFoundStore.refresh();
  } catch (err) {
    notFoundError = err instanceof Error ? err.message : String(err);
  }
  if (
    notFoundCalls !== 1 ||
    notFoundSleeps.length !== 0 ||
    notFoundError !== JWKS_FETCH_RETRIES_404_ERROR ||
    notFoundStore.stats().refreshes !== 0 ||
    notFoundStore.stats().refreshFailures !== 1 ||
    notFoundStore.resolve(JWKS_FETCH_RETRIES_KID) !== undefined
  )
    throw new Error(
      `benchmark self-check failed: terminal-4xx fetch-retries refresh gave ${notFoundCalls} fetches with sleeps ${JSON.stringify(notFoundSleeps)} and error ${JSON.stringify(notFoundError)} (expected 1 fetch, 0 sleeps, error ${JSON.stringify(JWKS_FETCH_RETRIES_404_ERROR)})`,
    );

  // Outside timing: an always-500 endpoint exhausts the budget —
  // three fetches, two sleeps, the pinned HTTP 500 error, and the
  // failure counted once, not once per attempt.
  let exhaustedCalls = 0;
  const exhaustedSleeps: number[] = [];
  const exhaustedStore = new JwksKeyStore(JWKS_FETCH_RETRIES_URL, {
    fetchImpl: async () => {
      exhaustedCalls++;
      return { ok: false, status: 500, json: async () => ({}) };
    },
    fetchRetries: JWKS_FETCH_RETRIES_RETRIES,
    fetchBackoffMs: JWKS_FETCH_RETRIES_BACKOFF_MS,
    sleepImpl: async (ms: number) => {
      exhaustedSleeps.push(ms);
    },
  });
  let exhaustedError = "";
  try {
    await exhaustedStore.refresh();
  } catch (err) {
    exhaustedError = err instanceof Error ? err.message : String(err);
  }
  if (
    exhaustedCalls !== 3 ||
    exhaustedSleeps.length !== 2 ||
    exhaustedSleeps.some((ms) => ms !== JWKS_FETCH_RETRIES_BACKOFF_MS) ||
    exhaustedError !== JWKS_FETCH_RETRIES_500_ERROR ||
    exhaustedStore.stats().refreshes !== 0 ||
    exhaustedStore.stats().refreshFailures !== 1
  )
    throw new Error(
      `benchmark self-check failed: exhausted fetch-retries refresh gave ${exhaustedCalls} fetches with sleeps ${JSON.stringify(exhaustedSleeps)} and error ${JSON.stringify(exhaustedError)} (expected 3 fetches, 2 sleeps of ${JWKS_FETCH_RETRIES_BACKOFF_MS}ms, error ${JSON.stringify(JWKS_FETCH_RETRIES_500_ERROR)})`,
    );

  // Measured store: the fake fetch cycles 500, 500, 200 per refresh,
  // keyed off the running fetch count, so every measured refresh
  // pays the full retry loop and re-proves the snapshot swap.
  let fetchCalls = 0;
  const sleeps: number[] = [];
  const store = new JwksKeyStore(JWKS_FETCH_RETRIES_URL, {
    fetchImpl: async () => {
      fetchCalls++;
      if ((fetchCalls - 1) % 3 < 2)
        return { ok: false, status: 500, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => doc };
    },
    fetchRetries: JWKS_FETCH_RETRIES_RETRIES,
    fetchBackoffMs: JWKS_FETCH_RETRIES_BACKOFF_MS,
    sleepImpl: async (ms: number) => {
      sleeps.push(ms);
    },
  });
  const ops = await measureAsync(async () => {
    const beforeFetches = fetchCalls;
    const beforeSleeps = sleeps.length;
    const beforeRefreshes = store.stats().refreshes;
    await store.refresh();
    if (fetchCalls !== beforeFetches + 3)
      throw new Error(
        `benchmark self-check failed: fetch-retries refresh made ${fetchCalls - beforeFetches} fetches (expected 3)`,
      );
    if (
      sleeps.length !== beforeSleeps + 2 ||
      sleeps
        .slice(beforeSleeps)
        .some((ms) => ms !== JWKS_FETCH_RETRIES_BACKOFF_MS)
    )
      throw new Error(
        `benchmark self-check failed: fetch-retries refresh recorded sleeps ${JSON.stringify(sleeps.slice(beforeSleeps))} (expected 2 sleeps of ${JWKS_FETCH_RETRIES_BACKOFF_MS}ms)`,
      );
    if (store.stats().refreshes !== beforeRefreshes + 1)
      throw new Error(
        `benchmark self-check failed: fetch-retries refresh counted ${store.stats().refreshes - beforeRefreshes} refreshes (expected 1)`,
      );
    if (store.resolve(JWKS_FETCH_RETRIES_KID) === undefined)
      throw new Error(
        "benchmark self-check failed: fetch-retries refresh does not resolve the pinned kid",
      );
  }, ITERATIONS);
  if (fetchCalls !== 3 * (WARMUP + ITERATIONS))
    throw new Error(
      `benchmark self-check failed: fetch-retries path made ${fetchCalls} fetches (expected ${3 * (WARMUP + ITERATIONS)})`,
    );
  if (sleeps.length !== 2 * (WARMUP + ITERATIONS))
    throw new Error(
      `benchmark self-check failed: fetch-retries path recorded ${sleeps.length} sleeps (expected ${2 * (WARMUP + ITERATIONS)})`,
    );
  if (
    store.stats().refreshes !== WARMUP + ITERATIONS ||
    store.stats().refreshFailures !== 0
  )
    throw new Error(
      `benchmark self-check failed: stats() ${JSON.stringify(store.stats())} (expected refreshes ${WARMUP + ITERATIONS}, refreshFailures 0)`,
    );
  return ops;
}

/** Steady-state `JwksKeyStore.resolve` hit: a Map lookup by keyid. */
function benchmarkJwksResolve(store: JwksKeyStore): number {
  return measure(() => {
    if (store.resolve("bench-key") === undefined)
      throw new Error("benchmark self-check failed: resolve missed bench-key");
  }, ITERATIONS);
}

/**
 * Pinned shape of the `JwksKeyStore` requireHttps benchmark:
 * the endpoint-rule form a gateway runs when it hardens its
 * JWKS endpoint against plaintext downgrade — a store built
 * over an https endpoint with `requireHttps: true`, restored
 * offline from a snapshot of one freshly generated ed25519
 * key (its fetch implementation throws if it is ever called,
 * so the measured path performs zero network I/O), plus the
 * construction-time rules asserted outside timing: an http
 * endpoint with `requireHttps: true` throws the pinned
 * error before any fetch, and an https endpoint with
 * `requireHttps: true` constructs without fetching.
 */
const JWKS_REQUIRE_HTTPS_HTTP_URL =
  "http://gateway.example.com/.well-known/jwks.json";
const JWKS_REQUIRE_HTTPS_HTTPS_URL =
  "https://gateway.example.com/.well-known/jwks.json";
const JWKS_REQUIRE_HTTPS_ERROR =
  'JwksKeyStore: `requireHttps` requires https: for the JWKS endpoint, got "http:"';

/**
 * `JwksKeyStore` with `requireHttps: true` steady state:
 * every measured call resolves the pinned kid against the
 * https-endpoint store, which is exactly the per-request
 * cost a hardened gateway pays — the endpoint rule itself
 * is construction-time only (the constructor rejects a
 * non-https endpoint; `resolve` never consults it), so the
 * measured path runs the identical resolve code as the
 * plain `resolve` row above. Both rows are sub-microsecond
 * Map lookups, so any gap between them is measurement
 * noise at this scale, not a construction artefact.
 * Outside timing,
 * the http-endpoint rejection (pinned error, zero fetches)
 * and the https-endpoint construction (zero fetches) are
 * pinned, and the measured store's pinned kid resolves
 * before any timing starts. Zero network, zero wall clock
 * (the store's clock is injected).
 */
function benchmarkJwksRequireHttps(): number {
  let fetches = 0;
  const countingFetch: JwksFetchImpl = async () => {
    fetches++;
    throw new Error("benchmark must not fetch (requireHttps store)");
  };

  // Outside timing: an http endpoint with `requireHttps: true`
  // throws the pinned error and fetches zero times.
  try {
    new JwksKeyStore(JWKS_REQUIRE_HTTPS_HTTP_URL, {
      requireHttps: true,
      fetchImpl: countingFetch,
    });
    throw new Error(
      "benchmark self-check failed: http endpoint with requireHttps did not throw",
    );
  } catch (err) {
    if (!(err instanceof Error) || err.message !== JWKS_REQUIRE_HTTPS_ERROR)
      throw new Error(
        `benchmark self-check failed: http endpoint with requireHttps gave ${err instanceof Error ? JSON.stringify(err.message) : String(err)}`,
      );
  }
  if (fetches !== 0)
    throw new Error(
      `benchmark self-check failed: rejected http endpoint fetched ${fetches} times (expected 0)`,
    );

  // Outside timing: an https endpoint with `requireHttps: true`
  // constructs, and construction itself performs no fetch.
  new JwksKeyStore(JWKS_REQUIRE_HTTPS_HTTPS_URL, {
    requireHttps: true,
    fetchImpl: countingFetch,
  });
  if (fetches !== 0)
    throw new Error(
      `benchmark self-check failed: https endpoint construction fetched ${fetches} times (expected 0)`,
    );

  // The measured store: the same https endpoint, hardened
  // with `requireHttps: true`, restored offline like
  // {@link offlineJwksStore} so no fetch can ever fire.
  const { publicKey } = generateEd25519KeyPair();
  const store = JwksKeyStore.restore(
    {
      v: 1 as const,
      fetchedAtSec: 1_700_000_000,
      keys: [{ ...exportPublicKeyJwk(publicKey), kid: "bench-key" }],
    },
    JWKS_REQUIRE_HTTPS_HTTPS_URL,
    {
      requireHttps: true,
      fetchImpl: async () => {
        throw new Error("benchmark must not fetch (offline store)");
      },
      now: () => 1_700_000_000,
    },
  );
  if (store.resolve("bench-key") === undefined)
    throw new Error(
      "benchmark self-check failed: requireHttps store missed bench-key",
    );
  return measure(() => {
    if (store.resolve("bench-key") === undefined)
      throw new Error(
        "benchmark self-check failed: requireHttps resolve missed bench-key",
      );
  }, ITERATIONS);
}

/**
 * `memoizeKeyResolver` cache hit: the wrapper is primed once, then every
 * measured call must be served from the cache — the self-check asserts
 * the counting underlying resolver was still called exactly once after
 * the whole measured run (warmup included).
 */
function benchmarkMemoizeHit(store: JwksKeyStore): number {
  let underlying = 0;
  const counting = (keyId: string) => {
    underlying++;
    return store.resolve(keyId);
  };
  const memoized = memoizeKeyResolver(counting, {
    ttlSec: 300,
    now: () => 1_700_000_000,
  });
  if (memoized("bench-key") === undefined)
    throw new Error("benchmark self-check failed: priming resolve missed");
  const ops = measure(() => {
    if (memoized("bench-key") === undefined)
      throw new Error("benchmark self-check failed: memoized hit missed");
  }, ITERATIONS);
  if (underlying !== 1)
    throw new Error(
      `benchmark self-check failed: hit path penetrated to the underlying resolver ${underlying} times (expected 1)`,
    );
  return ops;
}

/**
 * `memoizeKeyResolver` cache miss: every call uses an unknown keyid.
 * Unknown keyids are deliberately never cached (see memoizeKeyResolver),
 * so every measured call penetrates to the counting underlying resolver
 * and returns undefined — the steady-state cost of verifying against a
 * keyid the store does not hold. The self-check asserts the underlying
 * call count equals warmup + timed iterations exactly.
 */
function benchmarkMemoizeMiss(store: JwksKeyStore): number {
  let underlying = 0;
  const counting = (keyId: string) => {
    underlying++;
    return store.resolve(keyId);
  };
  const memoized = memoizeKeyResolver(counting, {
    ttlSec: 300,
    now: () => 1_700_000_000,
  });
  const ops = measure(() => {
    if (memoized("bench-unknown") !== undefined)
      throw new Error("benchmark self-check failed: unknown keyid resolved");
  }, ITERATIONS);
  if (underlying !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: miss path made ${underlying} underlying calls (expected ${WARMUP + ITERATIONS})`,
    );
  return ops;
}

/**
 * Fixed public-JWK fixture for the `jwkThumbprint` path — the three
 * shapes this library exports, with sources that exist independently
 * of this implementation:
 * - ed25519: the RFC 8032 §7.1 Test 1 public key.
 * - P-256: the curve generator point G (SEC 2), as a public JWK.
 * - RSA: the RFC 7638 §3.1 example JWK, verbatim (including its
 *   non-required `alg`/`kid` members, which must not participate).
 */
const THUMBPRINT_FIXTURE = {
  ed25519: {
    kty: "OKP",
    crv: "Ed25519",
    x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
  },
  p256: {
    kty: "EC",
    crv: "P-256",
    x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
  },
  rsa: {
    kty: "RSA",
    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    e: "AQAB",
    alg: "RS256",
    kid: "2011-04-29",
  },
} as const;

/**
 * Expected thumbprints for the fixture above. The RSA value is the
 * thumbprint published in RFC 7638 §3.1 itself (the same value
 * test/jwkThumbprint.test.ts pins). The ed25519 / P-256 values were
 * computed independently of this implementation (canonical required-
 * member JSON + SHA-256, cross-checked in Python's hashlib, whose
 * RSA output reproduces the RFC value exactly) and are pinned here
 * as literals — never derived from `jwkThumbprint` at bench time.
 */
const THUMBPRINT_EXPECTED = {
  ed25519: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
  p256: "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  rsa: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
} as const;

/**
 * `jwkThumbprint` steady state: one measured call derives the
 * thumbprint of each of the three fixture shapes (3 derivations per
 * call) — the per-key cost a JWKS publisher/rotator pays to assign
 * stable keyids. Self-checks run outside timing: every shape must
 * reproduce its pinned expected thumbprint above.
 */
function benchmarkJwkThumbprint(): number {
  for (const shape of ["ed25519", "p256", "rsa"] as const) {
    const tp = jwkThumbprint(THUMBPRINT_FIXTURE[shape]);
    if (tp !== THUMBPRINT_EXPECTED[shape])
      throw new Error(
        `benchmark self-check failed: ${shape} thumbprint ${tp} ` +
          `(expected ${THUMBPRINT_EXPECTED[shape]})`,
      );
  }
  return measure(() => {
    jwkThumbprint(THUMBPRINT_FIXTURE.ed25519);
    jwkThumbprint(THUMBPRINT_FIXTURE.p256);
    jwkThumbprint(THUMBPRINT_FIXTURE.rsa);
  }, ITERATIONS);
}

/** Number of nonces prefilled into the ReplayCache benchmark fixture. */
const REPLAY_PREFILL = 1000;

/**
 * `ReplayCache.check` steady-state hit: the cache is prefilled with
 * REPLAY_PREFILL nonces under a fixed fake clock (no wall clock, no
 * randomness, no network), then every measured call checks a nonce
 * that is already recorded — the replay path a verifier with
 * `requireNonce` takes on a duplicate nonce. Calls rotate over the
 * whole prefilled set so the LRU recency refresh is exercised across
 * entries, not just on one hot key.
 *
 * Self-checks: every prefill call must report not-a-replay; an unseen
 * nonce must report false on first check and true on the second; and
 * after the measured run the stats counters must match the exact
 * number of check calls made (prefill misses + one unseen miss, and
 * the unseen re-check hit + warmup + timed hits).
 */
function benchmarkReplayCacheHit(): number {
  const FIXED_NOW = 1_700_000_000;
  const cache = new ReplayCache({
    maxEntries: 10_000,
    ttlSec: 3600,
    now: () => FIXED_NOW,
  });
  for (let i = 0; i < REPLAY_PREFILL; i++) {
    if (cache.check(`bench-nonce-${i}`) !== false)
      throw new Error(
        `benchmark self-check failed: prefill nonce ${i} reported as replay`,
      );
  }
  if (cache.check("bench-unseen") !== false)
    throw new Error(
      "benchmark self-check failed: unseen nonce reported as replay",
    );
  if (cache.check("bench-unseen") !== true)
    throw new Error(
      "benchmark self-check failed: second check of unseen nonce not a replay",
    );
  let idx = 0;
  const ops = measure(() => {
    const nonce = `bench-nonce-${idx % REPLAY_PREFILL}`;
    idx++;
    if (cache.check(nonce) !== true)
      throw new Error(
        `benchmark self-check failed: prefilled nonce ${nonce} not a replay`,
      );
  }, ITERATIONS);
  const stats = cache.stats();
  const expectedHits = 1 + WARMUP + ITERATIONS;
  const expectedMisses = REPLAY_PREFILL + 1;
  if (
    stats.hits !== expectedHits ||
    stats.misses !== expectedMisses ||
    stats.size !== REPLAY_PREFILL + 1 ||
    stats.evictions !== 0
  )
    throw new Error(
      `benchmark self-check failed: stats ${JSON.stringify(stats)} ` +
        `(expected hits=${expectedHits}, misses=${expectedMisses}, ` +
        `size=${REPLAY_PREFILL + 1}, evictions=0)`,
    );
  return ops;
}

/** Fixed export instant for the ReplayCache export fixture (no wall clock). */
const REPLAY_EXPORT_NOW = 1_700_000_000;
/** TTL of the ReplayCache export fixture, in seconds. */
const REPLAY_EXPORT_TTL_SEC = 3600;
/** Nonce recorded 7,200s before the export instant: expired at export. */
const REPLAY_EXPORT_EXPIRED_NONCE = "bench-export-expired";
/**
 * Hand-pinned live entries of the export fixture at
 * REPLAY_EXPORT_NOW, in LRU (insertion) order — written literally,
 * never derived from `exportSnapshot` itself.
 */
const REPLAY_EXPORT_EXPECTED: Array<[string, number]> = [
  ["bench-export-first", REPLAY_EXPORT_NOW - 30],
  ["bench-export-second", REPLAY_EXPORT_NOW - 20],
  ["bench-export-last", REPLAY_EXPORT_NOW - 10],
];

/**
 * Build the fixed ReplayCache export fixture: an injectable clock is
 * walked through the pinned recording instants (the expired nonce
 * first, then the three live nonces at their pinned `seenAt` values)
 * and frozen at REPLAY_EXPORT_NOW, so the cache's map holds four
 * entries of which exactly one is already expired at export time.
 * Every recording must report not-a-replay.
 */
function replayExportFixture(): ReplayCache {
  let clock = REPLAY_EXPORT_NOW - 7200;
  const cache = new ReplayCache({
    maxEntries: 10_000,
    ttlSec: REPLAY_EXPORT_TTL_SEC,
    now: () => clock,
  });
  if (cache.check(REPLAY_EXPORT_EXPIRED_NONCE) !== false)
    throw new Error(
      "benchmark self-check failed: expired-fixture nonce reported as replay",
    );
  for (const [nonce, seenAt] of REPLAY_EXPORT_EXPECTED) {
    clock = seenAt;
    if (cache.check(nonce) !== false)
      throw new Error(
        `benchmark self-check failed: fixture nonce ${nonce} reported as replay`,
      );
  }
  clock = REPLAY_EXPORT_NOW;
  return cache;
}

/**
 * Pin one exported snapshot against the hand-written expectation:
 * version 1, exactly the live-entry count (the expired entry is
 * filtered out), every entry item by item (nonce and `seenAt`, first
 * and last included), and the expired nonce absent.
 */
function assertReplayExportSnapshot(
  snapshot: ReturnType<ReplayCache["exportSnapshot"]>,
): void {
  if (snapshot.v !== 1)
    throw new Error(
      `benchmark self-check failed: replay exportSnapshot v ${String(snapshot.v)} (expected 1)`,
    );
  if (snapshot.entries.length !== REPLAY_EXPORT_EXPECTED.length)
    throw new Error(
      `benchmark self-check failed: replay exportSnapshot exported ${snapshot.entries.length} entries ` +
        `(expected ${REPLAY_EXPORT_EXPECTED.length} live)`,
    );
  for (let i = 0; i < REPLAY_EXPORT_EXPECTED.length; i++) {
    const entry = snapshot.entries[i]!;
    const [nonce, seenAt] = REPLAY_EXPORT_EXPECTED[i]!;
    if (entry[0] !== nonce || entry[1] !== seenAt)
      throw new Error(
        `benchmark self-check failed: replay exportSnapshot entries[${i}] ${JSON.stringify(entry)} ` +
          `(expected ${JSON.stringify([nonce, seenAt])})`,
      );
  }
  if (snapshot.entries.some(([nonce]) => nonce === REPLAY_EXPORT_EXPIRED_NONCE))
    throw new Error(
      "benchmark self-check failed: replay exportSnapshot carries the expired nonce",
    );
}

/**
 * `ReplayCache.exportSnapshot` steady state: every measured call
 * re-exports the fixed-clock fixture and re-pins the whole snapshot
 * (see {@link assertReplayExportSnapshot}) — the live-entry filter
 * plus detached `{ v: 1, entries }` assembly a verifier pays when it
 * persists its replay cache before a restart. Outside timing, the
 * detached-copy semantics are asserted (mutating an exported
 * snapshot — entry nonce, `seenAt`, an injected entry, the version —
 * leaves a re-export unchanged) and an empty cache must export
 * `{ v: 1, entries: [] }`.
 */
function benchmarkReplayCacheExportSnapshot(): number {
  const cache = replayExportFixture();
  assertReplayExportSnapshot(cache.exportSnapshot());
  const detached = cache.exportSnapshot();
  detached.entries[0]![0] = "bench-export-forged";
  detached.entries[0]![1] = 0;
  detached.entries.push(["bench-export-injected", REPLAY_EXPORT_NOW]);
  (detached as { v: number }).v = 99;
  assertReplayExportSnapshot(cache.exportSnapshot());
  const empty = new ReplayCache({ now: () => REPLAY_EXPORT_NOW }).exportSnapshot();
  if (empty.v !== 1 || empty.entries.length !== 0)
    throw new Error(
      `benchmark self-check failed: empty replay exportSnapshot ${JSON.stringify(empty)} ` +
        `(expected { v: 1, entries: [] })`,
    );
  return measure(() => {
    assertReplayExportSnapshot(cache.exportSnapshot());
  }, ITERATIONS);
}

/** Base instant of the ReplayCache stats fixture (no wall clock). */
const REPLAY_STATS_BASE = 1_700_100_000;
/** TTL of the ReplayCache stats fixture, in seconds. */
const REPLAY_STATS_TTL_SEC = 100;
/** Capacity of the ReplayCache stats fixture. */
const REPLAY_STATS_MAX_ENTRIES = 6;
/** Stats instant: exactly one TTL after the base instant. */
const REPLAY_STATS_NOW = REPLAY_STATS_BASE + REPLAY_STATS_TTL_SEC;
/**
 * Hand-pinned stats of the fixture at REPLAY_STATS_NOW — written
 * literally from the construction script in
 * {@link replayStatsFixture} and cross-checked against the
 * replayStats tests, never derived from `stats()` itself:
 * size counts only the five live entries (the boundary-expired
 * entry still sits in the map), with one hit, seven misses and
 * one LRU eviction accumulated during construction.
 */
const REPLAY_STATS_EXPECTED = { size: 5, hits: 1, misses: 7, evictions: 1 };
/** Live nonces of the stats fixture, recorded 10s before the stats instant. */
const REPLAY_STATS_LIVE_NONCES = [
  "bench-stats-live-00",
  "bench-stats-live-01",
  "bench-stats-live-02",
  "bench-stats-live-03",
];

/**
 * Build the fixed ReplayCache stats fixture: an injectable clock
 * advances only during construction.
 *
 * - At REPLAY_STATS_BASE, `bench-stats-evicted` and
 *   `bench-stats-expired` are recorded (2 misses).
 * - At BASE + 90s, the four live nonces are recorded (4 more
 *   misses; the map is now full at 6), the first live nonce is
 *   checked again (1 hit, refreshing its LRU recency so
 *   `bench-stats-evicted` stays at the head of the map), and
 *   `bench-stats-new` is recorded (1 more miss): making room
 *   LRU-evicts `bench-stats-evicted` — nothing is expired yet
 *   at that instant — (1 eviction).
 * - The clock then advances to REPLAY_STATS_NOW (BASE + TTL)
 *   and stays fixed there: `bench-stats-expired` is now exactly
 *   one TTL old (age >= TTL — the boundary rule the replayStats
 *   tests pin), so it is expired but still sits in the map (no
 *   check has run since, so nothing pruned it), and the five
 *   later nonces are 10 seconds old and live.
 *
 * Every recording must report not-a-replay and the repeat must
 * report a replay.
 */
function replayStatsFixture(): ReplayCache {
  let clock = REPLAY_STATS_BASE;
  const cache = new ReplayCache({
    maxEntries: REPLAY_STATS_MAX_ENTRIES,
    ttlSec: REPLAY_STATS_TTL_SEC,
    now: () => clock,
  });
  for (const nonce of ["bench-stats-evicted", "bench-stats-expired"]) {
    if (cache.check(nonce) !== false)
      throw new Error(
        `benchmark self-check failed: stats-fixture nonce ${nonce} reported as replay`,
      );
  }
  clock = REPLAY_STATS_BASE + REPLAY_STATS_TTL_SEC - 10;
  for (const nonce of REPLAY_STATS_LIVE_NONCES) {
    if (cache.check(nonce) !== false)
      throw new Error(
        `benchmark self-check failed: stats-fixture nonce ${nonce} reported as replay`,
      );
  }
  if (cache.check(REPLAY_STATS_LIVE_NONCES[0]!) !== true)
    throw new Error(
      "benchmark self-check failed: stats-fixture repeat of first live nonce not a replay",
    );
  if (cache.check("bench-stats-new") !== false)
    throw new Error(
      "benchmark self-check failed: stats-fixture nonce bench-stats-new reported as replay",
    );
  clock = REPLAY_STATS_NOW;
  return cache;
}

/**
 * Pin one stats reading of the fixture against the hand-written
 * expectation, item by item, with the `size` getter agreeing.
 */
function assertReplayStats(cache: ReplayCache): void {
  const stats = cache.stats();
  if (
    stats.size !== REPLAY_STATS_EXPECTED.size ||
    stats.hits !== REPLAY_STATS_EXPECTED.hits ||
    stats.misses !== REPLAY_STATS_EXPECTED.misses ||
    stats.evictions !== REPLAY_STATS_EXPECTED.evictions ||
    cache.size !== REPLAY_STATS_EXPECTED.size
  )
    throw new Error(
      `benchmark self-check failed: replay stats ${JSON.stringify(stats)} ` +
        `(expected ${JSON.stringify(REPLAY_STATS_EXPECTED)}, ` +
        `size getter ${cache.size})`,
    );
}

/**
 * `ReplayCache.stats` steady state: every measured call re-reads
 * the observability snapshot of the fixed-clock fixture and
 * re-pins it (see {@link assertReplayStats}) — the live-entry
 * scan against the injected clock plus the detached counter copy
 * a verifier's monitoring pays on every polling tick. `stats()`
 * is a pure read, so the timed loop reuses this one fixture.
 * Outside timing, the detached-copy semantics are asserted
 * (mutating a returned snapshot — every field rewritten to 999 —
 * leaves a re-read unchanged) and an empty cache must report
 * all-zero stats.
 */
function benchmarkReplayCacheStats(): number {
  const cache = replayStatsFixture();
  assertReplayStats(cache);
  const detached = cache.stats();
  detached.size = 999;
  detached.hits = 999;
  detached.misses = 999;
  detached.evictions = 999;
  assertReplayStats(cache);
  const empty = new ReplayCache({ now: () => REPLAY_STATS_NOW }).stats();
  if (
    empty.size !== 0 ||
    empty.hits !== 0 ||
    empty.misses !== 0 ||
    empty.evictions !== 0
  )
    throw new Error(
      `benchmark self-check failed: empty replay stats ${JSON.stringify(empty)} ` +
        `(expected { size: 0, hits: 0, misses: 0, evictions: 0 })`,
    );
  return measure(() => {
    assertReplayStats(cache);
  }, ITERATIONS);
}

/** Export instant of the ReplayCache restore fixture (no wall clock). */
const REPLAY_RESTORE_NOW = 1_700_200_000;
/** TTL of the ReplayCache restore fixture, in seconds. */
const REPLAY_RESTORE_TTL_SEC = 3600;
/**
 * Restore instant used only by the outside-timing expiry check:
 * 200 seconds after the export instant, so the oldest fixture
 * entry (3,500 seconds old at export) is 3,700 seconds old there
 * — past the TTL — while the three later entries are still live.
 */
const REPLAY_RESTORE_EXPIRED_AT = REPLAY_RESTORE_NOW + 200;
/**
 * Hand-pinned live entries of the restore fixture at
 * REPLAY_RESTORE_NOW, in LRU (insertion) order — written
 * literally, never derived from `exportSnapshot` itself.
 */
const REPLAY_RESTORE_EXPECTED: Array<[string, number]> = [
  ["bench-restore-oldest", REPLAY_RESTORE_NOW - 3500],
  ["bench-restore-first", REPLAY_RESTORE_NOW - 30],
  ["bench-restore-second", REPLAY_RESTORE_NOW - 20],
  ["bench-restore-last", REPLAY_RESTORE_NOW - 10],
];
/**
 * Hand-pinned observability reading of a freshly restored fixture
 * cache: all four entries live, and the counters start at zero —
 * a snapshot carries no counters and load-time work is not an
 * eviction (the same rule the replaySnapshot tests pin).
 */
const REPLAY_RESTORE_STATS = { size: 4, hits: 0, misses: 0, evictions: 0 };

/**
 * Build the pinned snapshot for the restore benchmark: an
 * injectable clock is walked through the pinned recording
 * instants and frozen at REPLAY_RESTORE_NOW, the source cache
 * records the four fixture nonces, and its `exportSnapshot()`
 * envelope is the measured input. Every recording must report
 * not-a-replay.
 */
function replayRestoreFixtureSnapshot(): ReturnType<ReplayCache["exportSnapshot"]> {
  let clock = REPLAY_RESTORE_EXPECTED[0]![1];
  const source = new ReplayCache({
    maxEntries: 10_000,
    ttlSec: REPLAY_RESTORE_TTL_SEC,
    now: () => clock,
  });
  for (const [nonce, seenAt] of REPLAY_RESTORE_EXPECTED) {
    clock = seenAt;
    if (source.check(nonce) !== false)
      throw new Error(
        `benchmark self-check failed: restore-fixture nonce ${nonce} reported as replay`,
      );
  }
  clock = REPLAY_RESTORE_NOW;
  const snapshot = source.exportSnapshot();
  assertReplayRestoreSnapshot(snapshot);
  return snapshot;
}

/**
 * Pin one fixture snapshot against the hand-written expectation:
 * version 1 and every entry item by item (nonce and `seenAt`,
 * first and last included).
 */
function assertReplayRestoreSnapshot(
  snapshot: ReturnType<ReplayCache["exportSnapshot"]>,
): void {
  if (snapshot.v !== 1)
    throw new Error(
      `benchmark self-check failed: replay restore snapshot v ${String(snapshot.v)} (expected 1)`,
    );
  if (snapshot.entries.length !== REPLAY_RESTORE_EXPECTED.length)
    throw new Error(
      `benchmark self-check failed: replay restore snapshot carries ${snapshot.entries.length} entries ` +
        `(expected ${REPLAY_RESTORE_EXPECTED.length})`,
    );
  for (let i = 0; i < REPLAY_RESTORE_EXPECTED.length; i++) {
    const entry = snapshot.entries[i]!;
    const [nonce, seenAt] = REPLAY_RESTORE_EXPECTED[i]!;
    if (entry[0] !== nonce || entry[1] !== seenAt)
      throw new Error(
        `benchmark self-check failed: replay restore snapshot entries[${i}] ${JSON.stringify(entry)} ` +
          `(expected ${JSON.stringify([nonce, seenAt])})`,
      );
  }
}

/**
 * Pin one freshly restored fixture cache: the `size` getter and
 * the whole `stats()` reading must equal the hand-written
 * expectation (four live entries, counters still at zero — no
 * `check` has run on the restored cache yet).
 */
function assertReplayRestored(cache: ReplayCache): void {
  const stats = cache.stats();
  if (
    cache.size !== REPLAY_RESTORE_STATS.size ||
    stats.size !== REPLAY_RESTORE_STATS.size ||
    stats.hits !== REPLAY_RESTORE_STATS.hits ||
    stats.misses !== REPLAY_RESTORE_STATS.misses ||
    stats.evictions !== REPLAY_RESTORE_STATS.evictions
  )
    throw new Error(
      `benchmark self-check failed: restored replay stats ${JSON.stringify(stats)} ` +
        `(expected ${JSON.stringify(REPLAY_RESTORE_STATS)}, size getter ${cache.size})`,
    );
}

/** Assert that `fn` throws an `Error` whose message matches `pattern`. */
function assertBenchThrows(fn: () => unknown, pattern: RegExp, label: string): void {
  let matched = false;
  try {
    fn();
  } catch (err) {
    matched = err instanceof Error && pattern.test(err.message);
  }
  if (!matched)
    throw new Error(`benchmark self-check failed: ${label} did not throw ${String(pattern)}`);
}

/**
 * `ReplayCache.fromSnapshot` steady state: every measured call
 * restores the pinned snapshot under a clock frozen at the
 * export instant and re-pins the rebuilt cache (see
 * {@link assertReplayRestored}), then checks every restored
 * nonce — each must still report a replay, so the restart does
 * not reopen the replay window — and the hit counter must
 * advance by exactly the entry count. Outside timing, a restore
 * under a clock advanced past the oldest entry's TTL drops
 * exactly that entry (its nonce records as fresh again while a
 * surviving nonce still replays), and corrupt envelopes — an
 * unsupported version and a malformed entry — throw the pinned
 * configuration errors instead of silently disabling replay
 * protection.
 */
function benchmarkReplayCacheFromSnapshot(): number {
  const snapshot = replayRestoreFixtureSnapshot();
  const opts = { ttlSec: REPLAY_RESTORE_TTL_SEC, now: () => REPLAY_RESTORE_NOW };
  const pre = ReplayCache.fromSnapshot(snapshot, opts);
  assertReplayRestored(pre);
  for (const [nonce] of REPLAY_RESTORE_EXPECTED) {
    if (pre.check(nonce) !== true)
      throw new Error(
        `benchmark self-check failed: restored nonce ${nonce} not a replay`,
      );
  }
  const expired = ReplayCache.fromSnapshot(snapshot, {
    ttlSec: REPLAY_RESTORE_TTL_SEC,
    now: () => REPLAY_RESTORE_EXPIRED_AT,
  });
  if (expired.size !== REPLAY_RESTORE_EXPECTED.length - 1)
    throw new Error(
      `benchmark self-check failed: expired-at-restore size ${expired.size} ` +
        `(expected ${REPLAY_RESTORE_EXPECTED.length - 1})`,
    );
  if (expired.check(REPLAY_RESTORE_EXPECTED[0]![0]) !== false)
    throw new Error(
      "benchmark self-check failed: nonce expired at restore reported as replay",
    );
  if (expired.check(REPLAY_RESTORE_EXPECTED[1]![0]) !== true)
    throw new Error(
      "benchmark self-check failed: surviving nonce after expiry drop not a replay",
    );
  assertBenchThrows(
    () => ReplayCache.fromSnapshot({ v: 2, entries: [] }, opts),
    /invalid snapshot: unsupported snapshot version 2/,
    "wrong-version snapshot",
  );
  assertBenchThrows(
    () => ReplayCache.fromSnapshot({ v: 1, entries: ["bench-restore-first"] }, opts),
    /invalid snapshot: entries\[0\] must be a \[nonce, seenAt\] pair/,
    "malformed-entry snapshot",
  );
  return measure(() => {
    const restored = ReplayCache.fromSnapshot(snapshot, opts);
    assertReplayRestored(restored);
    for (const [nonce] of REPLAY_RESTORE_EXPECTED) {
      if (restored.check(nonce) !== true)
        throw new Error(
          `benchmark self-check failed: restored nonce ${nonce} not a replay`,
        );
    }
    const stats = restored.stats();
    if (stats.hits !== REPLAY_RESTORE_EXPECTED.length || stats.misses !== 0)
      throw new Error(
        `benchmark self-check failed: restored replay counters ${JSON.stringify(stats)} ` +
          `(expected hits=${REPLAY_RESTORE_EXPECTED.length}, misses=0)`,
      );
  }, ITERATIONS);
}

/** Fixed seed for the malformed corpus (same seed as test/parserFuzz). */
const MALFORMED_SEED = 20261005;
/** `created` of the malformed corpus's base signature (fixed, no wall clock). */
const MALFORMED_CREATED = 1_700_000_000;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface MalformedCase {
  kind: string;
  sigInput: string;
  sig: string;
}

/**
 * Deterministic malformed-input corpus for the rejection path, built
 * with the same generation approach as test/parserFuzz.test.ts (fixed
 * mulberry32 seed, truncations / byte-level mutations / hand-built
 * shapes / printable soup over a valid signed request, plus malformed
 * `signature` values and missing headers). Pathological-size cases
 * (multi-KB labels, thousands of members) are deliberately excluded:
 * the fuzz test already pins their per-call latency, and they would
 * dominate a steady-state throughput number.
 */
function buildMalformedCorpus(
  validInput: string,
  validSig: string,
): MalformedCase[] {
  const rand = mulberry32(MALFORMED_SEED);
  const int = (n: number): number => Math.floor(rand() * n);
  const pick = <T,>(arr: readonly T[]): T => arr[int(arr.length)];
  const NASTY = '";=()\\,\' \t\n<>[]{}|~!#$%&*+^`'.split("");
  const mutate = (s: string, edits: number): string => {
    let out = s;
    for (let i = 0; i < edits; i++) {
      const op = int(3);
      if (out.length === 0) {
        out = pick(NASTY);
        continue;
      }
      const pos = int(out.length);
      if (op === 0) out = out.slice(0, pos) + pick(NASTY) + out.slice(pos);
      else if (op === 1) out = out.slice(0, pos) + out.slice(pos + 1);
      else out = out.slice(0, pos) + pick(NASTY) + out.slice(pos + 1);
    }
    return out;
  };
  // Hand-built malformed signature-input shapes (from parserFuzz).
  const SYNTH: readonly string[] = [
    "sig1=",
    'sig1=("a"',
    'sig1=("a" "b"',
    "sig1=(\"a\");created=",
    'sig1=("a");created=abc',
    'sig1=("a");created="yesterday"',
    'sig1="a";created=1',
    'sig1=(("nested"))',
    "sig1=((((",
    'sig1=("unterminated);created=1',
    'sig1=("esc\\',
    'sig1=("bad-escape-\\q");created=1',
    'sig1=("a");created=1\\',
    "=",
    ",",
    "sig1",
    "sig1=;",
    "sig1=( );",
    "sig1=();created=1",
    "sig1=() garbage",
    '"sig1"=("@method");created=1',
    'sig1 = ("@method") ; created = 1',
    'SIG1=("@method");CREATED=1',
    'sig1=("@method");;created=1',
    'sig1=("@method"),,sig2=("@path")',
    'sig1=("@method");created=1,sig2',
    'sig1=("@method");created=1,',
    ',sig1=("@method");created=1',
    'sig1=("@method");keyid=',
    'sig1=("@method");keyid=""',
    'sig1=("@method");keyid="k',
    'sig1=("@method");alg=',
    'sig1=("@method");alg="',
    'sig1=("@method");nonce="\\',
    'sig1=("@method");created=-5',
    'sig1=("@method");created=99999999999999999999999',
    'sig1=("@method");created=0x10',
    'sig1=("@method");created=1.5',
    'sig1=("@method");created=+1',
    'sig1=("@method");created= 1',
    'sig1=("@method");unknown-param',
    'sig1=("@method");=1',
    'sig1=("@method");1=2',
    'sig1=("@CREATE\\d");created=1',
    'sig1=("@method" "@path");created=1',
    'sig1=("@method",);created=1',
    'sig1=(,@method,);created=1',
    'sig1=("@method");created=1;created=2',
    'sig 1=("@method");created=1',
    'sig1 =("@method");created=1',
    'sig-1=("@method");created=1',
    '1sig=("@method");created=1',
    "sig1:=:aGk=:",
    'sig1=("@method");created=1\x00',
  ];
  const SIG_SYNTH: readonly string[] = [
    "sig1=",
    "sig1=:",
    "sig1=::",
    "sig1=:!!!:",
    "sig1=:aGk",
    "sig1=aGk=:",
    "sig1=:aGk=",
    "sig1=:aGk=::extra",
    "sig1=:====:",
    "garbage",
  ];

  const cases: MalformedCase[] = [];
  for (let i = 0; i < 100; i++)
    cases.push({
      kind: "truncation",
      sigInput: validInput.slice(0, int(validInput.length)),
      sig: validSig,
    });
  for (let i = 0; i < 200; i++)
    cases.push({
      kind: "mutation",
      sigInput: mutate(validInput, 1 + int(4)),
      sig: validSig,
    });
  for (const s of SYNTH) cases.push({ kind: "synthetic", sigInput: s, sig: validSig });
  const PRINTABLE = Array.from({ length: 95 }, (_, i) =>
    String.fromCharCode(32 + i),
  );
  const soup = (len: number): string => {
    let s = "";
    for (let i = 0; i < len; i++) s += pick(PRINTABLE);
    return s;
  };
  for (let i = 0; i < 100; i++)
    cases.push({ kind: "soup", sigInput: soup(int(401)), sig: validSig });
  for (const s of SIG_SYNTH)
    cases.push({ kind: "sig-synthetic", sigInput: validInput, sig: s });
  for (let i = 0; i < 100; i++)
    cases.push({
      kind: "sig-mutation",
      sigInput: validInput,
      sig: mutate(validSig, 1 + int(3)),
    });
  cases.push({ kind: "missing-input", sigInput: "", sig: validSig });
  cases.push({ kind: "missing-sig", sigInput: validInput, sig: "" });
  return cases;
}

/**
 * `verifyRequest` rejection-path steady state: measured calls rotate
 * over the fixed malformed corpus, so the mix of parse failures,
 * base-build failures, malformed signature fields and signature
 * mismatches matches the corpus construction on every call.
 *
 * Self-checks (construction consistency, all untimed except the
 * per-call rejection assertion inside the measured loop): the whole
 * corpus is run once before timing — every case must return
 * `{ ok: false, code }` (a throw escapes and fails the bench), the two
 * missing-header cases must carry their exact codes, every
 * sig-synthetic case must fail at the signature field
 * (MALFORMED_SIGNATURE or SIGNATURE_MISMATCH), and
 * MALFORMED_SIGNATURE_INPUT must be the single largest error-code
 * bucket (the corpus is mostly input-side breakage by construction).
 * The measured loop asserts every call rejects, and the rejection
 * count afterwards must equal warmup + timed iterations exactly.
 */
function benchmarkMalformedReject(): { ops: number; corpusSize: number } {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const base: SignedHttpRequest = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: privateKey,
    created: MALFORMED_CREATED,
  });
  const corpus = buildMalformedCorpus(
    base.headers["signature-input"],
    base.headers["signature"],
  );
  const requestFor = (c: MalformedCase): SignedHttpRequest => {
    const headers = { ...base.headers };
    if (c.sigInput !== "") headers["signature-input"] = c.sigInput;
    else delete headers["signature-input"];
    if (c.sig !== "") headers["signature"] = c.sig;
    else delete headers["signature"];
    return { ...fixture, headers };
  };
  const verifyOpts = { key: publicKey, now: MALFORMED_CREATED + 60 };

  const histogram = new Map<string, number>();
  for (const c of corpus) {
    const res = verifyRequest(requestFor(c), verifyOpts);
    if (res.ok || typeof res.code !== "string" || res.code.length === 0)
      throw new Error(
        `benchmark self-check failed: ${c.kind} case was not rejected with a code: ${JSON.stringify(res)}`,
      );
    histogram.set(res.code, (histogram.get(res.code) ?? 0) + 1);
    if (c.kind === "missing-input" && res.code !== "MISSING_SIGNATURE_INPUT")
      throw new Error(
        `benchmark self-check failed: missing-input case gave ${res.code}`,
      );
    if (c.kind === "missing-sig" && res.code !== "MISSING_SIGNATURE")
      throw new Error(
        `benchmark self-check failed: missing-sig case gave ${res.code}`,
      );
    if (
      c.kind === "sig-synthetic" &&
      res.code !== "MALFORMED_SIGNATURE" &&
      res.code !== "SIGNATURE_MISMATCH"
    )
      throw new Error(
        `benchmark self-check failed: sig-synthetic case gave ${res.code}`,
      );
  }
  const malformedInputCount = histogram.get("MALFORMED_SIGNATURE_INPUT") ?? 0;
  for (const [code, count] of histogram) {
    if (code !== "MALFORMED_SIGNATURE_INPUT" && count >= malformedInputCount)
      throw new Error(
        `benchmark self-check failed: code ${code} (${count}) is not below MALFORMED_SIGNATURE_INPUT (${malformedInputCount})`,
      );
  }

  let idx = 0;
  let rejected = 0;
  const ops = measure(() => {
    const res = verifyRequest(requestFor(corpus[idx % corpus.length]), verifyOpts);
    idx++;
    if (res.ok || typeof res.code !== "string" || res.code.length === 0)
      throw new Error(
        "benchmark self-check failed: malformed corpus case verified ok or without a code",
      );
    rejected++;
  }, ITERATIONS);
  if (rejected !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: ${rejected} rejections (expected ${WARMUP + ITERATIONS})`,
    );
  return { ops, corpusSize: corpus.length };
}

/**
 * Expected Content-Digest wire values for the shared fixture body
 * (`JSON.stringify({ amount: 100, currency: "USD" })`, 31 bytes),
 * pinned as literals — never derived from `contentDigest` at bench
 * time:
 * - sha-256: the OpenSSL-derived vector for these exact bytes in
 *   test/contentDigestSha256Openssl.test.ts (openssl dgst -sha256).
 * - sha-512: computed outside this library with
 *   `openssl dgst -sha512` and cross-checked with Python hashlib
 *   (both agreed byte-for-byte) on 2026-10-14.
 * The sha-512 self-check additionally pins the pre-existing golden
 * vector from test/golden.test.ts: contentDigest("hello").
 */
const DIGEST_EXPECTED: Record<ContentDigestAlg, string> = {
  "sha-512":
    "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  "sha-256": "sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:",
};
const DIGEST_HELLO_SHA512 =
  "sha-512=:m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==:";

/**
 * `contentDigest` steady state over the shared fixture body (31
 * bytes, printed in the bench header): the standalone RFC 9530 body
 * hash, isolated from the sign/verify paths that normally bundle it
 * with an asymmetric signature, so a reader can see what hashing a
 * body costs on its own and how sha-512 compares with sha-256 at
 * this size. Self-checks run outside timing: the fixture body must
 * reproduce the pinned wire value for the algorithm, and the
 * sha-512 path must also reproduce the golden "hello" vector.
 */
function benchmarkContentDigest(alg: ContentDigestAlg): number {
  const actual = contentDigest(fixture.body, alg);
  if (actual !== DIGEST_EXPECTED[alg])
    throw new Error(
      `benchmark self-check failed: contentDigest(fixture, ${alg}) gave ${actual} ` +
        `(expected ${DIGEST_EXPECTED[alg]})`,
    );
  if (alg === "sha-512" && contentDigest("hello") !== DIGEST_HELLO_SHA512)
    throw new Error(
      "benchmark self-check failed: contentDigest(\"hello\") sha-512 golden mismatch",
    );
  return measure(() => {
    contentDigest(fixture.body, alg);
  }, ITERATIONS);
}

/**
 * Fixed mock inbound request for the `fromNodeRequest` path — a plain
 * `IncomingRequestLike` test double, NOT a real server (this path
 * performs zero network I/O and never opens a socket; the
 * `fromNodeResponse` section below is the bench's one loopback
 * exception). Composition,
 * item by item:
 * - method POST, origin-form url "/v1/payments?event=charge.succeeded";
 * - `socket.encrypted` true, so the rebuilt absolute URL is https;
 * - seven header entries: Host with a port (mixed-case name),
 *   Content-Type, Content-Digest (the pinned sha-512 wire value of
 *   the shared fixture body — the adapter passes header values
 *   through unvalidated; it never recomputes digests),
 *   Signature-Input / Signature (pass-through strings in the shapes
 *   `verifyRequest` would later parse), one multi-value
 *   X-Forwarded-For whose first element carries padding whitespace
 *   (exercising the per-element trim + ", " join), and one
 *   `undefined` X-Debug-Skip entry (must be dropped);
 * - trailers in BOTH Node forms, mutually consistent: `rawTrailers`
 *   in wire order with a duplicated X-Dup name (must merge to
 *   "a, b"), and the parsed `trailers` object saying the same thing;
 * - body: the shared 31-byte fixture body, passed as the buffered
 *   second argument exactly as a real handler would after `end`.
 */
const NODE_FIXTURE_REQ: IncomingRequestLike = {
  method: "POST",
  url: "/v1/payments?event=charge.succeeded",
  socket: { encrypted: true },
  headers: {
    Host: "gateway.example.com:8443",
    "Content-Type": "application/json",
    "Content-Digest":
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    "Signature-Input":
      'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"',
    Signature: "sig1=:dGVzdA==:",
    "X-Forwarded-For": [" 203.0.113.10 ", "10.0.0.8"],
    "X-Debug-Skip": undefined,
  },
  trailers: { "x-checksum": "trailer-value", "x-dup": ["a", "b"] },
  rawTrailers: [
    "X-Checksum", "trailer-value",
    "X-Dup", "a",
    "x-dup", "b",
  ],
};

/**
 * Hand-pinned expected normalization of NODE_FIXTURE_REQ — written
 * out literally from the adapter's documented rules (absolute-URL
 * rebuild from scheme + verbatim host + origin-form path, header
 * names lowercased, multi-value values trimmed and joined with
 * ", ", `undefined` entries dropped, raw trailers merged by
 * lowercased name), never derived from `fromNodeRequest` at bench
 * time.
 */
const NODE_EXPECTED_URL =
  "https://gateway.example.com:8443/v1/payments?event=charge.succeeded";
const NODE_EXPECTED_HEADERS: Record<string, string> = {
  host: "gateway.example.com:8443",
  "content-type": "application/json",
  "content-digest":
    "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  "signature-input":
    'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"',
  signature: "sig1=:dGVzdA==:",
  "x-forwarded-for": "203.0.113.10, 10.0.0.8",
};
const NODE_EXPECTED_TRAILERS: Record<string, string> = {
  "x-checksum": "trailer-value",
  "x-dup": "a, b",
};

/** Field-by-field equality of a normalized request against the pins above. */
function assertNodeShape(
  actual: ReturnType<typeof fromNodeRequest>,
  label: string,
): void {
  const fail = (what: string): never => {
    throw new Error(`benchmark self-check failed (${label}): ${what}`);
  };
  if (actual.method !== "POST") fail(`method ${actual.method}`);
  if (actual.url !== NODE_EXPECTED_URL) fail(`url ${actual.url}`);
  if (actual.body !== fixture.body) fail("body did not pass through");
  const headerKeys = Object.keys(actual.headers);
  if (headerKeys.length !== Object.keys(NODE_EXPECTED_HEADERS).length)
    fail(`headers ${JSON.stringify(actual.headers)}`);
  for (const [name, value] of Object.entries(NODE_EXPECTED_HEADERS)) {
    if (actual.headers[name] !== value)
      fail(`header ${name} is ${actual.headers[name]} (expected ${value})`);
  }
  if ("x-debug-skip" in actual.headers) fail("undefined header not dropped");
  if ("Host" in actual.headers) fail("header name not lowercased");
  const trailers = actual.trailers;
  if (trailers === undefined)
    throw new Error(
      `benchmark self-check failed (${label}): trailers missing`,
    );
  const trailerKeys = Object.keys(trailers);
  if (trailerKeys.length !== Object.keys(NODE_EXPECTED_TRAILERS).length)
    fail(`trailers ${JSON.stringify(trailers)}`);
  for (const [name, value] of Object.entries(NODE_EXPECTED_TRAILERS)) {
    if (trailers[name] !== value)
      fail(`trailer ${name} is ${trailers[name]} (expected ${value})`);
  }
}

/**
 * `fromNodeRequest` steady state: the inbound normalization a
 * gateway runs on every received request before `verifyRequest` —
 * header folding, absolute-URL rebuild and trailer carry-over over
 * the fixed mock above. Self-checks run outside timing: the fixture
 * must normalize to the hand-pinned expectation field by field; the
 * parsed-trailers-object form (no `rawTrailers`) must produce the
 * identical result; a disagreeing parsed object must lose to
 * `rawTrailers`; and a trailer-less message must gain no `trailers`
 * field at all. The measured loop additionally pins the rebuilt URL
 * on every call.
 */
function benchmarkFromNodeRequest(): number {
  assertNodeShape(
    fromNodeRequest(NODE_FIXTURE_REQ, fixture.body),
    "raw-trailers fixture",
  );
  assertNodeShape(
    fromNodeRequest(
      { ...NODE_FIXTURE_REQ, rawTrailers: undefined },
      fixture.body,
    ),
    "trailers-object fixture",
  );
  const precedence = fromNodeRequest(
    {
      ...NODE_FIXTURE_REQ,
      trailers: { "x-checksum": "stale-object-value" },
    },
    fixture.body,
  );
  if (precedence.trailers?.["x-checksum"] !== "trailer-value")
    throw new Error(
      "benchmark self-check failed: rawTrailers did not take precedence",
    );
  const bare = fromNodeRequest(
    { ...NODE_FIXTURE_REQ, rawTrailers: undefined, trailers: undefined },
    fixture.body,
  );
  if ("trailers" in bare)
    throw new Error(
      "benchmark self-check failed: trailer-less request gained trailers",
    );
  return measure(() => {
    const r = fromNodeRequest(NODE_FIXTURE_REQ, fixture.body);
    if (r.url !== NODE_EXPECTED_URL)
      throw new Error(
        "benchmark self-check failed: fromNodeRequest rebuilt an unexpected URL",
      );
  }, ITERATIONS);
}

/**
 * Pinned shape of the `fromNodeRequest` + `verifyRequest` trailer
 * benchmark: one ed25519 key pair (generated once, outside timing),
 * one fixture signed outside timing covering `x-checksum;tr`
 * alongside `@method`/`@authority`/`@path`, and a Node-shaped
 * incoming double (mixed-case trailer name, so the measured
 * pass also pays the adapter's lowercasing) rebuilt from the
 * signed headers. The verifier's injected `now` sits 60s after
 * `created`, so no wall clock enters the measured loop. This is
 * the request-side mirror of the `fromNodeResponse` adapt+verify
 * row: the existing `fromNodeRequest` row above times only the
 * normalization, never the `;tr` verification it enables.
 */
const NODE_TRAILER_CREATED = 1_700_000_000;
const NODE_TRAILER_NOW = NODE_TRAILER_CREATED + 60;
const NODE_TRAILER_VALUE = "trailer-value";
const NODE_TRAILER_MISMATCH_CODE = "SIGNATURE_MISMATCH";
const NODE_TRAILER_DROPPED_CODE = "SIGNATURE_BASE_BUILD_FAILED";

/**
 * `fromNodeRequest` (with trailers) + `verifyRequest` steady
 * state: the inbound normalization and verification a webhook
 * receiver runs on every trailer-bound callback. One measured op
 * adapts the incoming double and verifies the `;tr`-covered
 * signature, asserting the adapted trailer value and a passing
 * verification on every pass, so a silently dropped trailer
 * cannot produce a fast-but-meaningless number. Outside timing,
 * the negative halves are pinned once: a forged trailer value
 * reports `SIGNATURE_MISMATCH`, a signature received without its
 * trailers fails closed with `SIGNATURE_BASE_BUILD_FAILED`
 * (never silently verified), and a raw-trailers form beats a
 * stale parsed-trailers object, matching the adapter's
 * precedence rule. Zero network, zero randomness in the
 * measured assertions, no wall clock (every verify instant is
 * injected).
 */
function benchmarkVerifyNodeRequestTrailer(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook",
      headers: { "content-type": "application/json" },
      trailers: { "x-checksum": NODE_TRAILER_VALUE },
      body: "hello",
    },
    {
      keyId: "bench-tr-1",
      alg: "ed25519",
      key: privateKey,
      created: NODE_TRAILER_CREATED,
      coveredComponents: ["@method", "@authority", "@path", "x-checksum;tr"],
    },
  );
  const incoming: IncomingRequestLike = {
    method: "POST",
    url: "/webhook",
    socket: { encrypted: true },
    headers: {
      Host: "hooks.example.com",
      "Content-Type": "application/json",
      "Signature-Input": signed.headers["signature-input"] as string,
      Signature: signed.headers["signature"] as string,
    },
    // Mixed-case name exercises the adapter's lowercasing, the same
    // convention it applies to headers.
    trailers: { "X-Checksum": NODE_TRAILER_VALUE },
  };
  const assertTrailerVerify = (where: string): void => {
    const adapted = fromNodeRequest(incoming, "hello");
    if (adapted.trailers?.["x-checksum"] !== NODE_TRAILER_VALUE)
      throw new Error(
        `benchmark self-check failed: fromNodeRequest trailer normalization (${where}) gave ${JSON.stringify(adapted.trailers)}`,
      );
    const res = verifyRequest(adapted, {
      key: publicKey,
      now: NODE_TRAILER_NOW,
    });
    if (!res.ok)
      throw new Error(
        `benchmark self-check failed: ;tr trailer verification (${where}) gave ${JSON.stringify(res)}`,
      );
  };

  // Outside timing: the adapted request verifies with its trailer bound.
  assertTrailerVerify("outside timing");

  // Outside timing: a forged trailer value fails with the pinned code.
  const tampered = fromNodeRequest(
    { ...incoming, trailers: { "x-checksum": "forged-value" } },
    "hello",
  );
  const tamperedRes = verifyRequest(tampered, {
    key: publicKey,
    now: NODE_TRAILER_NOW,
  });
  if (tamperedRes.ok || tamperedRes.code !== NODE_TRAILER_MISMATCH_CODE)
    throw new Error(
      `benchmark self-check failed: forged trailer gave ${JSON.stringify(tamperedRes)}`,
    );

  // Outside timing: a ;tr signature received without its trailers
  // fails closed, never silently verifies.
  const dropped = fromNodeRequest(
    { ...incoming, trailers: undefined },
    "hello",
  );
  const droppedRes = verifyRequest(dropped, {
    key: publicKey,
    now: NODE_TRAILER_NOW,
  });
  if (droppedRes.ok || droppedRes.code !== NODE_TRAILER_DROPPED_CODE)
    throw new Error(
      `benchmark self-check failed: dropped trailer gave ${JSON.stringify(droppedRes)}`,
    );

  // Outside timing: raw trailers beat a stale parsed-trailers object.
  const raw = fromNodeRequest(
    {
      ...incoming,
      trailers: { "x-checksum": "stale-object-value" },
      rawTrailers: ["X-Checksum", NODE_TRAILER_VALUE],
    },
    "hello",
  );
  if (
    raw.trailers?.["x-checksum"] !== NODE_TRAILER_VALUE ||
    !verifyRequest(raw, { key: publicKey, now: NODE_TRAILER_NOW }).ok
  )
    throw new Error(
      "benchmark self-check failed: rawTrailers did not take precedence over the trailers object",
    );

  return measure(() => {
    assertTrailerVerify("measured pass");
  }, ITERATIONS);
}

/**
 * Loopback-signed response for the `fromNodeResponse` path — the
 * gateway-settlement shape a client verifies on every callback: a
 * real `http` server (loopback only, no external network) signs a
 * 200 response covering `@status`, the bound request's `@method`
 * (`;req`), and a settlement trailer (`;tr`), and sends the trailer
 * with `addTrailers` over a chunked response, exactly as the
 * `nodeHttpResponse` test's loopback case does. The signature is
 * created once, outside timing, when the server answers the bench's
 * single client request; the timed loop then re-measures only the
 * client-side work (`fromNodeResponse` + `verifyRequest`) over that
 * captured live response — re-measuring the network per iteration
 * would time TCP loopback, not the adapter, and a live
 * `IncomingMessage` is inert after `end`, so reusing it across
 * passes is sound (the adapter builds a fresh `RequestLike` per
 * call and never mutates the message).
 */
const RESP_CREATED = 1_700_000_000;
const RESP_NOW = RESP_CREATED + 60;
const RESP_STATUS = 200;
const RESP_BODY = JSON.stringify({ settled: true, amount: 100 });
const RESP_TRAILER_NAME = "x-settlement-id";
const RESP_TRAILER_VALUE = "stl_42";
const RESP_COVERED_COMPONENTS: string[] = [
  "@status",
  "@method;req",
  "x-settlement-id;tr",
];

/**
 * `fromNodeResponse` + `verifyRequest` steady state: the
 * response-side normalization and verification a client runs on
 * every gateway-signed settlement callback. Self-checks on every
 * measured pass pin the adapted `@status` (200), the carried-over
 * trailer, and a successful verification requiring `@status`.
 * Asserted outside timing: a response without `statusCode` fails
 * fast with the adapter's pinned message, and transplanting the
 * captured response onto a request with a different method breaks
 * the `;req` binding with a pinned `SIGNATURE_MISMATCH` (the
 * response cannot be replayed against another request).
 */
async function benchmarkFromNodeResponse(): Promise<number> {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const server = createServer((req, res) => {
    const port = (server.address() as AddressInfo).port;
    const request: RequestLike = {
      method: "GET",
      url: `http://127.0.0.1:${port}/settle`,
      headers: { host: `127.0.0.1:${port}` },
    };
    const signed = signRequest(
      {
        method: "GET",
        url: `http://127.0.0.1:${port}/settle`,
        headers: {},
        trailers: { [RESP_TRAILER_NAME]: RESP_TRAILER_VALUE },
        body: RESP_BODY,
        status: RESP_STATUS,
        request,
      },
      {
        keyId: "gateway-key",
        alg: "ed25519",
        key: privateKey,
        created: RESP_CREATED,
        coveredComponents: RESP_COVERED_COMPONENTS,
      },
    );
    res.writeHead(RESP_STATUS, {
      "content-type": "application/json",
      "signature-input": signed.headers["signature-input"] as string,
      signature: signed.headers["signature"] as string,
    });
    res.addTrailers({ [RESP_TRAILER_NAME]: RESP_TRAILER_VALUE });
    res.end(RESP_BODY);
  });
  try {
    const captured = await new Promise<{
      res: IncomingMessage;
      body: Buffer;
      request: RequestLike;
    }>((resolve, reject) => {
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
        const url = `http://127.0.0.1:${port}/settle`;
        const request: RequestLike = {
          method: "GET",
          url,
          headers: { host: `127.0.0.1:${port}` },
        };
        get(url, (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            try {
              resolve({ res, body: Buffer.concat(chunks), request });
            } catch (e) {
              reject(e);
            }
          });
          res.on("error", reject);
        }).on("error", reject);
      });
      server.on("error", reject);
    });
    const { res, body, request } = captured;
    const adapted = fromNodeResponse(res, body, { request });
    if (adapted.status !== RESP_STATUS)
      throw new Error(
        `benchmark self-check failed: fromNodeResponse adapted status ${adapted.status}`,
      );
    if (adapted.trailers?.[RESP_TRAILER_NAME] !== RESP_TRAILER_VALUE)
      throw new Error(
        "benchmark self-check failed: fromNodeResponse dropped the settlement trailer",
      );
    if (adapted.request !== request)
      throw new Error(
        "benchmark self-check failed: fromNodeResponse did not attach the bound request",
      );
    let missingStatusThrew = false;
    try {
      fromNodeResponse({ headers: {} }, RESP_BODY, { request });
    } catch (e) {
      missingStatusThrew =
        e instanceof Error &&
        e.message.startsWith("fromNodeResponse: res.statusCode is missing");
    }
    if (!missingStatusThrew)
      throw new Error(
        "benchmark self-check failed: missing statusCode did not fail fast",
      );
    const transplanted = verifyRequest(
      fromNodeResponse(res, body, {
        request: { ...request, method: "POST" },
      }),
      { key: publicKey, now: RESP_NOW },
    );
    if (transplanted.ok || transplanted.code !== "SIGNATURE_MISMATCH")
      throw new Error(
        `benchmark self-check failed: transplanted response verified as ${JSON.stringify(transplanted)}`,
      );
    return measure(() => {
      const r = fromNodeResponse(res, body, { request });
      if (r.status !== RESP_STATUS)
        throw new Error(
          "benchmark self-check failed: fromNodeResponse adapted an unexpected status",
        );
      if (r.trailers?.[RESP_TRAILER_NAME] !== RESP_TRAILER_VALUE)
        throw new Error(
          "benchmark self-check failed: fromNodeResponse dropped the settlement trailer",
        );
      const result = verifyRequest(r, {
        key: publicKey,
        now: RESP_NOW,
        requiredComponents: ["@status"],
      });
      if (!result.ok)
        throw new Error(
          `benchmark self-check failed: loopback response did not verify (${result.code})`,
        );
    }, ITERATIONS);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/**
 * Per-curve JWK round-trip steady state: for one key shape, a measured
 * call runs `exportPublicKeyJwk*` on a fixed public key, pushes the
 * JWK through a JSON stringify/parse round trip (the wire form a JWKS
 * document actually travels in), and re-imports it with
 * `importPublicKeyJwk*` — the key-distribution work a publisher pays
 * when serializing a key set and a verifier pays when loading one,
 * for the shapes the generic ed25519-only `exportPublicKeyJwk` does
 * not cover.
 *
 * Fixture caliber (fixed, stated here as the backlog requires): one
 * fresh key pair per shape, generated ONCE before timing with the
 * library's own generators — P-256 / P-384 / P-521 via
 * generateP256KeyPair / generateP384KeyPair / generateP521KeyPair,
 * RSA via generateRsaPssKeyPair (2048-bit modulus, the library
 * default; the RSA JWK carries no `alg`, so this one round trip
 * serves both `rsa-pss-sha512` and `rsa-v1_5-sha256`). The keys are
 * random per bench run, but nothing measured depends on their values
 * and the only assertion is the round-trip property below — no wall
 * clock, no network.
 *
 * Self-check (outside timing): the re-imported key's SPKI DER
 * encoding — produced by node:crypto directly, independently of the
 * JWK helpers — must equal the original public key's DER
 * byte-for-byte, for every shape.
 *
 * The optional `checkJwk` hook runs on every exported JWK — the
 * outside-timing pass and every measured pass — for shapes whose
 * wire form carries a hand-pinned shape worth re-pinning per call
 * (the ed25519 OKP shape; see {@link benchmarkJwkRoundTripEd25519}).
 * The four EC / RSA rows pass no hook and keep their original
 * measured shape.
 */
function benchmarkJwkRoundTrip(
  shape: string,
  publicKey: KeyObject,
  exportJwk: (key: KeyObject) => unknown,
  importJwk: (jwk: unknown) => KeyObject,
  checkJwk?: (jwk: unknown) => void,
): number {
  const originalDer = publicKey.export({ format: "der", type: "spki" });
  const exported = exportJwk(publicKey);
  checkJwk?.(exported);
  const revived = importJwk(JSON.parse(JSON.stringify(exported)));
  const revivedDer = revived.export({ format: "der", type: "spki" });
  if (!originalDer.equals(revivedDer))
    throw new Error(
      `benchmark self-check failed: ${shape} JWK round trip changed the key ` +
        `(re-imported DER ${revivedDer.length} bytes, original ${originalDer.length} bytes)`,
    );
  return measure(() => {
    const jwk = exportJwk(publicKey);
    checkJwk?.(jwk);
    importJwk(JSON.parse(JSON.stringify(jwk)));
  }, ITERATIONS);
}

/** Fixed `created` for the ed25519 JWK path's outside-timing sign → verify. */
const JWK_ED25519_CREATED = 1_700_000_000;

/**
 * Hand-pinned shape of the ed25519 public JWK the generic
 * `exportPublicKeyJwk` must produce on every call: exactly the
 * RFC 8037 OKP form a JWKS document distributes for the library's
 * default algorithm — `kty` "OKP", `crv` "Ed25519", a non-empty
 * base64url `x`, and no private `d` field (public-key distribution
 * only). Written out here, never derived from the exported value
 * the bench is checking.
 */
function checkEd25519Jwk(jwk: unknown): void {
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk))
    throw new Error(
      "benchmark self-check failed: ed25519 JWK round trip exported a non-object JWK",
    );
  const o = jwk as Record<string, unknown>;
  if (o["kty"] !== "OKP")
    throw new Error(
      `benchmark self-check failed: ed25519 JWK kty ${JSON.stringify(o["kty"])} (expected "OKP")`,
    );
  if (o["crv"] !== "Ed25519")
    throw new Error(
      `benchmark self-check failed: ed25519 JWK crv ${JSON.stringify(o["crv"])} (expected "Ed25519")`,
    );
  if ("d" in o)
    throw new Error(
      'benchmark self-check failed: ed25519 JWK carries private material ("d")',
    );
  if (typeof o["x"] !== "string" || o["x"].length === 0)
    throw new Error(
      "benchmark self-check failed: ed25519 JWK x is missing or empty",
    );
}

/**
 * ed25519 JWK round-trip steady state: the generic
 * `exportPublicKeyJwk` → JSON stringify/parse → `importPublicKeyJwk`
 * round trip over one fixed ed25519 key pair — the key-distribution
 * work a JWKS publisher pays when serializing the library's default
 * algorithm and a verifier pays when loading it, in the OKP JWK
 * shape the JWKS documentation distributes. The EC / RSA rows above
 * cover the per-curve helpers; this row covers the generic pair the
 * PEM row does not (PEM is the other encoding of the same key).
 *
 * Fixture caliber (fixed, stated here as the backlog requires):
 * one ed25519 key pair generated ONCE before timing with the
 * library's own `generateEd25519KeyPair`. The key is random per
 * bench run, but nothing measured depends on its value and no
 * assertion names a random value — no wall clock, no network.
 *
 * Self-checks: every measured pass re-exports the JWK and re-pins
 * its shape item by item via {@link checkEd25519Jwk} before
 * re-importing (through the shared {@link benchmarkJwkRoundTrip}
 * helper, whose outside-timing SPKI DER equality also applies);
 * outside timing, the re-imported public key must verify a
 * signature made with the original private key over the shared
 * fixture (created pinned at JWK_ED25519_CREATED, verified at
 * created+60) — the same sign → verify assertion shape the PEM
 * round-trip row makes for its re-imported keys.
 */
function benchmarkJwkRoundTripEd25519(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const revived = importPublicKeyJwk(
    JSON.parse(JSON.stringify(exportPublicKeyJwk(publicKey))),
  );
  const signed = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: privateKey,
    created: JWK_ED25519_CREATED,
  });
  const verified = verifyRequest(signed, {
    key: revived,
    now: JWK_ED25519_CREATED + 60,
  });
  if (!verified.ok)
    throw new Error(
      `benchmark self-check failed: ed25519 JWK round-trip sign → verify gave ` +
        `${verified.code}: ${verified.reason}`,
    );
  return benchmarkJwkRoundTrip(
    "ed25519",
    publicKey,
    exportPublicKeyJwk,
    importPublicKeyJwk,
    checkEd25519Jwk,
  );
}

/**
 * Hand-pinned first lines (PEM type headers) for the PEM round-trip
 * path: `exportPublicKeyPem` exports in SPKI form, whose PEM header
 * is `-----BEGIN PUBLIC KEY-----`, and `exportPrivateKeyPem`
 * exports in PKCS#8 form, whose PEM header is
 * `-----BEGIN PRIVATE KEY-----` — the formats written literally in
 * `src/keys.ts` (spki / pkcs8), the same expectations the CLI demo
 * pins as DEMO_PEM_PUBLIC_HEADER / DEMO_PEM_PRIVATE_HEADER. Written
 * out here, never derived from the exported text the bench is
 * checking.
 */
const PEM_PUBLIC_HEADER = "-----BEGIN PUBLIC KEY-----";
const PEM_PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----";
/** Fixed `created` for the PEM path's outside-timing sign → verify. */
const PEM_CREATED = 1_700_000_000;

/**
 * One PEM round trip over a fixed ed25519 key pair: export both
 * PEMs and re-import both keys, asserting the two hand-pinned type
 * headers and that the re-imported public key's JWK thumbprint
 * (RFC 7638, over the generic `exportPublicKeyJwk` form) equals the
 * original public key's — the fingerprint identity check a receiver
 * runs before trusting a re-imported key. Returns the re-imported
 * pair so the caller can additionally sign → verify with it outside
 * timing.
 */
function pemRoundTripOnce(
  publicKey: KeyObject,
  privateKey: KeyObject,
  expectedThumbprint: string,
  label: string,
): { revivedPublic: KeyObject; revivedPrivate: KeyObject } {
  const pemPublic = exportPublicKeyPem(publicKey);
  const pemPrivate = exportPrivateKeyPem(privateKey);
  const publicHeader = pemPublic.split("\n")[0] ?? "";
  const privateHeader = pemPrivate.split("\n")[0] ?? "";
  if (publicHeader !== PEM_PUBLIC_HEADER)
    throw new Error(
      `benchmark self-check failed (${label}): public PEM header ` +
        `${JSON.stringify(publicHeader)} (expected ${JSON.stringify(PEM_PUBLIC_HEADER)})`,
    );
  if (privateHeader !== PEM_PRIVATE_HEADER)
    throw new Error(
      `benchmark self-check failed (${label}): private PEM header ` +
        `${JSON.stringify(privateHeader)} (expected ${JSON.stringify(PEM_PRIVATE_HEADER)})`,
    );
  const revivedPublic = importPublicKey(pemPublic);
  const revivedPrivate = importPrivateKey(pemPrivate);
  const revivedThumbprint = jwkThumbprint(exportPublicKeyJwk(revivedPublic));
  if (revivedThumbprint !== expectedThumbprint)
    throw new Error(
      `benchmark self-check failed (${label}): re-imported public key ` +
        `thumbprint ${revivedThumbprint} (expected ${expectedThumbprint})`,
    );
  return { revivedPublic, revivedPrivate };
}

/**
 * PEM round-trip steady state: one measured call exports the fixed
 * ed25519 pair as PEM (SPKI public / PKCS#8 private) and re-imports
 * both keys — the key-handover work a signer pays when shipping
 * keys to a gateway / KMS / peer verifier as PEM files and the
 * receiver pays when loading them, in the encoding the JWK
 * round-trip rows above do not cover.
 *
 * Fixture caliber (fixed, stated here as the backlog requires):
 * one ed25519 key pair — the same shape the CLI demo's PEM segment
 * round-trips — generated ONCE before timing with the library's own
 * `generateEd25519KeyPair`. The key is random per bench run, but
 * nothing measured depends on its value: the only assertions are
 * the round-trip properties (pinned PEM type headers, thumbprint
 * identity) and the outside-timing sign → verify below — no wall
 * clock, no network, no assertion on a random value.
 *
 * Self-checks: every measured pass re-runs the full round trip with
 * its header and thumbprint assertions (see `pemRoundTripOnce`);
 * outside timing, the keys re-imported by one such round trip must
 * complete a sign → verify over the shared fixture (created pinned
 * at PEM_CREATED, verified at created+60).
 */
function benchmarkPemRoundTrip(): number {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const expectedThumbprint = jwkThumbprint(exportPublicKeyJwk(publicKey));
  const { revivedPublic, revivedPrivate } = pemRoundTripOnce(
    publicKey,
    privateKey,
    expectedThumbprint,
    "outside timing",
  );
  const signed = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: revivedPrivate,
    created: PEM_CREATED,
  });
  const verified = verifyRequest(signed, {
    key: revivedPublic,
    now: PEM_CREATED + 60,
  });
  if (!verified.ok)
    throw new Error(
      `benchmark self-check failed: PEM round-trip sign → verify gave ` +
        `${verified.code}: ${verified.reason}`,
    );
  return measure(() => {
    pemRoundTripOnce(publicKey, privateKey, expectedThumbprint, "measured pass");
  }, ITERATIONS);
}

/**
 * Fixed covered set for the `buildSignatureBase` path — the same
 * set the bench header names for the sign/verify scenarios
 * (`@method @authority @path content-digest`).
 */
const BASE_COMPONENTS = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
] as const;

/** Fixed signature parameters for the base path (no wall clock). */
const BASE_PARAMS: SignatureParams = {
  created: 1_700_000_000,
  keyid: "bench-key",
  alg: "ed25519",
};

/**
 * Fixed request for the base path: the shared bench fixture (same
 * method / URL / body shape as every other path), with the
 * `content-digest` header the covered set resolves — its value is
 * the pinned sha-512 wire value of the fixture body from
 * DIGEST_EXPECTED above, written out literally here.
 */
const BASE_REQUEST: RequestLike = {
  method: fixture.method,
  url: fixture.url,
  headers: {
    "content-type": "application/json",
    "content-digest":
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  },
  body: fixture.body,
};

/**
 * Hand-written expected signature base for BASE_REQUEST /
 * BASE_COMPONENTS / BASE_PARAMS — written out literally from the
 * RFC 9421 §2.5 rules (one `"id": value` line per covered component:
 * method uppercased, authority lowercased host, path alone, the
 * digest header value verbatim; then the `@signature-params` line
 * with parameters in created / keyid / alg order), in the same
 * hand-pinned style as the golden vector in test/golden.test.ts.
 * Never derived from `buildSignatureBase` at bench time.
 */
const BASE_EXPECTED =
  `"@method": POST\n` +
  `"@authority": api.example.com\n` +
  `"@path": /v1/payments\n` +
  `"content-digest": sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:\n` +
  `"@signature-params": ("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"`;

/**
 * `buildSignatureBase` steady state: the pure string-building step
 * every sign and verify pays before any cryptography — resolving
 * each covered component against the fixture request and
 * serializing the `"@signature-params"` line. Isolated here so a
 * reader can see what base construction costs on its own and how
 * much of a sign/verify number is cryptography versus base
 * building. Self-check outside timing: the built base must equal
 * BASE_EXPECTED byte-for-byte; the measured loop re-pins the full
 * text on every call. Zero network, zero randomness, no wall-clock
 * assertions.
 */
function benchmarkBuildSignatureBase(): number {
  const actual = buildSignatureBase(
    [...BASE_COMPONENTS],
    BASE_REQUEST,
    BASE_PARAMS,
  );
  if (actual !== BASE_EXPECTED)
    throw new Error(
      `benchmark self-check failed: buildSignatureBase gave ${JSON.stringify(actual)} ` +
        `(expected ${JSON.stringify(BASE_EXPECTED)})`,
    );
  return measure(() => {
    const base = buildSignatureBase(
      [...BASE_COMPONENTS],
      BASE_REQUEST,
      BASE_PARAMS,
    );
    if (base !== BASE_EXPECTED)
      throw new Error(
        "benchmark self-check failed: buildSignatureBase diverged from the pinned base text",
      );
  }, ITERATIONS);
}

/** Fixed `created` for the signRequest fixture (no wall clock). */
const SIGNREQ_CREATED = 1_700_000_000;
/**
 * Hand-pinned label expectation for the signRequest path — written
 * here as a literal, independently of the sign call below (which
 * omits `label`, so the value on the wire is the library's default
 * `sig1`): changing this expectation alone must fail the bench.
 */
const SIGNREQ_EXPECTED_LABEL = "sig1";
/**
 * Hand-pinned full `signature-input` value for the signRequest
 * fixture — written out literally from the RFC 9421 §2.3
 * serialization (the fixed four covered components named in the
 * bench header, parameters in created / keyid / alg order), in
 * the same hand-pinned style as BASE_EXPECTED above. Never
 * derived from `signRequest` at bench time.
 */
const SIGNREQ_EXPECTED_INPUT =
  'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="bench-key";alg="ed25519"';
/**
 * Pinned failure code for the tampered signRequest fixture —
 * written here as a literal, from the verify contract: changing
 * the body after signing leaves the signature itself intact but
 * breaks the covered `content-digest`, so the code is
 * BODY_DIGEST_MISMATCH (the same pin the CLI demo's curve
 * segments and the ecdsa test suites use for a one-byte body
 * tamper).
 */
const SIGNREQ_TAMPERED_CODE = "BODY_DIGEST_MISMATCH";
/** Tampered body for the signRequest fixture: amount 100 -> 101. */
const SIGNREQ_TAMPERED_BODY = JSON.stringify({
  amount: 101,
  currency: "USD",
});

/**
 * Fixed fixture for the `signRequest` end-to-end path: one
 * ed25519 key pair generated once at bench start (outside
 * timing; the key is random per bench run, but nothing measured
 * or asserted depends on its value — ed25519 signing is
 * deterministic per key/message, and the only pinned wire
 * shapes are the label, the `signature-input` value and the
 * 64-byte signature length), signing the shared fixture with
 * `created` pinned at SIGNREQ_CREATED and verifying at
 * created+60 — no wall clock, zero network.
 */
function buildSignRequestFixture(): {
  signOpts: Parameters<typeof signRequest>[1];
  verifyOpts: {
    key: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
    now: number;
  };
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  return {
    signOpts: {
      keyId: "bench-key",
      alg: "ed25519",
      key: privateKey,
      created: SIGNREQ_CREATED,
    },
    verifyOpts: { key: publicKey, now: SIGNREQ_CREATED + 60 },
  };
}

/**
 * Shape checks every signed output of the signRequest fixture
 * must pass, on the outside-timing pass and on every measured
 * pass alike: both signature headers present, the
 * `signature-input` value equal to the hand-pinned
 * SIGNREQ_EXPECTED_INPUT byte-for-byte, the label list exactly
 * [SIGNREQ_EXPECTED_LABEL], the `content-digest` header equal
 * to the pinned fixture digest carried by BASE_REQUEST, and the
 * `signature` value a single `sig1=:base64:` member decoding to
 * the 64 bytes an ed25519 signature occupies. No key or
 * signature bytes are ever printed.
 */
function checkSignedShape(signed: SignedHttpRequest, label: string): void {
  const input = signed.headers["signature-input"];
  const signature = signed.headers["signature"];
  if (typeof input !== "string" || typeof signature !== "string")
    throw new Error(
      `benchmark self-check failed (${label}): signRequest output is missing a signature header`,
    );
  if (input !== SIGNREQ_EXPECTED_INPUT)
    throw new Error(
      `benchmark self-check failed (${label}): signature-input ${JSON.stringify(input)} ` +
        `(expected ${JSON.stringify(SIGNREQ_EXPECTED_INPUT)})`,
    );
  const labels = listSignatureLabels(input);
  if (labels.length !== 1 || labels[0] !== SIGNREQ_EXPECTED_LABEL)
    throw new Error(
      `benchmark self-check failed (${label}): labels ${JSON.stringify(labels)} ` +
        `(expected ["${SIGNREQ_EXPECTED_LABEL}"])`,
    );
  if (signed.headers["content-digest"] !== BASE_REQUEST.headers["content-digest"])
    throw new Error(
      `benchmark self-check failed (${label}): content-digest diverged from the pinned fixture digest`,
    );
  const m = /^sig1=:([A-Za-z0-9+/=]+):$/.exec(signature);
  if (m === null || Buffer.from(m[1], "base64").length !== 64)
    throw new Error(
      `benchmark self-check failed (${label}): signature is not a single 64-byte ed25519 member`,
    );
}

/**
 * Exhaustive outside-timing assertion for the signRequest
 * fixture: a fresh signed request passes the shape checks, is
 * verified by `verifyRequest` with the pinned identity (label /
 * keyid / alg), and the same request with its body tampered by
 * one byte (amount 100 -> 101, the demo/test tamper shape) is
 * rejected with the pinned SIGNREQ_TAMPERED_CODE.
 */
function assertSignRequestFixture(
  fx: ReturnType<typeof buildSignRequestFixture>,
): void {
  const signed = signRequest(fixture, fx.signOpts);
  checkSignedShape(signed, "outside timing");
  const verified = verifyRequest(signed, fx.verifyOpts);
  if (
    !verified.ok ||
    verified.label !== SIGNREQ_EXPECTED_LABEL ||
    verified.keyId !== "bench-key" ||
    verified.alg !== "ed25519"
  )
    throw new Error(
      `benchmark self-check failed: verifyRequest(signRequest) gave ${JSON.stringify(verified)}`,
    );
  const tampered: SignedHttpRequest = { ...signed, body: SIGNREQ_TAMPERED_BODY };
  const rejected = verifyRequest(tampered, fx.verifyOpts);
  if (rejected.ok || rejected.code !== SIGNREQ_TAMPERED_CODE)
    throw new Error(
      `benchmark self-check failed: tampered signRequest output gave ${JSON.stringify(rejected)} ` +
        `(expected code ${SIGNREQ_TAMPERED_CODE})`,
    );
}

/**
 * `signRequest` end-to-end steady state: one measured call is
 * one complete signing of the shared fixture — signature-base
 * construction, the ed25519 cryptography and the
 * `signature-input` / `signature` header serialization — the
 * total a signer pays per request, isolated as its own checked
 * row. The per-algorithm scenario rows at the top of the bench
 * also time `signRequest`, but they discard the output
 * unchecked; here every measured pass re-pins the full output
 * shape (see checkSignedShape), and the verify / tamper
 * assertions run exhaustively outside timing (in the
 * PEM-round-trip row's style, so the measured number stays the
 * sign cost alone, not a sign+verify pair). Zero network, the
 * only randomness is the one key pair generated outside timing,
 * no wall-clock assertions, no key bytes printed.
 */
function benchmarkSignRequest(): number {
  const fx = buildSignRequestFixture();
  assertSignRequestFixture(fx);
  return measure(() => {
    const signed = signRequest(fixture, fx.signOpts);
    checkSignedShape(signed, "measured pass");
  }, ITERATIONS);
}

/**
 * Fixed dual-label wire fixture for the standalone-parser paths —
 * written out literally here, NOT produced by `signRequest` at
 * bench time, so the expected parse shapes pinned below are
 * checked against the wire text itself:
 * - `signature-input`: two members. `merchant` covers
 *   `@method @authority @path content-digest` with parameters
 *   created=1700000000, keyid="merchant-key", alg="ed25519",
 *   nonce="bench-nonce" (no expires). `gateway` covers
 *   `@method @authority content-type` with parameters
 *   created=1700000060, expires=1700003600, keyid="gateway-key",
 *   alg="hmac-sha256" (no nonce).
 * - `signature`: the `merchant` member is the base64 of the 16
 *   bytes 0,1,…,15; the `gateway` member is the base64 of the
 *   11 ASCII bytes `hello-world`. Neither value is a real
 *   signature — the parsers never verify, they only decode.
 */
const PARSER_INPUT =
  'merchant=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="merchant-key";alg="ed25519";nonce="bench-nonce", ' +
  'gateway=("@method" "@authority" "content-type");created=1700000060;expires=1700003600;keyid="gateway-key";alg="hmac-sha256"';
const PARSER_SIG =
  "merchant=:AAECAwQFBgcICQoLDA0ODw==:, gateway=:aGVsbG8td29ybGQ=:";

/** Hand-pinned parse shapes for the fixture above. */
const PARSER_EXPECTED_LABELS = ["merchant", "gateway"] as const;
const PARSER_EXPECTED_MERCHANT_COMPONENTS = [
  "@method",
  "@authority",
  "@path",
  "content-digest",
] as const;
const PARSER_EXPECTED_GATEWAY_COMPONENTS = [
  "@method",
  "@authority",
  "content-type",
] as const;
const PARSER_EXPECTED_MERCHANT_BYTES = Buffer.from([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
]);
const PARSER_EXPECTED_GATEWAY_BYTES = Buffer.from("hello-world", "utf8");

/**
 * Hand-pinned malformed set for the standalone parsers: every entry
 * must throw, with a message containing the pinned substring.
 * (The two `parseSignatureField` shape cases report "not present"
 * because that parser's only failure mode is finding no
 * `:base64:` member for the label — pinned as its actual contract.)
 */
const PARSER_MALFORMED: ReadonlyArray<{
  name: string;
  run: () => unknown;
  message: string;
}> = [
  {
    name: "listSignatureLabels empty value",
    run: () => listSignatureLabels(""),
    message: "malformed Signature-Input member",
  },
  {
    name: "listSignatureLabels trailing empty member",
    run: () => listSignatureLabels('sig1=("@method");created=1, ,'),
    message: "malformed Signature-Input member",
  },
  {
    name: "parseSignatureInput unknown label",
    run: () => parseSignatureInput(PARSER_INPUT, "missing"),
    message: "not present in Signature-Input",
  },
  {
    name: "parseSignatureInput unterminated inner list",
    run: () => parseSignatureInput('sig1=("a"', "sig1"),
    message: "unterminated inner list",
  },
  {
    name: "parseSignatureInput missing inner list",
    run: () => parseSignatureInput('sig1="a";created=1', "sig1"),
    message: "expected inner list",
  },
  {
    name: "parseSignatureField unknown label",
    run: () => parseSignatureField(PARSER_SIG, "missing"),
    message: "not present in Signature field",
  },
  {
    name: "parseSignatureField non-base64 member value",
    run: () => parseSignatureField("merchant=:!!!:", "merchant"),
    message: "not present in Signature field",
  },
  {
    name: "parseSignatureField member without colons",
    run: () => parseSignatureField("merchant=aGk=", "merchant"),
    message: "not present in Signature field",
  },
];

function assertParserComponents(
  actual: readonly string[],
  expected: readonly string[],
  what: string,
): void {
  if (
    actual.length !== expected.length ||
    actual.some((v, i) => v !== expected[i])
  )
    throw new Error(
      `benchmark self-check failed: ${what} parsed to ${JSON.stringify(actual)} ` +
        `(expected ${JSON.stringify(expected)})`,
    );
}

/**
 * Outside-timing self-checks for the standalone-parser fixture:
 * the label list, both members' component lists and every pinned
 * parameter, both members' decoded bytes, and the whole malformed
 * set (each entry must throw with its pinned message substring).
 */
function assertParserFixture(): void {
  const labels = listSignatureLabels(PARSER_INPUT);
  assertParserComponents(labels, PARSER_EXPECTED_LABELS, "label list");

  const merchant = parseSignatureInput(PARSER_INPUT, "merchant");
  if (merchant.label !== "merchant")
    throw new Error("benchmark self-check failed: merchant label mismatch");
  assertParserComponents(
    merchant.componentIds,
    PARSER_EXPECTED_MERCHANT_COMPONENTS,
    "merchant components",
  );
  if (
    merchant.params.created !== 1700000000 ||
    merchant.params.keyid !== "merchant-key" ||
    merchant.params.alg !== "ed25519" ||
    merchant.params.nonce !== "bench-nonce" ||
    merchant.params.expires !== undefined
  )
    throw new Error(
      `benchmark self-check failed: merchant params ${JSON.stringify(merchant.params)}`,
    );

  const gateway = parseSignatureInput(PARSER_INPUT, "gateway");
  if (gateway.label !== "gateway")
    throw new Error("benchmark self-check failed: gateway label mismatch");
  assertParserComponents(
    gateway.componentIds,
    PARSER_EXPECTED_GATEWAY_COMPONENTS,
    "gateway components",
  );
  if (
    gateway.params.created !== 1700000060 ||
    gateway.params.expires !== 1700003600 ||
    gateway.params.keyid !== "gateway-key" ||
    gateway.params.alg !== "hmac-sha256" ||
    gateway.params.nonce !== undefined
  )
    throw new Error(
      `benchmark self-check failed: gateway params ${JSON.stringify(gateway.params)}`,
    );

  if (!parseSignatureField(PARSER_SIG, "merchant").equals(PARSER_EXPECTED_MERCHANT_BYTES))
    throw new Error(
      "benchmark self-check failed: merchant signature bytes mismatch",
    );
  if (!parseSignatureField(PARSER_SIG, "gateway").equals(PARSER_EXPECTED_GATEWAY_BYTES))
    throw new Error(
      "benchmark self-check failed: gateway signature bytes mismatch",
    );

  for (const bad of PARSER_MALFORMED) {
    let thrown: unknown;
    try {
      bad.run();
    } catch (e) {
      thrown = e;
    }
    if (!(thrown instanceof Error) || !thrown.message.includes(bad.message))
      throw new Error(
        `benchmark self-check failed: ${bad.name} did not throw "${bad.message}" ` +
          `(got ${thrown instanceof Error ? JSON.stringify(thrown.message) : "no throw"})`,
      );
  }
}

/**
 * Standalone-parser steady states: each measured call runs ONE of
 * the three parsers over the valid dual-label fixture above (the
 * three are reported as separate rows, matching the table) and
 * re-pins the core of its expected result on every call. This is
 * the pre-screening work a gateway does before any cryptography —
 * splitting labels, parsing one member's covered components and
 * parameters, decoding one member's signature bytes — isolated
 * from the end-to-end `verifyRequest` paths that bundle it with
 * base building and crypto. Zero network, zero randomness, no
 * wall-clock assertions.
 */
function benchmarkListSignatureLabels(): number {
  assertParserFixture();
  return measure(() => {
    const labels = listSignatureLabels(PARSER_INPUT);
    if (
      labels.length !== 2 ||
      labels[0] !== "merchant" ||
      labels[1] !== "gateway"
    )
      throw new Error(
        "benchmark self-check failed: listSignatureLabels diverged from the pinned labels",
      );
  }, ITERATIONS);
}

function benchmarkParseSignatureInput(): number {
  assertParserFixture();
  return measure(() => {
    const parsed = parseSignatureInput(PARSER_INPUT, "merchant");
    if (
      parsed.componentIds.length !== 4 ||
      parsed.componentIds[3] !== "content-digest" ||
      parsed.params.created !== 1700000000 ||
      parsed.params.keyid !== "merchant-key" ||
      parsed.params.nonce !== "bench-nonce"
    )
      throw new Error(
        "benchmark self-check failed: parseSignatureInput diverged from the pinned shape",
      );
  }, ITERATIONS);
}

function benchmarkParseSignatureField(): number {
  assertParserFixture();
  return measure(() => {
    const bytes = parseSignatureField(PARSER_SIG, "merchant");
    if (!bytes.equals(PARSER_EXPECTED_MERCHANT_BYTES))
      throw new Error(
        "benchmark self-check failed: parseSignatureField diverged from the pinned bytes",
      );
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `canonicalizeStructuredFieldValue` path —
 * six values written out literally here, covering the three shapes
 * the function tries (Dictionary, then List, then Item) and the
 * normalization boundaries a gateway's `;sf` values actually hit.
 * Every expected serialization is hand-pinned below from the
 * RFC 8941 §4 strict-serialization rules (and matches the values
 * pinned independently in test/sfComponent.test.ts) — never
 * derived from `canonicalizeStructuredFieldValue` at bench time:
 * - dict-decimal: a Dictionary whose second member is a Decimal —
 *   decimals serialize with exactly three fractional digits
 *   (`1.5` → `1.500`); the Integer member is already canonical.
 * - dict-params-inner-list: a Dictionary with sloppy spacing,
 *   member parameters, and an Inner List — separators collapse
 *   to `, ` between members and `;` with no space before each
 *   parameter, inner-list items join with a single space.
 * - list-strings: a List of two Strings — the member separator
 *   collapses to `, ` regardless of the wire spacing.
 * - item-decimal: a lone Decimal Item — same three-digit rule.
 * - item-leading-zero-int: a lone Integer Item with leading
 *   zeros — integers serialize as the bare number (`007` → `7`).
 * - dict-byte-sequence: a Dictionary member holding a Byte
 *   Sequence with a Boolean parameter — the base64 is re-encoded
 *   canonically (this value is already canonical, so input and
 *   expectation coincide) and `?0` stays `?0`.
 */
const SF_FIXTURE: ReadonlyArray<{
  name: string;
  input: string;
  expected: string;
}> = [
  {
    name: "dict-decimal",
    input: "limit=1500, remaining=1.5",
    expected: "limit=1500, remaining=1.500",
  },
  {
    name: "dict-params-inner-list",
    input: "a=1,  b=2;x=1;  y=2, c=(a   b  c)",
    expected: "a=1, b=2;x=1;y=2, c=(a b c)",
  },
  {
    name: "list-strings",
    input: '"a" ,  "b"',
    expected: '"a", "b"',
  },
  {
    name: "item-decimal",
    input: "1.5",
    expected: "1.500",
  },
  {
    name: "item-leading-zero-int",
    input: "007",
    expected: "7",
  },
  {
    name: "dict-byte-sequence",
    input: "sig=:aGVsbG8=:;x=?0",
    expected: "sig=:aGVsbG8=:;x=?0",
  },
];

/**
 * `canonicalizeStructuredFieldValue` steady state: one measured
 * call is one pass over the whole six-value SF_FIXTURE corpus
 * (6 canonicalizations per op) — the parse-as-Dictionary/List/Item
 * plus strict-reserialize work every `;sf` covered component pays
 * on the signer and the verifier, isolated from the end-to-end
 * `;sf` verify path that bundles it with base building and
 * cryptography. Self-checks: every corpus entry is verified
 * against its hand-pinned expectation outside timing first, and
 * the measured loop re-pins every entry's result on every pass.
 * Zero network, zero randomness, no wall-clock assertions.
 */
function benchmarkCanonicalizeStructuredFieldValue(): number {
  for (const entry of SF_FIXTURE) {
    const actual = canonicalizeStructuredFieldValue(entry.input);
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: ${entry.name} canonicalized to ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  return measure(() => {
    for (const entry of SF_FIXTURE) {
      const actual = canonicalizeStructuredFieldValue(entry.input);
      if (actual !== entry.expected)
        throw new Error(
          `benchmark self-check failed: ${entry.name} canonicalization diverged from the pinned serialization`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `serializeDictionaryMemberValue` path —
 * one multi-member Dictionary value written out literally here,
 * plus a fixed six-key extraction set covering the member shapes
 * a gateway's `;key` components actually select. Every expected
 * serialization is hand-pinned below from the RFC 8941 §4.1.2
 * member-serialization rules — the member value WITHOUT its
 * Dictionary key, parameters still attached — and matches the
 * values pinned independently in test/keyComponent.test.ts (the
 * `a` / `b` / `c` / `d` members of its DICT fixture and the
 * `n=1.5` decimal case) and test/sfComponent.test.ts (the Byte
 * Sequence member's canonical form) — never derived from
 * `serializeDictionaryMemberValue` at bench time:
 * - a: an Integer member, already canonical → `1`.
 * - b: a member carrying parameters → `2;x=1;y=2` (the
 *   parameters stay attached to the extracted member value).
 * - n: a Decimal member → `1.500` (exactly three fractional
 *   digits, the same rule the `;sf` corpus pins).
 * - sig: a Byte Sequence member with a Boolean parameter →
 *   `:aGVsbG8=:;x=?0` (base64 re-encoded canonically).
 * - c: an Inner List member → `(a b c)`.
 * - d: a bare key — a Boolean-true member serializes as `?1`,
 *   the key itself is not included.
 */
const DICT_MEMBER_VALUE =
  "a=1, b=2;x=1;y=2, n=1.5, sig=:aGVsbG8=:;x=?0, c=(a b c), d";
const DICT_MEMBER_FIXTURE: ReadonlyArray<{
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
 * `serializeDictionaryMemberValue` steady state: one measured
 * call is one pass over the whole fixed key set (6 extractions
 * per op, each re-parsing the whole Dictionary value — that is
 * the function's actual contract, there is no incremental API)
 * — the single-member extraction every `;key` covered component
 * pays on the signer and the verifier, isolated from the
 * end-to-end `;key` verify path and from the whole-value
 * `canonicalizeStructuredFieldValue` path above, whose cost
 * covers reserializing every member rather than one. Self-checks:
 * every fixture entry is verified against its hand-pinned
 * expectation outside timing first, a missing key (`zzz`) must
 * throw "not present" outside timing, and the measured loop
 * re-pins every entry's result on every pass. Zero network, zero
 * randomness, no wall-clock assertions.
 */
function benchmarkSerializeDictionaryMemberValue(): number {
  for (const entry of DICT_MEMBER_FIXTURE) {
    const actual = serializeDictionaryMemberValue(
      DICT_MEMBER_VALUE,
      entry.key,
    );
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: member ${entry.key} serialized to ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  let missingThrown: unknown;
  try {
    serializeDictionaryMemberValue(DICT_MEMBER_VALUE, "zzz");
  } catch (e) {
    missingThrown = e;
  }
  if (
    !(missingThrown instanceof Error) ||
    !missingThrown.message.includes("not present")
  )
    throw new Error(
      `benchmark self-check failed: missing key did not throw "not present" ` +
        `(got ${missingThrown instanceof Error ? JSON.stringify(missingThrown.message) : "no throw"})`,
    );
  return measure(() => {
    for (const entry of DICT_MEMBER_FIXTURE) {
      const actual = serializeDictionaryMemberValue(
        DICT_MEMBER_VALUE,
        entry.key,
      );
      if (actual !== entry.expected)
        throw new Error(
          `benchmark self-check failed: member ${entry.key} extraction diverged from the pinned serialization`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `serializeSignatureParams` path — five
 * (componentIds, params) cases spanning zero to four covered
 * components and parameter sets from three members up to all
 * six. Every expected serialization is hand-pinned below from
 * the serializer's contract — the inner list is the covered
 * component ids in canonical wire form (quoted base, then
 * `;req` / `;tr` / `;name=` / `;key=` parameters), followed by
 * the signature parameters in the fixed order created, expires,
 * keyid, alg, nonce, tag, with string values quoted and
 * backslash / quote characters escaped — and matches values
 * pinned independently elsewhere in the suite — never derived
 * from `serializeSignatureParams` at bench time:
 * - empty: no covered components, created + keyid + nonce —
 *   exactly the RFC 9421 §B.2.1 `@signature-params` value pinned
 *   in test/rfc9421AppendixB.test.ts.
 * - golden: the shared four components with created + keyid +
 *   alg — the `@signature-params` line pinned in
 *   test/golden.test.ts.
 * - full: the same four components with all six parameters set
 *   (expires sits between created and keyid, tag last).
 * - parameterized: four component ids carrying `;req`, `;tr`,
 *   `;name="amount"` and `;key="b"` — each member's canonical
 *   form matches the pins in the `;req` / `;tr` /
 *   `@query-param` / `;key` component tests.
 * - escaped: a nonce carrying a quote and a backslash
 *   (`a"b\c d`) serializes with both escaped, matching the
 *   wire form pinned in test/nonce.test.ts.
 */
const SIG_PARAMS_FIXTURE: ReadonlyArray<{
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

/**
 * `serializeSignatureParams` steady state: one measured call is
 * one pass over the whole fixed corpus (5 serializations per
 * op) — the inner-list-plus-parameters string building every
 * sign/verify pays before any cryptography runs, isolated from
 * the `buildSignatureBase` path above, whose cost additionally
 * covers resolving every covered component's value. Self-checks:
 * every fixture entry is verified against its hand-pinned
 * expectation outside timing first, and the measured loop
 * re-pins every entry's result on every pass. Zero network,
 * zero randomness, no wall-clock assertions.
 */
function benchmarkSerializeSignatureParams(): number {
  for (const entry of SIG_PARAMS_FIXTURE) {
    const actual = serializeSignatureParams(
      entry.componentIds,
      entry.params,
    );
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: case ${entry.name} serialized to ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  return measure(() => {
    for (const entry of SIG_PARAMS_FIXTURE) {
      const actual = serializeSignatureParams(
        entry.componentIds,
        entry.params,
      );
      if (actual !== entry.expected)
        throw new Error(
          `benchmark self-check failed: case ${entry.name} serialization diverged from the pinned string`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed byte tiers for the `generateNonce` path — the two sizes
 * the backlog names: the default 16 bytes (128 bits, the standard
 * nonce strength) and 32 bytes (256 bits). The expected lengths
 * are hand-pinned from the shape test/generateNonce.test.ts pins —
 * 16 bytes -> ceil(128 / 6) = 22 base64url characters, 32 bytes ->
 * ceil(256 / 6) = 43, with no padding — never derived from
 * `generateNonce` at bench time.
 */
const NONCE_TIERS = [
  { bytes: 16, expectedLength: 22 },
  { bytes: 32, expectedLength: 43 },
] as const;
const NONCE_SHAPE = /^[A-Za-z0-9_-]+$/;

function assertNonceShape(
  nonce: string,
  bytes: number,
  expectedLength: number,
): void {
  if (
    nonce.length !== expectedLength ||
    !NONCE_SHAPE.test(nonce) ||
    /[+/=]/.test(nonce)
  )
    throw new Error(
      `benchmark self-check failed: generateNonce(${bytes}) gave ` +
        `${JSON.stringify(nonce)} (expected ${expectedLength} base64url chars)`,
    );
}

/**
 * `generateNonce` steady state: one measured call generates one
 * nonce per fixed tier (2 generations per op) — the default tier
 * is exercised through the no-argument default, the 32-byte tier
 * through the explicit argument. This is the fixed per-request
 * cost an anti-replay signer pays before signing: drawing bytes
 * from the system CSPRNG (`node:crypto` `randomBytes`, so the
 * numbers include entropy-source cost) plus base64url encoding.
 * Self-checks assert morphology only — exact length and the
 * base64url-only character set the generateNonce test pins — on
 * every measured call, and never a specific value: the output is
 * random by design, and that randomness comes only from the
 * function under test itself. Zero network, no wall-clock
 * assertions.
 */
function benchmarkGenerateNonce(): number {
  for (const tier of NONCE_TIERS) {
    const nonce =
      tier.bytes === 16 ? generateNonce() : generateNonce(tier.bytes);
    assertNonceShape(nonce, tier.bytes, tier.expectedLength);
  }
  return measure(() => {
    for (const tier of NONCE_TIERS) {
      const nonce =
        tier.bytes === 16 ? generateNonce() : generateNonce(tier.bytes);
      assertNonceShape(nonce, tier.bytes, tier.expectedLength);
    }
  }, ITERATIONS);
}

/** Fixed `created` for the OrThrow fixture (no wall clock). */
const ORTHROW_CREATED = 1_700_000_000;
/** Pinned failure code for the tampered OrThrow fixture — written
 * here as a literal, from the verify contract: flipping a signature
 * byte leaves the base rebuildable but fails the cryptography, so
 * the code is SIGNATURE_MISMATCH (same pin as test/verifyErrors). */
const ORTHROW_TAMPERED_CODE = "SIGNATURE_MISMATCH";

/**
 * Fixed corpus for the `verifyRequestOrThrow` paths: one valid
 * ed25519-signed request over the shared fixture (created pinned at
 * ORTHROW_CREATED, verified at created+60 — no wall clock) and the
 * same request with the first signature byte flipped (`buf[0] ^= 0xff`,
 * the tamper construction from test/verifyErrors.test.ts).
 * Reported as TWO separate rows (success / tampered), not merged:
 * the success row is the unwrapping cost over `verifyRequest`, the
 * tampered row additionally pays for VerifyError construction.
 */
function buildOrThrowFixture(): {
  valid: SignedHttpRequest;
  tampered: SignedHttpRequest;
  verifyOpts: { key: ReturnType<typeof generateEd25519KeyPair>["publicKey"]; now: number };
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const valid: SignedHttpRequest = signRequest(fixture, {
    keyId: "bench-key",
    alg: "ed25519",
    key: privateKey,
    created: ORTHROW_CREATED,
  });
  const sigHeader = valid.headers["signature"];
  const tamperedSig = sigHeader.replace(
    /:([A-Za-z0-9+/=]+):/,
    (_m, b64: string) => {
      const buf = Buffer.from(b64, "base64");
      buf[0] ^= 0xff;
      return `:${buf.toString("base64")}:`;
    },
  );
  if (tamperedSig === sigHeader)
    throw new Error("benchmark self-check failed: tamper did not change the signature");
  const tampered: SignedHttpRequest = {
    ...valid,
    headers: { ...valid.headers, signature: tamperedSig },
  };
  return { valid, tampered, verifyOpts: { key: publicKey, now: ORTHROW_CREATED + 60 } };
}

function assertOrThrowFixture(
  fx: ReturnType<typeof buildOrThrowFixture>,
): void {
  const ok = verifyRequestOrThrow(fx.valid, fx.verifyOpts);
  if (ok.label !== "sig1" || ok.keyId !== "bench-key" || ok.alg !== "ed25519")
    throw new Error(
      `benchmark self-check failed: verifyRequestOrThrow(valid) gave ${JSON.stringify(ok)}`,
    );
  let thrown: unknown;
  try {
    verifyRequestOrThrow(fx.tampered, fx.verifyOpts);
  } catch (e) {
    thrown = e;
  }
  if (!isVerifyError(thrown) || thrown.code !== ORTHROW_TAMPERED_CODE)
    throw new Error(
      `benchmark self-check failed: verifyRequestOrThrow(tampered) gave ` +
        `${thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : "no throw"} ` +
        `(expected VerifyError ${ORTHROW_TAMPERED_CODE})`,
    );
}

/** `verifyRequestOrThrow` success path: result unwrapping, no throw. */
function benchmarkVerifyRequestOrThrowOk(): number {
  const fx = buildOrThrowFixture();
  assertOrThrowFixture(fx);
  return measure(() => {
    const r = verifyRequestOrThrow(fx.valid, fx.verifyOpts);
    if (r.label !== "sig1" || r.keyId !== "bench-key" || r.alg !== "ed25519")
      throw new Error(
        "benchmark self-check failed: verifyRequestOrThrow(valid) diverged in the measured loop",
      );
  }, ITERATIONS);
}

/**
 * `verifyRequestOrThrow` failure path: every call must throw a
 * VerifyError carrying the pinned code; the throw count afterwards
 * must equal warmup + timed iterations exactly.
 */
function benchmarkVerifyRequestOrThrowTampered(): number {
  const fx = buildOrThrowFixture();
  assertOrThrowFixture(fx);
  let thrownCount = 0;
  const ops = measure(() => {
    let thrown: unknown;
    try {
      verifyRequestOrThrow(fx.tampered, fx.verifyOpts);
    } catch (e) {
      thrown = e;
    }
    if (!isVerifyError(thrown) || thrown.code !== ORTHROW_TAMPERED_CODE)
      throw new Error(
        "benchmark self-check failed: verifyRequestOrThrow(tampered) did not throw the pinned VerifyError in the measured loop",
      );
    thrownCount++;
  }, ITERATIONS);
  if (thrownCount !== WARMUP + ITERATIONS)
    throw new Error(
      `benchmark self-check failed: ${thrownCount} tampered throws (expected ${WARMUP + ITERATIONS})`,
    );
  return ops;
}

/**
 * Fixed multi-header fixture for the `getHeader` / `getHeaderRaw`
 * paths — one headers object written out literally here, holding
 * eight entries in insertion order:
 * - `Host` (mixed case, with a port) AND a later lowercase `host`
 *   entry holding a different value: the two keys coexist in one
 *   object, and a case-insensitive lookup must return the FIRST
 *   matching key in insertion order, never the shadowed second
 *   one — the duplicate-casing case a gateway hits when a proxy
 *   re-adds a header under a different casing;
 * - `Content-Type` and `Content-Digest` single strings (the
 *   digest value is the pinned sha-512 wire value of the shared
 *   fixture body, carried here as an opaque header value — the
 *   lookup helpers never recompute digests);
 * - two multi-value fields whose elements carry padding
 *   whitespace (`X-Forwarded-For`, `X-Trace`): the canonical
 *   `getHeader` form trims each element and joins with ", ",
 *   while `getHeaderRaw` joins the raw elements with ", " and
 *   keeps every space — the two forms MUST differ on these
 *   entries, which is exactly what the pins below assert;
 * - `x-custom`, a single string with padding: a single (non-array)
 *   value is returned verbatim by BOTH helpers (neither trims a
 *   lone string), so its two pins coincide;
 * - `Authorization`, a plain single string;
 * - `X-Debug-Skip`, present with an `undefined` value: both
 *   helpers return `undefined` for it, asserted outside timing
 *   together with the genuinely missing names below.
 */
const HEADER_FIXTURE: Record<string, string | string[] | undefined> = {
  Host: "gateway.example.com:8443",
  host: "shadowed.example.com",
  "Content-Type": "application/json",
  "Content-Digest":
    "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  "X-Forwarded-For": [" 203.0.113.10 ", "10.0.0.8"],
  "X-Trace": ["  alpha  ", " beta "],
  "x-custom": "  padded value  ",
  Authorization: "Bearer bench-token",
  "X-Debug-Skip": undefined,
};

/**
 * Hand-pinned expected lookups over HEADER_FIXTURE — every
 * expected value is written out literally from the two helpers'
 * documented contracts (case-insensitive first-match scan;
 * canonical form trims and joins multi-value elements with
 * ", "; raw form joins them untrimmed; a single string passes
 * through verbatim in both forms) — never derived from
 * `getHeader` / `getHeaderRaw` at bench time:
 * - host / HOST: both casings resolve to the FIRST `Host` entry
 *   (`gateway.example.com:8443`), not the shadowed lowercase one;
 * - content-type / content-digest: the single strings verbatim;
 * - x-forwarded-for: canonical `203.0.113.10, 10.0.0.8`, raw
 *   ` 203.0.113.10 , 10.0.0.8` (the first element's trailing
 *   space survives, then the ", " separator);
 * - X-TRACE: canonical `alpha, beta`, raw `  alpha  ,  beta `;
 * - x-custom / X-Custom: `  padded value  ` in both forms;
 * - authorization: `Bearer bench-token` in both forms.
 */
const HEADER_LOOKUPS: ReadonlyArray<{
  name: string;
  canonical: string;
  raw: string;
}> = [
  {
    name: "host",
    canonical: "gateway.example.com:8443",
    raw: "gateway.example.com:8443",
  },
  {
    name: "HOST",
    canonical: "gateway.example.com:8443",
    raw: "gateway.example.com:8443",
  },
  {
    name: "content-type",
    canonical: "application/json",
    raw: "application/json",
  },
  {
    name: "content-digest",
    canonical:
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    raw: "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  },
  {
    name: "x-forwarded-for",
    canonical: "203.0.113.10, 10.0.0.8",
    raw: " 203.0.113.10 , 10.0.0.8",
  },
  {
    name: "X-TRACE",
    canonical: "alpha, beta",
    raw: "  alpha  ,  beta ",
  },
  {
    name: "x-custom",
    canonical: "  padded value  ",
    raw: "  padded value  ",
  },
  {
    name: "authorization",
    canonical: "Bearer bench-token",
    raw: "Bearer bench-token",
  },
  {
    name: "X-Custom",
    canonical: "  padded value  ",
    raw: "  padded value  ",
  },
];

/**
 * Names whose lookup result must be `undefined` from BOTH
 * helpers, asserted outside timing only (the missing-header
 * return form is a contract check, not part of the measured
 * pass): three names absent from the fixture entirely, plus
 * `x-debug-skip`, which is present but carries an `undefined`
 * value.
 */
const HEADER_MISSING = ["x-missing", "signature", "cookie", "x-debug-skip"] as const;

function assertHeaderFixture(): void {
  for (const entry of HEADER_LOOKUPS) {
    const canonical = getHeader(HEADER_FIXTURE, entry.name);
    if (canonical !== entry.canonical)
      throw new Error(
        `benchmark self-check failed: getHeader(${entry.name}) gave ${JSON.stringify(canonical)} ` +
          `(expected ${JSON.stringify(entry.canonical)})`,
      );
    const raw = getHeaderRaw(HEADER_FIXTURE, entry.name);
    if (raw !== entry.raw)
      throw new Error(
        `benchmark self-check failed: getHeaderRaw(${entry.name}) gave ${JSON.stringify(raw)} ` +
          `(expected ${JSON.stringify(entry.raw)})`,
      );
  }
  for (const name of HEADER_MISSING) {
    if (getHeader(HEADER_FIXTURE, name) !== undefined)
      throw new Error(
        `benchmark self-check failed: getHeader(${name}) did not return undefined`,
      );
    if (getHeaderRaw(HEADER_FIXTURE, name) !== undefined)
      throw new Error(
        `benchmark self-check failed: getHeaderRaw(${name}) did not return undefined`,
      );
  }
}

/**
 * `getHeader` / `getHeaderRaw` steady state: one measured call
 * is one pass over the whole fixed lookup set (9 names × both
 * helpers = 18 lookups per op) — the case-insensitive scan and
 * multi-value fold every covered component pays when
 * `resolveComponent` reads a field from the request, on the
 * signer and the verifier alike. Self-checks: every fixture
 * entry is verified against its hand-pinned expectation for
 * both helpers outside timing first (with the missing /
 * undefined-valued names asserted there too), and the measured
 * loop re-pins every lookup's result for both helpers on every
 * pass. Zero network, zero randomness, no wall-clock
 * assertions.
 */
function benchmarkGetHeader(): number {
  assertHeaderFixture();
  return measure(() => {
    for (const entry of HEADER_LOOKUPS) {
      if (getHeader(HEADER_FIXTURE, entry.name) !== entry.canonical)
        throw new Error(
          `benchmark self-check failed: getHeader(${entry.name}) diverged from the pinned value`,
        );
      if (getHeaderRaw(HEADER_FIXTURE, entry.name) !== entry.raw)
        throw new Error(
          `benchmark self-check failed: getHeaderRaw(${entry.name}) diverged from the pinned value`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed multi-value corpus for the `joinHeaderValues` path —
 * nine value arrays written out literally here, spanning the
 * shapes a repeated header takes on a proxy chain:
 * - the empty array (no values at all);
 * - a single padded value and a plain two-value array;
 * - padded multi-value arrays (spaces and tabs around elements);
 * - empty-string elements: one lone empty string, two
 *   whitespace-only elements, an empty element in the middle of
 *   real values, and an empty first element before real values.
 * Empty elements are NOT dropped: each element is trimmed and
 * the results are joined with ", ", so an empty element still
 * contributes its separator — the pins below state that
 * explicitly, because dropping empties would canonicalize two
 * different wire shapes onto one signature base.
 */
const JOIN_CORPUS: ReadonlyArray<{
  values: string[];
  expected: string;
}> = [
  // [] — no elements, nothing to join: "".
  { values: [], expected: "" },
  // ["  solo  "] — one element, trimmed: "solo".
  { values: ["  solo  "], expected: "solo" },
  // ["a", "b"] — plain pair: "a, b".
  { values: ["a", "b"], expected: "a, b" },
  // ["  a  ", "b "] — padded pair (pin from the component tests): "a, b".
  { values: ["  a  ", "b "], expected: "a, b" },
  // ["\ta\t", "  b", "c  "] — tab/space padding, three values: "a, b, c".
  { values: ["\ta\t", "  b", "c  "], expected: "a, b, c" },
  // [""] — one empty element, trimmed to "": "".
  { values: [""], expected: "" },
  // ["   ", "\t"] — two whitespace-only elements trim to "" and "":
  // joined with the separator they still produce ", ".
  { values: ["   ", "\t"], expected: ", " },
  // ["a", "", "b"] — empty middle element keeps its separators: "a, , b".
  { values: ["a", "", "b"], expected: "a, , b" },
  // ["", " 203.0.113.10 ", "10.0.0.8"] — empty first element, then
  // a padded address and a plain one: ", 203.0.113.10, 10.0.0.8".
  {
    values: ["", " 203.0.113.10 ", "10.0.0.8"],
    expected: ", 203.0.113.10, 10.0.0.8",
  },
];

/**
 * `joinHeaderValues` steady state: one measured call is one pass
 * over the whole fixed corpus (9 combinations per op) — the
 * trim-and-join step every canonical header lookup, signer-side
 * fold and Node-adapter fold pays for a multi-value field, on the
 * signer and the verifier alike. Self-checks: every corpus entry
 * is verified against its hand-pinned expectation outside timing
 * first — the non-empty pins match the values pinned
 * independently in test/multiValueHeaderWhitespace.test.ts, and
 * no expected value is derived from `joinHeaderValues` at bench
 * time — and the measured loop re-pins every entry's result on
 * every pass. Zero network, zero randomness, no wall-clock
 * assertions.
 */
function benchmarkJoinHeaderValues(): number {
  for (const entry of JOIN_CORPUS) {
    const actual = joinHeaderValues(entry.values);
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: joinHeaderValues(${JSON.stringify(entry.values)}) gave ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  return measure(() => {
    for (const entry of JOIN_CORPUS) {
      if (joinHeaderValues(entry.values) !== entry.expected)
        throw new Error(
          `benchmark self-check failed: joinHeaderValues(${JSON.stringify(entry.values)}) diverged from the pinned value`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed Content-Digest header-value corpus for the
 * `contentDigestAlgOf` path — ten values written out literally
 * here. The two single-algorithm values are the pinned
 * DIGEST_EXPECTED wire values of the shared fixture body above.
 * Composition, with the hand-pinned expectation for each:
 * - sha-512 alone -> "sha-512"; sha-256 alone -> "sha-256"
 *   (the only two algorithms this library can emit);
 * - mixed values in both orders: the helper reads only the
 *   prefix before the FIRST "=", so sha-512-first ->
 *   "sha-512" and sha-256-first -> "sha-256". This is the
 *   signer-side pinning contract `addSignature` relies on (the
 *   wire header written by the first signer carries a single
 *   algorithm); it is NOT the verifier's body check, which
 *   scans the whole value and prefers sha-512 when both are
 *   present (see src/verify.ts);
 * - unknown algorithms sha-1 and sha-384 -> undefined
 *   (fail-closed: a caller such as `addSignature` must reject
 *   a header it cannot emit, and the sha-1 shape is the one the
 *   contentDigestAlg tests pin for that rejection);
 * - malformed shapes -> undefined: an uppercase "SHA-512"
 *   prefix (the comparison is case-sensitive), a leading
 *   space before the algorithm, a bare "sha-512" with no "="
 *   at all, and the empty string.
 * No expected value is derived from `contentDigestAlgOf` at
 * bench time.
 */
const DIGEST_ALG_CORPUS: ReadonlyArray<{
  value: string;
  expected: ContentDigestAlg | undefined;
}> = [
  // sha-512 alone — the DIGEST_EXPECTED sha-512 wire value: "sha-512".
  {
    value:
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    expected: "sha-512",
  },
  // sha-256 alone — the DIGEST_EXPECTED sha-256 wire value: "sha-256".
  {
    value: "sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:",
    expected: "sha-256",
  },
  // Mixed, sha-512 first: the first "=" prefix wins: "sha-512".
  {
    value:
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:, sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:",
    expected: "sha-512",
  },
  // Mixed, sha-256 first: the first "=" prefix wins: "sha-256".
  {
    value:
      "sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:, sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    expected: "sha-256",
  },
  // sha-1 — an algorithm this library cannot emit: undefined.
  { value: "sha-1=:abc=:", expected: undefined },
  // sha-384 — likewise unemittable here: undefined.
  { value: "sha-384=:abc=:", expected: undefined },
  // Uppercase "SHA-512" — the comparison is case-sensitive: undefined.
  {
    value:
      "SHA-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    expected: undefined,
  },
  // Leading space — the prefix is " sha-512", not "sha-512": undefined.
  {
    value:
      " sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    expected: undefined,
  },
  // Bare "sha-512" with no "=" — no prefix to read: undefined.
  { value: "sha-512", expected: undefined },
  // Empty string: undefined.
  { value: "", expected: undefined },
];

/**
 * `contentDigestAlgOf` steady state: one measured call is one
 * pass over the whole fixed corpus (10 identifications per
 * op) — the prefix scan a signer appending a second signature
 * pays to pin itself to the existing wire digest algorithm,
 * before any hashing runs. Self-checks: every corpus entry is
 * verified against its hand-pinned expectation outside timing
 * first — in particular the unknown and malformed entries must
 * all come back `undefined` (the fail-closed shape a caller
 * turns into an explicit rejection) — and the measured loop
 * re-pins every entry's result on every pass. Zero network,
 * zero randomness, no wall-clock assertions.
 */
function benchmarkContentDigestAlgOf(): number {
  for (const entry of DIGEST_ALG_CORPUS) {
    const actual = contentDigestAlgOf(entry.value);
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed: contentDigestAlgOf(${JSON.stringify(entry.value)}) gave ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
  return measure(() => {
    for (const entry of DIGEST_ALG_CORPUS) {
      if (contentDigestAlgOf(entry.value) !== entry.expected)
        throw new Error(
          `benchmark self-check failed: contentDigestAlgOf(${JSON.stringify(entry.value)}) diverged from the pinned value`,
        );
    }
  }, ITERATIONS);
}

/**
 * Fixed secret-length corpus for the `assertHmacSecretLength`
 * path — ten cases written out here, with every secret a
 * `createSecretKey` KeyObject built ONCE at bench start from a
 * fixed 0xab fill (deterministic, zero randomness; only the byte
 * length matters to the guard, never the content). Composition,
 * with the hand-pinned outcome for each:
 * - hmac-sha256 via the DEFAULT (one-argument) call — the
 *   backwards-compatible form the keyLength suite pins:
 *   0 bytes -> throws "at least 32 bytes … got 0 bytes";
 *   31 bytes (one below the floor) -> throws "… got 31 bytes";
 *   32 bytes (exactly the RFC 2104 floor) -> passes;
 *   128 bytes (far above) -> passes.
 * - hmac-sha256 explicit: 63 bytes -> passes (the same secret
 *   fails for hmac-sha512 below — the floor is paired with the
 *   algorithm, never shared).
 * - hmac-sha512: 0 bytes -> throws "at least 64 bytes … got 0
 *   bytes"; 32 bytes (adequate for sha256, half the sha512
 *   floor) -> throws "… got 32 bytes"; 63 bytes (one below) ->
 *   throws "… got 63 bytes"; 64 bytes (exactly the floor) ->
 *   passes; 128 bytes (far above) -> passes.
 * Every pinned floor and byte count matches the messages the
 * keyLength and hmacSha512 suites pin independently. No
 * expected outcome is derived from `assertHmacSecretLength`
 * at bench time.
 */
const HMAC_GUARD_CORPUS: ReadonlyArray<{
  bytes: number;
  alg: "hmac-sha256" | "hmac-sha512" | undefined;
  key: KeyObject;
  /** Pinned throw-message fragment, or null when the call passes. */
  expectedError: string | null;
}> = [
  {
    bytes: 0,
    alg: undefined,
    key: createSecretKey(Buffer.alloc(0, 0xab)),
    expectedError:
      "assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes",
  },
  {
    bytes: 31,
    alg: undefined,
    key: createSecretKey(Buffer.alloc(31, 0xab)),
    expectedError:
      "assertHmacSecretLength: hmac-sha256 secret must be at least 32 bytes",
  },
  {
    bytes: 32,
    alg: undefined,
    key: createSecretKey(Buffer.alloc(32, 0xab)),
    expectedError: null,
  },
  {
    bytes: 128,
    alg: undefined,
    key: createSecretKey(Buffer.alloc(128, 0xab)),
    expectedError: null,
  },
  {
    bytes: 63,
    alg: "hmac-sha256",
    key: createSecretKey(Buffer.alloc(63, 0xab)),
    expectedError: null,
  },
  {
    bytes: 0,
    alg: "hmac-sha512",
    key: createSecretKey(Buffer.alloc(0, 0xab)),
    expectedError:
      "assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes",
  },
  {
    bytes: 32,
    alg: "hmac-sha512",
    key: createSecretKey(Buffer.alloc(32, 0xab)),
    expectedError:
      "assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes",
  },
  {
    bytes: 63,
    alg: "hmac-sha512",
    key: createSecretKey(Buffer.alloc(63, 0xab)),
    expectedError:
      "assertHmacSecretLength: hmac-sha512 secret must be at least 64 bytes",
  },
  {
    bytes: 64,
    alg: "hmac-sha512",
    key: createSecretKey(Buffer.alloc(64, 0xab)),
    expectedError: null,
  },
  {
    bytes: 128,
    alg: "hmac-sha512",
    key: createSecretKey(Buffer.alloc(128, 0xab)),
    expectedError: null,
  },
];

/** Run one corpus case and return its outcome: null on pass, the thrown message otherwise. */
function hmacGuardOutcome(
  entry: (typeof HMAC_GUARD_CORPUS)[number],
): string | null {
  try {
    if (entry.alg === undefined) assertHmacSecretLength(entry.key);
    else assertHmacSecretLength(entry.key, entry.alg);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

function assertHmacGuardCorpus(label: string): void {
  for (const entry of HMAC_GUARD_CORPUS) {
    const outcome = hmacGuardOutcome(entry);
    if (entry.expectedError === null) {
      if (outcome !== null)
        throw new Error(
          `benchmark self-check failed (${label}): assertHmacSecretLength(${entry.bytes} bytes, ${entry.alg ?? "default"}) threw ${JSON.stringify(outcome)} (expected pass)`,
        );
    } else if (
      outcome === null ||
      !outcome.includes(entry.expectedError) ||
      !outcome.includes(`got ${entry.bytes} bytes`)
    )
      throw new Error(
        `benchmark self-check failed (${label}): assertHmacSecretLength(${entry.bytes} bytes, ${entry.alg ?? "default"}) gave ${JSON.stringify(outcome)} ` +
          `(expected a throw containing ${JSON.stringify(entry.expectedError)} and "got ${entry.bytes} bytes")`,
      );
  }
}

/**
 * `assertHmacSecretLength` steady state: one measured call is
 * one pass over the whole fixed corpus (10 guard checks per
 * op, six of which throw and are caught inside the outcome
 * helper — the fail-closed rejection is part of the steady
 * state, exactly as a caller constructing a secretKey-guarded
 * sign/verify pays it) — the per-algorithm HMAC key-length
 * floor (RFC 2104: sha256 >= 32 bytes, sha512 >= 64 bytes)
 * the sign and verify paths enforce before any MAC runs.
 * Self-checks: the whole corpus is asserted exhaustively
 * outside timing first, and the measured loop re-pins every
 * case's pass/throw outcome on every pass. Zero network, zero
 * randomness, no wall-clock assertions.
 */
function benchmarkAssertHmacSecretLength(): number {
  assertHmacGuardCorpus("outside timing");
  return measure(() => {
    assertHmacGuardCorpus("measured pass");
  }, ITERATIONS);
}

/** Fixed caller context the bench passes to the RSA guard — the
 *  guard prefixes every throw with the caller-supplied context,
 *  exactly as the sign/verify paths pass theirs (see src/keys.ts). */
const RSA_GUARD_CONTEXT = "assertRsaModulusLength bench";

/**
 * Fixed key corpus for the `assertRsaModulusLength` path —
 * seven cases, with every key generated ONCE here at bench
 * start (the 2048-bit pair via the library generator, the
 * 1024-bit pair and the wrong-shape keys via node:crypto
 * directly); the timed region generates no keys at all.
 * Composition, with the hand-pinned outcome for each:
 * - RSA 2048 public and private — exactly at the
 *   MIN_RSA_MODULUS_BITS floor (2048) -> both pass;
 * - RSA 1024 public and private — below the floor -> both
 *   throw "RSA modulus must be at least 2048 bits, got 1024
 *   bits" (the message the rsaV15 suite pins for the same
 *   weak pair on both the sign and verify sides);
 * - ed25519 public -> throws "expected an RSA key, got an
 *   asymmetric ed25519 key"; P-256 public -> throws
 *   "expected an RSA key, got an asymmetric ec key" (the
 *   shape the rsaV15 suite pins for a P-256 key on the
 *   verify side); a symmetric secret KeyObject -> throws
 *   "expected an RSA key, got a secret (symmetric) key".
 * Every pinned message is the guard's documented contract
 * with RSA_GUARD_CONTEXT as the prefix. No expected outcome
 * is derived from `assertRsaModulusLength` at bench time.
 */
const RSA_GUARD_STRONG = generateRsaPssKeyPair();
const RSA_GUARD_WEAK = generateKeyPairSync("rsa", {
  modulusLength: 1024,
});
const RSA_GUARD_CORPUS: ReadonlyArray<{
  label: string;
  key: KeyObject;
  /** Pinned full throw message, or null when the call passes. */
  expectedError: string | null;
}> = [
  { label: "rsa-2048 public", key: RSA_GUARD_STRONG.publicKey, expectedError: null },
  { label: "rsa-2048 private", key: RSA_GUARD_STRONG.privateKey, expectedError: null },
  {
    label: "rsa-1024 public",
    key: RSA_GUARD_WEAK.publicKey,
    expectedError:
      `${RSA_GUARD_CONTEXT}: RSA modulus must be at least 2048 bits, got 1024 bits`,
  },
  {
    label: "rsa-1024 private",
    key: RSA_GUARD_WEAK.privateKey,
    expectedError:
      `${RSA_GUARD_CONTEXT}: RSA modulus must be at least 2048 bits, got 1024 bits`,
  },
  {
    label: "ed25519 public",
    key: generateEd25519KeyPair().publicKey,
    expectedError:
      `${RSA_GUARD_CONTEXT}: expected an RSA key, got an asymmetric ed25519 key`,
  },
  {
    label: "p-256 public",
    key: generateP256KeyPair().publicKey,
    expectedError:
      `${RSA_GUARD_CONTEXT}: expected an RSA key, got an asymmetric ec key`,
  },
  {
    label: "secret key",
    key: createSecretKey(Buffer.alloc(32, 0xab)),
    expectedError:
      `${RSA_GUARD_CONTEXT}: expected an RSA key, got a secret (symmetric) key`,
  },
];

/** Run one corpus case and return its outcome: null on pass, the thrown message otherwise. */
function rsaGuardOutcome(
  entry: (typeof RSA_GUARD_CORPUS)[number],
): string | null {
  try {
    assertRsaModulusLength(entry.key, RSA_GUARD_CONTEXT);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

function assertRsaGuardCorpus(label: string): void {
  for (const entry of RSA_GUARD_CORPUS) {
    const outcome = rsaGuardOutcome(entry);
    if (outcome !== entry.expectedError)
      throw new Error(
        `benchmark self-check failed (${label}): assertRsaModulusLength(${entry.label}) gave ${JSON.stringify(outcome)} ` +
          `(expected ${JSON.stringify(entry.expectedError)})`,
      );
  }
}

/**
 * `assertRsaModulusLength` steady state: one measured call is
 * one pass over the whole fixed corpus (7 guard checks per
 * op, five of which throw and are caught inside the outcome
 * helper — the fail-closed rejection is part of the steady
 * state, exactly as a caller importing an RSA key pays it) —
 * the RSA modulus floor (at least MIN_RSA_MODULUS_BITS =
 * 2048 bits, plus the RSA key-shape check) the rsa-v1_5-sha256
 * sign and verify paths enforce before any RSA operation
 * runs. Self-checks: the whole corpus is asserted
 * exhaustively outside timing first, and the measured loop
 * re-pins every case's pass/throw outcome on every pass.
 * Zero network, zero key generation inside timing, no
 * wall-clock assertions.
 */
function benchmarkAssertRsaModulusLength(): number {
  assertRsaGuardCorpus("outside timing");
  return measure(() => {
    assertRsaGuardCorpus("measured pass");
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `signatureInputValue` path — four
 * (label, componentIds, params) cases. Every expected value
 * is hand-pinned below from the function's contract — the
 * result is exactly `label + "=" + serializeSignatureParams(
 * componentIds, params)` rendered as one string, with the
 * inner list and parameter order the SIG_PARAMS_* fixture
 * above pins — and matches values pinned independently
 * elsewhere in the suite — never derived from
 * `signatureInputValue` at bench time:
 * - minimal: one covered component and an empty parameter
 *   set — the value renders as the bare inner list with no
 *   `;param` suffix at all (there is no undefined outcome:
 *   this function builds a value, it does not look one up).
 * - golden: the shared four components with created + keyid
 *   + alg under the label `sig1` — the `@signature-params`
 *   line pinned in test/golden.test.ts, with its `sig1=`
 *   prefix.
 * - merchant-full: a second label, `merchant`, over the
 *   same four components with all six parameters set — the
 *   second member a multi-label header is built from.
 * - gateway-parameterized: the label `gateway`, two
 *   parameterized component ids (`;req`, `;key="b"`) and a
 *   nonce carrying a quote and a backslash, serialized
 *   escaped exactly as the SIG_PARAMS_* escaped case pins.
 * Outside timing, the golden and merchant-full values are
 * also joined with ", " and pinned against the full
 * dual-label header literal below — the merge shape
 * test/multiLabel.test.ts and the multi-label cases in
 * test/invalidTimeWindow.test.ts build from two
 * `signatureInputValue` outputs.
 */
const SIG_INPUT_FIXTURE: ReadonlyArray<{
  name: string;
  label: string;
  componentIds: string[];
  params: SignatureParams;
  expected: string;
}> = [
  {
    name: "minimal",
    label: "sig1",
    componentIds: ["@method"],
    params: {},
    expected: 'sig1=("@method")',
  },
  {
    name: "golden",
    label: "sig1",
    componentIds: ["@method", "@authority", "@path", "content-digest"],
    params: { created: 1700000000, keyid: "k1", alg: "hmac-sha256" },
    expected:
      'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256"',
  },
  {
    name: "merchant-full",
    label: "merchant",
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
      'merchant=("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"',
  },
  {
    name: "gateway-parameterized",
    label: "gateway",
    componentIds: ["@method;req", 'x-dict;key="b"'],
    params: {
      created: 1700000000,
      keyid: "k",
      alg: "ed25519",
      nonce: 'a"b\\c d',
    },
    expected:
      'gateway=("@method";req "x-dict";key="b");created=1700000000;keyid="k";alg="ed25519";nonce="a\\"b\\\\c d"',
  },
];

/** Full dual-label `Signature-Input` header built by joining the
 *  golden and merchant-full corpus values with ", " — hand-pinned
 *  as one literal, asserted outside timing only. */
const SIG_INPUT_JOINED_EXPECTED =
  'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="k1";alg="hmac-sha256", ' +
  'merchant=("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;keyid="demo-key-1";alg="ed25519";nonce="demo-nonce-001";tag="payment-webhook-v1"';

function assertSigInputCorpus(label: string): void {
  for (const entry of SIG_INPUT_FIXTURE) {
    const actual = signatureInputValue(
      entry.label,
      entry.componentIds,
      entry.params,
    );
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed (${label}): signatureInputValue(${entry.name}) gave ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
}

/**
 * `signatureInputValue` steady state: one measured call is
 * one pass over the whole fixed corpus (4 value builds per
 * op) — the `label=` prefix plus inner-list-and-parameters
 * serialization a signer pays once per label before the
 * signature base is built, isolated from the
 * `serializeSignatureParams` row above (which measures the
 * same serialization without the label prefix) and from
 * the sign rows that bundle it with base building and
 * cryptography. Self-checks: the whole corpus is asserted
 * exhaustively outside timing first — including the
 * dual-label ", " join pinned against
 * SIG_INPUT_JOINED_EXPECTED — and the measured loop
 * re-pins every case's built value on every pass. Zero
 * network, zero randomness, no wall-clock assertions.
 */
function benchmarkSignatureInputValue(): number {
  assertSigInputCorpus("outside timing");
  const golden = SIG_INPUT_FIXTURE[1];
  const merchant = SIG_INPUT_FIXTURE[2];
  const joined =
    signatureInputValue(golden.label, golden.componentIds, golden.params) +
    ", " +
    signatureInputValue(
      merchant.label,
      merchant.componentIds,
      merchant.params,
    );
  if (joined !== SIG_INPUT_JOINED_EXPECTED)
    throw new Error(
      `benchmark self-check failed (outside timing): dual-label join gave ${JSON.stringify(joined)} ` +
        `(expected ${JSON.stringify(SIG_INPUT_JOINED_EXPECTED)})`,
    );
  return measure(() => {
    assertSigInputCorpus("measured pass");
  }, ITERATIONS);
}

/**
 * Fixed corpus for the `assertContentDigestAlg` path — ten
 * cases written out here, with the hand-pinned outcome for
 * each. Composition:
 * - the two emittable algorithms: "sha-512" (the default)
 *   and "sha-256" -> both pass;
 * - unknown algorithms: "sha-1" (the shape the
 *   contentDigestAlg suite pins as a configuration error on
 *   the sign side and as an unemittable header algorithm)
 *   and "md5" (the shape that same suite pins through
 *   `contentDigest` directly) -> both throw;
 * - the empty string "" (pinned as a configuration error
 *   by the contentDigestAlg suite) -> throws;
 * - wrong-case spellings: "SHA-512" and "Sha-256" -> both
 *   throw (the comparison is exact and case-sensitive);
 * - a trailing-space spelling "sha-512 " -> throws (no
 *   trimming is performed);
 * - non-string values: undefined and null -> both throw.
 * Every pinned throw is the guard's full message
 * `contentDigest: "alg" must be "sha-512" or "sha-256", got
 * <JSON.stringify(value)>` — for undefined the JSON form
 * renders as the bare word `undefined`, for null as
 * `null`. No expected outcome is derived from
 * `assertContentDigestAlg` at bench time.
 */
const DIGEST_GUARD_CORPUS: ReadonlyArray<{
  label: string;
  alg: unknown;
  /** Pinned full throw message, or null when the call passes. */
  expectedError: string | null;
}> = [
  { label: "sha-512", alg: "sha-512", expectedError: null },
  { label: "sha-256", alg: "sha-256", expectedError: null },
  {
    label: "sha-1",
    alg: "sha-1",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-1"',
  },
  {
    label: "md5",
    alg: "md5",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got "md5"',
  },
  {
    label: "empty string",
    alg: "",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got ""',
  },
  {
    label: "SHA-512 (uppercase)",
    alg: "SHA-512",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got "SHA-512"',
  },
  {
    label: "Sha-256 (mixed case)",
    alg: "Sha-256",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got "Sha-256"',
  },
  {
    label: "sha-512 with trailing space",
    alg: "sha-512 ",
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got "sha-512 "',
  },
  {
    label: "undefined",
    alg: undefined,
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got undefined',
  },
  {
    label: "null",
    alg: null,
    expectedError:
      'contentDigest: "alg" must be "sha-512" or "sha-256", got null',
  },
];

/** Run one corpus case and return its outcome: null on pass, the thrown message otherwise. */
function digestGuardOutcome(
  entry: (typeof DIGEST_GUARD_CORPUS)[number],
): string | null {
  try {
    assertContentDigestAlg(entry.alg);
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

function assertDigestGuardCorpus(label: string): void {
  for (const entry of DIGEST_GUARD_CORPUS) {
    const outcome = digestGuardOutcome(entry);
    if (outcome !== entry.expectedError)
      throw new Error(
        `benchmark self-check failed (${label}): assertContentDigestAlg(${entry.label}) gave ${JSON.stringify(outcome)} ` +
          `(expected ${JSON.stringify(entry.expectedError)})`,
      );
  }
}

/**
 * `assertContentDigestAlg` steady state: one measured call
 * is one pass over the whole fixed corpus (10 guard checks
 * per op, eight of which throw and are caught inside the
 * outcome helper — the fail-closed rejection is part of
 * the steady state, exactly as a caller selecting a digest
 * algorithm pays it) — the configuration guard the signer
 * and `contentDigest` enforce before any hashing runs, so
 * an unsupported algorithm can never be emitted on the
 * wire. Self-checks: the whole corpus is asserted
 * exhaustively outside timing first, and the measured loop
 * re-pins every case's pass/throw outcome on every pass.
 * Zero network, zero randomness, no wall-clock assertions.
 */
function benchmarkAssertContentDigestAlg(): number {
  assertDigestGuardCorpus("outside timing");
  return measure(() => {
    assertDigestGuardCorpus("measured pass");
  }, ITERATIONS);
}

/**
 * Fixed request for the `resolveComponent` path: the shared
 * bench fixture's method / URL shape extended with a query
 * string, a status, trailers and an associated request, so
 * every component form has a value to resolve against. The
 * `content-digest` header carries the pinned sha-512 wire
 * value of the fixture body (the same literal BASE_REQUEST
 * carries); the `x-charge-ref` value keeps the trailing
 * space the `;bs` test suite pins (plain normalization
 * would erase it, the raw-bytes form must not); the
 * `example-dict` value carries the sloppy spacing the `;sf`
 * test suite pins; the `x-dict` value is the dictionary the
 * `;key` test suite pins; the `x-checksum` trailer differs
 * from the same-named header on purpose (the `;tr` test
 * suite's shape), so a resolver reading the wrong source
 * fails the self-check.
 */
const RESOLVE_REQUEST: RequestLike = {
  method: fixture.method,
  url: "https://api.example.com/v1/payments?amount=100&currency=USD",
  headers: {
    "content-type": "application/json",
    "content-digest":
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
    "x-charge-ref": "ch_42, settled ",
    "example-dict": "a=1,  b=2;x=1;  y=2, c=(a   b  c)",
    "x-dict": "a=1, b=2;x=1;y=2, c=(a b c), d",
    "x-checksum": "header-value",
  },
  trailers: { "x-checksum": "trailer-value" },
  status: 200,
  body: fixture.body,
  request: {
    method: "GET",
    url: "https://api.example.com/v1/charge?order=42",
    headers: { "x-charge-id": "ch_42" },
  },
};

/**
 * Fixed corpus for the `resolveComponent` path — eighteen
 * cases written out here, each paired with the exact value
 * the resolver must return for RESOLVE_REQUEST under
 * BASE_PARAMS (created pinned at 1700000000). Composition:
 * - ten derived components: `@method` (uppercased),
 *   `@scheme`, `@authority` (lowercased host), `@path`,
 *   `@query` (leading "?" included), `@request-target`
 *   (path + query, origin form), `@target-uri` (the full
 *   URL), `@query-param;name="amount"` (the one named
 *   parameter's re-encoded value), `@created` (from the
 *   signature parameters) and `@status` (from the fixture's
 *   status);
 * - two plain header fields: `content-type` and
 *   `content-digest` (the demo segment's pinned digest —
 *   the same four-component shape the CLI demo resolves,
 *   widened here with the forms the demo does not cover);
 * - six parameterized forms: `x-charge-ref;bs` (the raw
 *   value, trailing space included, as a `:base64:` byte
 *   sequence — the base64 is written out literally here),
 *   `example-dict;sf` (the strict re-serialization of the
 *   sloppy dictionary), `x-dict;key="b"` (only the selected
 *   member's serialization, key not included),
 *   `x-checksum;tr` (resolved from the trailers, not the
 *   same-named header), `@method;req` and `x-charge-id;req`
 *   (both resolved against the associated request).
 * Every expectation is hand-pinned here from the resolver's
 * contract, cross-checked against the values the demo
 * segment and the bs / sf / key / tr / req / query-param
 * test suites pin independently — never derived from
 * `resolveComponent` at bench time.
 */
const RESOLVE_CORPUS: ReadonlyArray<{
  component: string;
  expected: string;
}> = [
  { component: "@method", expected: "POST" },
  { component: "@scheme", expected: "https" },
  { component: "@authority", expected: "api.example.com" },
  { component: "@path", expected: "/v1/payments" },
  { component: "@query", expected: "?amount=100&currency=USD" },
  {
    component: "@request-target",
    expected: "/v1/payments?amount=100&currency=USD",
  },
  {
    component: "@target-uri",
    expected: "https://api.example.com/v1/payments?amount=100&currency=USD",
  },
  { component: '@query-param;name="amount"', expected: "100" },
  { component: "@created", expected: "1700000000" },
  { component: "@status", expected: "200" },
  { component: "content-type", expected: "application/json" },
  {
    component: "content-digest",
    expected:
      "sha-512=:4HIUuHJ8vINiO2AATKEX/LXYfOo9YkjeZ6IyUzYyAPzc5smC+Bn0HzWXfHusb5AvA1kU6qBMf4sGMhFm6OGI0w==:",
  },
  { component: "x-charge-ref;bs", expected: ":Y2hfNDIsIHNldHRsZWQg:" },
  { component: "example-dict;sf", expected: "a=1, b=2;x=1;y=2, c=(a b c)" },
  { component: 'x-dict;key="b"', expected: "2;x=1;y=2" },
  { component: "x-checksum;tr", expected: "trailer-value" },
  { component: "@method;req", expected: "GET" },
  { component: "x-charge-id;req", expected: "ch_42" },
];

/**
 * Illegal component id for the `resolveComponent` path: a
 * real field component carrying the unsupported `;zz`
 * parameter — the same shape the CLI demo's resolution
 * segment pins. The resolver must reject it before any
 * value is produced; an unsupported parameter is never
 * silently ignored.
 */
const RESOLVE_ILLEGAL_COMPONENT = "content-digest;zz";
/**
 * Hand-pinned rejection message for RESOLVE_ILLEGAL_COMPONENT
 * — the exact string `resolveComponent` throws for an
 * unsupported component parameter (the same literal the
 * demo pins as DEMO_RESOLVE_ILLEGAL_ERROR). Written out
 * here, never derived from the resolver under test.
 */
const RESOLVE_ILLEGAL_ERROR =
  'unsupported component parameter ";zz" on component "content-digest": only ";req", ";bs", ";sf", ";key", ";tr" and ";name" are supported';

function assertResolveCorpus(label: string): void {
  for (const entry of RESOLVE_CORPUS) {
    const actual = resolveComponent(entry.component, RESOLVE_REQUEST, BASE_PARAMS);
    if (actual !== entry.expected)
      throw new Error(
        `benchmark self-check failed (${label}): resolveComponent(${JSON.stringify(entry.component)}) gave ${JSON.stringify(actual)} ` +
          `(expected ${JSON.stringify(entry.expected)})`,
      );
  }
}

/**
 * Exhaustive outside-timing assertion for the
 * `resolveComponent` fixture: the illegal component id is
 * rejected with exactly the hand-pinned
 * RESOLVE_ILLEGAL_ERROR. Kept outside timing — the measured
 * steady state is successful resolutions only, so no
 * exception construction is folded into the number.
 */
function assertResolveIllegal(): void {
  let message: string | null = null;
  try {
    resolveComponent(RESOLVE_ILLEGAL_COMPONENT, RESOLVE_REQUEST, BASE_PARAMS);
  } catch (e) {
    message = e instanceof Error ? e.message : String(e);
  }
  if (message !== RESOLVE_ILLEGAL_ERROR)
    throw new Error(
      `benchmark self-check failed (outside timing): resolveComponent(${JSON.stringify(RESOLVE_ILLEGAL_COMPONENT)}) gave ${JSON.stringify(message)} ` +
        `(expected throw ${JSON.stringify(RESOLVE_ILLEGAL_ERROR)})`,
    );
}

/**
 * `resolveComponent` steady state: one measured call is one
 * pass over the whole fixed corpus (18 resolutions per op)
 * — the per-component step every sign and verify pays once
 * per covered component, isolated here so its cost is
 * visible apart from the `buildSignatureBase` row that
 * bundles it with the `@signature-params` serialization
 * and apart from the end-to-end rows that bundle it with
 * cryptography. Self-checks: the whole corpus plus the
 * illegal-component rejection are asserted exhaustively
 * outside timing first, and the measured loop re-pins every
 * case's value on every pass. Zero network, zero
 * randomness, no wall-clock assertions.
 */
function benchmarkResolveComponent(): number {
  assertResolveCorpus("outside timing");
  assertResolveIllegal();
  return measure(() => {
    assertResolveCorpus("measured pass");
  }, ITERATIONS);
}

function fmt(ops: number): string {
  const s = ops >= 1000 ? ops.toLocaleString("en-US", { maximumFractionDigits: 0 }) : ops.toFixed(1);
  const perOpUs = (1e6 / ops).toFixed(2);
  return `${s} ops/sec (${perOpUs} µs/op)`;
}

console.log("rfc9421-signing-demo benchmark");
console.log(`Node: ${process.version} on ${process.platform}/${process.arch}`);
console.log(`CPU: ${cpus()[0]?.model ?? "unknown"}`);
console.log(`Request: POST with JSON body (${Buffer.byteLength(fixture.body)} bytes), covered: @method @authority @path content-digest`);
console.log(`Iterations per op: ${ITERATIONS} (after ${WARMUP} warmup)`);
console.log("");

const results: Array<{ alg: string; op: string; ops: number }> = [];
for (const alg of [
  "ed25519",
  "hmac-sha256",
  "hmac-sha512",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "ecdsa-p521-sha512",
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
] as const) {
  const { signOps, verifyOps } = benchmarkScenario(alg);
  results.push({ alg, op: "sign", ops: signOps });
  results.push({ alg, op: "verify", ops: verifyOps });
}
results.push({
  alg: "verifyAllLabels (2 labels)",
  op: "verify",
  ops: benchmarkMultiLabel(),
});
const benchStore = offlineJwksStore();
results.push({
  alg: "JwksKeyStore.resolve (hit)",
  op: "resolve",
  ops: benchmarkJwksResolve(benchStore),
});
results.push({
  alg: "JwksKeyStore.requireHttps (resolve)",
  op: "resolve",
  ops: benchmarkJwksRequireHttps(),
});
results.push({
  alg: "memoizeKeyResolver (hit)",
  op: "resolve",
  ops: benchmarkMemoizeHit(benchStore),
});
results.push({
  alg: "memoizeKeyResolver (miss)",
  op: "resolve",
  ops: benchmarkMemoizeMiss(benchStore),
});
results.push({
  alg: "JwksKeyStore.exportSnapshot (3 keys)",
  op: "export",
  ops: benchmarkJwksExportSnapshot(offlineJwksExportStore()),
});
results.push({
  alg: "JwksKeyStore.restoreSnapshot (3 keys)",
  op: "restore",
  ops: await benchmarkJwksRestoreSnapshot(),
});
results.push({
  alg: "verifyRequest keyResolver (2 keyids)",
  op: "verify",
  ops: benchmarkVerifyKeyResolver(),
});
results.push({
  alg: "verifyRequest maxSignatureAgeSec (300s cap)",
  op: "verify",
  ops: benchmarkVerifyMaxSignatureAge(),
});
results.push({
  alg: "verifyRequest requireExpires",
  op: "verify",
  ops: benchmarkVerifyRequireExpires(),
});
results.push({
  alg: "verifyRequest requireCreated",
  op: "verify",
  ops: benchmarkVerifyRequireCreated(),
});
results.push({
  alg: "verifyRequest expectedTag",
  op: "verify",
  ops: benchmarkVerifyExpectedTag(),
});
results.push({
  alg: "verifyRequest replayCache",
  op: "verify",
  ops: benchmarkVerifyReplayCache(),
});
results.push({
  alg: "verifyRequest requireNonce",
  op: "verify",
  ops: benchmarkVerifyRequireNonce(),
});
results.push({
  alg: "verifyRequest requireTag",
  op: "verify",
  ops: benchmarkVerifyRequireTag(),
});
results.push({
  alg: "verifyRequest clockSkewToleranceSec (120s)",
  op: "verify",
  ops: benchmarkVerifyClockSkewTolerance(),
});
results.push({
  alg: "verifyRequest expiredToleranceSec (120s grace)",
  op: "verify",
  ops: benchmarkVerifyExpiredTolerance(),
});
results.push({
  alg: "verifyRequest expectedKeyId",
  op: "verify",
  ops: benchmarkVerifyExpectedKeyId(),
});
results.push({
  alg: "verifyAllLabels expectedKeyIds (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllExpectedKeyIds(),
});
results.push({
  alg: "verifyAllLabels keyResolvers (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllKeyResolvers(),
});
results.push({
  alg: "verifyAllLabels requireNonceByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllRequireNonceByLabel(),
});
results.push({
  alg: "verifyAllLabels candidateKeysByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllCandidateKeysByLabel(),
});
results.push({
  alg: "verifyAllLabels candidateKeysByLabel expectedKeyIds (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllCandidateKeysExpectedKeyIds(),
});
results.push({
  alg: "verifyAllLabels requireTagByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllRequireTagByLabel(),
});
results.push({
  alg: "verifyAllLabels expectedKeyIds requireTag (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllExpectedKeyIdsRequireTag(),
});
results.push({
  alg: "verifyAllLabels requireFreshnessByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllRequireFreshnessByLabel(),
});
results.push({
  alg: "verifyAllLabels requireCreatedExpiresByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllRequireCreatedExpiresByLabel(),
});
results.push({
  alg: "verifyAllLabels expectedTags (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllExpectedTags(),
});
results.push({
  alg: "verifyAllLabels maxSignatureAgeSecByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllMaxSignatureAgeSecByLabel(),
});
results.push({
  alg: "verifyAllLabels clockSkewToleranceSecByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllClockSkewToleranceSecByLabel(),
});
results.push({
  alg: "verifyAllLabels expiredToleranceSecByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllExpiredToleranceSecByLabel(),
});
results.push({
  alg: "verifyAllLabels requiredComponentsByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllRequiredComponentsByLabel(),
});
results.push({
  alg: "verifyAllLabels algFallbackByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllAlgFallbackByLabel(),
});
results.push({
  alg: "verifyAllLabels replayCacheByLabel (2 labels)",
  op: "verify",
  ops: benchmarkVerifyAllReplayCacheByLabel(),
});
results.push({
  alg: "verifyRequest algFallback (infer)",
  op: "verify",
  ops: benchmarkVerifyAlgFallback(),
});
results.push({
  alg: "verifyRequest requiredComponents",
  op: "verify",
  ops: benchmarkVerifyRequiredComponents(),
});
results.push({
  alg: "JwksKeyStore.refreshIfStale (stale)",
  op: "refresh",
  ops: await benchmarkJwksRefreshIfStale(),
});
results.push({
  alg: "JwksKeyStore.refresh (8-way single-flight)",
  op: "refresh",
  ops: await benchmarkJwksConcurrentRefresh(),
});
results.push({
  alg: "JwksKeyStore.refresh (fetchRetries 2, 500/500/200)",
  op: "refresh",
  ops: await benchmarkJwksFetchRetries(),
});
results.push({
  alg: "jwkThumbprint (3 JWK shapes)",
  op: "derive",
  ops: benchmarkJwkThumbprint(),
});
results.push({
  alg: "ReplayCache.check (hit, 1k)",
  op: "check",
  ops: benchmarkReplayCacheHit(),
});
results.push({
  alg: "ReplayCache.exportSnapshot (3 live)",
  op: "export",
  ops: benchmarkReplayCacheExportSnapshot(),
});
results.push({
  alg: "ReplayCache.stats (5 live)",
  op: "stats",
  ops: benchmarkReplayCacheStats(),
});
results.push({
  alg: "ReplayCache.fromSnapshot (4 live)",
  op: "restore",
  ops: benchmarkReplayCacheFromSnapshot(),
});
const malformed = benchmarkMalformedReject();
results.push({
  alg: `verifyRequest (malformed, ${malformed.corpusSize} cases)`,
  op: "reject",
  ops: malformed.ops,
});
results.push({
  alg: "contentDigest sha-512 (31-byte body)",
  op: "digest",
  ops: benchmarkContentDigest("sha-512"),
});
results.push({
  alg: "contentDigest sha-256 (31-byte body)",
  op: "digest",
  ops: benchmarkContentDigest("sha-256"),
});
results.push({
  alg: "fromNodeRequest (inbound, trailers)",
  op: "normalize",
  ops: benchmarkFromNodeRequest(),
});
results.push({
  alg: "fromNodeRequest + verifyRequest (;tr trailer)",
  op: "adapt+verify",
  ops: benchmarkVerifyNodeRequestTrailer(),
});
results.push({
  alg: "fromNodeResponse (@status, loopback)",
  op: "adapt+verify",
  ops: await benchmarkFromNodeResponse(),
});
results.push({
  alg: "JWK round-trip P-256",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-256",
    generateP256KeyPair().publicKey,
    exportPublicKeyJwkP256,
    importPublicKeyJwkP256,
  ),
});
results.push({
  alg: "JWK round-trip P-384",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-384",
    generateP384KeyPair().publicKey,
    exportPublicKeyJwkP384,
    importPublicKeyJwkP384,
  ),
});
results.push({
  alg: "JWK round-trip P-521",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "P-521",
    generateP521KeyPair().publicKey,
    exportPublicKeyJwkP521,
    importPublicKeyJwkP521,
  ),
});
results.push({
  alg: "JWK round-trip RSA-2048",
  op: "roundtrip",
  ops: benchmarkJwkRoundTrip(
    "RSA",
    generateRsaPssKeyPair().publicKey,
    exportPublicKeyJwkRsa,
    importPublicKeyJwkRsa,
  ),
});
results.push({
  alg: "JWK round-trip ed25519",
  op: "roundtrip",
  ops: benchmarkJwkRoundTripEd25519(),
});
results.push({
  alg: "PEM round-trip ed25519",
  op: "roundtrip",
  ops: benchmarkPemRoundTrip(),
});
results.push({
  alg: "buildSignatureBase (4 components)",
  op: "build",
  ops: benchmarkBuildSignatureBase(),
});
results.push({
  alg: "signRequest (ed25519, end-to-end)",
  op: "sign",
  ops: benchmarkSignRequest(),
});
results.push({
  alg: "listSignatureLabels (2 labels)",
  op: "parse",
  ops: benchmarkListSignatureLabels(),
});
results.push({
  alg: "parseSignatureInput (merchant)",
  op: "parse",
  ops: benchmarkParseSignatureInput(),
});
results.push({
  alg: "parseSignatureField (merchant)",
  op: "parse",
  ops: benchmarkParseSignatureField(),
});
results.push({
  alg: "canonicalizeStructuredFieldValue (6 values)",
  op: "canon",
  ops: benchmarkCanonicalizeStructuredFieldValue(),
});
results.push({
  alg: "serializeDictionaryMemberValue (6 keys)",
  op: "extract",
  ops: benchmarkSerializeDictionaryMemberValue(),
});
results.push({
  alg: "serializeSignatureParams (5 cases)",
  op: "serialize",
  ops: benchmarkSerializeSignatureParams(),
});
results.push({
  alg: "generateNonce (16 + 32 bytes)",
  op: "generate",
  ops: benchmarkGenerateNonce(),
});
results.push({
  alg: "verifyRequestOrThrow (valid)",
  op: "verify",
  ops: benchmarkVerifyRequestOrThrowOk(),
});
results.push({
  alg: "verifyRequestOrThrow (tampered)",
  op: "throw",
  ops: benchmarkVerifyRequestOrThrowTampered(),
});
results.push({
  alg: "getHeader/getHeaderRaw (9 names ×2)",
  op: "lookup",
  ops: benchmarkGetHeader(),
});
results.push({
  alg: "joinHeaderValues (9 cases)",
  op: "join",
  ops: benchmarkJoinHeaderValues(),
});
results.push({
  alg: "contentDigestAlgOf (10 cases)",
  op: "identify",
  ops: benchmarkContentDigestAlgOf(),
});
results.push({
  alg: "assertHmacSecretLength (10 cases)",
  op: "guard",
  ops: benchmarkAssertHmacSecretLength(),
});
results.push({
  alg: "assertRsaModulusLength (7 cases)",
  op: "guard",
  ops: benchmarkAssertRsaModulusLength(),
});
results.push({
  alg: "signatureInputValue (4 cases)",
  op: "serialize",
  ops: benchmarkSignatureInputValue(),
});
results.push({
  alg: "assertContentDigestAlg (10 cases)",
  op: "guard",
  ops: benchmarkAssertContentDigestAlg(),
});
results.push({
  alg: "resolveComponent (18 cases)",
  op: "resolve",
  ops: benchmarkResolveComponent(),
});

console.log("alg                                    op      throughput");
console.log("--------------------------------------------------------------------");
for (const r of results) {
  console.log(`${r.alg.padEnd(38)} ${r.op.padEnd(7)} ${fmt(r.ops)}`);
}
console.log("");
console.log("Numbers are machine-local measurements, not guarantees.");
