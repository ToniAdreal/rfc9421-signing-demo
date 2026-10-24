import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkP384,
  exportPublicKeyJwkP521,
  exportPublicKeyJwkRsa,
  importPublicKeyJwk,
  importPublicKeyJwkP256,
  importPublicKeyJwkP384,
  importPublicKeyJwkP521,
  importPublicKeyJwkRsa,
  type Ed25519PublicJwk,
  type P256PublicJwk,
  type P384PublicJwk,
  type P521PublicJwk,
  type RsaPublicJwk,
} from "./keys.js";

/**
 * The minimal slice of the Fetch API's `Response` that
 * {@link JwksKeyStore} consumes. The global `fetch` (Node ≥ 20) returns
 * objects satisfying this shape; tests and non-standard runtimes can
 * inject any function returning it.
 */
export interface JwksFetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

/**
 * Fetch implementation used by {@link JwksKeyStore.refresh}. Receives
 * the JWKS endpoint URL and resolves with the response. Defaults to the
 * global `fetch`.
 */
export type JwksFetchImpl = (url: string) => Promise<JwksFetchResponse>;

/**
 * Sleep implementation used between JWKS fetch retries (see
 * {@link JwksKeyStoreOptions.sleepImpl}). Receives the delay in
 * milliseconds and resolves when it has elapsed. Defaults to a
 * `setTimeout`-based sleep.
 */
export type JwksSleepImpl = (ms: number) => Promise<void>;

/**
 * Options for {@link JwksKeyStore}.
 */
export interface JwksKeyStoreOptions {
  /**
   * Fetch implementation for {@link JwksKeyStore.refresh}. Defaults to
   * the global `fetch` (Node ≥ 20, zero runtime dependencies — nothing
   * is bundled). Inject a stub in tests or behind a proxy / custom TLS
   * stack in production.
   */
  fetchImpl?: JwksFetchImpl;
  /**
   * Seconds a fetched snapshot is considered fresh for
   * {@link JwksKeyStore.isStale}. Defaults to 300. Must be a finite
   * number > 0. `isStale()` is advisory only: `resolve` keeps serving
   * the last good snapshot past the TTL until a `refresh()` succeeds,
   * so a JWKS outage never turns into a verification outage.
   */
  ttlSec?: number;
  /**
   * Injected clock returning unix seconds — the same convention as
   * `ReplayCacheOptions.now` / `MemoizeKeyResolverOptions.now` — so
   * tests can pin time deterministically. Defaults to the wall clock.
   */
  now?: () => number;
  /**
   * Opt-in fetch timeout in milliseconds, so a hung JWKS endpoint
   * cannot leave `refresh()` unsettled forever: key rotation is the
   * path that must keep working precisely during an outage, and under
   * the single-flight mechanism every waiter shares the in-flight
   * fetch, so one hang stalls them all.
   *
   * Must be a positive integer. When set, the default fetch performs
   * `globalThis.fetch(url, { signal })` with an `AbortController`
   * that aborts at the deadline; the timeout throws
   * `JwksKeyStore: JWKS fetch timed out after Nms` from `refresh()`
   * with the previous snapshot and freshness timestamp untouched
   * (fail-closed, counted as a refresh failure).
   *
   * Applies to the DEFAULT fetch only. The `JwksFetchImpl` signature
   * takes no signal, so a custom `fetchImpl` never receives one —
   * custom implementations must implement their own timeout if they
   * need one. Unset by default (zero behavior change).
   */
  fetchTimeoutMs?: number;
  /**
   * Opt-in transport-layer enforcement: when `true`, the JWKS
   * endpoint URL must use `https:` — a plaintext `http:` endpoint is
   * rejected at construction with a configuration error, before any
   * fetch happens. Whatever the endpoint serves becomes a
   * verification key, so over plaintext a path attacker can
   * substitute the entire key set; the plain-HTTP allowance exists
   * only for loopback development and tests.
   *
   * Defaults to `false` (an `http:` endpoint is allowed, so no
   * configuration change is zero behavior change). This is a
   * construction-time check only: it does not intercept a fetch
   * that is later redirected from https to http.
   */
  requireHttps?: boolean;
  /**
   * Opt-in fetch retries: how many times `refresh()` re-attempts a
   * failed fetch before giving up. Defaults to `0` — the current
   * single-attempt behavior, so no configuration change is zero
   * behavior change. Must be a non-negative integer.
   *
   * Only transient failures are retried: network errors from the
   * fetch itself, and HTTP 5xx responses. A 4xx response, a malformed
   * JWKS document, and a `fetchTimeoutMs` abort are terminal — a
   * bad document will not heal by re-fetching, a 4xx says the
   * request itself is wrong, and re-hanging a hung endpoint per
   * attempt gains nothing (the caller re-calls `refresh()` when
   * ready). Retries never multiply the `stats()` counters: one
   * `refresh()` call counts once, however many attempts it made.
   */
  fetchRetries?: number;
  /**
   * Fixed delay in milliseconds between fetch retry attempts (see
   * {@link JwksKeyStoreOptions.fetchRetries}). Defaults to `1000`.
   * Must be a finite number >= 0; `0` means retry immediately. The
   * delay is fixed, not exponential — a JWKS refresh is
   * caller-driven and infrequent, so one predictable pause per
   * retry is enough, and it keeps the worst-case refresh latency
   * bounded and easy to reason about.
   */
  fetchBackoffMs?: number;
  /**
   * Sleep implementation used between fetch retries. Defaults to a
   * `setTimeout`-based sleep. Inject a stub in tests to record the
   * requested delays without waiting for them.
   */
  sleepImpl?: JwksSleepImpl;
}

/**
 * Point-in-time observability counters for a {@link JwksKeyStore},
 * returned by {@link JwksKeyStore.stats} (mirroring `ReplayCache`'s
 * `stats()`).
 *
 * - `refreshes`: successful refreshes — one per `refresh()` call
 *   that fetched and swapped a snapshot, so concurrent calls merged
 *   by the single-flight mechanism count once, not once per waiter,
 *   and retry attempts inside one `refresh()` do not multiply the
 *   count either.
 * - `refreshFailures`: failed refreshes, under the same once-per-
 *   `refresh()`-call counting (a failed refresh shared by N waiters
 *   counts once, and a refresh that exhausted its retries counts
 *   once, not once per attempt).
 * - `hits`: `resolve()` calls that returned a key.
 * - `misses`: `resolve()` calls that returned `undefined` — an unknown
 *   keyid, any keyid before the first successful refresh, or an
 *   invalid (non-string / empty) keyid. `hits + misses` therefore
 *   equals the total number of `resolve()` calls.
 *
 * Counters start at zero, run for the lifetime of the store, and are
 * deliberately NOT part of a snapshot: `exportSnapshot()` does not
 * carry them and `restoreSnapshot()` does not reset them, so a
 * process that carries its keys across its own restart keeps one
 * continuous count. (A store built by the static
 * `JwksKeyStore.restore()` is a new store and starts at zero, like
 * any freshly constructed store.)
 */
export interface JwksKeyStoreStats {
  refreshes: number;
  refreshFailures: number;
  hits: number;
  misses: number;
}

/**
 * One key in a {@link JwksKeyStoreSnapshot}: a public-key-only JWK in
 * exactly one of the five shapes this library's JWK importers accept
 * (ed25519 / P-256 / P-384 / P-521 / RSA), tagged with the `kid` it
 * resolves under.
 * Private material never appears here — the store only ever holds
 * imported *public* keys, and the exporters refuse anything else.
 */
export type JwksSnapshotKey =
  | (Ed25519PublicJwk & { kid: string })
  | (P256PublicJwk & { kid: string })
  | (P384PublicJwk & { kid: string })
  | (P521PublicJwk & { kid: string })
  | (RsaPublicJwk & { kid: string });

/**
 * Import one JWK object from a JWKS document or a persisted snapshot.
 * The verify side supports all three NIST curves, so EC entries are
 * dispatched by `crv` (`P-256` / `P-384` / `P-521`); any other curve —
 * or a missing `crv` — is an explicit `Error`, never a silent skip:
 * dropping a key the publisher expects verifiers to use would be a
 * nastier surprise than a loud setup error. Callers wrap the thrown
 * error with their own document/kid context.
 */
function importJwkEntry(entry: unknown): KeyObject {
  const o = entry as Record<string, unknown>;
  const kty = o["kty"];
  if (kty === "OKP") return importPublicKeyJwk(entry);
  if (kty === "RSA") return importPublicKeyJwkRsa(entry);
  if (kty === "EC") {
    const crv = o["crv"];
    if (crv === "P-256") return importPublicKeyJwkP256(entry);
    if (crv === "P-384") return importPublicKeyJwkP384(entry);
    if (crv === "P-521") return importPublicKeyJwkP521(entry);
    throw new Error(
      `unsupported EC crv ${JSON.stringify(crv)} (supported: "P-256", "P-384", "P-521")`,
    );
  }
  throw new Error(
    `unsupported kty ${JSON.stringify(kty)} (supported: "OKP", "EC", "RSA")`,
  );
}

/**
 * Serializable snapshot of a {@link JwksKeyStore}, produced by
 * `exportSnapshot()` and consumed by `JwksKeyStore.restore()` /
 * `JwksKeyStore.fromSnapshot()` / `restoreSnapshot()`.
 *
 * - `v`: snapshot format version. Only `1` exists; restore rejects
 *   any other value (including a missing `v`) instead of guessing.
 * - `fetchedAtSec`: unix seconds of the successful `refresh()` that
 *   produced the snapshotted keys — the *original* fetch time, not
 *   the export time. A restored store's `isStale()` counts from this
 *   timestamp, so restoring never renews freshness: a snapshot taken
 *   just before its TTL expires is stale almost immediately after a
 *   restart, exactly as if no restart had happened.
 * - `keys`: the snapshot's public keys, each carrying its `kid`.
 *
 * The snapshot is plain JSON data (`JSON.stringify` it to persist
 * it), but it is **not signed and not integrity-protected**: anyone
 * who can rewrite the persisted snapshot can substitute their own
 * verification keys. Treat it as trusted configuration — store and
 * transport it only where you would store the JWKS endpoint's own
 * trust decision — and the endpoint-trust responsibility described on
 * {@link JwksKeyStore} is unchanged: whatever keys are restored
 * become verification keys.
 *
 * A snapshot covers a single process across its own restart only:
 * two processes restoring the same snapshot afterwards diverge, and
 * rotations fetched by one are invisible to the other.
 */
export interface JwksKeyStoreSnapshot {
  v: 1;
  fetchedAtSec: number;
  keys: JwksSnapshotKey[];
}

/**
 * Strictly validate untrusted snapshot data and import every key it
 * carries, returning the parsed freshness timestamp and key map.
 * Shared by the static and instance restore paths so both fail
 * identically. Throws a descriptive configuration `Error` on any
 * defect — restore is fail-closed, never partially applied.
 *
 * Deliberate semantic difference from `refresh()`: a JWKS entry
 * without a usable `kid` is *skipped* by `refresh()` (the document
 * may legitimately publish keys for other protocols), but a snapshot
 * entry without a `kid` is *fatal* here. A snapshot is this store's
 * own export format, so a kid-less entry means corrupt or tampered
 * data, not a foreign key — silently dropping it could retire a key
 * the operator believes is still being served.
 */
function parseJwksSnapshot(snapshot: unknown): {
  fetchedAtSec: number;
  keysByKid: Map<string, KeyObject>;
} {
  const fail = (detail: string): never => {
    throw new Error(`JwksKeyStore: invalid snapshot: ${detail}`);
  };
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot))
    fail("expected an object of the form { v: 1, fetchedAtSec, keys: [...] }");
  const record = snapshot as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (key !== "v" && key !== "fetchedAtSec" && key !== "keys")
      fail(`unknown field "${key}"`);
  }
  if (record["v"] !== 1)
    fail(
      `unsupported snapshot version ${JSON.stringify(record["v"]) ?? String(record["v"])} (expected 1)`,
    );
  const fetchedAtSec = record["fetchedAtSec"];
  if (
    typeof fetchedAtSec !== "number" ||
    !Number.isFinite(fetchedAtSec) ||
    fetchedAtSec < 0
  )
    fail("fetchedAtSec must be a finite non-negative number (unix seconds)");
  const rawKeysUnknown: unknown = record["keys"];
  if (!Array.isArray(rawKeysUnknown)) fail(`"keys" must be an array`);
  const rawKeys = rawKeysUnknown as unknown[];
  const keysByKid = new Map<string, KeyObject>();
  for (let i = 0; i < rawKeys.length; i++) {
    const entry: unknown = rawKeys[i];
    if (typeof entry !== "object" || entry === null || Array.isArray(entry))
      fail(`keys[${i}] must be a JWK object`);
    const o = entry as Record<string, unknown>;
    const kid = o["kid"];
    if (typeof kid !== "string" || kid.length === 0)
      fail(
        `keys[${i}]: kid must be a non-empty string ` +
          `(snapshot restore is fail-closed: unlike refresh(), kid-less entries are not skipped)`,
      );
    let key: KeyObject;
    try {
      key = importJwkEntry(entry);
    } catch (err) {
      throw new Error(
        `JwksKeyStore: invalid snapshot: keys[${i}] for kid ${JSON.stringify(kid)}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    // Duplicate kids: the later entry wins, matching refresh().
    keysByKid.set(kid as string, key);
  }
  return { fetchedAtSec: fetchedAtSec as number, keysByKid };
}

/**
 * Network key discovery for RFC 9421 verifiers: fetch a JWKS document
 * (RFC 7517) from an HTTPS endpoint, import every public key it
 * publishes, and resolve `keyid`s against the fetched snapshot.
 *
 * This is the layer that was missing between the JWK importers
 * (`importPublicKeyJwk` / `importPublicKeyJwkP256` /
 * `importPublicKeyJwkP384` / `importPublicKeyJwkP521` /
 * `importPublicKeyJwkRsa` in `keys.ts`, which convert one JWK each) and
 * `VerifyOptions.keyResolver` (which maps a claimed `keyid` to a key,
 * synchronously, in-process). Gateways and webhook receivers publish
 * their signing keys as JWKS precisely so verifiers can pick up key
 * rotation without a redeploy; this store is that pick-up mechanism:
 *
 * ```ts
 * const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json");
 * await store.refresh(); // async fetch stays in the caller's layer
 * const result = verifyRequest(signed, { keyResolver: store.resolve });
 * ```
 *
 * Architecture notes (deliberate, mirroring `NonceStore`):
 *
 * - **Fetching is async, resolution is sync.** `verifyRequest` calls
 *   `keyResolver` synchronously, so the network fetch cannot live
 *   inside `resolve`. `refresh()` is the async half, called by the
 *   caller at startup and whenever `isStale()` says the snapshot is
 *   old (or on a timer); `resolve` is the sync half, deliberately an
 *   arrow-function property so `store.resolve` can be passed to
 *   `verifyRequest` / `memoizeKeyResolver` without `.bind(store)`.
 * - **A failed refresh never touches the old snapshot.** HTTP errors,
 *   non-JSON bodies, malformed JWKS documents, and entries the JWK
 *   importers reject (including any entry carrying private `"d"`
 *   material) all throw a descriptive configuration `Error` from
 *   `refresh()` and leave the previously fetched keys — and the
 *   freshness timestamp — exactly as they were. Verification therefore
 *   fails closed on *unknown* keyids (`resolve` → `undefined` →
 *   `KEY_RESOLUTION_FAILED`), never on a half-parsed key set.
 * - **Entries without a usable `kid` are skipped, not fatal.** A JWKS
 *   may publish keys for other protocols that carry no `kid`; they
 *   simply cannot be selected by `keyid`, so they are ignored while
 *   their well-formed siblings still import.
 * - **Supported key types** are exactly the ones the importers support:
 *   `kty: "OKP"` (ed25519), `kty: "EC"` with `crv: "P-256"`, `"P-384"`,
 *   or `"P-521"`, and `kty: "RSA"`. Any other `kty` — or an `EC` entry
 *   with an unsupported or missing `crv` — makes `refresh()` throw:
 *   silently dropping a key the publisher expects verifiers to use
 *   would be a nastier surprise than a loud setup error.
 * - **Duplicate `kid`s** within one document: the later entry wins
 *   (ordinary dictionary semantics).
 * - **Refreshes are single-flight.** Concurrent `refresh()` calls —
 *   and stale `refreshIfStale()` calls — share one in-flight fetch
 *   and its single atomic snapshot replacement, so a burst of
 *   verifiers hitting a stale window together cannot thundering-herd
 *   the JWKS endpoint. A settled refresh is never reused: the next
 *   call fetches again, and a failure is never cached.
 * - **Observable via `stats()`.** Successful/failed refreshes and
 *   `resolve()` hits/misses are counted for the store's lifetime (see
 *   {@link JwksKeyStoreStats} for the exact counting rules, including
 *   the single-flight rule that merged calls count once), so an
 *   operator can tell whether rotation is taking effect and whether
 *   misses look like misconfiguration or retired keys. Retry
 *   attempts inside one `refresh()` do not multiply the counters.
 * - **Opt-in fetch retries.** With `fetchRetries` set, a `refresh()`
 *   re-attempts transient failures (network errors, HTTP 5xx) after
 *   a fixed `fetchBackoffMs` pause, up to the configured retry
 *   count; 4xx responses, malformed documents, and fetch timeouts
 *   are terminal. The previous snapshot is untouched until an
 *   attempt fully succeeds, so retries can never install a partial
 *   key set.
 *
 * Honest limits: trusting the endpoint is the caller's responsibility —
 * this store performs no TLS pinning, no response-signature check, and
 * no allow-listing beyond requiring an `http:`/`https:` URL; whatever
 * the endpoint serves becomes a verification key, so only point it at
 * origins you trust, over HTTPS. Rotation works by re-fetching: a
 * revoked key keeps verifying until the next successful `refresh()`
 * replaces the snapshot, bounded by how often the caller refreshes
 * (see `ttlSec` / `isStale()`). The snapshot is per-process and
 * in-memory only; multiple verifier processes each keep their own. A
 * single process *can* carry its snapshot across its own restart —
 * `exportSnapshot()` before shutdown, `JwksKeyStore.restore()` at
 * startup — so a cold start during a JWKS outage can still verify
 * with the last fetched keys (staleness still counted from the
 * original fetch time; see {@link JwksKeyStoreSnapshot}). This
 * library never writes the snapshot anywhere itself: persisting it,
 * and protecting its integrity, is the caller's job.
 */
export class JwksKeyStore {
  private readonly url: string;
  private readonly fetchImpl: JwksFetchImpl;
  private readonly ttlSec: number;
  private readonly clock: () => number;
  /**
   * Whether the store uses the default fetch. The timeout only applies
   * to the default fetch (see `fetchTimeoutMs`): a custom `fetchImpl`
   * never receives an abort signal, so it is never wrapped in one.
   */
  private readonly usingDefaultFetch: boolean;
  /** Opt-in fetch timeout in milliseconds, or undefined when unset. */
  private readonly fetchTimeoutMs?: number;
  /** Opt-in fetch retry count (0 = single attempt, the default). */
  private readonly fetchRetries: number;
  /** Fixed delay in milliseconds between fetch retry attempts. */
  private readonly fetchBackoffMs: number;
  /** Sleep implementation used between fetch retry attempts. */
  private readonly sleepImpl: JwksSleepImpl;
  /** kid -> imported public key, from the last successful refresh. */
  private keysByKid = new Map<string, KeyObject>();
  /** Unix seconds of the last successful refresh, or null if none. */
  private lastRefreshAtSec: number | null = null;
  /**
   * The single in-flight refresh, if any (single-flight). Concurrent
   * `refresh()` / stale `refreshIfStale()` calls all await this same
   * promise instead of each fetching. Cleared as soon as the refresh
   * settles — success or failure — so a later call always starts a
   * fresh fetch (a failure is never cached).
   */
  private inFlightRefresh: Promise<void> | null = null;
  /** Successful actual fetches (single-flight merges count once). */
  private refreshCount = 0;
  /** Failed actual fetches (single-flight merges count once). */
  private refreshFailureCount = 0;
  /** `resolve()` calls that returned a key. */
  private hitCount = 0;
  /** `resolve()` calls that returned `undefined`. */
  private missCount = 0;

  constructor(url: string, opts: JwksKeyStoreOptions = {}) {
    if (typeof url !== "string" || url.length === 0)
      throw new Error(
        `JwksKeyStore: \`url\` must be a non-empty string, got ${String(url)}`,
      );
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(
        `JwksKeyStore: \`url\` is not a valid URL: ${JSON.stringify(url)}`,
      );
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:")
      throw new Error(
        `JwksKeyStore: \`url\` must use http: or https:, got ${JSON.stringify(parsed.protocol)}`,
      );
    const {
      fetchImpl,
      ttlSec = 300,
      now,
      fetchTimeoutMs,
      requireHttps,
      fetchRetries = 0,
      fetchBackoffMs = 1000,
      sleepImpl,
    } = opts;
    if (requireHttps !== undefined && typeof requireHttps !== "boolean")
      throw new Error(
        `JwksKeyStore: \`requireHttps\` must be a boolean, got ${String(requireHttps)}`,
      );
    if (requireHttps === true && parsed.protocol !== "https:")
      throw new Error(
        `JwksKeyStore: \`requireHttps\` requires https: for the JWKS endpoint, got ${JSON.stringify(parsed.protocol)}`,
      );
    if (fetchImpl !== undefined && typeof fetchImpl !== "function")
      throw new Error("JwksKeyStore: `fetchImpl` must be a function");
    if (typeof ttlSec !== "number" || !Number.isFinite(ttlSec) || ttlSec <= 0)
      throw new Error(
        `JwksKeyStore: \`ttlSec\` must be a finite number > 0, got ${String(ttlSec)}`,
      );
    if (now !== undefined && typeof now !== "function")
      throw new Error(
        "JwksKeyStore: `now` must be a function returning unix seconds",
      );
    if (
      fetchTimeoutMs !== undefined &&
      (typeof fetchTimeoutMs !== "number" ||
        !Number.isInteger(fetchTimeoutMs) ||
        fetchTimeoutMs <= 0)
    )
      throw new Error(
        `JwksKeyStore: \`fetchTimeoutMs\` must be a positive integer (milliseconds), got ${String(fetchTimeoutMs)}`,
      );
    if (
      typeof fetchRetries !== "number" ||
      !Number.isInteger(fetchRetries) ||
      fetchRetries < 0
    )
      throw new Error(
        `JwksKeyStore: \`fetchRetries\` must be a non-negative integer, got ${String(fetchRetries)}`,
      );
    if (
      typeof fetchBackoffMs !== "number" ||
      !Number.isFinite(fetchBackoffMs) ||
      fetchBackoffMs < 0
    )
      throw new Error(
        `JwksKeyStore: \`fetchBackoffMs\` must be a finite number >= 0 (milliseconds), got ${String(fetchBackoffMs)}`,
      );
    if (sleepImpl !== undefined && typeof sleepImpl !== "function")
      throw new Error("JwksKeyStore: `sleepImpl` must be a function");
    this.url = url;
    this.usingDefaultFetch = fetchImpl === undefined;
    this.fetchImpl = fetchImpl ?? ((u: string) => globalThis.fetch(u));
    this.fetchTimeoutMs = fetchTimeoutMs;
    this.fetchRetries = fetchRetries;
    this.fetchBackoffMs = fetchBackoffMs;
    this.sleepImpl =
      sleepImpl ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    this.ttlSec = ttlSec;
    this.clock = now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** The JWKS endpoint URL this store fetches from. */
  get endpoint(): string {
    return this.url;
  }

  /** Number of keys in the current snapshot (0 before any refresh). */
  get size(): number {
    return this.keysByKid.size;
  }

  /**
   * Unix seconds of the last successful `refresh()`, or `null` when no
   * refresh has succeeded yet. A failed refresh never moves this.
   */
  get lastRefreshedAt(): number | null {
    return this.lastRefreshAtSec;
  }

  /**
   * Whether the snapshot should be re-fetched: `true` when no refresh
   * has succeeded yet, or when the last successful refresh is at least
   * `ttlSec` old by the store's clock. Advisory only — see the class
   * documentation for why `resolve` keeps serving a stale snapshot.
   */
  isStale(): boolean {
    if (this.lastRefreshAtSec === null) return true;
    return this.clock() - this.lastRefreshAtSec >= this.ttlSec;
  }

  /**
   * Point-in-time observability snapshot `{ refreshes, refreshFailures,
   * hits, misses }` (see {@link JwksKeyStoreStats} for the exact
   * counting rules). The returned object is a fresh copy — mutating
   * it does not affect the store's counters.
   */
  stats(): JwksKeyStoreStats {
    return {
      refreshes: this.refreshCount,
      refreshFailures: this.refreshFailureCount,
      hits: this.hitCount,
      misses: this.missCount,
    };
  }

  /**
   * Refresh only when the snapshot is stale: the convenience form of
   * the caller's `if (store.isStale()) await store.refresh()` loop.
   *
   * Returns `false` — and never calls the configured `fetchImpl` —
   * when {@link JwksKeyStore.isStale} reports the snapshot fresh.
   * Returns `true` after delegating to {@link JwksKeyStore.refresh}
   * when the snapshot is stale (including when no refresh has ever
   * succeeded), inheriting all of `refresh()`'s atomic semantics: on
   * failure this method throws the same descriptive `Error` and the
   * previous snapshot and freshness timestamp are left untouched, so
   * the store remains stale and a later call will retry.
   *
   * Concurrency: refreshes are single-flight — overlapping calls
   * that observe a stale snapshot share the one in-flight fetch (see
   * {@link JwksKeyStore.refresh}) instead of each fetching, and all
   * of them settle with that fetch's outcome.
   */
  async refreshIfStale(): Promise<boolean> {
    if (!this.isStale()) return false;
    await this.refresh();
    return true;
  }

  /**
   * Fetch the JWKS document and atomically replace the key snapshot.
   *
   * Single-flight: while one refresh is in flight, concurrent
   * `refresh()` calls (and stale `refreshIfStale()` calls, which
   * delegate here) do not fetch again — they all await the same
   * in-flight promise, share its one atomic snapshot replacement on
   * success, and receive the same error on failure. Only overlapping
   * calls are merged: once the in-flight refresh settles, the next
   * `refresh()` performs a real fetch again, so a failure is never
   * cached and can be retried immediately. While a refresh is in
   * flight, `resolve` keeps serving the previous complete snapshot.
   *
   * Throws a descriptive configuration `Error` — and leaves the
   * previous snapshot and freshness timestamp untouched — when the
   * fetch itself fails, the response is not `ok`, the body is not
   * JSON, the document is not a `{ keys: [...] }` object, or any
   * `kid`-carrying entry is rejected by the JWK importers (wrong shape,
   * unsupported `kty`, or private `"d"` material). Entries with a
   * missing or empty `kid` are skipped (see class documentation).
   */
  refresh(): Promise<void> {
    if (this.inFlightRefresh !== null) return this.inFlightRefresh;
    let flight: Promise<void>;
    flight = this.performRefresh().finally(() => {
      if (this.inFlightRefresh === flight) this.inFlightRefresh = null;
    });
    this.inFlightRefresh = flight;
    return flight;
  }

  /**
   * The actual fetch-and-swap behind {@link JwksKeyStore.refresh},
   * with the {@link JwksKeyStoreStats} counting applied here — inside
   * the single-flight body — so a refresh shared by any number of
   * concurrent waiters counts exactly once, as a success or as a
   * failure.
   */
  private async performRefresh(): Promise<void> {
    try {
      await this.fetchAndSwap();
      this.refreshCount++;
    } catch (err) {
      this.refreshFailureCount++;
      throw err;
    }
  }

  /**
   * Whether an error is a `fetchTimeoutMs` abort. Timeout aborts are
   * terminal for retries (see {@link JwksKeyStoreOptions.fetchRetries}),
   * so the retry loop needs to tell them apart from ordinary network
   * failures. The timeout error carries no distinct type — it is
   * matched by its pinned message (see `fetchWithTimeout`), which the
   * timeout tests nail down verbatim.
   */
  private isFetchTimeoutError(err: unknown): boolean {
    return (
      err instanceof Error &&
      err.message.startsWith("JwksKeyStore: JWKS fetch timed out after ")
    );
  }

  /** A single fetch attempt: no retry, no status handling. */
  private async fetchOnce(): Promise<JwksFetchResponse> {
    if (this.usingDefaultFetch && this.fetchTimeoutMs !== undefined) {
      return this.fetchWithTimeout();
    }
    try {
      return await this.fetchImpl(this.url);
    } catch (err) {
      throw new Error(
        `JwksKeyStore: failed to fetch JWKS from ${this.url}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  /**
   * Fetch with the opt-in retry policy: up to `fetchRetries + 1`
   * attempts in total, sleeping a fixed `fetchBackoffMs` between
   * attempts. Only network errors and HTTP 5xx responses are
   * retried; a 4xx response, a malformed response shape, and a
   * `fetchTimeoutMs` abort are terminal on the first attempt that
   * sees them. A response that is not `ok` but carries no `json()`
   * method is passed through untouched — `fetchAndSwap`'s shape
   * check, not this loop, owns that contract violation, so the
   * error ordering for malformed responses is unchanged.
   *
   * On exhaustion the last attempt's error is thrown unchanged, so
   * a caller that distinguishes "HTTP 500" from "network down" from
   * "timed out" keeps seeing exactly the error the final attempt
   * produced. The old snapshot and freshness timestamp are
   * untouched throughout — this method only ever returns a
   * response (or throws); swapping happens in `fetchAndSwap`.
   */
  private async fetchWithRetries(): Promise<JwksFetchResponse> {
    const maxAttempts = this.fetchRetries + 1;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      let res: JwksFetchResponse;
      try {
        res = await this.fetchOnce();
      } catch (err) {
        if (this.isFetchTimeoutError(err) || attempt === maxAttempts - 1)
          throw err;
        await this.sleepImpl(this.fetchBackoffMs);
        continue;
      }
      if (
        typeof res === "object" &&
        res !== null &&
        typeof res.json === "function" &&
        !res.ok
      ) {
        if (
          typeof res.status === "number" &&
          res.status >= 500 &&
          attempt < maxAttempts - 1
        ) {
          await this.sleepImpl(this.fetchBackoffMs);
          continue;
        }
        throw new Error(
          `JwksKeyStore: JWKS fetch failed: HTTP ${String(res.status)} from ${this.url}`,
        );
      }
      return res;
    }
    // Unreachable: every iteration returns, throws, or continues to
    // the next attempt, and the last attempt always returns or throws.
    throw new Error("JwksKeyStore: unreachable fetch retry state");
  }

  /** Fetch the JWKS document and build/swap the next snapshot. */
  private async fetchAndSwap(): Promise<void> {
    const res = await this.fetchWithRetries();
    if (
      typeof res !== "object" ||
      res === null ||
      typeof res.json !== "function"
    )
      throw new Error(
        `JwksKeyStore: fetch for ${this.url} did not return a response with a json() method`,
      );
    let doc: unknown;
    try {
      doc = await res.json();
    } catch (err) {
      throw new Error(
        `JwksKeyStore: JWKS response from ${this.url} is not valid JSON: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    // Build the next snapshot fully before swapping it in: any failure
    // below must leave the previous snapshot untouched.
    const next = new Map<string, KeyObject>();
    if (typeof doc !== "object" || doc === null || Array.isArray(doc))
      throw new Error(
        `JwksKeyStore: invalid JWKS from ${this.url}: expected an object with a "keys" array`,
      );
    const keys = (doc as Record<string, unknown>)["keys"];
    if (!Array.isArray(keys))
      throw new Error(
        `JwksKeyStore: invalid JWKS from ${this.url}: "keys" must be an array`,
      );
    for (const entry of keys) {
      if (typeof entry !== "object" || entry === null || Array.isArray(entry))
        throw new Error(
          `JwksKeyStore: invalid JWKS from ${this.url}: every entry in "keys" must be a JWK object`,
        );
      const o = entry as Record<string, unknown>;
      const kid = o["kid"];
      if (typeof kid !== "string" || kid.length === 0) continue; // skipped, not fatal
      let key: KeyObject;
      try {
        key = importJwkEntry(entry);
      } catch (err) {
        throw new Error(
          `JwksKeyStore: invalid JWKS from ${this.url}: entry for kid ${JSON.stringify(kid)}: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
      next.set(kid, key);
    }
    this.keysByKid = next;
    this.lastRefreshAtSec = this.clock();
  }

  /**
   * The default fetch with an abort deadline applied: an
   * `AbortController` aborts the request when `fetchTimeoutMs`
   * elapses, and the resulting abort rejection becomes a descriptive
   * timeout `Error` (not the generic fetch-failure wrap), so callers
   * can tell a hung endpoint apart from any other fetch failure.
   *
   * Any other failure — network error, DNS failure, non-2xx handled
   * later in `fetchAndSwap` — keeps the existing error shapes, so the
   * timeout is purely additive. The timer is always cleared.
   *
   * Deliberately separate from `fetchImpl`: only the default fetch is
   * constructed here with a `signal`, and only the default-fetch path
   * calls this method, so a custom `fetchImpl` is never timed out —
   * the timeout only applies to the default fetch, as documented on
   * {@link JwksKeyStoreOptions.fetchTimeoutMs}.
   */
  private async fetchWithTimeout(): Promise<JwksFetchResponse> {
    const timeoutMs = this.fetchTimeoutMs as number;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await globalThis.fetch(this.url, {
        signal: controller.signal,
      });
      return res as unknown as JwksFetchResponse;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error(
          `JwksKeyStore: JWKS fetch timed out after ${timeoutMs}ms`,
        );
      }
      throw new Error(
        `JwksKeyStore: failed to fetch JWKS from ${this.url}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Export the current snapshot as detached, JSON-serializable data
   * (see {@link JwksKeyStoreSnapshot}): persist it before a restart
   * and restore it at startup so the new process can verify offline
   * with the last fetched keys instead of being unable to verify
   * until its first successful `refresh()`.
   *
   * Only public key material is exported — the store holds nothing
   * else — each key re-exported through the same JWK exporter for
   * its `kty` and tagged with its `kid`. The returned object
   * (including every key) is a fresh copy: mutating it does not
   * affect this store.
   *
   * Throws when no `refresh()` has ever succeeded: there is no
   * meaningful `fetchedAtSec` for keys that were never fetched, and
   * exporting an empty placeholder would let a caller persist a
   * keyless snapshot that looks legitimate. (A store whose refresh
   * succeeded but imported zero keys — every entry was kid-less —
   * exports a valid snapshot with `keys: []`.)
   */
  exportSnapshot(): JwksKeyStoreSnapshot {
    if (this.lastRefreshAtSec === null)
      throw new Error(
        "JwksKeyStore: cannot export a snapshot before a successful refresh() " +
          "(no keys have been fetched yet)",
      );
    const keys: JwksSnapshotKey[] = [];
    for (const [kid, key] of this.keysByKid) {
      if (key.asymmetricKeyType === "ed25519")
        keys.push({ ...exportPublicKeyJwk(key), kid });
      else if (key.asymmetricKeyType === "ec") {
        // The store imports P-256/P-384/P-521 by crv; export by the same
        // rule so a fetched P-384/P-521 key survives a snapshot round-trip.
        const curve = key.asymmetricKeyDetails?.namedCurve;
        if (curve === "prime256v1")
          keys.push({ ...exportPublicKeyJwkP256(key), kid });
        else if (curve === "secp384r1")
          keys.push({ ...exportPublicKeyJwkP384(key), kid });
        else if (curve === "secp521r1")
          keys.push({ ...exportPublicKeyJwkP521(key), kid });
        else
          throw new Error(
            `JwksKeyStore: cannot export key for kid ${JSON.stringify(kid)}: ` +
              `unsupported EC curve ${String(curve)} ` +
              `(expected one of prime256v1, secp384r1, secp521r1)`,
          );
      } else if (key.asymmetricKeyType === "rsa")
        keys.push({ ...exportPublicKeyJwkRsa(key), kid });
      else
        // Unreachable: refresh()/restore only import the five types
        // above. Fail loudly rather than silently dropping a key.
        throw new Error(
          `JwksKeyStore: cannot export key for kid ${JSON.stringify(kid)}: ` +
            `unsupported asymmetricKeyType ${String(key.asymmetricKeyType)}`,
        );
    }
    return { v: 1, fetchedAtSec: this.lastRefreshAtSec, keys };
  }

  /**
   * Atomically replace this store's snapshot with one produced by
   * `exportSnapshot()` (typically after a `JSON.parse` of the
   * persisted form), without any network access. On success the
   * store's endpoint, `fetchImpl`, TTL and clock are unchanged; only
   * the keys and the freshness timestamp are replaced, and the
   * timestamp is the snapshot's original `fetchedAtSec` — restoring
   * never renews freshness, so `isStale()` may immediately report
   * `true` and the caller's normal refresh loop takes it from there.
   * Restoring also does not reset the `stats()` counters: they are
   * not part of the snapshot and keep running across a restore.
   *
   * The input is untrusted data and is validated strictly (see
   * {@link JwksKeyStoreSnapshot} and the note on `parseJwksSnapshot`):
   * a malformed snapshot, an entry carrying private `"d"` material,
   * an unsupported `kty`/curve, or a kid-less entry throws a
   * descriptive `Error` and leaves the current snapshot and freshness
   * timestamp exactly as they were — restore is fail-closed and
   * never partially applied.
   *
   * The snapshot is not signed: treat it as trusted configuration
   * (see {@link JwksKeyStoreSnapshot}).
   */
  restoreSnapshot(snapshot: unknown): void {
    const { fetchedAtSec, keysByKid } = parseJwksSnapshot(snapshot);
    this.keysByKid = keysByKid;
    this.lastRefreshAtSec = fetchedAtSec;
  }

  /**
   * Build a new store for `url` pre-loaded with a snapshot produced
   * by `exportSnapshot()` — the cold-start path: the returned store
   * resolves and verifies immediately, with no network access, and
   * its staleness counts from the snapshot's original `fetchedAtSec`.
   * `opts` configures the new store (`fetchImpl`/`ttlSec`/`now`) and
   * is validated exactly like the constructor's; the endpoint is
   * still needed because later `refresh()` calls fetch from it.
   *
   * Snapshot validation is identical to
   * {@link JwksKeyStore.restoreSnapshot}: any defect throws and no
   * store is produced.
   */
  static restore(
    snapshot: unknown,
    url: string,
    opts: JwksKeyStoreOptions = {},
  ): JwksKeyStore {
    const store = new JwksKeyStore(url, opts);
    store.restoreSnapshot(snapshot);
    return store;
  }

  /** Alias of {@link JwksKeyStore.restore} (snapshot naming). */
  static fromSnapshot(
    snapshot: unknown,
    url: string,
    opts: JwksKeyStoreOptions = {},
  ): JwksKeyStore {
    return JwksKeyStore.restore(snapshot, url, opts);
  }

  /**
   * Synchronously resolve a `keyid` against the fetched snapshot —
   * shaped exactly as `VerifyOptions.keyResolver`, and deliberately an
   * arrow-function property so it can be passed by reference
   * (`verifyRequest(req, { keyResolver: store.resolve })`, or wrapped
   * with `memoizeKeyResolver(store.resolve)`) without binding.
   *
   * Returns `undefined` for unknown keyids (and before the first
   * successful `refresh()`), which `verifyRequest` fails closed as
   * `KEY_RESOLUTION_FAILED`. Never throws and never performs I/O.
   * Every call is counted by {@link JwksKeyStore.stats}: returning a
   * key is a hit, returning `undefined` (including for an invalid
   * keyid) is a miss.
   */
  resolve = (keyId: string): KeyObject | undefined => {
    if (typeof keyId !== "string" || keyId.length === 0) {
      this.missCount++;
      return undefined;
    }
    const key = this.keysByKid.get(keyId);
    if (key === undefined) this.missCount++;
    else this.hitCount++;
    return key;
  };
}
