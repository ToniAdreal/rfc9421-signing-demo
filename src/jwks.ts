import type { KeyObject } from "node:crypto";
import {
  importPublicKeyJwk,
  importPublicKeyJwkP256,
  importPublicKeyJwkRsa,
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
}

/**
 * Network key discovery for RFC 9421 verifiers: fetch a JWKS document
 * (RFC 7517) from an HTTPS endpoint, import every public key it
 * publishes, and resolve `keyid`s against the fetched snapshot.
 *
 * This is the layer that was missing between the JWK importers
 * (`importPublicKeyJwk` / `importPublicKeyJwkP256` /
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
 *   `kty: "OKP"` (ed25519), `kty: "EC"` with `crv: "P-256"`, and
 *   `kty: "RSA"`. Any other `kty` makes `refresh()` throw — silently
 *   dropping a key the publisher expects verifiers to use would be a
 *   nastier surprise than a loud setup error.
 * - **Duplicate `kid`s** within one document: the later entry wins
 *   (ordinary dictionary semantics).
 *
 * Honest limits: trusting the endpoint is the caller's responsibility —
 * this store performs no TLS pinning, no response-signature check, and
 * no allow-listing beyond requiring an `http:`/`https:` URL; whatever
 * the endpoint serves becomes a verification key, so only point it at
 * origins you trust, over HTTPS. Rotation works by re-fetching: a
 * revoked key keeps verifying until the next successful `refresh()`
 * replaces the snapshot, bounded by how often the caller refreshes
 * (see `ttlSec` / `isStale()`). The snapshot is per-process and
 * in-memory only; multiple verifier processes each keep their own.
 */
export class JwksKeyStore {
  private readonly url: string;
  private readonly fetchImpl: JwksFetchImpl;
  private readonly ttlSec: number;
  private readonly clock: () => number;
  /** kid -> imported public key, from the last successful refresh. */
  private keysByKid = new Map<string, KeyObject>();
  /** Unix seconds of the last successful refresh, or null if none. */
  private lastRefreshAtSec: number | null = null;

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
    const { fetchImpl, ttlSec = 300, now } = opts;
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
    this.url = url;
    this.fetchImpl =
      fetchImpl ?? ((u: string) => globalThis.fetch(u));
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
   * Concurrency: concurrent calls are NOT deduplicated — there is no
   * in-flight promise sharing, so two overlapping calls that both
   * observe a stale snapshot may each perform a fetch (the later
   * successful snapshot simply replaces the earlier one, exactly as
   * with two overlapping `refresh()` calls). Callers that need
   * single-flight behaviour must serialize calls themselves.
   */
  async refreshIfStale(): Promise<boolean> {
    if (!this.isStale()) return false;
    await this.refresh();
    return true;
  }

  /**
   * Fetch the JWKS document and atomically replace the key snapshot.
   *
   * Throws a descriptive configuration `Error` — and leaves the
   * previous snapshot and freshness timestamp untouched — when the
   * fetch itself fails, the response is not `ok`, the body is not
   * JSON, the document is not a `{ keys: [...] }` object, or any
   * `kid`-carrying entry is rejected by the JWK importers (wrong shape,
   * unsupported `kty`, or private `"d"` material). Entries with a
   * missing or empty `kid` are skipped (see class documentation).
   */
  async refresh(): Promise<void> {
    let res: JwksFetchResponse;
    try {
      res = await this.fetchImpl(this.url);
    } catch (err) {
      throw new Error(
        `JwksKeyStore: failed to fetch JWKS from ${this.url}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    if (
      typeof res !== "object" ||
      res === null ||
      typeof res.json !== "function"
    )
      throw new Error(
        `JwksKeyStore: fetch for ${this.url} did not return a response with a json() method`,
      );
    if (!res.ok)
      throw new Error(
        `JwksKeyStore: JWKS fetch failed: HTTP ${String(res.status)} from ${this.url}`,
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
        if (o["kty"] === "OKP") key = importPublicKeyJwk(entry);
        else if (o["kty"] === "EC") key = importPublicKeyJwkP256(entry);
        else if (o["kty"] === "RSA") key = importPublicKeyJwkRsa(entry);
        else
          throw new Error(
            `unsupported kty ${JSON.stringify(o["kty"])} (supported: "OKP", "EC", "RSA")`,
          );
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
   * Synchronously resolve a `keyid` against the fetched snapshot —
   * shaped exactly as `VerifyOptions.keyResolver`, and deliberately an
   * arrow-function property so it can be passed by reference
   * (`verifyRequest(req, { keyResolver: store.resolve })`, or wrapped
   * with `memoizeKeyResolver(store.resolve)`) without binding.
   *
   * Returns `undefined` for unknown keyids (and before the first
   * successful `refresh()`), which `verifyRequest` fails closed as
   * `KEY_RESOLUTION_FAILED`. Never throws and never performs I/O.
   */
  resolve = (keyId: string): KeyObject | undefined => {
    if (typeof keyId !== "string" || keyId.length === 0) return undefined;
    return this.keysByKid.get(keyId);
  };
}
