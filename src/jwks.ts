import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  importPublicKeyJwk,
  importPublicKeyJwkP256,
  importPublicKeyJwkRsa,
  type Ed25519PublicJwk,
  type P256PublicJwk,
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
 * One key in a {@link JwksKeyStoreSnapshot}: a public-key-only JWK in
 * exactly one of the three shapes this library's JWK importers accept
 * (ed25519 / P-256 / RSA), tagged with the `kid` it resolves under.
 * Private material never appears here — the store only ever holds
 * imported *public* keys, and the exporters refuse anything else.
 */
export type JwksSnapshotKey =
  | (Ed25519PublicJwk & { kid: string })
  | (P256PublicJwk & { kid: string })
  | (RsaPublicJwk & { kid: string });

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
      if (o["kty"] === "OKP") key = importPublicKeyJwk(entry);
      else if (o["kty"] === "EC") key = importPublicKeyJwkP256(entry);
      else if (o["kty"] === "RSA") key = importPublicKeyJwkRsa(entry);
      else
        throw new Error(
          `unsupported kty ${JSON.stringify(o["kty"])} (supported: "OKP", "EC", "RSA")`,
        );
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
      else if (key.asymmetricKeyType === "ec")
        keys.push({ ...exportPublicKeyJwkP256(key), kid });
      else if (key.asymmetricKeyType === "rsa")
        keys.push({ ...exportPublicKeyJwkRsa(key), kid });
      else
        // Unreachable: refresh()/restore only import the three types
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
   */
  resolve = (keyId: string): KeyObject | undefined => {
    if (typeof keyId !== "string" || keyId.length === 0) return undefined;
    return this.keysByKid.get(keyId);
  };
}
