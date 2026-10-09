/**
 * In-memory nonce replay cache (zero dependencies).
 *
 * Optional defense-in-depth against RFC 9421 signature replay attacks: pair
 * it with the `nonce` signature-input parameter (see `signRequest`). The
 * freshness window (`created`/`expires`) bounds the acceptance window; this
 * cache additionally detects a signature whose *valid* nonce has already been
 * seen inside the window.
 *
 * Honest scope: this is a single-process, in-memory helper. It is not
 * shared between verifier instances. A single process *can* carry its
 * tracked nonces across its own restart: `exportSnapshot()` before
 * shutdown and `ReplayCache.restore()` at startup (see
 * {@link ReplayCacheSnapshot}) — but that covers only the process that
 * saved the snapshot, never a fleet. The `NonceStore` interface below
 * makes the store pluggable — `ReplayCache` is the built-in in-memory
 * implementation; a deployment with multiple verifier processes should
 * implement `NonceStore` over shared storage (e.g. Redis) for real
 * replay protection — see SECURITY.md.
 */

/**
 * Pluggable nonce store for replay detection (zero dependencies).
 *
 * `check` has the same check-and-record contract as `ReplayCache.check`:
 * returns `true` when the nonce was already seen within the tracking
 * window (i.e. this is a replay); otherwise records the nonce and returns
 * `false`. `verifyRequest` invokes it synchronously with the nonce and the
 * verification time (unix seconds), so an implementation that needs an
 * async backend (e.g. a Redis client) cannot be awaited inside `check`:
 * do the async check-and-record in the caller's own layer instead
 * (see SECURITY.md for the pattern).
 *
 * `ReplayCache` is the built-in in-memory implementation of this
 * interface. Implementations must never report a replay for a nonce they
 * have never recorded — verification fails closed only on
 * explicitly-seen nonces — and should reject empty nonces the way
 * `ReplayCache.check` does.
 */
export interface NonceStore {
  check(nonce: string, now?: number): boolean;
}

export interface ReplayCacheOptions {
  /**
   * Maximum number of nonces tracked. When exceeded, the least recently
   * seen nonce is evicted (LRU). Defaults to 10_000. Must be >= 1.
   */
  maxEntries?: number;
  /**
   * Seconds a seen nonce stays tracked. A nonce older than this is treated
   * as unseen (and its slot is reclaimed). Defaults to 3600. Must be > 0.
   */
  ttlSec?: number;
  /**
   * Clock source (unix seconds). Defaults to the wall clock. Inject a fake
   * clock for deterministic tests.
   */
  now?: () => number;
}

/**
 * Observability snapshot of a {@link ReplayCache}.
 *
 * - `size`: live (unexpired) entries tracked, computed against the cache's
 *   injected clock — same reading as the `size` getter.
 * - `hits`: `check` calls where the nonce was already seen within the TTL
 *   (i.e. replays).
 * - `misses`: `check` calls where the nonce was unseen and got recorded
 *   (including a nonce whose previous record had expired — expiry means
 *   "unseen").
 * - `evictions`: entries dropped by `prune` to make room — both
 *   expired-entry reclamation and LRU eviction count. The delete+re-record
 *   of an expired nonce inside `check` is part of the miss path and is
 *   *not* an eviction.
 *
 * Counters reset to zero on `clear()`.
 */
export interface ReplayCacheStats {
  size: number;
  hits: number;
  misses: number;
  evictions: number;
}

/**
 * Serializable snapshot of a {@link ReplayCache}, produced by
 * `exportSnapshot()` and consumed by `ReplayCache.restore()`.
 *
 * - `v`: snapshot format version. Only `1` exists; `restore` rejects
 *   any other value (including a missing `v`) instead of guessing.
 * - `entries`: `[nonce, seenAt]` pairs in LRU order (least recently
 *   seen first). `seenAt` is a unix-seconds timestamp in the same unit
 *   as `ReplayCacheOptions.now` / the `now` argument of `check` — the
 *   original first-seen time, *not* the export time, so a restored
 *   nonce keeps counting down its original TTL instead of getting a
 *   fresh window. Only entries still live at export time are included.
 *
 * The observability counters (`hits`/`misses`/`evictions`) are *not*
 * part of the snapshot: a restored cache starts them at zero.
 *
 * The snapshot is plain JSON data (`JSON.stringify` it to persist it),
 * but it is not a shared store: two processes restoring the same
 * snapshot afterwards diverge, and nonces recorded by one are invisible
 * to the other. Multi-instance deployments still need shared storage
 * behind the `NonceStore` interface.
 */
export interface ReplayCacheSnapshot {
  v: 1;
  entries: Array<[nonce: string, seenAt: number]>;
}

export class ReplayCache implements NonceStore {
  private readonly maxEntries: number;
  private readonly ttlSec: number;
  private readonly clock: () => number;
  /** nonce -> first-seen-at (unix seconds). Insertion order = LRU order. */
  private readonly seenAt = new Map<string, number>();
  private hits = 0;
  private misses = 0;
  private evictions = 0;

  constructor(opts: ReplayCacheOptions = {}) {
    const maxEntries = opts.maxEntries ?? 10_000;
    const ttlSec = opts.ttlSec ?? 3600;
    if (!Number.isInteger(maxEntries) || maxEntries < 1)
      throw new Error("ReplayCache: maxEntries must be a positive integer");
    if (!Number.isFinite(ttlSec) || ttlSec <= 0)
      throw new Error("ReplayCache: ttlSec must be a positive finite number");
    this.maxEntries = maxEntries;
    this.ttlSec = ttlSec;
    this.clock = opts.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Atomically check-and-record: returns `true` when the nonce was already
   * seen within the TTL (i.e. this is a replay); otherwise records the
   * nonce and returns `false`.
   *
   * Expired entries are treated as unseen and reclaimed. On a replay hit
   * the entry's recency is refreshed but its original first-seen timestamp
   * is kept, so repeated replays cannot extend the tracking window.
   * Accepts an explicit `now` (unix seconds) so callers can share their
   * own clock with the cache; defaults to the injected clock.
   */
  check(nonce: string, now?: number): boolean {
    if (nonce === "")
      throw new Error("ReplayCache: nonce must be non-empty");
    const t = now ?? this.clock();
    const prev = this.seenAt.get(nonce);
    if (prev !== undefined) {
      if (t - prev < this.ttlSec) {
        // Refresh LRU recency (delete + re-insert moves it to the tail)
        // while keeping the original first-seen timestamp.
        this.seenAt.delete(nonce);
        this.seenAt.set(nonce, prev);
        this.hits++;
        return true; // replay
      }
      // Expired: drop and fall through to re-record with a fresh timestamp.
      // This is the miss path (an expired record means "unseen"), not an
      // eviction — the delete is immediately followed by a re-record.
      this.seenAt.delete(nonce);
    }
    this.prune(t);
    this.seenAt.set(nonce, t);
    this.misses++;
    return false;
  }

  /**
   * Number of live (unexpired) entries tracked, computed against the
   * cache's injected clock. If callers pass their own `now` to `check`
   * (as `verifyRequest` does with the verification time), give the cache
   * the same clock via `ReplayCacheOptions.now` for a consistent reading.
   */
  get size(): number {
    const t = this.clock();
    let n = 0;
    for (const at of this.seenAt.values()) if (t - at < this.ttlSec) n++;
    return n;
  }

  /** Drop all tracked nonces and reset the observability counters. */
  clear(): void {
    this.seenAt.clear();
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  /**
   * Point-in-time observability snapshot `{ size, hits, misses, evictions }`
   * (see {@link ReplayCacheStats}). The returned object is a fresh copy —
   * mutating it does not affect the cache.
   */
  stats(): ReplayCacheStats {
    return { size: this.size, hits: this.hits, misses: this.misses, evictions: this.evictions };
  }

  /**
   * Export the live tracked nonces as a detached, JSON-serializable
   * {@link ReplayCacheSnapshot}: persist it before a restart and pass
   * it to `ReplayCache.restore()` at startup so the restart does not
   * reopen the replay window for nonces seen inside their TTL.
   *
   * Entries already expired against this cache's clock are excluded.
   * The returned object (including every entry pair) is a fresh copy —
   * mutating it does not affect this cache.
   */
  exportSnapshot(): ReplayCacheSnapshot {
    const t = this.clock();
    const entries: Array<[string, number]> = [];
    for (const [nonce, at] of this.seenAt) {
      if (t - at < this.ttlSec) entries.push([nonce, at]);
    }
    return { v: 1, entries };
  }

  /**
   * Rebuild a cache from a snapshot produced by `exportSnapshot()`
   * (typically after a `JSON.parse` of the persisted form). `opts`
   * configures the *new* cache (`maxEntries`/`ttlSec`/`now`) and is
   * validated exactly like the constructor's.
   *
   * The input is untrusted data and is validated strictly: a non-object
   * snapshot, an unknown top-level field, a `v` other than `1`, a
   * non-array `entries`, or a malformed entry (not a `[nonce, seenAt]`
   * pair, an empty/non-string nonce, a non-finite or negative `seenAt`)
   * throws a configuration `Error` — a corrupt snapshot fails loudly at
   * startup rather than silently disabling replay protection.
   *
   * Entries already expired against the new cache's clock are dropped.
   * If the surviving entries exceed `maxEntries`, the oldest by
   * `seenAt` are evicted first until the cache fits (ties break by
   * snapshot order, least recently seen first). Duplicate nonces
   * collapse to their last occurrence. TTLs keep counting from each
   * entry's original `seenAt` — restoring never extends a nonce's
   * tracking window. Observability counters start at zero: the load-time
   * drops above are not counted as `evictions`.
   *
   * This covers a single process across its own restart only; see
   * {@link ReplayCacheSnapshot} for the multi-instance limit.
   */
  static restore(snapshot: unknown, opts: ReplayCacheOptions = {}): ReplayCache {
    const fail = (detail: string): never => {
      throw new Error(`ReplayCache: invalid snapshot: ${detail}`);
    };
    if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot))
      fail("expected an object of the form { v: 1, entries: [...] }");
    const record = snapshot as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key !== "v" && key !== "entries") fail(`unknown field "${key}"`);
    }
    if (record.v !== 1)
      fail(
        `unsupported snapshot version ${JSON.stringify(record.v) ?? String(record.v)} (expected 1)`,
      );
    const rawEntries: unknown = record.entries;
    if (!Array.isArray(rawEntries)) fail("entries must be an array");
    const entriesList = rawEntries as unknown[];
    const parsed: Array<[string, number]> = [];
    for (let i = 0; i < entriesList.length; i++) {
      const entry: unknown = entriesList[i];
      if (!Array.isArray(entry) || entry.length !== 2)
        fail(`entries[${i}] must be a [nonce, seenAt] pair`);
      const pair = entry as unknown[];
      const nonce: unknown = pair[0];
      const seenAt: unknown = pair[1];
      if (typeof nonce !== "string" || nonce === "")
        fail(`entries[${i}]: nonce must be a non-empty string`);
      if (typeof seenAt !== "number" || !Number.isFinite(seenAt) || seenAt < 0)
        fail(`entries[${i}]: seenAt must be a finite non-negative number (unix seconds)`);
      parsed.push([nonce as string, seenAt as number]);
    }

    const cache = new ReplayCache(opts);
    const t = cache.clock();
    // Drop entries whose TTL already ran out against the new clock, and
    // collapse duplicate nonces to their last occurrence (position and
    // timestamp), mirroring the recency refresh in `check`.
    const live = new Map<string, number>();
    for (const [nonce, at] of parsed) {
      if (t - at >= cache.ttlSec) continue;
      live.delete(nonce);
      live.set(nonce, at);
    }
    let kept = [...live.entries()];
    if (kept.length > cache.maxEntries) {
      const excess = kept.length - cache.maxEntries;
      const drop = new Set(
        kept
          .map((_, i) => i)
          .sort((a, b) => kept[a][1] - kept[b][1] || a - b)
          .slice(0, excess),
      );
      kept = kept.filter((_, i) => !drop.has(i));
    }
    for (const [nonce, at] of kept) cache.seenAt.set(nonce, at);
    return cache;
  }

  /** Alias of {@link ReplayCache.restore} (snapshot naming). */
  static fromSnapshot(snapshot: unknown, opts: ReplayCacheOptions = {}): ReplayCache {
    return ReplayCache.restore(snapshot, opts);
  }

  /**
   * Make room for one new entry: reclaim expired entries first, then evict
   * the least recently seen ones. Map iteration order is insertion order,
   * so the head is always the oldest entry. Every entry dropped here
   * counts as an eviction for observability.
   */
  private prune(t: number): void {
    if (this.seenAt.size < this.maxEntries) return;
    for (const [nonce, at] of this.seenAt) {
      if (t - at >= this.ttlSec) {
        this.seenAt.delete(nonce);
        this.evictions++;
      }
      if (this.seenAt.size < this.maxEntries) return;
    }
    while (this.seenAt.size >= this.maxEntries) {
      const oldest = this.seenAt.keys().next();
      if (oldest.done) break;
      this.seenAt.delete(oldest.value);
      this.evictions++;
    }
  }
}
