/**
 * In-memory nonce replay cache (zero dependencies).
 *
 * Optional defense-in-depth against RFC 9421 signature replay attacks: pair
 * it with the `nonce` signature-input parameter (see `signRequest`). The
 * freshness window (`created`/`expires`) bounds the acceptance window; this
 * cache additionally detects a signature whose *valid* nonce has already been
 * seen inside the window.
 *
 * Honest scope: this is a single-process, in-memory helper. It does not
 * survive restarts and is not shared between verifier instances. The
 * `NonceStore` interface below makes the store pluggable — `ReplayCache`
 * is the built-in in-memory implementation; a deployment with multiple
 * verifier processes should implement `NonceStore` over shared storage
 * (e.g. Redis) for real replay protection — see SECURITY.md.
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
