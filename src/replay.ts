import { createHmac, timingSafeEqual } from "node:crypto";

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
 *
 * The unsigned snapshot is trusted configuration only: anyone who can
 * rewrite the persisted snapshot can delete tracked nonces and reopen
 * the replay window. For an integrity-protected form, use the signed
 * envelope instead (see {@link ReplayCacheSignedSnapshotEnvelope} and
 * `ReplayCache.exportSignedSnapshot()` /
 * `ReplayCache.restoreSignedSnapshot()`): the unsigned snapshot stays
 * unsigned, the envelope is the opt-in that catches a rewrite.
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
 * but it is **not signed and not integrity-protected**: anyone who can
 * rewrite the persisted snapshot can delete tracked nonces and reopen
 * the replay window for them. Treat it as trusted configuration —
 * store and transport it only where you would store the verifier's own
 * trust decision — and for an integrity-protected form, use the signed
 * envelope instead (see {@link ReplayCacheSignedSnapshotEnvelope} and
 * `ReplayCache.exportSignedSnapshot()` /
 * `ReplayCache.restoreSignedSnapshot()`): the unsigned snapshot stays
 * unsigned, the envelope is the opt-in that catches a rewrite.
 *
 * A snapshot covers a single process across its own restart only:
 * two processes restoring the same snapshot afterwards diverge, and
 * nonces recorded by one are invisible to the other. Multi-instance
 * deployments still need shared storage behind the `NonceStore`
 * interface.
 */
export interface ReplayCacheSnapshot {
  v: 1;
  entries: Array<[nonce: string, seenAt: number]>;
}

/**
 * Integrity-protected form of a {@link ReplayCacheSnapshot}, produced
 * by `ReplayCache.exportSignedSnapshot(secret)` and consumed by
 * `ReplayCache.restoreSignedSnapshot(envelope, secret, opts?)` (see
 * those methods for the exact contract). Same envelope shape as the
 * JWKS signed snapshot (`JwksSignedSnapshotEnvelope`).
 *
 * - `v`: envelope format version. Only `1` exists; restore rejects
 *   any other value (including a missing `v`) instead of guessing.
 * - `snapshot`: the wrapped {@link ReplayCacheSnapshot}, exactly as
 *   `exportSnapshot()` produces it (live nonces only, with their
 *   original first-seen timestamps).
 * - `mac`: lowercase hex HMAC-SHA256 over the canonical JSON of
 *   `snapshot` (object keys sorted recursively, array order
 *   preserved) under the caller's secret.
 *
 * The envelope carries no secret: the secret is caller configuration,
 * never persisted in the envelope, and the same secret must be
 * supplied at restore time. An envelope with any other field is
 * rejected, so a caller cannot smuggle extra data (including a
 * secret) past restore. The MAC is integrity protection only — it
 * proves the snapshot was not rewritten by anyone without the
 * secret — not confidentiality: the nonces inside are not secrets
 * (they are wire-visible values from signed requests), and the
 * envelope itself is plain JSON. A caller that needs the snapshot
 * kept private must encrypt it separately; this envelope does not.
 */
export interface ReplayCacheSignedSnapshotEnvelope {
  v: 1;
  snapshot: ReplayCacheSnapshot;
  mac: string;
}

/**
 * Options for {@link ReplayCache.restoreSignedSnapshotsByLabel}:
 * the {@link ReplayCacheOptions} of every restored cache, plus an
 * optional expected label set.
 *
 * - `expectedLabels`: when provided, the envelope map must contain
 *   exactly these labels. An unknown/extra label, or a missing
 *   expected label, fails the whole restore. This is the label
 *   binding the per-label MAC cannot provide on its own: the MAC
 *   covers a label's snapshot, not the label name, so without an
 *   expected set a persisted file could gain a copied envelope
 *   under a label the deployment never had (the copied MAC still
 *   verifies). When omitted, any label set is accepted — each label
 *   is still individually MAC-verified, so a forged label cannot be
 *   smuggled in without the secret.
 */
export interface ReplayCacheSignedSnapshotsByLabelOptions
  extends ReplayCacheOptions {
  expectedLabels?: readonly string[];
}

/**
 * Export the signed snapshot envelope of every cache in `caches`,
 * keyed by the same labels (`VerifyAllOptions.replayCacheByLabel`
 * shape): `{ [label]: ReplayCacheSignedSnapshotEnvelope }`. A
 * multi-signature deployment persists one envelope per label and
 * restores them together with
 * {@link ReplayCache.restoreSignedSnapshotsByLabel} — a rewritten
 * entry in any label's persisted snapshot is caught at restore
 * instead of silently reopening that label's replay window.
 *
 * The input is caller configuration and is validated strictly: a
 * non-object map, an empty label, or a value that is not a
 * `ReplayCache` throws a configuration `Error` before any envelope
 * is produced. The secret is validated the same way as
 * {@link ReplayCache.exportSignedSnapshot} (non-empty string or
 * `Buffer`). An empty map exports to an empty map.
 */
export function exportSignedSnapshotsByLabel(
  caches: Record<string, ReplayCache>,
  secret: string | Buffer,
): Record<string, ReplayCacheSignedSnapshotEnvelope> {
  const secretBytes = signedSnapshotSecretBytes(secret);
  if (
    typeof caches !== "object" ||
    caches === null ||
    Array.isArray(caches)
  )
    throw new Error(
      "ReplayCache: signed snapshot export expects a label -> ReplayCache object",
    );
  const envelopes: Record<string, ReplayCacheSignedSnapshotEnvelope> = {};
  for (const label of Object.keys(caches)) {
    if (label === "")
      throw new Error(
        "ReplayCache: signed snapshot label must be a non-empty string",
      );
    const cache = caches[label];
    if (!(cache instanceof ReplayCache))
      throw new Error(
        `ReplayCache: signed snapshot export: caches["${label}"] must be a ReplayCache`,
      );
    envelopes[label] = cache.exportSignedSnapshot(secretBytes);
  }
  return envelopes;
}

/**
 * Canonical JSON for snapshot MACing: object keys sorted
 * recursively (so a JSON round-trip that reorders keys still
 * verifies), array order preserved (reordering entries would change
 * which nonce wins a duplicate, so it must change the MAC), and
 * primitives via `JSON.stringify`. A non-JSON value (notably
 * `undefined`, which `JSON.stringify` would silently drop) throws
 * instead of being silently normalized — a MAC computed over a
 * silently altered document would be worse than no MAC.
 * Same semantics as the JWKS signed snapshot's canonical form.
 */
function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new Error(
        "ReplayCache: cannot canonicalize a non-finite number for snapshot signing",
      );
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new Error(
    `ReplayCache: cannot canonicalize a non-JSON value of type ${typeof value} for snapshot signing`,
  );
}

/**
 * Validate a signed-snapshot secret and return its bytes. A secret
 * is a non-empty string (UTF-8) or a non-empty `Buffer` — the same
 * input shapes as `keys.secretKey`, but deliberately without that
 * helper's 32-byte floor: this MAC is integrity protection for a
 * list of already wire-visible nonces, and the backlog contract for
 * this helper rejects only an empty secret, so a shorter caller
 * secret is the caller's risk to take (use a long random secret;
 * the envelope never records how long it was). An empty or
 * wrongly typed secret is a caller-configuration error, thrown
 * before any cache state is touched.
 */
function signedSnapshotSecretBytes(secret: unknown): Buffer {
  if (typeof secret === "string") {
    if (secret.length === 0)
      throw new Error(
        "ReplayCache: signed snapshot secret must not be empty",
      );
    return Buffer.from(secret, "utf8");
  }
  if (Buffer.isBuffer(secret)) {
    if (secret.length === 0)
      throw new Error(
        "ReplayCache: signed snapshot secret must not be empty",
      );
    return secret;
  }
  throw new Error(
    `ReplayCache: signed snapshot secret must be a non-empty string or Buffer, got ${typeof secret}`,
  );
}

/** HMAC-SHA256 (hex) over the canonical JSON of a snapshot. */
function computeSnapshotMac(
  snapshot: ReplayCacheSnapshot,
  secretBytes: Buffer,
): string {
  return createHmac("sha256", secretBytes)
    .update(canonicalJson(snapshot), "utf8")
    .digest("hex");
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
   * Export the current snapshot wrapped in an HMAC-signed envelope
   * (see {@link ReplayCacheSignedSnapshotEnvelope}): `{ v: 1, snapshot,
   * mac }` where `mac` is HMAC-SHA256 over the canonical JSON of
   * the snapshot under `secret`. Persist the envelope (plain JSON)
   * before a restart and restore it with
   * {@link ReplayCache.restoreSignedSnapshot} — a process that
   * restarts keeps rejecting nonces seen inside their TTL, and anyone
   * who rewrites the persisted entries without the secret is caught
   * at restore instead of silently reopening the replay window.
   *
   * The secret is never written into the envelope, and the envelope
   * is integrity protection only, not encryption: the nonces inside
   * are wire-visible values, so the envelope itself needs no secrecy,
   * but the secret must be kept where the snapshot writer keeps its
   * other signing-side secrets. An empty secret is a
   * caller-configuration error. The unsigned `exportSnapshot()`
   * path is unchanged: this envelope is opt-in, and a caller that
   * never signs keeps the old trusted-configuration semantics.
   */
  exportSignedSnapshot(secret: string | Buffer): ReplayCacheSignedSnapshotEnvelope {
    const secretBytes = signedSnapshotSecretBytes(secret);
    const snapshot = this.exportSnapshot();
    return { v: 1, snapshot, mac: computeSnapshotMac(snapshot, secretBytes) };
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
   * Rebuild a cache from a signed envelope produced by
   * {@link ReplayCache.exportSignedSnapshot} (typically after a
   * `JSON.parse` of the persisted form). `opts` configures the *new*
   * cache (`maxEntries`/`ttlSec`/`now`) and is validated exactly
   * like the constructor's. The returned cache is a fresh object —
   * nothing is installed into any existing cache, so a failed
   * restore leaves the caller's caches untouched.
   *
   * Restore is fail-closed in the same order as the unsigned path,
   * with authenticity checked first: an envelope with an unknown
   * field (including a smuggled `secret`), a version other than
   * `1`, a malformed `mac`, or a MAC that does not match the
   * snapshot under `secret` throws a descriptive configuration
   * `Error` and no cache is produced — a tampered entry, a tampered
   * `seenAt`, or a wrong secret all fail here, before any snapshot
   * parsing, so a tampered envelope can never partially install. A
   * MAC-valid envelope whose snapshot is itself malformed then
   * fails through the same strict snapshot validation as
   * {@link ReplayCache.restore}, again with no cache produced. The
   * MAC comparison is constant-time over equal-length hex digests; a
   * wrong-length `mac` is rejected as malformed before comparison.
   *
   * On success the semantics are exactly {@link ReplayCache.restore}'s:
   * expired entries are dropped, over-capacity snapshots keep the
   * newest entries, TTLs keep counting from each entry's original
   * `seenAt`, and the observability counters start at zero.
   */
  static restoreSignedSnapshot(
    envelope: unknown,
    secret: string | Buffer,
    opts: ReplayCacheOptions = {},
  ): ReplayCache {
    const secretBytes = signedSnapshotSecretBytes(secret);
    const fail = (detail: string): never => {
      throw new Error(`ReplayCache: invalid signed snapshot envelope: ${detail}`);
    };
    if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope))
      fail("expected an object of the form { v: 1, snapshot, mac }");
    const record = envelope as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key !== "v" && key !== "snapshot" && key !== "mac")
        fail(`unknown field "${key}"`);
    }
    if (record.v !== 1)
      fail(
        `unsupported envelope version ${JSON.stringify(record.v) ?? String(record.v)} (expected 1)`,
      );
    const mac = record.mac;
    if (typeof mac !== "string" || !/^[0-9a-f]{64}$/.test(mac))
      throw new Error(
        "ReplayCache: invalid signed snapshot envelope: mac must be a 64-character lowercase hex HMAC-SHA256 digest",
      );
    const snapshot = record.snapshot;
    if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot))
      fail('"snapshot" must be an object');
    const expectedMac = computeSnapshotMac(
      snapshot as ReplayCacheSnapshot,
      secretBytes,
    );
    const macBytes = Buffer.from(mac, "hex");
    const expectedBytes = Buffer.from(expectedMac, "hex");
    if (
      macBytes.length !== expectedBytes.length ||
      !timingSafeEqual(macBytes, expectedBytes)
    )
      throw new Error(
        "ReplayCache: signed snapshot MAC mismatch: the snapshot was tampered with or the secret is wrong",
      );
    // MAC verified — now the same strict structural validation as restore().
    return ReplayCache.restore(snapshot, opts);
  }

  /** Alias of {@link ReplayCache.restoreSignedSnapshot} (snapshot naming). */
  static fromSignedSnapshot(
    envelope: unknown,
    secret: string | Buffer,
    opts: ReplayCacheOptions = {},
  ): ReplayCache {
    return ReplayCache.restoreSignedSnapshot(envelope, secret, opts);
  }

  /**
   * Rebuild one cache per label from a map of signed envelopes
   * produced by {@link exportSignedSnapshotsByLabel} (typically
   * after a `JSON.parse` of the persisted form): `{ [label]:
   * ReplayCache }`, ready to plug back into
   * `VerifyAllOptions.replayCacheByLabel`. `opts` configures every
   * restored cache (`maxEntries`/`ttlSec`/`now`, validated exactly
   * like the constructor's) and may additionally pin
   * `expectedLabels` (see
   * {@link ReplayCacheSignedSnapshotsByLabelOptions}).
   *
   * The restore is atomic: every label's envelope is MAC-verified
   * and restored into a scratch map first, and the map is only
   * returned when every label succeeded — any label failure (a
   * tampered entry, a tampered `seenAt`, a wrong secret, a malformed
   * envelope, an unknown/extra or missing label against
   * `expectedLabels`) throws a descriptive configuration `Error`
   * and installs nothing, so a failed restore can never partially
   * reopen one label's replay window while leaving another
   * protected. Per-label failures surface the same errors as
   * {@link ReplayCache.restoreSignedSnapshot}; map-level failures
   * (a non-object map, an empty label, an unexpected/missing label)
   * are reported as `invalid signed snapshot envelopes`. An empty
   * map restores to an empty map.
   *
   * On success the semantics are exactly
   * {@link ReplayCache.restoreSignedSnapshot}'s per label: expired
   * entries are dropped, over-capacity snapshots keep the newest
   * entries, TTLs keep counting from each entry's original
   * `seenAt`, and the observability counters start at zero.
   */
  static restoreSignedSnapshotsByLabel(
    envelopes: unknown,
    secret: string | Buffer,
    opts: ReplayCacheSignedSnapshotsByLabelOptions = {},
  ): Record<string, ReplayCache> {
    const secretBytes = signedSnapshotSecretBytes(secret);
    const fail = (detail: string): never => {
      throw new Error(
        `ReplayCache: invalid signed snapshot envelopes: ${detail}`,
      );
    };
    if (
      typeof envelopes !== "object" ||
      envelopes === null ||
      Array.isArray(envelopes)
    )
      fail("expected an object mapping label -> signed snapshot envelope");
    const record = envelopes as Record<string, unknown>;
    const labels = Object.keys(record);
    for (const label of labels) {
      if (label === "")
        fail("label must be a non-empty string");
    }
    const expected = opts.expectedLabels;
    if (expected !== undefined) {
      if (
        !Array.isArray(expected) ||
        expected.some(
          (label) => typeof label !== "string" || label === "",
        )
      )
        throw new Error(
          "ReplayCache: expectedLabels must be an array of non-empty label strings",
        );
      if (new Set(expected).size !== expected.length)
        throw new Error(
          "ReplayCache: expectedLabels must not contain duplicates",
        );
      const expectedSet = new Set(expected);
      for (const label of labels) {
        if (!expectedSet.has(label)) fail(`unexpected label "${label}"`);
      }
      for (const label of expected) {
        if (!Object.prototype.hasOwnProperty.call(record, label))
          fail(`missing expected label "${label}"`);
      }
    }
    // Restore into a scratch map: any label failure throws before
    // anything is returned, so a failed restore installs nothing.
    const restored: Record<string, ReplayCache> = {};
    for (const label of labels) {
      restored[label] = ReplayCache.restoreSignedSnapshot(
        record[label],
        secretBytes,
        opts,
      );
    }
    return restored;
  }

  /** Alias of {@link ReplayCache.restoreSignedSnapshotsByLabel} (snapshot naming). */
  static fromSignedSnapshotsByLabel(
    envelopes: unknown,
    secret: string | Buffer,
    opts: ReplayCacheSignedSnapshotsByLabelOptions = {},
  ): Record<string, ReplayCache> {
    return ReplayCache.restoreSignedSnapshotsByLabel(envelopes, secret, opts);
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
