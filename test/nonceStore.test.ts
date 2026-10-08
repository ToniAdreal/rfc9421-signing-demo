import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  ReplayCache,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  verifyRequestOrThrow,
  VerifyError,
  type NonceStore,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;

/** Minimal custom `NonceStore` backed by a plain Map. */
class MapNonceStore implements NonceStore {
  readonly seen = new Map<string, number>();
  checks = 0;
  constructor(private readonly ttlSec = 3600) {}
  check(nonce: string, now: number = Math.floor(Date.now() / 1000)): boolean {
    if (nonce === "") throw new Error("nonce must be non-empty");
    this.checks++;
    const prev = this.seen.get(nonce);
    if (prev !== undefined && now - prev < this.ttlSec) return true; // replay
    this.seen.set(nonce, now);
    return false;
  }
}

/**
 * Mirrors the out-of-process `SharedNonceStore` example from SECURITY.md
 * (the `backend` map stands in for storage shared across verifier
 * instances). Keeping the same shape here means the documented pattern
 * is compile-checked by `tsc` on every `npm test`.
 */
class SharedNonceStore implements NonceStore {
  constructor(
    private readonly backend: Map<string, number>,
    private readonly ttlSec = 3600,
  ) {}
  check(nonce: string, now: number = Math.floor(Date.now() / 1000)): boolean {
    const prev = this.backend.get(nonce);
    if (prev !== undefined && now - prev < this.ttlSec) return true; // replay
    this.backend.set(nonce, now); // record
    return false;
  }
}

function signedReq(nonce?: string): { signed: SignedHttpRequest; publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"] } {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "GET", url: "https://api.example.com/v1/status", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      ...(nonce === undefined ? {} : { nonce }),
    },
  );
  return { signed, publicKey };
}

test("custom Map-backed NonceStore detects replay end-to-end", () => {
  const { signed, publicKey } = signedReq("custom-1");
  const store = new MapNonceStore();
  const first = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: store,
  });
  assert.equal(first.ok, true);
  assert.equal(first.nonce, "custom-1");

  const second = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: store,
  });
  assert.equal(second.ok, false);
  assert.equal(second.code, "NONCE_REPLAY");
  assert.match(second.reason ?? "", /replay/);
  assert.equal(second.nonce, "custom-1");
});

test("ReplayCache still satisfies NonceStore (type-level) and old path is unchanged", () => {
  // Type-level: a ReplayCache must be assignable to the widened option type.
  const store: NonceStore = new ReplayCache({ ttlSec: 3600, now: () => CREATED + 60 });
  const { signed, publicKey } = signedReq("legacy-1");
  const opts = { key: publicKey, now: CREATED + 60, replayCache: store };
  assert.equal(verifyRequest(signed, opts).ok, true);
  const replay = verifyRequest(signed, opts);
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");
});

test("request without a nonce never touches the custom store", () => {
  const { signed, publicKey } = signedReq();
  const store = new MapNonceStore();
  const res = verifyRequest(signed, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: store,
  });
  assert.equal(res.ok, true);
  assert.equal(store.checks, 0);
  assert.equal(store.seen.size, 0);
});

test("failed verification never records in the custom store", () => {
  const { signed, publicKey } = signedReq("no-pollute");
  // Tamper with the signed base: flip a byte of the signature so the
  // request fails crypto verification.
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: { ...signed.headers },
  };
  const sig = tampered.headers["signature"] as string;
  tampered.headers["signature"] = sig.slice(0, -4) + "AAAA";
  const store = new MapNonceStore();
  const bad = verifyRequest(tampered, {
    key: publicKey,
    now: CREATED + 60,
    replayCache: store,
  });
  assert.equal(bad.ok, false);
  assert.notEqual(bad.code, "NONCE_REPLAY");
  assert.equal(store.seen.has("no-pollute"), false);
});

test("SECURITY.md SharedNonceStore example works end-to-end with TTL expiry", () => {
  const shared = new Map<string, number>();
  const store = new SharedNonceStore(shared, 600);
  const { signed, publicKey } = signedReq("shared-1");
  const opts = { key: publicKey, replayCache: store as NonceStore };

  assert.equal(verifyRequest(signed, { ...opts, now: CREATED + 10 }).ok, true);
  const replay = verifyRequest(signed, { ...opts, now: CREATED + 20 });
  assert.equal(replay.ok, false);
  assert.equal(replay.code, "NONCE_REPLAY");

  // After the TTL the same nonce is treated as unseen again.
  const fresh = verifyRequest(signed, { ...opts, now: CREATED + 700 });
  assert.equal(fresh.ok, true);
  assert.equal(shared.get("shared-1"), CREATED + 700);
});

test("verifyRequestOrThrow raises VerifyError(NONCE_REPLAY) through a custom store", () => {
  const { signed, publicKey } = signedReq("throw-1");
  const store = new MapNonceStore();
  const opts = { key: publicKey, now: CREATED + 60, replayCache: store };
  verifyRequestOrThrow(signed, opts);
  assert.throws(() => verifyRequestOrThrow(signed, opts), (err: unknown) => {
    assert.ok(err instanceof VerifyError);
    assert.equal(err.code, "NONCE_REPLAY");
    return true;
  });
});

test("verifyAllLabels consults the custom store per label", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const base = {
    method: "POST",
    url: "https://pay.example.com/hooks",
    headers: { "content-type": "application/json" },
  };
  const first = signRequest(base, {
    keyId: "m",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "merchant",
    nonce: "multi-1",
  });
  const store = new MapNonceStore();
  const opts = { key: publicKey, now: CREATED + 60, replayCache: store };
  const once = verifyAllLabels(first, opts);
  assert.equal(once.every((r) => r.ok), true);
  const twice = verifyAllLabels(first, opts);
  assert.equal(twice.every((r) => !r.ok && r.code === "NONCE_REPLAY"), true);
});
