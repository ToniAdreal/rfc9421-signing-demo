import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  exportPublicKeyJwkP256,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  JwksKeyStore,
  memoizeKeyResolver,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function freshReq(): typeof REQ {
  return { ...REQ, headers: { ...REQ.headers } };
}

/** Three signing key pairs, one per supported JWKS key type. */
function keyMaterial() {
  const ed = generateEd25519KeyPair();
  const p256 = generateP256KeyPair();
  const rsa = generateRsaPssKeyPair();
  return { ed, p256, rsa };
}

type Keys = ReturnType<typeof keyMaterial>;

/** The JWKS document a gateway would publish for those three keys. */
function jwksDocument({ ed, p256, rsa }: Keys): { keys: unknown[] } {
  return {
    keys: [
      { ...exportPublicKeyJwk(ed.publicKey), kid: "ed-key-1" },
      { ...exportPublicKeyJwkP256(p256.publicKey), kid: "p256-key-1" },
      { ...exportPublicKeyJwkRsa(rsa.publicKey), kid: "rsa-key-1" },
    ],
  };
}

function signAs(
  keyId: string,
  alg: "ed25519" | "ecdsa-p256-sha256" | "rsa-pss-sha512",
  privateKey: KeyObject,
): SignedHttpRequest {
  return signRequest(freshReq(), { keyId, alg, key: privateKey, created: CREATED });
}

/**
 * Serve `getBody()` (re-read per request, so tests can rotate the
 * document mid-test) from a local HTTP server on an ephemeral port.
 */
async function serve(
  getBody: () => string,
  status = 200,
): Promise<{ server: Server; url: string }> {
  const server = createServer((_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(getBody());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(typeof addr === "object" && addr !== null);
  return { server, url: `http://127.0.0.1:${addr.port}/.well-known/jwks.json` };
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
}

/** A fetch stub that serves a fixed JSON body without any network. */
function stubFetch(body: unknown, status = 200): JwksFetchImpl {
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

test("JwksKeyStore: refresh→resolve→verify round-trip for ed25519, P-256 and RSA keys served over HTTP", async () => {
  const keys = keyMaterial();
  const { server, url } = await serve(() => JSON.stringify(jwksDocument(keys)));
  try {
    const store = new JwksKeyStore(url);
    // Before refresh: empty snapshot, everything unresolved, stale.
    assert.equal(store.size, 0);
    assert.equal(store.resolve("ed-key-1"), undefined);
    assert.equal(store.isStale(), true);

    await store.refresh();
    assert.equal(store.size, 3);
    assert.equal(store.isStale(), false);
    assert.ok(store.lastRefreshedAt !== null);

    const cases: Array<[string, SignedHttpRequest]> = [
      ["ed-key-1", signAs("ed-key-1", "ed25519", keys.ed.privateKey)],
      ["p256-key-1", signAs("p256-key-1", "ecdsa-p256-sha256", keys.p256.privateKey)],
      ["rsa-key-1", signAs("rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey)],
    ];
    for (const [keyId, signed] of cases) {
      // `store.resolve` is passed by reference, exactly as documented:
      // no .bind(store), no wrapper closure.
      const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
      assert.equal(res.ok, true, `${signed.headers["signature-input"]}`);
      assert.equal(res.keyId, keyId);
    }
    // The resolved keys are the very keys the endpoint published.
    assert.equal(
      store.resolve("ed-key-1")?.export({ format: "pem", type: "spki" }).toString(),
      keys.ed.publicKey.export({ format: "pem", type: "spki" }).toString(),
    );
  } finally {
    await close(server);
  }
});

test("JwksKeyStore: unknown kid resolves to undefined and verify fails with KEY_RESOLUTION_FAILED", async () => {
  const keys = keyMaterial();
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(jwksDocument(keys)),
  });
  await store.refresh();
  assert.equal(store.resolve("no-such-key"), undefined);
  assert.equal(store.resolve(""), undefined);
  const signed = signAs("no-such-key", "ed25519", keys.ed.privateKey);
  const res = verifyRequest(signed, { keyResolver: store.resolve, now: CREATED });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
});

test("JwksKeyStore: HTTP 500 refresh throws and the previous snapshot is preserved", async () => {
  const keys = keyMaterial();
  const body = JSON.stringify(jwksDocument(keys));
  const { server, url } = await serve(() => body, 200);
  // First refresh delegates to the real local server; later refreshes
  // are short-circuited to an HTTP 500 by the injected fetchImpl.
  let failNext = false;
  const fetchImpl: JwksFetchImpl = async (u) => {
    if (failNext) return { ok: false, status: 500, json: async () => ({}) };
    return globalThis.fetch(u);
  };
  try {
    const store = new JwksKeyStore(url, { fetchImpl });
    await store.refresh();
    const before = store.resolve("ed-key-1");
    assert.ok(before !== undefined);
    const refreshedAt = store.lastRefreshedAt;

    failNext = true;
    await assert.rejects(() => store.refresh(), /HTTP 500/);
    // Old snapshot and freshness timestamp untouched: rotation failures
    // must not turn into verification outages.
    assert.equal(store.resolve("ed-key-1"), before);
    assert.equal(store.size, 3);
    assert.equal(store.lastRefreshedAt, refreshedAt);
    const signed = signAs("ed-key-1", "ed25519", keys.ed.privateKey);
    assert.equal(
      verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
      true,
    );
  } finally {
    await close(server);
  }
});

test("JwksKeyStore: isStale() flips at the TTL boundary under an injected clock", async () => {
  const keys = keyMaterial();
  let t = 1_700_000_000;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(jwksDocument(keys)),
    ttlSec: 120,
    now: () => t,
  });
  assert.equal(store.isStale(), true); // never refreshed
  await store.refresh();
  assert.equal(store.lastRefreshedAt, 1_700_000_000);
  assert.equal(store.isStale(), false);
  t = 1_700_000_119;
  assert.equal(store.isStale(), false);
  t = 1_700_000_120; // exactly at TTL: stale (>= boundary, like memoizeKeyResolver)
  assert.equal(store.isStale(), true);
  // A stale snapshot still resolves: staleness is advisory, not a cutoff.
  assert.ok(store.resolve("ed-key-1") !== undefined);
  await store.refresh();
  assert.equal(store.isStale(), false);
  assert.equal(store.lastRefreshedAt, 1_700_000_120);
});

test("JwksKeyStore: a JWKS entry carrying private \"d\" material makes refresh throw and keeps the old snapshot", async () => {
  const keys = keyMaterial();
  const good = jwksDocument(keys);
  let doc: unknown = good;
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => doc }),
  });
  await store.refresh();
  assert.equal(store.size, 3);

  doc = {
    keys: [
      {
        ...exportPublicKeyJwk(keys.ed.publicKey),
        kid: "ed-key-1",
        d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    ],
  };
  await assert.rejects(() => store.refresh(), /private key material/);
  assert.equal(store.size, 3); // rejected document did not replace the snapshot
  assert.ok(store.resolve("rsa-key-1") !== undefined);
});

test("JwksKeyStore: non-JWKS JSON documents throw a clear error", async () => {
  const cases: Array<[string, unknown, RegExp]> = [
    ["array document", [], /expected an object with a "keys" array/],
    ["null document", null, /expected an object with a "keys" array/],
    ["no keys field", { notKeys: [] }, /"keys" must be an array/],
    ["keys not an array", { keys: { "ed-key-1": {} } }, /"keys" must be an array/],
    ["entry not an object", { keys: ["nope"] }, /must be a JWK object/],
    [
      "unsupported kty",
      { keys: [{ kty: "oct", kid: "sym-1", k: "AAAA" }] },
      /unsupported kty/,
    ],
  ];
  for (const [name, doc, re] of cases) {
    const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
      fetchImpl: stubFetch(doc),
    });
    await assert.rejects(() => store.refresh(), re, name);
    assert.equal(store.size, 0, name);
    assert.equal(store.lastRefreshedAt, null, name);
  }
  // A body that is not JSON at all fails in json() and is reported as such.
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error("Unexpected token < in JSON");
      },
    }),
  });
  await assert.rejects(() => store.refresh(), /not valid JSON/);
});

test("JwksKeyStore: entries without a kid are skipped, their siblings still import", async () => {
  const keys = keyMaterial();
  const doc = {
    keys: [
      exportPublicKeyJwk(keys.ed.publicKey), // no kid at all
      { ...exportPublicKeyJwkP256(keys.p256.publicKey), kid: "" }, // empty kid
      { ...exportPublicKeyJwkRsa(keys.rsa.publicKey), kid: "rsa-key-1" },
    ],
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(doc),
  });
  await store.refresh(); // must not throw
  assert.equal(store.size, 1);
  assert.ok(store.resolve("rsa-key-1") !== undefined);
  const signed = signAs("rsa-key-1", "rsa-pss-sha512", keys.rsa.privateKey);
  assert.equal(
    verifyRequest(signed, { keyResolver: store.resolve, now: CREATED }).ok,
    true,
  );
});

test("JwksKeyStore: memoizeKeyResolver composes on top of store.resolve", async () => {
  const keys = keyMaterial();
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl: stubFetch(jwksDocument(keys)),
  });
  await store.refresh();
  let underlying = 0;
  const countingResolve = (id: string): KeyObject | undefined => {
    underlying++;
    return store.resolve(id);
  };
  const memoized = memoizeKeyResolver(countingResolve, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  const signed = signAs("ed-key-1", "ed25519", keys.ed.privateKey);
  for (let i = 0; i < 3; i++) {
    assert.equal(
      verifyRequest(signed, { keyResolver: memoized, now: CREATED }).ok,
      true,
    );
  }
  assert.equal(underlying, 1);
  // store.resolve itself can also be memoized directly (arrow property,
  // no binding needed) and yields the same key.
  const direct = memoizeKeyResolver(store.resolve, {
    ttlSec: 60,
    now: () => 1_700_000_000,
  });
  assert.equal(direct("p256-key-1"), store.resolve("p256-key-1"));
});

test("JwksKeyStore: rotation — a re-refresh replaces the snapshot (old kid retired, new kid live)", async () => {
  const keys = keyMaterial();
  const rotated = generateEd25519KeyPair();
  let doc = jwksDocument(keys);
  const { server, url } = await serve(() => JSON.stringify(doc));
  try {
    const store = new JwksKeyStore(url);
    await store.refresh();
    const oldSigned = signAs("ed-key-1", "ed25519", keys.ed.privateKey);
    assert.equal(
      verifyRequest(oldSigned, { keyResolver: store.resolve, now: CREATED }).ok,
      true,
    );
    // Gateway rotates: ed-key-1 disappears, ed-key-2 appears.
    doc = {
      keys: [{ ...exportPublicKeyJwk(rotated.publicKey), kid: "ed-key-2" }],
    };
    await store.refresh();
    assert.equal(store.size, 1);
    assert.equal(store.resolve("ed-key-1"), undefined);
    const retired = verifyRequest(oldSigned, {
      keyResolver: store.resolve,
      now: CREATED,
    });
    assert.equal(retired.ok, false);
    assert.equal(retired.code, "KEY_RESOLUTION_FAILED");
    const newSigned = signAs("ed-key-2", "ed25519", rotated.privateKey);
    assert.equal(
      verifyRequest(newSigned, { keyResolver: store.resolve, now: CREATED }).ok,
      true,
    );
  } finally {
    await close(server);
  }
});

test("JwksKeyStore: constructor rejects invalid url/options with configuration errors", () => {
  assert.throws(() => new JwksKeyStore(""), /`url` must be a non-empty string/);
  assert.throws(() => new JwksKeyStore("not a url"), /not a valid URL/);
  assert.throws(() => new JwksKeyStore("ftp://example.com/jwks.json"), /http: or https:/);
  assert.throws(
    () => new JwksKeyStore("https://example.com/jwks.json", { ttlSec: 0 }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () => new JwksKeyStore("https://example.com/jwks.json", { ttlSec: NaN }),
    /`ttlSec` must be a finite number > 0/,
  );
  assert.throws(
    () =>
      new JwksKeyStore("https://example.com/jwks.json", {
        fetchImpl: 42 as never,
      }),
    /`fetchImpl` must be a function/,
  );
  assert.throws(
    () =>
      new JwksKeyStore("https://example.com/jwks.json", { now: 42 as never }),
    /`now` must be a function/,
  );
  const store = new JwksKeyStore("https://example.com/jwks.json");
  assert.equal(store.endpoint, "https://example.com/jwks.json");
});

test("JwksKeyStore: a network-level fetch failure throws and preserves the snapshot", async () => {
  const keys = keyMaterial();
  let down = false;
  const fetchImpl: JwksFetchImpl = async () => {
    if (down) throw new Error("connect ECONNREFUSED");
    return { ok: true, status: 200, json: async () => jwksDocument(keys) };
  };
  const store = new JwksKeyStore("https://gateway.example.com/jwks.json", {
    fetchImpl,
  });
  await store.refresh();
  down = true;
  await assert.rejects(() => store.refresh(), /failed to fetch JWKS.*ECONNREFUSED/);
  assert.equal(store.size, 3);
  assert.ok(store.resolve("ed-key-1") !== undefined);
});
