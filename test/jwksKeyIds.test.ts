import test from "node:test";
import assert from "node:assert/strict";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  type JwksFetchImpl,
} from "../src/index.js";

const URL = "https://gateway.example.com/.well-known/jwks.json";

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

function docForEntries(entries: { key: KeyPair; kid: string }[]) {
  return {
    keys: entries.map(({ key, kid }) => ({
      ...exportPublicKeyJwk(key.publicKey),
      kid,
    })),
  };
}

/** Fetch stub serving whatever document `getBody()` currently returns. */
function controlledFetch(getBody: () => unknown) {
  const fetchImpl: JwksFetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => getBody(),
  });
  return { fetchImpl };
}

test("keyIds: a fresh store lists no kids", () => {
  const { fetchImpl } = controlledFetch(() => ({ keys: [] }));
  const store = new JwksKeyStore(URL, { fetchImpl });
  assert.deepEqual(store.keyIds(), []);
  assert.equal(store.size, 0);
});

test("keyIds: after refresh the list matches the JWKS kids in document order", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() =>
    docForEntries([
      { key: a, kid: "gw-2026-a" },
      { key: b, kid: "gw-2026-b" },
      { key: c, kid: "gw-2026-c" },
    ]),
  );
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["gw-2026-a", "gw-2026-b", "gw-2026-c"]);
  assert.equal(store.size, 3);
});

test("keyIds: a single-key snapshot lists exactly that kid", async () => {
  const pair = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() =>
    docForEntries([{ key: pair, kid: "only-key" }]),
  );
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["only-key"]);
});

test("keyIds: clear empties the list", async () => {
  const a = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() =>
    docForEntries([{ key: a, kid: "gw-2026-a" }]),
  );
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["gw-2026-a"]);

  store.clear();

  assert.deepEqual(store.keyIds(), []);
  assert.equal(store.size, 0);
});

test("keyIds: restoreSnapshot updates the list to the restored kids", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  let doc = docForEntries([
    { key: a, kid: "gw-2026-a" },
    { key: b, kid: "gw-2026-b" },
  ]);
  const { fetchImpl } = controlledFetch(() => doc);
  const source = new JwksKeyStore(URL, { fetchImpl });
  await source.refresh();

  const store = new JwksKeyStore(URL, { fetchImpl });
  store.restoreSnapshot(source.exportSnapshot());
  assert.deepEqual(store.keyIds(), ["gw-2026-a", "gw-2026-b"]);

  // Rotate the source and restore again: the list follows the newest snapshot.
  doc = docForEntries([{ key: c, kid: "gw-2026-c" }]);
  await source.refresh();
  store.restoreSnapshot(source.exportSnapshot());
  assert.deepEqual(store.keyIds(), ["gw-2026-c"]);
});

test("keyIds: mutating the returned array does not affect the store", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() =>
    docForEntries([
      { key: a, kid: "gw-2026-a" },
      { key: b, kid: "gw-2026-b" },
    ]),
  );
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();

  const ids = store.keyIds();
  ids.push("forged-kid");
  ids.length = 0;

  assert.deepEqual(store.keyIds(), ["gw-2026-a", "gw-2026-b"]);
  assert.equal(store.size, 2);
  assert.ok(store.resolve("gw-2026-a"));
  assert.ok(store.resolve("gw-2026-b"));
});

test("keyIds: a re-refresh with a rotated document lists only the new kids", async () => {
  const a = generateEd25519KeyPair();
  const b = generateEd25519KeyPair();
  const c = generateEd25519KeyPair();
  let doc = docForEntries([
    { key: a, kid: "gw-2026-a" },
    { key: b, kid: "gw-2026-b" },
  ]);
  const { fetchImpl } = controlledFetch(() => doc);
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["gw-2026-a", "gw-2026-b"]);

  // Rotation: gw-2026-a retires, gw-2026-c is published.
  doc = docForEntries([
    { key: b, kid: "gw-2026-b" },
    { key: c, kid: "gw-2026-c" },
  ]);
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["gw-2026-b", "gw-2026-c"]);
  assert.equal(store.resolve("gw-2026-a"), undefined);
});

test("keyIds: a JWKS document listing the same kid twice lists it once (last entry wins)", async () => {
  const first = generateEd25519KeyPair();
  const second = generateEd25519KeyPair();
  const { fetchImpl } = controlledFetch(() =>
    docForEntries([
      { key: first, kid: "dup-kid" },
      { key: second, kid: "dup-kid" },
    ]),
  );
  const store = new JwksKeyStore(URL, { fetchImpl });
  await store.refresh();
  assert.deepEqual(store.keyIds(), ["dup-kid"]);
  assert.equal(store.size, 1);
  assert.deepEqual(
    exportPublicKeyJwk(store.resolve("dup-kid")!),
    exportPublicKeyJwk(second.publicKey),
  );
});
