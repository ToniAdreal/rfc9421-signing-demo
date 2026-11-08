import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { type KeyObject } from "node:crypto";
import {
  exportPublicKeyJwk,
  generateEd25519KeyPair,
  JwksKeyStore,
  signRequest,
  verifyRequest,
  type JwksFetchImpl,
  type JwksFetchResponse,
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

/** One ed25519 key and the JWKS document publishing it (~150 bytes). */
function edDoc(): {
  pair: { publicKey: KeyObject; privateKey: KeyObject };
  doc: { keys: unknown[] };
} {
  const pair = generateEd25519KeyPair();
  return {
    pair,
    doc: { keys: [{ ...exportPublicKeyJwk(pair.publicKey), kid: "ed-key-1" }] },
  };
}

function signAs(privateKey: KeyObject): SignedHttpRequest {
  return signRequest(freshReq(), {
    keyId: "ed-key-1",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
}

function assertVerifies(store: JwksKeyStore, privateKey: KeyObject): void {
  const res = verifyRequest(signAs(privateKey), {
    keyResolver: store.resolve,
    now: CREATED,
  });
  assert.equal(res.ok, true, "the seeded snapshot must still verify");
}

/**
 * Pad a JWKS JSON string with trailing spaces to exactly `targetBytes`.
 * The fixture is ASCII, so bytes === chars, and trailing whitespace is
 * valid JSON whitespace — the padded document still parses.
 */
function padToBytes(json: string, targetBytes: number): string {
  const bytes = Buffer.byteLength(json, "utf8");
  assert.ok(
    bytes <= targetBytes,
    `fixture is ${bytes} bytes, over the ${targetBytes} byte target`,
  );
  return json + " ".repeat(targetBytes - bytes);
}

/**
 * A stub response that serves `body` through `text()` (and reports an
 * optional Content-Length). Its `json()` throws if called, so a test
 * that takes the text path proves it never fell back to `json()`.
 */
function textResponse(
  body: string,
  contentLength: string | null = null,
): { res: JwksFetchResponse; calls: { text: number; json: number } } {
  const calls = { text: 0, json: 0 };
  const res: JwksFetchResponse = {
    ok: true,
    status: 200,
    json: async () => {
      calls.json++;
      throw new Error("json() must not be called on the text() path");
    },
    text: async () => {
      calls.text++;
      return body;
    },
    headers: {
      get: (name: string) =>
        name.toLowerCase() === "content-length" ? contentLength : null,
    },
  };
  return { res, calls };
}

/** A fetch stub whose served response can be swapped mid-test. */
function mutableFetch(initial: () => JwksFetchResponse): {
  impl: JwksFetchImpl;
  set: (next: () => JwksFetchResponse) => void;
} {
  let current = initial;
  return {
    impl: async () => current(),
    set: (next) => {
      current = next;
    },
  };
}

/**
 * Serve `getBody()` from a local HTTP server on an ephemeral port.
 * `withContentLength` sets an explicit Content-Length header (the
 * precheck path); without it Node sends chunked encoding and the
 * client sees no Content-Length (the post-read path).
 */
async function serve(
  getBody: () => string,
  withContentLength: boolean,
): Promise<{ server: Server; url: string }> {
  const server = createServer((_req, res) => {
    const body = getBody();
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (withContentLength)
      headers["content-length"] = String(Buffer.byteLength(body, "utf8"));
    res.writeHead(200, headers);
    res.end(body);
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

test("JwksKeyStore maxBodyBytes: small body refreshes through the text() path and verifies", async () => {
  const { pair, doc } = edDoc();
  const body = JSON.stringify(doc);
  const { res, calls } = textResponse(body);
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assert.equal(calls.text, 1);
  assert.equal(calls.json, 0);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: Content-Length over the limit is rejected before the body is read, old snapshot keeps verifying", async () => {
  const { pair, doc } = edDoc();
  const good = textResponse(JSON.stringify(doc));
  const fetch = mutableFetch(() => good.res);
  const url = "https://gateway.example.com/.well-known/jwks.json";
  const store = new JwksKeyStore(url, { fetchImpl: fetch.impl, maxBodyBytes: 800 });
  await store.refresh();
  assertVerifies(store, pair.privateKey);

  // The advertised length (801) is over the 800-byte cap, but the
  // served body is the small good document: the precheck must fire
  // before either reader is touched.
  const over = textResponse(JSON.stringify(doc), "801");
  fetch.set(() => over.res);
  await assert.rejects(
    () => store.refresh(),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /exceeds the 800 byte body limit/);
      assert.match(err.message, /Content-Length: 801 bytes/);
      assert.ok(err.message.includes(url), "the error names the endpoint");
      return true;
    },
  );
  assert.equal(over.calls.text, 0, "the body must never be read");
  assert.equal(over.calls.json, 0);
  assert.equal(store.size, 1);
  assert.equal(store.stats().refreshFailures, 1);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: over-limit body without Content-Length is rejected after reading, old snapshot kept", async () => {
  const { pair, doc } = edDoc();
  const json = JSON.stringify(doc);
  const good = textResponse(json);
  const fetch = mutableFetch(() => good.res);
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: fetch.impl,
    maxBodyBytes: 800,
  });
  await store.refresh();
  assertVerifies(store, pair.privateKey);

  const over = textResponse(padToBytes(json, 801));
  fetch.set(() => over.res);
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit \(received 801 bytes\)/,
  );
  assert.equal(over.calls.text, 1, "the body is read, then measured");
  assert.equal(store.size, 1);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: body exactly at the limit passes", async () => {
  const { pair, doc } = edDoc();
  const body = padToBytes(JSON.stringify(doc), 800);
  assert.equal(Buffer.byteLength(body, "utf8"), 800);
  const { res } = textResponse(body, "800");
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: Content-Length exactly at the limit passes", async () => {
  const { pair, doc } = edDoc();
  const body = padToBytes(JSON.stringify(doc), 800);
  const { res } = textResponse(body, "800");
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: custom fetchImpl with text() still enforces the limit", async () => {
  const { doc } = edDoc();
  const json = JSON.stringify(doc);
  const { res } = textResponse(padToBytes(json, 801));
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit \(received 801 bytes\)/,
  );
  assert.equal(store.size, 0);
  assert.equal(store.stats().refreshFailures, 1);
});

test("JwksKeyStore maxBodyBytes: json()-only custom fetchImpl keeps working (limit unmeasurable there)", async () => {
  const { pair, doc } = edDoc();
  // The document (~150 bytes) is over this store's 100-byte cap, but
  // a json()-only response cannot be measured, so the documented
  // fallback parses it exactly as before.
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => doc }),
    maxBodyBytes: 100,
  });
  await store.refresh();
  assert.equal(store.size, 1);
  assertVerifies(store, pair.privateKey);
});

test("JwksKeyStore maxBodyBytes: invalid maxBodyBytes throws at construction", () => {
  const url = "https://gateway.example.com/.well-known/jwks.json";
  for (const bad of [0, -1, 1.5, Number.NaN, "1024", null]) {
    assert.throws(
      () => new JwksKeyStore(url, { maxBodyBytes: bad as never }),
      /`maxBodyBytes` must be a positive integer \(bytes\)/,
      `maxBodyBytes=${String(bad)}`,
    );
  }
});

test("JwksKeyStore maxBodyBytes: default fetch over loopback rejects an over-limit body advertised by Content-Length", async () => {
  const { pair, doc } = edDoc();
  const json = JSON.stringify(doc);
  let body = json;
  const { server, url } = await serve(() => body, true);
  try {
    const store = new JwksKeyStore(url, { maxBodyBytes: 800 });
    await store.refresh();
    assertVerifies(store, pair.privateKey);

    body = padToBytes(json, 801);
    await assert.rejects(
      () => store.refresh(),
      /exceeds the 800 byte body limit \(Content-Length: 801 bytes\)/,
    );
    assert.equal(store.size, 1);
    assertVerifies(store, pair.privateKey);
  } finally {
    await close(server);
  }
});

test("JwksKeyStore maxBodyBytes: default fetch over loopback (chunked, no Content-Length) rejects an over-limit body after reading", async () => {
  const { pair, doc } = edDoc();
  const json = JSON.stringify(doc);
  let body = json;
  const { server, url } = await serve(() => body, false);
  try {
    const store = new JwksKeyStore(url, { maxBodyBytes: 800 });
    await store.refresh();
    assertVerifies(store, pair.privateKey);

    body = padToBytes(json, 801);
    await assert.rejects(
      () => store.refresh(),
      /exceeds the 800 byte body limit \(received 801 bytes\)/,
    );
    assert.equal(store.size, 1);
    assertVerifies(store, pair.privateKey);
  } finally {
    await close(server);
  }
});

test("JwksKeyStore maxBodyBytes: over-limit rejection is terminal under retries (fetch attempted once)", async () => {
  const { doc } = edDoc();
  const json = JSON.stringify(doc);
  let calls = 0;
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => {
      calls++;
      return textResponse(padToBytes(json, 801)).res;
    },
    maxBodyBytes: 800,
    fetchRetries: 2,
    sleepImpl: async () => {},
  });
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit/,
  );
  assert.equal(calls, 1, "a too-large body must not be re-fetched");
  assert.equal(store.stats().refreshFailures, 1);
});

test("JwksKeyStore maxBodyBytes: over-limit refresh on a fresh store leaves it empty", async () => {
  const { doc } = edDoc();
  const json = JSON.stringify(doc);
  const { res } = textResponse(padToBytes(json, 801));
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit/,
  );
  assert.equal(store.size, 0);
  assert.equal(store.resolve("ed-key-1"), undefined);
  assert.equal(store.lastRefreshedAt, null);
});

test("JwksKeyStore maxBodyBytes: a lying Content-Length under the limit does not bypass the post-read check", async () => {
  const { doc } = edDoc();
  const json = JSON.stringify(doc);
  // Advertised 100 bytes, actually 801: the precheck passes, the
  // authoritative post-read check must still reject.
  const { res } = textResponse(padToBytes(json, 801), "100");
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit \(received 801 bytes\)/,
  );
});

test("JwksKeyStore maxBodyBytes: an unparseable Content-Length is skipped, post-read check still applies", async () => {
  const { doc } = edDoc();
  const json = JSON.stringify(doc);
  const { res } = textResponse(padToBytes(json, 801), "not-a-number");
  const store = new JwksKeyStore("https://gateway.example.com/.well-known/jwks.json", {
    fetchImpl: async () => res,
    maxBodyBytes: 800,
  });
  await assert.rejects(
    () => store.refresh(),
    /exceeds the 800 byte body limit \(received 801 bytes\)/,
  );
});
