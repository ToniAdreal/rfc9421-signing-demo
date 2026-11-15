import test from "node:test";
import assert from "node:assert/strict";
import { connect, createServer } from "node:http2";
import {
  fromNodeRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type IncomingRequestLike,
  type RequestLike,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 2500, currency: "USD" });
const CREATED = 1700000000;

/** A test double shaped like the fields of http.IncomingMessage. */
function incomingMessage(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/v1/payments",
    socket: {},
    ...overrides,
  };
}

test("h2c compat server: request with only :authority verifies end-to-end", async (t) => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  let capturedRawHeaderNames: string[] = [];
  let capturedAdapted: RequestLike | undefined;
  let capturedVerifyOk: boolean | undefined;

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      // Pin the backlog premise on the real wire shape: the compat
      // server exposes only pseudo-headers, no `host` header.
      capturedRawHeaderNames = Object.keys(req.headers);
      const body = Buffer.concat(chunks);
      // Feed the adapter exactly the fields it reads: a real
      // Http2ServerRequest satisfies IncomingRequestLike at runtime,
      // but its `socket` is typed net.Socket, which has no `encrypted`
      // property for TS's weak-type check — the same narrowing
      // `createVerifiedHandler` applies to IncomingMessage.
      const adapted = fromNodeRequest(
        {
          method: req.method,
          url: req.url,
          headers: req.headers,
          socket: req.socket as { encrypted?: boolean } | null | undefined,
          trailers: req.trailers,
          rawTrailers: req.rawTrailers,
        },
        body,
      );
      capturedAdapted = adapted;
      const result = verifyRequest(adapted, {
        key: publicKey,
        now: CREATED + 60,
      });
      capturedVerifyOk = result.ok;
      res.writeHead(result.ok ? 200 : 401).end(result.ok ? "ok" : "bad");
    });
  });
  t.after(() => server.close());
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;

  const signed = signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/v1/payments`,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "payments-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@scheme", "@authority", "@path", "content-type"],
    },
  );

  const client = connect(`http://127.0.0.1:${port}`);
  // destroy, not close: a graceful close waits for the server to end
  // its side of the session, while server.close() does not end
  // existing sessions — the pair would keep the event loop alive and
  // the test file would never exit.
  t.after(() => client.destroy());
  const status = await new Promise<number>((resolve, reject) => {
    const stream = client.request({
      ":method": "POST",
      ":path": "/v1/payments",
      "content-type": "application/json",
      "signature-input": signed.headers["signature-input"],
      signature: signed.headers["signature"],
      "content-digest": signed.headers["content-digest"],
    });
    stream.on("response", (headers) => resolve(headers[":status"] as number));
    stream.on("error", reject);
    stream.end(BODY);
  });

  assert.equal(status, 200);
  assert.equal(capturedVerifyOk, true);
  // The premise, pinned on the real server object: no host header,
  // :authority present.
  assert.ok(!capturedRawHeaderNames.includes("host"));
  assert.ok(capturedRawHeaderNames.includes(":authority"));
  assert.ok(capturedAdapted !== undefined);
  assert.equal(
    capturedAdapted.url,
    `http://127.0.0.1:${port}/v1/payments`,
  );
  // Pseudo-headers never leak into the normalized headers map.
  for (const pseudo of [":method", ":path", ":authority", ":scheme"]) {
    assert.ok(!(pseudo in capturedAdapted.headers), `${pseudo} leaked`);
  }
  assert.equal(capturedAdapted.headers["content-type"], "application/json");
});

test("no host header: :authority rebuilds the URL, port preserved", () => {
  const req = fromNodeRequest(
    incomingMessage({
      headers: { ":authority": "hooks.example.com:8443" },
    }),
  );
  assert.equal(req.url, "http://hooks.example.com:8443/v1/payments");
});

test(":scheme pseudo-header binds @scheme (https over a cleartext socket)", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@scheme", "@authority", "@path"],
    },
  );
  // socket is cleartext (encrypted absent) — without the :scheme
  // fallback this would rebuild as http:// and verification would fail.
  const req = fromNodeRequest(
    incomingMessage({
      headers: {
        ":authority": "hooks.example.com",
        ":scheme": "https",
        "content-type": "application/json",
        "signature-input": signed.headers["signature-input"],
        signature: signed.headers["signature"],
        "content-digest": signed.headers["content-digest"],
      },
      socket: {},
    }),
    BODY,
  );
  assert.equal(req.url, "https://hooks.example.com/v1/payments");
  const result = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(result.ok, true);
});

test("explicit opts.scheme beats :scheme; :scheme beats socket inference", () => {
  const withOverride = fromNodeRequest(
    incomingMessage({
      headers: { ":authority": "h.example", ":scheme": "http" },
      socket: { encrypted: true },
    }),
    undefined,
    { scheme: "https" },
  );
  assert.equal(withOverride.url, "https://h.example/v1/payments");

  const schemeWinsOverSocket = fromNodeRequest(
    incomingMessage({
      headers: { ":authority": "h.example", ":scheme": "http" },
      socket: { encrypted: true },
    }),
  );
  assert.equal(schemeWinsOverSocket.url, "http://h.example/v1/payments");

  const socketFallback = fromNodeRequest(
    incomingMessage({
      headers: { ":authority": "h.example" },
      socket: { encrypted: true },
    }),
  );
  assert.equal(socketFallback.url, "https://h.example/v1/payments");
});

test("pseudo-headers are stripped from the normalized headers map", () => {
  const req = fromNodeRequest(
    incomingMessage({
      headers: {
        ":method": "POST",
        ":path": "/v1/payments",
        ":authority": "hooks.example.com",
        ":scheme": "https",
        "x-trace-id": "abc-123",
      },
    }),
  );
  for (const pseudo of [":method", ":path", ":authority", ":scheme"]) {
    assert.ok(!(pseudo in req.headers), `${pseudo} leaked`);
  }
  assert.equal(req.headers["x-trace-id"], "abc-123");
  assert.equal(req.url, "https://hooks.example.com/v1/payments");
});

test("missing host and :authority still fails fast with the original error", () => {
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({ headers: { "content-type": "application/json" } }),
      ),
    /cannot rebuild the request URL without a host header/,
  );
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({ headers: { ":authority": "" } }),
      ),
    /cannot rebuild the request URL without a host header/,
  );
});

test("host header wins over :authority when both are present", () => {
  const req = fromNodeRequest(
    incomingMessage({
      headers: { host: "a.example", ":authority": "b.example" },
      socket: { encrypted: true },
    }),
  );
  assert.equal(req.url, "https://a.example/v1/payments");
  assert.equal(req.headers["host"], "a.example");
  assert.ok(!(":authority" in req.headers));
});

test("HTTP/1.1 behavior is unchanged: host header, no pseudo-headers", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@scheme", "@authority", "@path"],
    },
  );
  const req = fromNodeRequest(
    incomingMessage({
      headers: {
        host: "hooks.example.com",
        "content-type": "application/json",
        "signature-input": signed.headers["signature-input"],
        signature: signed.headers["signature"],
        "content-digest": signed.headers["content-digest"],
      },
      socket: { encrypted: true },
    }),
    BODY,
  );
  assert.equal(req.url, "https://hooks.example.com/v1/payments");
  const result = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(result.ok, true);
});
