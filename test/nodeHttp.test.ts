import test from "node:test";
import assert from "node:assert/strict";
import {
  fromNodeRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type IncomingRequestLike,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;

function signedPayment() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook?event=push",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    { keyId: "webhook-key", alg: "ed25519", key: privateKey, created: CREATED },
  );
  return { publicKey, signed };
}

/** A test double shaped like the fields of http.IncomingMessage. */
function incomingMessage(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/webhook?event=push",
    socket: { encrypted: true },
    ...overrides,
  };
}

test("sign -> fromNodeRequest -> verify round-trip (ed25519, https)", () => {
  const { publicKey, signed } = signedPayment();
  // Mixed-case header names exercise the adapter's lowercasing; a real
  // Node server would already lowercase them.
  const req = fromNodeRequest(
    incomingMessage({
      headers: {
        Host: "hooks.example.com",
        "Content-Type": "application/json",
        "Signature-Input": signed.headers["signature-input"],
        Signature: signed.headers["signature"],
        "Content-Digest": signed.headers["content-digest"],
      },
    }),
    BODY,
  );

  assert.equal(req.method, "POST");
  assert.equal(req.url, "https://hooks.example.com/webhook?event=push");
  // host is preserved in the normalized headers
  assert.equal(req.headers["host"], "hooks.example.com");
  // mixed-case names were lowercased
  assert.ok("signature-input" in req.headers);
  assert.ok(!("Signature-Input" in req.headers));

  const res = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "webhook-key");
  assert.equal(res.alg, "ed25519");
});

test("multi-value headers are joined with ', ' (normalization parity)", () => {
  // Direct normalization check.
  const direct = fromNodeRequest(
    incomingMessage({ headers: { Host: "h", "X-Multi": ["a", "b"] } }),
  );
  assert.equal(direct.headers["x-multi"], "a, b");

  // End-to-end: the adapter's join matches what signRequest produced, so a
  // covered multi-value header still verifies.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://hooks.example.com/ping",
      headers: { "x-multi": ["a", "b"] },
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@authority", "@path", "x-multi"],
    },
  );
  const req = fromNodeRequest(
    incomingMessage({
      method: "GET",
      url: "/ping",
      headers: {
        host: "hooks.example.com",
        "X-Multi": ["a", "b"],
        "signature-input": signed.headers["signature-input"],
        signature: signed.headers["signature"],
      },
    }),
  );
  const res = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("host with port is preserved; scheme follows the socket", () => {
  const plain = fromNodeRequest(
    incomingMessage({
      method: "GET",
      url: "/p?q=1",
      headers: { host: "hooks.example.com:8443" },
      socket: { encrypted: false },
    }),
  );
  assert.equal(plain.url, "http://hooks.example.com:8443/p?q=1");

  const tls = fromNodeRequest(
    incomingMessage({
      method: "GET",
      url: "/p",
      headers: { host: "hooks.example.com" },
      socket: { encrypted: true },
    }),
  );
  assert.equal(tls.url, "https://hooks.example.com/p");
});

test("scheme override for TLS-terminating proxies", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: "https://hooks.example.com/webhook", headers: {} },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      // @scheme must be covered for the proxy scenario to matter.
      coveredComponents: ["@method", "@scheme", "@authority", "@path"],
    },
  );
  const wire = {
    method: "POST",
    url: "/webhook",
    headers: {
      host: "hooks.example.com",
      "signature-input": signed.headers["signature-input"],
      signature: signed.headers["signature"],
    },
    socket: { encrypted: false }, // proxy already terminated TLS
  };

  // Without the override the rebuilt URL is http://, so @scheme mismatches.
  const wrong = verifyRequest(fromNodeRequest(incomingMessage(wire)), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(wrong.ok, false);

  const right = verifyRequest(
    fromNodeRequest(incomingMessage(wire), undefined, { scheme: "https" }),
    { key: publicKey, now: CREATED + 60 },
  );
  assert.equal(right.ok, true);
});

test("body passes through as string or Buffer", () => {
  const asString = fromNodeRequest(
    incomingMessage({ headers: { host: "h" } }),
    BODY,
  );
  assert.equal(asString.body, BODY);

  const buf = Buffer.from(BODY, "utf8");
  const asBuffer = fromNodeRequest(
    incomingMessage({ headers: { host: "h" } }),
    buf,
  );
  assert.ok(Buffer.isBuffer(asBuffer.body));
  assert.equal((asBuffer.body as Buffer).toString("utf8"), BODY);

  // Buffer body still verifies (digest is computed over the raw bytes).
  const { publicKey, signed } = signedPayment();
  const req = fromNodeRequest(
    incomingMessage({
      headers: {
        host: "hooks.example.com",
        "signature-input": signed.headers["signature-input"],
        signature: signed.headers["signature"],
        "content-digest": signed.headers["content-digest"],
      },
    }),
    buf,
  );
  const res = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("missing method/url/host throw clear configuration errors", () => {
  assert.throws(
    () =>
      fromNodeRequest({ headers: { host: "h" }, url: "/" } as IncomingRequestLike),
    /req\.method is missing/,
  );
  assert.throws(
    () =>
      fromNodeRequest({ method: "GET", headers: { host: "h" } } as IncomingRequestLike),
    /req\.url is missing/,
  );
  assert.throws(
    () => fromNodeRequest({ method: "GET", url: "/", headers: {} }),
    /without a host header/,
  );
  assert.throws(
    () => fromNodeRequest({ method: "", url: "/", headers: { host: "h" } }),
    /req\.method is missing/,
  );
});

test("absolute-form url passes through unchanged", () => {
  const req = fromNodeRequest({
    method: "GET",
    url: "https://proxy.example/absolute",
    headers: { host: "ignored.example" },
    socket: { encrypted: false },
  });
  assert.equal(req.url, "https://proxy.example/absolute");
});
