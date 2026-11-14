import test from "node:test";
import assert from "node:assert/strict";
import {
  fromFetchRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type FetchRequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const URL = "https://api.example.com:8443/v1/charge";

/** A test double shaped like the fields of a fetch Request. */
function fetchRequest(
  overrides: Partial<FetchRequestLike> & {
    headers: Iterable<[string, string]>;
  },
): FetchRequestLike {
  return { method: "POST", url: URL, ...overrides };
}

/** Signed headers as wire entries, for building a fetch Request. */
function signedEntries(signed: SignedHttpRequest): [string, string][] {
  return Object.entries(signed.headers).flatMap(([name, value]) =>
    value === undefined ? [] : [[name, value as string] as [string, string]],
  );
}

function signedPayment() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: URL,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "webhook-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  return { publicKey, signed };
}

test("sign -> real fetch Request -> fromFetchRequest -> verify round-trip", async () => {
  const { publicKey, signed } = signedPayment();
  const headers = new Headers();
  for (const [name, value] of signedEntries(signed)) headers.set(name, value);
  // A real Request, as a fetch-style server (undici / WinterCG / edge)
  // hands its handler: absolute URL, Headers instance, one-shot body.
  const req = new Request(URL, { method: "POST", headers, body: BODY });
  assert.equal(req.bodyUsed, false);
  // The caller reads the body first — the adapter never consumes it.
  const body = Buffer.from(await req.arrayBuffer());
  const adapted = fromFetchRequest(req, body);
  assert.equal(adapted.method, "POST");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.body, body);
  assert.equal("trailers" in adapted, false);
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "webhook-key");
  assert.equal(result.alg, "ed25519");
});

test("sign -> minimal fetch Request double -> fromFetchRequest -> verify round-trip", () => {
  const { publicKey, signed } = signedPayment();
  const adapted = fromFetchRequest(
    fetchRequest({ headers: signedEntries(signed) }),
    BODY,
  );
  assert.equal(adapted.method, "POST");
  assert.equal(adapted.url, URL);
  assert.equal(adapted.body, BODY);
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("multi-value headers are joined with ', ' (normalization parity)", () => {
  // Direct normalization check: two entries under differently-cased
  // names land as one lowercased field.
  const direct = fromFetchRequest(
    fetchRequest({
      headers: [
        ["Host", "api.example.com:8443"],
        ["X-Multi", "a"],
        ["x-multi", "b"],
      ],
    }),
  );
  assert.equal(direct.headers["x-multi"], "a, b");

  // End-to-end: the adapter's join matches what signRequest produced,
  // so a covered multi-value header still verifies.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com:8443/ping",
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
  const adapted = fromFetchRequest(
    fetchRequest({
      method: "GET",
      url: "https://api.example.com:8443/ping",
      headers: [
        ["X-Multi", "a"],
        ["x-multi", "b"],
        // signRequest echoes the covered header into signed.headers
        // as the joined value — filter it out, or the wire message
        // would carry x-multi three times instead of twice.
        ...signedEntries(signed).filter(([name]) => name !== "x-multi"),
      ],
    }),
  );
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("absolute URL is passed through verbatim, port included", () => {
  const { publicKey, signed } = signedPayment();
  const adapted = fromFetchRequest(
    fetchRequest({ headers: signedEntries(signed) }),
    BODY,
  );
  assert.equal(adapted.url, "https://api.example.com:8443/v1/charge");
  // @authority is a default covered component: a rebuilt URL that
  // dropped the port would fail verification here.
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("missing method throws a descriptive error", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({ method: undefined, headers: [] }),
        BODY,
      ),
    /fromFetchRequest: req\.method is missing/,
  );
});

test("missing url throws a descriptive error", () => {
  assert.throws(
    () =>
      fromFetchRequest(fetchRequest({ url: undefined, headers: [] }), BODY),
    /fromFetchRequest: req\.url is missing/,
  );
});

test("absolute URL without a host throws a descriptive error", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({ url: "https:///v1/charge", headers: [] }),
        BODY,
      ),
    /fromFetchRequest: req\.url has no host/,
  );
});

test("unparseable absolute URL throws a descriptive error", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({ url: "https://exa mple.com/v1/charge", headers: [] }),
        BODY,
      ),
    /fromFetchRequest: req\.url is not a valid absolute URL/,
  );
});

test("origin-form path without a host header throws a descriptive error", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({ url: "/v1/charge", headers: [] }),
        BODY,
      ),
    /fromFetchRequest: cannot rebuild the request URL without a host header/,
  );
});

test("origin-form path with a host header rebuilds http://host + path", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "http://api.example.com:8443/v1/charge",
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  const adapted = fromFetchRequest(
    fetchRequest({
      url: "/v1/charge",
      headers: [
        ["host", "api.example.com:8443"],
        ...signedEntries(signed),
      ],
    }),
    BODY,
  );
  assert.equal(adapted.url, "http://api.example.com:8443/v1/charge");
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("body forms: string and Buffer pass through, Uint8Array is copied to a Buffer", () => {
  const req = fetchRequest({ headers: [] });
  assert.equal(fromFetchRequest(req, BODY).body, BODY);
  const buf = Buffer.from(BODY, "utf8");
  assert.equal(fromFetchRequest(req, buf).body, buf);
  const bytes = new TextEncoder().encode(BODY);
  const adapted = fromFetchRequest(req, bytes);
  assert.equal(Buffer.isBuffer(adapted.body), true);
  assert.deepEqual(adapted.body, buf);
  // The copy is independent: mutating it leaves the caller's bytes alone.
  (adapted.body as Buffer)[0] = 0x58;
  assert.notEqual(bytes[0], 0x58);
});

test("Headers instance and entries array normalize identically", () => {
  const headers = new Headers([
    ["X-A", "1"],
    ["x-a", "2"],
  ]);
  const fromInstance = fromFetchRequest(
    fetchRequest({ headers }),
  );
  const fromEntries = fromFetchRequest(
    fetchRequest({
      headers: [
        ["X-A", "1"],
        ["x-a", "2"],
      ],
    }),
  );
  assert.deepEqual(fromInstance.headers, fromEntries.headers);
  assert.equal(fromInstance.headers["x-a"], "1, 2");
});

test("the adapter never consumes req.body", async () => {
  const { signed } = signedPayment();
  const headers = new Headers();
  for (const [name, value] of signedEntries(signed)) headers.set(name, value);
  const req = new Request(URL, { method: "POST", headers, body: BODY });
  fromFetchRequest(req, BODY);
  assert.equal(req.bodyUsed, false);
});
