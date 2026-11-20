import test from "node:test";
import assert from "node:assert/strict";
import {
  fromFetchRequest,
  fromNodeRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type FetchRequestLike,
  type IncomingRequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const HTTPS_URL = "https://api.example.com:8443/v1/charge";
const HTTP_URL = "http://api.example.com:8443/v1/charge";

/** Covered components that pin the scheme into the signature base. */
const COVERED = [
  "@method",
  "@scheme",
  "@authority",
  "@path",
  "content-digest",
  "content-type",
];

/** A test double shaped like the fields of http.IncomingMessage. */
function incomingMessage(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/v1/charge",
    socket: { encrypted: true },
    ...overrides,
  };
}

/** A test double shaped like the fields of a fetch Request. */
function fetchRequest(
  overrides: Partial<FetchRequestLike> & {
    headers: Iterable<[string, string]>;
  },
): FetchRequestLike {
  return { method: "POST", url: HTTPS_URL, ...overrides };
}

/** Signed headers as wire entries, for building a fetch Request. */
function signedEntries(signed: SignedHttpRequest): [string, string][] {
  return Object.entries(signed.headers).flatMap(([name, value]) =>
    value === undefined ? [] : [[name, value as string] as [string, string]],
  );
}

function signedPayment(url: string) {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url,
      headers: { "content-type": "application/json" },
      body: BODY,
    },
    {
      keyId: "webhook-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: COVERED,
    },
  );
  return { publicKey, signed };
}

test("fromNodeRequest rejects an empty opts.scheme", () => {
  const { signed } = signedPayment(HTTPS_URL);
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({
          headers: {
            Host: "api.example.com:8443",
            "Signature-Input": signed.headers["signature-input"],
            Signature: signed.headers["signature"],
            "Content-Digest": signed.headers["content-digest"],
          },
        }),
        BODY,
        { scheme: "" },
      ),
    /fromNodeRequest: scheme must be "http" or "https", got ""/,
  );
});

test("fromNodeRequest rejects opts.scheme 'ftp'", () => {
  const { signed } = signedPayment(HTTPS_URL);
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({
          headers: {
            Host: "api.example.com:8443",
            "Signature-Input": signed.headers["signature-input"],
            Signature: signed.headers["signature"],
            "Content-Digest": signed.headers["content-digest"],
          },
        }),
        BODY,
        { scheme: "ftp" },
      ),
    /fromNodeRequest: scheme must be "http" or "https", got "ftp"/,
  );
});

test("fromNodeRequest rejects opts.scheme 'javascript'", () => {
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({ headers: { Host: "api.example.com:8443" } }),
        BODY,
        { scheme: "javascript" },
      ),
    /fromNodeRequest: scheme must be "http" or "https", got "javascript"/,
  );
});

test("fromNodeRequest rejects a non-http(s) :scheme pseudo-header", () => {
  assert.throws(
    () =>
      fromNodeRequest(
        incomingMessage({
          socket: { encrypted: false },
          headers: {
            ":authority": "api.example.com:8443",
            ":scheme": "ftp",
          },
        }),
        BODY,
      ),
    /fromNodeRequest: scheme must be "http" or "https", got "ftp"/,
  );
});

test("fromNodeRequest rejects a non-string scheme from a JS caller", () => {
  let caught: unknown;
  try {
    fromNodeRequest(
      incomingMessage({ headers: { Host: "api.example.com:8443" } }),
      BODY,
      // A JS caller can pass a number despite the TS type.
      { scheme: 443 as unknown as string },
    );
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof Error);
  assert.match(
    caught.message,
    /fromNodeRequest: scheme must be "http" or "https", got 443/,
  );
  // A configuration mistake, not a runtime type accident.
  assert.equal(caught instanceof TypeError, false);
});

test("fromFetchRequest rejects an ftp:// absolute URL", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({
          url: "ftp://api.example.com:8443/v1/charge",
          headers: [],
        }),
        BODY,
      ),
    /fromFetchRequest: req\.url scheme must be "http" or "https", got "ftp"/,
  );
});

test("fromFetchRequest rejects a javascript: absolute URL", () => {
  assert.throws(
    () =>
      fromFetchRequest(
        fetchRequest({
          url: "javascript://api.example.com:8443/v1/charge",
          headers: [],
        }),
        BODY,
      ),
    /fromFetchRequest: req\.url scheme must be "http" or "https", got "javascript"/,
  );
});

test("fromFetchRequest accepts an uppercase HTTPS:// absolute URL and @scheme resolves to https", () => {
  const { publicKey, signed } = signedPayment(HTTPS_URL);
  const adapted = fromFetchRequest(
    fetchRequest({
      url: "HTTPS://api.example.com:8443/v1/charge",
      headers: signedEntries(signed),
    }),
    BODY,
  );
  // The absolute URL still passes through verbatim, port included.
  assert.equal(adapted.url, "HTTPS://api.example.com:8443/v1/charge");
  // @scheme is a covered component: verification only passes if the
  // adapter's URL parses to scheme "https".
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("fromNodeRequest accepts an uppercase opts.scheme and rebuilds to lowercase https", () => {
  const { publicKey, signed } = signedPayment(HTTPS_URL);
  const adapted = fromNodeRequest(
    incomingMessage({
      socket: { encrypted: false },
      headers: {
        Host: "api.example.com:8443",
        "Content-Type": "application/json",
        "Signature-Input": signed.headers["signature-input"],
        Signature: signed.headers["signature"],
        "Content-Digest": signed.headers["content-digest"],
      },
    }),
    BODY,
    { scheme: "HTTPS" },
  );
  assert.equal(adapted.url, HTTPS_URL);
  // @scheme is covered, so this also proves the rebuilt URL's scheme
  // is "https", not the caller's "HTTPS" spelling.
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("fromNodeRequest still round-trips legal http and https", () => {
  for (const [url, encrypted] of [
    [HTTPS_URL, true],
    [HTTP_URL, false],
  ] as const) {
    const { publicKey, signed } = signedPayment(url);
    const adapted = fromNodeRequest(
      incomingMessage({
        socket: { encrypted },
        headers: {
          Host: "api.example.com:8443",
          "Content-Type": "application/json",
          "Signature-Input": signed.headers["signature-input"],
          Signature: signed.headers["signature"],
          "Content-Digest": signed.headers["content-digest"],
        },
      }),
      BODY,
    );
    assert.equal(adapted.url, url);
    const result = verifyRequest(adapted, { key: publicKey, now: NOW });
    assert.equal(result.ok, true);
  }
});

test("an explicit opts.scheme wins over a bogus :scheme pseudo-header", () => {
  const { publicKey, signed } = signedPayment(HTTPS_URL);
  const adapted = fromNodeRequest(
    incomingMessage({
      socket: { encrypted: false },
      headers: {
        ":authority": "api.example.com:8443",
        ":scheme": "ftp",
        "Content-Type": "application/json",
        "Signature-Input": signed.headers["signature-input"],
        Signature: signed.headers["signature"],
        "Content-Digest": signed.headers["content-digest"],
      },
    }),
    BODY,
    { scheme: "https" },
  );
  // The check applies to the effective scheme, and the explicit
  // option is the effective one — so no throw, and the URL is https.
  assert.equal(adapted.url, HTTPS_URL);
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});

test("fromFetchRequest still round-trips a legal http absolute URL", () => {
  const { publicKey, signed } = signedPayment(HTTP_URL);
  const adapted = fromFetchRequest(
    fetchRequest({ url: HTTP_URL, headers: signedEntries(signed) }),
    BODY,
  );
  assert.equal(adapted.url, HTTP_URL);
  const result = verifyRequest(adapted, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
});
