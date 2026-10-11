import test from "node:test";
import assert from "node:assert/strict";
import {
  fromNodeRequest,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type IncomingRequestLike,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;

/** Sign a request whose `x-checksum` trailer is bound via `;tr`. */
function signedTrailerRequest() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signerSide: RequestLike = {
    method: "POST",
    url: "https://hooks.example.com/webhook",
    headers: { "content-type": "application/json" },
    trailers: { "x-checksum": "trailer-value" },
    body: "hello",
  };
  const signed = signRequest(signerSide, {
    keyId: "tr-node",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    coveredComponents: ["@method", "@authority", "@path", "x-checksum;tr"],
  });
  return { publicKey, signed };
}

/** A test double shaped like the fields of http.IncomingMessage. */
function incoming(
  overrides: Partial<IncomingRequestLike> & {
    headers: Record<string, string | string[] | undefined>;
  },
): IncomingRequestLike {
  return {
    method: "POST",
    url: "/webhook",
    socket: { encrypted: true },
    ...overrides,
  };
}

function wireHeaders(signed: RequestLike): Record<string, string | undefined> {
  return {
    Host: "hooks.example.com",
    "Content-Type": "application/json",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
  };
}

test("trailers object: adapter output verifies a ;tr covered component", () => {
  const { publicKey, signed } = signedTrailerRequest();
  const req = fromNodeRequest(
    incoming({
      headers: wireHeaders(signed),
      // Mixed-case name exercises the adapter's lowercasing, the same
      // convention it applies to headers.
      trailers: { "X-Checksum": "trailer-value" },
    }),
    "hello",
  );
  assert.deepEqual(req.trailers, { "x-checksum": "trailer-value" });
  const res = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
});

test("trailers object: a tampered trailer value fails verification", () => {
  const { publicKey, signed } = signedTrailerRequest();
  const req = fromNodeRequest(
    incoming({
      headers: wireHeaders(signed),
      trailers: { "x-checksum": "forged-value" },
    }),
    "hello",
  );
  const res = verifyRequest(req, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("no trailers: RequestLike gains no trailers field and plain verification is unchanged", () => {
  // Every "no trailer" shape a real or doubled message can take.
  for (const extra of [
    {},
    { trailers: {} },
    { trailers: { "x-unused": undefined } },
    { rawTrailers: [] },
  ] as Partial<IncomingRequestLike>[]) {
    const req = fromNodeRequest(
      incoming({ headers: { host: "hooks.example.com" }, ...extra }),
      "hello",
    );
    assert.equal("trailers" in req, false, JSON.stringify(extra));
    assert.equal(req.trailers, undefined);
  }

  // A plain (non-;tr) signature round-trips through the adapter
  // exactly as before this feature existed.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook",
      headers: { "content-type": "application/json" },
      body: "hello",
    },
    { keyId: "plain", alg: "ed25519", key: privateKey, created: CREATED },
  );
  const req = fromNodeRequest(
    incoming({
      headers: {
        ...wireHeaders(signed),
        "Content-Digest": signed.headers["content-digest"] as string,
      },
    }),
    "hello",
  );
  assert.equal(verifyRequest(req, { key: publicKey, now: CREATED + 60 }).ok, true);

  // And the converse: a ;tr signature received WITHOUT its trailers
  // (the pre-feature adapter behavior) fails closed, never silently.
  const tr = signedTrailerRequest();
  const dropped = fromNodeRequest(
    incoming({ headers: wireHeaders(tr.signed) }),
    "hello",
  );
  const res = verifyRequest(dropped, { key: tr.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_BASE_BUILD_FAILED");
});

test("multi-value trailers join with ', ' — the header convention", () => {
  const direct = fromNodeRequest(
    incoming({
      headers: { host: "h" },
      trailers: { "X-Multi": ["  alpha  ", "beta "] },
    }),
  );
  assert.equal(direct.trailers?.["x-multi"], "alpha, beta");

  // End-to-end: the signer canonicalized ["alpha", "beta"] to
  // "alpha, beta"; the adapter must produce the same bytes.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook",
      headers: {},
      trailers: { "x-multi": ["alpha", "beta"] },
      body: "hello",
    },
    {
      keyId: "mv",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: ["@method", "x-multi;tr"],
    },
  );
  const req = fromNodeRequest(
    incoming({
      headers: wireHeaders(signed),
      trailers: { "x-multi": ["  alpha  ", "beta "] },
    }),
    "hello",
  );
  assert.equal(verifyRequest(req, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("rawTrailers: parsed in wire order, names lowercased (original case NOT preserved), duplicates merged", () => {
  const req = fromNodeRequest(
    incoming({
      headers: { host: "h" },
      rawTrailers: [
        "X-Checksum", "trailer-value",
        "X-Dup", "a",
        "x-dup", "b",
      ],
    }),
  );
  // Pin the case behavior: raw names arrive mixed-case, the
  // normalized RequestLike carries lowercase names only — the same
  // treatment headers get, because ;tr lookup is case-insensitive.
  assert.deepEqual(req.trailers, {
    "x-checksum": "trailer-value",
    "x-dup": "a, b",
  });
  assert.ok(!("X-Checksum" in (req.trailers ?? {})));
});

test("rawTrailers: adapter output verifies a ;tr covered component end-to-end", () => {
  const { publicKey, signed } = signedTrailerRequest();
  const req = fromNodeRequest(
    incoming({
      headers: wireHeaders(signed),
      rawTrailers: ["X-Checksum", "trailer-value"],
    }),
    "hello",
  );
  assert.equal(verifyRequest(req, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("rawTrailers takes precedence over the trailers object when both are present", () => {
  const { publicKey, signed } = signedTrailerRequest();
  const req = fromNodeRequest(
    incoming({
      headers: wireHeaders(signed),
      // The parsed object disagrees with the raw form; the raw form
      // is the lossless wire record, so it wins.
      trailers: { "x-checksum": "stale-object-value" },
      rawTrailers: ["X-Checksum", "trailer-value"],
    }),
    "hello",
  );
  assert.deepEqual(req.trailers, { "x-checksum": "trailer-value" });
  assert.equal(verifyRequest(req, { key: publicKey, now: CREATED + 60 }).ok, true);
});
