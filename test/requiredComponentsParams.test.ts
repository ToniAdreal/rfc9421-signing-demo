import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  contentDigest,
  generateEd25519KeyPair,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type RequestLike,
  type SignedHttpRequest,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const BODY = '{"amount":100}';
const DIGEST = contentDigest(BODY);

type KeyPair = ReturnType<typeof generateEd25519KeyPair>;

// A POST whose body digest is precomputed into the header: the sign side
// only auto-computes a digest for the bare `content-digest` component
// (backlog #1271), so parameterized forms (`;bs`, `;sf`, `;key="…"`) must
// carry the header themselves — exactly what a gateway that already
// computed the digest would send.
function signBody(covered: string[]): {
  signed: SignedHttpRequest;
  publicKey: KeyPair["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-digest": DIGEST },
      body: BODY,
    },
    {
      alg: "ed25519",
      key: privateKey,
      keyId: "gw-1",
      coveredComponents: covered,
    },
  );
  return { signed, publicKey };
}

// A request carrying its associated (triggering) request, whose body
// digest is likewise precomputed: `;req` coverage resolves the
// component against the associated request, never against this message.
function signWithAssoc(covered: string[]): {
  signed: SignedHttpRequest;
  publicKey: KeyPair["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const assoc: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-digest": DIGEST },
    body: BODY,
  };
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: BODY,
      request: assoc,
    },
    {
      alg: "ed25519",
      key: privateKey,
      keyId: "gw-1",
      coveredComponents: covered,
    },
  );
  return { signed, publicKey };
}

// ---------- value parameters satisfy a bare requirement ----------

test("requiredComponents: \"content-digest\";bs satisfies [\"content-digest\"]", () => {
  const { signed, publicKey } = signBody(["@method", "content-digest;bs"]);
  assert.match(signed.headers["signature-input"], /"content-digest";bs/);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, true);
});

test("requiredComponents: \"content-digest\";sf satisfies [\"content-digest\"]", () => {
  const { signed, publicKey } = signBody(["@method", "content-digest;sf"]);
  assert.match(signed.headers["signature-input"], /"content-digest";sf/);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, true);
});

test("requiredComponents: \"content-digest\";key=\"sha-512\" satisfies [\"content-digest\"]", () => {
  const { signed, publicKey } = signBody([
    "@method",
    'content-digest;key="sha-512"',
  ]);
  assert.match(
    signed.headers["signature-input"],
    /"content-digest";key="sha-512"/,
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, true);
});

test("requiredComponents: \"x-a\";tr satisfies [\"x-a\"]", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      trailers: { "x-a": "trailer-value" },
      body: BODY,
    },
    {
      alg: "ed25519",
      key: privateKey,
      keyId: "gw-1",
      coveredComponents: ["@method", "x-a;tr"],
    },
  );
  assert.match(signed.headers["signature-input"], /"x-a";tr/);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["x-a"],
  });
  assert.equal(res.ok, true);
});

// ---------- ;req never satisfies a plain requirement (and vice versa) ----------

test("requiredComponents: \"content-digest\";req does NOT satisfy [\"content-digest\"]", () => {
  const { signed, publicKey } = signWithAssoc([
    "@method",
    "content-digest;req",
  ]);
  assert.match(signed.headers["signature-input"], /"content-digest";req/);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.match(res.reason ?? "", /content-digest/);
});

test("requiredComponents: \"content-digest\";req satisfies [\"content-digest;req\"]", () => {
  const { signed, publicKey } = signWithAssoc([
    "@method",
    "content-digest;req",
  ]);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest;req"],
  });
  assert.equal(res.ok, true);
});

test("requiredComponents: plain \"content-digest\" does NOT satisfy [\"content-digest;req\"]", () => {
  const { signed, publicKey } = signBody(["@method", "content-digest"]);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest;req"],
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "MISSING_REQUIRED_COMPONENT");
  assert.match(res.reason ?? "", /content-digest;req/);
});

test("requiredComponents: \"content-digest\";req;bs satisfies [\"content-digest;req\"] but not [\"content-digest\"]", () => {
  const { signed, publicKey } = signWithAssoc([
    "@method",
    "content-digest;req;bs",
  ]);
  assert.match(signed.headers["signature-input"], /"content-digest";req;bs/);
  const viaReq = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest;req"],
  });
  assert.equal(viaReq.ok, true);
  const viaPlain = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest"],
  });
  assert.equal(viaPlain.ok, false);
  assert.equal(viaPlain.code, "MISSING_REQUIRED_COMPONENT");
});

// ---------- case-insensitivity survives parameters ----------

test("requiredComponents: \"Content-Digest\";BS matches [\"Content-Digest\"]", () => {
  const { signed, publicKey } = signBody(["@method", "Content-Digest;BS"]);
  assert.match(signed.headers["signature-input"], /"content-digest";bs/);
  const res = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["Content-Digest"],
  });
  assert.equal(res.ok, true);
});

// ---------- per-label independence ----------

test("requiredComponents: verifyAllLabels isolates a ;req-only label from a plain label", () => {
  // "sig1" binds only the associated request's digest; "gateway" binds
  // this message's body. A gateway policy demanding `content-digest`
  // must fail sig1 without touching gateway's verdict, and the reverse
  // policy must fail gateway without touching sig1's.
  const first = signWithAssoc(["@method", "content-digest;req"]);
  const { publicKey: gwPublic, privateKey: gwPrivate } =
    generateEd25519KeyPair();
  const multi = addSignature(first.signed, {
    alg: "ed25519",
    key: gwPrivate,
    keyId: "gw-2",
    label: "gateway",
    coveredComponents: ["@method", "content-digest"],
  });
  const plain = verifyAllLabels(multi, {
    keys: { sig1: first.publicKey, gateway: gwPublic },
    requiredComponents: ["content-digest"],
  });
  assert.equal(plain.length, 2);
  const plainByLabel = new Map(plain.map((r) => [r.label, r]));
  assert.equal(plainByLabel.get("sig1")?.ok, false);
  assert.equal(plainByLabel.get("sig1")?.code, "MISSING_REQUIRED_COMPONENT");
  assert.equal(plainByLabel.get("gateway")?.ok, true);

  const viaReq = verifyAllLabels(multi, {
    keys: { sig1: first.publicKey, gateway: gwPublic },
    requiredComponents: ["content-digest;req"],
  });
  assert.equal(viaReq.length, 2);
  const reqByLabel = new Map(viaReq.map((r) => [r.label, r]));
  assert.equal(reqByLabel.get("sig1")?.ok, true);
  assert.equal(reqByLabel.get("gateway")?.ok, false);
  assert.equal(reqByLabel.get("gateway")?.code, "MISSING_REQUIRED_COMPONENT");
});

// ---------- old behavior is unchanged ----------

test("requiredComponents: bare entries still match exactly and a missing one keeps the original code/reason", () => {
  const { signed, publicKey } = signBody(["@method", "content-digest"]);
  const covered = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest", "@method"],
  });
  assert.equal(covered.ok, true);

  const missing = verifyRequest(signed, {
    key: publicKey,
    requiredComponents: ["content-digest", "@path"],
  });
  assert.equal(missing.ok, false);
  assert.equal(missing.code, "MISSING_REQUIRED_COMPONENT");
  assert.equal(
    missing.reason,
    'signature does not cover required component: "@path"',
  );
});
