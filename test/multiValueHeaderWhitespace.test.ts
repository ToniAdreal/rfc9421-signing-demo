import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSignatureBase,
  fromNodeRequest,
  generateEd25519KeyPair,
  getHeader,
  joinHeaderValues,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const COVERED = ["@method", "@authority", "@path", "x-foo"];

function signWithFoo(fooValues: string[]) {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "x-foo": fooValues },
    },
    {
      keyId: "k1",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: COVERED,
    },
  );
  return { publicKey, signed };
}

test("joinHeaderValues trims every element and joins with ', '", () => {
  assert.equal(joinHeaderValues(["  a  ", "b "]), "a, b");
  assert.equal(joinHeaderValues(["\ta\t", "  b", "c  "]), "a, b, c");
  assert.equal(joinHeaderValues(["  solo  "]), "solo");
  assert.equal(joinHeaderValues(["a", "b"]), "a, b");
  assert.equal(joinHeaderValues([]), "");
});

test("getHeader canonicalizes arrays through the same helper", () => {
  const values = ["  a  ", "b "];
  assert.equal(getHeader({ "X-Foo": values }, "x-foo"), "a, b");
  assert.equal(
    getHeader({ "X-Foo": values }, "x-foo"),
    joinHeaderValues(values),
  );
  // Single string values pass through untouched (outer-field
  // normalization in resolveComponent handles their edges).
  assert.equal(getHeader({ "x-foo": "a, b" }, "x-foo"), "a, b");
});

test("signature base golden: whitespace-padded elements normalize to 'a, b'", () => {
  const base = buildSignatureBase(
    ["x-foo"],
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "x-foo": ["  a  ", "b "] },
    },
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.equal(
    base,
    `"x-foo": a, b\n` +
      `"@signature-params": ("x-foo");created=1700000000;keyid="k1";alg="ed25519"`,
  );
});

test("sign -> verify round-trip with whitespace-padded multi-value header", () => {
  const { publicKey, signed } = signWithFoo(["  a  ", "b "]);
  // The signer emits the canonical wire value, not the padded join.
  assert.equal(signed.headers["x-foo"], "a, b");
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
});

test("verify accepts the same logical header presented again as a padded array", () => {
  const { publicKey, signed } = signWithFoo(["  a  ", "b "]);
  // A verifier-side framework may hand the header back as an array with
  // its own padding; that is the same field value and must verify.
  const asArray = {
    method: signed.method,
    url: signed.url,
    headers: { ...signed.headers, "x-foo": [" a", "b  "] },
  };
  assert.equal(
    verifyRequest(asArray, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
  // A genuinely different value still fails.
  const tampered = {
    method: signed.method,
    url: signed.url,
    headers: { ...signed.headers, "x-foo": ["a", "c"] },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("fromNodeRequest path canonicalizes the same way and round-trips", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://hooks.example.com/webhook?event=push",
      headers: { "x-foo": ["  a  ", "b "] },
    },
    {
      keyId: "webhook-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      coveredComponents: COVERED,
    },
  );
  const req = fromNodeRequest({
    method: "POST",
    url: "/webhook?event=push",
    socket: { encrypted: true },
    headers: {
      Host: "hooks.example.com",
      "X-Foo": ["  a  ", "b "],
      "Signature-Input": signed.headers["signature-input"],
      Signature: signed.headers["signature"],
    },
  });
  assert.equal(req.headers["x-foo"], "a, b");
  assert.equal(req.headers["x-foo"], joinHeaderValues(["  a  ", "b "]));
  assert.equal(
    verifyRequest(req, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
});

test("signer, verifier lookup, and Node adapter all agree on one value", () => {
  const values = ["  alpha ", " beta  ", "gamma"];
  const { signed } = signWithFoo(values);
  assert.equal(signed.headers["x-foo"], joinHeaderValues(values));
  assert.equal(getHeader({ "x-foo": values }, "x-foo"), signed.headers["x-foo"]);
  const adapted = fromNodeRequest({
    method: "POST",
    url: "/webhook",
    headers: { Host: "hooks.example.com", "X-Foo": values },
  });
  assert.equal(adapted.headers["x-foo"], signed.headers["x-foo"]);
});

test("multi-value header without padding is unchanged (regression)", () => {
  const { publicKey, signed } = signWithFoo(["a", "b"]);
  assert.equal(signed.headers["x-foo"], "a, b");
  assert.equal(
    verifyRequest(signed, { key: publicKey, now: CREATED + 60 }).ok,
    true,
  );
  const base = buildSignatureBase(
    ["x-foo"],
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "x-foo": ["a", "b"] },
    },
    { created: CREATED, keyid: "k1", alg: "ed25519" },
  );
  assert.match(base, /^"x-foo": a, b\n/);
});
