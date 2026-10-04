import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;

function signedEd(body: string): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body,
    },
    { keyId: "k", alg: "ed25519", key: privateKey, created: CREATED },
  );
  return { signed, publicKey };
}

test("tampered body fails verification", () => {
  const { signed, publicKey } = signedEd('{"amount":100}');
  const tampered: SignedHttpRequest = { ...signed, body: '{"amount":999999}' };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

test("tampered signature-input fails verification", () => {
  const { signed, publicKey } = signedEd('{"amount":100}');
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        "created=1700000000",
        "created=1700000099",
      ),
    },
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

test("tampered path fails verification", () => {
  const { signed, publicKey } = signedEd('{"amount":100}');
  const tampered: SignedHttpRequest = {
    ...signed,
    url: "https://api.example.com/v1/refunds",
  };
  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
});

test("wrong key fails verification", () => {
  const { signed } = signedEd('{"amount":100}');
  const { publicKey: other } = generateEd25519KeyPair();
  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "signature mismatch");
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("missing signature headers fail cleanly", () => {
  const { signed, publicKey } = signedEd('{"amount":100}');
  const { "signature-input": _i, ...noInput } = signed.headers;
  const r1 = verifyRequest(
    { ...signed, headers: noInput },
    { key: publicKey, now: CREATED + 60 },
  );
  assert.equal(r1.ok, false);
  assert.equal(r1.reason, "missing signature-input header");
  assert.equal(r1.code, "MISSING_SIGNATURE_INPUT");
});
