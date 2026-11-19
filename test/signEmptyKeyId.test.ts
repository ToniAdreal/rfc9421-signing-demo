import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const URL = "https://api.example.com/v1/payments";

function signWithKeyId(keyId: string) {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: "{}" },
    { keyId, alg: "ed25519", key: kp.privateKey, created: CREATED },
  );
  return { ...kp, signed };
}

test("empty keyId throws and the message names keyId", () => {
  assert.throws(
    () => signWithKeyId(""),
    /signRequest: "keyId" must not be an empty string; an empty keyid cannot be resolved/,
  );
});

test("whitespace-only keyId is non-empty and still signs", () => {
  const { publicKey, signed } = signWithKeyId(" ");
  assert.match(signed.headers["signature-input"], /;keyid=" "/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, " ");
});

test("keyId of exactly 256 characters signs (the length cap)", () => {
  const keyId = "k".repeat(256);
  const { publicKey, signed } = signWithKeyId(keyId);
  assert.match(signed.headers["signature-input"], new RegExp(`;keyid="${keyId}"`));
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, keyId);
});

test("keyId of 257 characters still reports the length error (empty check does not mask it)", () => {
  assert.throws(
    () => signWithKeyId("k".repeat(257)),
    /signRequest: "keyId" must be at most 256 characters, got 257/,
  );
});

test("normal keyId round-trips and VerifyResult.keyId echoes it", () => {
  const { publicKey, signed } = signWithKeyId("merchant-key-1");
  assert.match(signed.headers["signature-input"], /;keyid="merchant-key-1"/);
  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "merchant-key-1");
});

test("omitted keyId still signs with no keyid parameter (empty check does not break omission)", () => {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(
    { method: "POST", url: URL, headers: {}, body: "{}" },
    { alg: "ed25519", key: kp.privateKey, created: CREATED },
  );
  assert.ok(!/;keyid=/.test(signed.headers["signature-input"]));
  const res = verifyRequest(signed, { key: kp.publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, undefined);
});

test("addSignature inherits the empty-keyId rejection via signRequest delegation", () => {
  const { signed } = signWithKeyId("merchant-key-1");
  const kp = generateEd25519KeyPair();
  assert.throws(
    () =>
      addSignature(signed, {
        keyId: "",
        alg: "ed25519",
        key: kp.privateKey,
        created: CREATED,
        label: "gateway",
      }),
    /signRequest: "keyId" must not be an empty string/,
  );
});
