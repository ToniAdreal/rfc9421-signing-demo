import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  signatureInputValue,
  verifyRequest,
  verifyRequestOrThrow,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: {} as Record<string, string>,
  body: '{"amount":100}',
};

function signAs(keyId: string): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQT(REQ), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
  });
  return { signed, publicKey };
}

// Fresh request object per call (signRequest never mutates, but the
// headers record is rebuilt each time for clarity).
function REQT(r: typeof REQ): typeof REQ {
  return { ...r, headers: { ...r.headers } };
}

test("expectedKeyId: matching keyid passes and echoes the keyId", () => {
  const { signed, publicKey } = signAs("merchant-key-1");
  const res = verifyRequest(signed, {
    key: publicKey,
    expectedKeyId: "merchant-key-1",
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "merchant-key-1");
});

test("expectedKeyId: wrong keyid is rejected with KEYID_MISMATCH", () => {
  const { signed, publicKey } = signAs("merchant-key-1");
  const res = verifyRequest(signed, {
    key: publicKey,
    expectedKeyId: "merchant-key-2",
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEYID_MISMATCH");
  assert.match(res.reason ?? "", /keyid mismatch/);
  assert.equal(res.keyId, "merchant-key-1");
  assert.equal(res.label, "sig1");
});

test("expectedKeyId: unset means no check (backward compatible)", () => {
  const { signed, publicKey } = signAs("merchant-key-1");
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "merchant-key-1");
});

test("expectedKeyId: signature with no keyid param still fails the pin", () => {
  // Hand-build a valid signature whose signature-input carries no `keyid`,
  // so the pinning check sees a missing claim instead of a mismatch.
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const covered = ["@method", "@authority", "@path"];
  const params = { created: CREATED, alg: "ed25519" } as SignatureParams;
  const base = buildSignatureBase(covered, REQT(REQ), params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const headers: Record<string, string> = {
    "signature-input": signatureInputValue("sig1", covered, params),
    signature: `sig1=:${sig.toString("base64")}:`,
  };
  const res = verifyRequest({ ...REQ, headers }, {
    key: publicKey,
    expectedKeyId: "merchant-key-1",
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEYID_MISMATCH");
  assert.equal(res.keyId, undefined);
  assert.match(res.reason ?? "", /no keyid/);
});

test("expectedKeyId: crypto runs before the pin (wrong key -> SIGNATURE_MISMATCH)", () => {
  const { signed } = signAs("merchant-key-1");
  const { publicKey: otherKey } = generateEd25519KeyPair();
  const res = verifyRequest(signed, {
    key: otherKey,
    expectedKeyId: "merchant-key-2",
    now: CREATED,
  });
  // The wrong-key failure wins: the request never reaches the pin check.
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("expectedKeyId: right key but keyed to another id is a pin failure, not a crypto failure", () => {
  // Key-confusion shape: attacker signature with their own key and their
  // own keyid, verified with the honest key -> caught as KEYID_MISMATCH.
  const { signed, publicKey } = signAs("attacker-key");
  const res = verifyRequest(signed, {
    key: publicKey,
    expectedKeyId: "merchant-key-1",
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEYID_MISMATCH");
});

test("expectedKeyId: verifyRequestOrThrow throws VerifyError with KEYID_MISMATCH", () => {
  const { signed, publicKey } = signAs("merchant-key-1");
  assert.throws(
    () =>
      verifyRequestOrThrow(signed, {
        key: publicKey,
        expectedKeyId: "merchant-key-2",
        now: CREATED,
      }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "KEYID_MISMATCH");
      assert.equal(e.keyId, "merchant-key-1");
      return true;
    },
  );
});

test("expectedKeyId: pin check does not disturb nonce or freshness results", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(REQT(REQ), {
    keyId: "k",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    nonce: "n-1",
  });
  const res = verifyRequest(signed, {
    key: publicKey,
    expectedKeyId: "k",
    now: CREATED,
  });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, "n-1");
});
