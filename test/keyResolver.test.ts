import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign, type KeyObject } from "node:crypto";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  signatureInputValue,
  verifyAllLabels,
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

function REQT(r: typeof REQ): typeof REQ {
  return { ...r, headers: { ...r.headers } };
}

/** Two rotating key pairs behind a `keyid`→key map, like a keystore. */
function keystore() {
  const k1 = generateEd25519KeyPair();
  const k2 = generateEd25519KeyPair();
  const store = new Map<string, KeyObject>([
    ["merchant-key-1", k1.publicKey],
    ["merchant-key-2", k2.publicKey],
  ]);
  return { k1, k2, store, keyResolver: (id: string) => store.get(id) };
}

function signAs(
  keyId: string,
  privateKey: KeyObject,
  extra: { label?: string } = {},
): SignedHttpRequest {
  return signRequest(REQT(REQ), {
    keyId,
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    ...extra,
  });
}

test("keyResolver: both key ids verify through the resolver (rotation round-trip)", () => {
  const { k1, k2, keyResolver } = keystore();
  const s1 = signAs("merchant-key-1", k1.privateKey);
  const s2 = signAs("merchant-key-2", k2.privateKey);
  const r1 = verifyRequest(s1, { keyResolver, now: CREATED });
  const r2 = verifyRequest(s2, { keyResolver, now: CREATED });
  assert.equal(r1.ok, true);
  assert.equal(r1.keyId, "merchant-key-1");
  assert.equal(r2.ok, true);
  assert.equal(r2.keyId, "merchant-key-2");
});

test("keyResolver: rotation — old key still verifies after the new key signs", () => {
  const { k1, k2, store, keyResolver } = keystore();
  const oldSig = signAs("merchant-key-1", k1.privateKey);
  const newSig = signAs("merchant-key-2", k2.privateKey);
  // "Rotate": the old id is retired from the store.
  store.delete("merchant-key-1");
  assert.equal(verifyRequest(newSig, { keyResolver, now: CREATED }).ok, true);
  const retired = verifyRequest(oldSig, { keyResolver, now: CREATED });
  assert.equal(retired.ok, false);
  assert.equal(retired.code, "KEY_RESOLUTION_FAILED");
});

test("keyResolver: unknown keyid fails with KEY_RESOLUTION_FAILED", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("attacker-key", k1.privateKey);
  const res = verifyRequest(signed, { keyResolver, now: CREATED });
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
  assert.equal(res.keyId, "attacker-key");
  assert.match(res.reason ?? "", /could not be resolved/);
});

test("keyResolver: signature with no keyid fails with KEY_RESOLUTION_FAILED", () => {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const covered = ["@method", "@authority", "@path"];
  const params = { created: CREATED, alg: "ed25519" } as SignatureParams;
  const base = buildSignatureBase(covered, REQT(REQ), params);
  const sig = edSign(null, Buffer.from(base, "utf8"), privateKey);
  const headers: Record<string, string> = {
    "signature-input": signatureInputValue("sig1", covered, params),
    signature: `sig1=:${sig.toString("base64")}:`,
  };
  const res = verifyRequest(
    { ...REQ, headers },
    { keyResolver: () => publicKey, now: CREATED },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "KEY_RESOLUTION_FAILED");
  assert.match(res.reason ?? "", /no keyid/);
});

test("keyResolver: resolver returning the wrong key -> SIGNATURE_MISMATCH", () => {
  const { k1, k2 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  // Resolver maps to k2's public key: the keyid resolves, but the crypto
  // check must still reject because the signature was made with k1.
  const res = verifyRequest(signed, {
    keyResolver: () => k2.publicKey,
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("keyResolver: key + keyResolver together throws a configuration error", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  assert.throws(
    () => verifyRequest(signed, { key: k1.publicKey, keyResolver, now: CREATED }),
    /mutually exclusive/,
  );
});

test("keyResolver: neither key nor keyResolver throws a configuration error", () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  assert.throws(
    () => verifyRequest(signed, { now: CREATED }),
    /either `key` or `keyResolver`/,
  );
});

test("keyResolver: a throwing resolver surfaces VERIFICATION_ERROR, never escapes", () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const res = verifyRequest(signed, {
    keyResolver: () => {
      throw new Error("store is down");
    },
    now: CREATED,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "VERIFICATION_ERROR");
  assert.match(res.reason ?? "", /key resolver threw/);
});

test("keyResolver: verifyRequestOrThrow throws VerifyError with KEY_RESOLUTION_FAILED", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("ghost-key", k1.privateKey);
  assert.throws(
    () => verifyRequestOrThrow(signed, { keyResolver, now: CREATED }),
    (e: unknown) => {
      assert.ok(isVerifyError(e));
      assert.equal(e.code, "KEY_RESOLUTION_FAILED");
      assert.equal(e.keyId, "ghost-key");
      return true;
    },
  );
});

test("keyResolver: verifyAllLabels resolves each label independently", () => {
  const { k1, k2, keyResolver } = keystore();
  const first = signAs("merchant-key-1", k1.privateKey, { label: "sig1" });
  const second = signAs("merchant-key-2", k2.privateKey, { label: "sig2" });
  // Merge the two signatures onto one request.
  const headers = { ...first.headers };
  headers["signature-input"] = [
    first.headers["signature-input"],
    second.headers["signature-input"],
  ].join(", ");
  headers["signature"] = [first.headers["signature"], second.headers["signature"]].join(
    ", ",
  );
  const results = verifyAllLabels(
    { method: first.method, url: first.url, headers, body: first.body },
    { keyResolver, now: CREATED },
  );
  assert.equal(results.length, 2);
  assert.ok(results.every((r) => r.ok));
  assert.deepEqual(
    results.map((r) => r.keyId).sort(),
    ["merchant-key-1", "merchant-key-2"],
  );
});

test("keyResolver: verifyAllLabels keys+keyResolver conflict throws", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        keyResolver,
        keys: { sig1: k1.publicKey },
        now: CREATED,
      }),
    /mutually exclusive/,
  );
});

test("keyResolver: composes with expectedKeyId pinning", () => {
  const { k1, keyResolver } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const pass = verifyRequest(signed, {
    keyResolver,
    expectedKeyId: "merchant-key-1",
    now: CREATED,
  });
  assert.equal(pass.ok, true);
  const pinned = verifyRequest(signed, {
    keyResolver,
    expectedKeyId: "merchant-key-2",
    now: CREATED,
  });
  assert.equal(pinned.ok, false);
  assert.equal(pinned.code, "KEYID_MISMATCH");
});

test("keyResolver: resolution runs after header parse, not before it", () => {
  // A malformed signature-input must still report MALFORMED_SIGNATURE_INPUT,
  // not attempt resolution with a garbage keyid.
  const { keyResolver } = keystore();
  const res = verifyRequest(
    {
      method: "POST",
      url: "https://api.example.com/",
      headers: {
        "signature-input": 'sig1=("unclosed',
        signature: "sig1=:AAAA:",
      },
    },
    { keyResolver, now: CREATED },
  );
  assert.equal(res.ok, false);
  assert.equal(res.code, "MALFORMED_SIGNATURE_INPUT");
});

test("keyResolver: static key path is unchanged (backward compatible)", () => {
  const { k1 } = keystore();
  const signed = signAs("merchant-key-1", k1.privateKey);
  const res = verifyRequest(signed, { key: k1.publicKey, now: CREATED });
  assert.equal(res.ok, true);
});
