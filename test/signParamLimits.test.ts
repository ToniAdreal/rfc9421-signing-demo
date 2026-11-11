import test from "node:test";
import assert from "node:assert/strict";
import { sign as edSign } from "node:crypto";
import {
  addSignature,
  buildSignatureBase,
  generateEd25519KeyPair,
  MAX_COVERED_COMPONENTS,
  MAX_KEY_ID_LENGTH,
  MAX_NONCE_LENGTH,
  MAX_TAG_LENGTH,
  secretKey,
  signatureInputValue,
  signRequest,
  verifyRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;
const COVERED = ["@method", "@authority", "@path"];
const URL = "https://api.example.com/v1/payments";

function paymentRequest() {
  return { method: "POST", url: URL, headers: {} };
}

function signEd(opts: {
  tag?: string;
  nonce?: string;
  keyId?: string;
  coveredComponents?: string[];
  req?: ReturnType<typeof paymentRequest>;
}) {
  const kp = generateEd25519KeyPair();
  const signed = signRequest(opts.req ?? paymentRequest(), {
    ...(opts.keyId !== undefined ? { keyId: opts.keyId } : {}),
    alg: "ed25519",
    key: kp.privateKey,
    created: CREATED,
    ...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
    ...(opts.tag !== undefined ? { tag: opts.tag } : {}),
    ...(opts.coveredComponents !== undefined
      ? { coveredComponents: opts.coveredComponents }
      : {}),
  });
  return { ...kp, signed };
}

// --- Sign-side caps: over the limit fails fast, input untouched. ---

test("over-long tag is rejected and the input request is untouched", () => {
  assert.equal(MAX_TAG_LENGTH, 256);
  const req = paymentRequest();
  const before = JSON.stringify(req);
  assert.throws(
    () => signEd({ tag: "t".repeat(MAX_TAG_LENGTH + 1), req }),
    /signRequest: "tag" must be at most 256 characters, got 257/,
  );
  assert.equal(JSON.stringify(req), before);
});

test("over-long nonce is rejected and the input request is untouched", () => {
  assert.equal(MAX_NONCE_LENGTH, 256);
  const req = paymentRequest();
  const before = JSON.stringify(req);
  assert.throws(
    () =>
      signRequest(req, {
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
        nonce: "n".repeat(MAX_NONCE_LENGTH + 1),
      }),
    /signRequest: "nonce" must be at most 256 characters, got 257/,
  );
  assert.equal(JSON.stringify(req), before);
});

test("over-long keyId is rejected and the input request is untouched", () => {
  assert.equal(MAX_KEY_ID_LENGTH, 256);
  const req = paymentRequest();
  const before = JSON.stringify(req);
  assert.throws(
    () =>
      signRequest(req, {
        keyId: "k".repeat(MAX_KEY_ID_LENGTH + 1),
        alg: "ed25519",
        key: generateEd25519KeyPair().privateKey,
        created: CREATED,
      }),
    /signRequest: "keyId" must be at most 256 characters, got 257/,
  );
  assert.equal(JSON.stringify(req), before);
});

// --- At the limit: all three round-trip through verifyRequest. ---

test("a 256-character tag signs and verifies (at the limit)", () => {
  const tag = "t".repeat(MAX_TAG_LENGTH);
  const { publicKey, signed } = signEd({ tag });
  assert.match(signed.headers["signature-input"], new RegExp(`;tag="${tag}"`));
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.tag, tag);
});

test("a 256-character nonce signs and verifies (at the limit)", () => {
  const nonce = "n".repeat(MAX_NONCE_LENGTH);
  const { publicKey, signed } = signEd({ nonce });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, nonce);
});

test("a 256-character keyId signs and verifies via keyResolver (at the limit)", () => {
  const keyId = "k".repeat(MAX_KEY_ID_LENGTH);
  const { publicKey, signed } = signEd({ keyId });
  const res = verifyRequest(signed, {
    keyResolver: (kid) => (kid === keyId ? publicKey : undefined),
    now: NOW,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, keyId);
});

// --- Covered-components count: same bound as the verify-side parser. ---

test("65 covered components are rejected with the parser's wording", () => {
  assert.equal(MAX_COVERED_COMPONENTS, 64);
  const covered = Array.from({ length: 65 }, (_, i) => `x-h-${String(i).padStart(2, "0")}`);
  assert.throws(
    () => signEd({ coveredComponents: covered }),
    /signRequest: too many covered components: 65 \(max 64\)/,
  );
});

test("64 covered components sign and verify (at the limit)", () => {
  const headers: Record<string, string> = {};
  const covered = [...COVERED];
  for (let i = 0; i < 61; i++) {
    const name = `x-h-${String(i).padStart(2, "0")}`;
    headers[name] = `v${i}`;
    covered.push(name);
  }
  assert.equal(covered.length, 64);
  const { publicKey, signed } = signEd({
    coveredComponents: covered,
    req: { method: "POST", url: URL, headers },
  });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, covered);
});

// --- The new guards never steal an older error. ---

test("known alg + wrong key still reports the old key-shape wording", () => {
  assert.throws(
    () =>
      signRequest(paymentRequest(), {
        alg: "ed25519",
        key: secretKey("wrong-key-shape-secret-32-bytes-0"),
        created: CREATED,
      }),
    /signRequest: alg "ed25519" is incompatible with the key/,
  );
});

// --- addSignature inherits the guards through signRequest. ---

test("addSignature inherits the tag cap for the appended signature", () => {
  const { signed } = signEd({});
  assert.throws(
    () =>
      addSignature(signed, {
        label: "sig2",
        alg: "hmac-sha256",
        key: secretKey("gateway-shared-secret-32-bytes-0!"),
        created: CREATED,
        tag: "t".repeat(MAX_TAG_LENGTH + 1),
      }),
    /signRequest: "tag" must be at most 256 characters, got 257/,
  );
});

// --- Verify-side ruling: no per-field cap on the wire (RFC 9421 sets
// none); the 64 KiB signature-input cap bounds total header size.
// These signatures are hand-minted with node:crypto because our own
// signer now refuses to mint them. ---

function handMintedSigned(params: {
  tag?: string;
  nonce?: string;
  keyid?: string;
}) {
  const kp = generateEd25519KeyPair();
  const req = paymentRequest();
  const fullParams = { created: CREATED, alg: "ed25519", ...params };
  const base = buildSignatureBase(COVERED, req, fullParams);
  const sig = edSign(null, Buffer.from(base, "utf8"), kp.privateKey);
  const signed = {
    ...req,
    headers: {
      ...req.headers,
      "signature-input": signatureInputValue("sig1", COVERED, fullParams),
      signature: `sig1=:${sig.toString("base64")}:`,
    },
  };
  return { ...kp, signed };
}

test("verify accepts a hand-minted 300-character tag (no verify-side cap)", () => {
  const tag = "t".repeat(300);
  const { publicKey, signed } = handMintedSigned({ tag });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.tag, tag);
});

test("verify accepts a hand-minted 300-character nonce (no verify-side cap)", () => {
  const nonce = "n".repeat(300);
  const { publicKey, signed } = handMintedSigned({ nonce });
  const res = verifyRequest(signed, { key: publicKey, now: NOW });
  assert.equal(res.ok, true);
  assert.equal(res.nonce, nonce);
});

test("verify accepts a hand-minted 300-character keyId via keyResolver (no verify-side cap)", () => {
  const keyid = "k".repeat(300);
  const { publicKey, signed } = handMintedSigned({ keyid });
  const res = verifyRequest(signed, {
    keyResolver: (kid) => (kid === keyid ? publicKey : undefined),
    now: NOW,
  });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, keyid);
});
