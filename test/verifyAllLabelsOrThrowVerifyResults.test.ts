import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair, isVerifyError,
  signRequest, verifyAllLabels, verifyAllLabelsOrThrow,
  VerifyError, type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

function base(body?: string) {
  return { method: "POST", url: "https://api.example.com/v1/payments", headers: { "content-type": "application/json" }, body };
}
function merge(a: SignedHttpRequest, b: SignedHttpRequest): SignedHttpRequest {
  return { ...a, headers: { ...a.headers, "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`, signature: `${a.headers["signature"]}, ${b.headers["signature"]}` } };
}
function tamper(req: SignedHttpRequest, label: string): SignedHttpRequest {
  const rx = new RegExp(`((?:^|,)\\s*${label}\\s*=:)([A-Za-z0-9+/])`);
  const sig = req.headers["signature"].replace(rx, (_m, p, ch) => `${p}${ch === "A" ? "B" : "A"}`);
  assert.notEqual(sig, req.headers["signature"]);
  return { ...req, headers: { ...req.headers, signature: sig } };
}

const { publicKey, privateKey } = generateEd25519KeyPair();
const body = JSON.stringify({ amount: 100 });
const merchant = signRequest(base(body), { keyId: "merchant-key", alg: "ed25519", key: privateKey, created: CREATED, label: "merchant" });
const gateway = signRequest(base(body), { keyId: "gateway-key", alg: "ed25519", key: privateKey, created: CREATED, label: "gateway" });
const dual = merge(merchant, gateway);

test("req throw attaches verifyResults with both entries in wire order, bad label matches error", () => {
  const bad = tamper(dual, "gateway"); // gateway bad, merchant good
  assert.throws(() => verifyAllLabelsOrThrow(bad, { key: publicKey, now: NOW }), (e: unknown) => {
    assert.ok(e instanceof VerifyError); assert.ok(isVerifyError(e));
    assert.equal(e.label, "gateway"); assert.equal(e.code, "SIGNATURE_MISMATCH");
    assert.ok(Array.isArray(e.verifyResults)); assert.equal(e.verifyResults!.length, 2);
    assert.equal(e.verifyResults![0].label, "merchant"); assert.equal(e.verifyResults![0].ok, true);
    assert.equal(e.verifyResults![1].label, "gateway"); assert.equal(e.verifyResults![1].ok, false);
    return true;
  });
});

test("attached array is a detached copy: mutating it does not affect a fresh verification", () => {
  const bad = tamper(dual, "gateway");
  let attached: any = null;
  assert.throws(() => verifyAllLabelsOrThrow(bad, { key: publicKey, now: NOW }), (e: unknown) => {
    attached = (e as VerifyError).verifyResults!;
    attached.push({ label: "fake", ok: true, code: "OK", reason: "", keyId: "", alg: "", nonce: "", tag: "", created: 0, expires: 0, coveredComponents: [] });
    return true;
  });
  const fresh = verifyAllLabels(bad, { key: publicKey, now: NOW });
  assert.equal(fresh.length, 2); // unchanged by the mutation
});

test("success path returns results unchanged (no throw)", () => {
  const res = verifyAllLabelsOrThrow(dual, { key: publicKey, now: NOW });
  assert.equal(res.length, 2);
  assert.equal(res[0].label, "merchant"); assert.equal(res[0].ok, true);
  assert.equal(res[1].label, "gateway"); assert.equal(res[1].ok, true);
});

test("requiredLabels synthetic failure appears in thrown verifyResults", () => {
  // merchant signed; request missing gateway label but required
  const onlyMerchant = merchant;
  assert.throws(() => verifyAllLabelsOrThrow(onlyMerchant, { key: publicKey, now: NOW, requiredLabels: ["merchant", "gateway"] }), (e: unknown) => {
    assert.ok(e instanceof VerifyError);
    assert.equal(e.code, "MISSING_REQUIRED_LABEL");
    const arr = (e as VerifyError).verifyResults!;
    assert.equal(arr.length, 2);
    assert.equal(arr[0].label, "merchant"); assert.equal(arr[0].ok, true);
    assert.equal(arr[1].label, "gateway"); assert.equal(arr[1].ok, false); assert.equal(arr[1].code, "MISSING_REQUIRED_LABEL");
    return true;
  });
});

test("unsigned request returns [] without throwing", () => {
  const r = verifyAllLabelsOrThrow(base(), { key: publicKey, now: NOW });
  assert.deepEqual(r, []);
});

test("single label failure carry verifyResults as single-entry array", () => {
  const bad = tamper(merchant, "merchant");
  assert.throws(() => verifyAllLabelsOrThrow(bad, { key: publicKey, now: NOW }), (e: unknown) => {
    assert.ok(e instanceof VerifyError);
    const arr = (e as VerifyError).verifyResults!;
    assert.equal(arr.length, 1);
    assert.equal(arr[0].label, "merchant"); assert.equal(arr[0].ok, false);
    return true;
  });
});

test("first failing label wins with both failures in verifyResults order", () => {
  const expired = signRequest(base(body), { keyId: "merchant-key", alg: "ed25519", key: privateKey, created: CREATED, expires: CREATED + 10, label: "merchant" });
  const badGateway = tamper(gateway, "gateway");
  const bothBad = merge(expired, badGateway); // merchant expired (first), gateway bad
  assert.throws(() => verifyAllLabelsOrThrow(bothBad, { key: publicKey, now: NOW }), (e: unknown) => {
    assert.ok(e instanceof VerifyError);
    assert.equal(e.code, "EXPIRED");
    assert.equal(e.label, "merchant");
    const arr = (e as VerifyError).verifyResults!;
    assert.equal(arr.length, 2);
    assert.equal(arr[0].code, "EXPIRED");
    assert.equal(arr[1].code, "SIGNATURE_MISMATCH");
    return true;
  });
});

test("mutating a verifyAllLabels return does not affect a later thrown verifyResults", () => {
  const bad = tamper(dual, "gateway");
  const returned = verifyAllLabels(bad, { key: publicKey, now: NOW });
  assert.equal(returned.length, 2);
  returned.length = 0; // caller mutates the array it was handed
  assert.throws(() => verifyAllLabelsOrThrow(bad, { key: publicKey, now: NOW }), (e: unknown) => {
    assert.ok(e instanceof VerifyError);
    const arr = (e as VerifyError).verifyResults!;
    assert.equal(arr.length, 2);
    assert.equal(arr[0].label, "merchant");
    assert.equal(arr[1].label, "gateway");
    return true;
  });
});

