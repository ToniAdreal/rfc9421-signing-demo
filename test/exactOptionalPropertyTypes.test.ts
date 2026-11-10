import test from "node:test";
import assert from "node:assert/strict";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type RequestLike,
  type SignOptions,
  type VerifyOptions,
} from "../src/index.js";

// Backlog #1021: `exactOptionalPropertyTypes` is on. Two rules hold:
//  - message/result shapes (RequestLike, VerifyResult, ...) genuinely
//    carry undefined at runtime, so their optional fields accept an
//    explicit undefined (absent == undefined there);
//  - config options (SignOptions, VerifyOptions) do NOT accept one:
//    omitting the field is the only way to take the default, so a
//    caller that forwards a possibly-undefined value must omit it
//    (conditional spread) instead of passing it through.
// Each negative case below must fail to compile without its
// expect-error comment: if a type ever re-admits explicit undefined, tsc
// reports the directive as unused and the suite goes red.

const CREATED = 1700000000;
const { publicKey, privateKey } = generateEd25519KeyPair();

test("exactOptionalPropertyTypes: message shapes still accept explicit undefined, and omitted config optionals still sign and verify", () => {
  const req: RequestLike = {
    method: "POST",
    url: "https://api.example.com/v1/payments",
    headers: { "content-type": "application/json" },
    body: undefined,
    status: undefined,
    trailers: undefined,
    request: undefined,
    requestTarget: undefined,
  };
  const signed = signRequest(req, {
    alg: "ed25519",
    key: privateKey,
    keyId: "k",
    created: CREATED,
  });
  const res = verifyRequest(signed, { key: publicKey, now: CREATED });
  assert.equal(res.ok, true);
});

// Positive controls: omitting an optional config field still compiles.
const omittedSign: SignOptions = { alg: "ed25519", key: privateKey };
const omittedVerify: VerifyOptions = { key: publicKey };
void omittedSign;
void omittedVerify;

// Negative pins: an explicit undefined on a config option must not compile.
// @ts-expect-error SignOptions.keyId does not accept an explicit undefined
const rejectedSignKeyId: SignOptions = { alg: "ed25519", key: privateKey, keyId: undefined };
// @ts-expect-error SignOptions.nonce does not accept an explicit undefined
const rejectedSignNonce: SignOptions = { alg: "ed25519", key: privateKey, nonce: undefined };
// @ts-expect-error SignOptions.tag does not accept an explicit undefined
const rejectedSignTag: SignOptions = { alg: "ed25519", key: privateKey, tag: undefined };
// @ts-expect-error SignOptions.created does not accept an explicit undefined
const rejectedSignCreated: SignOptions = { alg: "ed25519", key: privateKey, created: undefined };
// @ts-expect-error SignOptions.expires does not accept an explicit undefined
const rejectedSignExpires: SignOptions = { alg: "ed25519", key: privateKey, expires: undefined };
// @ts-expect-error SignOptions.label does not accept an explicit undefined
const rejectedSignLabel: SignOptions = { alg: "ed25519", key: privateKey, label: undefined };
// @ts-expect-error SignOptions.coveredComponents does not accept an explicit undefined
const rejectedSignCovered: SignOptions = { alg: "ed25519", key: privateKey, coveredComponents: undefined };
// @ts-expect-error SignOptions.contentDigestAlg does not accept an explicit undefined
const rejectedSignDigestAlg: SignOptions = { alg: "ed25519", key: privateKey, contentDigestAlg: undefined };
// @ts-expect-error SignOptions.structuredFieldTypes does not accept an explicit undefined
const rejectedSignSfTypes: SignOptions = { alg: "ed25519", key: privateKey, structuredFieldTypes: undefined };
// @ts-expect-error VerifyOptions.key does not accept an explicit undefined
const rejectedVerifyKey: VerifyOptions = { key: undefined };
// @ts-expect-error VerifyOptions.expectedKeyId does not accept an explicit undefined
const rejectedVerifyExpectedKeyId: VerifyOptions = { key: publicKey, expectedKeyId: undefined };
// @ts-expect-error VerifyOptions.expectedTag does not accept an explicit undefined
const rejectedVerifyExpectedTag: VerifyOptions = { key: publicKey, expectedTag: undefined };
// @ts-expect-error VerifyOptions.replayCache does not accept an explicit undefined
const rejectedVerifyReplayCache: VerifyOptions = { key: publicKey, replayCache: undefined };
// @ts-expect-error VerifyOptions.keyResolver does not accept an explicit undefined
const rejectedVerifyKeyResolver: VerifyOptions = { keyResolver: undefined };
// @ts-expect-error VerifyOptions.requireNonce does not accept an explicit undefined
const rejectedVerifyRequireNonce: VerifyOptions = { key: publicKey, requireNonce: undefined };
void rejectedSignKeyId;
void rejectedSignNonce;
void rejectedSignTag;
void rejectedSignCreated;
void rejectedSignExpires;
void rejectedSignLabel;
void rejectedSignCovered;
void rejectedSignDigestAlg;
void rejectedSignSfTypes;
void rejectedVerifyKey;
void rejectedVerifyExpectedKeyId;
void rejectedVerifyExpectedTag;
void rejectedVerifyReplayCache;
void rejectedVerifyKeyResolver;
void rejectedVerifyRequireNonce;
