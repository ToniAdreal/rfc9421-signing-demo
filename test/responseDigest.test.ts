import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  addResponseSignature,
  digest,
  generateEd25519KeyPair,
  signResponse,
  verifyAllResponseLabels,
  verifyResponse,
  type SignedHttpResponse,
} from "../src/index.js";

// Response-side twin of test/digest.test.ts (backlog #1100, request
// side). The binding itself lives in the shared verify path
// (`verifyResponse` delegates to `verifyRequest`), so these tests pin
// that the delegation actually enforces the legacy RFC 3230 `Digest`
// body binding for responses — a regression here would let a swapped
// settlement body verify against a legacy gateway's signature. The
// probe that motivated this file verified the behaviour first (every
// case below was observed live before being written down); nothing
// here asserts a code path that was only assumed to exist.

const CREATED = 1700000000;
const BODY = '{"status":"settled","amount":100,"currency":"USD"}';
const { publicKey, privateKey } = generateEd25519KeyPair();

/** Sign a response whose Digest header we control exactly. */
function signedWithDigestHeader(
  body: string | Buffer | undefined,
  digestHeader: string,
  covered: string[] = ["@status", "digest"],
): SignedHttpResponse {
  return signResponse(
    { status: 200, headers: { digest: digestHeader }, body },
    {
      key: privateKey,
      keyId: "gw",
      alg: "ed25519",
      coveredComponents: covered,
      created: CREATED,
    },
  );
}

function verify(signed: SignedHttpResponse) {
  return verifyResponse(signed, { key: publicKey, now: CREATED + 60 });
}

test("response sha-256 Digest round-trip verifies", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const res = verify(signed);
  assert.equal(res.ok, true);
  assert.deepEqual(res.coveredComponents, ["@status", "digest"]);
});

test("response sha-512 Digest round-trip verifies", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-512"));
  assert.equal(verify(signed).ok, true);
});

test("response body swapped under a covered Digest: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const res = verify({ ...signed, body: '{"status":"settled","amount":999,"currency":"USD"}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.match(res.reason ?? "", /body does not match Digest/);
});

test("response Digest value signed over a different body: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(
    BODY,
    digest('{"status":"settled","amount":1,"currency":"USD"}', "sha-256"),
  );
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("Digest + Content-Digest dual coverage, body swapped: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-512"), [
    "@status",
    "content-digest",
    "digest",
  ]);
  assert.equal(verify(signed).ok, true);
  const res = verify({ ...signed, body: '{"status":"voided"}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("response Digest covered but the header is missing: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"));
  const headersWithoutDigest: Record<string, string> = {};
  for (const [k, v] of Object.entries(signed.headers))
    if (k !== "digest") headersWithoutDigest[k] = v;
  const res = verify({ ...signed, headers: headersWithoutDigest });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.match(res.reason ?? "", /no Digest header is present/);
});

test("response md5 Digest fails closed: BODY_DIGEST_MISMATCH", () => {
  const md5 = `md5=:${createHash("md5").update(Buffer.from(BODY, "utf8")).digest("base64")}:`;
  const signed = signedWithDigestHeader(BODY, md5);
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
  assert.match(res.reason ?? "", /md5/);
});

test("response unknown Digest algorithm fails closed: BODY_DIGEST_MISMATCH", () => {
  const signed = signedWithDigestHeader(
    BODY,
    `sha-999=:${Buffer.from("nonsense").toString("base64")}:`,
  );
  const res = verify(signed);
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("response Digest present but not covered: no binding check, body swap verifies", () => {
  // The Digest check only runs when `digest` is covered. An uncovered
  // Digest header is opaque data the signature does not bind — the
  // same rule as the request side (test/digest.test.ts).
  const signed = signedWithDigestHeader(
    BODY,
    digest('{"status":"settled","amount":1,"currency":"USD"}', "sha-256"),
    ["@status"],
  );
  assert.equal(verify(signed).ok, true);
  const swapped = verify({
    ...signed,
    body: '{"status":"settled","amount":999,"currency":"USD"}',
  });
  assert.equal(swapped.ok, true);
});

test("response Digest with both algorithms prefers sha-512", () => {
  const header =
    `sha-512=${digest(BODY, "sha-512").slice("sha-512=".length)}, ` +
    `sha-256=:${Buffer.from("wrong").toString("base64")}:`;
  const signed = signedWithDigestHeader(BODY, header);
  assert.equal(verify(signed).ok, true);
});

test("response Digest covered with ;bs still binds the body", () => {
  const signed = signedWithDigestHeader(BODY, digest(BODY, "sha-256"), [
    "@status",
    "digest;bs",
  ]);
  assert.equal(verify(signed).ok, true);
  const res = verify({ ...signed, body: '{"status":"settled","amount":999,"currency":"USD"}' });
  assert.equal(res.ok, false);
  assert.equal(res.code, "BODY_DIGEST_MISMATCH");
});

test("verifyAllResponseLabels: a Digest-covered label fails alone, the other label still passes", () => {
  const merchant = generateEd25519KeyPair();
  const gateway = generateEd25519KeyPair();
  const first = signResponse(
    { status: 200, headers: { digest: digest(BODY, "sha-256") }, body: BODY },
    {
      key: merchant.privateKey,
      keyId: "merchant",
      alg: "ed25519",
      coveredComponents: ["@status"],
      created: CREATED,
      label: "merchant",
    },
  );
  const dual = addResponseSignature(first, {
    key: gateway.privateKey,
    keyId: "gateway",
    alg: "ed25519",
    coveredComponents: ["@status", "digest"],
    created: CREATED,
    label: "gateway",
  });
  const tampered = { ...dual, body: '{"status":"settled","amount":999,"currency":"USD"}' };
  const results = verifyAllResponseLabels(tampered, {
    keys: { merchant: merchant.publicKey, gateway: gateway.publicKey },
    now: CREATED + 60,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.label, "merchant");
  assert.equal(results[0]?.ok, true);
  assert.equal(results[1]?.label, "gateway");
  assert.equal(results[1]?.ok, false);
  assert.equal(results[1]?.code, "BODY_DIGEST_MISMATCH");
});
