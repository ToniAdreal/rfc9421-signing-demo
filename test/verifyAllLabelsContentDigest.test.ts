import test from "node:test";
import assert from "node:assert/strict";
import { createHash, sign as edSign } from "node:crypto";
import {
  addSignature,
  buildSignatureBase,
  generateEd25519KeyPair,
  signatureInputValue,
  signRequest,
  verifyAllLabels,
  type SignatureParams,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #730: `multiLabel.test.ts` never mentions digest /
// content-digest, and the content-digest edge tests (#12) are all
// single-signature. The interesting multi-label questions are about
// interaction, not about either surface alone:
//
// - Both labels cover `content-digest` (sha-512): the original dual
//   verifies, and a body swap is reported as BODY_DIGEST_MISMATCH
//   for both labels — not masked as SIGNATURE_MISMATCH.
// - The two tamper dimensions stay distinct: swapping the body
//   (header untouched) is a digest failure, because the signature
//   base only covers the header *value*; swapping the header value
//   itself is a crypto failure, because `verify.ts` checks the
//   signature before the body binding.
// - The wire carries a single `content-digest` header, so a
//   post-hoc edit cannot tamper "only one label's" digest. The
//   per-label-divergence case is therefore built in signing
//   history: one label signed over a different body's digest, with
//   the wire header/body left at the other label's values. Only
//   that label must fail, with SIGNATURE_MISMATCH.
// - Digest-algorithm semantics are read from `src/verify.ts` and
//   `src/digest.ts`, not assumed: the verifier prefers sha-512
//   when the header carries both algorithms and falls back to
//   sha-256 only when no sha-512 entry is present. So a sha-256-only
//   dual verifies (fallback), while a both-algorithms header whose
//   sha-512 entry is of another body fails both labels with
//   BODY_DIGEST_MISMATCH even though its sha-256 entry matches.
// - The body check in `verify.ts` runs whenever a content-digest
//   header is present, regardless of whether a label's covered
//   list includes `content-digest` — so a non-covering label is
//   still body-bound by the wire digest. That is pinned here
//   rather than assumed away.
//
// Pure test addition: no source change, since the combination was
// untested, not unimplemented.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const URL = "https://api.example.com/v1/payments";
const BODY_A = '{"amount":100}';
const BODY_B = '{"amount":1}';

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();

function baseRequest(body: string) {
  return {
    method: "POST",
    url: URL,
    headers: { "content-type": "application/json" },
    body,
  };
}

function mergeSignatures(
  a: SignedHttpRequest,
  b: SignedHttpRequest,
): SignedHttpRequest {
  return {
    ...a,
    headers: {
      ...a.headers,
      "signature-input": `${a.headers["signature-input"]}, ${b.headers["signature-input"]}`,
      signature: `${a.headers["signature"]}, ${b.headers["signature"]}`,
    },
  };
}

function keys() {
  return { merchant: merchant.publicKey, gateway: gateway.publicKey };
}

function digestOf(body: string, alg: "sha-256" | "sha-512"): string {
  const nodeAlg = alg === "sha-256" ? "sha256" : "sha512";
  return `${alg}=:${createHash(nodeAlg).update(Buffer.from(body, "utf8")).digest("base64")}:`;
}

/** Sign one label by hand over an exact Content-Digest header value. */
function manualLabel(
  pair: ReturnType<typeof generateEd25519KeyPair>,
  label: string,
  digestHeader: string,
  body: string,
): SignedHttpRequest {
  const headers: Record<string, string> = { "content-digest": digestHeader };
  const covered = ["@method", "@authority", "@path", "content-digest"];
  const params: SignatureParams = {
    created: CREATED,
    keyid: label,
    alg: "ed25519",
  };
  const req = { method: "POST", url: URL, headers, body };
  const base = buildSignatureBase(covered, req, params);
  const sig = edSign(null, Buffer.from(base, "utf8"), pair.privateKey);
  headers["signature-input"] = signatureInputValue(label, covered, params);
  headers["signature"] = `${label}=:${sig.toString("base64")}:`;
  return { method: "POST", url: URL, headers, body };
}

function dualSha512(body: string = BODY_A) {
  return mergeSignatures(
    signRequest(baseRequest(body), {
      label: "merchant",
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
    }),
    signRequest(baseRequest(body), {
      label: "gateway",
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
    }),
  );
}

test("verifyAllLabels x content-digest: dual sha-512 labels both cover the digest and both verify", () => {
  const results = verifyAllLabels(dualSha512(), { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  assert.deepEqual(
    results.map((r) => r.label),
    ["merchant", "gateway"],
  );
  for (const r of results) {
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.ok(
      r.coveredComponents?.includes("content-digest"),
      `${r.label} must cover content-digest`,
    );
  }
  assert.equal(results[0].keyId, "merchant-key");
  assert.equal(results[1].keyId, "gateway-key");
});

test("verifyAllLabels x content-digest: body swapped after signing fails both labels as BODY_DIGEST_MISMATCH", () => {
  const swapped = { ...dualSha512(), body: BODY_B };
  const results = verifyAllLabels(swapped, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  for (const r of results) {
    // The header value is untouched, so crypto still passes and the
    // verifier's body-vs-digest check is the rejection — the digest
    // dimension must not be masked as a signature failure.
    assert.equal(r.ok, false);
    assert.equal(r.code, "BODY_DIGEST_MISMATCH");
    assert.equal(r.reason, "body does not match content-digest");
  }
});

test("verifyAllLabels x content-digest: digest header swapped to another body's digest fails both labels as SIGNATURE_MISMATCH", () => {
  const signed = dualSha512();
  const tampered: SignedHttpRequest = {
    ...signed,
    headers: {
      ...signed.headers,
      "content-digest": digestOf(BODY_B, "sha-512"),
    },
  };
  assert.notEqual(
    tampered.headers["content-digest"],
    signed.headers["content-digest"],
    "tamper must actually change the header",
  );
  const results = verifyAllLabels(tampered, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  for (const r of results) {
    // The header value is part of both signature bases, so the
    // crypto check (which runs before the body binding) rejects
    // both labels before any digest comparison is reached.
    assert.equal(r.ok, false);
    assert.equal(r.code, "SIGNATURE_MISMATCH");
    assert.equal(r.reason, "signature mismatch");
  }
});

test("verifyAllLabels x content-digest: a label signed over a different digest fails alone, the other label still verifies", () => {
  // The wire header is shared, so per-label divergence can only
  // come from signing history: the gateway label is minted over
  // BODY_B's digest while the wire carries BODY_A's digest/body.
  const divergent = mergeSignatures(
    signRequest(baseRequest(BODY_A), {
      label: "merchant",
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
    }),
    signRequest(baseRequest(BODY_B), {
      label: "gateway",
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
    }),
  );
  const results = verifyAllLabels(divergent, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  assert.equal(results[0].label, "merchant");
  assert.equal(results[0].ok, true, JSON.stringify(results[0]));
  assert.equal(results[1].label, "gateway");
  assert.equal(results[1].ok, false);
  assert.equal(results[1].code, "SIGNATURE_MISMATCH");
});

test("verifyAllLabels x content-digest: sha-256-only dual verifies via the sha-256 fallback", () => {
  const dual = mergeSignatures(
    signRequest(baseRequest(BODY_A), {
      label: "merchant",
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      contentDigestAlg: "sha-256",
    }),
    signRequest(baseRequest(BODY_A), {
      label: "gateway",
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      contentDigestAlg: "sha-256",
    }),
  );
  assert.ok(
    dual.headers["content-digest"]?.startsWith("sha-256="),
    "both labels must emit the sha-256 line",
  );
  const results = verifyAllLabels(dual, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
});

test("verifyAllLabels x content-digest: sha-512 of another body wins over a matching sha-256 entry, both labels fail", () => {
  // Header offers a sha-256 of the true body and a sha-512 of
  // another body; the verifier must check against sha-512, so
  // both labels report the digest mismatch even though the
  // sha-256 entry matches.
  const header = `${digestOf(BODY_A, "sha-256")}, ${digestOf(BODY_B, "sha-512")}`;
  const dual = mergeSignatures(
    manualLabel(merchant, "merchant", header, BODY_A),
    manualLabel(gateway, "gateway", header, BODY_A),
  );
  const results = verifyAllLabels(dual, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  for (const r of results) {
    assert.equal(r.ok, false);
    assert.equal(r.code, "BODY_DIGEST_MISMATCH");
    assert.equal(r.reason, "body does not match content-digest");
  }
});

test("verifyAllLabels x content-digest: addSignature-appended second label covers the same wire digest and both verify", () => {
  const first = signRequest(baseRequest(BODY_A), {
    label: "merchant",
    keyId: "merchant-key",
    alg: "ed25519",
    key: merchant.privateKey,
    created: CREATED,
  });
  const appended = addSignature(first, {
    label: "gateway",
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
  });
  // The appended signature must not mint a second digest header:
  // the wire value stays the merchant's original sha-512 line.
  assert.equal(
    appended.headers["content-digest"],
    first.headers["content-digest"],
  );
  const results = verifyAllLabels(appended, { now: NOW, keys: keys() });
  assert.equal(results.length, 2);
  for (const r of results) assert.equal(r.ok, true, JSON.stringify(r));
});

test("verifyAllLabels x content-digest: a label not covering content-digest is still body-bound by the wire digest", () => {
  const mixed = mergeSignatures(
    signRequest(baseRequest(BODY_A), {
      label: "merchant",
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
    }),
    signRequest(baseRequest(BODY_A), {
      label: "gateway",
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      coveredComponents: ["@method", "@authority", "@path"],
    }),
  );
  const intact = verifyAllLabels(mixed, { now: NOW, keys: keys() });
  assert.equal(intact[0].ok, true);
  assert.equal(intact[1].ok, true);
  assert.ok(!intact[1].coveredComponents?.includes("content-digest"));
  // `verify.ts` checks the body against the wire digest whenever
  // the header is present, regardless of a label's covered list —
  // so the non-covering label fails on a body swap too.
  const swapped = verifyAllLabels(
    { ...mixed, body: BODY_B },
    { now: NOW, keys: keys() },
  );
  assert.equal(swapped[0].code, "BODY_DIGEST_MISMATCH");
  assert.equal(swapped[1].code, "BODY_DIGEST_MISMATCH");
});
