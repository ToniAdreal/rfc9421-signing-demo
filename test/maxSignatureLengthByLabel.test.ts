import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  isVerifyError,
  signRequest,
  verifyAllLabels,
  verifyAllLabelsOrThrow,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

// Backlog #1312: `VerifyAllOptions.maxSignatureLengthByLabel` had only
// configuration-validation tests (a non-integer limit throws, in
// `test/verifyHeaderLimits.test.ts`) — no behavior-level test pinned
// whether a per-label `signature`-value length limit really rejects
// only its own label. The `maxSignatureInputLengthByLabel` twin
// already has that behavior test in the same file; the signature-value
// limit was the unpinned mirror.
//
// A separate file (rather than appending to `verifyHeaderLimits.test.ts`,
// already 433 lines covering the global limits plus the input-length
// per-label mirror) keeps this per-label behavior cohesive, matching
// the repo's focused-file convention (`candidateKeysByLabel.test.ts`,
// `jwksEcCurves.test.ts`).
//
// One correction to the backlog sketch: the limit is measured against
// the whole shared `signature` header, not against one label's base64
// value — `verifyAllLabels` hands each label's mapped limit to
// `verifyRequest` as that label's `maxSignatureLength`, and
// `checkSignatureHeaderLengths` measures the shared header
// (`src/verify.ts`, same as the global limit; backlog #1309/#1311
// already pinned the shared-header reading in the demo and the bench).
// Every test below therefore computes the shared header's byte length
// at runtime and never hardcodes it.

const CREATED = 1700000000;
const NOW = CREATED + 60;

function dualSignedEd(): {
  signed: SignedHttpRequest;
  publicKey: ReturnType<typeof generateEd25519KeyPair>["publicKey"];
} {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: {},
      body: '{"amount":100}',
    },
    {
      keyId: "k",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
    },
  );
  // Both labels share one key pair (different keyIds): the test is
  // about length limits, not key separation, so a single `key` must
  // verify both labels.
  const dual = addSignature(signed, {
    keyId: "gw",
    alg: "ed25519",
    key: privateKey,
    created: CREATED,
    label: "sig2",
  });
  return { signed: dual, publicKey };
}

function sharedSignatureBytes(signed: SignedHttpRequest): number {
  return Buffer.byteLength(signed.headers["signature"] as string, "utf8");
}

test("verifyAllLabels: a tight per-label limit rejects only its label", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  assert.ok(sigBytes > 50, `fixture signature header is ${sigBytes} bytes`);
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLengthByLabel: { sig1: 50 },
  });
  assert.equal(results.length, 2);
  assert.equal(results[0]?.label, "sig1");
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "SIGNATURE_TOO_LARGE");
  // The reason names the per-label limit and the shared header length
  // it was measured against.
  assert.match(results[0]?.reason ?? "", /maxSignatureLength=50/);
  assert.match(results[0]?.reason ?? "", new RegExp(`${sigBytes} bytes`));
  assert.equal(results[1]?.label, "sig2");
  assert.equal(results[1]?.ok, true);
});

test("verifyAllLabels: a per-label limit exactly equal to the shared header length passes both labels", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLengthByLabel: { sig1: sigBytes },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["sig1", true],
      ["sig2", true],
    ],
  );
});

test("verifyAllLabels: an unmapped label falls back to the global limit", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  // sig1 is pinned tight, sig2 has no entry: it falls back to the
  // global `maxSignatureLength`, set here to exactly the shared header
  // length, so it verifies at the boundary. Note the pre-parse gate in
  // `verifyAllLabels` enforces the global limit before the header is
  // split into labels, so a global limit below the header length can
  // never reach the per-label delegation — the boundary case is the
  // observable fallback assertion; the `?? opts.maxSignatureLength`
  // fallback itself lives at `src/verify.ts` in the delegation loop.
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLength: sigBytes,
    maxSignatureLengthByLabel: { sig1: 50 },
  });
  assert.equal(results[0]?.label, "sig1");
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "SIGNATURE_TOO_LARGE");
  assert.equal(results[1]?.label, "sig2");
  assert.equal(results[1]?.ok, true);
});

test("verifyAllLabels: a global limit below the shared header fires the pre-parse gate as one synthetic result", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLength: sigBytes - 1,
  });
  // The header is never split into labels: one synthetic result, same
  // shape as the unparseable-header case (label "").
  assert.equal(results.length, 1);
  assert.equal(results[0]?.label, "");
  assert.equal(results[0]?.ok, false);
  assert.equal(results[0]?.code, "SIGNATURE_TOO_LARGE");
  assert.match(
    results[0]?.reason ?? "",
    new RegExp(`maxSignatureLength=${sigBytes - 1}`),
  );
});

test("verifyAllLabels: two mapped labels are checked independently", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLengthByLabel: { sig1: 50, sig2: sigBytes },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok, r.code]),
    [
      ["sig1", false, "SIGNATURE_TOO_LARGE"],
      ["sig2", true, undefined],
    ],
  );
});

test("verifyAllLabels: a map entry for a label absent from the wire is inert", () => {
  const { signed, publicKey } = dualSignedEd();
  const results = verifyAllLabels(signed, {
    key: publicKey,
    now: NOW,
    maxSignatureLengthByLabel: { nosuch: 1 },
  });
  assert.deepEqual(
    results.map((r) => [r.label, r.ok]),
    [
      ["sig1", true],
      ["sig2", true],
    ],
  );
});

test("verifyAllLabels: invalid per-label limits throw a configuration error", () => {
  const { signed, publicKey } = dualSignedEd();
  for (const bad of [0, -1, 1.5, Number.NaN, "100"]) {
    assert.throws(
      () =>
        verifyAllLabels(signed, {
          key: publicKey,
          now: NOW,
          maxSignatureLengthByLabel: { sig1: bad as never },
        }),
      /maxSignatureLengthByLabel\["sig1"\]/,
    );
  }
  assert.throws(
    () =>
      verifyAllLabels(signed, {
        key: publicKey,
        now: NOW,
        maxSignatureLengthByLabel: 50 as never,
      }),
    /maxSignatureLengthByLabel.*must be a label→limit object/,
  );
});

test("verifyRequest: a single label's limit is the global limit for that label", () => {
  const { signed, publicKey } = dualSignedEd();
  const sigBytes = sharedSignatureBytes(signed);
  // This is the call `verifyAllLabels` makes per label: the mapped
  // limit arrives as `maxSignatureLength`. Pin the equivalence here so
  // the delegation cannot silently drift from it.
  assert.equal(
    verifyRequest(signed, {
      key: publicKey,
      now: NOW,
      label: "sig2",
      maxSignatureLength: sigBytes,
    }).ok,
    true,
  );
  const res = verifyRequest(signed, {
    key: publicKey,
    now: NOW,
    label: "sig2",
    maxSignatureLength: sigBytes - 1,
  });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_TOO_LARGE");
  assert.match(
    res.reason ?? "",
    new RegExp(`maxSignatureLength=${sigBytes - 1}`),
  );
});

test("verifyAllLabelsOrThrow: an over-limit label throws with the full verifyResults attached", () => {
  const { signed, publicKey } = dualSignedEd();
  let caught: unknown;
  try {
    verifyAllLabelsOrThrow(signed, {
      key: publicKey,
      now: NOW,
      maxSignatureLengthByLabel: { sig1: 50 },
    });
    assert.fail("expected a throw");
  } catch (e) {
    caught = e;
  }
  assert.equal(isVerifyError(caught), true);
  const err = caught as {
    code: string;
    label: string;
    verifyResults?: { label: string; ok: boolean; code?: string }[];
  };
  assert.equal(err.code, "SIGNATURE_TOO_LARGE");
  assert.equal(err.label, "sig1");
  assert.ok(err.verifyResults !== undefined);
  assert.equal(err.verifyResults?.length, 2);
  assert.deepEqual(
    err.verifyResults?.map((r) => [r.label, r.ok, r.code]),
    [
      ["sig1", false, "SIGNATURE_TOO_LARGE"],
      ["sig2", true, undefined],
    ],
  );
  // The attached array is a detached copy: mutating it must not
  // change a later verification of the same request.
  err.verifyResults?.push({ label: "sig1", ok: true });
  assert.deepEqual(
    verifyAllLabels(signed, {
      key: publicKey,
      now: NOW,
      maxSignatureLengthByLabel: { sig1: 50 },
    }).map((r) => [r.label, r.ok]),
    [
      ["sig1", false],
      ["sig2", true],
    ],
  );
});
