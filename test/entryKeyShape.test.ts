import test from "node:test";
import assert from "node:assert/strict";
import {
  generateHmacSecret,
  secretKey,
  signRequest,
  signResponse,
  verifyAllLabels,
  verifyAllResponseLabels,
  verifyRequest,
  verifyResponse,
  type HttpResponseLike,
  type RequestLike,
} from "../src/index.js";

// Backlog #1382: the six sign/verify entry points dereferenced a
// `null` `key` with no guard — the sign side read `key.type` through
// the alg/key-shape helpers, the verify side read
// `key.symmetricKeySize` in `assertHmacSecretLength` — so a caller
// passing an unassigned variable got a bare `TypeError` instead of
// the library's named configuration error. The two shared choke
// points now reject it first: `signRequestCore` (inherited by
// `signResponse`) and `assertKeyConfig` (inherited by
// `verifyAllLabels`, `verifyResponse`, and
// `verifyAllResponseLabels` through `verifyRequest` delegation).
// These tests pin the exact wording, the plain-`Error` (never
// `TypeError`) shape, and the untouched wire contract: a malformed
// signature is still a `{ ok: false, code }` result, never a throw
// (backlog #31), and a non-KeyObject `key` keeps its existing error.

const CREATED = 1700000000;
const NOW = CREATED + 60;

const key = secretKey(generateHmacSecret());
const req: RequestLike = {
  method: "GET",
  url: "https://api.example.com/v1",
  headers: {},
};
const signed = signRequest(req, { key, alg: "hmac-sha256", created: CREATED });
const res: HttpResponseLike = { status: 200, headers: {} };
const signedRes = signResponse(res, {
  key,
  alg: "hmac-sha256",
  created: CREATED,
  request: signed,
});

function assertNamedKeyError(fn: () => unknown, caller: string): void {
  assert.throws(
    fn,
    (e: unknown) => {
      assert.ok(e instanceof Error, "expected an Error");
      assert.ok(
        !(e instanceof TypeError),
        `expected a plain Error, got TypeError: ${(e as Error).message}`,
      );
      assert.match(
        (e as Error).message,
        new RegExp(
          `^${caller}: \`key\` must be a KeyObject, got null$`,
        ),
      );
      return true;
    },
  );
}

test("signRequest rejects key: null with a named error", () => {
  assertNamedKeyError(
    () => signRequest(req, { key: null as never, alg: "hmac-sha256" }),
    "signRequest",
  );
});

test("signResponse rejects key: null with a named error", () => {
  assertNamedKeyError(
    () =>
      signResponse(res, {
        key: null as never,
        alg: "hmac-sha256",
        request: signed,
      }),
    "signRequest",
  );
});

test("verifyRequest rejects key: null with a named error", () => {
  assertNamedKeyError(
    () => verifyRequest(signed, { key: null as never, now: NOW }),
    "verifyRequest",
  );
});

test("verifyAllLabels rejects key: null with a named error", () => {
  assertNamedKeyError(
    () => verifyAllLabels(signed, { key: null as never, now: NOW }),
    "verifyRequest",
  );
});

test("verifyResponse rejects key: null with a named error", () => {
  assertNamedKeyError(
    () => verifyResponse(signedRes, { key: null as never, now: NOW }),
    "verifyRequest",
  );
});

test("verifyAllResponseLabels rejects key: null with a named error", () => {
  assertNamedKeyError(
    () => verifyAllResponseLabels(signedRes, { key: null as never, now: NOW }),
    "verifyRequest",
  );
});

test("key: 42 keeps its existing sign-side error", () => {
  assert.throws(
    () => signRequest(req, { key: 42 as never, alg: "hmac-sha256" }),
    (e: unknown) => {
      assert.ok(e instanceof Error && !(e instanceof TypeError));
      assert.match(
        (e as Error).message,
        /^algMatchesKeyShape: expected a KeyObject, got number$/,
      );
      return true;
    },
  );
});

test("key: 42 keeps its existing verify-side error", () => {
  assert.throws(
    () => verifyRequest(signed, { key: 42 as never, now: NOW }),
    (e: unknown) => {
      assert.ok(e instanceof Error && !(e instanceof TypeError));
      assert.match(
        (e as Error).message,
        /^assertHmacSecretLength: expected a symmetric secret KeyObject \(see keys\.secretKey\), got a non-symmetric key$/,
      );
      return true;
    },
  );
});

test("legal request and response round-trips are unchanged", () => {
  const verified = verifyRequest(signed, { key, now: NOW });
  assert.equal(verified.ok, true);
  assert.equal(verified.alg, "hmac-sha256");
  const verifiedRes = verifyResponse(signedRes, { key, now: NOW });
  assert.equal(verifiedRes.ok, true);
  assert.equal(verifiedRes.alg, "hmac-sha256");
});

test("a malformed signature still returns { ok: false } instead of throwing", () => {
  const tampered: RequestLike = {
    ...signed,
    headers: { ...signed.headers, signature: "sig1=:AAAAAAAAAAAAAAAAAAAAAA==:" },
  };
  const result = verifyRequest(tampered, { key, now: NOW });
  assert.equal(result.ok, false);
  assert.equal(result.code, "SIGNATURE_MISMATCH");
});
