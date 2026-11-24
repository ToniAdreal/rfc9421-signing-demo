import test from "node:test";
import assert from "node:assert/strict";
import { secretKey, signRequest, verifyRequest } from "../src/index.js";

// Backlog #1372: `secretKey` took its bytes before any type check —
// `secretKey(null)` escaped as a bare `TypeError` (`reading 'length'`),
// and `secretKey(42)` / `secretKey({})` escaped as node:crypto
// `TypeError`s from `createSecretKey`, never as a library named error.
// The guard now runs first, before the 32-byte floor check, throwing a
// plain named `Error` for anything that is not a `string` or a `Buffer`.
// These cases pin the guard shapes, the guard-before-floor ordering, and
// the unchanged legal paths (32/64-byte string and Buffer secrets).

const FLOOR_MESSAGE =
  "secretKey: hmac secret must be at least 32 bytes (RFC 2104: the key SHOULD be at least as long as the hash output; sha-256 → 32 bytes)";

function expectNamedTypeError(value: unknown, got: string): void {
  assert.throws(
    () => secretKey(value as string),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        `secretKey: hmac secret must be a string or a Buffer, got ${got}`,
      );
      return true;
    },
  );
}

test("secretKey: null throws a named Error, not a bare TypeError", () => {
  expectNamedTypeError(null, "null");
});

test("secretKey: undefined throws a named Error", () => {
  expectNamedTypeError(undefined, "undefined");
});

test("secretKey: number input throws a named Error", () => {
  expectNamedTypeError(42, "number");
});

test("secretKey: plain-object input throws a named Error", () => {
  expectNamedTypeError({}, "object");
});

test("secretKey: boolean input throws a named Error", () => {
  expectNamedTypeError(true, "boolean");
});

test("secretKey: array input throws a named Error even at floor length", () => {
  // A 32-element array used to reach `createSecretKey` and escape as a
  // node:crypto TypeError; the guard must fire first, before the floor
  // check (which the array would otherwise pass on `.length`).
  expectNamedTypeError(new Array<number>(32).fill(1), "object");
});

test("secretKey: short string keeps the existing 32-byte floor error", () => {
  assert.throws(
    () => secretKey("short"),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.ok(!(err instanceof TypeError));
      assert.equal(
        (err as Error).message,
        `${FLOOR_MESSAGE}, got 5 bytes`,
      );
      return true;
    },
  );
});

test("secretKey: empty Buffer keeps the existing 32-byte floor error", () => {
  assert.throws(
    () => secretKey(Buffer.alloc(0)),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        `${FLOOR_MESSAGE}, got 0 bytes`,
      );
      return true;
    },
  );
});

test("secretKey: 31-byte string is still refused by the floor check", () => {
  assert.throws(
    () => secretKey("a".repeat(31)),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        `${FLOOR_MESSAGE}, got 31 bytes`,
      );
      return true;
    },
  );
});

test("secretKey: 32/64-byte string and Buffer secrets still produce keys", () => {
  for (const secret of [
    "a".repeat(32),
    "b".repeat(64),
    Buffer.alloc(32, 0x47),
    Buffer.alloc(64, 0x48),
  ]) {
    const key = secretKey(secret);
    assert.equal(key.type, "secret");
    assert.equal(key.symmetricKeySize, secret.length);
  }
});

test("secretKey: multibyte string is measured in bytes, not characters", () => {
  // 16 × "é" is 32 UTF-8 bytes: passes the floor. 15 × "é" is 30 bytes.
  const key = secretKey("é".repeat(16));
  assert.equal(key.type, "secret");
  assert.equal(key.symmetricKeySize, 32);
  assert.throws(
    () => secretKey("é".repeat(15)),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        (err as Error).message,
        `${FLOOR_MESSAGE}, got 30 bytes`,
      );
      return true;
    },
  );
});

test("secretKey: a guarded key still signs and verifies (hmac-sha256)", () => {
  const key = secretKey("a-shared-hmac-secret-of-32-bytes!!");
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1",
      headers: {},
    },
    { key, alg: "hmac-sha256", keyId: "test-key", created: 1700000000 },
  );
  const result = verifyRequest(signed, {
    key,
    now: 1700000060,
  });
  assert.equal(result.ok, true);
});
