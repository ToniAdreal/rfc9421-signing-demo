import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { contentDigest } from "../src/index.js";

/**
 * Independent cross-check of the sha-256 Content-Digest path (#222).
 *
 * Every expected value below was produced OUTSIDE this library, by
 * feeding the exact body bytes (no trailing newline) to OpenSSL:
 *
 *   <body bytes> | openssl dgst -sha256 -binary | base64
 *   # wire value is then `sha-256=:<that base64>:`
 *
 * captured locally with OpenSSL 3.0.13 (30 Jan 2024) on 2026-10-12.
 * None of the expectations are computed with node:crypto in this file,
 * so a broken sha-256 path in src/digest.ts cannot make these tests
 * pass by agreeing with itself (the failure mode of the older
 * content-digest tests, whose expectations are self-computed).
 *
 * One vector is additionally an external published value: RFC 9530
 * Appendix D lists sha-256 `:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`
 * for the exact input `{"hello": "world"}`.
 *
 * If no `openssl` binary is available in the environment running the
 * tests, the live re-check at the bottom is EXPLICITLY skipped (see
 * its skip reason) — it never passes silently. The hardcoded
 * openssl-derived vectors above it still run in that case, and the
 * README states honestly that the live re-check was done locally.
 */

interface Vector {
  name: string;
  body: string | Buffer;
  /** Exact bytes fed to openssl, for the live re-check. */
  bytes: Buffer;
  expected: string;
}

const VECTORS: Vector[] = [
  {
    name: "empty body",
    body: Buffer.alloc(0),
    bytes: Buffer.alloc(0),
    expected: "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
  },
  {
    name: "ASCII JSON body",
    body: '{"amount":100,"currency":"USD"}',
    bytes: Buffer.from('{"amount":100,"currency":"USD"}', "utf8"),
    expected: "sha-256=:nRIVtM4I5bjHe8zXwvZzr4LRU7HqvqIqHjxSQnK3jbE=:",
  },
  {
    name: "multi-byte UTF-8 body",
    body: "支付 ¥100 — café ☕",
    bytes: Buffer.from("支付 ¥100 — café ☕", "utf8"),
    expected: "sha-256=:w6y7qgmp0WPVkvsxJM8pFzkrtu4py5B4Eup9eiSAoIk=:",
  },
  {
    name: "binary body (non-UTF-8 bytes)",
    body: Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x80, 0x7f, 0x0a, 0x0d]),
    bytes: Buffer.from([0x00, 0xff, 0xfe, 0x01, 0x02, 0x80, 0x7f, 0x0a, 0x0d]),
    expected: "sha-256=:NYRKODAYJ039r1hlYM8ZHxfgxka69+CNMnDvpMzsWo8=:",
  },
  {
    name: "RFC 9530 Appendix D sample body",
    body: '{"hello": "world"}',
    bytes: Buffer.from('{"hello": "world"}', "utf8"),
    expected: "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
  },
];

for (const v of VECTORS) {
  test(`sha-256 openssl vector: ${v.name}`, () => {
    assert.equal(contentDigest(v.body, "sha-256"), v.expected);
    // The Buffer form of the same bytes must agree byte-for-byte.
    assert.equal(contentDigest(v.bytes, "sha-256"), v.expected);
  });
}

test("sha-256 vector matches RFC 9530 Appendix D published sample", () => {
  // RFC 9530 Appendix D: input {"hello": "world"}, sha-256 sample value.
  assert.equal(
    contentDigest('{"hello": "world"}', "sha-256"),
    "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
  );
});

const opensslProbe = spawnSync("openssl", ["version"], { encoding: "utf8" });
const opensslAvailable = !opensslProbe.error && opensslProbe.status === 0;

test(
  "live openssl dgst -sha256 re-check agrees with contentDigest and the hardcoded vectors",
  {
    skip: opensslAvailable
      ? false
      : "openssl binary not available in this environment: live re-check " +
        "skipped explicitly (not a pass); the hardcoded openssl-derived " +
        "vectors in this file still ran — live cross-check was done locally",
  },
  () => {
    for (const v of VECTORS) {
      const run = spawnSync("openssl", ["dgst", "-sha256", "-binary"], {
        input: v.bytes,
      });
      assert.equal(run.status, 0, `openssl failed for ${v.name}: ${run.stderr}`);
      const wire = `sha-256=:${(run.stdout as Buffer).toString("base64")}:`;
      assert.equal(wire, v.expected, `openssl disagrees with vector: ${v.name}`);
      assert.equal(contentDigest(v.bytes, "sha-256"), wire, v.name);
    }
  },
);
