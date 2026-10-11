import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  DEMO_BODY,
  DEMO_CREATED,
  DEMO_KEY_ID,
  DEMO_NONCE,
  DEMO_TAMPERED_BODY,
  runDemo,
} from "../src/demo.js";

const repoRoot = path.dirname(
  path.dirname(path.dirname(fileURLToPath(import.meta.url))),
); // dist/test/*.test.js -> repo root

test("demo signs a fixed request with content-digest and nonce, and it verifies", () => {
  const { signed, verification } = runDemo();

  assert.ok(signed.headers["content-digest"].startsWith("sha-512=:"));
  assert.match(
    signed.headers["signature-input"],
    /\("@method" "@authority" "@path" "content-digest"\)/,
  );
  assert.ok(
    signed.headers["signature-input"].includes(`created=${DEMO_CREATED}`),
  );
  assert.ok(
    signed.headers["signature-input"].includes(`keyid="${DEMO_KEY_ID}"`),
  );
  assert.ok(
    signed.headers["signature-input"].includes(`nonce="${DEMO_NONCE}"`),
  );
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  assert.equal(verification.ok, true);
  assert.equal(verification.keyId, DEMO_KEY_ID);
  assert.equal(verification.alg, "ed25519");
  assert.equal(verification.nonce, DEMO_NONCE);
});

test("demo tamper changes exactly one body byte and verification rejects it", () => {
  const { tamperedBody, tamperedVerification } = runDemo();

  assert.equal(tamperedBody, DEMO_TAMPERED_BODY);
  assert.equal(tamperedBody.length, DEMO_BODY.length);
  let differingBytes = 0;
  for (let i = 0; i < DEMO_BODY.length; i++) {
    if (tamperedBody[i] !== DEMO_BODY[i]) differingBytes++;
  }
  assert.equal(differingBytes, 1);

  assert.equal(tamperedVerification.ok, false);
  assert.equal(tamperedVerification.code, "BODY_DIGEST_MISMATCH");
});

test("demo lines contain the headers, the success, and the tamper rejection", () => {
  const { lines } = runDemo();
  const out = lines.join("\n");

  assert.match(out, /Signature-Input: sig1=/);
  assert.match(out, /Signature: sig1=:/);
  assert.match(out, /Content-Digest: sha-512=:/);
  assert.match(out, /Verification: OK /);
  assert.match(
    out,
    /Verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
});

test("demo request data is deterministic across runs (fresh key aside)", () => {
  const a = runDemo();
  const b = runDemo();

  // Everything except the Signature line is byte-identical: the key pair
  // is generated fresh per run, so the signature bytes themselves differ.
  const withoutSignature = (lines: string[]) =>
    lines.filter((l) => !l.startsWith("Signature: "));
  assert.deepEqual(withoutSignature(a.lines), withoutSignature(b.lines));
  assert.equal(a.signed.headers["signature-input"], b.signed.headers["signature-input"]);
  assert.equal(a.signed.headers["content-digest"], b.signed.headers["content-digest"]);
  assert.notEqual(a.signed.headers["signature"], b.signed.headers["signature"]);
});

test("compiled demo script exits 0 and prints success plus tamper rejection", () => {
  const out = execFileSync("node", [path.join(repoRoot, "dist", "src", "demo.js")], {
    encoding: "utf8",
  });

  assert.match(out, /RFC 9421 signing demo \(ed25519\)/);
  assert.match(out, /Signature-Input: sig1=/);
  assert.match(out, /Signature: sig1=:/);
  assert.match(out, /Verification: OK /);
  assert.match(
    out,
    /Verification after tampering: FAILED \(code BODY_DIGEST_MISMATCH:/,
  );
});
