/**
 * Demo: sign one fixed request with a freshly generated ed25519 key,
 * print the wire headers, verify it, then tamper the body by one byte
 * and show the verifier rejecting it.
 *
 * Usage: `npm run demo` (builds with tsc, then runs node on the compiled
 * output). Zero runtime dependencies: this file only imports the library
 * itself.
 *
 * The request data is deterministic — fixed method, URL, body, `created`
 * timestamp, key id, and nonce are constants below; no wall clock beyond
 * the injected verify instant, no network. The ed25519 key pair itself
 * is generated fresh on every run (see `generateEd25519KeyPair`), so the
 * signature bytes differ between runs while every other printed line is
 * identical.
 */

import { fileURLToPath } from "node:url";
import {
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type SignedHttpRequest,
  type VerifyResult,
} from "./index.js";

export const DEMO_KEY_ID = "demo-key-1";
export const DEMO_CREATED = 1700000000;
export const DEMO_NONCE = "demo-nonce-001";
export const DEMO_BODY = JSON.stringify({ amount: 100, currency: "USD" });
/** DEMO_BODY with exactly one byte changed: amount 100 -> 101. */
export const DEMO_TAMPERED_BODY = JSON.stringify({
  amount: 101,
  currency: "USD",
});

export interface DemoResult {
  signed: SignedHttpRequest;
  tamperedBody: string;
  verification: VerifyResult;
  tamperedVerification: VerifyResult;
  lines: string[];
}

/**
 * Run the demo without printing anything, and return the signed request,
 * both verification results, and the exact lines `main()` prints — so
 * tests can assert on the demo itself, not just on the library.
 */
export function runDemo(): DemoResult {
  const { publicKey, privateKey } = generateEd25519KeyPair();

  const signed = signRequest(
    {
      method: "POST",
      url: "https://api.example.com/v1/payments",
      headers: { "content-type": "application/json" },
      body: DEMO_BODY,
    },
    {
      keyId: DEMO_KEY_ID,
      alg: "ed25519",
      key: privateKey,
      created: DEMO_CREATED,
      nonce: DEMO_NONCE,
    },
  );

  // Verify at a fixed instant inside the signature's freshness window.
  const verification = verifyRequest(signed, {
    key: publicKey,
    now: DEMO_CREATED + 60,
  });

  // One byte of the body changed (100 -> 101); the headers — including
  // the signed content-digest — are left untouched, exactly as a
  // man-in-the-middle body swap would leave them.
  const tamperedVerification = verifyRequest(
    { ...signed, body: DEMO_TAMPERED_BODY },
    { key: publicKey, now: DEMO_CREATED + 60 },
  );

  const lines: string[] = [
    "RFC 9421 signing demo (ed25519)",
    `Request: POST https://api.example.com/v1/payments`,
    `Body: ${DEMO_BODY}`,
    `Content-Digest: ${signed.headers["content-digest"]}`,
    `Signature-Input: ${signed.headers["signature-input"]}`,
    `Signature: ${signed.headers["signature"]}`,
    verification.ok
      ? `Verification: OK (label ${verification.label}, keyid="${verification.keyId}", alg="${verification.alg}", nonce="${verification.nonce}")`
      : `Verification: FAILED (code ${verification.code}: ${verification.reason})`,
    "",
    `Tampered body: ${DEMO_TAMPERED_BODY} (one byte changed: amount 100 -> 101)`,
    tamperedVerification.ok
      ? "Verification after tampering: OK (unexpected — tampering was not detected)"
      : `Verification after tampering: FAILED (code ${tamperedVerification.code}: ${tamperedVerification.reason})`,
  ];

  return {
    signed,
    tamperedBody: DEMO_TAMPERED_BODY,
    verification,
    tamperedVerification,
    lines,
  };
}

function main(): void {
  console.log(runDemo().lines.join("\n"));
}

// Run only when executed directly (`node dist/src/demo.js`), not when
// imported by tests.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
