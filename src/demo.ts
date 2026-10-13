/**
 * Demo: sign one fixed request with a freshly generated ed25519 key,
 * print the wire headers, verify it, then tamper the body by one byte
 * and show the verifier rejecting it. After that single-signature
 * script, the demo runs the canonical multi-party payments flow: the
 * payment gateway appends a second signature with `addSignature`
 * (label `gateway`, hmac-sha256), the merged wire headers are printed,
 * and `verifyAllLabels` verifies each label independently. Finally the
 * demo tampers `content-type` — a component only the gateway signature
 * covers — to show one label failing while the other still verifies.
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
 * identical. The gateway HMAC secret below is a fixed demo value (never
 * use it anywhere else), so the gateway signature itself is
 * deterministic; only the merchant's fresh-key signature varies.
 */

import { fileURLToPath } from "node:url";
import {
  addSignature,
  generateEd25519KeyPair,
  secretKey,
  signRequest,
  verifyAllLabels,
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
/** Label of the gateway's appended second signature. */
export const DEMO_GATEWAY_LABEL = "gateway";
export const DEMO_GATEWAY_KEY_ID = "gateway-key-1";
/**
 * Demo-only gateway HMAC secret: 49 bytes (the hmac-sha256 floor is
 * 32), fixed so the gateway signature is deterministic, and labelled
 * as a demo value — it must never be used outside this demo.
 */
export const DEMO_GATEWAY_SECRET =
  "demo-gateway-secret-do-not-use-in-prod-0123456789";
/**
 * Components the gateway signature covers. Unlike the merchant's
 * `sig1` signature (the default set, including `content-digest`), the
 * gateway additionally covers `content-type` — which is what makes
 * the tamper-isolation step below possible: changing `content-type`
 * breaks only the gateway label.
 */
export const DEMO_GATEWAY_COVERED_COMPONENTS: string[] = [
  "@method",
  "@authority",
  "@path",
  "content-type",
];
/** Value `content-type` is tampered to in the isolation step. */
export const DEMO_TAMPERED_CONTENT_TYPE = "text/plain";

export interface DemoResult {
  signed: SignedHttpRequest;
  tamperedBody: string;
  verification: VerifyResult;
  tamperedVerification: VerifyResult;
  /** The request after the gateway appended its second signature. */
  dualSigned: SignedHttpRequest;
  /** Per-label results for the dual-signed request (both ok). */
  dualVerification: VerifyResult[];
  /**
   * Per-label results after `content-type` was tampered: the merchant
   * `sig1` label still verifies, the `gateway` label fails.
   */
  contentTypeTamperedVerification: VerifyResult[];
  lines: string[];
}

function formatLabelResult(prefix: string, result: VerifyResult): string {
  return result.ok
    ? `${prefix} ${result.label}: OK (label ${result.label}, keyid="${result.keyId}", alg="${result.alg}")`
    : `${prefix} ${result.label}: FAILED (code ${result.code}: ${result.reason})`;
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

  // Multi-party step: the merchant's `sig1` signature above is the
  // first signature; the payment gateway now appends its own second
  // signature with `addSignature` (hmac-sha256 under a demo-only
  // secret), without touching the merchant's entries. The gateway
  // covers `content-type` in addition to the derived components —
  // see DEMO_GATEWAY_COVERED_COMPONENTS.
  const gatewaySecret = secretKey(DEMO_GATEWAY_SECRET);
  const dualSigned = addSignature(signed, {
    keyId: DEMO_GATEWAY_KEY_ID,
    alg: "hmac-sha256",
    key: gatewaySecret,
    created: DEMO_CREATED,
    label: DEMO_GATEWAY_LABEL,
    coveredComponents: [...DEMO_GATEWAY_COVERED_COMPONENTS],
  });
  const dualVerifyOptions = {
    key: publicKey,
    keys: { [DEMO_GATEWAY_LABEL]: gatewaySecret },
    now: DEMO_CREATED + 60,
  };
  const dualVerification = verifyAllLabels(dualSigned, dualVerifyOptions);

  // Tamper isolation: `content-type` is covered only by the gateway
  // signature, so changing it must fail the gateway label while the
  // merchant `sig1` label (which does not cover `content-type`, and
  // whose content-digest still matches the untouched body) still
  // verifies — `verifyAllLabels` reports each label independently.
  const contentTypeTamperedVerification = verifyAllLabels(
    {
      ...dualSigned,
      headers: {
        ...dualSigned.headers,
        "content-type": DEMO_TAMPERED_CONTENT_TYPE,
      },
    },
    dualVerifyOptions,
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
    "",
    "Multi-party signing: gateway adds a second signature with addSignature (hmac-sha256)",
    `Dual Signature-Input: ${dualSigned.headers["signature-input"]}`,
    `Dual Signature: ${dualSigned.headers["signature"]}`,
    ...dualVerification.map((r) => formatLabelResult("Dual verification", r)),
    "",
    `Tampered content-type: ${DEMO_TAMPERED_CONTENT_TYPE} (only the gateway signature covers "content-type")`,
    ...contentTypeTamperedVerification.map((r) =>
      formatLabelResult("After content-type tampering", r),
    ),
  ];

  return {
    signed,
    tamperedBody: DEMO_TAMPERED_BODY,
    verification,
    tamperedVerification,
    dualSigned,
    dualVerification,
    contentTypeTamperedVerification,
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
