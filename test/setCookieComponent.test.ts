import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { KeyObject } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  buildSignatureBase,
  generateEd25519KeyPair,
  signRequest,
  verifyRequest,
  type RequestLike,
} from "../src/index.js";

const CREATED = 1700000000;
// A Set-Cookie value whose Expires attribute itself contains a comma:
// the exact shape that makes ", " combination ambiguous (RFC 9421
// §2.1, §7.5.6). Both cookies carry one, so the joined string holds
// two Expires commas and no reader can tell where one cookie ends.
const COOKIE_1 = "session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/";
const COOKIE_2 = "prefs=dark; Expires=Thu, 22 Oct 2026 07:28:00 GMT; Path=/";

const repoRoot = path.dirname(
  path.dirname(path.dirname(fileURLToPath(import.meta.url))),
); // dist/test/*.test.js -> repo root

function makeResponse(cookies: string[]): RequestLike {
  return {
    method: "GET",
    url: "https://api.example.com/v1/settle",
    headers: { "set-cookie": cookies },
    status: 200,
  };
}

function sign(cookies: string[], coveredComponents: string[]) {
  const keys = generateEd25519KeyPair();
  const signed = signRequest(makeResponse(cookies), {
    keyId: "sc-1",
    alg: "ed25519",
    key: keys.privateKey,
    created: CREATED,
    coveredComponents,
  });
  return { ...keys, signed };
}

function verify(signed: RequestLike, publicKey: KeyObject) {
  return verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
}

test("single-value set-cookie round-trips", () => {
  const { publicKey, signed } = sign([COOKIE_1], ["@status", "set-cookie"]);
  assert.equal(verify(signed, publicKey).ok, true);
});

test("double-value set-cookie round-trips via the ', ' join (current behavior, pinned)", () => {
  const { publicKey, signed } = sign([COOKIE_1, COOKIE_2], ["@status", "set-cookie"]);
  assert.equal(verify(signed, publicKey).ok, true);
  // The pinned behavior: the signature base holds the two cookies as
  // one ", "-joined string, not as two separate values.
  const base = buildSignatureBase(["set-cookie"], makeResponse([COOKIE_1, COOKIE_2]), {});
  assert.match(base, /"set-cookie": session=abc; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=\/, prefs=dark;/);
});

test("set-cookie;bs wraps double values and round-trips", () => {
  const { publicKey, signed } = sign([COOKIE_1, COOKIE_2], ["@status", "set-cookie;bs"]);
  assert.match(signed.headers["signature-input"], /"set-cookie";bs/);
  assert.equal(verify(signed, publicKey).ok, true);
  // ;bs binds the exact joined bytes as one base64 byte sequence.
  const base = buildSignatureBase(["set-cookie;bs"], makeResponse([COOKIE_1, COOKIE_2]), {});
  const decoded = Buffer.from(
    base.match(/:([A-Za-z0-9+/=]+):/)?.[1] as string,
    "base64",
  ).toString("utf8");
  assert.equal(decoded, `${COOKIE_1}, ${COOKIE_2}`);
});

test("tampering the second cookie fails with SIGNATURE_MISMATCH (bare)", () => {
  const { publicKey, signed } = sign([COOKIE_1, COOKIE_2], ["@status", "set-cookie"]);
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "set-cookie": [COOKIE_1, "prefs=light; Expires=Thu, 22 Oct 2026 07:28:00 GMT; Path=/"],
    },
  };
  const res = verify(tampered, publicKey);
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("tampering the second cookie fails with SIGNATURE_MISMATCH (;bs)", () => {
  const { publicKey, signed } = sign([COOKIE_1, COOKIE_2], ["@status", "set-cookie;bs"]);
  const tampered = {
    ...signed,
    headers: {
      ...signed.headers,
      "set-cookie": [COOKIE_1, "prefs=light; Expires=Thu, 22 Oct 2026 07:28:00 GMT; Path=/"],
    },
  };
  const res = verify(tampered, publicKey);
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("ambiguity evidence: single- and double-value bases differ literally, and the double base carries the Expires comma", () => {
  const single = buildSignatureBase(["set-cookie"], makeResponse([COOKIE_1]), {});
  const double = buildSignatureBase(["set-cookie"], makeResponse([COOKIE_1, COOKIE_2]), {});
  assert.notEqual(single, double);
  assert.ok(double.includes("Expires=Wed, 21 Oct 2026 07:28:00 GMT"));
  assert.equal(
    double,
    `"set-cookie": ${COOKIE_1}, ${COOKIE_2}\n"@signature-params": ("set-cookie")`,
  );
});

test("ambiguity evidence: two different cookie splits produce the identical bare base", () => {
  // Same joined string, different split points: the signature binds
  // the joined string, not the individual cookies.
  const splitA = [COOKIE_1, COOKIE_2];
  const splitB = [
    "session=abc; Expires=Wed",
    "21 Oct 2026 07:28:00 GMT; Path=/, prefs=dark; Expires=Thu, 22 Oct 2026 07:28:00 GMT; Path=/",
  ];
  assert.equal(
    buildSignatureBase(["set-cookie"], makeResponse(splitA), {}),
    buildSignatureBase(["set-cookie"], makeResponse(splitB), {}),
  );
});

test("ambiguity evidence: ;bs does not remove the split ambiguity either", () => {
  // ;bs binds the exact joined bytes, so it still cannot tell two
  // splittings of the same joined string apart — only a single-valued
  // set-cookie is unambiguous to cover.
  const splitA = [COOKIE_1, COOKIE_2];
  const splitB = [
    "session=abc; Expires=Wed",
    "21 Oct 2026 07:28:00 GMT; Path=/, prefs=dark; Expires=Thu, 22 Oct 2026 07:28:00 GMT; Path=/",
  ];
  assert.equal(
    buildSignatureBase(["set-cookie;bs"], makeResponse(splitA), {}),
    buildSignatureBase(["set-cookie;bs"], makeResponse(splitB), {}),
  );
});

test("README Limitations carries the multi-value set-cookie warning", () => {
  const readme = readFileSync(path.join(repoRoot, "README.md"), "utf8");
  const start = readme.indexOf("## Limitations (honest)");
  assert.ok(start >= 0, "README drift: no ## Limitations (honest) section found");
  const section = readme.slice(start);
  assert.match(section, /Multi-value `set-cookie` is ambiguous when covered bare/);
  assert.match(section, /RFC 9421 §7\.5\.6/);
  assert.match(section, /only when it carries a single value/);
});
