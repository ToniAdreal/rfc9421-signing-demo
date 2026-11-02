import test from "node:test";
import assert from "node:assert/strict";
import {
  addSignature,
  generateEd25519KeyPair,
  listSignatureLabels,
  parseSignatureField,
  parseSignatureInput,
  signRequest,
  verifyAllLabels,
  verifyRequest,
  type SignedHttpRequest,
} from "../src/index.js";

const CREATED = 1700000000;
const NOW = CREATED + 60;

/**
 * Two genuinely different signatures minted under the SAME label
 * ("sig1"), so a verifier that picked the wrong occurrence would see
 * different covered components, a different keyid, a different
 * `created`, and signature bytes over a different path. The first
 * member covers @method/@authority/@path on /v1/payments; the second
 * covers only @method on /v1/refunds. The duplicated wire below is
 * what a proxy that appended its own entry without renaming would
 * produce; this library's verify side silently converges on the
 * first occurrence rather than rejecting it (contrast with
 * `addSignature`, which refuses a duplicate label at sign time).
 */
function duplicatedWire() {
  const { publicKey, privateKey } = generateEd25519KeyPair();
  const first = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      keyId: "first-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "sig1",
    },
  );
  const second = signRequest(
    { method: "POST", url: "https://api.example.com/v1/refunds", headers: {} },
    {
      keyId: "second-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED + 3600,
      label: "sig1",
      coveredComponents: ["@method"],
    },
  );
  const duplicated: SignedHttpRequest = {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": `${first.headers["signature-input"]}, ${second.headers["signature-input"]}`,
      signature: `${first.headers["signature"]}, ${second.headers["signature"]}`,
    },
  };
  return { first, second, duplicated, publicKey, privateKey };
}

/** Corrupt the Nth (0-based) member of a `label=:base64:` field. */
function corruptSignatureMember(fieldValue: string, index: number): string {
  const members = fieldValue.split(", ");
  const m = /^([A-Za-z][A-Za-z0-9!#$%&'*+\-.^_`|~]*)=:(.+):$/.exec(
    members[index],
  );
  assert.ok(m, `member ${index} must be label=:base64:`);
  const bytes = Buffer.from(m[2], "base64");
  bytes[0] ^= 0xff;
  members[index] = `${m[1]}=:${bytes.toString("base64")}:`;
  return members.join(", ");
}

/** Replace the second occurrence of `keyid="second-key"` in a field. */
function retagSecondMember(fieldValue: string): string {
  const firstAt = fieldValue.indexOf("sig1=");
  const secondAt = fieldValue.indexOf("sig1=", firstAt + 1);
  assert.ok(secondAt !== -1, "wire must carry a second sig1 member");
  const keyidAt = fieldValue.indexOf('keyid="second-key"', secondAt);
  assert.ok(keyidAt !== -1, "second member must carry keyid second-key");
  return (
    fieldValue.slice(0, keyidAt) +
    'keyid="attacker-key"' +
    fieldValue.slice(keyidAt + 'keyid="second-key"'.length)
  );
}

test("listSignatureLabels returns a duplicate label once, in wire order", () => {
  const { duplicated, privateKey } = duplicatedWire();
  const gateway = signRequest(
    { method: "POST", url: "https://api.example.com/v1/payments", headers: {} },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: privateKey,
      created: CREATED,
      label: "gateway",
    },
  );
  assert.deepEqual(
    listSignatureLabels(
      `${duplicated.headers["signature-input"]}, ${gateway.headers["signature-input"]}`,
    ),
    ["sig1", "gateway"],
  );
  assert.deepEqual(listSignatureLabels(duplicated.headers["signature-input"]), [
    "sig1",
  ]);
  // A distinct label after the duplicate still appears, exactly once.
  const triple = `${duplicated.headers["signature-input"]}, sig1=("@method");created=1700000000;keyid="third-key";alg="ed25519"`;
  assert.deepEqual(listSignatureLabels(triple), ["sig1"]);
});

test("parseSignatureInput returns the first member's components and params", () => {
  const { first, duplicated } = duplicatedWire();
  const parsed = parseSignatureInput(
    duplicated.headers["signature-input"],
    "sig1",
  );
  const firstParsed = parseSignatureInput(
    first.headers["signature-input"],
    "sig1",
  );
  assert.deepEqual(parsed.componentIds, ["@method", "@authority", "@path"]);
  assert.deepEqual(parsed, firstParsed);
  assert.equal(parsed.params.keyid, "first-key");
  assert.equal(parsed.params.created, CREATED);
});

test("parseSignatureField returns the first member's signature bytes", () => {
  const { first, second, duplicated } = duplicatedWire();
  const bytes = parseSignatureField(duplicated.headers["signature"], "sig1");
  assert.ok(
    bytes.equals(parseSignatureField(first.headers["signature"], "sig1")),
  );
  assert.ok(
    !bytes.equals(parseSignatureField(second.headers["signature"], "sig1")),
  );
});

test("verifyAllLabels returns one result for a duplicate label, decided by the first member", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const results = verifyAllLabels(duplicated, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].label, "sig1");
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "first-key");
  assert.equal(results[0].created, CREATED);
  assert.deepEqual(results[0].coveredComponents, [
    "@method",
    "@authority",
    "@path",
  ]);
});

test("verifyRequest on the duplicated wire verifies the first member only", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const result = verifyRequest(duplicated, { key: publicKey, now: NOW });
  assert.equal(result.ok, true);
  assert.equal(result.keyId, "first-key");
  assert.equal(result.created, CREATED);
});

test("corrupting only the second member's signature bytes leaves the verdict unchanged", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const tampered: SignedHttpRequest = {
    ...duplicated,
    headers: {
      ...duplicated.headers,
      signature: corruptSignatureMember(duplicated.headers["signature"], 1),
    },
  };
  const results = verifyAllLabels(tampered, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "first-key");
});

test("retargeting only the second member's keyid leaves the verdict unchanged", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const tampered: SignedHttpRequest = {
    ...duplicated,
    headers: {
      ...duplicated.headers,
      "signature-input": retagSecondMember(
        duplicated.headers["signature-input"],
      ),
    },
  };
  const results = verifyAllLabels(tampered, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].keyId, "first-key");
});

test("corrupting the first member's signature bytes fails the verdict", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const tampered: SignedHttpRequest = {
    ...duplicated,
    headers: {
      ...duplicated.headers,
      signature: corruptSignatureMember(duplicated.headers["signature"], 0),
    },
  };
  const results = verifyAllLabels(tampered, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].code, "SIGNATURE_MISMATCH");
});

test("a third occurrence of the same label is still converged to one result", () => {
  const { duplicated, publicKey } = duplicatedWire();
  const triple: SignedHttpRequest = {
    ...duplicated,
    headers: {
      ...duplicated.headers,
      "signature-input": `${duplicated.headers["signature-input"]}, ${duplicated.headers["signature-input"].split(", ")[1]}`,
      signature: `${duplicated.headers["signature"]}, ${duplicated.headers["signature"].split(", ")[1]}`,
    },
  };
  assert.deepEqual(listSignatureLabels(triple.headers["signature-input"]), [
    "sig1",
  ]);
  const results = verifyAllLabels(triple, { key: publicKey, now: NOW });
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, true);
});

test("sign side contrast: addSignature refuses a duplicate label", () => {
  const { first, privateKey } = duplicatedWire();
  assert.throws(
    () =>
      addSignature(first, {
        keyId: "another-key",
        alg: "ed25519",
        key: privateKey,
        label: "sig1",
      }),
    /already present/,
  );
});
