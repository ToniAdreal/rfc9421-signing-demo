import test from "node:test";
import assert from "node:assert/strict";
import {
  constants,
  createSign,
  createVerify,
  generateKeyPairSync,
} from "node:crypto";
import {
  buildSignatureBase,
  exportPublicKeyJwkRsa,
  generateEd25519KeyPair,
  generateP256KeyPair,
  generateRsaPssKeyPair,
  generateRsaV15KeyPair,
  importPublicKeyJwkRsa,
  parseSignatureField,
  parseSignatureInput,
  signRequest,
  verifyAllLabels,
  verifyRequest,
} from "../src/index.js";

const BODY = JSON.stringify({ amount: 100, currency: "USD" });
const CREATED = 1700000000;
const REQ = {
  method: "POST",
  url: "https://api.example.com/v1/payments",
  headers: { "content-type": "application/json" },
  body: BODY,
};

function signV15() {
  const { publicKey, privateKey } = generateRsaV15KeyPair();
  const signed = signRequest(REQ, {
    keyId: "test-rsa-v15",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  return { publicKey, privateKey, signed };
}

test("rsa-v1_5-sha256 round-trip with body; alg serialized verbatim", () => {
  const { publicKey, signed } = signV15();

  assert.equal(
    signed.headers["signature-input"],
    'sig1=("@method" "@authority" "@path" "content-digest");created=1700000000;keyid="test-rsa-v15";alg="rsa-v1_5-sha256"',
  );
  // 2048-bit RSA signature → 256 raw bytes, base64-wrapped per §4.2.
  assert.match(signed.headers["signature"], /^sig1=:[A-Za-z0-9+/=]+:$/);

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.keyId, "test-rsa-v15");
  assert.equal(res.alg, "rsa-v1_5-sha256");
});

test("rsa-v1_5-sha256 round-trip without body", () => {
  const { publicKey, privateKey } = generateRsaV15KeyPair();
  const signed = signRequest(
    {
      method: "GET",
      url: "https://api.example.com/v1/status?verbose=1",
      headers: {},
    },
    {
      keyId: "test-rsa-v15",
      alg: "rsa-v1_5-sha256",
      key: privateKey,
      created: CREATED,
    },
  );

  const res = verifyRequest(signed, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-v1_5-sha256");
});

test("v1.5 signatures are deterministic: same base and key sign to identical bytes (unlike PSS)", () => {
  const { publicKey, privateKey } = generateRsaV15KeyPair();
  const opts = {
    keyId: "test-rsa-v15",
    alg: "rsa-v1_5-sha256" as const,
    key: privateKey,
    created: CREATED,
  };
  const a = signRequest(REQ, opts);
  const b = signRequest(REQ, opts);
  assert.equal(a.headers["signature"], b.headers["signature"]);
  assert.equal(verifyRequest(a, { key: publicKey, now: CREATED + 60 }).ok, true);
  assert.equal(verifyRequest(b, { key: publicKey, now: CREATED + 60 }).ok, true);
});

test("golden base: v1.5 and PSS share every base line except the alg parameter; signature values differ", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const v15 = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  const pss = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-pss-sha512",
    key: privateKey,
    created: CREATED,
  });

  const baseOf = (signed: typeof v15) => {
    const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
    return buildSignatureBase(
      parsed.componentIds,
      { method: signed.method, url: signed.url, headers: signed.headers },
      parsed.params,
    );
  };
  const v15Lines = baseOf(v15).split("\n");
  const pssLines = baseOf(pss).split("\n");
  assert.deepEqual(v15Lines.slice(0, -1), pssLines.slice(0, -1));
  assert.equal(
    v15Lines.at(-1)?.replace('alg="rsa-v1_5-sha256"', 'alg="rsa-pss-sha512"'),
    pssLines.at(-1),
  );
  assert.notEqual(v15.headers["signature"], pss.headers["signature"]);

  // Independent check with raw node:crypto (no library verify path):
  // the v1.5 signature must verify over the hand-built base under
  // RSASSA-PKCS1-v1_5 + SHA-256, and must not verify under PSS.
  const sigBytes = parseSignatureField(v15.headers["signature"], "sig1");
  assert.equal(
    createVerify("sha256")
      .update(baseOf(v15), "utf8")
      .verify({ key: publicKey, padding: constants.RSA_PKCS1_PADDING }, sigBytes),
    true,
  );
  assert.equal(
    createVerify("sha512")
      .update(baseOf(v15), "utf8")
      .verify(
        { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
        sigBytes,
      ),
    false,
  );
});

test("tampered covered component (@path) fails with SIGNATURE_MISMATCH", () => {
  const { publicKey, signed } = signV15();
  const tampered = { ...signed, url: "https://api.example.com/v1/refunds" };

  const res = verifyRequest(tampered, { key: publicKey, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("wrong RSA key fails with SIGNATURE_MISMATCH", () => {
  const { signed } = signV15();
  const { publicKey: other } = generateRsaV15KeyPair();

  const res = verifyRequest(signed, { key: other, now: CREATED + 60 });
  assert.equal(res.ok, false);
  assert.equal(res.code, "SIGNATURE_MISMATCH");
});

test("padding confusion at the same base: PSS bytes never verify as v1.5, v1.5 bytes never verify as PSS", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const swapSig = (
    signed: ReturnType<typeof signRequest>,
    bytes: Buffer,
  ) => ({
    ...signed,
    headers: {
      ...signed.headers,
      signature: `sig1=:${bytes.toString("base64")}:`,
    },
  });
  const baseOf = (signed: ReturnType<typeof signRequest>) => {
    const parsed = parseSignatureInput(signed.headers["signature-input"], "sig1");
    return buildSignatureBase(
      parsed.componentIds,
      { method: signed.method, url: signed.url, headers: signed.headers },
      parsed.params,
    );
  };

  // PSS bytes (SHA-512, PSS padding) over the v1.5 base, alg stays v1.5.
  const v15 = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  const pssBytes = createSign("sha512")
    .update(baseOf(v15), "utf8")
    .sign({
      key: privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 64,
    });
  const resA = verifyRequest(swapSig(v15, pssBytes), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(resA.ok, false);

  // v1.5 bytes (SHA-256, PKCS#1 padding) over the PSS base, alg stays PSS.
  const pss = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-pss-sha512",
    key: privateKey,
    created: CREATED,
  });
  const v15Bytes = createSign("sha256")
    .update(baseOf(pss), "utf8")
    .sign(privateKey);
  const resB = verifyRequest(swapSig(pss, v15Bytes), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(resB.ok, false);
});

test("relabeling the declared alg flips verification to failure in both directions", () => {
  const { publicKey, privateKey } = generateRsaPssKeyPair();
  const relabel = (
    signed: ReturnType<typeof signRequest>,
    from: string,
    to: string,
  ) => ({
    ...signed,
    headers: {
      ...signed.headers,
      "signature-input": signed.headers["signature-input"].replace(
        `alg="${from}"`,
        `alg="${to}"`,
      ),
    },
  });

  const pss = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-pss-sha512",
    key: privateKey,
    created: CREATED,
  });
  const asV15 = verifyRequest(relabel(pss, "rsa-pss-sha512", "rsa-v1_5-sha256"), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(asV15.ok, false);

  const v15 = signRequest(REQ, {
    keyId: "test-rsa",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  const asPss = verifyRequest(relabel(v15, "rsa-v1_5-sha256", "rsa-pss-sha512"), {
    key: publicKey,
    now: CREATED + 60,
  });
  assert.equal(asPss.ok, false);
});

test("a P-256 key paired with rsa-v1_5-sha256 is a clear configuration error on both sides, not a crash", () => {
  const { publicKey: p256Pub, privateKey: p256Priv } = generateP256KeyPair();

  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "bad",
        alg: "rsa-v1_5-sha256",
        key: p256Priv,
        created: CREATED,
      }),
    /signRequest: alg "rsa-v1_5-sha256": expected an RSA key/,
  );

  const { signed } = signV15();
  assert.throws(
    () => verifyRequest(signed, { key: p256Pub, now: CREATED + 60 }),
    /verifyRequest: alg "rsa-v1_5-sha256": expected an RSA key/,
  );
});

test("a sub-2048-bit RSA key is rejected on both sides (existing RSA floor)", () => {
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });

  assert.throws(
    () =>
      signRequest(REQ, {
        keyId: "weak",
        alg: "rsa-v1_5-sha256",
        key: weak.privateKey,
        created: CREATED,
      }),
    /RSA modulus must be at least 2048 bits, got 1024 bits/,
  );

  const { signed } = signV15();
  assert.throws(
    () => verifyRequest(signed, { key: weak.publicKey, now: CREATED + 60 }),
    /RSA modulus must be at least 2048 bits, got 1024 bits/,
  );
});

test("one RSA key serves both paddings, and its JWK export verifies v1.5 signatures", () => {
  const { publicKey, privateKey } = generateRsaV15KeyPair();

  const v15 = signRequest(REQ, {
    keyId: "shared-rsa",
    alg: "rsa-v1_5-sha256",
    key: privateKey,
    created: CREATED,
  });
  const pss = signRequest(REQ, {
    keyId: "shared-rsa",
    alg: "rsa-pss-sha512",
    key: privateKey,
    created: CREATED,
  });
  assert.equal(verifyRequest(v15, { key: publicKey, now: CREATED + 60 }).ok, true);
  assert.equal(verifyRequest(pss, { key: publicKey, now: CREATED + 60 }).ok, true);

  // The JWK carries no alg: the imported key verifies the v1.5
  // signature because the declared alg picks the padding.
  const wireKey = importPublicKeyJwkRsa(
    JSON.parse(JSON.stringify(exportPublicKeyJwkRsa(publicKey))),
  );
  const res = verifyRequest(v15, { key: wireKey, now: CREATED + 60 });
  assert.equal(res.ok, true);
  assert.equal(res.alg, "rsa-v1_5-sha256");
});

test("verifyAllLabels verifies a mixed rsa-v1_5 + ed25519 request", () => {
  const { publicKey: rsaPub, privateKey: rsaPriv } = generateRsaV15KeyPair();
  const { publicKey: edPub, privateKey: edPriv } = generateEd25519KeyPair();
  const first = signRequest(REQ, {
    keyId: "rsa-signer",
    alg: "rsa-v1_5-sha256",
    key: rsaPriv,
    created: CREATED,
    label: "sig-rsa",
  });
  const second = signRequest(REQ, {
    keyId: "ed-signer",
    alg: "ed25519",
    key: edPriv,
    created: CREATED,
    label: "sig-ed",
  });
  const merged = {
    ...first,
    headers: {
      ...first.headers,
      "signature-input": `${first.headers["signature-input"]}, ${second.headers["signature-input"]}`,
      signature: `${first.headers["signature"]}, ${second.headers["signature"]}`,
    },
  };

  const results = verifyAllLabels(merged, {
    keys: { "sig-rsa": rsaPub, "sig-ed": edPub },
    now: CREATED + 60,
  });
  assert.equal(results.length, 2);
  assert.equal(results[0].ok, true);
  assert.equal(results[0].alg, "rsa-v1_5-sha256");
  assert.equal(results[1].ok, true);
  assert.equal(results[1].alg, "ed25519");
});
