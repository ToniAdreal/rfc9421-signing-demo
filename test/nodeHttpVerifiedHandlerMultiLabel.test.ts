import test from "node:test";
import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import type { AddressInfo } from "node:net";
import {
  addSignature,
  createVerifiedHandler,
  generateEd25519KeyPair,
  signRequest,
  type CreateVerifiedHandlerOptions,
  type SignedHttpRequest,
  type VerifyAllOptions,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";

// Backlog #1090: `createVerifiedHandler` only ever called
// `verifyRequest` (single label) — its own JSDoc admitted it never
// called `verifyAllLabels`. A dual-signed webhook (merchant signature
// plus payment-gateway signature on the same request) could not be
// received through the handler at all: the caller had to bypass it
// and hand-roll buffer→adapt→verifyAllLabels→401, and the per-label
// keys / pins / `requiredLabels` of `VerifyAllOptions` had no landing
// point at the handler entry. #1077 explicitly left this gap open.
// This file pins the opt-in `verifyAllLabels` mode.

const CREATED = 1700000000;
const BODY = JSON.stringify({ settled: true, amount: 100 });
const TAMPERED_BODY = JSON.stringify({ settled: true, amount: 999 });

const merchant = generateEd25519KeyPair();
const gateway = generateEd25519KeyPair();
const wrongKey = generateEd25519KeyPair();

/** Wire-style headers carrying a signature, as a client would send them. */
function wireHeaders(
  signed: SignedHttpRequest,
): Record<string, string | undefined> {
  return {
    "Content-Type": "application/json",
    "Signature-Input": signed.headers["signature-input"] as string,
    Signature: signed.headers["signature"] as string,
    "Content-Digest": signed.headers["content-digest"] as string,
  };
}

/** Sign a POST to the exact loopback URL the server rebuilds. */
function signedPost(
  port: number,
  body: string = BODY,
): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
    },
  );
}

/** A dual-signed POST: merchant first, gateway appended. */
function dualSignedPost(port: number, body: string = BODY): SignedHttpRequest {
  const merchantSigned = signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
  return addSignature(merchantSigned, {
    keyId: "gateway-key",
    alg: "ed25519",
    key: gateway.privateKey,
    created: CREATED,
    label: "gateway",
  });
}

/** A merchant-only POST (no gateway label on the wire). */
function merchantOnlyPost(port: number, body: string = BODY): SignedHttpRequest {
  return signRequest(
    {
      method: "POST",
      url: `http://127.0.0.1:${port}/webhook`,
      headers: { "content-type": "application/json" },
      body,
    },
    {
      keyId: "merchant-key",
      alg: "ed25519",
      key: merchant.privateKey,
      created: CREATED,
      label: "merchant",
    },
  );
}

/** Flip the first base64 character of one label's signature value. */
function tamperLabelSignature(
  signed: SignedHttpRequest,
  label: string,
): SignedHttpRequest {
  const raw = signed.headers["signature"] as string;
  const entries = raw.split(", ");
  const tampered = entries.map((entry) => {
    if (!entry.startsWith(`${label}=:`)) return entry;
    const inner = entry.slice(label.length + 2, -1);
    const flipped = (inner[0] === "A" ? "B" : "A") + inner.slice(1);
    return `${label}=:${flipped}:`;
  });
  return {
    ...signed,
    headers: { ...signed.headers, signature: tampered.join(", ") },
  };
}

/** Minimal POST client: returns status, raw body, and response headers. */
function post(
  port: number,
  headers: Record<string, string | undefined>,
  body: string,
): Promise<{
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path: "/webhook",
        method: "POST",
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
            headers: res.headers,
          }),
        );
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

interface Harness {
  port: number;
  /** VerifyResults the business handler received, in arrival order. */
  calls: VerifyResult[];
  close: () => Promise<void>;
}

async function startServer(
  verifyOpts: VerifyOptions,
  handlerOpts?: CreateVerifiedHandlerOptions,
): Promise<Harness> {
  const calls: VerifyResult[] = [];
  const server = createServer(
    createVerifiedHandler(
      verifyOpts,
      (_req, res, result) => {
        calls.push(result);
        res.writeHead(200).end("ok");
      },
      handlerOpts,
    ),
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    calls,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}

/** The multi-label verifier both signers share: per-label keys. */
function multiLabelOpts(
  overrides: Partial<Omit<VerifyAllOptions, "label">> = {},
): Omit<VerifyAllOptions, "label"> {
  return {
    keys: {
      merchant: merchant.publicKey,
      gateway: gateway.publicKey,
    },
    requiredLabels: ["merchant", "gateway"],
    ...overrides,
  };
}

/** Single-label placeholder `verifyOpts`: valid, but unused per request in multi-label mode. */
const PLACEHOLDER_VERIFY_OPTS: VerifyOptions = {
  key: gateway.publicKey,
};

test("verified handler (multi-label): dual-signed request passes both labels and the handler gets per-label results", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    const signed = dualSignedPost(harness.port);
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 200);
    assert.equal(body, "ok");
    assert.equal(harness.calls.length, 1);
    const result = harness.calls[0];
    assert.equal(result.ok, true);
    // The aggregate has no single label: the per-label results carry
    // the signers.
    assert.equal(result.label, "");
    assert.equal(result.perLabelResults?.length, 2);
    assert.deepEqual(
      result.perLabelResults?.map((r) => r.label),
      ["merchant", "gateway"],
    );
    assert.deepEqual(
      result.perLabelResults?.map((r) => r.keyId),
      ["merchant-key", "gateway-key"],
    );
    for (const r of result.perLabelResults ?? [])
      assert.equal(r.ok, true, JSON.stringify(r));
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a tampered gateway signature is 401 and never reaches the business handler", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    const signed = tamperLabelSignature(
      dualSignedPost(harness.port),
      "gateway",
    );
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a tampered body fails both labels and is 401", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    const signed = dualSignedPost(harness.port, BODY);
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      TAMPERED_BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "BODY_DIGEST_MISMATCH",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a missing required label is 401 MISSING_REQUIRED_LABEL", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    // Only the merchant label is on the wire; the gateway co-signature
    // was stripped.
    const signed = merchantOnlyPost(harness.port);
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "MISSING_REQUIRED_LABEL",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): an unsigned request with required labels is 401 MISSING_REQUIRED_LABEL", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    const { status, body } = await post(
      harness.port,
      { "Content-Type": "application/json" },
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "MISSING_REQUIRED_LABEL",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): an unsigned request with no required labels is 401 MISSING_SIGNATURE_INPUT, never a vacuous pass", async () => {
  // No requiredLabels at all: strip the key (exactOptionalPropertyTypes
  // forbids passing `requiredLabels: undefined` explicitly).
  const { requiredLabels: _drop, ...noRequired } = multiLabelOpts();
  void _drop;
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: noRequired },
  );
  try {
    const { status, body } = await post(
      harness.port,
      { "Content-Type": "application/json" },
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "MISSING_SIGNATURE_INPUT",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): requiredLabels is a subset — only the gateway signature is required", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    {
      verifyAllLabels: multiLabelOpts({ requiredLabels: ["gateway"] }),
    },
  );
  try {
    // Merchant label absent entirely: only the gateway signature is
    // required, so the request still passes.
    const signed = signRequest(
      {
        method: "POST",
        url: `http://127.0.0.1:${harness.port}/webhook`,
        headers: { "content-type": "application/json" },
        body: BODY,
      },
      {
        keyId: "gateway-key",
        alg: "ed25519",
        key: gateway.privateKey,
        created: CREATED,
        label: "gateway",
      },
    );
    const { status } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 200);
    assert.equal(harness.calls.length, 1);
    assert.deepEqual(
      harness.calls[0].perLabelResults?.map((r) => r.label),
      ["gateway"],
    );
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a per-label keyid pin mismatch is 401", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    {
      verifyAllLabels: multiLabelOpts({
        expectedKeyIds: { gateway: "some-other-key" },
      }),
    },
  );
  try {
    const signed = dualSignedPost(harness.port);
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "KEYID_MISMATCH",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a wrong-key merchant signature is 401 and the gateway label alone cannot save it", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    { verifyAllLabels: multiLabelOpts() },
  );
  try {
    const merchantSigned = signRequest(
      {
        method: "POST",
        url: `http://127.0.0.1:${harness.port}/webhook`,
        headers: { "content-type": "application/json" },
        body: BODY,
      },
      {
        keyId: "merchant-key",
        alg: "ed25519",
        key: wrongKey.privateKey,
        created: CREATED,
        label: "merchant",
      },
    );
    const signed = addSignature(merchantSigned, {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gateway.privateKey,
      created: CREATED,
      label: "gateway",
    });
    const { status, body } = await post(
      harness.port,
      wireHeaders(signed),
      BODY,
    );
    assert.equal(status, 401);
    assert.deepEqual(JSON.parse(body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(harness.calls.length, 0);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): an illegal per-label configuration throws at creation time", () => {
  // Empty keyid pin: verifyAllLabels rejects it, and the handler must
  // surface that at build time, never on the first live request.
  assert.throws(
    () =>
      createVerifiedHandler(
        PLACEHOLDER_VERIFY_OPTS,
        (_req, res) => {
          res.writeHead(200).end("ok");
        },
        {
          verifyAllLabels: multiLabelOpts({
            expectedKeyIds: { gateway: "" },
          }),
        },
      ),
    /createVerifiedHandler: invalid verifyAllLabels: /,
  );
  // Duplicate required labels are a configuration error too.
  assert.throws(
    () =>
      createVerifiedHandler(
        PLACEHOLDER_VERIFY_OPTS,
        (_req, res) => {
          res.writeHead(200).end("ok");
        },
        {
          verifyAllLabels: multiLabelOpts({
            requiredLabels: ["gateway", "gateway"],
          }),
        },
      ),
    /createVerifiedHandler: invalid verifyAllLabels: /,
  );
  // An empty requiredLabels list is a caller mistake at the handler
  // entry (omit the field to require every label on the wire).
  assert.throws(
    () =>
      createVerifiedHandler(
        PLACEHOLDER_VERIFY_OPTS,
        (_req, res) => {
          res.writeHead(200).end("ok");
        },
        {
          verifyAllLabels: multiLabelOpts({ requiredLabels: [] }),
        },
      ),
    /createVerifiedHandler: invalid verifyAllLabels: .*must not be empty/,
  );
  // No key source anywhere (neither global nor per-label) fails fast.
  assert.throws(
    () =>
      createVerifiedHandler(
        PLACEHOLDER_VERIFY_OPTS,
        (_req, res) => {
          res.writeHead(200).end("ok");
        },
        { verifyAllLabels: { requiredLabels: ["gateway"] } },
      ),
    /createVerifiedHandler: invalid verifyAllLabels: .*must be provided/,
  );
  // A non-object verifyAllLabels fails fast.
  assert.throws(
    () =>
      createVerifiedHandler(
        PLACEHOLDER_VERIFY_OPTS,
        (_req, res) => {
          res.writeHead(200).end("ok");
        },
        // Deliberately wrong type: the runtime shape check must fire.
        { verifyAllLabels: "yes" as unknown as Omit<VerifyAllOptions, "label"> },
      ),
    /createVerifiedHandler: invalid verifyAllLabels: .*must be an object/,
  );
});

test("verified handler (multi-label): without verifyAllLabels the single-label behaviour is unchanged (regression #1016)", async () => {
  const harness = await startServer({ key: gateway.publicKey });
  try {
    const signed = signedPost(harness.port);
    const ok = await post(harness.port, wireHeaders(signed), BODY);
    assert.equal(ok.status, 200);
    assert.equal(harness.calls.length, 1);
    // The single-label result carries no per-label aggregate.
    assert.equal(harness.calls[0].perLabelResults, undefined);
    assert.equal(harness.calls[0].keyId, "gateway-key");

    const tampered = tamperLabelSignature(signedPost(harness.port), "sig1");
    const bad = await post(harness.port, wireHeaders(tampered), BODY);
    assert.equal(bad.status, 401);
    assert.deepEqual(JSON.parse(bad.body), {
      error: "signature verification failed",
      code: "SIGNATURE_MISMATCH",
    });
    assert.equal(harness.calls.length, 1);
  } finally {
    await harness.close();
  }
});

test("verified handler (multi-label): a 401 answer is never signed, a 200 answer is", async () => {
  const harness = await startServer(
    PLACEHOLDER_VERIFY_OPTS,
    {
      verifyAllLabels: multiLabelOpts(),
      signResponse: {
        key: merchant.privateKey,
        alg: "ed25519",
        keyId: "merchant-key",
        coveredComponents: ["@status"],
      },
    },
  );
  try {
    const tampered = tamperLabelSignature(
      dualSignedPost(harness.port),
      "gateway",
    );
    const rejected = await post(
      harness.port,
      wireHeaders(tampered),
      BODY,
    );
    assert.equal(rejected.status, 401);
    assert.equal(rejected.headers["signature-input"], undefined);
    assert.equal(rejected.headers["signature"], undefined);

    const signed = dualSignedPost(harness.port);
    const accepted = await post(harness.port, wireHeaders(signed), BODY);
    assert.equal(accepted.status, 200);
    assert.match(
      String(accepted.headers["signature-input"]),
      /sig1=\(/,
    );
  } finally {
    await harness.close();
  }
});
