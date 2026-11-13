import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  generateEd25519KeyPair,
  isVerifyError,
  signResponse,
  verifiedFetch,
  type SignedHttpResponse,
  type VerifiedFetchFn,
  type VerifiedFetchResponse,
  type VerifiedFetchSignOptions,
  type VerifiedFetchVerifyOptions,
} from "../src/index.js";

// Backlog #1112: `verifiedFetch` had no cancellation — `VerifiedFetchInit`
// carried no `signal`, the default fetch wrapper forwarded only
// method/headers/body, and an injected `fetchImpl` never received one,
// so a hung peer left the call unsettled forever while the sibling
// server side (`deliverSettlementWebhook`, #112) already had a signal.
// These cases pin the signal end to end: pre-abort fail-fast with
// zero fetch calls, illegal signal values, the signal reaching the
// injected and the default fetch, in-flight abort passing the fetch's
// own abort error through, and body-stream abort cancelling the
// reader instead of verifying a partial body.

const CREATED = 1700000000;
const NOW = CREATED + 60;
const REQ_BODY = JSON.stringify({ amount: 100, currency: "USD" });
const RES_BODY = JSON.stringify({ status: "settled", amount: 100 });

const clientKeys = generateEd25519KeyPair();
const gatewayKeys = generateEd25519KeyPair();

async function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        // A hung peer holds its socket open: destroy in-flight
        // connections so the test process can exit.
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function signGatewayResponse(body?: string, status = 200): SignedHttpResponse {
  return signResponse(
    {
      status,
      headers: { "content-type": "application/json" },
      ...(body !== undefined ? { body } : {}),
    },
    {
      keyId: "gateway-key",
      alg: "ed25519",
      key: gatewayKeys.privateKey,
      created: CREATED,
    },
  );
}

function signOpts(): VerifiedFetchSignOptions {
  return {
    keyId: "client-key",
    alg: "ed25519",
    key: clientKeys.privateKey,
    created: CREATED,
  };
}

function verifyOpts(): VerifiedFetchVerifyOptions {
  return { key: gatewayKeys.publicKey, now: NOW };
}

/**
 * Guard a call that must settle via the abort: if the implementation
 * ignored the signal the call would hang forever, so the test fails
 * on a timeout instead of hanging the suite.
 */
async function withSettleGuard<T>(
  promise: Promise<T>,
  what: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`timed out: abort did not end ${what}`)),
      5000,
    );
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

test("verifiedFetch: pre-aborted signal throws before any network, zero fetch calls", async () => {
  let calls = 0;
  const fetchImpl: VerifiedFetchFn = async () => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY, signal: controller.signal },
      { sign: signOpts(), verify: verifyOpts(), fetchImpl },
    ),
    /verifiedFetch: request aborted/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: non-AbortSignal signal value throws before fetch", async () => {
  let calls = 0;
  const fetchImpl: VerifiedFetchFn = async () => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  for (const bad of ["not-a-signal", 42, {}, { aborted: false }]) {
    await assert.rejects(
      verifiedFetch(
        "http://127.0.0.1:9/echo",
        {
          method: "POST",
          body: REQ_BODY,
          signal: bad as unknown as AbortSignal,
        },
        { sign: signOpts(), verify: verifyOpts(), fetchImpl },
      ),
      /init\.signal must be an AbortSignal/,
    );
  }
  assert.equal(calls, 0);
});

test("verifiedFetch: non-aborted signal round-trips normally over an injected fetchImpl", async () => {
  const signed = signGatewayResponse(RES_BODY);
  const controller = new AbortController();
  let seenSignal: AbortSignal | undefined;
  const fetchImpl: VerifiedFetchFn = async (_url, init) => {
    seenSignal = init.signal;
    assert.equal(init.method, "POST");
    assert.match(init.headers["signature-input"] ?? "", /sig1=\(/);
    return {
      status: 200,
      headers: new Headers(signed.headers),
      arrayBuffer: async () => new ArrayBuffer(0),
      body: new ReadableStream<Uint8Array<ArrayBuffer>>({
        start(c) {
          c.enqueue(new TextEncoder().encode(RES_BODY));
          c.close();
        },
      }),
    };
  };
  const result = await verifiedFetch(
    "https://gateway.example/v1/settlement",
    { method: "POST", body: REQ_BODY, signal: controller.signal },
    { sign: signOpts(), verify: verifyOpts(), fetchImpl },
  );
  assert.equal(result.body, RES_BODY);
  assert.equal(result.verifyResult.ok, true);
  assert.equal(result.verifyResult.keyId, "gateway-key");
  // The injected implementation received the very signal the caller
  // passed — it is not a copy, so aborting it later still cancels
  // anything the implementation is doing with it.
  assert.equal(seenSignal, controller.signal);
});

test("verifiedFetch: in-flight abort ends a hung fetchImpl fast with the abort error, not a VerifyError", async () => {
  const controller = new AbortController();
  const fetchImpl: VerifiedFetchFn = async (_url, init) => {
    assert.equal(init.signal, controller.signal);
    // Hang until the signal fires, then reject with the signal's
    // own reason — what a real fetch does on abort.
    await new Promise<never>((_resolve, reject) => {
      controller.signal.addEventListener(
        "abort",
        () => reject(controller.signal.reason),
        { once: true },
      );
    });
    throw new Error("unreachable");
  };
  const started = Date.now();
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(
    withSettleGuard(
      verifiedFetch(
        "http://127.0.0.1:9/echo",
        { method: "POST", body: REQ_BODY, signal: controller.signal },
        { sign: signOpts(), verify: verifyOpts(), fetchImpl },
      ),
      "the hung fetchImpl",
    ),
    (e: unknown) => {
      assert.ok(e instanceof Error, "must throw an Error");
      assert.equal(e.name, "AbortError");
      assert.ok(!isVerifyError(e), "an abort is not a verification failure");
      return true;
    },
  );
  // Fast: the call ended on the abort (~10ms), it did not wait out
  // any fetch or verification timeout.
  assert.ok(Date.now() - started < 5000, "abort must end the call quickly");
});

test("verifiedFetch: abort while the body streams cancels the reader and throws the abort reason", async () => {
  const controller = new AbortController();
  let cancelled = false;
  let pulls = 0;
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    pull() {
      pulls++;
      // Never enqueue: the read waits until the signal aborts.
      return new Promise<void>(() => {});
    },
    cancel() {
      cancelled = true;
    },
  });
  const fetchImpl: VerifiedFetchFn = async () => ({
    status: 200,
    headers: new Headers(signGatewayResponse(RES_BODY).headers),
    arrayBuffer: async () => new ArrayBuffer(0),
    body: stream,
  });
  const started = Date.now();
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(
    withSettleGuard(
      verifiedFetch(
        "http://127.0.0.1:9/echo",
        { method: "POST", body: REQ_BODY, signal: controller.signal },
        { sign: signOpts(), verify: verifyOpts(), fetchImpl },
      ),
      "the hung body stream",
    ),
    (e: unknown) => {
      assert.ok(e instanceof Error, "must throw an Error");
      assert.equal(e.name, "AbortError");
      assert.ok(!isVerifyError(e), "an abort is not a verification failure");
      return true;
    },
  );
  assert.ok(Date.now() - started < 5000, "abort must end the body read quickly");
  assert.equal(cancelled, true, "the reader must be cancelled on abort");
  // Exactly one pull: the aborted read never retried, and no further
  // chunk was requested after the abort.
  assert.equal(pulls, 1);
});

test("verifiedFetch: abort during the body read wins over a bad signature — no VerifyError", async () => {
  const controller = new AbortController();
  // The response is signed over the true body but the stream only
  // ever yields a tampered first chunk, then hangs: without the
  // abort this would end in BODY_DIGEST_MISMATCH, with it the abort
  // must win — verification never runs over a partial body.
  const tampered = JSON.stringify({ status: "settled", amount: 10001 });
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    start(c) {
      c.enqueue(new TextEncoder().encode(tampered));
    },
    pull() {
      return new Promise<void>(() => {});
    },
  });
  const fetchImpl: VerifiedFetchFn = async () => ({
    status: 200,
    headers: new Headers(signGatewayResponse(RES_BODY).headers),
    arrayBuffer: async () => new ArrayBuffer(0),
    body: stream,
  });
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(
    withSettleGuard(
      verifiedFetch(
        "http://127.0.0.1:9/echo",
        { method: "POST", body: REQ_BODY, signal: controller.signal },
        { sign: signOpts(), verify: verifyOpts(), fetchImpl },
      ),
      "the hung body stream",
    ),
    (e: unknown) => {
      assert.ok(e instanceof Error, "must throw an Error");
      assert.equal(e.name, "AbortError");
      assert.ok(!isVerifyError(e), "verification must not run on abort");
      return true;
    },
  );
});

test("verifiedFetch: default global fetch passes the signal through — a hung loopback server aborts fast", async () => {
  const { baseUrl, close } = await listen((_req, _res) => {
    // Never respond: the peer hangs, so only the signal can end it.
  });
  try {
    const controller = new AbortController();
    const started = Date.now();
    setTimeout(() => controller.abort(), 10);
    await assert.rejects(
      withSettleGuard(
        verifiedFetch(
          `${baseUrl}/hang`,
          { method: "GET", signal: controller.signal },
          { sign: signOpts(), verify: verifyOpts() },
        ),
        "the hung loopback fetch",
      ),
      (e: unknown) => {
        assert.ok(e instanceof Error, "must throw an Error");
        assert.equal(e.name, "AbortError");
        assert.ok(!isVerifyError(e), "an abort is not a verification failure");
        return true;
      },
    );
    assert.ok(Date.now() - started < 5000, "abort must end the default fetch quickly");
  } finally {
    await close();
  }
});

test("verifiedFetch: default global fetch round-trips normally with a non-aborted signal", async () => {
  const { baseUrl, close } = await listen((_req, res) => {
    const signed = signGatewayResponse(RES_BODY);
    res.writeHead(signed.status, {
      "content-type": "application/json",
      ...(signed.headers["content-digest"] !== undefined
        ? { "content-digest": signed.headers["content-digest"] }
        : {}),
      ...(signed.headers["signature-input"] !== undefined
        ? { "signature-input": signed.headers["signature-input"] }
        : {}),
      ...(signed.headers["signature"] !== undefined
        ? { signature: signed.headers["signature"] }
        : {}),
    });
    res.end(RES_BODY);
  });
  try {
    const controller = new AbortController();
    const result = await verifiedFetch(
      `${baseUrl}/status`,
      { method: "GET", signal: controller.signal },
      { sign: signOpts(), verify: verifyOpts() },
    );
    assert.equal(result.body, RES_BODY);
    assert.equal(result.verifyResult.ok, true);
    assert.equal(result.verifyResult.keyId, "gateway-key");
  } finally {
    await close();
  }
});

test("verifiedFetch: pre-aborted signal also fails fast in multi-label mode, zero fetch calls", async () => {
  let calls = 0;
  const fetchImpl: VerifiedFetchFn = async () => {
    calls++;
    throw new Error("fetchImpl must not be called");
  };
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    verifiedFetch(
      "http://127.0.0.1:9/echo",
      { method: "POST", body: REQ_BODY, signal: controller.signal },
      {
        sign: signOpts(),
        verify: {
          verifyAllLabels: {
            keys: { sig1: gatewayKeys.publicKey },
            now: NOW,
          },
        },
        fetchImpl,
      },
    ),
    /verifiedFetch: request aborted/,
  );
  assert.equal(calls, 0);
});

test("verifiedFetch: aborting after a successful fetch but before the body read still throws AbortError", async () => {
  const controller = new AbortController();
  const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
    pull() {
      // The body never arrives: the read waits until the abort.
      return new Promise<void>(() => {});
    },
  });
  const fetchImpl: VerifiedFetchFn = async () => ({
    status: 200,
    headers: new Headers(signGatewayResponse(RES_BODY).headers),
    arrayBuffer: async () => new ArrayBuffer(0),
    body: stream,
  });
  // Abort only after the fetch has resolved: the fetch itself
  // completed, the abort lands on the body read.
  const promise = verifiedFetch(
    "http://127.0.0.1:9/echo",
    { method: "POST", body: REQ_BODY, signal: controller.signal },
    { sign: signOpts(), verify: verifyOpts(), fetchImpl },
  );
  await new Promise((resolve) => setTimeout(resolve, 50));
  controller.abort();
  await assert.rejects(
    withSettleGuard(promise, "the hung body stream"),
    (e: unknown) => {
      assert.ok(e instanceof Error, "must throw an Error");
      assert.equal(e.name, "AbortError");
      return true;
    },
  );
});
