/**
 * Client-side one-call helper: sign a request, fetch it, and verify
 * the signed response — the client twin of `createVerifiedHandler`
 * (backlog #1087).
 *
 * The server side already had the four-step receive path in one place
 * (`createVerifiedHandler`: buffer → adapt → verify → 401), but the
 * client side had no equivalent: a caller that wanted a signed
 * request and a verified response had to hand-roll `signRequest` +
 * `fetch` + `fromFetchResponse` + `verifyResponse` itself — the same
 * "four hand-written steps, easy to skip one" shape #1016 removed on
 * the server. `verifiedFetch` is that missing call: it signs the
 * request, performs the fetch, reads the response body under a cap,
 * adapts it with `fromFetchResponse`, and verifies it with
 * `verifyResponse`, in that order, so a missed step cannot let an
 * unverified response into the caller.
 *
 * What it returns, and what it throws:
 * - Success is `{ response, body, verifyResult }`: the raw fetch
 *   response (its body stream is already consumed — read `body`
 *   instead), the response body decoded as a UTF-8 string, and the
 *   `VerifyResult` (label / keyId / alg / nonce / tag / created /
 *   coveredComponents for audit). A non-2xx response is still
 *   verified and returned, never rejected on status alone: the
 *   signature is what decides trust, not the status code.
 * - A failed response verification throws `VerifyError` (same code /
 *   reason / label fields as `verifyRequestOrThrow`), so the caller
 *   never has to remember to check `verifyResult.ok`. This is a
 *   deliberate, documented split from the response API itself, which
 *   returns wire failures instead of throwing them: `verifiedFetch`
 *   is the caller's explicit opt-in to the throwing entry point.
 * - Caller configuration errors throw before any network happens:
 *   an invalid sign configuration (via `signRequest`), an invalid
 *   verify configuration (via the pre-flight dry run below), a bad
 *   `maxBodyBytes`, or a `verify.request` the caller tried to supply
 *   (the helper anchors `;req` to the request it just signed).
 * - Fetch-layer errors (DNS, connection refused, TLS, a GET with a
 *   body) pass through untouched, unwrapped.
 *
 * Honest scope limits (see also SECURITY.md):
 * - The body is returned as a string: binary bodies are out of
 *   scope. Verification itself always runs over the exact raw bytes
 *   (the `content-digest` check recomputes over them), so a lossy
 *   UTF-8 decode can never make an unverified body look verified —
 *   but a binary payload decoded this way is mangled, so use the
 *   four-step manual path (`signRequest` + `fetch` +
 *   `fromFetchResponse` + `verifyResponse`) when the body is not
 *   text.
 * - `maxBodyBytes` (default `DEFAULT_MAX_BODY_BYTES`, 1 MiB, the
 *   same value and semantics as `createVerifiedHandler`) bounds the
 *   response body before any verification runs: an over-long body is
 *   rejected, never truncated into a digest check. Over the stream
 *   path the reader is cancelled as soon as the cap is passed, so
 *   the peer cannot make the client buffer an unbounded body; the
 *   `arrayBuffer()` fallback (for doubles that expose no stream)
 *   reads fully and then enforces the cap, so it bounds what is
 *   verified but not what is buffered — prefer a real `Response`.
 * - This helper does not replace TLS, and the signing key stays the
 *   caller's: the key is never sent, logged, or stored here.
 * - A fetch `Response` carries no trailers, so a covered `;tr`
 *   component cannot verify through this helper, exactly as through
 *   `fromFetchResponse` — use `fromNodeResponse` when trailers
 *   matter.
 */

import {
  joinHeaderValues,
  type RequestLike,
} from "./components.js";
import { VerifyError } from "./errors.js";
import {
  DEFAULT_MAX_BODY_BYTES,
  fromFetchResponse,
  type FetchResponseLike,
} from "./nodeHttp.js";
import {
  verifyResponse,
  type VerifyResponseOptions,
} from "./response.js";
import { signRequest, type SignOptions } from "./sign.js";
import type { VerifyResult } from "./verify.js";

/**
 * Signing options for `verifiedFetch`: exactly the options
 * `signRequest` takes (`key` / `alg` / `label` / `keyId` /
 * `coveredComponents` / `created` / `expires` / `nonce` / `tag` /
 * `contentDigestAlg` / `structuredFieldTypes`), passed through
 * unchanged, so the request signature follows exactly the rules
 * `signRequest` documents — including its default covered components
 * (`@method`, `@authority`, `@path`, plus `content-digest` when the
 * request has a body).
 */
export type VerifiedFetchSignOptions = SignOptions;

/**
 * Verification options for `verifiedFetch`: exactly the options
 * `verifyResponse` takes, minus `request` — the helper supplies the
 * request it just signed, so callers never pass one (and a
 * caller-supplied request could bind the response signature to a
 * request nobody sent). Everything else (`key` / `keyResolver` /
 * `candidateKeys` / `expectedKeyId` / `expectedTag` / freshness
 * windows / `replayCache` / …) is passed through unchanged, so the
 * response verification follows exactly the rules `verifyResponse`
 * documents. To bind the response to the triggering request, the
 * peer covers a `;req` component (e.g. `"@method";req`); it resolves
 * against the request this call sent.
 */
export type VerifiedFetchVerifyOptions = Omit<
  VerifyResponseOptions,
  "request"
>;

/**
 * The `fetch()` `Response` fields `verifiedFetch` actually reads.
 * The global `fetch` (Node ≥ 20) returns objects satisfying this
 * shape; plain test doubles do too. `status` is required here (a
 * missing status is a fetch-layer defect, not a verifiable response),
 * and `body` is the web stream the cap is enforced over — a double
 * that exposes no stream falls back to `arrayBuffer()` (see
 * `readResponseBodyCapped`).
 */
export interface VerifiedFetchResponse extends FetchResponseLike {
  /** The response status code — the field a covered `@status` binds. */
  status: number;
  /** Read the whole body as bytes (fallback when `body` is absent). */
  arrayBuffer(): Promise<ArrayBuffer>;
  /**
   * The response body stream, when the implementation exposes one
   * (a real `fetch` `Response` always does, except for responses
   * with no body, where it is `null`). Typed as `Response["body"]`
   * — the same stream type the global `fetch` returns — so a real
   * `Response` always satisfies this interface and no structural
   * re-declaration can drift from it. Read through a reader so the
   * cap can stop the peer mid-body; `null` / absent means "no body
   * stream", and the helper falls back to `arrayBuffer()`.
   */
  body?: Response["body"];
}

/**
 * The `fetch()` implementation `verifiedFetch` calls. The global
 * `fetch` (Node ≥ 20) satisfies this shape; pass a double to test
 * without a network, or to point the call at a non-global transport.
 * Called as `fetchImpl(url, { method, headers, body })` with the
 * signed request's method, headers (including `signature-input` /
 * `signature` / `content-digest`), and body. `body` is omitted when
 * the request has none.
 */
export type VerifiedFetchFn = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string | Buffer },
) => Promise<VerifiedFetchResponse>;

/** The `fetch()` request `verifiedFetch` builds and signs. */
export interface VerifiedFetchInit {
  /** HTTP method. Defaults to `"GET"`. */
  method?: string;
  /**
   * Request headers: a `Headers` instance or a record (same
   * conventions as `RequestLike.headers`). Signature headers are
   * added by the signing step; a caller-supplied `signature-input`
   * / `signature` header is overwritten, never merged.
   */
  headers?: Headers | Record<string, string | string[] | undefined>;
  /** Request body. Defaults to none. */
  body?: string | Buffer;
}

export interface VerifiedFetchOptions {
  /**
   * Signing options for the outgoing request (required — a
   * `verifiedFetch` call that does not sign is a plain `fetch`).
   */
  sign: VerifiedFetchSignOptions;
  /**
   * Verification options for the response (required — a
   * `verifiedFetch` call that does not verify is a plain `fetch`).
   */
  verify: VerifiedFetchVerifyOptions;
  /**
   * The fetch implementation to call. Defaults to the global
   * `fetch`. Inject a double to test without a network.
   */
  fetchImpl?: VerifiedFetchFn;
  /**
   * Maximum response body size in bytes. A body larger than this is
   * rejected before any verification runs — the digest is never
   * computed over a truncated body. Defaults to
   * `DEFAULT_MAX_BODY_BYTES` (1 MiB, the same value as
   * `createVerifiedHandler`). Must be a positive integer; anything
   * else throws a configuration `Error` at call time, before any
   * network happens. A body exactly at the cap still verifies.
   */
  maxBodyBytes?: number;
}

/** What a successful `verifiedFetch` call returns. */
export interface VerifiedFetchResult {
  /**
   * The raw fetch response, for status / headers access. Its body
   * stream is already consumed by the helper — read `body` below,
   * do not call `arrayBuffer()` / `text()` on it again.
   */
  response: VerifiedFetchResponse;
  /** The response body decoded as a UTF-8 string (see module docstring: binary bodies are out of scope). */
  body: string;
  /**
   * The response verification result. `ok` is always `true` here —
   * a failed verification throws `VerifyError` instead of returning
   * (see the module docstring). `label` / `keyId` / `alg` /
   * `nonce` / `tag` / `created` / `coveredComponents` are available
   * for logging and audit.
   */
  verifyResult: VerifyResult;
}

/**
 * Synthetic unsigned response the verify pre-flight checks against.
 * It is never sent anywhere and carries no signature headers: it
 * only exists so `verifyResponse` runs every configuration
 * assertion it would run for a real response (key selection,
 * candidate lists, freshness windows, header limits, required
 * components, allowed algorithms, Structured Field types, clock
 * options) before returning `MISSING_SIGNATURE_INPUT` — without
 * touching the key resolver or the replay cache, which are only
 * consulted once a signature header parses. Mirrors
 * `VERIFY_OPTIONS_VALIDATION_REQUEST` in `nodeHttp.ts`, on the
 * response side.
 */
const VERIFY_OPTIONS_VALIDATION_RESPONSE = {
  status: 200,
  headers: {},
} as const;

/**
 * Validate `opts.verify` at call time, before any network happens —
 * the same level as the `maxBodyBytes` check and the `signRequest`
 * call that precedes the fetch: a misconfigured verifier must fail
 * here, never after the peer has already answered (where it would
 * surface as a `VerifyError` on a response the caller already paid
 * to fetch, or — worse — as a verification that never ran). The
 * exact verify path the helper will use is dry-run once — a
 * `verifyResponse` over the synthetic unsigned response above, with
 * the request this call just signed attached as `request` — so every
 * configuration check `verifyResponse` runs is exercised here, and
 * the expected `MISSING_SIGNATURE_INPUT` result is swallowed.
 *
 * One check cannot ride the dry run: `verifyRequest` only throws
 * "one of `key`, `keyResolver`, or `candidateKeys` must be provided"
 * after a signature header parses, so an unsigned response never
 * reaches it — a verifier with no key source at all is checked
 * explicitly here, with the same wording `verifyRequest` uses, so it
 * still fails at call time.
 *
 * The dry run has no side effects: it never calls the key resolver
 * and never touches the replay cache.
 */
function assertVerifyOptionsPreflight(
  verifyOpts: VerifiedFetchVerifyOptions,
  request: RequestLike,
): void {
  try {
    if (
      verifyOpts.key === undefined &&
      verifyOpts.keyResolver === undefined &&
      verifyOpts.candidateKeys === undefined
    )
      throw new Error(
        "verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided",
      );
    const result = verifyResponse(
      {
        status: VERIFY_OPTIONS_VALIDATION_RESPONSE.status,
        headers: { ...VERIFY_OPTIONS_VALIDATION_RESPONSE.headers },
      },
      { ...verifyOpts, request },
    );
    if (result.ok || result.code !== "MISSING_SIGNATURE_INPUT")
      throw new Error(
        `dry-run verification returned unexpected result: ${result.ok ? "ok" : result.code ?? "no code"}`,
      );
  } catch (e) {
    if (
      e instanceof Error &&
      e.message.startsWith("verifiedFetch: invalid verify options:")
    )
      throw e;
    throw new Error(
      `verifiedFetch: invalid verify options: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/**
 * Normalize an init `Headers` instance into the `RequestLike.headers`
 * record shape: names lowercased, entries grouped by name, each group
 * combined via `joinHeaderValues` — the exact convention
 * `fromFetchResponse` applies to a `Response`'s headers, so a header
 * the caller passes as a `Headers` instance and the same header as
 * the peer returns it can never diverge on multi-value fields.
 */
function normalizeInitHeaders(
  headers: Headers | Record<string, string | string[] | undefined>,
): Record<string, string | string[] | undefined> {
  if (headers instanceof Headers) {
    const grouped = new Map<string, string[]>();
    for (const [name, value] of headers.entries()) {
      const lower = name.toLowerCase();
      const list = grouped.get(lower);
      if (list) list.push(value);
      else grouped.set(lower, [value]);
    }
    const out: Record<string, string> = {};
    for (const [name, values] of grouped) {
      out[name] = joinHeaderValues(values);
    }
    return out;
  }
  return headers as Record<string, string | string[] | undefined>;
}

/**
 * Read the response body under the cap, as exact raw bytes.
 *
 * Over the stream path the reader is cancelled as soon as the
 * accumulated size passes `maxBodyBytes`, so the peer cannot make
 * the client buffer an unbounded body — the buffered prefix is
 * discarded and the cap error thrown, before any verification runs.
 * When the response exposes no body stream (`body` null or absent —
 * a bodyless response, or a double that only implements
 * `arrayBuffer()`), the whole body is read and the cap enforced
 * after: the cap still bounds what is verified, never what is
 * buffered, so a real `Response` is preferred for untrusted peers.
 * A body exactly at the cap is accepted.
 */
async function readResponseBodyCapped(
  res: VerifiedFetchResponse,
  maxBodyBytes: number,
): Promise<Buffer> {
  const stream = res.body;
  if (stream !== undefined && stream !== null) {
    const reader = stream.getReader();
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value === undefined) continue;
        const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
        size += buf.length;
        if (size > maxBodyBytes) {
          await reader.cancel();
          throw new Error(
            `verifiedFetch: response body exceeds maxBodyBytes (${maxBodyBytes} bytes); the body is rejected before verification, not truncated`,
          );
        }
        chunks.push(buf);
      }
    } finally {
      reader.releaseLock();
    }
    return Buffer.concat(chunks);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBodyBytes)
    throw new Error(
      `verifiedFetch: response body exceeds maxBodyBytes (${maxBodyBytes} bytes); the body is rejected before verification, not truncated`,
    );
  return buf;
}

/**
 * Sign a request, fetch it, and verify the signed response — one
 * call for the whole client round-trip.
 *
 * Steps, in order: build the request from `input` + `init`; sign it
 * with `signRequest` (`opts.sign`); validate the verifier with the
 * pre-flight dry run (`opts.verify`); fetch it (`opts.fetchImpl`,
 * defaulting to the global `fetch`); read the response body under
 * `opts.maxBodyBytes`; adapt it with `fromFetchResponse` (the request
 * just signed attached as `request`, so covered `;req` components
 * bind the response signature to it); verify it with
 * `verifyResponse`. Returns `{ response, body, verifyResult }` on a
 * verified response; throws `VerifyError` on a failed verification.
 *
 * Fail-fast configuration errors (thrown, before any network):
 * everything `signRequest` already rejects, plus a verifier with no
 * key source or any other misconfiguration the dry run catches, a
 * non-positive-integer `maxBodyBytes`, and a caller-supplied
 * `verify.request` (managed by this helper — pass no `request`).
 * Fetch-layer errors pass through untouched. See the module
 * docstring for the full contract (non-2xx, binary bodies, the body
 * cap, trailers).
 */
export async function verifiedFetch(
  input: string | URL,
  init: VerifiedFetchInit | undefined,
  opts: VerifiedFetchOptions,
): Promise<VerifiedFetchResult> {
  if (opts === null || typeof opts !== "object")
    throw new Error(
      `verifiedFetch: opts must be an object, got ${opts === null ? "null" : typeof opts}`,
    );
  if (opts.sign === null || typeof opts.sign !== "object")
    throw new Error(
      `verifiedFetch: opts.sign (SignOptions) is required, got ${opts.sign === null ? "null" : typeof opts.sign}`,
    );
  if (opts.verify === null || typeof opts.verify !== "object")
    throw new Error(
      `verifiedFetch: opts.verify (VerifyResponseOptions) is required, got ${opts.verify === null ? "null" : typeof opts.verify}`,
    );
  if (opts.fetchImpl !== undefined && typeof opts.fetchImpl !== "function")
    throw new Error(
      `verifiedFetch: opts.fetchImpl must be a function, got ${typeof opts.fetchImpl}`,
    );
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0)
    throw new Error(
      `verifiedFetch: maxBodyBytes must be a positive integer number of bytes, got ${String(opts.maxBodyBytes)}`,
    );
  // `verify.request` is managed by this helper: the response is
  // anchored to the request this call just signed. A caller-supplied
  // request could bind the signature to a request nobody sent, so
  // it is a configuration error, not a silent override — the type
  // already omits it (`VerifiedFetchVerifyOptions`), this guard is
  // for JavaScript callers.
  if (
    (opts.verify as VerifyResponseOptions).request !== undefined
  )
    throw new Error(
      'verifiedFetch: "verify.request" is managed by verifiedFetch — the response is anchored to the request this call just signed; pass no request',
    );

  const url = input.toString();
  const method = init?.method ?? "GET";
  const headers: Record<string, string | string[] | undefined> =
    init?.headers !== undefined
      ? normalizeInitHeaders(init.headers)
      : {};
  const request: RequestLike = {
    method,
    url,
    headers,
    ...(init?.body !== undefined ? { body: init.body } : {}),
  };

  // Signs first, so an invalid sign configuration throws before any
  // network happens — and the signed request is what the response
  // verification anchors `;req` components to.
  const signed = signRequest(request, opts.sign);

  // Verifier pre-flight, also before any network: a misconfigured
  // verifier throws here, never after the peer has answered.
  assertVerifyOptionsPreflight(opts.verify, signed);

  const fetchImpl: VerifiedFetchFn =
    opts.fetchImpl ??
    (async (url, init) => {
      // The global fetch's `BodyInit` does not accept a `Buffer`
      // directly under this project's `ArrayBuffer` generics, so a
      // Buffer body is copied into a plain `Uint8Array` over a fresh
      // `ArrayBuffer` — the same bytes, a type the fetch init
      // accepts.
      const body =
        init.body === undefined
          ? undefined
          : typeof init.body === "string"
            ? init.body
            : new Uint8Array(init.body);
      return fetch(url, {
        method: init.method,
        headers: init.headers,
        ...(body !== undefined ? { body } : {}),
      });
    });
  const res = await fetchImpl(url, {
    method: signed.method,
    headers: signed.headers,
    ...(signed.body !== undefined ? { body: signed.body } : {}),
  });

  const bodyBuf = await readResponseBodyCapped(res, maxBodyBytes);

  // `fromFetchResponse` normalizes the fetch headers and binds the
  // signed request as the triggering request; `verifyResponse` gets
  // the same request as its `request` option, so a covered `;req`
  // component resolves against what this call actually sent. The
  // spread pins a definite status (the adapter validated it is an
  // integer 100-599) for the `HttpResponseLike` shape.
  const resLike = fromFetchResponse(res, bodyBuf, { request: signed });
  const verifyResult = verifyResponse(
    { ...resLike, status: res.status },
    { ...opts.verify, request: signed },
  );
  if (!verifyResult.ok)
    throw new VerifyError(
      verifyResult.code ?? "VERIFICATION_ERROR",
      verifyResult.reason ?? "verification failed",
      {
        label: verifyResult.label,
        keyId: verifyResult.keyId,
        alg: verifyResult.alg,
        nonce: verifyResult.nonce,
        tag: verifyResult.tag,
        created: verifyResult.created,
        expires: verifyResult.expires,
      },
    );

  return {
    response: res,
    body: bodyBuf.toString("utf8"),
    verifyResult,
  };
}
