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
 *   In multi-label mode (`verify.verifyAllLabels`, backlog #1105)
 *   the thrown error carries the first failing label's code /
 *   reason / label, with the full per-label array attached as
 *   `verifyResults` — a bad gateway signature never hides the
 *   merchant signature that verified — and a successful call
 *   returns the same array as `verifyResults`, with `verifyResult`
 *   as the aggregate (`ok: true`, empty `label`, `perLabelResults`),
 *   exactly as `createVerifiedHandler` reports it.
 * - Caller configuration errors throw before any network happens:
 *   an invalid sign configuration (via `signRequest`), an invalid
 *   verify configuration (via the pre-flight dry run below), a bad
 *   `maxBodyBytes`, or a `verify.request` the caller tried to supply
 *   (the helper anchors `;req` to the request it just signed). In
 *   multi-label mode, an illegal label policy — an empty,
 *   duplicate, or non-string `requiredLabels` entry, no key source
 *   at all, or a verification option left on the outer `verify`
 *   object — likewise throws before any network happens.
 * - Fetch-layer errors (DNS, connection refused, TLS, a GET with a
 *   body) pass through untouched, unwrapped.
 * - Cancellation: pass an `AbortSignal` as `init.signal` — the same
 *   signal the request is sent with and the body is read under. A
 *   signal already aborted throws `verifiedFetch: request aborted`
 *   before any network happens (the `verifiedFetch` wording of the
 *   `webhook delivery aborted` shape `deliverSettlementWebhook`
 *   uses, backlog #112); an abort while the fetch is in flight
 *   passes the fetch's own abort error through untouched, never
 *   wrapped as a verification failure; an abort while the response
 *   body is streaming cancels the reader and throws the signal's
 *   abort reason. A non-`AbortSignal` value is a configuration
 *   error, thrown before any network happens.
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
  verifyAllResponseLabels,
  verifyResponse,
  type VerifyAllResponseOptions,
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
 *
 * Multi-label responses (backlog #1105): set `verifyAllLabels` to
 * verify every signature on the response with
 * `verifyAllResponseLabels` instead — the client-side mirror of the
 * `createVerifiedHandler` multi-label mode (#1090), for the
 * merchant-ed25519-signs / gateway-hmac-appends settlement flow.
 * The value is exactly the `VerifyAllResponseOptions` the response
 * API takes, minus `request` (anchored by this helper as above):
 * per-label keys / resolvers / candidate lists (`keys` /
 * `keyResolvers` / `candidateKeysByLabel`), per-label freshness
 * windows and pins, and `requiredLabels` — the label list: every
 * label named there that never appears on the wire is a synthetic
 * `MISSING_REQUIRED_LABEL` failure, so a stripped co-signature can
 * never pass. The mode is fail-closed: every label must pass, and
 * the first failing label's code / reason / label is thrown as the
 * `VerifyError`, with the full per-label array attached to the error
 * as `verifyResults` (and to a successful result as `verifyResults`)
 * so a bad gateway signature never hides the merchant signature
 * that verified. An unsigned response in this mode yields no results
 * at all, which must not pass vacuously — it throws
 * `MISSING_SIGNATURE_INPUT` like the single-label path. A caller
 * that sets `verifyAllLabels` must put *every* verification option
 * inside it: any other field on the outer `verify` object (`key`,
 * `now`, …) is rejected as a configuration error before any network
 * happens, because it would otherwise be silently ignored — the
 * multi-label options object is self-contained, exactly as in
 * `createVerifiedHandler`.
 */
export type VerifiedFetchVerifyOptions = Omit<
  VerifyResponseOptions,
  "request"
> & {
  /**
   * Multi-label verification options. When present, the response is
   * verified with `verifyAllResponseLabels` (see the
   * `VerifiedFetchVerifyOptions` documentation); when absent, the
   * existing single-label `verifyResponse` behavior is unchanged.
   */
  verifyAllLabels?: Omit<VerifyAllResponseOptions, "request">;
};

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
 * Called as `fetchImpl(url, { method, headers, body, signal })` with the
 * signed request's method, headers (including `signature-input` /
 * `signature` / `content-digest`), and body. `body` is omitted when
 * the request has none; `signal` is the caller's `init.signal` when
 * one was passed, so an implementation that honors it can stop a
 * hung request — an implementation that ignores its signal cannot be
 * force-stopped by the caller.
 */
export type VerifiedFetchFn = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string | Buffer; signal?: AbortSignal },
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
  /**
   * Abort signal for the whole call (backlog #1112): forwarded to
   * the fetch implementation — the default global `fetch` and any
   * injected `fetchImpl` receive it — and watched while the
   * response body streams. A signal already aborted throws
   * `verifiedFetch: request aborted` before any network happens; an
   * abort in flight passes the fetch's abort error through
   * untouched; an abort while the body streams cancels the reader
   * and throws the signal's abort reason. Must be an `AbortSignal`
   * when present; anything else is a configuration error, thrown
   * before any network happens.
   */
  signal?: AbortSignal;
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
   * for logging and audit. In multi-label mode (`verify.verifyAllLabels`)
   * this is the aggregate result — `ok: true`, an empty `label` (no
   * single label owns it), and `perLabelResults` carrying each
   * label's own result, exactly as `createVerifiedHandler` reports
   * it; read `verifyResults` for the per-label array directly.
   */
  verifyResult: VerifyResult;
  /**
   * Per-label verification results, in wire order — set only in
   * multi-label mode (`verify.verifyAllLabels`). Each entry is one
   * label's own `VerifyResult` (`label` / `keyId` / `alg` /
   * `nonce` / `tag` / `created` / `coveredComponents`), so the
   * caller can audit every signer (merchant and gateway) without
   * re-parsing the `signature-input` header. Absent in single-label
   * mode, where `verifyResult` alone carries the one result.
   */
  verifyResults?: VerifyResult[];
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
 * Synthetic signed response the multi-label verify pre-flight checks
 * against. It is never sent anywhere: it only exists so
 * `verifyAllResponseLabels` runs every configuration assertion it
 * would run for a real response (per-label key selection, candidate
 * lists, freshness windows, header limits, required components,
 * Structured Field types, clock options) before returning failure
 * results for the bogus all-zero signature — without touching the
 * replay cache, which is only consulted for a signature carrying a
 * nonce. Mirrors `VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE_INPUT` /
 * `VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE` in `nodeHttp.ts`, on the
 * response side: the canned `signature-input` covers `@status` only
 * (no `;req`, so no triggering request is needed for the dry run),
 * and the label is swapped for the dry-run label below.
 */
const VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE_INPUT =
  'dryrun=("@status");created=1700000000';
const VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE =
  "dryrun=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:";

/**
 * Pick the label the multi-label dry run signs as: the first
 * required label when one is named (a required label with no key
 * source must fail the pre-flight, not the first live call), else
 * the first label named in a per-label key map, else `"dryrun"`.
 * Mirrors `dryRunLabelForVerifyAll` in `nodeHttp.ts`.
 */
function dryRunLabelForVerifyAllResponse(
  allOpts: Omit<VerifyAllResponseOptions, "request">,
): string {
  if (allOpts.requiredLabels !== undefined && allOpts.requiredLabels.length > 0)
    return allOpts.requiredLabels[0] as string;
  for (const map of [
    allOpts.keys,
    allOpts.keyResolvers,
    allOpts.candidateKeysByLabel,
  ]) {
    if (map !== undefined) {
      const first = Object.keys(map)[0];
      if (first !== undefined) return first;
    }
  }
  return "dryrun";
}

/**
 * Validate `opts.verify.verifyAllLabels` at call time, before any
 * network happens — the multi-label twin of
 * `assertVerifyOptionsPreflight`, mirroring `assertVerifyAllOptions`
 * in `nodeHttp.ts` for the client side. A misconfigured multi-label
 * verifier must fail here, never after the peer has already answered
 * (where it would surface as a `VerifyError` on a response the
 * caller already paid to fetch, or — worse — as a verification that
 * never ran). The exact verify path the helper will use is dry-run
 * once — a `verifyAllResponseLabels` over the synthetic signed
 * response above, with the request this call just signed attached
 * as `request` — so every configuration check
 * `verifyAllResponseLabels` / `verifyRequest` runs is exercised
 * here, and the expected failure results are swallowed.
 *
 * Three checks cannot ride the dry run and are explicit, with the
 * same wording the response / handler side uses: a verifier with no
 * key source at all; an empty `requiredLabels` (omit it to require
 * every label present on the wire); and any verification option left
 * on the outer `verify` object, which the multi-label path never
 * reads — silently ignoring a caller's `key` or `now` would be worse
 * than rejecting it.
 *
 * The dry run has one accepted side effect: a `keyResolver` for the
 * dry-run label may be consulted once for the bogus signature, as in
 * the handler's dry run. It never touches the replay cache (the
 * canned signature carries no nonce).
 */
function assertVerifyAllOptionsPreflight(
  verifyOpts: VerifiedFetchVerifyOptions,
  request: RequestLike,
): void {
  try {
    const allOpts = verifyOpts.verifyAllLabels;
    if (allOpts === null || typeof allOpts !== "object")
      throw new Error(
        `verifyAllLabels must be an object, got ${allOpts === null ? "null" : typeof allOpts}`,
      );
    const outerKeys = Object.keys(verifyOpts).filter(
      (k) => k !== "verifyAllLabels",
    );
    if (outerKeys.length > 0)
      throw new Error(
        `verifyAllLabels is set: pass every verification option inside verifyAllLabels — ` +
          `outer verify option${outerKeys.length === 1 ? "" : "s"} ${outerKeys.map((k) => `"${k}"`).join(", ")} ${outerKeys.length === 1 ? "is" : "are"} never read in multi-label mode`,
      );
    if (
      allOpts.key === undefined &&
      allOpts.keyResolver === undefined &&
      allOpts.candidateKeys === undefined &&
      allOpts.keys === undefined &&
      allOpts.keyResolvers === undefined &&
      allOpts.candidateKeysByLabel === undefined
    )
      throw new Error(
        "verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided",
      );
    if (
      allOpts.requiredLabels !== undefined &&
      allOpts.requiredLabels.length === 0
    )
      throw new Error(
        "verifyAllLabels: `requiredLabels` must not be empty — omit it to require every label present on the wire",
      );
    const label = dryRunLabelForVerifyAllResponse(allOpts);
    const results = verifyAllResponseLabels(
      {
        status: VERIFY_OPTIONS_VALIDATION_RESPONSE.status,
        headers: {
          "signature-input":
            VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE_INPUT.replace(
              "dryrun",
              label,
            ),
          signature: VERIFY_ALL_OPTIONS_VALIDATION_SIGNATURE.replace(
            "dryrun",
            label,
          ),
        },
        body: "",
      },
      { ...allOpts, request },
    );
    if (results.length > 0 && results.every((r) => r.ok))
      throw new Error(
        "dry-run verification returned unexpected result: ok",
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
 * The abort error for a signal that fired while the response body
 * was streaming: the signal's own reason when it is an `Error`
 * (a plain `controller.abort()` yields the standard `AbortError`
 * `DOMException`), else a fresh `AbortError` — so the caller sees
 * the abort the way the fetch itself would have reported it, never
 * wrapped as a verification failure.
 */
function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("The operation was aborted", "AbortError");
}

/**
 * Await one `reader.read()` unless the signal aborts first: on
 * abort the reader is cancelled — so the pending read settles and
 * the peer stops streaming — and the signal's abort reason is
 * thrown. The listener is removed once the read settles either way,
 * so a completed call leaves no listener behind.
 *
 * A cancelled read resolves `done: true` as the cancel settles it,
 * so the race can settle with that resolved read instead of the
 * abort rejection: the post-race `signal.aborted` check makes the
 * caller's abort win either way — a body that only arrived because
 * the reader was cancelled must never verify.
 */
async function readWithAbort(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  signal: AbortSignal,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  let onAbort: (() => void) | undefined;
  try {
    const result = await Promise.race([
      reader.read(),
      new Promise<never>((_resolve, reject) => {
        onAbort = () => {
          // Cancel first so the pending read settles; the rejection
          // below is what the caller sees, whether the cancel
          // itself succeeds or not.
          void reader.cancel().then(
            () => reject(abortError(signal)),
            () => reject(abortError(signal)),
          );
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }),
    ]);
    if (signal.aborted) throw abortError(signal);
    return result;
  } finally {
    if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
  }
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
 *
 * When `signal` is passed, each stream read races against it: an
 * abort while waiting cancels the reader and throws the signal's
 * abort reason (see `readWithAbort`), and an abort noticed between
 * reads does the same — so a hung peer cannot hold the call past
 * the caller's cancellation. The `arrayBuffer()` fallback has no
 * stream to cancel, so it is not raced; it still runs under the
 * cap, and the pre-abort fail-fast in `verifiedFetch` already
 * rejects a signal that was aborted before the fetch.
 */
async function readResponseBodyCapped(
  res: VerifiedFetchResponse,
  maxBodyBytes: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  const stream = res.body;
  if (stream !== undefined && stream !== null) {
    const reader = stream.getReader();
    const chunks: Buffer[] = [];
    let size = 0;
    try {
      for (;;) {
        if (signal?.aborted) {
          await reader.cancel();
          throw abortError(signal);
        }
        const { done, value } =
          signal === undefined
            ? await reader.read()
            : await readWithAbort(reader, signal);
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
      // `releaseLock` throws when a read is still pending — which is
      // exactly the state an abort rejection can leave behind if it
      // won the race before the cancelled read settled. Swallow
      // that, so the abort error surfaces, not a lock error; the
      // reader and its stream are discarded with the call either way.
      try {
        reader.releaseLock();
      } catch {
        // Pending read already rejected by the abort; nothing to do.
      }
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
 * pre-flight dry run (`opts.verify` — or, when
 * `opts.verify.verifyAllLabels` is set, the multi-label pre-flight
 * over `verifyAllResponseLabels`); fetch it (`opts.fetchImpl`,
 * defaulting to the global `fetch`); read the response body under
 * `opts.maxBodyBytes`; adapt it with `fromFetchResponse` (the request
 * just signed attached as `request`, so covered `;req` components
 * bind the response signature to it); verify it with
 * `verifyResponse` — or, in multi-label mode, with
 * `verifyAllResponseLabels`, requiring every label to pass. Returns
 * `{ response, body, verifyResult }` on a verified response (plus
 * `verifyResults` in multi-label mode); throws `VerifyError` on a
 * failed verification — in multi-label mode the first failing
 * label's code / reason / label, with the full per-label array
 * attached to the error as `verifyResults`.
 *
 * Fail-fast configuration errors (thrown, before any network):
 * everything `signRequest` already rejects, plus a verifier with no
 * key source or any other misconfiguration the dry run catches, a
 * non-positive-integer `maxBodyBytes`, a caller-supplied
 * `verify.request` (managed by this helper — pass no `request`),
 * and a non-`AbortSignal` `init.signal`. A signal already aborted
 * likewise throws before any network — `verifiedFetch: request
 * aborted` — so a cancelled call never signs, never fetches, and
 * never verifies. Fetch-layer errors pass through untouched. See the module
 * docstring for the full contract (non-2xx, binary bodies, the body
 * cap, trailers, cancellation).
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
  // A non-AbortSignal `signal` is a configuration error, like a bad
  // `maxBodyBytes` — and a signal already aborted fails fast here,
  // before signing or fetching, so a cancelled call costs no work
  // and no network. The message shape mirrors #112's
  // `webhook delivery aborted` (`deliverSettlementWebhook`).
  const signal = init?.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal))
    throw new Error(
      `verifiedFetch: init.signal must be an AbortSignal, got ${String(signal)}`,
    );
  if (signal?.aborted)
    throw new Error("verifiedFetch: request aborted");
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
  // verifier throws here, never after the peer has answered. The
  // multi-label pre-flight runs when `verifyAllLabels` is set.
  if (opts.verify.verifyAllLabels !== undefined)
    assertVerifyAllOptionsPreflight(opts.verify, signed);
  else assertVerifyOptionsPreflight(opts.verify, signed);

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
        ...(init.signal !== undefined ? { signal: init.signal } : {}),
      });
    });
  // The caller's signal rides along, so the fetch itself can be
  // cancelled in flight: an abort here rejects with the fetch's own
  // abort error, passed through untouched — never wrapped as a
  // verification failure.
  const res = await fetchImpl(url, {
    method: signed.method,
    headers: signed.headers,
    ...(signed.body !== undefined ? { body: signed.body } : {}),
    ...(signal !== undefined ? { signal } : {}),
  });

  const bodyBuf = await readResponseBodyCapped(res, maxBodyBytes, signal);

  // `fromFetchResponse` normalizes the fetch headers and binds the
  // signed request as the triggering request; `verifyResponse` gets
  // the same request as its `request` option, so a covered `;req`
  // component resolves against what this call actually sent. The
  // spread pins a definite status (the adapter validated it is an
  // integer 100-599) for the `HttpResponseLike` shape.
  const resLike = fromFetchResponse(res, bodyBuf, { request: signed });
  const allOpts = opts.verify.verifyAllLabels;
  if (allOpts !== undefined) {
    // Multi-label mode: every label must pass before the response is
    // returned. An unsigned response yields no results at all (unless
    // requiredLabels synthesizes failures), and an empty result set
    // must not pass an `every` check vacuously — it is a missing
    // signature, thrown like the single-label path. The first failing
    // label's code is the thrown code, so a stripped co-signature
    // (`MISSING_REQUIRED_LABEL`) and a tampered one
    // (`SIGNATURE_MISMATCH`) stay distinguishable — and the full
    // per-label array rides on the error, so the label that did
    // verify stays visible to the caller.
    const results = verifyAllResponseLabels(
      { ...resLike, status: res.status },
      { ...allOpts, request: signed },
    );
    if (results.length === 0)
      throw new VerifyError(
        "MISSING_SIGNATURE_INPUT",
        "response carries no signature-input header",
        { label: "", verifyResults: results },
      );
    const failed = results.find((r) => !r.ok);
    if (failed !== undefined)
      throw new VerifyError(
        failed.code ?? "VERIFICATION_ERROR",
        failed.reason ?? "verification failed",
        {
          label: failed.label,
          keyId: failed.keyId,
          alg: failed.alg,
          nonce: failed.nonce,
          tag: failed.tag,
          created: failed.created,
          expires: failed.expires,
          verifyResults: results,
        },
      );
    return {
      response: res,
      body: bodyBuf.toString("utf8"),
      verifyResult: { ok: true, label: "", perLabelResults: results },
      verifyResults: results,
    };
  }
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
