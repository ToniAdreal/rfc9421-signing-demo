/**
 * Node.js HTTP adapters (client + server direction).
 *
 * Normalizes Node `http` message shapes (or any structurally identical
 * objects, e.g. test doubles) into the library's `RequestLike` shape so
 * `verifyRequest` can check signatures on messages received by a real
 * server (`fromNodeRequest`) or on responses received by a real client
 * (`fromNodeResponse`, e.g. verifying a gateway-signed settlement
 * callback). `fromFetchResponse` is the same client-direction adapter
 * for the global `fetch` API: a `Response` from `fetch()` instead of an
 * `http.IncomingMessage`. Zero runtime dependencies.
 *
 * The request body is NOT read here: `IncomingMessage` is a stream, so
 * the caller must buffer it first and pass the complete bytes (string or
 * Buffer) as the second argument. Signing covers the *value* of the
 * `Content-Digest` header plus a digest recomputation over the body, so
 * the exact bytes matter — pass the raw buffered body, never a
 * re-serialized one.
 *
 * Trailers are carried over too: a real `IncomingMessage` exposes them
 * as `req.trailers` (parsed object) and `req.rawTrailers` (flat
 * wire-order array). Honest caveats: trailers only exist at all when
 * the peer actually sends them (on a chunked message), and on a real
 * `IncomingMessage` they are only complete after the `end` event —
 * which is the same moment the buffered body is ready, so calling this
 * adapter after `end` (as the README example does) is both necessary
 * and sufficient. Before `end`, `trailers` is empty even for a message
 * that will carry trailers.
 *
 * `createVerifiedHandler` is the server-side counterpart that closes
 * the loop: it buffers the body, adapts it with `fromNodeRequest`,
 * verifies it, and only then calls the business handler — so a
 * webhook receiver cannot forget a step and let an unverified request
 * into its logic. The `node:http` import below is type-only (erased at
 * compile time): the runtime dependency count stays zero.
 */

import { KeyObject } from "node:crypto";
import type { IncomingMessage, RequestListener, ServerResponse } from "node:http";
import { joinHeaderValues, type RequestLike } from "./components.js";
import { signResponse, type SignResponseOptions } from "./response.js";
import { verifyRequest, type VerifyOptions, type VerifyResult } from "./verify.js";

/**
 * The trailer fields an adapter actually reads, shared by the request
 * and response message shapes. `normalizeTrailers` is typed against this
 * minimal shape so both adapters reuse the exact same normalization
 * (and its `getHeaderRaw`-consistent conventions).
 */
export interface IncomingTrailersLike {
  /**
   * Parsed trailer fields, as Node exposes them on
   * `IncomingMessage.trailers`. Read only when `rawTrailers` is absent
   * or empty. A real message has this set to `{}` when the peer sent
   * no trailers; the adapter normalizes that to "no trailers".
   */
  trailers?: Record<string, string | string[] | undefined> | undefined;
  /**
   * Raw trailer fields, as Node exposes them on
   * `IncomingMessage.rawTrailers`: a flat `[name, value, name, value,
   * …]` array in wire order, with the sender's original name casing.
   * When non-empty it takes precedence over `trailers`, because it is
   * the lossless form (duplicate fields are still separate entries).
   * The normalized output lowercases names exactly like headers — the
   * original casing is NOT preserved in `RequestLike.trailers`.
   */
  rawTrailers?: string[] | undefined;
}

/**
 * The `IncomingMessage` fields the request adapter actually reads. A real
 * `http.IncomingMessage` satisfies this interface; plain test doubles do
 * too, without importing `node:http`.
 */
export interface IncomingRequestLike extends IncomingTrailersLike {
  method?: string | undefined;
  /** Origin-form path+query on real servers (e.g. "/webhook?event=push"). */
  url?: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  /** Only `encrypted` is read, to infer the URL scheme. */
  socket?: { encrypted?: boolean } | null | undefined;
}

/**
 * The `IncomingMessage` fields the response adapter actually reads. On
 * the client side a real `http.IncomingMessage` (the object an
 * `http.get` callback receives) satisfies this interface; plain test
 * doubles do too, without importing `node:http`.
 */
export interface IncomingResponseLike extends IncomingTrailersLike {
  /** The response status code — the field a covered `@status` binds. */
  statusCode?: number | undefined;
  headers: Record<string, string | string[] | undefined>;
}

export interface FromNodeResponseOptions {
  /**
   * The request that triggered this response. Supplies the
   * `RequestLike.method`/`url` fields (which a pure `@status` flow never
   * covers, but the type requires) and is attached as
   * `RequestLike.request`, so a covered `;req` component
   * (e.g. `"@method";req`) resolves against it and binds the response
   * signature to that request. Takes precedence over the explicit
   * `method`/`url` pair.
   */
  request?: RequestLike;
  /**
   * Explicit request method, used only when `request` is absent. Must be
   * paired with `url`.
   */
  method?: string;
  /**
   * Explicit request URL, used only when `request` is absent. Must be
   * paired with `method`.
   */
  url?: string;
}

/**
 * The `Response` fields the fetch adapter actually reads. The global
 * `fetch` (Node ≥ 20) returns objects satisfying this shape; plain test
 * doubles do too — any iterable of `[name, value]` header pairs works
 * (a real `Headers` instance, or a literal array of pairs), with no
 * dependency on the DOM `Headers` type.
 *
 * `status` is optional only so a missing status fails fast with a
 * descriptive error instead of silently defaulting: a real `Response`
 * always carries one.
 */
export interface FetchResponseLike {
  /** The response status code — the field a covered `@status` binds. */
  status?: number;
  /**
   * Header fields, as `[name, value]` pairs in iteration order. A real
   * `Headers` instance already combines repeated fields (other than
   * `set-cookie`, which it yields as separate entries) with `", "`; the
   * adapter groups entries by lowercased name and joins each group with
   * `joinHeaderValues`, the same convention `fromNodeResponse` applies
   * to Node's array-valued headers.
   */
  headers: Iterable<[string, string]>;
}

export interface FromFetchResponseOptions {
  /**
   * The request that triggered this response. Supplies the
   * `RequestLike.method`/`url` fields (which a pure `@status` flow never
   * covers, but the type requires) and is attached as
   * `RequestLike.request`, so a covered `;req` component
   * (e.g. `"@method";req`) resolves against it and binds the response
   * signature to that request. Takes precedence over the explicit
   * `method`/`url` pair.
   */
  request?: RequestLike;
  /**
   * Explicit request method, used only when `request` is absent. Must be
   * paired with `url`.
   */
  method?: string;
  /**
   * Explicit request URL, used only when `request` is absent. Must be
   * paired with `method`.
   */
  url?: string;
}

/**
 * Build a `RequestLike` from a Node HTTP response plus its
 * already-buffered body.
 *
 * `RequestLike.method`/`url` are required by the type, but a response
 * message has neither of its own — they describe the *request* the
 * response answers, so the caller supplies them via `opts.request` (the
 * request the client actually sent; also attached as
 * `RequestLike.request`, enabling `;req` binding) or via the explicit
 * `opts.method` + `opts.url` pair. Neither → a descriptive `Error`.
 *
 * Throws a descriptive `Error` on a missing `res.statusCode`: `@status`
 * is the whole point of response verification, so a response without a
 * status is a caller configuration mistake, never silently defaulted.
 * The same fail-fast applies to a non-integer or out-of-range
 * (100-599) `statusCode` (a string `"200"`, a float, `NaN`, a
 * boolean, or an undefined code such as 999): `signResponse` /
 * `verifyResponse` reject non-integer statuses outright
 * (`assertStatus` in `response.ts`), and `@status` resolution
 * stringifies whatever it is given — without this check a string
 * `"200"` would verify as status 200, so the adapter is the boundary
 * where the integer rule is enforced.
 *
 * Multi-value headers are combined with `joinHeaderValues` — see its
 * warning before covering `set-cookie`: two cookies join into one
 * string that cannot be split back into the original cookies.
 */
export function fromNodeResponse(
  res: IncomingResponseLike,
  body?: string | Buffer,
  opts?: FromNodeResponseOptions,
): RequestLike {
  const status = res.statusCode;
  if (status === undefined)
    throw new Error(
      "fromNodeResponse: res.statusCode is missing — @status verification needs the response status",
    );
  if (
    typeof status !== "number" ||
    !Number.isInteger(status) ||
    status < 100 ||
    status > 599
  )
    throw new Error(
      `fromNodeResponse: res.statusCode must be an integer HTTP status code, got ${String(status)} (expected 100-599)`,
    );

  let method: string | undefined;
  let url: string | undefined;
  let boundRequest: RequestLike | undefined;
  if (opts?.request !== undefined) {
    boundRequest = opts.request;
    method = boundRequest.method;
    url = boundRequest.url;
  } else {
    method = opts?.method;
    url = opts?.url;
  }
  if (method === undefined || method === "" || url === undefined || url === "")
    throw new Error(
      "fromNodeResponse: cannot determine the request this response answers — " +
        "pass opts.request, or the opts.method + opts.url pair",
    );

  const headers = normalizeHeaders(res.headers);
  const requestLike: RequestLike = {
    method,
    url,
    headers,
    body,
    status,
    ...(boundRequest !== undefined ? { request: boundRequest } : {}),
  };

  // Trailers are only attached when the message actually carries them;
  // on a real client they are complete only after the response's `end`
  // event, which is when the caller has the buffered body anyway.
  const trailers = normalizeTrailers(res);
  return trailers === undefined ? requestLike : { ...requestLike, trailers };
}

/**
 * Build a `RequestLike` from a `fetch()` `Response` plus its
 * already-read body.
 *
 * This is the fetch-API twin of `fromNodeResponse`: same `status` /
 * `method` / `url` / `;req` semantics, same fail-fast errors, only the
 * input shape differs (`Response.status` / `Response.headers` instead
 * of `IncomingMessage.statusCode` / a record of headers).
 *
 * The body is NOT read here and `res.body` is never consumed: a fetch
 * body is a one-shot stream, and verification needs the exact raw
 * bytes (the `Content-Digest` check recomputes over them), so the
 * caller reads it first — typically
 * `Buffer.from(await res.arrayBuffer())` — and passes the bytes in.
 * A `Uint8Array` body is copied into a `Buffer` (the `RequestLike`
 * body type is `string | Buffer`); a `Buffer` or string passes through
 * untouched.
 *
 * A fetch `Response` carries no trailers, so the resulting
 * `RequestLike` never gains a `trailers` field: a covered `;tr`
 * component cannot verify through this adapter (it resolves against
 * `RequestLike.trailers`, which is absent), exactly as if the peer
 * sent no trailers. Use `fromNodeResponse` when trailers matter.
 *
 * Throws a descriptive `Error` on a missing `res.status` or a
 * non-integer or out-of-range (100-599) status — the same boundary rule as `fromNodeResponse` —
 * and when neither `opts.request` nor the `opts.method` + `opts.url`
 * pair supplies the triggering request.
 *
 * Multi-value headers are combined with `joinHeaderValues` — see its
 * warning before covering `set-cookie`: two cookies join into one
 * string that cannot be split back into the original cookies.
 */
export function fromFetchResponse(
  res: FetchResponseLike,
  body?: string | Buffer | Uint8Array,
  opts?: FromFetchResponseOptions,
): RequestLike {
  const status = res.status;
  if (status === undefined)
    throw new Error(
      "fromFetchResponse: res.status is missing — @status verification needs the response status",
    );
  if (
    typeof status !== "number" ||
    !Number.isInteger(status) ||
    status < 100 ||
    status > 599
  )
    throw new Error(
      `fromFetchResponse: res.status must be an integer HTTP status code, got ${String(status)} (expected 100-599)`,
    );

  let method: string | undefined;
  let url: string | undefined;
  let boundRequest: RequestLike | undefined;
  if (opts?.request !== undefined) {
    boundRequest = opts.request;
    method = boundRequest.method;
    url = boundRequest.url;
  } else {
    method = opts?.method;
    url = opts?.url;
  }
  if (method === undefined || method === "" || url === undefined || url === "")
    throw new Error(
      "fromFetchResponse: cannot determine the request this response answers — " +
        "pass opts.request, or the opts.method + opts.url pair",
    );

  const headers = normalizeFetchHeaders(res.headers);
  const requestLike: RequestLike = {
    method,
    url,
    headers,
    body:
      body === undefined
        ? undefined
        : typeof body === "string" || Buffer.isBuffer(body)
          ? body
          : Buffer.from(body),
    status,
    ...(boundRequest !== undefined ? { request: boundRequest } : {}),
  };
  return requestLike;
}

/**
 * Normalize a fetch `Headers` iteration into the `RequestLike.headers`
 * shape: names lowercased, entries grouped by name, each group combined
 * via `joinHeaderValues` — the exact convention `fromNodeResponse`
 * applies to Node's array-valued headers, so a signer that built its
 * `RequestLike` by hand and a verifier that received the message
 * through this adapter can never diverge on multi-value fields.
 */
function normalizeFetchHeaders(
  headers: Iterable<[string, string]>,
): Record<string, string> {
  const grouped = new Map<string, string[]>();
  for (const [name, value] of headers) {
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

export interface FromNodeRequestOptions {
  /**
   * Scheme used when rebuilding the absolute request URL. Defaults to
   * "https" when `req.socket` is a TLS socket, otherwise "http".
   *
   * Set this explicitly behind a TLS-terminating proxy, where the socket
   * seen by Node is plain HTTP but the public URL the signer signed is
   * https. Signer and verifier must agree on the exact URL: `@scheme`,
   * `@authority` and `@path` are covered components, so a mismatch here
   * fails verification (correctly — it means the two sides disagree on
   * what was signed).
   */
  scheme?: string;
}

function normalizeHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    // Multi-value headers (e.g. repeated fields, which Node exposes as
    // arrays) are combined via the shared `joinHeaderValues` helper —
    // the exact same canonicalization `signRequest` and `getHeader`
    // apply for RFC 9421 §2.5 field-value combination (per-element trim
    // + ", " join), so signer and verifier can never diverge on
    // whitespace around individual values.
    out[name.toLowerCase()] = Array.isArray(value)
      ? joinHeaderValues(value)
      : value;
  }
  return out;
}

/**
 * Normalize an incoming message's trailers into the
 * `RequestLike.trailers` shape: names lowercased, multi-value fields
 * combined via `joinHeaderValues` — the exact header conventions, so a
 * `;tr` covered component (RFC 9421 §2.1.4) canonicalizes identically
 * whether the signer built its `RequestLike` by hand or the verifier
 * received the message through this adapter.
 *
 * Returns `undefined` when the message carries no trailers (absent,
 * empty object, empty raw array, or only `undefined` values), so the
 * resulting `RequestLike` gains no `trailers` field at all and plain
 * request flows keep their exact previous shape. A non-empty
 * `rawTrailers` wins over the parsed `trailers` object; duplicate raw
 * names merge into one field. An unpaired trailing raw entry (a name
 * with no value — Node never produces one) is ignored.
 */
function normalizeTrailers(
  req: IncomingTrailersLike,
): Record<string, string> | undefined {
  if (Array.isArray(req.rawTrailers) && req.rawTrailers.length > 0) {
    const grouped = new Map<string, string[]>();
    for (let i = 0; i + 1 < req.rawTrailers.length; i += 2) {
      const name = (req.rawTrailers[i] as string).toLowerCase();
      const value = req.rawTrailers[i + 1] as string;
      const list = grouped.get(name);
      if (list) list.push(value);
      else grouped.set(name, [value]);
    }
    if (grouped.size === 0) return undefined;
    const out: Record<string, string> = {};
    for (const [name, values] of grouped) {
      out[name] = values.length === 1 ? (values[0] as string) : joinHeaderValues(values);
    }
    return out;
  }
  if (req.trailers === undefined) return undefined;
  const normalized = normalizeHeaders(req.trailers);
  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

/**
 * Build a `RequestLike` from a received Node HTTP request plus its
 * already-buffered body.
 *
 * The absolute URL is rebuilt as `<scheme>://<host><path>`; the `host`
 * header value (including any port) is preserved verbatim. This
 * adapter never sets `RequestLike.requestTarget`: a server only ever
 * sees the origin form, so an absolute-/authority-/asterisk-form
 * override is always the caller's explicit choice, set on the
 * `RequestLike` after this call. Throws a
 * descriptive `Error` on missing `method`, `url`, or `host` header —
 * those are caller configuration mistakes, never silently defaulted.
 *
 * Multi-value headers are combined with `joinHeaderValues` — see its
 * warning before covering `set-cookie`: two cookies join into one
 * string that cannot be split back into the original cookies.
 */
export function fromNodeRequest(
  req: IncomingRequestLike,
  body?: string | Buffer,
  opts?: FromNodeRequestOptions,
): RequestLike {
  const method = req.method;
  if (method === undefined || method === "")
    throw new Error("fromNodeRequest: req.method is missing");
  const path = req.url;
  if (path === undefined || path === "")
    throw new Error("fromNodeRequest: req.url is missing");

  const headers = normalizeHeaders(req.headers);
  const host = headers["host"];
  if (host === undefined || host === "")
    throw new Error(
      "fromNodeRequest: cannot rebuild the request URL without a host header",
    );

  const encrypted =
    (req.socket as { encrypted?: boolean } | null | undefined)?.encrypted ===
    true;
  const scheme = opts?.scheme ?? (encrypted ? "https" : "http");
  // Servers see the origin-form path; accept an already-absolute URL
  // unchanged (e.g. from a forward proxy in absolute-form).
  const url = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(path)
    ? path
    : `${scheme}://${host}${path}`;

  // Trailers are only attached when the message actually carries
  // them; on a real server they are complete only after the `end`
  // event, which is when the caller has the buffered body anyway.
  const trailers = normalizeTrailers(req);
  return trailers === undefined
    ? { method, url, headers, body }
    : { method, url, headers, body, trailers };
}

/**
 * Default cap on the request body `createVerifiedHandler` buffers, in
 * bytes: 1 MiB. A webhook body is a signed JSON payload (a settlement
 * callback, a gateway notification), not a file upload — 1 MiB is more
 * than 100x a typical signed callback, and anything larger is rejected
 * with 413 before any verification runs. Raise it via
 * `CreateVerifiedHandlerOptions.maxBodyBytes` for a deployment that
 * legitimately signs larger payloads.
 */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

/**
 * The business handler a verified request is handed to: the raw Node
 * request/response pair plus the `VerifyResult` of the signature that
 * was just checked. `result.ok` is always `true` here — a failed
 * verification never reaches this handler, it is answered 401 by the
 * wrapper. `result.keyId` / `result.alg` / `result.nonce` /
 * `result.created` are available for logging and audit; the handler
 * owns the response (status, headers, body) from here on.
 */
export type VerifiedRequestHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  result: VerifyResult,
) => void;

export interface CreateVerifiedHandlerOptions {
  /**
   * Maximum request body size in bytes. A body larger than this is
   * rejected with 413 before any verification runs — the key resolver
   * is never called and the buffered prefix is discarded. Defaults to
   * `DEFAULT_MAX_BODY_BYTES` (1 MiB). Must be a positive integer;
   * anything else throws a configuration `Error` at handler-creation
   * time, never per request. A body exactly at the cap still verifies.
   */
  maxBodyBytes?: number;
  /**
   * Opt-in response signing: when present, the wrapper signs the
   * business handler's response with `signResponse` before it is
   * sent, binding it to the request that was just verified — the
   * wrapper passes that request as the `request` option, so a covered
   * `;req` component (e.g. `"@method";req`) resolves against it and
   * the response signature cannot be transplanted onto a different
   * request. Absent, the response is sent exactly as the handler
   * wrote it, as before.
   *
   * The response is buffered in full (status, headers, body) until
   * the handler ends it, then signed and flushed in one go — the
   * signature needs the complete body for `content-digest`, so a
   * streaming response cannot be signed this way. `writeHead` /
   * `write` / `flushHeaders` are held, not sent, until the signed
   * flush; the handler keeps using them exactly as before.
   *
   * A signing failure at request time (e.g. a covered header the
   * handler did not set) is answered 500 `{ error: "internal error",
   * code: "INTERNAL_ERROR" }` — nothing has been sent yet, so no
   * unsigned response ever reaches the wire. A 401/400/413/500
   * rejection from the wrapper itself is never signed: a failed
   * verification gets no response signature.
   *
   * Pass `created` / `expires` / `nonce` only if you rotate them:
   * the same options sign every response, so a pinned `created`
   * ages out of the verifier's freshness window and a pinned
   * `nonce` repeats on every response (a verifier with a replay
   * cache rejects the repeats). Leave them unset for the usual
   * per-response `created: now` and no nonce.
   */
  signResponse?: VerifiedHandlerSignResponseOptions;
}

/**
 * Signing options for a verified handler's responses: exactly the
 * options `signResponse` takes, minus `request` — the wrapper
 * supplies the request it just verified, so callers never pass one
 * (and a caller-supplied request could bind the signature to a
 * request nobody sent). Everything else (`key`, `alg`, `label`,
 * `keyId`, `coveredComponents`, `created`, `expires`, `nonce`,
 * `tag`, `contentDigestAlg`, `structuredFieldTypes`) is passed
 * through unchanged, so the handler's signature follows exactly the
 * rules `signResponse` documents — including its default covered
 * components (`@status`, plus `content-digest` when the response has
 * a body). To bind the response to the triggering request, cover a
 * `;req` component, e.g. `coveredComponents: ["@status",
 * "@method;req"]`.
 */
export type VerifiedHandlerSignResponseOptions = Omit<
  SignResponseOptions,
  "request"
>;

/**
 * Synthetic request the creation-time dry run signs against. It is
 * never sent anywhere: it only exists so covered `;req` components
 * (e.g. `"@method";req`) resolve during validation the way they will
 * against a real verified request.
 */
const SIGN_RESPONSE_VALIDATION_REQUEST: RequestLike = {
  method: "POST",
  url: "http://127.0.0.1/verified-handler-validation",
  headers: {},
  body: "",
};

/**
 * Whether a dry-run signing error is about response *content* the
 * business handler supplies per request — a covered header field (or
 * query parameter, or Structured Field member) that is absent from
 * the synthetic validation response. Such an absence says nothing
 * about the live path, where the handler may set the field, so it
 * must not fail handler creation. Every other error is a
 * configuration error (bad label, alg/key mismatch, short HMAC
 * secret, bad timestamps, malformed covered component, a
 * request-derived component without `;req`, …) and fails creation.
 */
function isSignResponseContentError(e: Error): boolean {
  return (
    e.message.includes("is missing from the request") ||
    e.message.includes(
      "does not occur in the request target's query string",
    ) ||
    e.message.includes("cannot be serialized with")
  );
}

/**
 * Validate `CreateVerifiedHandlerOptions.signResponse` at
 * handler-creation time, at the same level as the `maxBodyBytes`
 * check: a misconfigured response signer must fail when the handler
 * is built, never on the first live request. The `key` shape is
 * checked directly (anything that is not a `KeyObject` cannot be a
 * private key), then the exact sign path the wrapper will use per
 * request is dry-run once — a throwaway `signResponse` over a
 * synthetic response — so every configuration check `signResponse` /
 * `signRequest` runs (label shape, alg/key match, HMAC/RSA floors,
 * timestamps, tag/nonce, covered-component shape, the
 * request-component guard) is exercised here. Only
 * content-dependent failures are forgiven (see
 * `isSignResponseContentError`).
 */
function assertSignResponseOptions(
  sign: VerifiedHandlerSignResponseOptions,
): void {
  if (typeof sign !== "object" || sign === null)
    throw new Error(
      `createVerifiedHandler: signResponse must be an object, got ${sign === null ? "null" : typeof sign}`,
    );
  if (!(sign.key instanceof KeyObject))
    throw new Error(
      "createVerifiedHandler: signResponse.key must be a KeyObject " +
        "(a private key from keys.generate*KeyPair / importPrivateKey / secretKey), got " +
        (sign.key === null ? "null" : typeof sign.key),
    );
  try {
    signResponse(
      { status: 200, headers: {}, body: "" },
      { ...sign, request: SIGN_RESPONSE_VALIDATION_REQUEST },
    );
  } catch (e) {
    if (e instanceof Error && isSignResponseContentError(e)) return;
    throw new Error(
      `createVerifiedHandler: invalid signResponse options: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/**
 * Synthetic unsigned request the creation-time verify dry run checks
 * against. It is never sent anywhere and carries no signature headers:
 * it only exists so `verifyRequest` runs every configuration assertion
 * it would run for a real request (key selection, candidate lists,
 * freshness windows, header limits, required components, allowed
 * algorithms, Structured Field types, clock options) before returning
 * `MISSING_SIGNATURE_INPUT` — without touching the key resolver or
 * the replay cache, which are only consulted once a signature header
 * parses.
 */
const VERIFY_OPTIONS_VALIDATION_REQUEST: RequestLike = {
  method: "POST",
  url: "http://127.0.0.1/verified-handler-validation",
  headers: {},
  body: "",
};

/**
 * Validate `CreateVerifiedHandlerOptions`-adjacent `verifyOpts` at
 * handler-creation time, at the same level as the `maxBodyBytes` check
 * and the `assertSignResponseOptions` dry run: a misconfigured verifier
 * must fail when the handler is built, never on the first live request
 * (where it would surface as a 500 `INTERNAL_ERROR` after the client
 * already sent a signed body). The exact verify path the wrapper will
 * use per request is dry-run once — a `verifyRequest` over the
 * synthetic unsigned request above — so every configuration check
 * `verifyRequest` runs is exercised here, and the expected
 * `MISSING_SIGNATURE_INPUT` result is swallowed.
 *
 * One check cannot ride the dry run: `verifyRequest` only throws "one
 * of `key`, `keyResolver`, or `candidateKeys` must be provided" after
 * a signature header parses, so an unsigned request never reaches it —
 * a verifier with no key source at all is checked explicitly here,
 * with the same wording `verifyRequest` uses, so it still fails at
 * creation time.
 *
 * Per-label maps (`VerifyAllOptions`, e.g. `keyResolvers`,
 * `candidateKeysByLabel`) are not covered here on purpose: they belong
 * to `verifyAllLabels`, which this handler never calls — `verifyOpts`
 * is a `VerifyOptions` and carries no per-label map to validate.
 */
function assertVerifyOptions(verifyOpts: VerifyOptions): void {
  try {
    if (verifyOpts === null || typeof verifyOpts !== "object")
      throw new Error(
        `verifyOpts must be an object, got ${verifyOpts === null ? "null" : typeof verifyOpts}`,
      );
    if (
      verifyOpts.key === undefined &&
      verifyOpts.keyResolver === undefined &&
      verifyOpts.candidateKeys === undefined
    )
      throw new Error(
        "verifyRequest: one of `key`, `keyResolver`, or `candidateKeys` must be provided",
      );
    const result = verifyRequest(
      VERIFY_OPTIONS_VALIDATION_REQUEST,
      verifyOpts,
    );
    if (result.ok || result.code !== "MISSING_SIGNATURE_INPUT")
      throw new Error(
        `dry-run verification returned unexpected result: ${result.ok ? "ok" : result.code ?? "no code"}`,
      );
  } catch (e) {
    if (
      e instanceof Error &&
      e.message.startsWith("createVerifiedHandler: invalid verifyOpts:")
    )
      throw e;
    throw new Error(
      `createVerifiedHandler: invalid verifyOpts: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/**
 * Build a standard `http.RequestListener` that verifies RFC 9421
 * signatures before any business logic runs — the four steps a webhook
 * receiver otherwise hand-rolls (buffer the body, adapt it with
 * `fromNodeRequest`, verify it, answer 401 on failure) in one place,
 * so a missed step cannot let an unverified request into the handler.
 *
 * Flow per request:
 * 1. Stream the body into memory, up to `opts.maxBodyBytes`
 *    (default 1 MiB). Past the cap the handler stops reading, answers
 *    413 with `{ error: "request body too large", code:
 *    "BODY_TOO_LARGE" }`, and never calls the key resolver — the
 *    buffered prefix is discarded and the socket is closed once the
 *    413 is flushed, so a peer cannot keep uploading into a dead
 *    verification.
 * 2. `fromNodeRequest` + `verifyRequest` with the `verifyOpts` given
 *    at creation. A request that cannot even be adapted (missing
 *    method/url/host) is answered 400 `{ error: "malformed request",
 *    code: "MALFORMED_REQUEST" }`; a misconfigured `verifyOpts`
 *    is answered 500 `{ error: "internal error", code: "INTERNAL_ERROR"
 *    }` — a server bug, never a client verdict, so no detail leaks.
 *    A stream that errors mid-body is answered 500 `{ error: "failed
 *    to read request body", code: "BODY_READ_FAILED" }` without
 *    verifying.
 * 3. Verification failure is answered 401 with exactly `{ error:
 *    "signature verification failed", code }`, where `code` is the
 *    `VerifyResult.code` (e.g. `SIGNATURE_MISMATCH`, `EXPIRED`,
 *    `MISSING_SIGNATURE_INPUT`) — no `reason`, no stack, no key
 *    material. The business handler is never called.
 * 4. Verification success calls `handler(req, res, result)` with the
 *    raw Node pair and the `VerifyResult`; the handler owns the
 *    response from there. With opt-in `opts.signResponse`, the `res`
 *    handed to the handler buffers the response instead of sending
 *    it: on `end` the wrapper signs it with `signResponse` (the
 *    just-verified request attached as `request`, so covered `;req`
 *    components bind the signature to it) and flushes the signed
 *    headers and body in one go. A signing failure at request time
 *    is answered 500 `INTERNAL_ERROR` — nothing was sent yet, so no
 *    unsigned response reaches the wire. Rejections from steps 1–3
 *    (400/401/413/500) are never signed.
 *
 * `verifyOpts` (and `opts.signResponse`, when present) are validated
 * at handler-creation time by a dry run — a misconfigured verifier
 * throws `createVerifiedHandler: invalid verifyOpts: …` when the
 * handler is built, never on the first live request. The per-request
 * 500 in step 2 therefore only remains as defense-in-depth: it can
 * still fire if the caller mutates the `verifyOpts` object after
 * creation (the wrapper reads the same object per request).
 *
 * Honest limits (see also SECURITY.md): TLS is the caller's job —
 * this handler sees whatever the socket gives it, and `@scheme`
 * follows the `fromNodeRequest` default (https on a TLS socket, http
 * otherwise) — this wrapper takes no scheme option, so behind a
 * TLS-terminating proxy sign over the plain-http URL the server
 * rebuilds, or terminate TLS in Node. The body is held in memory up
 * to the cap. The handler is single-process and stateless: replay
 * protection still needs an opt-in `VerifyOptions.replayCache` (see
 * SECURITY.md).
 */
export function createVerifiedHandler(
  verifyOpts: VerifyOptions,
  handler: VerifiedRequestHandler,
  opts?: CreateVerifiedHandlerOptions,
): RequestListener {
  const maxBodyBytes = opts?.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0)
    throw new Error(
      `createVerifiedHandler: maxBodyBytes must be a positive integer number of bytes, got ${String(opts?.maxBodyBytes)}`,
    );
  assertVerifyOptions(verifyOpts);
  const signOpts = opts?.signResponse;
  if (signOpts !== undefined) assertSignResponseOptions(signOpts);

  return (req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;

    function cleanup(): void {
      req.removeListener("data", onData);
      req.removeListener("end", onEnd);
      req.removeListener("error", onError);
    }

    function reject(
      status: number,
      error: string,
      code: string,
      destroyAfterFlush: boolean,
    ): void {
      if (settled) return;
      settled = true;
      cleanup();
      res.writeHead(status, { "content-type": "application/json" });
      const body = JSON.stringify({ error, code });
      if (destroyAfterFlush) {
        // The 413 path: the peer may still be uploading, so close the
        // socket once the rejection is flushed — nothing more is read.
        res.end(body, () => {
          req.destroy();
        });
      } else {
        res.end(body);
      }
    }

    function onData(chunk: Buffer): void {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buf.length;
      if (size > maxBodyBytes) {
        // Fail-closed: stop accumulating, never verify, 413. The
        // buffered prefix is discarded.
        reject(413, "request body too large", "BODY_TOO_LARGE", true);
        return;
      }
      chunks.push(buf);
    }

    function onEnd(): void {
      if (settled) return;
      const body = Buffer.concat(chunks);
      let requestLike: RequestLike;
      try {
        // Feed the adapter exactly the fields it reads: a real
        // IncomingMessage satisfies IncomingRequestLike at runtime,
        // but its `socket` is typed net.Socket, which has no
        // `encrypted` property for TS's weak-type check — narrow it
        // to the one flag the adapter reads (a TLSSocket carries it),
        // the same cast `fromNodeRequest` itself applies.
        requestLike = fromNodeRequest(
          {
            method: req.method,
            url: req.url,
            headers: req.headers,
            socket: req.socket as { encrypted?: boolean } | null | undefined,
            trailers: req.trailers,
            rawTrailers: req.rawTrailers,
          },
          body,
        );
      } catch {
        // A real IncomingMessage always carries method/url; a missing
        // host header (e.g. an HTTP/1.0 peer) is the realistic miss —
        // the request cannot even be adapted, so it is malformed,
        // not a signature verdict.
        reject(400, "malformed request", "MALFORMED_REQUEST", false);
        return;
      }
      let result: VerifyResult;
      try {
        result = verifyRequest(requestLike, verifyOpts);
      } catch {
        // verifyRequest throws only on caller configuration errors
        // (bad key setup) — a server bug, never a client verdict.
        reject(500, "internal error", "INTERNAL_ERROR", false);
        return;
      }
      if (!result.ok) {
        reject(
          401,
          "signature verification failed",
          result.code ?? "SIGNATURE_MISMATCH",
          false,
        );
        return;
      }
      settled = true;
      cleanup();
      handler(
        req,
        signOpts !== undefined
          ? wrapResponseForSigning(res, signOpts, requestLike)
          : res,
        result,
      );
    }

    function onError(): void {
      // Stream read error mid-body: fail closed without verifying.
      reject(500, "failed to read request body", "BODY_READ_FAILED", false);
    }

    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
  };
}

/**
 * Buffer a business handler's response so it can be signed before
 * anything reaches the wire. `writeHead` records the status and
 * headers (via `setHeader`, so later `setHeader` calls still land)
 * without flushing; `write` buffers each chunk and reports success
 * (its callback fires on the next tick, as if flushed); `end`
 * buffers the final chunk, signs `{ status, headers, body }` with
 * `signResponse` — the just-verified request attached as `request`,
 * so covered `;req` components bind the signature to it — and then
 * flushes the signed headers and the original body in one go.
 * `flushHeaders` is held to a no-op while signing: flushing early
 * would send the headers unsigned.
 *
 * The response is held in memory in full, like the request body on
 * the verify side — a webhook acknowledgement is small, and a
 * signature over `content-digest` needs the complete body anyway.
 * A signing failure here (the configuration was validated at
 * creation, so the realistic miss is a covered header the handler
 * did not set) is answered 500 `INTERNAL_ERROR`: nothing was sent
 * yet, so no unsigned response reaches the wire. The returned object
 * is the same `ServerResponse`, with its send methods replaced —
 * anything else on it (`statusCode`, `setHeader`, `getHeaders`,
 * `socket`, event listeners) behaves exactly as before.
 */
function wrapResponseForSigning(
  res: ServerResponse,
  signOpts: VerifiedHandlerSignResponseOptions,
  requestLike: RequestLike,
): ServerResponse {
  const origWriteHead = res.writeHead.bind(res);
  const origEnd = res.end.bind(res);
  const chunks: Buffer[] = [];
  let ended = false;

  function bufferChunk(chunk: unknown, encoding?: BufferEncoding): void {
    if (chunk === undefined || chunk === null) return;
    if (typeof chunk === "string")
      chunks.push(Buffer.from(chunk, encoding ?? "utf8"));
    else if (Buffer.isBuffer(chunk)) chunks.push(chunk);
    else if (chunk instanceof Uint8Array) chunks.push(Buffer.from(chunk));
    else chunks.push(Buffer.from(String(chunk)));
  }

  function applyHeaders(hdrs: unknown): void {
    if (hdrs === undefined || hdrs === null) return;
    if (Array.isArray(hdrs)) {
      for (const [name, value] of hdrs as [string, unknown][]) {
        if (value !== undefined)
          res.setHeader(name, value as string | number | string[]);
      }
      return;
    }
    for (const [name, value] of Object.entries(
      hdrs as Record<string, unknown>,
    )) {
      if (value !== undefined)
        res.setHeader(name, value as string | number | string[]);
    }
  }

  res.writeHead = function (
    statusCode: number,
    statusMessage?: string | Record<string, unknown>,
    headers?: Record<string, unknown>,
  ): ServerResponse {
    res.statusCode = statusCode;
    if (typeof statusMessage === "string") {
      res.statusMessage = statusMessage;
      applyHeaders(headers);
    } else {
      applyHeaders(statusMessage);
    }
    return res;
  } as typeof res.writeHead;

  res.write = function (
    chunk: unknown,
    encoding?: BufferEncoding | ((error?: Error | null) => void),
    cb?: (error?: Error | null) => void,
  ): boolean {
    const callback = typeof encoding === "function" ? encoding : cb;
    bufferChunk(chunk, typeof encoding === "string" ? encoding : undefined);
    // Pretend the bytes were flushed: the real write happens at end.
    if (callback !== undefined) process.nextTick(callback);
    return true;
  } as typeof res.write;

  res.flushHeaders = function (): void {
    // Held: flushing now would send the headers unsigned. They go
    // out with the signature at end.
  };

  res.end = function (
    chunk?: unknown,
    encoding?: BufferEncoding | ((error?: Error | null) => void),
    cb?: (error?: Error | null) => void,
  ): ServerResponse {
    if (ended) return res;
    ended = true;
    const callback = typeof encoding === "function" ? encoding : cb;
    bufferChunk(chunk, typeof encoding === "string" ? encoding : undefined);

    const headers: Record<string, string | string[] | undefined> = {};
    for (const [name, value] of Object.entries(res.getHeaders())) {
      if (value === undefined) continue;
      headers[name] = typeof value === "number" ? String(value) : value;
    }
    const body = chunks.length > 0 ? Buffer.concat(chunks) : undefined;
    let signed;
    try {
      signed = signResponse(
        { status: res.statusCode, headers, body },
        { ...signOpts, request: requestLike },
      );
    } catch {
      origWriteHead(500, { "content-type": "application/json" });
      origEnd(
        JSON.stringify({ error: "internal error", code: "INTERNAL_ERROR" }),
        "utf8",
        callback as () => void,
      );
      return res;
    }
    origWriteHead(signed.status, signed.headers);
    if (signed.body !== undefined)
      origEnd(signed.body, "utf8", callback as () => void);
    else origEnd(callback as () => void);
    return res;
  } as typeof res.end;

  return res;
}
