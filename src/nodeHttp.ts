/**
 * Node.js HTTP adapters (client + server direction).
 *
 * Normalizes Node `http` message shapes (or any structurally identical
 * objects, e.g. test doubles) into the library's `RequestLike` shape so
 * `verifyRequest` can check signatures on messages received by a real
 * server (`fromNodeRequest`) or on responses received by a real client
 * (`fromNodeResponse`, e.g. verifying a gateway-signed settlement
 * callback). Zero runtime dependencies.
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
 */

import { joinHeaderValues, type RequestLike } from "./components.js";

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
  trailers?: Record<string, string | string[] | undefined>;
  /**
   * Raw trailer fields, as Node exposes them on
   * `IncomingMessage.rawTrailers`: a flat `[name, value, name, value,
   * …]` array in wire order, with the sender's original name casing.
   * When non-empty it takes precedence over `trailers`, because it is
   * the lossless form (duplicate fields are still separate entries).
   * The normalized output lowercases names exactly like headers — the
   * original casing is NOT preserved in `RequestLike.trailers`.
   */
  rawTrailers?: string[];
}

/**
 * The `IncomingMessage` fields the request adapter actually reads. A real
 * `http.IncomingMessage` satisfies this interface; plain test doubles do
 * too, without importing `node:http`.
 */
export interface IncomingRequestLike extends IncomingTrailersLike {
  method?: string;
  /** Origin-form path+query on real servers (e.g. "/webhook?event=push"). */
  url?: string;
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
  statusCode?: number;
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
