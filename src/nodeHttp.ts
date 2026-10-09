/**
 * Node.js HTTP server adapter.
 *
 * Normalizes an `http.IncomingMessage` (or any structurally identical
 * object, e.g. a test double) into the library's `RequestLike` shape so
 * `verifyRequest` can check signatures on requests received by a real
 * server. Zero runtime dependencies.
 *
 * The request body is NOT read here: `IncomingMessage` is a stream, so
 * the caller must buffer it first and pass the complete bytes (string or
 * Buffer) as the second argument. Signing covers the *value* of the
 * `Content-Digest` header plus a digest recomputation over the body, so
 * the exact bytes matter — pass the raw buffered body, never a
 * re-serialized one.
 */

import { joinHeaderValues, type RequestLike } from "./components.js";

/**
 * The `IncomingMessage` fields this adapter actually reads. A real
 * `http.IncomingMessage` satisfies this interface; plain test doubles do
 * too, without importing `node:http`.
 */
export interface IncomingRequestLike {
  method?: string;
  /** Origin-form path+query on real servers (e.g. "/webhook?event=push"). */
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  /** Only `encrypted` is read, to infer the URL scheme. */
  socket?: { encrypted?: boolean } | null | undefined;
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
 * Build a `RequestLike` from a received Node HTTP request plus its
 * already-buffered body.
 *
 * The absolute URL is rebuilt as `<scheme>://<host><path>`; the `host`
 * header value (including any port) is preserved verbatim. Throws a
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

  return { method, url, headers, body };
}
