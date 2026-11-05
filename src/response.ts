/**
 * Response signing convenience entry points (thin wrappers over
 * `signRequest` / `verifyRequest`, zero new cryptography).
 *
 * A response has no method or URL of its own, so signing one through
 * `signRequest` forces the caller to hand-assemble a `RequestLike` and
 * to know — from reading the source — that `method`/`url` are inert
 * unless a request-derived component is covered, and that `@status`
 * is what binds the status code. `signResponse` / `verifyResponse`
 * take the response shape directly (`{ status, headers, body? }`) and
 * cover `@status` by default (plus `content-digest` when a body is
 * present); the caller may still override `coveredComponents`
 * explicitly, exactly as on the request side.
 *
 * Honest scope limit: response signing covers response components
 * only, unless the caller attaches the triggering request. A covered
 * component that carries the `;req` parameter binds the signature to
 * the triggering request, and both wrappers accept it when the caller
 * passes that request as the `request` option (`SignResponseOptions`
 * / `VerifyResponseOptions`): `;req` components then resolve against
 * the attached request with the same rules as the request side, so a
 * gateway callback signature cannot be transplanted onto a different
 * request. A `;req` component with no request attached is still a
 * caller configuration error, thrown with a pointer to the
 * request-side API (`signRequest` / `verifyRequest` with
 * `RequestLike.request` set, or `fromNodeResponse` with
 * `opts.request`). A request-derived component WITHOUT `;req`
 * (`@method`, `@scheme`, …) is always rejected here, even with a
 * request attached: without `;req` it would resolve against the
 * response itself, which has no method or URL — cover the `;req`
 * form instead. The wrappers never invent a method or URL to fill
 * the gap: a fabricated method would mint a signature that verifies
 * against a request nobody sent. Note the direction of the binding:
 * a response `;req` component reads the triggering request itself
 * (its method, authority, headers), not the request's signature
 * values.
 *
 * The sign side returns a response shape, not a `SignedHttpRequest`:
 * `{ status, headers, body?, trailers?, coveredComponents? }`.
 * `verifyResponse` returns a plain `VerifyResult`, identical in shape
 * to the request side, so receivers audit both directions with one
 * code path.
 */

import {
  getHeader,
  listSignatureLabels,
  parseSignatureInput,
  type RequestLike,
} from "./components.js";
import { contentDigestAlgOf } from "./digest.js";
import { signRequest, type SignOptions } from "./sign.js";
import { verifyRequest, type VerifyOptions, type VerifyResult } from "./verify.js";

/**
 * The response shape both wrappers accept. `headers` keeps the
 * `RequestLike` conventions (case-insensitive names, multi-value
 * fields as arrays); `trailers` is consulted only by covered `;tr`
 * components, exactly as on the request side.
 */
export interface HttpResponseLike {
  /** HTTP response status code, bound by a covered `@status`. */
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: string | Buffer;
  trailers?: Record<string, string | string[] | undefined>;
}

/**
 * A signed response: the input response with `Signature-Input` /
 * `Signature` (and `Content-Digest` when the body is covered) headers
 * attached. The input response is not mutated. `coveredComponents`
 * mirrors `SignedHttpRequest.coveredComponents`: the list actually
 * written to `signature-input`, as a detached copy.
 */
export interface SignedHttpResponse {
  status: number;
  headers: Record<string, string>;
  body?: string | Buffer;
  trailers?: Record<string, string | string[] | undefined>;
  coveredComponents?: string[];
}

/**
 * Signing options for `signResponse`: identical to `SignOptions`,
 * except the default `coveredComponents` is `["@status"]` (plus
 * `"content-digest"` when the response has a body) instead of the
 * request-side `["@method", "@authority", "@path"]` default. An
 * explicitly supplied list is used as-is, subject to the
 * response-only guard below. `request` attaches the triggering
 * request, which is what makes covering `;req` components honest:
 * they resolve against it (see the module docstring). It is inert
 * when no `;req` component is covered.
 */
export type SignResponseOptions = SignOptions & {
  /** The request that triggered this response, for `;req` coverage. */
  request?: RequestLike;
};

/**
 * Verification options for `verifyResponse`: identical to
 * `VerifyOptions`, plus the same optional `request` as the sign side:
 * a wire signature covering `;req` components verifies against the
 * request passed here, and fails the guard without one.
 */
export type VerifyResponseOptions = VerifyOptions & {
  /** The request that triggered this response, for `;req` coverage. */
  request?: RequestLike;
};

/**
 * Components whose value derives from the request, not the response.
 * Covering one through the response API would sign a value this API
 * cannot know — the guard rejects them instead of inventing one.
 */
const REQUEST_DERIVED_COMPONENTS = new Set([
  "@method",
  "@scheme",
  "@authority",
  "@path",
  "@query",
  "@query-param",
  "@target-uri",
  "@request-target",
]);

function defaultResponseCoveredComponents(hasBody: boolean): string[] {
  return hasBody ? ["@status", "content-digest"] : ["@status"];
}

/**
 * Split a covered-component entry into its base identifier and its
 * parameters. Entries arrive in the `signRequest` array form
 * (`"@method"`, `"x-field;bs;req"`), so the base is the text before
 * the first `;`, with any surrounding double quotes stripped; a
 * parameter is the text before any `=` (`req`, not `req=...`).
 */
function splitComponent(entry: string): { base: string; params: string[] } {
  const parts = entry.split(";");
  let base = (parts[0] as string).trim().toLowerCase();
  if (base.startsWith('"') && base.endsWith('"') && base.length >= 2)
    base = base.slice(1, -1);
  const params = parts.slice(1).map((p) => p.trim().toLowerCase().split("=")[0] as string);
  return { base, params };
}

/**
 * Return the first covered component this API cannot honestly cover,
 * or `undefined` when every entry is coverable. A request-derived
 * base without `;req` is never coverable here: it would resolve
 * against the response itself, which has no method or URL. A `;req`
 * parameter on any component counts as request-bound even when the
 * base field itself is a response header — and is coverable exactly
 * when the caller attached the triggering request (`hasRequest`).
 */
function findRequestComponent(
  components: string[],
  hasRequest: boolean,
): string | undefined {
  for (const entry of components) {
    const { base, params } = splitComponent(entry);
    // A `;req` suffix reroutes the component to the associated
    // request, so a derived base WITH `;req` is coverable exactly
    // when a request is attached — checking the derived set first
    // would wrongly reject `"@method";req` even with one attached.
    if (params.includes("req")) {
      if (!hasRequest) return entry;
      continue;
    }
    if (REQUEST_DERIVED_COMPONENTS.has(base)) return entry;
  }
  return undefined;
}

/**
 * Configuration-error message for a rejected component. The hint
 * depends on what would fix it: a bare derived component with a
 * request attached wants the `;req` form of the same component; a
 * `;req` component with no request wants the request attached (or
 * the request-side API); anything else keeps the original pointer
 * to the request-side API.
 */
function requestComponentError(
  caller: "signResponse" | "verifyResponse",
  entry: string,
  hasRequest: boolean,
): string {
  const { base, params } = splitComponent(entry);
  const otherSide =
    caller === "signResponse" ? "signRequest" : "verifyRequest";
  if (REQUEST_DERIVED_COMPONENTS.has(base) && hasRequest)
    return (
      `${caller}: covered component "${entry}" derives from the request, not the response — ` +
      `cover "${base}";req with the triggering request attached via the \`request\` option instead`
    );
  if (params.includes("req"))
    return (
      `${caller}: covered component "${entry}" derives from the request, not the response — ` +
      `sign it with ${otherSide} (RequestLike.request) instead, or attach the triggering request via the \`request\` option; ` +
      `${caller} covers response components only`
    );
  return (
    `${caller}: covered component "${entry}" derives from the request, not the response — ` +
    `sign it with ${otherSide} (RequestLike.request) instead; ${caller} covers response components only`
  );
}

function assertStatus(
  caller: "signResponse" | "verifyResponse",
  status: unknown,
): asserts status is number {
  if (typeof status !== "number" || !Number.isInteger(status))
    throw new Error(
      `${caller}: "status" must be an integer HTTP status code, got ${String(status)}`,
    );
}

/**
 * Sign an HTTP response per RFC 9421. Returns a copy of the response
 * with `Signature-Input`, `Signature` (and `Content-Digest` when the
 * body is covered) headers attached. The input response is not
 * mutated.
 *
 * Fail-fast configuration errors (thrown, not embedded in the
 * signature): everything `signRequest` already rejects, plus
 * - a missing or non-integer `status` (`@status` is covered by
 *   default, so a response without a status to bind is a caller
 *   mistake, never silently defaulted);
 * - a covered component that derives from the request without
 *   `;req`, or a `;req` component with no `request` attached (see
 *   the module docstring — attach the triggering request via the
 *   `request` option, or use `signRequest` with
 *   `RequestLike.request`).
 */
export function signResponse(
  res: HttpResponseLike,
  opts: SignResponseOptions,
): SignedHttpResponse {
  assertStatus("signResponse", res.status);
  const covered =
    opts.coveredComponents ?? defaultResponseCoveredComponents(res.body !== undefined);
  const offending = findRequestComponent(covered, opts.request !== undefined);
  if (offending !== undefined)
    throw new Error(
      requestComponentError("signResponse", offending, opts.request !== undefined),
    );
  // `method`/`url` are required by the RequestLike type but are never
  // consulted here: the guard above rejects every component that could
  // read them, so no fabricated value can leak into a signature base.
  // The URL still has to parse — `resolveComponent` runs `new URL`
  // before its switch — so it is a reserved `.invalid` host (RFC 2606)
  // that can never be a real request target, never a plausible one.
  // `request` is consumed here, not forwarded into SignOptions.
  const { request, ...signOpts } = opts;
  const signed = signRequest(
    {
      method: "",
      url: "https://response.invalid/",
      headers: res.headers,
      body: res.body,
      status: res.status,
      trailers: res.trailers,
      // The attached request is what `;req` components resolve
      // against; without one the guard above already rejected them.
      ...(request !== undefined ? { request } : {}),
    },
    { ...signOpts, coveredComponents: covered },
  );
  return {
    status: res.status,
    headers: signed.headers,
    ...(res.body !== undefined ? { body: res.body } : {}),
    ...(signed.trailers !== undefined ? { trailers: signed.trailers } : {}),
    ...(signed.coveredComponents !== undefined
      ? { coveredComponents: [...signed.coveredComponents] }
      : {}),
  };
}

/**
 * Verify an HTTP response signature per RFC 9421. Returns the same
 * `VerifyResult` shape as `verifyRequest`: wire failures
 * (`SIGNATURE_MISMATCH`, `BODY_DIGEST_MISMATCH`, missing headers, …)
 * are returned, never thrown.
 *
 * Two caller configuration errors still throw, matching the sign
 * side: a missing or non-integer `status`, and a wire signature
 * whose covered components derive from the request without `;req`,
 * or carry `;req` with no `request` attached (attach the triggering
 * request via the `request` option, or verify with `verifyRequest`
 * on a `RequestLike` carrying it). A missing or malformed
 * `signature-input` header is NOT thrown here — it is delegated to
 * `verifyRequest`, which reports it as `MISSING_SIGNATURE_INPUT` /
 * `MALFORMED_SIGNATURE_INPUT` like any other wire failure.
 */
export function verifyResponse(
  res: HttpResponseLike,
  opts: VerifyResponseOptions,
): VerifyResult {
  assertStatus("verifyResponse", res.status);
  const sigInput = getHeader(res.headers, "signature-input");
  if (sigInput !== undefined) {
    try {
      const parsed = parseSignatureInput(sigInput, opts.label ?? "sig1");
      const offending = findRequestComponent(
        parsed.componentIds,
        opts.request !== undefined,
      );
      if (offending !== undefined)
        throw new Error(
          requestComponentError(
            "verifyResponse",
            offending,
            opts.request !== undefined,
          ),
        );
    } catch (e) {
      // Our own guard error propagates; a parse failure means the
      // header is malformed, which verifyRequest reports properly.
      if (
        e instanceof Error &&
        e.message.startsWith("verifyResponse: covered component")
      )
        throw e;
    }
  }
  // `request` is consumed here, not forwarded into VerifyOptions.
  const { request, ...verifyOpts } = opts;
  const req: RequestLike = {
    method: "",
    url: "https://response.invalid/",
    headers: res.headers,
    body: res.body,
    status: res.status,
    trailers: res.trailers,
    ...(request !== undefined ? { request } : {}),
  };
  return verifyRequest(req, verifyOpts);
}

/**
 * Append a second party's signature to an already-signed response —
 * the response-side twin of `addSignature`, producing a genuine
 * multi-label RFC 9421 §2.4 dictionary. The canonical use case is
 * multi-party settlement flows: a merchant signs the settlement
 * response with its own key (e.g. ed25519), then a payment gateway
 * appends its own signature (e.g. hmac) without touching the
 * merchant's entries.
 *
 * The second signature base is built over the original response
 * content (the existing `signature-input` / `signature` headers are
 * stripped before signing), so both parties sign the same status,
 * headers, and body. Parameters, covered components, key id, and
 * nonce are taken from `opts` exactly as `signResponse` would apply
 * them; `opts.label` names the appended entry (defaults to `"sig1"`
 * like `signResponse`). A `;req` component in the appended
 * signature is covered exactly as on the first sign: pass the
 * triggering request as `opts.request`.
 *
 * One Content-Digest header constraint, identical to `addSignature`:
 * a response carries a single `content-digest` header, and every
 * label's signature base covers the wire value. If the existing
 * response already has one, the second signature is built with the
 * same digest algorithm — the algorithm of the existing header wins
 * over `opts.contentDigestAlg` (an explicitly contradictory choice
 * is a configuration error), and an existing header whose digest
 * algorithm this library cannot emit is a configuration error too.
 * Without this, the appended signature's base would cover a value
 * that is never on the wire and `verifyAllLabels` would reject it.
 *
 * Fail-fast configuration errors (thrown, never embedded):
 * - the input has no `signature-input`/`signature` headers (nothing
 *   to append to — call `signResponse` first);
 * - the existing `signature-input` header is malformed;
 * - `opts.label` is empty or already present in the response
 *   (RFC 9421 dictionary labels must be unique).
 *
 * The input response is not mutated; a new `SignedHttpResponse` is
 * returned. The returned `coveredComponents` is the appended
 * signature's own list (from the fresh sign), not a merge with the
 * first signature's: each label's audit record stays attributable
 * to the party that minted it.
 */
export function addResponseSignature(
  signedRes: SignedHttpResponse,
  opts: SignResponseOptions,
): SignedHttpResponse {
  const label = opts.label ?? "sig1";
  if (label.length === 0)
    throw new Error(
      'addResponseSignature: "label" must be a non-empty string',
    );

  let existingInput: string | undefined;
  let existingSig: string | undefined;
  for (const [k, v] of Object.entries(signedRes.headers)) {
    const lower = k.toLowerCase();
    if (lower === "signature-input") existingInput = v;
    else if (lower === "signature") existingSig = v;
  }
  if (existingInput === undefined || existingSig === undefined)
    throw new Error(
      "addResponseSignature: the response has no signature-input/signature headers; sign it with signResponse first",
    );

  let labels: string[];
  try {
    labels = listSignatureLabels(existingInput);
  } catch (e) {
    throw new Error(
      `addResponseSignature: existing signature-input header is malformed (${(e as Error).message})`,
    );
  }
  if (labels.includes(label))
    throw new Error(
      `addResponseSignature: label "${label}" is already present; every signature must use a distinct label`,
    );

  // Strip the signature dictionaries so the second base is computed over
  // the original response content, exactly as the first signature was.
  const unsignedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(signedRes.headers)) {
    const lower = k.toLowerCase();
    if (lower === "signature-input" || lower === "signature") continue;
    unsignedHeaders[k] = v;
  }
  // Pin the digest algorithm to the existing Content-Digest header, if
  // any: the second signature's base must cover the value that stays on
  // the wire (see the JSDoc above).
  let digestAlg = opts.contentDigestAlg;
  const existingDigest = Object.entries(unsignedHeaders).find(
    ([k]) => k.toLowerCase() === "content-digest",
  )?.[1];
  if (existingDigest !== undefined) {
    const wireAlg = contentDigestAlgOf(existingDigest);
    if (wireAlg === undefined)
      throw new Error(
        `addResponseSignature: the response carries a content-digest header with a digest algorithm this library cannot emit (${JSON.stringify(existingDigest.slice(0, existingDigest.indexOf("="))) || JSON.stringify(existingDigest)}); the second signature cannot cover it`,
      );
    if (digestAlg !== undefined && digestAlg !== wireAlg)
      throw new Error(
        `addResponseSignature: the response already carries a content-digest header emitted with "${wireAlg}"; contentDigestAlg "${digestAlg}" would build the second signature base over a different value than the wire one`,
      );
    digestAlg = wireAlg;
  }
  const fresh = signResponse(
    {
      status: signedRes.status,
      headers: unsignedHeaders,
      ...(signedRes.body !== undefined ? { body: signedRes.body } : {}),
      ...(signedRes.trailers !== undefined
        ? { trailers: signedRes.trailers }
        : {}),
    },
    { ...opts, contentDigestAlg: digestAlg },
  );

  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(signedRes.headers)) {
    const lower = k.toLowerCase();
    if (lower === "signature-input" || lower === "signature") continue;
    out[k] = v;
  }
  out["signature-input"] = `${existingInput}, ${fresh.headers["signature-input"]}`;
  out["signature"] = `${existingSig}, ${fresh.headers["signature"]}`;
  if (
    fresh.headers["content-digest"] !== undefined &&
    out["content-digest"] === undefined
  )
    out["content-digest"] = fresh.headers["content-digest"];

  return {
    status: signedRes.status,
    headers: out,
    ...(signedRes.body !== undefined ? { body: signedRes.body } : {}),
    ...(signedRes.trailers !== undefined
      ? { trailers: signedRes.trailers }
      : {}),
    // The appended signature's own covered list (from `fresh`), not a
    // merge with the first signature's: each label's audit record
    // stays attributable to the party that minted it.
    ...(fresh.coveredComponents !== undefined
      ? { coveredComponents: [...fresh.coveredComponents] }
      : {}),
  };
}
