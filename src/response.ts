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
import { VerifyError } from "./errors.js";
import { signRequest, assertCoveredComponentsShape, assertLabelShape, assertNoDuplicateCoveredComponents, assertNoUnknownOptions, SIGN_OPTION_KEYS, type SignOptions } from "./sign.js";
import {
  checkSignatureHeaderLengths,
  verifyAllLabels,
  verifyRequest,
  VERIFY_ALL_OPTION_KEYS,
  VERIFY_OPTION_KEYS,
  type VerifyAllOptions,
  type VerifyOptions,
  type VerifyResult,
} from "./verify.js";

/**
 * Response-side option allowlists (backlog #1251): each is the
 * request-side list plus `"request"`, the one option the response
 * wrappers consume themselves instead of forwarding. The unknown-key
 * scan runs at the top of each wrapper, before the status guard, so
 * a misspelled option throws with the wrapper's own name in the
 * message — the delegated `signRequest` / `verifyRequest` /
 * `verifyAllLabels` call would reject it too, but under its own
 * name.
 */
const SIGN_RESPONSE_OPTION_KEYS: readonly string[] = [
  ...SIGN_OPTION_KEYS,
  "request",
];
const VERIFY_RESPONSE_OPTION_KEYS: readonly string[] = [
  ...VERIFY_OPTION_KEYS,
  "request",
];
const VERIFY_ALL_RESPONSE_OPTION_KEYS: readonly string[] = [
  ...VERIFY_ALL_OPTION_KEYS,
  "request",
];

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
  body?: string | Buffer | undefined;
  trailers?: Record<string, string | string[] | undefined> | undefined;
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
  body?: string | Buffer | undefined;
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
 * Verification options for `verifyAllResponseLabels`: identical to
 * `VerifyAllOptions` (per-label keys, resolvers, freshness windows,
 * `requiredLabels`, …), plus the same optional `request` as the
 * single-label side: a wire signature covering `;req` components
 * verifies against the request passed here, and fails the guard
 * without one.
 */
export type VerifyAllResponseOptions = VerifyAllOptions & {
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
  caller: "signResponse" | "verifyResponse" | "verifyAllResponseLabels",
  entry: string,
  hasRequest: boolean,
): string {
  const { base, params } = splitComponent(entry);
  const otherSide =
    caller === "signResponse"
      ? "signRequest"
      : caller === "verifyAllResponseLabels"
        ? "verifyAllLabels"
        : "verifyRequest";
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

// The range is the registered HTTP status-code range (RFC 9110 §15):
// 100-599. Codes 600-999 are undefined, and an `@status` bound to one
// would sign a meaningless value for a webhook/gateway verifier, so
// they are rejected here rather than only below 100.
function assertStatus(
  caller: "signResponse" | "verifyResponse" | "verifyAllResponseLabels",
  status: unknown,
): asserts status is number {
  if (
    typeof status !== "number" ||
    !Number.isInteger(status) ||
    status < 100 ||
    status > 599
  )
    throw new Error(
      `${caller}: "status" must be an integer HTTP status code, got ${String(status)} (expected 100-599)`,
    );
}

/**
 * Synthesize the `RequestLike` the request-side API verifies a
 * response through — the single synthesis path both `verifyResponse`
 * and `verifyAllResponseLabels` share, so the fabricated shape can
 * never drift between the two entry points.
 *
 * `method`/`url` are required by the `RequestLike` type but are never
 * consulted here: the guard in each caller rejects every component
 * that could read them, so no fabricated value can leak into a
 * signature base. The URL still has to parse — `resolveComponent`
 * runs `new URL` before its switch — so it is a reserved `.invalid`
 * host (RFC 2606) that can never be a real request target, never a
 * plausible one. `request` is the attached triggering request, what
 * `;req` components resolve against; without one the guard already
 * rejected them.
 */
function responseToRequestLike(
  res: HttpResponseLike,
  request?: RequestLike,
): RequestLike {
  return {
    method: "",
    url: "https://response.invalid/",
    headers: res.headers,
    body: res.body,
    status: res.status,
    trailers: res.trailers,
    ...(request !== undefined ? { request } : {}),
  };
}

/**
 * Sign an HTTP response per RFC 9421. Returns a copy of the response
 * with `Signature-Input`, `Signature` (and `Content-Digest` when the
 * body is covered) headers attached. The input response is not
 * mutated.
 *
 * Fail-fast configuration errors (thrown, not embedded in the
 * signature): everything `signRequest` already rejects, plus
 * - a missing, non-integer, or out-of-range (100-599) `status` (`@status` is covered by
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
  assertNoUnknownOptions(opts, SIGN_RESPONSE_OPTION_KEYS, "signResponse");
  assertStatus("signResponse", res.status);
  // `undefined` means "use the default list"; an explicit `null`
  // is a caller mistake, not a request for the default — it must
  // reach the shape guard below instead of being swallowed by `??`.
  const covered =
    opts.coveredComponents === undefined
      ? defaultResponseCoveredComponents(res.body !== undefined)
      : opts.coveredComponents;
  // Shape first, for the same reason as the request side: the
  // duplicate guard below calls `entry.trim()` and would throw a
  // bare TypeError on a non-string entry before the delegated
  // signRequest call could reject it in this entry point's words.
  assertCoveredComponentsShape("signResponse", covered);
  // Same duplicate guard as the request side, naming this entry
  // point; the delegated signRequest call would reject it too, but
  // with the wrong caller in the message.
  assertNoDuplicateCoveredComponents("signResponse", covered);
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
 * side: a missing, non-integer, or out-of-range (100-599) `status`, and a wire signature
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
  assertNoUnknownOptions(opts, VERIFY_RESPONSE_OPTION_KEYS, "verifyResponse");
  assertStatus("verifyResponse", res.status);
  // Header length limits (fail-closed, before the guard below parses
  // `signature-input`): the guard's own parse must never run over an
  // oversized header. `verifyRequest` re-checks the same limits after
  // the delegation, so this gate only protects the parse here.
  const sigField = getHeader(res.headers, "signature");
  const sigInputEarly = getHeader(res.headers, "signature-input");
  const tooLarge = checkSignatureHeaderLengths(
    sigInputEarly,
    sigField,
    opts,
    opts.label ?? "sig1",
    "verifyResponse",
  );
  if (tooLarge !== undefined) return tooLarge;
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
  return verifyRequest(responseToRequestLike(res, request), verifyOpts);
}

/**
 * Like `verifyResponse`, but throws a `VerifyError` — an `Error` subclass
 * carrying a machine-readable `.code` — instead of returning
 * `{ ok: false, ... }`. Use when callers prefer exceptions over
 * result-branching (e.g. a settlement-webhook receiver that rejects a
 * bad gateway signature with one call instead of branching on
 * `result.ok`).
 *
 * On success returns the verified identity (`label`, `keyid`, `alg`,
 * `nonce`, `tag`, `created`, `expires`, `coveredComponents`) — the same
 * shape `verifyRequestOrThrow` returns. Caller configuration errors (a
 * missing, non-integer, or out-of-range `status`; a wire signature
 * whose covered components derive from the request without `;req`, or
 * carry `;req` with no `request` attached) still throw a plain `Error`,
 * exactly as `verifyResponse` does.
 */
export function verifyResponseOrThrow(
  res: HttpResponseLike,
  opts: VerifyResponseOptions,
): { label: string; keyId?: string | undefined; alg?: string | undefined; nonce?: string | undefined; tag?: string | undefined; created?: number | undefined; expires?: number | undefined; coveredComponents?: string[] | undefined } {
  const result = verifyResponse(res, opts);
  if (result.ok)
    return { label: result.label, keyId: result.keyId, alg: result.alg, nonce: result.nonce, tag: result.tag, created: result.created, expires: result.expires, coveredComponents: result.coveredComponents };
  throw new VerifyError(
    result.code ?? "VERIFICATION_ERROR",
    result.reason ?? "verification failed",
    { label: result.label, keyId: result.keyId, alg: result.alg, nonce: result.nonce, tag: result.tag, created: result.created, expires: result.expires },
  );
}

/**
 * Verify every signature carried by the response — the response-side
 * twin of `verifyAllLabels`, for the multi-party settlement flow
 * `addResponseSignature` documents (merchant ed25519 signs, gateway
 * hmac appends). Parses all labels from the `Signature-Input` header
 * and verifies each one through the response synthesis path (the same
 * `RequestLike` `verifyResponse` builds: `@status` binds the status
 * code, `;req` components resolve against the attached triggering
 * request), returning one `VerifyResult` per label in wire order. A
 * failing label never blocks the remaining labels.
 *
 * With `opts.requiredLabels`, every required label that never appears
 * on the wire is appended as a synthetic failure (`{ ok: false, code:
 * "MISSING_REQUIRED_LABEL", label }`) after the wire-order results, in
 * `requiredLabels` order — the same empty-array trap closure as
 * `verifyAllLabels`. Returns an empty array when the response has no
 * `Signature-Input` header and no labels are required. When the header
 * is present but cannot even be split into labels, returns a
 * single-element array with `ok: false` and code
 * `MALFORMED_SIGNATURE_INPUT`. Like `verifyAllLabels`, this function
 * never throws on malformed input.
 *
 * Two caller configuration errors still throw, matching
 * `verifyResponse`: a missing, non-integer, or out-of-range (100-599) `status`, and a wire
 * signature whose covered components derive from the request without
 * `;req`, or carry `;req` with no `request` attached — checked for
 * every label, not just the first. Per-label option maps (`keys`,
 * `keyResolvers`, `expectedKeyIds`, …) behave exactly as in
 * `verifyAllLabels`: the delegation below is the same function, so a
 * label's own key, resolver, freshness window, or replay store is
 * honoured and never leaks onto another label.
 */
export function verifyAllResponseLabels(
  res: HttpResponseLike,
  opts: VerifyAllResponseOptions,
): VerifyResult[] {
  assertNoUnknownOptions(opts, VERIFY_ALL_RESPONSE_OPTION_KEYS, "verifyAllResponseLabels");
  assertStatus("verifyAllResponseLabels", res.status);
  // Header length limits (fail-closed, before the guard below parses
  // `signature-input`): the guard's own parse must never run over an
  // oversized header. `verifyAllLabels` re-checks the same limits
  // after the delegation, so this gate only protects the parse here.
  const sigField = getHeader(res.headers, "signature");
  const sigInput = getHeader(res.headers, "signature-input");
  const tooLarge = checkSignatureHeaderLengths(
    sigInput,
    sigField,
    opts,
    "",
    "verifyAllResponseLabels",
  );
  if (tooLarge !== undefined) return [tooLarge];
  // Response-side guard over every label: a request-derived component
  // without `;req`, or a `;req` component with no request attached, is
  // a caller configuration error — checked per label, so a second
  // party's label cannot smuggle in a component the first label's
  // guard already passed on. A parse failure means the header is
  // malformed, which `verifyAllLabels` reports properly below.
  if (sigInput !== undefined) {
    try {
      const labels = listSignatureLabels(sigInput);
      for (const label of labels) {
        try {
          const parsed = parseSignatureInput(sigInput, label);
          const offending = findRequestComponent(
            parsed.componentIds,
            opts.request !== undefined,
          );
          if (offending !== undefined)
            throw new Error(
              requestComponentError(
                "verifyAllResponseLabels",
                offending,
                opts.request !== undefined,
              ),
            );
        } catch (e) {
          if (
            e instanceof Error &&
            e.message.startsWith("verifyAllResponseLabels: covered component")
          )
            throw e;
          // This label's entry is unparsable — the delegation below
          // reports it as MALFORMED_SIGNATURE_INPUT; the remaining
          // labels still get their guard check.
        }
      }
    } catch (e) {
      if (
        e instanceof Error &&
        e.message.startsWith("verifyAllResponseLabels: covered component")
      )
        throw e;
      // The header cannot even be split into labels — `verifyAllLabels`
      // reports it as MALFORMED_SIGNATURE_INPUT below.
    }
  }
  // `request` is consumed here, not forwarded into VerifyAllOptions.
  // The synthesis path is the one `verifyResponse` uses, shared
  // through `responseToRequestLike` — `@status` still binds the
  // status code and `;req` still resolves against the attached
  // request, per label.
  const { request, ...verifyAllOpts } = opts;
  return verifyAllLabels(responseToRequestLike(res, request), verifyAllOpts);
}

/**
 * Throwing variant of `verifyAllResponseLabels`, for callers that prefer
 * exception flow over per-label result inspection (e.g. a settlement
 * webhook receiver that rejects the whole response on the first bad
 * co-signature instead of reporting per-signer outcomes).
 *
 * Calls `verifyAllResponseLabels` and throws a `VerifyError` carrying the
 * first failing label's stable `code` and `label` (plus the wire fields
 * `keyId` / `alg` / `nonce` / `tag` / `created` / `expires` the failure
 * result reported, mirroring `verifyRequestOrThrow`), with the full
 * per-label array attached as `verifyResults` — a detached copy, so a
 * bad gateway signature never hides the merchant signature that
 * verified, and mutating the attached array never affects a later
 * verification. When every label verifies, returns the per-label
 * success results in wire order.
 *
 * A response with no `signature-input` header returns `[]` without
 * throwing, exactly as `verifyAllResponseLabels` does — callers that
 * must reject unsigned responses should check the returned length
 * themselves, or pass `requiredLabels` (with required labels set, an
 * unsigned response yields `MISSING_REQUIRED_LABEL` failures and this
 * function throws a `VerifyError` carrying that code). Caller
 * configuration errors (a missing, non-integer, or out-of-range
 * `status`; a wire signature whose covered components derive from the
 * request without `;req`, or carry `;req` with no `request` attached)
 * still throw a plain `Error`, never a `VerifyError`.
 */
export function verifyAllResponseLabelsOrThrow(
  res: HttpResponseLike,
  opts: VerifyAllResponseOptions,
): VerifyResult[] {
  const results = verifyAllResponseLabels(res, opts);
  for (const result of results) {
    if (!result.ok)
      throw new VerifyError(
        result.code ?? "VERIFICATION_ERROR",
        result.reason ?? "verification failed",
        {
          label: result.label,
          keyId: result.keyId,
          alg: result.alg,
          nonce: result.nonce,
          tag: result.tag,
          created: result.created,
          expires: result.expires,
          verifyResults: [...results],
        },
      );
  }
  return results;
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
 * - `opts.label` is empty, not an RFC 9421 token, or already present in
 *   the response (RFC 9421 dictionary labels must be unique). A
 *   malformed label is rejected here, naming `addResponseSignature`,
 *   before any crypto runs — the delegated `signResponse` never sees it.
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
  assertNoUnknownOptions(opts, SIGN_RESPONSE_OPTION_KEYS, "addResponseSignature");
  const label = opts.label ?? "sig1";
  if (label.length === 0)
    throw new Error(
      'addResponseSignature: "label" must be a non-empty string',
    );
  assertLabelShape(label, "addResponseSignature");

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
    { ...opts, ...(digestAlg !== undefined ? { contentDigestAlg: digestAlg } : {}) },
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
