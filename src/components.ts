/**
 * Covered-component resolution, signature-base construction, and
 * Signature-Input parsing for a practical subset of RFC 9421
 * (HTTP Message Signatures).
 *
 * Covered components supported: @method, @scheme, @authority, @path, @query,
 * @query-param, @status, @target-uri, @created, @expires, plus any HTTP
 * header field name.
 * Any of them may carry the RFC 9421 §2.4 `;req` component parameter
 * (e.g. `"@method";req`), which resolves the component against the
 * associated request (`RequestLike.request`) instead of the message
 * being signed — the mechanism that binds a response signature to the
 * request that triggered it. Header field components may also carry
 * the §2.1.2 `;bs` (byte sequence) parameter: the field value enters
 * the signature base as its raw bytes serialized `:base64:`, with no
 * whitespace normalization, so values that differ only in trailing
 * whitespace or other bytes a plain string join would erase are
 * distinguished. `;bs` and `;req` may combine (in either order; the
 * canonical wire form is `;req;bs`). `;bs` on a derived component
 * (`"@method";bs`, …) is rejected on both sides. Header field
 * components may also carry the §2.1.1 `;sf` (strict serialization)
 * parameter: the field value is parsed as an HTTP Structured Field
 * (RFC 8941) and re-serialized with the strict rules of RFC 8941 §4
 * before entering the signature base, so insignificant wire
 * whitespace canonicalizes identically on both sides (see
 * structuredFields.ts for the supported types and the honest
 * type-selection rule). `;sf` combines with `;req` (canonical wire
 * form `;req;sf`) but is incompatible with `;bs` — `;bs` binds the
 * raw field bytes while `;sf` binds the parsed value, so the pair
 * fails closed on both sides, as does `;sf` on a derived component.
 * Header field components may also carry the §2.1.1 `;key="…"`
 * parameter: the field value is parsed as a Dictionary Structured
 * Field and only the named member enters the signature base, as its
 * strict member serialization (Item or Inner List, without the key
 * itself) — other members are deliberately NOT bound, so they may
 * change without breaking the signature. `;key` combines with `;req`
 * (canonical wire form `;req;key="…"`) but not with `;bs` or `;sf`:
 * `;bs` binds the raw field bytes and `;sf` re-serializes the whole
 * field, while `;key` already applies the strict serialization to
 * the selected member alone, so both pairs fail closed, as does
 * `;key` on a derived component. Header field components may also
 * carry the §2.1.4 `;tr` (trailer) parameter: the field value is
 * taken from the message's trailers (`RequestLike.trailers`) instead
 * of its headers, reusing the same multi-value join / normalization
 * as header fields. Without `;tr`, trailers never participate — a
 * header and a trailer with the same field name are independent.
 * `;tr` is orthogonal to the value transforms: it combines with
 * `;req` (the trailer is then read from the associated request;
 * canonical wire form `;req;tr`), with `;bs`, with `;sf`, and with
 * `;key` (each still subject to its own incompatibilities: `;bs`
 * with `;sf`/`;key` still fail closed). `;tr` on a derived component
 * (`"@method";tr`, …) is rejected on both sides, since derived
 * components have no field value in either headers or trailers.
 * A covered `;tr` field with no matching trailer fails fast on the
 * sign side and fails closed on the verify side — never an empty
 * string. The §2.2.8 `@query-param` derived component binds ONE named
 * query parameter instead of the whole query string: it REQUIRES the
 * `;name="<param>"` component parameter, whose value is the parameter's
 * name in its percent-encoded form. The query is parsed as
 * `application/x-www-form-urlencoded` (percent-decoding, `+` as space);
 * the component value is the parameter's decoded value re-encoded with
 * the RFC's percent-encode-after-encoding process (UTF-8 bytes, only
 * the unreserved characters `A-Z a-z 0-9 - . _ ~` left literal), so
 * differently-spelled encodings of the same value (`%20` vs `+`)
 * canonicalize identically while other parameters may be added,
 * removed, or reordered freely. A named parameter with an empty value
 * (with or without `=`) has the empty string as its component value; a
 * named parameter that does not occur is an error on both sides, and
 * a name that occurs more than once MUST NOT be covered (RFC 9421
 * §2.2.8) — cover `@query` instead. `;name` combines with `;req`
 * (canonical wire form `;req;name="…"`) and with nothing else.
 * Other component parameters are not supported and fail
 * closed.
 * Signature algorithms are handled by sign.ts / verify.ts; this module
 * only deals with the canonical bytes that get signed.
 */

import {
  canonicalizeStructuredFieldValue,
  serializeDictionaryMemberValue,
} from "./structuredFields.js";

export interface RequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  /**
   * Trailer fields of the message (RFC 9110 §6.5), with the same shape
   * as `headers`. Only consulted when a covered field component
   * carries the RFC 9421 §2.1.4 `;tr` parameter: such a component
   * resolves against `trailers`, never `headers`. Plain (non-`;tr`)
   * components never consult this field.
   */
  trailers?: Record<string, string | string[] | undefined>;
  body?: string | Buffer;
  /**
   * HTTP response status code. Only consulted when `"@status"` is covered
   * (RFC 9421 §2.2.8) — signing/verifying responses, e.g. webhook
   * callbacks or signed API responses. Plain request flows leave it unset.
   */
  status?: number;
  /**
   * The request that triggered this message, when this message is a
   * response. Only consulted when a covered component carries the
   * RFC 9421 §2.4 `;req` parameter (e.g. `"@method";req`): such a
   * component resolves against this associated request instead of the
   * response itself, binding the response signature to that request so
   * the response cannot be transplanted onto a different request.
   * Plain request flows leave it unset.
   */
  request?: RequestLike;
}

export interface SignatureParams {
  created?: number;
  expires?: number;
  keyid?: string;
  alg?: string;
  nonce?: string;
  tag?: string;
}

function quoteString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function unquoteString(s: string): string {
  return s.replace(/\\(.)/g, "$1");
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Combine the values of a multi-value header field into its canonical
 * single string: each element is trimmed of surrounding whitespace and
 * the elements are joined with ", " (RFC 9421 §2.5 field-value
 * combination, with optional whitespace around each element discarded).
 *
 * This is the ONE place that combination happens. The signer
 * (`signRequest`), the verifier (`getHeader`), and the Node adapter
 * (`fromNodeRequest`) all call this helper, so the same logical header
 * can never canonicalize to different bytes on different paths — before
 * it was shared, the signer joined without trimming while the verifier
 * trimmed, and a value like `["  a  ", "b "]` signed as `"a ,  b"` but
 * verified as `"a, b"`, failing its own round-trip with
 * SIGNATURE_MISMATCH.
 */
export function joinHeaderValues(values: string[]): string {
  return values.map((x) => x.trim()).join(", ");
}

/**
 * Case-insensitive header lookup. Multi-value headers are joined with
 * ", " per RFC 9421 §2.5 (see `joinHeaderValues`).
 */
export function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === want) {
      const v = headers[k];
      if (v === undefined) return undefined;
      return Array.isArray(v) ? joinHeaderValues(v) : v;
    }
  }
  return undefined;
}

/**
 * Raw header lookup for `;bs`: the field value exactly as given, with
 * NO trimming or normalization. Multi-value fields are joined with
 * ", " between the raw (untrimmed) elements — the same separator the
 * canonical combination uses, but without discarding per-element
 * whitespace, which is precisely the information `;bs` exists to bind.
 */
export function getHeaderRaw(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === want) {
      const v = headers[k];
      if (v === undefined) return undefined;
      return Array.isArray(v) ? v.join(", ") : v;
    }
  }
  return undefined;
}

function normalizeFieldValue(value: string): string {
  // RFC 9421 §2.5: strip leading/trailing whitespace, unfold obs-fold.
  return value.replace(/^[ \t]+|[ \t]+$/g, "").replace(/\r\n[ \t]+/g, " ");
}

interface ComponentIdParts {
  /** Bare component name, lowercased (e.g. `@method`, `content-digest`). */
  base: string;
  /** True when the identifier carries the RFC 9421 §2.4 `;req` parameter. */
  req: boolean;
  /** True when the identifier carries the RFC 9421 §2.1.2 `;bs` parameter. */
  bs: boolean;
  /** True when the identifier carries the RFC 9421 §2.1.1 `;sf` parameter. */
  sf: boolean;
  /** True when the identifier carries the RFC 9421 §2.1.4 `;tr` parameter. */
  tr: boolean;
  /**
   * The Dictionary member name carried by the RFC 9421 §2.1.1
   * `;key="…"` parameter, or `undefined` when the parameter is absent.
   */
  key?: string;
  /**
   * The percent-encoded query-parameter name carried by the RFC 9421
   * §2.2.8 `;name="…"` parameter of `@query-param`, or `undefined`
   * when the parameter is absent. Only valid on `@query-param`,
   * where it is REQUIRED.
   */
  name?: string;
}

/** A Dictionary key (RFC 8941 §3.1.3): lowercase letter or `*`, then key chars. */
const DICTIONARY_KEY_RE = /^[a-z*][a-z0-9_\-.*]*$/;

interface RawParam {
  name: string;
  /** Unquoted value text, or `undefined` for a bare (valueless) parameter. */
  value?: string;
  /** True when the value arrived as a quoted string (`;key="a"`). */
  quoted: boolean;
}

/**
 * Split a covered component identifier into its bare name and its
 * component parameters. The bare (valueless) parameters `;req`,
 * `;bs`, `;sf`, and `;tr` are supported, each at most once, in any
 * order, as
 * are the valued parameters `;key="<name>"` (whose value must be a
 * quoted string naming a Dictionary key) and `;name="<param>"` (whose
 * value must be a quoted, non-empty, printable-ASCII string holding
 * the percent-encoded name of a query parameter; only valid on —
 * and required by — the `@query-param` derived component). Any other parameter
 * (a valued `;req=…`/`;bs=…`/`;sf=…`/`;tr=…`, a valueless,
 * unquoted, or non-key `;key` value, or a duplicate) is a hard
 * error — silently ignoring an unknown parameter would build a
 * different signature base than the signer intended, so this fails
 * closed on both sides. Incompatible pairs are likewise hard errors:
 * `;bs` with `;sf` (RFC 9421 §2.1: raw field bytes vs. parsed field
 * value) and `;key` with either of them (`;key` selects one member
 * and already serializes it strictly, so a whole-field `;sf` or a
 * raw-bytes `;bs` cannot also apply). `;tr` introduces no new
 * incompatibility: it only selects trailers as the field source, so
 * it combines with `;req`, `;bs`, `;sf`, and `;key` (subject to the
 * pairs above). `;name` introduces its own incompatibilities: it
 * selects one query parameter of the request target, so it cannot
 * combine with the field-value parameters `;bs`/`;sf`/`;key`/`;tr`,
 * and `@query-param` without `;name` names nothing at all, so the
 * pair (component, parameter) is validated together here.
 */
function parseComponentId(raw: string): ComponentIdParts {
  const input = raw.trim();
  const semi = input.indexOf(";");
  const base = (semi === -1 ? input : input.slice(0, semi)).trim().toLowerCase();
  const params: RawParam[] = [];
  let i = semi;
  while (i !== -1 && i < input.length) {
    // Invariant: input[i] is the ";" opening the next parameter.
    i++;
    while (input[i] === " " || input[i] === "\t") i++;
    const nameMatch = /^[A-Za-z][A-Za-z0-9_-]*/.exec(input.slice(i));
    if (!nameMatch)
      throw new Error(
        `malformed component parameter on component "${base}" at offset ${i}`,
      );
    const name = nameMatch[0].toLowerCase();
    i += nameMatch[0].length;
    while (input[i] === " " || input[i] === "\t") i++;
    let value: string | undefined;
    let quoted = false;
    if (input[i] === "=") {
      i++;
      while (input[i] === " " || input[i] === "\t") i++;
      if (input[i] === '"') {
        quoted = true;
        i++;
        let out = "";
        let closed = false;
        while (i < input.length) {
          const c = input[i];
          if (c === "\\" && i + 1 < input.length) {
            out += input[i + 1];
            i += 2;
          } else if (c === '"') {
            closed = true;
            i++;
            break;
          } else {
            out += c;
            i++;
          }
        }
        if (!closed)
          throw new Error(
            `unterminated string value for component parameter ";${name}" on component "${base}"`,
          );
        value = out;
      } else {
        const start = i;
        while (i < input.length && input[i] !== ";" && input[i] !== " " && input[i] !== "\t") i++;
        value = input.slice(start, i);
      }
    }
    params.push({ name, value, quoted });
    while (input[i] === " " || input[i] === "\t") i++;
    if (i < input.length && input[i] !== ";")
      throw new Error(
        `malformed component parameter ";${name}" on component "${base}" at offset ${i}`,
      );
  }
  for (const p of params) {
    if (p.name !== "req" && p.name !== "bs" && p.name !== "sf" && p.name !== "key" && p.name !== "tr" && p.name !== "name")
      throw new Error(
        `unsupported component parameter ";${p.name}" on component "${base}": only ";req", ";bs", ";sf", ";key", ";tr" and ";name" are supported`,
      );
    if (p.name !== "key" && p.name !== "name" && p.value !== undefined)
      throw new Error(
        `component parameter ";${p.name}" on component "${base}" does not take a value`,
      );
  }
  const names = params.map((p) => p.name);
  if (new Set(names).size !== names.length)
    throw new Error(
      `duplicate component parameter on component "${base}": ";req", ";bs", ";sf", ";key", ";tr" and ";name" may each appear at most once`,
    );
  const keyParam = params.find((p) => p.name === "key");
  let key: string | undefined;
  if (keyParam !== undefined) {
    if (keyParam.value === undefined || !keyParam.quoted)
      throw new Error(
        `component parameter ";key" on component "${base}" requires a quoted string value: write it as ;key="<name>"`,
      );
    if (!DICTIONARY_KEY_RE.test(keyParam.value))
      throw new Error(
        `invalid ";key" value "${keyParam.value}" on component "${base}": not a valid Dictionary key`,
      );
    key = keyParam.value;
  }
  const has = (n: string) => names.includes(n);
  if (has("bs") && has("sf"))
    throw new Error(
      `component parameters ";bs" and ";sf" are not compatible on component "${base}": ";bs" binds the raw field bytes, ";sf" binds the parsed Structured Field value`,
    );
  if (key !== undefined && has("bs"))
    throw new Error(
      `component parameters ";key" and ";bs" are not compatible on component "${base}": ";key" binds one parsed Dictionary member, ";bs" binds the raw field bytes`,
    );
  if (key !== undefined && has("sf"))
    throw new Error(
      `component parameters ";key" and ";sf" are not compatible on component "${base}": ";key" already serializes the selected Dictionary member with the strict rules, so a whole-field ";sf" cannot also apply`,
    );
  const nameParam = params.find((p) => p.name === "name");
  let name: string | undefined;
  if (nameParam !== undefined) {
    if (nameParam.value === undefined || !nameParam.quoted)
      throw new Error(
        `component parameter ";name" on component "${base}" requires a quoted string value: write it as ;name="<param>"`,
      );
    // The ;name value holds the parameter name in its percent-encoded
    // form (RFC 9421 §2.2.8), which is printable ASCII with no spaces:
    // a raw space or non-ASCII byte would be a decoded name smuggled
    // into the identifier, and an empty value names nothing.
    if (!/^[\x21-\x7e]+$/.test(nameParam.value))
      throw new Error(
        `invalid ";name" value "${nameParam.value}" on component "${base}": not a non-empty percent-encoded query parameter name`,
      );
    name = nameParam.value;
    if (base !== "@query-param")
      throw new Error(
        `component parameter ";name" is only supported on the "@query-param" derived component, not on component "${base}"`,
      );
    for (const other of ["bs", "sf", "key", "tr"] as const) {
      if (has(other))
        throw new Error(
          `component parameters ";name" and ";${other}" are not compatible on component "${base}": ";name" selects one query parameter of the request target, ";${other}" transforms an HTTP field value`,
        );
    }
  }
  if (base === "@query-param" && name === undefined)
    throw new Error(
      `derived component "@query-param" requires the ";name" component parameter: write it as "@query-param";name="<param>"`,
    );
  return {
    base,
    req: has("req"),
    bs: has("bs"),
    sf: has("sf"),
    tr: has("tr"),
    key,
    name,
  };
}

/**
 * Canonical wire form of one component identifier: `"base"`, optionally
 * followed by `;req`, `;tr`, `;name="…"`, `;key="…"`, `;bs`, then `;sf` (canonical
 * order, regardless of the order the caller wrote them in — so
 * `;req` always precedes `;tr`, e.g. `;req;tr`; `;key` never
 * co-occurs with `;bs`/`;sf` and `;bs`/`;sf` never co-occur — those
 * pairs are rejected by `parseComponentId`).
 */
function serializeComponentId(raw: string): string {
  const { base, req, bs, sf, key, tr, name } = parseComponentId(raw);
  return `${quoteString(base)}${req ? ";req" : ""}${tr ? ";tr" : ""}${name !== undefined ? `;name=${quoteString(name)}` : ""}${key !== undefined ? `;key=${quoteString(key)}` : ""}${bs ? ";bs" : ""}${sf ? ";sf" : ""}`;
}

/** Characters RFC 3986 calls unreserved; everything else is percent-encoded. */
const QUERY_UNRESERVED_RE = /^[A-Za-z0-9\-._~]$/;

/**
 * The "percent-encode after encoding" step of RFC 9421 §2.2.8: the
 * string is encoded as UTF-8 and every byte that is not an unreserved
 * ASCII character is percent-encoded with uppercase hex. A space
 * therefore becomes `%20` (never `+`), and a decoded `+` — which the
 * form parser reads as a space — re-encodes to `%20` as well, so the
 * two spellings of the same value canonicalize identically.
 */
function percentEncodeAfterEncoding(s: string): string {
  let out = "";
  for (const b of new TextEncoder().encode(s)) {
    const ch = String.fromCharCode(b);
    out += QUERY_UNRESERVED_RE.test(ch)
      ? ch
      : `%${b.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/**
 * Resolve the RFC 9421 §2.2.8 `@query-param` component value for the
 * parameter whose percent-encoded name is `encodedName`: parse the
 * target URL's query as `application/x-www-form-urlencoded`
 * (`URLSearchParams`: percent-decoding, `+` as space, a parameter
 * without `=` has the empty string as its value), match on the
 * re-encoded name, and return the re-encoded value. A name that does
 * not occur is an error, and so is a name that occurs more than once
 * — the RFC states such a parameter MUST NOT be included as a
 * `@query-param` component (cover `@query` instead); neither case is
 * ever silently signed as an empty or first-wins value.
 */
function resolveQueryParamValue(target: RequestLike, encodedName: string): string {
  const url = new URL(target.url);
  const rawQuery = url.search.startsWith("?") ? url.search.slice(1) : url.search;
  const matches = [...new URLSearchParams(rawQuery).entries()].filter(
    ([n]) => percentEncodeAfterEncoding(n) === encodedName,
  );
  if (matches.length === 0)
    throw new Error(
      `covered query parameter "${encodedName}" does not occur in the request target's query string`,
    );
  if (matches.length > 1)
    throw new Error(
      `covered query parameter "${encodedName}" occurs ${matches.length} times in the request target's query string: a repeated parameter must not be covered with "@query-param" (RFC 9421 §2.2.8) — cover "@query" instead`,
    );
  return percentEncodeAfterEncoding(matches[0][1]);
}

/** Resolve one covered component identifier to its canonical string value. */
export function resolveComponent(
  id: string,
  req: RequestLike,
  params: SignatureParams,
): string {
  const { base: cid, req: isReq, bs: isBs, sf: isSf, key: dictKey, tr: isTr, name: queryParamName } = parseComponentId(id);
  // RFC 9421 §2.4: a `;req` component resolves against the associated
  // request, not the message carrying the signature. Without an
  // associated request there is nothing to bind to — fail fast on the
  // sign side; on the verify side buildSignatureBase's throw converges
  // to SIGNATURE_BASE_BUILD_FAILED.
  if (isReq && req.request === undefined)
    throw new Error(
      `"${cid}";req is covered but no associated request was given (set RequestLike.request)`,
    );
  const target: RequestLike = isReq ? (req.request as RequestLike) : req;
  // RFC 9421 §2.1.4: `;tr` selects the message's trailers as the field
  // source instead of its headers. Derived components have no field
  // value in either place, so `;tr` on one is a hard error on both
  // sides, like `;bs`/`;sf`/`;key`. With `;req`, the trailers are
  // those of the associated request (target already resolved above).
  if (isTr && cid.startsWith("@"))
    throw new Error(
      `unsupported component parameter ";tr" on derived component "${cid}": ";tr" is only supported on header field components`,
    );
  const fieldSource: Record<string, string | string[] | undefined> = isTr
    ? (target.trailers ?? {})
    : target.headers;
  const fieldKind = isTr ? "trailer" : "header";
  // RFC 9421 §2.1.2: `;bs` serializes a *field value* as a byte
  // sequence. Derived components have no field value — their values
  // are already canonical strings — so `;bs` on one is a hard error
  // on both sides (sign: throw; verify: SIGNATURE_BASE_BUILD_FAILED
  // via buildSignatureBase), never silently ignored.
  if (isBs) {
    if (cid.startsWith("@"))
      throw new Error(
        `unsupported component parameter ";bs" on derived component "${cid}": ";bs" is only supported on header field components`,
      );
    const raw = getHeaderRaw(fieldSource, cid);
    if (raw === undefined)
      throw new Error(`covered ${fieldKind} field "${cid}" is missing from the request`);
    return `:${Buffer.from(raw, "utf8").toString("base64")}:`;
  }
  // RFC 9421 §2.1.1: `;sf` re-serializes a *field value* with the
  // strict Structured Field rules. As with `;bs`, a derived component
  // has no field value to parse, so `;sf` on one is a hard error on
  // both sides. A field value that is not a valid Structured Field
  // fails closed the same way — never silently signed as-is.
  if (isSf) {
    if (cid.startsWith("@"))
      throw new Error(
        `unsupported component parameter ";sf" on derived component "${cid}": ";sf" is only supported on header field components`,
      );
    const v = getHeader(fieldSource, cid);
    if (v === undefined)
      throw new Error(`covered ${fieldKind} field "${cid}" is missing from the request`);
    try {
      return canonicalizeStructuredFieldValue(normalizeFieldValue(v));
    } catch (err) {
      throw new Error(
        `covered ${fieldKind} field "${cid}" cannot be serialized with ";sf": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  // RFC 9421 §2.1.1: `;key` selects one member of a Dictionary
  // field value. A derived component has no field value to select
  // from, so `;key` on one is a hard error on both sides, like
  // `;bs`/`;sf`. The selected member is serialized strictly WITHOUT
  // its key (a missing member or a non-Dictionary value fails closed
  // — never an empty string, which would let distinct field values
  // collide onto one signature base).
  if (dictKey !== undefined) {
    if (cid.startsWith("@"))
      throw new Error(
        `unsupported component parameter ";key" on derived component "${cid}": ";key" is only supported on header field components`,
      );
    const v = getHeader(fieldSource, cid);
    if (v === undefined)
      throw new Error(`covered ${fieldKind} field "${cid}" is missing from the request`);
    try {
      return serializeDictionaryMemberValue(normalizeFieldValue(v), dictKey);
    } catch (err) {
      throw new Error(
        `covered ${fieldKind} field "${cid}" cannot be serialized with ";key=\"${dictKey}\"": ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
  const url = new URL(target.url);
  switch (cid) {
    case "@method":
      return target.method.toUpperCase();
    case "@scheme":
      return url.protocol.replace(/:$/, "").toLowerCase();
    case "@authority":
      return url.host.toLowerCase();
    case "@path":
      return url.pathname || "/";
    case "@query":
      // RFC 9421 §2.2.7: the query component of the request target,
      // including the leading "?" — empty string when the URL has no query.
      return url.search;
    case "@query-param":
      // RFC 9421 §2.2.8: one named query parameter, addressed by the
      // REQUIRED ;name parameter (parseComponentId has already
      // rejected a missing or malformed one, so this is defensive).
      if (queryParamName === undefined)
        throw new Error(
          'derived component "@query-param" requires the ";name" component parameter',
        );
      return resolveQueryParamValue(target, queryParamName);
    case "@target-uri":
      return target.url;
    case "@created":
      if (params.created === undefined)
        throw new Error('"@created" is covered but no created parameter was given');
      return String(params.created);
    case "@expires":
      if (params.expires === undefined)
        throw new Error('"@expires" is covered but no expires parameter was given');
      return String(params.expires);
    case "@status":
      // RFC 9421 §2.2.9: the status code of the response. There is no
      // sensible default — a covered @status with no status to bind is a
      // caller configuration error, same fail-fast style as @created/@expires.
      if (target.status === undefined)
        throw new Error('"@status" is covered but no status was given');
      return String(target.status);
    default: {
      const v = getHeader(fieldSource, cid);
      if (v === undefined)
        throw new Error(`covered ${fieldKind} field "${cid}" is missing from the request`);
      return normalizeFieldValue(v);
    }
  }
}

/** Serialize the inner-list of covered components plus its parameters. */
export function serializeSignatureParams(
  componentIds: string[],
  params: SignatureParams,
): string {
  const items = componentIds.map((c) => serializeComponentId(c)).join(" ");
  let out = `(${items})`;
  if (params.created !== undefined) out += `;created=${params.created}`;
  if (params.expires !== undefined) out += `;expires=${params.expires}`;
  if (params.keyid !== undefined) out += `;keyid=${quoteString(params.keyid)}`;
  if (params.alg !== undefined) out += `;alg=${quoteString(params.alg)}`;
  if (params.nonce !== undefined) out += `;nonce=${quoteString(params.nonce)}`;
  if (params.tag !== undefined) out += `;tag=${quoteString(params.tag)}`;
  return out;
}

/** Full `Signature-Input` field value for one signature label. */
export function signatureInputValue(
  label: string,
  componentIds: string[],
  params: SignatureParams,
): string {
  return `${label}=${serializeSignatureParams(componentIds, params)}`;
}

/**
 * Build the exact byte string that gets signed (RFC 9421 §2.5):
 * one `"id": value` line per covered component, then the
 * `"@signature-params"` line.
 */
export function buildSignatureBase(
  componentIds: string[],
  req: RequestLike,
  params: SignatureParams,
): string {
  const lines = componentIds.map((id) => {
    const value = resolveComponent(id, req, params);
    return `${serializeComponentId(id)}: ${value}`;
  });
  lines.push(`"@signature-params": ${serializeSignatureParams(componentIds, params)}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Parsing (verifier side)
// ---------------------------------------------------------------------------

export interface ParsedSignatureInput {
  label: string;
  componentIds: string[];
  params: SignatureParams;
}

/**
 * Parse the inside of a covered-components inner list, preserving any
 * component parameters that follow a quoted identifier (the old
 * quoted-strings-only scan silently swallowed a `;req` suffix, which
 * rebuilt a different signature base than the signer signed). Each id
 * keeps the suffix it carried on the wire (name lowercased, value
 * as-is); `serializeComponentId` canonicalizes a supported
 * `;req`/`;bs` suffix (`;req` before `;bs`) when the base is
 * rebuilt, and unsupported parameters are preserved verbatim in
 * the stored form so `resolveComponent` can reject them
 * fail-closed instead of ignoring them. (Wording covers `;sf`,
 * `;tr`, `;name="…"`, and
 * `;key="…"` the same way: a supported suffix is canonicalized on
 * rebuild, with the `;key`/`;name` string value preserved as-is.)
 */
function parseComponentIds(inner: string): string[] {
  const ids: string[] = [];
  let i = 0;
  while (i < inner.length) {
    while (i < inner.length && /\s/.test(inner[i])) i++;
    if (i >= inner.length) break;
    if (inner[i] !== '"')
      throw new Error(
        `malformed covered component at offset ${i}: expected a quoted string`,
      );
    let j = i + 1;
    let raw = "";
    let closed = false;
    while (j < inner.length) {
      const c = inner[j];
      if (c === "\\" && j + 1 < inner.length) {
        raw += inner[j + 1];
        j += 2;
      } else if (c === '"') {
        closed = true;
        j++;
        break;
      } else {
        raw += c;
        j++;
      }
    }
    if (!closed)
      throw new Error("malformed covered component: unterminated quoted string");
    let suffix = "";
    // Component parameters: `;name` or `;name=value` sequences directly
    // following the quoted identifier (RFC 9421 §2.4 / RFC 8941 §3.1.2).
    while (j < inner.length && inner[j] === ";") {
      const pm = /^;([A-Za-z][A-Za-z0-9_-]*)(?:=("(?:[^"\\]|\\.)*"|[^\s;]+))?/.exec(
        inner.slice(j),
      );
      if (!pm)
        throw new Error(
          `malformed component parameter at offset ${j} in covered components`,
        );
      suffix += `;${pm[1].toLowerCase()}${pm[2] !== undefined ? `=${pm[2]}` : ""}`;
      j += pm[0].length;
    }
    ids.push(raw.toLowerCase() + suffix);
    i = j;
  }
  return ids;
}

function parseParamList(segment: string): SignatureParams {
  const params: SignatureParams = {};
  // A repeated parameter is ambiguous authenticated input: a verifier must
  // not silently let the later value win (signature ambiguity /
  // malleability). Every parsed parameter name is recorded; the second
  // occurrence — case variants included ("Created" vs "created", names are
  // matched case-insensitively per RFC 9421 §2.4) — is a hard parse error
  // that verifyRequest converges to MALFORMED_SIGNATURE_INPUT.
  const seen = new Set<string>();
  const re = /;\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(segment)) !== null) {
    const key = m[1].toLowerCase();
    if (seen.has(key))
      throw new Error(`duplicate signature-input parameter ";${key}"`);
    seen.add(key);
    if (m[2] !== undefined) {
      const s = unquoteString(m[2]);
      if (key === "keyid") params.keyid = s;
      else if (key === "alg") params.alg = s;
      else if (key === "nonce") params.nonce = s;
      else if (key === "tag") params.tag = s;
    } else if (m[3] !== undefined) {
      const n = parseInt(m[3], 10);
      if (key === "created") params.created = n;
      else if (key === "expires") params.expires = n;
    }
  }
  return params;
}

/** Parse one signature's covered components + parameters from Signature-Input. */
export function parseSignatureInput(
  fieldValue: string,
  label: string,
): ParsedSignatureInput {
  const labelRe = new RegExp(`(?:^|,)\\s*${escapeRegExp(label)}\\s*=`);
  const m = labelRe.exec(fieldValue);
  if (!m) throw new Error(`signature "${label}" not present in Signature-Input`);
  const rest = fieldValue.slice(m.index + m[0].length).trimStart();
  if (!rest.startsWith("("))
    throw new Error("malformed Signature-Input: expected inner list");
  const close = rest.indexOf(")");
  if (close === -1)
    throw new Error("malformed Signature-Input: unterminated inner list");
  const componentIds = parseComponentIds(rest.slice(1, close));
  const after = rest.slice(close + 1);
  // Parameters run until the next top-level comma (start of another signature).
  const nextSig = after.search(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  const segment = nextSig === -1 ? after : after.slice(0, nextSig);
  return { label, componentIds, params: parseParamList(segment) };
}

/** Extract the raw signature bytes for `label` from a Signature field value. */
export function parseSignatureField(fieldValue: string, label: string): Buffer {
  const re = new RegExp(
    `(?:^|,)\\s*${escapeRegExp(label)}\\s*=:([A-Za-z0-9+/=]+):`,
  );
  const m = re.exec(fieldValue);
  if (!m) throw new Error(`signature "${label}" not present in Signature field`);
  return Buffer.from(m[1], "base64");
}

/**
 * List every signature label present in a `Signature-Input` field value,
 * in wire order. Splits on top-level commas: commas inside the
 * parenthesized component list or inside quoted strings do not count.
 * Duplicate labels are returned once (first occurrence wins), matching
 * `parseSignatureInput`'s first-match behavior.
 *
 * Throws on a member that is not `label=(...)…` shaped.
 */
export function listSignatureLabels(fieldValue: string): string[] {
  const members: string[] = [];
  let depth = 0;
  let inString = false;
  let start = 0;
  for (let i = 0; i < fieldValue.length; i++) {
    const c = fieldValue[i];
    if (inString) {
      if (c === "\\") i++; // skip escaped character
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
    } else if (c === "(") {
      depth++;
    } else if (c === ")") {
      if (depth > 0) depth--;
    } else if (c === "," && depth === 0) {
      members.push(fieldValue.slice(start, i));
      start = i + 1;
    }
  }
  members.push(fieldValue.slice(start));
  const labels: string[] = [];
  for (const member of members) {
    const m =
      /^\s*([A-Za-z][A-Za-z0-9!#$%&'*+\-.^_`|~]*)\s*=/.exec(member);
    if (!m)
      throw new Error(`malformed Signature-Input member: "${member.trim()}"`);
    if (!labels.includes(m[1])) labels.push(m[1]);
  }
  return labels;
}
