/**
 * Covered-component resolution, signature-base construction, and
 * Signature-Input parsing for a practical subset of RFC 9421
 * (HTTP Message Signatures).
 *
 * Covered components supported: @method, @scheme, @authority, @path, @query,
 * @status, @target-uri, @created, @expires, plus any HTTP header field name.
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
 * (`"@method";bs`, …) is rejected on both sides. Other component
 * parameters (`;key`, `;sf`, …) are not supported and fail closed.
 * Signature algorithms are handled by sign.ts / verify.ts; this module
 * only deals with the canonical bytes that get signed.
 */

export interface RequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
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
}

/**
 * Split a covered component identifier into its bare name and its
 * component parameters. Only the bare (valueless) parameters `;req`
 * and `;bs` are supported, each at most once, in either order; any
 * other parameter (`;key`, `;sf`, a valued `;req=…`/`;bs=…`, or a
 * duplicate) is a hard error — silently ignoring an unknown parameter
 * would build a different signature base than the signer intended, so
 * this fails closed on both sides.
 */
function parseComponentId(raw: string): ComponentIdParts {
  const parts = raw.trim().split(";");
  const base = parts[0].trim().toLowerCase();
  if (parts.length === 1) return { base, req: false, bs: false };
  const params = parts.slice(1).map((p) => p.trim().toLowerCase());
  const bad = params.find((p) => p !== "req" && p !== "bs");
  if (bad !== undefined)
    throw new Error(
      `unsupported component parameter ";${bad}" on component "${base}": only ";req" and ";bs" are supported`,
    );
  if (new Set(params).size !== params.length)
    throw new Error(
      `duplicate component parameter on component "${base}": ";req" and ";bs" may each appear at most once`,
    );
  return { base, req: params.includes("req"), bs: params.includes("bs") };
}

/**
 * Canonical wire form of one component identifier: `"base"`, optionally
 * followed by `;req` then `;bs` (canonical order, regardless of the
 * order the caller wrote them in).
 */
function serializeComponentId(raw: string): string {
  const { base, req, bs } = parseComponentId(raw);
  return `${quoteString(base)}${req ? ";req" : ""}${bs ? ";bs" : ""}`;
}

/** Resolve one covered component identifier to its canonical string value. */
export function resolveComponent(
  id: string,
  req: RequestLike,
  params: SignatureParams,
): string {
  const { base: cid, req: isReq, bs: isBs } = parseComponentId(id);
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
    const raw = getHeaderRaw(target.headers, cid);
    if (raw === undefined)
      throw new Error(`covered header field "${cid}" is missing from the request`);
    return `:${Buffer.from(raw, "utf8").toString("base64")}:`;
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
      // RFC 9421 §2.2.8: the status code of the response. There is no
      // sensible default — a covered @status with no status to bind is a
      // caller configuration error, same fail-fast style as @created/@expires.
      if (target.status === undefined)
        throw new Error('"@status" is covered but no status was given');
      return String(target.status);
    default: {
      const v = getHeader(target.headers, cid);
      if (v === undefined)
        throw new Error(`covered header field "${cid}" is missing from the request`);
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
 * fail-closed instead of ignoring them.
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
