/**
 * Covered-component resolution, signature-base construction, and
 * Signature-Input parsing for a practical subset of RFC 9421
 * (HTTP Message Signatures).
 *
 * Covered components supported: @method, @scheme, @authority, @path,
 * @target-uri, @created, @expires, plus any HTTP header field name.
 * Signature algorithms are handled by sign.ts / verify.ts; this module
 * only deals with the canonical bytes that get signed.
 */

export interface RequestLike {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body?: string | Buffer;
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
 * Case-insensitive header lookup. Multi-value headers are joined with
 * ", " per RFC 9421 §2.5.
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
      return Array.isArray(v) ? v.map((x) => x.trim()).join(", ") : v;
    }
  }
  return undefined;
}

function normalizeFieldValue(value: string): string {
  // RFC 9421 §2.5: strip leading/trailing whitespace, unfold obs-fold.
  return value.replace(/^[ \t]+|[ \t]+$/g, "").replace(/\r\n[ \t]+/g, " ");
}

/** Resolve one covered component identifier to its canonical string value. */
export function resolveComponent(
  id: string,
  req: RequestLike,
  params: SignatureParams,
): string {
  const cid = id.toLowerCase();
  const url = new URL(req.url);
  switch (cid) {
    case "@method":
      return req.method.toUpperCase();
    case "@scheme":
      return url.protocol.replace(/:$/, "").toLowerCase();
    case "@authority":
      return url.host.toLowerCase();
    case "@path":
      return url.pathname || "/";
    case "@target-uri":
      return req.url;
    case "@created":
      if (params.created === undefined)
        throw new Error('"@created" is covered but no created parameter was given');
      return String(params.created);
    case "@expires":
      if (params.expires === undefined)
        throw new Error('"@expires" is covered but no expires parameter was given');
      return String(params.expires);
    default: {
      const v = getHeader(req.headers, cid);
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
  const items = componentIds.map((c) => quoteString(c.toLowerCase())).join(" ");
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
    return `${quoteString(id.toLowerCase())}: ${value}`;
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

function parseQuotedStrings(inner: string): string[] {
  const ids: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) ids.push(unquoteString(m[1]));
  return ids;
}

function parseParamList(segment: string): SignatureParams {
  const params: SignatureParams = {};
  const re = /;\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(segment)) !== null) {
    const key = m[1].toLowerCase();
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
  const componentIds = parseQuotedStrings(rest.slice(1, close));
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
