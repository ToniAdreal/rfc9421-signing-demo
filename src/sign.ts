import {
  constants,
  createHmac,
  createSign,
  sign as edSign,
  type KeyObject,
} from "node:crypto";
import {
  buildSignatureBase,
  joinHeaderValues,
  listSignatureLabels,
  MAX_COVERED_COMPONENTS,
  signatureInputValue,
  type RequestLike,
  type SignatureParams,
} from "./components.js";
import { contentDigest, assertContentDigestAlg, contentDigestAlgOf } from "./digest.js";
import type { ContentDigestAlg } from "./digest.js";
import { algMatchesKeyShape, assertHmacSecretLength, assertRsaModulusLength, describeKey } from "./keys.js";
import {
  assertStructuredFieldTypes,
  type StructuredFieldType,
} from "./structuredFields.js";

/**
 * Longest `tag` / `nonce` / `keyid` a `signRequest` call may emit, in
 * characters (`String.length`, UTF-16 code units). All three are short
 * identifiers by nature — a tag names one application protocol, a
 * nonce is one replay token, a keyid is a lookup key — so 256 leaves
 * an order of magnitude of headroom over any realistic value, while
 * an over-long value is almost certainly a caller bug (a payload
 * pasted into a label field) and is rejected fail-fast, before the
 * signature base is built or any crypto runs.
 *
 * Sign side only, deliberately: the verifier does NOT apply these
 * caps. RFC 9421 sets no per-field length limit on `tag` / `nonce` /
 * `keyid`, so a validly signed longer value from another
 * implementation still verifies — rejecting it would be a
 * non-conformant interop restriction. The 64 KiB
 * `DEFAULT_MAX_SIGNATURE_INPUT_LENGTH` cap bounds total
 * `signature-input` size on the verify side instead. This asymmetry
 * is pinned by `test/signParamLimits.test.ts`: our signer refuses a
 * 257-character tag, our verifier accepts a hand-minted 300-character
 * one.
 *
 * Contrast `MAX_COVERED_COMPONENTS` (64, in `components.ts`): that
 * cap IS symmetric — the verify-side parser refuses a longer list
 * with `MALFORMED_SIGNATURE_INPUT` — so the sign side refusing more
 * than 64 keeps the signer from minting signatures its own verifier
 * refuses.
 */
export const MAX_TAG_LENGTH = 256;
export const MAX_NONCE_LENGTH = 256;
export const MAX_KEY_ID_LENGTH = 256;

export type SignAlg =
  | "ed25519"
  | "hmac-sha256"
  | "hmac-sha512"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ecdsa-p521-sha512"
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256";

export interface SignOptions {
  /**
   * Optional per RFC 9421 (§2.3): `keyid` is not a required parameter.
   * When omitted, no `keyid` parameter is emitted in `signature-input`
   * (the verifier returns `keyId: undefined`, and `keyResolver`/
   * `expectedKeyId` flows treat a missing `keyid` the way they already
   * do — e.g. `keyResolver` reports `KEY_RESOLUTION_FAILED`).
   * Longer than `MAX_KEY_ID_LENGTH` (256) characters is rejected with
   * a configuration error (a keyid is a short lookup key, not a
   * payload); the verifier applies no such cap (see the constants
   * above for the reasoning).
   */
  keyId?: string;
  alg: SignAlg;
  /**
   * ed25519: a private KeyObject (see keys.generateEd25519KeyPair).
   * ecdsa-p256-sha256: a P-256 private KeyObject (see
   * keys.generateP256KeyPair); signatures are the raw r‖s concatenation
   * (each integer padded to 32 octets, 64 octets total) that RFC 9421
   * §3.3.4 defines.
   * ecdsa-p384-sha384: a P-384 private KeyObject (see
   * keys.generateP384KeyPair); signatures are the raw r‖s concatenation
   * (each integer padded to 48 octets, 96 octets total) that RFC 9421
   * §3.3.5 defines.
   * ecdsa-p521-sha512: a P-521 private KeyObject (see
   * keys.generateP521KeyPair); signatures are the raw r‖s concatenation
   * (each integer padded to 66 octets, 132 octets total) that RFC 9421
   * §3.3.6 defines.
   * rsa-pss-sha512: an RSA private KeyObject (see
   * keys.generateRsaPssKeyPair); signed with RSASSA-PSS (SHA-512, MGF1
   * with SHA-512, 64-byte salt) per RFC 9421 §3.3.1.
   * rsa-v1_5-sha256: an RSA private KeyObject (see
   * keys.generateRsaV15KeyPair — the same RSA key material as PSS);
   * signed with RSASSA-PKCS1-v1_5 (SHA-256) per RFC 9421 §3.3.2. The
   * key must be RSA with a ≥ 2048-bit modulus; anything else throws a
   * configuration error before any crypto runs.
   * hmac-sha256: a secret KeyObject of ≥ 32 bytes (see keys.secretKey).
   * hmac-sha512: a secret KeyObject of ≥ 64 bytes (RFC 2104 §3 pairs the
   * floor with the hash output length; a 32–63 byte secret is rejected on
   * both the sign and verify sides).
   */
  key: KeyObject;
  /** Unix seconds. Defaults to now. */
  created?: number;
  /** Unix seconds. Optional; verifiers reject the signature after this time. */
  expires?: number;
  /** Signature label. Defaults to "sig1". */
  label?: string;
  /**
   * Optional nonce (RFC 9421 §2.3): emitted as a `nonce` signature-input
   * parameter and therefore covered by the signature. The verifier
   * returns it on `VerifyResult.nonce`; tracking seen nonces to detect
   * replays is the caller's job. An empty-string nonce is rejected with
   * a configuration error (it would silently bypass replay detection).
   * Longer than `MAX_NONCE_LENGTH` (256) characters is rejected the
   * same way; the verifier applies no such cap (see the constants
   * above for the reasoning).
   */
  nonce?: string;
  /**
   * Optional application tag (RFC 9421 §2.3): emitted as a `tag`
   * signature-input parameter and therefore covered by the signature.
   * The tag binds the signature to one application protocol (e.g.
   * `"payment-webhook-v1"`), so a signature minted for one protocol
   * cannot be replayed into another that happens to share a key: the
   * verifier pins its expected protocol with
   * `VerifyOptions.expectedTag` and mismatches fail with
   * `TAG_MISMATCH`. The verifier returns the wire tag on
   * `VerifyResult.tag`. An empty-string tag is rejected with a
   * configuration error (it binds nothing and is indistinguishable
   * from a signer that forgot to set one). Longer than
   * `MAX_TAG_LENGTH` (256) characters is rejected the same way; the
   * verifier applies no such cap (see the constants above for the
   * reasoning).
   */
  tag?: string;
  /**
   * Covered components, in order. Defaults to
   * ["@method", "@authority", "@path"] plus "content-digest" when a body
   * is present. More than `MAX_COVERED_COMPONENTS` (64) entries are
   * rejected with a configuration error — the verifier's parser
   * refuses a longer list with `MALFORMED_SIGNATURE_INPUT`, so the
   * signer must never mint one.
   */
  coveredComponents?: string[];
  /**
   * Content-Digest hash algorithm emitted when `content-digest` is
   * covered and the request has a body. Defaults to `"sha-512"`; pass
   * `"sha-256"` when the peer (e.g. a payment gateway webhook endpoint)
   * only accepts sha-256 digests. Any other value is a configuration
   * error, thrown before any crypto runs. The verifier already accepts
   * both algorithms, so a sha-256 signature round-trips through
   * `verifyRequest` unchanged.
   */
  contentDigestAlg?: ContentDigestAlg;
  /**
   * Per-field Structured Field type registry for `;sf` and `;key`
   * covered components (RFC 9421 §2.1.1): maps a header field name
   * to the one type that field's value is — `"dictionary"`,
   * `"list"`, or `"item"`. A registered field is parsed only as its
   * registered type: a Dictionary-shaped value registered as
   * `"list"` fails fast on the sign side instead of silently
   * serializing under the trial order's first match, and under
   * `;key` a field registered as a List or an Item fails fast (a
   * field registered as a Dictionary behaves as before), so the
   * registry and `;key` agree on the field's type. Field names
   * match case-insensitively (header names are case-insensitive);
   * two keys differing only by case, an empty field name, or an
   * unknown type name is a caller configuration error (throw,
   * before any crypto runs). Fields absent from the map keep the
   * default Dictionary → List → Item trial order, so omitting the
   * option is fully backwards compatible. The verifier must be
   * given the same registry for its own side (see
   * `VerifyOptions.structuredFieldTypes`) — the registry is caller
   * configuration, not wire data, so it is never emitted into
   * `signature-input`. It does not affect `;bs` components (raw
   * bytes keep their own rule), and `;sf` combined with `;bs` or
   * `;key` still fails closed.
   */
  structuredFieldTypes?: Record<string, StructuredFieldType>;
}

export interface SignedHttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string | Buffer | undefined;
  /**
   * HTTP response status code, carried through from the signed
   * `RequestLike` when present. Only consulted when `"@status"` is
   * covered; preserved so `addSignature` can rebuild the second
   * signature base for multi-party response signing without losing it.
   */
  status?: number;
  /**
   * Associated request, carried through from the signed `RequestLike`
   * when present. Only consulted when a covered component carries
   * `;req`; preserved so a signed response can be verified (and
   * `addSignature` can rebuild a second base) without the caller
   * re-attaching the triggering request by hand.
   */
  request?: RequestLike;
  /**
   * Trailer fields, carried through from the signed `RequestLike`
   * when present. Only consulted when a covered component carries
   * `;tr`; preserved so the signed message can be verified (and
   * `addSignature` can rebuild a second base) without the caller
   * re-attaching the trailers by hand.
   */
  trailers?: Record<string, string | string[] | undefined>;
  /**
   * Explicit request-target override, carried through from the
   * signed `RequestLike` when present. Only consulted when
   * `"@request-target"` is covered; preserved so the signed message
   * can be verified (and `addSignature` can rebuild a second base)
   * without the caller re-attaching the override by hand. Without
   * this carry-through, a signature minted over an absolute-,
   * authority-, or asterisk-form target would verify against the
   * origin-form reconstruction and fail.
   */
  requestTarget?: string;
  /**
   * Covered components this signature actually covers, in signature
   * order — the wire value, not a re-derivation: it is exactly the
   * `SignOptions.coveredComponents` list (or the default set when the
   * caller omitted one) that `signRequest` wrote into
   * `signature-input`. A caller auditing "what did this signature
   * cover?" reads this field instead of parsing the header a second
   * time — the sign-side mirror of `VerifyResult.coveredComponents`
   * (#566), so the two sides can be compared item for item. Always a
   * detached copy: mutating it never affects a later signature or
   * verification. For `addSignature`, this is the appended
   * signature's own list, not the merged list of both labels.
   */
  coveredComponents?: string[];
}

function defaultCoveredComponents(hasBody: boolean): string[] {
  return hasBody
    ? ["@method", "@authority", "@path", "content-digest"]
    : ["@method", "@authority", "@path"];
}

/**
 * Canonical identity of one covered-component entry for duplicate
 * detection: the base identifier lowercased (component ids are
 * case-insensitive, RFC 9421 §2.1) with surrounding quotes stripped,
 * plus each parameter name lowercased, in listed order. Parameter
 * values are kept verbatim — Dictionary keys (`;key="a"` vs
 * `;key="b"`) and query-param names are case-sensitive, so two
 * entries differing only in a parameter value name different
 * components.
 *
 * The parameters are part of the key on purpose: a parameter
 * reroutes what the component binds, so `"@method"` and
 * `"@method";req` are distinct identifiers — the first binds this
 * message's method, the second the associated request's method
 * (RFC 9421 §2.2.7), and covering both is legitimate (pinned by
 * `test/reqComponent.test.ts`: same base, `@method` vs `@method;req`,
 * coexists). What is rejected is the same identifier twice:
 * `"@method"` + `"@method"`, or case/quoting variants of it
 * (`"@METHOD"`, `"@method";req` + `"@METHOD";REQ`), which would
 * mint a signature base with the identical line twice — a silent
 * non-standard signature the verifier rejects as
 * `MALFORMED_SIGNATURE_INPUT` (backlog #1001: the verify side
 * applies this same identity at parse time). Entries this helper
 * cannot split (malformed) fall
 * through to `buildSignatureBase`, which reports them properly;
 * the key is only used for equality, never for parsing.
 */
export function coveredComponentKey(entry: string): string {
  const input = entry.trim();
  const semi = input.indexOf(";");
  let base = (semi === -1 ? input : input.slice(0, semi)).trim().toLowerCase();
  if (base.length >= 2 && base.startsWith('"') && base.endsWith('"'))
    base = base.slice(1, -1);
  if (semi === -1) return base;
  const params = input
    .slice(semi + 1)
    .split(";")
    .map((p) => {
      const eq = p.indexOf("=");
      const name = (eq === -1 ? p : p.slice(0, eq)).trim().toLowerCase();
      return eq === -1 ? name : `${name}=${p.slice(eq + 1).trim()}`;
    })
    .join(";");
  return `${base};${params}`;
}

/**
 * Fail fast on a repeated covered component, before the signature
 * base is built and before any crypto runs. Without this,
 * `["@method", "@method"]` mints a base with the `@method` line
 * twice; the verifier applies the same identity at parse time and
 * rejects it as `MALFORMED_SIGNATURE_INPUT` (backlog #1001), so
 * this guard keeps the signer from minting signatures its own
 * verifier refuses. `signResponse` calls this
 * with its own name (it delegates the actual signing to
 * `signRequest`, so the message names the entry point the caller
 * used); `addSignature` / `addResponseSignature` inherit the
 * guard through `signRequest` / `signResponse`.
 */
export function assertNoDuplicateCoveredComponents(
  caller: "signRequest" | "signResponse",
  covered: string[],
): void {
  const seen = new Set<string>();
  for (const entry of covered) {
    const key = coveredComponentKey(entry);
    if (seen.has(key))
      throw new Error(
        `${caller}: coveredComponents must not repeat a component, got ${JSON.stringify(entry)} twice`,
      );
    seen.add(key);
  }
}

/**
 * `created`/`expires` are Unix seconds on the wire, and the verifier's
 * `signature-input` parser only recognizes the `-?\d+` integer shape.
 * Reject anything else here so the signer can never emit a timestamp the
 * verifier would silently truncate (e.g. `1759.5` → `1759`).
 */
function assertTimestamp(name: "created" | "expires", value: number): void {
  if (!Number.isInteger(value))
    throw new Error(
      `signRequest: "${name}" must be an integer number of Unix seconds, got ${value}`,
    );
}

/**
 * The label becomes a dictionary member key in the `signature-input` /
 * `signature` headers. `listSignatureLabels` splits members on top-level
 * commas and matches keys against a token shape, so a label containing a
 * comma or a space would emit a header the verifier's own multi-label path
 * (`verifyAllLabels`) reports as MALFORMED_SIGNATURE_INPUT. Reject anything
 * that is not a token the library can parse back.
 *
 * The shape is the RFC 8941 token shape used by RFC 9421 dictionaries,
 * minus `:` `/` and a leading `*`: this library's dictionary parser
 * (`listSignatureLabels`) cannot split members whose keys contain those
 * characters, so accepting them here would mint signatures
 * `verifyAllLabels` cannot read back. Labels like `sig1`, `merchant-1`,
 * or `gateway.key_sig` are accepted.
 */
const LABEL_TOKEN_RE = /^[A-Za-z][A-Za-z0-9!#$%&'*+\-.^_`|~]*$/;
function assertLabelShape(label: string): void {
  if (!LABEL_TOKEN_RE.test(label))
    throw new Error(
      `signRequest: "label" must be an RFC 9421 token (start with a letter, then letters, digits, or one of !#$%&'*+-.^_\`|~ — no commas, spaces, colons, or slashes), got "${label}"`,
    );
}

/**
 * Fail fast on an over-long sign-side identifier (see
 * `MAX_TAG_LENGTH` / `MAX_NONCE_LENGTH` / `MAX_KEY_ID_LENGTH`).
 * The name in the message is the `SignOptions` field name.
 */
function assertSignParamLength(
  name: "tag" | "nonce" | "keyId",
  value: string,
  max: number,
): void {
  if (value.length > max)
    throw new Error(
      `signRequest: "${name}" must be at most ${max} characters, got ${value.length}`,
    );
}

/**
 * Whether `alg` names an algorithm this library implements (the
 * `SignAlg` union). Algorithm names are matched exactly — no case
 * folding: a wire or caller value of `"ED25519"` is not `"ed25519"`
 * and is unsupported, the same verdict the verify side reaches for a
 * miscased wire `alg` (`UNSUPPORTED_ALG`). Kept next to the dispatch
 * chain below so the three listings (union, guard, dispatch) drift
 * together, never apart.
 */
function isSupportedAlg(alg: string): alg is SignAlg {
  return (
    alg === "ed25519" ||
    alg === "hmac-sha256" ||
    alg === "hmac-sha512" ||
    alg === "ecdsa-p256-sha256" ||
    alg === "ecdsa-p384-sha384" ||
    alg === "ecdsa-p521-sha512" ||
    alg === "rsa-pss-sha512" ||
    alg === "rsa-v1_5-sha256"
  );
}

/**
 * Sign an HTTP request per RFC 9421. Returns a copy of the request with
 * `Signature-Input`, `Signature` (and `Content-Digest` when the body is
 * covered) headers attached. The input request is not mutated.
 *
 * Fail-fast configuration errors (thrown, not embedded in the signature):
 * - `coveredComponents: []` signs nothing, so it is rejected;
 * - a covered component listed twice (same identifier after
 *   lowercasing the base and parameter names, parameters included —
 *   `"@method"` + `"@method"`, or `"@method";req` + `"@METHOD";REQ`)
 *   is rejected: it would mint a base with the identical line twice,
 *   a silent non-standard signature the verifier also rejects as
 *   `MALFORMED_SIGNATURE_INPUT` (backlog #1001). `"@method"` +
 *   `"@method";req` is NOT a
 *   duplicate — `;req` reroutes the component to the associated
 *   request, so the two bind different values;
 * - `created` / `expires` must be finite integers (Unix seconds) — the
 *   verifier's `signature-input` parser only recognizes integer values, so
 *   a fractional timestamp would silently diverge between signer and
 *   verifier;
 * - `expires < created` would mint a signature that is already expired, so
 *   it is rejected (`expires === created` is allowed);
 * - `nonce: ""` would be emitted yet bypass the replay cache, so it is
 *   rejected;
 * - `tag: ""` would bind the signature to no application protocol, so
 *   it is rejected;
 * - `tag` / `nonce` / `keyid` longer than 256 characters
 *   (`MAX_TAG_LENGTH` / `MAX_NONCE_LENGTH` / `MAX_KEY_ID_LENGTH`)
 *   are rejected: all three are short identifiers by nature, and an
 *   over-long value is almost certainly a caller bug. Sign side only —
 *   the verifier applies no per-field cap (RFC 9421 sets none), so a
 *   validly signed longer value from another implementation still
 *   verifies; see the constants above;
 * - more than 64 covered components (`MAX_COVERED_COMPONENTS`, the
 *   same bound the verify-side parser applies) is rejected: the
 *   verifier refuses a longer list with `MALFORMED_SIGNATURE_INPUT`,
 *   so minting one would produce a signature this library itself
 *   cannot verify;
 * - `label` must be an RFC 9421 token the verifier can parse back: commas
 *   and spaces would corrupt the `signature-input` dictionary (the label
 *   is the member key `verifyAllLabels` splits on), and `:`/`/`/leading
 *   `*` are refused because `listSignatureLabels` cannot split members
 *   whose keys contain them.
 * - `contentDigestAlg` must be `"sha-512"` or `"sha-256"` — anything else
 *   would emit a digest the verifier cannot name.
 * - `alg` must name an algorithm this library implements and match
 *   the shape of `key` (ed25519 needs an Ed25519 key, `hmac-*` a secret
 *   key, each `ecdsa-p*-*` the EC key on the matching curve, `rsa-*` an
 *   RSA key) — checked here, before the signature base is built and
 *   before any crypto runs, so a swapped key or alg is a clear
 *   configuration error instead of a cryptic node:crypto complaint.
 *   An unknown `alg` (including the classic downgrade value `"none"`)
 *   is rejected first, as `unsupported alg`, so it is never misreported
 *   as a key mismatch — no key of any shape can sign `"none"`.
 *   `signResponse`, `addSignature`, and `addResponseSignature` inherit
 *   these checks through `signRequest`.
 */
export function signRequest(
  req: RequestLike,
  opts: SignOptions,
): SignedHttpRequest {
  const label = opts.label ?? "sig1";
  assertLabelShape(label);
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  assertTimestamp("created", created);
  if (opts.expires !== undefined) {
    assertTimestamp("expires", opts.expires);
    if (opts.expires < created)
      throw new Error(
        `signRequest: "expires" (${opts.expires}) must not be earlier than "created" (${created}); the signature would be expired at birth`,
      );
  }
  // An empty-string nonce would be emitted into signature-input yet
  // silently bypass the verify-side replay cache (which skips empty
  // nonces) — fail fast rather than minting a signature that looks
  // replay-protected but isn't.
  if (opts.nonce !== undefined && opts.nonce === "")
    throw new Error(
      'signRequest: "nonce" must not be an empty string; the replay cache skips empty nonces, so this would bypass replay protection',
    );
  // An empty-string tag binds the signature to no application protocol
  // at all — fail fast rather than minting a signature that looks
  // protocol-bound but isn't.
  if (opts.tag !== undefined && opts.tag === "")
    throw new Error(
      'signRequest: "tag" must not be an empty string; an empty tag binds the signature to no application protocol',
    );
  // Over-long identifiers fail fast for the same reason as the empty
  // checks above: tag/nonce/keyid are short identifiers, and a value
  // past 256 characters is almost certainly a caller bug. Checked
  // here, before the base is built, so the input request is left
  // untouched. Sign side only — the verifier applies no per-field cap
  // (see MAX_TAG_LENGTH).
  if (opts.keyId !== undefined)
    assertSignParamLength("keyId", opts.keyId, MAX_KEY_ID_LENGTH);
  if (opts.nonce !== undefined)
    assertSignParamLength("nonce", opts.nonce, MAX_NONCE_LENGTH);
  if (opts.tag !== undefined)
    assertSignParamLength("tag", opts.tag, MAX_TAG_LENGTH);
  const covered =
    opts.coveredComponents ?? defaultCoveredComponents(req.body !== undefined);
  if (covered.length === 0)
    throw new Error(
      'signRequest: "coveredComponents" must cover at least one component; an empty list would sign nothing',
    );
  // The verify-side parser refuses a longer list with
  // MALFORMED_SIGNATURE_INPUT (see MAX_COVERED_COMPONENTS), so
  // minting one would produce a signature this library itself
  // cannot verify — refuse it here, in the same words, before the
  // base is built.
  if (covered.length > MAX_COVERED_COMPONENTS)
    throw new Error(
      `signRequest: too many covered components: ${covered.length} (max ${MAX_COVERED_COMPONENTS})`,
    );
  assertNoDuplicateCoveredComponents("signRequest", covered);
  const digestAlg = opts.contentDigestAlg ?? "sha-512";
  assertContentDigestAlg(digestAlg);
  assertStructuredFieldTypes(opts.structuredFieldTypes, "signRequest");
  // Fail fast on an alg/key mismatch before the signature base is
  // built or any crypto runs: without this, an RSA key paired with
  // `alg: "ed25519"` (or any other swapped pair) surfaces as a
  // cryptic node:crypto error that says nothing about which of the
  // two is wrong. The shape predicate is shared with the verify
  // side (`keys.algMatchesKeyShape`), so the two sides can never
  // disagree about which alg goes with which key.
  //
  // An unknown `alg` is rejected before the shape check, in its own
  // words: the predicate returns false for every unknown value, so
  // without this guard `alg: "none"` would be misreported as
  // "incompatible with the key" — and the `unsupported alg` branch at
  // the end of the crypto dispatch below could never be reached by an
  // unknown value. That branch stays as the exhaustiveness guard (see
  // below): it is unreachable today, and exists so a future algorithm
  // added to `SignAlg` without a dispatch branch fails loudly instead
  // of proceeding with an unassigned signature — and so TypeScript's
  // definite-assignment analysis holds.
  if (!isSupportedAlg(opts.alg))
    throw new Error(`signRequest: unsupported alg "${opts.alg}"`);
  if (!algMatchesKeyShape(opts.alg, opts.key))
    throw new Error(
      `signRequest: alg "${opts.alg}" is incompatible with the key (${describeKey(opts.key)}) — pass a key of the matching type for the algorithm`,
    );

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers[k] = Array.isArray(v) ? joinHeaderValues(v) : v;
  }
  if (covered.map((c) => c.toLowerCase()).includes("content-digest")) {
    if (req.body === undefined)
      throw new Error('content-digest is covered but the request has no body');
    headers["content-digest"] = contentDigest(req.body, digestAlg);
  }

  // `keyid` is an optional RFC 9421 parameter: only emit it when the caller
  // supplies one, so the wire shape is identical to what a keyid-less
  // signer would produce.
  const params: SignatureParams = { created, alg: opts.alg };
  if (opts.keyId !== undefined) params.keyid = opts.keyId;
  if (opts.expires !== undefined) params.expires = opts.expires;
  if (opts.nonce !== undefined) params.nonce = opts.nonce;
  if (opts.tag !== undefined) params.tag = opts.tag;

  const signingInput: RequestLike = {
    method: req.method,
    url: req.url,
    headers,
    body: req.body,
    status: req.status,
    request: req.request,
    trailers: req.trailers,
    // Carried through so a covered "@request-target" signs the
    // caller's explicit override, not the origin-form reconstruction:
    // dropping it here would mint a signature the verifier (seeing
    // the override) could never match.
    requestTarget: req.requestTarget,
  };
  const base = buildSignatureBase(covered, signingInput, params, {
    ...(opts.structuredFieldTypes !== undefined
      ? { structuredFieldTypes: opts.structuredFieldTypes }
      : {}),
  });

  let sig: Buffer;
  if (opts.alg === "ed25519") {
    sig = edSign(null, Buffer.from(base, "utf8"), opts.key);
  } else if (opts.alg === "ecdsa-p256-sha256") {
    // RFC 9421 §3.3.4: the signature value is the raw concatenation of
    // the ECDSA integers r and s, each padded to 32 octets (64 octets
    // total) — NOT the DER encoding node:crypto emits by default.
    // `dsaEncoding: "ieee-p1363"` selects exactly that raw form, and
    // verifyRequest consumes it with the same option. There is no DER
    // fallback on either side: DER signatures minted by earlier
    // versions of this library are rejected (see CHANGELOG).
    sig = createSign("sha256")
      .update(base, "utf8")
      .sign({ key: opts.key, dsaEncoding: "ieee-p1363" });
  } else if (opts.alg === "ecdsa-p384-sha384") {
    // RFC 9421 §3.3.5: the signature value is the raw concatenation of
    // the ECDSA integers r and s, each padded to 48 octets (96 octets
    // total) — NOT the DER encoding node:crypto emits by default.
    // `dsaEncoding: "ieee-p1363"` selects exactly that raw form, and
    // verifyRequest consumes it with the same option. The limb width is
    // the only difference from the P-256 branch above (32 octets), and
    // the two widths are pinned separately on both sides so a P-256
    // signature can never be re-read as P-384 or vice versa.
    sig = createSign("sha384")
      .update(base, "utf8")
      .sign({ key: opts.key, dsaEncoding: "ieee-p1363" });
  } else if (opts.alg === "ecdsa-p521-sha512") {
    // RFC 9421 §3.3.6: the signature value is the raw concatenation of
    // the ECDSA integers r and s, each padded to 66 octets (132 octets
    // total) — NOT the DER encoding node:crypto emits by default.
    // `dsaEncoding: "ieee-p1363"` selects exactly that raw form, and
    // verifyRequest consumes it with the same option. The limb width is
    // the only difference from the P-384 branch above (48 octets), and
    // the three EC widths are pinned separately on both sides so a
    // signature from one curve can never be re-read as another's.
    sig = createSign("sha512")
      .update(base, "utf8")
      .sign({ key: opts.key, dsaEncoding: "ieee-p1363" });
  } else if (opts.alg === "rsa-v1_5-sha256") {
    // RFC 9421 §3.3.2: RSASSA-PKCS1-v1_5 with SHA-256. v1.5 padding is
    // deterministic — the same base and key always produce the same
    // signature bytes (unlike PSS). The key-shape/modulus check runs
    // first so a non-RSA key or a sub-2048-bit modulus is a clear
    // configuration error rather than a node:crypto complaint.
    assertRsaModulusLength(opts.key, 'signRequest: alg "rsa-v1_5-sha256"');
    sig = createSign("sha256")
      .update(base, "utf8")
      .sign({ key: opts.key, padding: constants.RSA_PKCS1_PADDING });
  } else if (opts.alg === "rsa-pss-sha512") {
    // RFC 9421 §3.3.1: RSASSA-PSS-SIGN with SHA-512, MGF1 with SHA-512,
    // and a fixed 64-byte salt. PSS is probabilistic — the same base
    // signs to a different byte string every time, so verifiers must
    // re-verify, never re-sign-and-compare.
    sig = createSign("sha512")
      .update(base, "utf8")
      .sign({
        key: opts.key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64,
      });
  } else if (opts.alg === "hmac-sha256") {
    // Fail fast on weak secrets: a short key must never silently mint
    // signatures the verifier would also (correctly) refuse to check.
    assertHmacSecretLength(opts.key);
    sig = createHmac("sha256", opts.key).update(base, "utf8").digest();
  } else if (opts.alg === "hmac-sha512") {
    // SHA-512 twin of the hmac-sha256 branch above. The floor is paired
    // with the algorithm (RFC 2104 §3: the key SHOULD be at least as long
    // as the hash output; sha-512 → 64 bytes), so a secret that is only
    // adequate for hmac-sha256 is rejected here on both sides.
    assertHmacSecretLength(opts.key, "hmac-sha512");
    sig = createHmac("sha512", opts.key).update(base, "utf8").digest();
  } else {
    // Exhaustiveness guard, unreachable today: the `isSupportedAlg`
    // check above rejects every unknown value before the base is built,
    // and the branches above cover all eight `SignAlg` members. Kept
    // (rather than deleted) so a future algorithm added to the union
    // without a branch here fails loudly instead of proceeding with an
    // unassigned signature — and so TypeScript accepts `sig` as
    // definitely assigned.
    throw new Error(`unsupported alg "${opts.alg}"`);
  }

  headers["signature-input"] = signatureInputValue(label, covered, params);
  headers["signature"] = `${label}=:${sig.toString("base64")}:`;

  return {
    method: req.method,
    url: req.url,
    headers,
    body: req.body,
    ...(req.status !== undefined ? { status: req.status } : {}),
    ...(req.request !== undefined ? { request: req.request } : {}),
    ...(req.trailers !== undefined ? { trailers: req.trailers } : {}),
    ...(req.requestTarget !== undefined
      ? { requestTarget: req.requestTarget }
      : {}),
    // Detached copy of the list actually written to signature-input:
    // the caller must not be able to rewrite the signer's record of
    // what was covered by mutating the returned array, and the
    // returned array must not alias the caller's options array.
    coveredComponents: [...covered],
  };
}

/**
 * Append a second party's signature to an already-signed request,
 * producing a genuine multi-label RFC 9421 §2.4 dictionary — the
 * sign-side twin of `verifyAllLabels`. The canonical use case is
 * multi-party payment flows: a merchant signs with its own key (e.g.
 * ed25519), then a payment gateway appends its own signature (e.g. hmac)
 * without touching the merchant's entries.
 *
 * The second signature base is built over the original message content
 * (the existing `signature-input` / `signature` headers are stripped
 * before signing), so both parties sign the same request components.
 * Parameters, covered components, key id, and nonce are taken from
 * `opts` exactly as `signRequest` would apply them; `opts.label` names
 * the appended entry (defaults to `"sig1"` like `signRequest`).
 *
 * One Content-Digest header constraint: a request carries a single
 * `content-digest` header, and every label's signature base covers the
 * wire value. If the existing request already has one, the second
 * signature is built with the same digest algorithm — the algorithm of
 * the existing header wins over `opts.contentDigestAlg` (an explicitly
 * contradictory choice is a configuration error), and an existing header
 * whose digest algorithm this library cannot emit is a configuration
 * error too. Without this, the appended signature's base would cover a
 * value that is never on the wire and `verifyAllLabels` would reject it.
 *
 * Fail-fast configuration errors (thrown, never embedded):
 * - the input has no `signature-input`/`signature` headers (nothing to
 *   append to — call `signRequest` first);
 * - the existing `signature-input` header is malformed;
 * - `opts.label` is empty or already present in the request (RFC 9421
 *   dictionary labels must be unique).
 *
 * The input request is not mutated; a new `SignedHttpRequest` is
 * returned.
 */
export function addSignature(
  signedReq: SignedHttpRequest,
  opts: SignOptions,
): SignedHttpRequest {
  const label = opts.label ?? "sig1";
  if (label.length === 0)
    throw new Error('addSignature: "label" must be a non-empty string');

  let existingInput: string | undefined;
  let existingSig: string | undefined;
  for (const [k, v] of Object.entries(signedReq.headers)) {
    const lower = k.toLowerCase();
    if (lower === "signature-input") existingInput = v;
    else if (lower === "signature") existingSig = v;
  }
  if (existingInput === undefined || existingSig === undefined)
    throw new Error(
      "addSignature: the request has no signature-input/signature headers; sign it with signRequest first",
    );

  let labels: string[];
  try {
    labels = listSignatureLabels(existingInput);
  } catch (e) {
    throw new Error(
      `addSignature: existing signature-input header is malformed (${(e as Error).message})`,
    );
  }
  if (labels.includes(label))
    throw new Error(
      `addSignature: label "${label}" is already present; every signature must use a distinct label`,
    );

  // Strip the signature dictionaries so the second base is computed over
  // the original message content, exactly as the first signature was.
  // Covered components are honored from the stripped set, so a caller
  // explicitly covering "signature-input"/"signature" signs the original
  // request minus its own (not yet appended) entry — dictionaries are
  // never re-signed after the fact.
  const unsignedHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(signedReq.headers)) {
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
        `addSignature: the request carries a content-digest header with a digest algorithm this library cannot emit (${JSON.stringify(existingDigest.slice(0, existingDigest.indexOf("="))) || JSON.stringify(existingDigest)}); the second signature cannot cover it`,
      );
    if (digestAlg !== undefined && digestAlg !== wireAlg)
      throw new Error(
        `addSignature: the request already carries a content-digest header emitted with "${wireAlg}"; contentDigestAlg "${digestAlg}" would build the second signature base over a different value than the wire one`,
      );
    digestAlg = wireAlg;
  }
  const fresh = signRequest(
    {
      method: signedReq.method,
      url: signedReq.url,
      headers: unsignedHeaders,
      body: signedReq.body,
      ...(signedReq.status !== undefined
        ? { status: signedReq.status }
        : {}),
      ...(signedReq.request !== undefined
        ? { request: signedReq.request }
        : {}),
      ...(signedReq.trailers !== undefined
        ? { trailers: signedReq.trailers }
        : {}),
      ...(signedReq.requestTarget !== undefined
        ? { requestTarget: signedReq.requestTarget }
        : {}),
    },
    { ...opts, ...(digestAlg !== undefined ? { contentDigestAlg: digestAlg } : {}) },
  );

  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(signedReq.headers)) {
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
    method: signedReq.method,
    url: signedReq.url,
    headers: out,
    body: signedReq.body,
    ...(signedReq.status !== undefined ? { status: signedReq.status } : {}),
    ...(signedReq.request !== undefined ? { request: signedReq.request } : {}),
    ...(signedReq.trailers !== undefined ? { trailers: signedReq.trailers } : {}),
    ...(signedReq.requestTarget !== undefined
      ? { requestTarget: signedReq.requestTarget }
      : {}),
    // The appended signature's own covered list (from `fresh`), not a
    // merge with the first signature's: each label's audit record
    // stays attributable to the party that minted it.
    ...(fresh.coveredComponents !== undefined
      ? { coveredComponents: [...fresh.coveredComponents] }
      : {}),
  };
}
