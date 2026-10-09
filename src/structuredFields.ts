/**
 * Minimal RFC 8941 (HTTP Structured Fields) parser and strict
 * serializer, used only for the RFC 9421 §2.1.1 `;sf` component
 * parameter: a covered header field's value is parsed as a Structured
 * Field and re-serialized with the formal serialization rules of
 * RFC 8941 §4, so insignificant whitespace and formatting differences
 * in the wire value canonicalize to identical signature-base bytes on
 * the signer and the verifier.
 *
 * Scope (honest): this implements the RFC 8941 core data types —
 * Integer, Decimal, String, Token, Byte Sequence, Boolean, plus
 * Parameters, Inner Lists, Lists, and Dictionaries. The RFC 9651
 * extensions (Date `@…`, Display String `%…`) are NOT supported and
 * fail closed, as does any value that parses as none of the types.
 *
 * Type selection: RFC 9421 requires the application to know the
 * field's Structured Field type, but the `;sf` flag itself does not
 * carry it, and this library keeps no per-field type registry (see
 * the README's `;sf` notes). `canonicalizeStructuredFieldValue`
 * therefore tries Dictionary, then List, then Item, accepting the
 * first type that consumes the entire value. For values whose type
 * is unambiguous — the Dictionary/List/Item shapes gateways actually
 * sign — every candidate type that parses at all serializes to the
 * same strict bytes (a lone Token, Integer, or String parses
 * identically as a one-member List and as an Item; a bare Dictionary
 * key and a List Token coincide), so the precedence cannot change
 * the result for well-typed values. A value that is not a valid
 * Structured Field of any type is a hard error on both sides.
 */

type SfBareItem =
  | { kind: "int"; text: string }
  | { kind: "dec"; neg: boolean; intPart: string; fracPart: string }
  | { kind: "string"; value: string }
  | { kind: "token"; value: string }
  | { kind: "bytes"; base64: string }
  | { kind: "bool"; value: boolean };

/** A parameter value, or `null` for a bare `;name` flag (Boolean true). */
type SfParamValue = SfBareItem | null;
type SfParams = Array<[string, SfParamValue]>;

interface SfItem {
  type: "item";
  bare: SfBareItem;
  params: SfParams;
}

interface SfInnerList {
  type: "inner-list";
  items: SfItem[];
  params: SfParams;
}

type SfListMember = SfItem | SfInnerList;

interface SfDictEntry {
  key: string;
  member: SfListMember;
}

const KEY_START = /[a-z*]/;
const KEY_CHAR = /[a-z0-9_\-.*]/;
const TOKEN_START = /[A-Za-z*]/;
const TOKEN_CHAR = /[A-Za-z0-9!#$%&'*+\-.^_`|~/:]/;

class SfParser {
  private pos = 0;

  constructor(private readonly input: string) {}

  get atEnd(): boolean {
    return this.pos >= this.input.length;
  }

  private peek(): string | undefined {
    return this.input[this.pos];
  }

  private fail(detail: string): Error {
    return new Error(`${detail} (at offset ${this.pos})`);
  }

  skipOws(): void {
    while (!this.atEnd && (this.input[this.pos] === " " || this.input[this.pos] === "\t")) {
      this.pos++;
    }
  }

  /** Parse a Dictionary/List key or a parameter name (RFC 8941 §3.1.2 / §3.1.3). */
  parseKey(): string {
    const start = this.pos;
    const first = this.peek();
    if (first === undefined || !KEY_START.test(first)) {
      throw this.fail("expected a key (lowercase letter or \"*\")");
    }
    this.pos++;
    while (!this.atEnd && KEY_CHAR.test(this.input[this.pos])) this.pos++;
    return this.input.slice(start, this.pos);
  }

  private parseIntegerOrDecimal(): SfBareItem {
    let neg = false;
    if (this.peek() === "-") {
      neg = true;
      this.pos++;
    }
    const intStart = this.pos;
    while (!this.atEnd && /[0-9]/.test(this.input[this.pos])) this.pos++;
    const intDigits = this.input.slice(intStart, this.pos);
    if (intDigits.length === 0) throw this.fail("expected digits in a number");
    if (this.peek() === ".") {
      if (intDigits.length > 12) {
        throw this.fail("decimal integer part exceeds 12 digits");
      }
      this.pos++;
      const fracStart = this.pos;
      while (!this.atEnd && /[0-9]/.test(this.input[this.pos])) this.pos++;
      const fracDigits = this.input.slice(fracStart, this.pos);
      if (fracDigits.length < 1 || fracDigits.length > 3) {
        throw this.fail("decimal fractional part must have 1 to 3 digits");
      }
      return { kind: "dec", neg, intPart: intDigits, fracPart: fracDigits };
    }
    if (intDigits.length > 15) {
      throw this.fail("integer exceeds 15 digits");
    }
    const value = Number(intDigits);
    return { kind: "int", text: String(neg ? -value : value) };
  }

  private parseString(): SfBareItem {
    this.pos++; // opening DQUOTE
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined) throw this.fail("unterminated string");
      if (c === '"') {
        this.pos++;
        return { kind: "string", value: out };
      }
      if (c === "\\") {
        const next = this.input[this.pos + 1];
        if (next !== '"' && next !== "\\") {
          throw this.fail('invalid escape in string (only \\" and \\\\ are allowed)');
        }
        out += next;
        this.pos += 2;
        continue;
      }
      const code = c.charCodeAt(0);
      if (code < 0x20 || code === 0x7f) {
        throw this.fail("control character in string");
      }
      out += c;
      this.pos++;
    }
  }

  private parseToken(): SfBareItem {
    const start = this.pos;
    const first = this.peek();
    if (first === undefined || !TOKEN_START.test(first)) {
      throw this.fail("expected a token");
    }
    this.pos++;
    while (!this.atEnd && TOKEN_CHAR.test(this.input[this.pos])) this.pos++;
    return { kind: "token", value: this.input.slice(start, this.pos) };
  }

  private parseByteSequence(): SfBareItem {
    this.pos++; // opening ":"
    const start = this.pos;
    while (!this.atEnd && this.input[this.pos] !== ":") this.pos++;
    if (this.atEnd) throw this.fail("unterminated byte sequence");
    const raw = this.input.slice(start, this.pos);
    this.pos++; // closing ":"
    if (raw.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(raw)) {
      throw this.fail("invalid base64 in byte sequence");
    }
    // Re-encode so the strict output is the canonical base64 of the bytes.
    return { kind: "bytes", base64: Buffer.from(raw, "base64").toString("base64") };
  }

  private parseBoolean(): SfBareItem {
    const c = this.input[this.pos + 1];
    if (c !== "0" && c !== "1") throw this.fail('boolean must be "?0" or "?1"');
    this.pos += 2;
    return { kind: "bool", value: c === "1" };
  }

  parseBareItem(): SfBareItem {
    const c = this.peek();
    if (c === undefined) throw this.fail("expected a value");
    if (c === "-" || /[0-9]/.test(c)) return this.parseIntegerOrDecimal();
    if (c === '"') return this.parseString();
    if (c === "?") return this.parseBoolean();
    if (c === ":") return this.parseByteSequence();
    if (c === "@" || c === "%") {
      throw this.fail(
        `unsupported Structured Field type starting with "${c}" (RFC 9651 Date/Display String are not supported)`,
      );
    }
    if (TOKEN_START.test(c)) return this.parseToken();
    throw this.fail(`unexpected character "${c}"`);
  }

  parseParams(): SfParams {
    const params: SfParams = [];
    while (this.peek() === ";") {
      this.pos++;
      // RFC 8941 parsing discards optional whitespace after ";".
      while (this.peek() === " ") this.pos++;
      const name = this.parseKey();
      let value: SfParamValue = null;
      if (this.peek() === "=") {
        this.pos++;
        value = this.parseBareItem();
      }
      params.push([name, value]);
    }
    return params;
  }

  parseItem(): SfItem {
    const bare = this.parseBareItem();
    const params = this.parseParams();
    return { type: "item", bare, params };
  }

  parseInnerList(): SfInnerList {
    this.pos++; // "("
    const items: SfItem[] = [];
    for (;;) {
      this.skipOws();
      if (this.peek() === ")") {
        this.pos++;
        break;
      }
      if (this.atEnd) throw this.fail("unterminated inner list");
      items.push(this.parseItem());
      const next = this.peek();
      if (next !== " " && next !== "\t" && next !== ")") {
        throw this.fail("inner-list items must be separated by whitespace");
      }
    }
    return { type: "inner-list", items, params: this.parseParams() };
  }

  private parseListMember(): SfListMember {
    return this.peek() === "(" ? this.parseInnerList() : this.parseItem();
  }

  /** Parse a full List; the caller checks that the input is fully consumed. */
  parseList(): SfListMember[] {
    const members: SfListMember[] = [this.parseListMember()];
    for (;;) {
      this.skipOws();
      if (this.atEnd) return members;
      if (this.peek() !== ",") throw this.fail('expected "," between list members');
      this.pos++;
      this.skipOws();
      if (this.atEnd) throw this.fail("trailing comma in list");
      members.push(this.parseListMember());
    }
  }

  /** Parse a full Dictionary; the caller checks full consumption. */
  parseDictionary(): SfDictEntry[] {
    const entries: SfDictEntry[] = [];
    for (;;) {
      const key = this.parseKey();
      let member: SfListMember;
      if (this.peek() === "=") {
        this.pos++;
        member = this.parseListMember();
      } else {
        // Bare key: the member is Boolean true carrying any parameters.
        member = { type: "item", bare: { kind: "bool", value: true }, params: this.parseParams() };
      }
      entries.push({ key, member });
      this.skipOws();
      if (this.atEnd) return entries;
      if (this.peek() !== ",") throw this.fail('expected "," between dictionary members');
      this.pos++;
      this.skipOws();
      if (this.atEnd) throw this.fail("trailing comma in dictionary");
    }
  }
}

// ---------------------------------------------------------------------------
// Strict serialization (RFC 8941 §4)
// ---------------------------------------------------------------------------

function serializeBareItem(bare: SfBareItem): string {
  switch (bare.kind) {
    case "int":
      return bare.text;
    case "dec":
      return `${bare.neg ? "-" : ""}${Number(bare.intPart)}.${bare.fracPart.padEnd(3, "0")}`;
    case "string":
      return `"${bare.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
    case "token":
      return bare.value;
    case "bytes":
      return `:${bare.base64}:`;
    case "bool":
      return bare.value ? "?1" : "?0";
  }
}

function serializeParams(params: SfParams): string {
  return params
    .map(([name, value]) => `;${name}${value === null ? "" : `=${serializeBareItem(value)}`}`)
    .join("");
}

function serializeMember(member: SfListMember): string {
  if (member.type === "inner-list") {
    const inner = member.items.map(serializeMember).join(" ");
    return `(${inner})${serializeParams(member.params)}`;
  }
  return `${serializeBareItem(member.bare)}${serializeParams(member.params)}`;
}

function serializeDictionary(entries: SfDictEntry[]): string {
  return entries
    .map(({ key, member }) => {
      // A bare key (Boolean-true member) serializes as just the key,
      // plus its parameters when it carries any (RFC 8941 §4.1.2).
      if (member.type === "item" && member.bare.kind === "bool" && member.bare.value) {
        return `${key}${serializeParams(member.params)}`;
      }
      return `${key}=${serializeMember(member)}`;
    })
    .join(", ");
}

/**
 * Parse `value` as an HTTP Structured Field and return its strict
 * (canonical) serialization per RFC 8941 §4 — the component value a
 * `;sf` covered component contributes to the signature base.
 *
 * Throws a descriptive `Error` when the value is empty or is not a
 * valid Structured Field of any supported type; see the module header
 * for the Dictionary → List → Item selection rule and its limits.
 */
export function canonicalizeStructuredFieldValue(value: string): string {
  const input = value.replace(/^[ \t]+|[ \t]+$/g, "");
  if (input.length === 0) {
    throw new Error("empty value is not a valid Structured Field");
  }
  const attempts: Array<() => string> = [
    () => {
      const p = new SfParser(input);
      const dict = p.parseDictionary();
      p.skipOws();
      if (!p.atEnd) throw new Error("trailing characters after dictionary");
      return serializeDictionary(dict);
    },
    () => {
      const p = new SfParser(input);
      const list = p.parseList();
      p.skipOws();
      if (!p.atEnd) throw new Error("trailing characters after list");
      return list.map(serializeMember).join(", ");
    },
    () => {
      const p = new SfParser(input);
      const item = p.parseItem();
      p.skipOws();
      if (!p.atEnd) throw new Error("trailing characters after item");
      return serializeMember(item);
    },
  ];
  let firstError: Error | undefined;
  for (const attempt of attempts) {
    try {
      return attempt();
    } catch (err) {
      firstError ??= err instanceof Error ? err : new Error(String(err));
    }
  }
  throw new Error(
    `not a valid Structured Field value: ${firstError?.message ?? "parse failed"}`,
  );
}
