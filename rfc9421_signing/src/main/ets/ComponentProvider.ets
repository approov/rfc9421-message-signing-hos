import { StringItem, BooleanItem, parseDictionary, parseList, parseItem, ByteSequenceItem, HttpHeaderUtils, SfvList } from '@approov/rfc8941_sfv';
import type { Dictionary, SfvParameters, ItemType, ListElement } from '@approov/rfc8941_sfv';
import {
  UnknownComponentError,
  MalformedComponentIdentifierError,
  UnsupportedComponentParameterError,
  ComponentValueError,
} from './errors';

/**
 * Provides component values for building HTTP message signature bases (RFC 9421 Section 2).
 *
 * Implementors supply derived-component accessors (method, path, etc.) and HTTP field accessors.
 * The default getComponentValue() dispatches to these based on the component identifier string.
 */
export abstract class ComponentProvider {
  // Derived Component Identifiers
  // HTTP OWS (RFC 9110 §5.6.3) is strictly SP/HTAB — deliberately narrower than JS's
  // Unicode-aware \s, which would silently strip characters (e.g. NBSP, U+2028) that HTTP
  // does not consider whitespace and that a compliant implementation must not trim away.
  private static readonly PATTERN_OWS: RegExp = /^[ \t]+|[ \t]+$/g;
  private static readonly PATTERN_WHITESPACE: RegExp = /[ \t]*\r\n[ \t]*/g;
  // RFC 9421 §2.5: derived-component-value = *( VCHAR / SP ) — visible ASCII plus space only.
  private static readonly PATTERN_DERIVED_VALUE_CHARS: RegExp = /^[\x20-\x7E]*$/;
  // RFC 9421 §2.5: a field-based signature-base-line reuses HTTP's field-content ABNF, but
  // explicitly excludes obs-fold and obs-text ("; no obs-fold nor obs-text"). With obs-text
  // (the %x80-FF octets HTTP's field-content otherwise allows) excluded, field-vchar reduces
  // to plain VCHAR, so the allowed body is HTAB/SP/VCHAR, and — per field-content's own
  // `field-vchar [ 1*( SP / HTAB / field-vchar ) field-vchar ]` shape — a non-empty value
  // must both start and end with a VCHAR (no leading/trailing SP/HTAB either).
  private static readonly PATTERN_FIELD_VALUE_CHARS: RegExp = /^[\t\x20-\x7E]*$/;
  private static readonly PATTERN_FIELD_VALUE_EDGE: RegExp = /^[\t\x20]|[\t\x20]$/;
  /** Component identifier parameters valid on any HTTP field (RFC 9421 §2.1/§2.1.1-4). */
  private static readonly FIELD_PARAMS: Set<string> = new Set<string>(['sf', 'key', 'bs', 'tr', 'req']);

  // Derived component identifiers
  /** The authority of the target URI for a request (Section 2.2.3). */
  static readonly DC_AUTHORITY = '@authority';

  /** The method used for a request (Section 2.2.1). */
  static readonly DC_METHOD = '@method';

  /** The absolute path portion of the target URI for a request (Section 2.2.6). */
  static readonly DC_PATH = '@path';

  /** The query portion of the target URI for a request (Section 2.2.7). */
  static readonly DC_QUERY = '@query';

  /** A parsed and encoded query parameter of the target URI for a request (Section 2.2.8). */
  static readonly DC_QUERY_PARAM = '@query-param';

  /** The request target (Section 2.2.5). */
  static readonly DC_REQUEST_TARGET = '@request-target';

  /** The scheme of the target URI for a request (Section 2.2.4). */
  static readonly DC_SCHEME = '@scheme';

  /** The status code for a response (Section 2.2.9). */
  static readonly DC_STATUS = '@status';

  /** The full target URI for a request (Section 2.2.2). */
  static readonly DC_TARGET_URI = '@target-uri';




  abstract getMethod(): string | null;
  abstract getAuthority(): string | null;
  abstract getScheme(): string | null;
  abstract getTargetUri(): string | null;
  abstract getRequestTarget(): string | null;
  abstract getPath(): string | null;
  abstract getQuery(): string | null;
  /**
   * Returns the *decoded* value of the named query parameter (RFC 9421 §2.2.8 step 1 — the
   * value after percent-decoded octets and "+"-as-space substitution are undone).
   *
   * This class — not the implementor — performs the re-encoding (§2.2.8 step 2) before the
   * value reaches the signature base (see getDerivedComponentValue()). Decoded-in,
   * encoded-out by the library is deliberate: correctly implementing "application/
   * x-www-form-urlencoded serializing" is a shared, easy-to-get-subtly-wrong piece of logic
   * (see the encoding note on getDerivedComponentValue()'s @query-param handling), and there
   * is no way for this class to verify that an implementor-supplied *already-encoded* value
   * actually followed that algorithm — centralizing it here removes that trust requirement
   * entirely, at the cost of every implementor needing to hand back the decoded form instead.
   *
   * Implementors MUST:
   *  - return the value decoded (not percent-encoded, and with literal "+" already read as
   *    part of the parameter's actual content, not as a space — that conversion is a
   *    property of the *encoded* wire form the caller already decoded away);
   *  - throw if the parameter name occurs more than once in the query string, since
   *    the component value would then be ambiguous and MUST NOT be signed;
   *  - throw (or return null, per the caller's null-handling) if the parameter is absent.
   *
   * @param name The decoded query parameter name.
   */
  abstract getQueryParam(name: string): string | null;
  abstract getStatus(): string | null;
  abstract hasBody(): boolean;

  // fields

  /**
   * Returns true if the HTTP message contains at least one header (or trailer)
   * with the given field name. Used by callers to decide whether an "optional"
   * field should be added to the signature parameters for the current request.
   *
   * @param name Lower-cased HTTP field name (e.g. "content-type").
   */
  abstract hasField(name: string): boolean;

  /**
   * Returns the canonicalized value of an HTTP field as required by RFC 9421 §2.1:
   * concatenate all values of same-named headers with ", ", strip leading/trailing
   * OWS, and fold obs-fold whitespace. Returns null if the field is absent.
   * This is the default value used in the signature base when no special parameter
   * (;key/;sf/;bs/...) applies.
   *
   * @param name Lower-cased HTTP field name (e.g. "content-digest").
   */
  abstract getField(name: string): string | null;

  /**
   * Returns the raw value of every field-line instance of the named field, in the order
   * they occur in the message, or null if the field is absent.
   *
   * Used only for the `;bs` (Byte Sequence) encoding (RFC 9421 §2.1.3), which MUST encode
   * each field-line instance as its own Byte Sequence *before* combining them — unlike the
   * default combination algorithm (see getField()), pre-combining instances into one string
   * would lose the very distinction `;bs` exists to preserve (e.g. a field sent as two
   * instances "value, with, lots" / "of, commas" must not become indistinguishable from a
   * single instance "value, with, lots, of, commas").
   *
   * Known limitation: this returns `string[]`, so a field value that is not valid UTF-8 in
   * the first place (RFC 9421 §2.1.3 allows "other octets" beyond ASCII in some
   * implementations) cannot be carried losslessly through this API — encodeUtf8() in
   * getByteSequenceValue() will not reproduce arbitrary raw octets. This is acceptable for
   * ASCII/UTF-8 field values (the overwhelming common case) but is not a fully general
   * implementation of §2.1.3 for opaque binary field content.
   *
   * @param name Lower-cased HTTP field name.
   */
  abstract getFieldValues(name: string): string[] | null;

  /**
   * Returns which kind of RFC 8941/9651 Structured Field the named HTTP field is — `null`
   * if it is not a Structured Field, or its type is not known to this provider. Used only
   * for the `;sf` (Structured Field serialization) and `;key` (Dictionary member lookup —
   * always 'dictionary') parameters (RFC 9421 §2.1.1/§2.1.2).
   *
   * Deliberately NOT inferred from the field name by this library: whether a field is a
   * Structured Field, and which of List/Dictionary/Item it is, is knowledge specific to the
   * field and the application (RFC 9421 §2.1.1: "If the application does not know the type
   * of the field ... the use of this flag will produce an error"). It is tracked in an
   * external, evolving IANA registry, not enumerable in this document or hardcodable here
   * without risking staleness or outright wrong entries (e.g. Content-Type and Host are
   * NOT Structured Fields, despite the name pattern of some registered examples suggesting
   * otherwise).
   *
   * @param name Lower-cased HTTP field name.
   */
  abstract getFieldStructuredType(name: string): 'list' | 'dictionary' | 'item' | null;

  getComponentValue(componentIdentifier: StringItem): string | null{
    const baseIdentifier: string = componentIdentifier.get();

    if (baseIdentifier.startsWith('@')) {
      return this.getDerivedComponentValue(baseIdentifier, componentIdentifier);
    } else {
      return this.getFieldComponentValue(baseIdentifier, componentIdentifier);
    }
  }

  private getDerivedComponentValue(name: string, componentIdentifier: StringItem): string | null{
    const params: SfvParameters = componentIdentifier.getParams();
    const contextLabel = `Derived component ${name}`;
    // RFC 8941 §3.1.2: a parameter with no "=value" defaults to Boolean ?1. ;req=?0 is
    // therefore a well-formed way of saying "not requested" — distinct from ;req being
    // absent only in that it consumes the parameter slot, not in effect. A non-Boolean
    // value (e.g. ;req=1) doesn't have the type this parameter requires and is rejected.
    const hasReq: boolean = ComponentProvider.readBooleanParam(params, 'req', contextLabel);

    if (name === ComponentProvider.DC_QUERY_PARAM) {
      // RFC 9421 §2.2.8: the only parameters @query-param accepts are the required ;name
      // and ;req (handled above via hasReq); anything else is unknown/inapplicable.
      const queryParamKeys: string[] = Array.from(params.keySet());
      for (const key of queryParamKeys) {
        if (key !== 'name' && key !== 'req') {
          throw new MalformedComponentIdentifierError(
            `Unknown or inapplicable parameter ';${key}' for ${name}`);
        }
      }
      // RFC 9421 §2.4: ;req can be applied to derived components that target the request;
      // this provider has no access to the request that triggered a signed response, so —
      // as with field components — fail loudly rather than silently using the wrong message.
      if (hasReq) {
        throw new UnsupportedComponentParameterError(
          `${contextLabel}: ';req' (request-response binding) parameter is not supported`);
      }
      if (!params.containsKey('name')) {
        throw new MalformedComponentIdentifierError(`'name' parameter of ${name} is required`);
      }
      const nameParam: ItemType | undefined = params.get('name');
      if (!(nameParam instanceof StringItem)) {
        throw new MalformedComponentIdentifierError(
          `Invalid Syntax: Value for 'name' parameter of ${name} must be a StringItem`);
      }
      // RFC 9421 §2.2.8: the "name" parameter is percent-encoded per the "application/
      // x-www-form-urlencoded" algorithm ([HTMLURL] §5.1), which decodes a literal "+" as
      // a space before percent-decoding the rest — unlike plain decodeURIComponent(), which
      // leaves "+" untouched. Both steps are required to get the same decoded name a
      // form-urlencoded query-string parser would produce.
      const decodedName = decodeURIComponent(nameParam.get().replace(/\+/g, ' '));
      const decodedValue = this.getQueryParam(decodedName);
      if (decodedValue === null || decodedValue === undefined) {
        return null;
      }
      // §2.2.8 step 2: re-encode the decoded value for the component value.
      return ComponentProvider.validateDerivedComponentValue(name, ComponentProvider.formUrlEncode(decodedValue));
    }

    // Every other derived component name defined by this library takes no parameters
    // besides ;req (handled via hasReq) — RFC 9421 §2.5: "If the component identifier has
    // a parameter that is not understood, produce an error."
    const remainingKeys: string[] = Array.from(params.keySet());
    for (const key of remainingKeys) {
      if (key !== 'req') {
        throw new MalformedComponentIdentifierError(
          `Unknown or inapplicable parameter ';${key}' for ${name}`);
      }
    }
    if (hasReq) {
      throw new UnsupportedComponentParameterError(
        `${contextLabel}: ';req' (request-response binding) parameter is not supported`);
    }

    let value: string | null;
    switch (name) {
      case ComponentProvider.DC_METHOD:
        value = this.getMethod();
        break;
      case ComponentProvider.DC_AUTHORITY:
        value = this.getAuthority();
        break;
      case ComponentProvider.DC_SCHEME:
        value = this.getScheme();
        break;
      case ComponentProvider.DC_TARGET_URI:
        value = this.getTargetUri();
        break;
      case ComponentProvider.DC_REQUEST_TARGET:
        value = this.getRequestTarget();
        break;
      case ComponentProvider.DC_PATH:
        value = this.getPath();
        break;
      case ComponentProvider.DC_QUERY:
        value = this.getQuery();
        break;
      case ComponentProvider.DC_STATUS:
        value = this.getStatus();
        break;
      default:
        throw new UnknownComponentError(`Unknown derived component: ${name}`);
    }
    return ComponentProvider.validateDerivedComponentValue(name, value);
  }

  /**
   * RFC 9421 §2.2: "Derived component values MUST be limited to printable characters and
   * spaces and MUST NOT contain any newline characters. Derived component values MUST NOT
   * start or end with whitespace characters." Applied to every derived component value
   * (including @query-param's, which previously returned early and skipped this check).
   */
  private static validateDerivedComponentValue(name: string, value: string | null): string | null {
    if (value === null || value === undefined || value.length === 0) {
      return value;
    }
    const isPrintableAscii = ComponentProvider.PATTERN_DERIVED_VALUE_CHARS.test(value);
    const hasEdgeWhitespace = value.charAt(0) === ' ' || value.charAt(value.length - 1) === ' ';
    if (!isPrintableAscii || hasEdgeWhitespace) {
      throw new ComponentValueError(
        `Derived component ${name}: value must be printable ASCII/space, with no leading or ` +
        `trailing whitespace (RFC 9421 §2.2)`);
    }
    return value;
  }

  /**
   * Percent-encodes `value` per RFC 9421 §2.2.8 step 2: the "percent-encode after encoding"
   * process (WHATWG URL §5.2, "application/x-www-form-urlencoded serializing"), applied
   * with the "application/x-www-form-urlencoded percent-encode set" and *without* the
   * space-as-"+" substitution that the full form-urlencoded serializer normally applies
   * (confirmed against RFC 9421's own worked examples, which show a decoded space
   * re-encoded as "%20", not "+").
   *
   * The percent-encode set's complement — the bytes left unescaped — is exactly
   * `[A-Za-z0-9*\-._]` (per the WHATWG URL spec's component/userinfo/path/query
   * percent-encode set definitions, working back from what they each add on top of the
   * previous). This is *not* the same as JS's `encodeURIComponent()`, which additionally
   * leaves `!'()*` unescaped — using it here would produce different bytes than another
   * RFC 9421 implementation for query parameter values containing those characters,
   * breaking interoperability.
   */
  private static formUrlEncode(value: string): string {
    const bytes: Uint8Array = HttpHeaderUtils.encodeUtf8(value);
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      const byte = bytes[i];
      if (ComponentProvider.isFormUrlEncodedSafeByte(byte)) {
        result += String.fromCharCode(byte);
      } else {
        const hex = byte.toString(16).toUpperCase();
        result += hex.length === 1 ? `%0${hex}` : `%${hex}`;
      }
    }
    return result;
  }

  /** The complement of the "application/x-www-form-urlencoded percent-encode set": `[A-Za-z0-9*\-._]`. */
  private static isFormUrlEncodedSafeByte(byte: number): boolean {
    return (byte >= 0x30 && byte <= 0x39) // 0-9
      || (byte >= 0x41 && byte <= 0x5A) // A-Z
      || (byte >= 0x61 && byte <= 0x7A) // a-z
      || byte === 0x2A // *
      || byte === 0x2D // -
      || byte === 0x2E // .
      || byte === 0x5F; // _
  }

  /**
   * Reads a Boolean-flag parameter (RFC 8941 §3.1.2: a parameter with no "=value" defaults
   * to ?1). Returns false if the parameter is absent *or* explicitly ?0 — both mean "not
   * requested". Throws if the parameter is present with a non-Boolean value (e.g. ;sf="yes"
   * or ;bs=1), since RFC 9421 §2.5 treats a parameter whose value doesn't have the expected
   * type as "not understood".
   */
  private static readBooleanParam(params: SfvParameters, key: string, contextLabel: string): boolean {
    if (!params.containsKey(key)) {
      return false;
    }
    const paramValue: ItemType | undefined = params.get(key);
    if (!(paramValue instanceof BooleanItem)) {
      throw new MalformedComponentIdentifierError(`${contextLabel}: ';${key}' parameter must be a Boolean`);
    }
    return paramValue.get();
  }

  private getFieldComponentValue(fieldName: string, id: StringItem): string | null {
    const params: SfvParameters = id.getParams();
    const contextLabel = `Field ${fieldName}`;
    // sf/bs/tr/req are all Boolean flags (RFC 8941 §3.1.2: no "=value" defaults to ?1).
    // readBooleanParam treats an explicit ;xx=?0 the same as the parameter being absent,
    // and rejects a non-Boolean value (e.g. ;sf="yes", ;bs=1) instead of silently treating
    // mere key-presence as "enabled".
    const hasSf: boolean = ComponentProvider.readBooleanParam(params, 'sf', contextLabel);
    const hasBs: boolean = ComponentProvider.readBooleanParam(params, 'bs', contextLabel);
    const hasTr: boolean = ComponentProvider.readBooleanParam(params, 'tr', contextLabel);
    const hasReq: boolean = ComponentProvider.readBooleanParam(params, 'req', contextLabel);
    const hasKey: boolean = params.containsKey('key');

    // RFC 9421 §2.5: "If the component identifier has a parameter that is not understood,
    // produce an error." sf/key/bs/tr/req are the only parameters this library recognizes
    // for HTTP fields; anything else (e.g. a stray ;name, or an unregistered parameter)
    // must not be silently ignored by falling through to the default encoding.
    const fieldParamKeys: string[] = Array.from(params.keySet());
    for (const paramKey of fieldParamKeys) {
      if (!ComponentProvider.FIELD_PARAMS.has(paramKey)) {
        throw new MalformedComponentIdentifierError(
          `Field ${fieldName}: unknown or inapplicable parameter ';${paramKey}'`);
      }
    }

    // RFC 9421 §2.1.3: ;bs (Strict Byte Sequence encoding) is mutually exclusive with
    // ;sf/;key (Structured Field / dictionary-key encoding) — they encode the value in
    // incompatible ways, so a combination is a malformed component identifier.
    if (hasBs && (hasSf || hasKey)) {
      throw new MalformedComponentIdentifierError(
        `Invalid Syntax: field ${fieldName} cannot combine ';bs' with ';sf' or ';key'`);
    }
    // ;tr (trailer fields) and ;req (request-response binding) are not implemented by
    // this provider. Rather than silently falling back to the default encoding (which
    // would produce a signature base that does not match what a compliant verifier
    // expects), fail loudly so callers don't sign or accept an incorrect value.
    if (hasTr) {
      throw new UnsupportedComponentParameterError(`Field ${fieldName}: ';tr' (trailer) parameter is not supported`);
    }
    if (hasReq) {
      throw new UnsupportedComponentParameterError(
        `Field ${fieldName}: ';req' (request-response binding) parameter is not supported`);
    }

    let value: string | null;
    if (hasKey) {
      // Dictionary field lookup (RFC 9421 Section 2.1.2)
      const keyParam: ItemType | undefined = params.get('key');
      if (!(keyParam instanceof StringItem)) {
        throw new MalformedComponentIdentifierError(
          `Invalid Syntax: Value for 'key' parameter of field ${fieldName} must be a StringItem`);
      }
      const fieldValue = this.getField(fieldName);
      let dict: Dictionary;
      try {
        dict = parseDictionary(fieldValue ?? '');
      } catch (e) {
        throw new ComponentValueError(`Field ${fieldName} is not a dictionary field`);
      }
      const key: string = keyParam.get();
      const dictMap: Map<string, ListElement> = dict.get();
      if (!dictMap.has(key)) {
        throw new ComponentValueError(`Value for '${key}' key of dictionary ${fieldName} does not exist`);
      }
      value = dictMap.get(key)!.serialize();
    } else if (hasSf) {
      // Structured-field serialization (RFC 9421 Section 2.1.1)
      value = this.getStructuredFieldValue(fieldName);
    } else if (hasBs) {
      // Strict Byte Sequence encoding (RFC 9421 Section 2.1.3)
      value = this.getByteSequenceValue(fieldName);
    } else {
      // No special parameter. Fall back to the default per RFC 9421 §2.1: read the raw
      // header, combine multi-values with ", " and trim OWS — which is exactly what
      // getField()/combineFieldValues() already do.
      value = this.getField(fieldName);
    }
    return ComponentProvider.validateFieldComponentValue(fieldName, value);
  }

  /**
   * RFC 9421 §2.5: a field-based signature-base-line reuses HTTP's field-content ABNF but
   * explicitly excludes obs-fold and obs-text — see PATTERN_FIELD_VALUE_CHARS/_EDGE above.
   * Applied to every field component value regardless of which parameter path produced it
   * (default/;sf/;key/;bs): the sfv package's own serialize() output is already
   * SFV-grammar-safe in practice, but this check is the single place that actually
   * guarantees it for every path, rather than relying on that being true incidentally.
   */
  private static validateFieldComponentValue(fieldName: string, value: string | null): string | null {
    if (value === null || value === undefined || value.length === 0) {
      return value;
    }
    const isAllowedChars = ComponentProvider.PATTERN_FIELD_VALUE_CHARS.test(value);
    const hasEdgeWhitespace = ComponentProvider.PATTERN_FIELD_VALUE_EDGE.test(value);
    if (!isAllowedChars || hasEdgeWhitespace) {
      throw new ComponentValueError(
        `Field ${fieldName}: value must be HTAB/SP/printable-ASCII only, with no leading or ` +
        `trailing whitespace (RFC 9421 §2.5)`);
    }
    return value;
  }

  /**
   * Strict-encodes a field as a List of Byte Sequences (RFC 9421 Section 2.1.3): each
   * field-line instance is independently OWS/obs-fold-trimmed and UTF-8 encoded into its
   * own Byte Sequence (":<base64>:"), then the resulting List of Byte Sequences is given
   * its strict Structured Field List serialization. This is deliberately *not* the same
   * as Byte-Sequence-encoding the already-combined getField() value — doing so would
   * collapse the distinction between multiple field instances and a single instance
   * containing embedded commas, which is exactly what ;bs exists to preserve.
   */
  private getByteSequenceValue(fieldName: string): string | null {
    const fieldValues = this.getFieldValues(fieldName);
    if (fieldValues === null || fieldValues === undefined || fieldValues.length === 0) {
      return null;
    }
    const byteSequenceItems: ListElement[] = [];
    for (const fieldValue of fieldValues) {
      const normalized = ComponentProvider.normalizeFieldValue(fieldValue);
      const bytes: Uint8Array = HttpHeaderUtils.encodeUtf8(normalized);
      byteSequenceItems.push(ByteSequenceItem.valueOf(bytes));
    }
    return SfvList.valueOf(byteSequenceItems).serialize();
  }

  /**
   * Strips leading/trailing HTTP OWS (SP/HTAB only — not JS's Unicode-aware \s) from a
   * single field-line value and folds any obs-fold (CRLF + OWS) into a single space, per
   * RFC 9421 §2.1 steps 2-3.
   */
  private static normalizeFieldValue(raw: string): string {
    return raw.replace(ComponentProvider.PATTERN_OWS, '').replace(ComponentProvider.PATTERN_WHITESPACE, ' ');
  }

  /**
   * Combine multiple field-line values into a single canonical value per RFC 9421 Section 2.1.
   *
   * Returns null only when the field is absent (`fields` is null/empty) — NOT when the
   * field is present but canonicalizes to an empty string. RFC 9421 §2.1 explicitly signs
   * empty fields as an empty string component value, so a present-but-empty field (e.g.
   * `X-Empty-Header:` with no content) must return `''` here, distinct from an absent field.
   */
  static combineFieldValues(fields: string[] | null): string | null {
    if (fields === null || fields === undefined || fields.length === 0) {
      return null;
    }
    let result = '';
    for (let i = 0; i < fields.length; i++) {
      const trimmed = ComponentProvider.normalizeFieldValue(fields[i]);
      if (i > 0) {
        result += ', ';
      }
      result += trimmed;
    }
    return result;
  }

  // ─── Structured-field normalization ──────────────────────────────────────

  private getStructuredFieldValue(fieldName: string): string {
    const fieldValue = this.getField(fieldName);
    const sfType = this.getFieldStructuredType(fieldName);

    switch (sfType) {
      case 'list':
        try {
          return parseList(fieldValue ?? '').serialize();
        } catch (e) {
          throw new ComponentValueError(`Field ${fieldName} is not a valid List structured field`);
        }
      case 'dictionary':
        try {
          return parseDictionary(fieldValue ?? '').serialize();
        } catch (e) {
          throw new ComponentValueError(`Field ${fieldName} is not a valid Dictionary structured field`);
        }
      case 'item':
        try {
          return parseItem(fieldValue ?? '').serialize();
        } catch (e) {
          throw new ComponentValueError(`Field ${fieldName} is not a valid Item structured field`);
        }
      default:
        // RFC 9421 §2.1.1: "If the application does not know the type of the field or does
        // not know how to serialize the type of the field, the use of this flag will
        // produce an error." Whether a field is a Structured Field — and which of List/
        // Dictionary/Item it is — is knowledge specific to the field and the application,
        // not something derivable from the field name alone (e.g. Content-Type and Host are
        // NOT Structured Fields despite the name superficially suggesting a value/param
        // shape; which fields are Structured Fields is an evolving, externally maintained
        // IANA registry, not something this library can safely hardcode).
        throw new ComponentValueError(
          `Field ${fieldName}: structured-field type is not known to this provider (;sf requires it)`);
    }
  }
}
