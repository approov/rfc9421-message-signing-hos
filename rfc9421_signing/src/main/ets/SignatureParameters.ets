import {
  StringItem,
  IntegerItem,
  BooleanItem,
  ByteSequenceItem,
  InnerList,
  SfvParameters,
  Dictionary,
  DecimalItem,
  DateItem,
} from '@approov/rfc8941_sfv';
import type { ItemType, SfvItemInput, ListElement } from '@approov/rfc8941_sfv';
import { Decimal } from '@kit.ArkTS';
import { MalformedComponentIdentifierError, MalformedSignatureInputError } from './errors';

/**
 * Carries the metadata for an HTTP message signature (RFC 9421 Section 2.3).
 *
 * Holds:
 * - An ordered list of component identifiers covered by the signature.
 * - The signature parameters: alg, created, expires, keyid, nonce, tag, and any custom params.
 */
export class SignatureParameters {
  private static readonly ALG = 'alg';
  private static readonly CREATED = 'created';
  private static readonly EXPIRES = 'expires';
  private static readonly KEYID = 'keyid';
  private static readonly NONCE = 'nonce';
  private static readonly TAG = 'tag';


  // set this to add an extra header to the request that includes the SHA256 of the signature base
  // which can be used to aid debugging on the server side to determine if there is a problem with
  // the reconstruction of the signature base or the verification of the signature.
  private _debugMode: boolean = false;
  private componentIdentifiers: StringItem[];
  /** Insertion-ordered map of parameter name → raw value (string | number | Item). */
  private params: Map<string, SfvItemInput>;

  constructor();
  constructor(base: SignatureParameters);
  constructor(base?: SignatureParameters) {
    if (base !== undefined) {
      this._debugMode = base._debugMode;
      this.componentIdentifiers = base.componentIdentifiers.slice();
      this.params = new Map<string, SfvItemInput>(base.params);
    } else {
      this.componentIdentifiers = [];
      this.params = new Map<string,SfvItemInput>();
    }
  }

  /**
   * @returns a copy of the componentIdentifiers. A copy — not the live internal array — is
   * returned so callers cannot mutate the covered-components list directly (e.g. via
   * `.push()`), which would bypass the duplicate-identifier check in addComponentIdentifier().
   */
  getComponentIdentifiers(): StringItem[] {
    return this.componentIdentifiers.slice();
  }

  /**
   * @returns a copy of the parameters map, this is used for ;sf ;key. A copy is returned so
   * callers cannot mutate an unvalidated value into it directly (bypassing the type checks
   * in setAlg()/setCreated()/etc. and setCustomParameter()).
   */
  getParameters(): Map<string, SfvItemInput> {
    return new Map<string, SfvItemInput>(this.params);
  }

  /**
   * Determine if debug mode has been set for this signature parameters instance.
   *
   * @returns true if debug mode is on; false otherwise
   */
  isDebugMode(): boolean {
    return this._debugMode;
  }

  /** @param debugMode - true to enable; false to disable */
  setDebugMode(debugMode: boolean): void {
    this._debugMode = debugMode;
  }

  /** @returns the alg */
  getAlg(): string | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.ALG);
    return typeof v === 'string' ? v : null;
  }

  /** @param alg - the alg to set */
  setAlg(alg: string): SignatureParameters {
    this.params.set(SignatureParameters.ALG, alg);
    return this;
  }

  /** @returns the created */
  getCreated(): number | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.CREATED);
    return typeof v === 'number' ? v : null;
  }

  /** @param created - the created to set */
  setCreated(created: number): SignatureParameters {
    this.params.set(SignatureParameters.CREATED, created);
    return this;
  }

  /** @returns the expires */
  getExpires(): number | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.EXPIRES);
    return typeof v === 'number' ? v : null;
  }

  /** @param expires - the expires to set */
  setExpires(expires: number): SignatureParameters {
    this.params.set(SignatureParameters.EXPIRES, expires);
    return this;
  }

  /** @returns the keyid */
  getKeyid(): string | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.KEYID);
    return typeof v === 'string' ? v : null;
  }

  /** @param keyid - the keyid to set */
  setKeyid(keyid: string): SignatureParameters {
    this.params.set(SignatureParameters.KEYID, keyid);
    return this;
  }

  /** @returns the nonce */
  getNonce(): string | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.NONCE);
    return typeof v === 'string' ? v : null;
  }

  /** @param nonce - the nonce to set */
  setNonce(nonce: string): SignatureParameters {
    this.params.set(SignatureParameters.NONCE, nonce);
    return this;
  }

  /** @returns the tag */
  getTag(): string | null {
    const v: SfvItemInput | undefined = this.params.get(SignatureParameters.TAG);
    return typeof v === 'string' ? v : null;
  }

  /** @param tag - the tag to set */
  setTag(tag: string): SignatureParameters {
    this.params.set(SignatureParameters.TAG, tag);
    return this;
  }

  getCustomParameter(key: string): SfvItemInput | undefined {
    return this.params.get(key);
  }

  setCustomParameter(key: string, value: SfvItemInput): SignatureParameters {
    switch (key) {
      case SignatureParameters.ALG:
        if (typeof value !== 'string') {
          throw new TypeError(`Parameter '${key}' must be a string, got ${typeof value}`);
        }
        this.setAlg(value as string);
        break;
      case SignatureParameters.CREATED:
        if (typeof value !== 'number') {
          throw new TypeError(`Parameter '${key}' must be a number, got ${typeof value}`);
        }
        this.setCreated(value as number);
        break;
      case SignatureParameters.EXPIRES:
        if (typeof value !== 'number') {
          throw new TypeError(`Parameter '${key}' must be a number, got ${typeof value}`);
        }
        this.setExpires(value as number);
        break;
      case SignatureParameters.KEYID:
        if (typeof value !== 'string') {
          throw new TypeError(`Parameter '${key}' must be a string, got ${typeof value}`);
        }
        this.setKeyid(value as string);
        break;
      case SignatureParameters.NONCE:
        if (typeof value !== 'string') {
          throw new TypeError(`Parameter '${key}' must be a string, got ${typeof value}`);
        }
        this.setNonce(value as string);
        break;
      case SignatureParameters.TAG:
        if (typeof value !== 'string') {
          throw new TypeError(`Parameter '${key}' must be a string, got ${typeof value}`);
        }
        this.setTag(value as string);
        break;
      default:
        this.params.set(key, value);
    }
    return this;
  }

  /**
   * Add a component with optional parameters.
   *
   * RFC 9421 §2.1 requires field component names to be lowercase. The plain-string overload
   * silently lowercases as a convenience for direct, programmatic construction (e.g.
   * `.addComponentIdentifier('Content-Type')`). The StringItem overload does NOT — it is
   * also the path fromDictionaryEntry() uses to reconstruct covered components from a
   * (possibly attacker-controlled) Signature-Input header off the wire, where an uppercase
   * field name is itself a non-compliant identifier that must be rejected, not silently
   * "fixed" into something the signer/attacker didn't actually send.
   *
   * RFC 9421 §2/§2.5 also requires each covered component identifier (name + parameters,
   * order-independent) to occur only once; this is enforced here too, since this is the
   * single insertion point for both overloads.
   *
   * RFC 9421 §2.3: "the component identifier MUST NOT be enumerated within the set of
   * covered components for any signature, including itself" — @signature-params is always
   * synthesized as the trailer line by SignatureBaseBuilder and must never be added here.
   */
  addComponentIdentifier(identifier: string | StringItem): SignatureParameters {
    let item: StringItem;
    if (typeof identifier === 'string') {
      const name = identifier.startsWith('@') ? identifier : identifier.toLocaleLowerCase("en-US");
      item = StringItem.valueOf(name);
    } else {
      const name: string = identifier.get();
      if (!name.startsWith('@') && name !== name.toLocaleLowerCase("en-US")) {
        throw new MalformedComponentIdentifierError(
          `Invalid Syntax: field component identifier '${name}' must be lowercase (RFC 9421 §2.1)`);
      }
      item = identifier;
    }
    if (item.get() === '@signature-params') {
      throw new MalformedComponentIdentifierError(
        `'@signature-params' MUST NOT be enumerated within the set of covered components (RFC 9421 §2.3)`);
    }
    if (this.containsComponentIdentifier(item)) {
      throw new MalformedComponentIdentifierError(
        `Duplicate component identifier: ${item.serialize()} (RFC 9421 §2: each covered ` +
        `component identifier MUST occur only once)`);
    }
    this.componentIdentifiers.push(item);
    return this;
  }

  /** Returns true if any covered component has the given name (ignores parameters). */
  containsComponentIdentifierByName(identifier: string): boolean {
    for (const item of this.componentIdentifiers) {
      if (item.get() === identifier) {
        return true;
      }
    }
    return false;
  }

  /** Returns true if the exact identifier (name + parameters) is covered. */
  containsComponentIdentifier(identifier: StringItem): boolean {
    const value:string = identifier.get();
    const params: SfvParameters = identifier.getParams();
    for (const item of this.componentIdentifiers) {
      if (item.get() === value && item.getParams().equals(params)) {
        return true;
      }
    }
    return false;
  }


  /** Returns the "@signature-params" component identifier. */
  toComponentIdentifier(): StringItem {
    return StringItem.valueOf('@signature-params');
  }

  /**
   * Serializes this SignatureParameters as an InnerList (RFC 9421 Section 2.3):
   *   (<covered-components>);alg="...";created=...;...
   */
  toComponentValue(): InnerList {
    const identifiers: StringItem[] = this.componentIdentifiers.slice();
    let list: InnerList = InnerList.valueOf(identifiers);

    const paramsMap = new Map<string, ItemType>();
    for (const entry of this.params.entries()) {
      const k = entry[0];
      const v = entry[1];
      if (typeof v === 'string') {
        paramsMap.set(k, StringItem.valueOf(v));
      } else if (typeof v === 'number') {
        paramsMap.set(k, IntegerItem.valueOf(v));
      } else if (typeof v === 'boolean') {
        paramsMap.set(k, BooleanItem.valueOf(v));
      } else if (v instanceof Uint8Array) {
        paramsMap.set(k, ByteSequenceItem.valueOf(v));
      } else if (v instanceof Decimal) {
        paramsMap.set(k, DecimalItem.valueOf(v));
      } else if (v instanceof Date){
        paramsMap.set(k,DateItem.valueOf(v))
      } else {
        paramsMap.set(k, v);
      }
    }
    list = list.withParams(SfvParameters.valueOf(paramsMap));

    return list;
  }

  /**
   * Reconstruct SignatureParameters from a parsed Signature-Input Dictionary entry.
   *
   * @param signatureInput  the parsed Dictionary from the "Signature-Input" header
   * @param sigId           the signature label (e.g. "sig1")
   */
  static fromDictionaryEntry(signatureInput: Dictionary, sigId: string): SignatureParameters {
    const map: Map<string, ListElement> = signatureInput.get();
    if (!map.has(sigId)) {
      throw new MalformedSignatureInputError(
        `Could not find identifier '${sigId}' in dictionary ${signatureInput.serialize()}`);
    }

    const item: ListElement = map.get(sigId)!;
    if (!(item instanceof InnerList)) {
      throw new MalformedSignatureInputError(`Invalid syntax, identifier '${sigId}' must be an inner list`);
    }

    const coveredComponents = item as InnerList;
    const result = new SignatureParameters();

    // Populate covered components. RFC 9421 §2.3 requires every member of the covered-
    // components inner list to be a String Item (a component identifier); a non-string
    // member makes the whole Signature-Input entry malformed, so reject it outright
    // rather than silently dropping the offending member and signing/verifying against
    // an incomplete component list.
    const coveredComponentItems: ItemType[] = coveredComponents.get();
    for (const innerItem of coveredComponentItems) {
      if (!(innerItem instanceof StringItem)) {
        throw new MalformedSignatureInputError(
          `Invalid syntax, identifier '${sigId}': covered component '${innerItem.serialize()}' ` +
          `must be a String Item`);
      }
      result.addComponentIdentifier(innerItem as StringItem);
    }

    // Populate parameters. A known parameter (alg/created/expires/keyid/nonce/tag) whose
    // value has the wrong SFV type is a malformed Signature-Input entry — reject the whole
    // entry instead of silently ignoring the bad parameter, which would otherwise leave
    // the caller with an incomplete/incorrect SignatureParameters and no indication why.
    const coveredComponentParams: IterableIterator<[string, ItemType]> = coveredComponents.getParams().entrySet();
    for (const entry of coveredComponentParams) {
      const key: string = entry[0];
      const paramValue: ItemType = entry[1];
      switch (key) {
        case SignatureParameters.ALG:
          if (!(paramValue instanceof StringItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'alg' parameter must be a String Item`);
          }
          result.setAlg(paramValue.get());
          break;
        case SignatureParameters.CREATED:
          if (!(paramValue instanceof IntegerItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'created' parameter must be an Integer Item`);
          }
          result.setCreated(paramValue.get());
          break;
        case SignatureParameters.EXPIRES:
          if (!(paramValue instanceof IntegerItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'expires' parameter must be an Integer Item`);
          }
          result.setExpires(paramValue.get());
          break;
        case SignatureParameters.KEYID:
          if (!(paramValue instanceof StringItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'keyid' parameter must be a String Item`);
          }
          result.setKeyid(paramValue.get());
          break;
        case SignatureParameters.NONCE:
          if (!(paramValue instanceof StringItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'nonce' parameter must be a String Item`);
          }
          result.setNonce(paramValue.get());
          break;
        case SignatureParameters.TAG:
          if (!(paramValue instanceof StringItem)) {
            throw new MalformedSignatureInputError(
              `Invalid syntax, identifier '${sigId}': 'tag' parameter must be a String Item`);
          }
          result.setTag(paramValue.get());
          break;
        default:
          // Store the Item itself, not paramValue.get(): unwrapping to the bare JS value
          // (e.g. a TokenItem's bare value is a plain `string`, indistinguishable at that
          // point from a StringItem's) would lose which SFV type the parameter actually
          // was. toComponentValue() re-derives StringItem for any `typeof v === 'string'`
          // entry, so a Token would silently come back quoted (foo=bar -> foo="bar") on
          // reserialization — producing a signature base that doesn't match what the
          // signer actually signed. ItemType is already a valid SfvItemInput, so this
          // round-trips exactly regardless of the concrete SFV type.
          result.params.set(key, paramValue);
      }
    }

    return result;
  }

  toString(): string {
    return `SignatureParameters: ${this.toComponentValue().serialize()}`;
  }
}
