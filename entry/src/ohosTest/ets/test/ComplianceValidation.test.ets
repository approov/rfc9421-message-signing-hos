import { describe, it, expect } from '@ohos/hypium';
import { Dictionary, IntegerItem, StringItem, TokenItem, parseDictionary, parseItem } from '@approov/rfc9651-sfv';
import type { ItemType } from '@approov/rfc9651-sfv';
import {
  ComponentProvider,
  SignatureBaseBuilder,
  SignatureParameters,
  ComponentValueError,
  MalformedComponentIdentifierError,
  UnsupportedComponentParameterError,
} from '@approov/rfc9421-message-signing';

class ComplianceFixture extends ComponentProvider {
  method: string | null = 'GET';
  queryParamValue: string | null = 'value';
  requestedQueryParamName: string = '';
  fields: Map<string, string[]> = new Map<string, string[]>();

  getMethod(): string | null { return this.method; }
  getAuthority(): string | null { return 'example.com'; }
  getScheme(): string | null { return 'https'; }
  getTargetUri(): string | null { return 'https://example.com/'; }
  getRequestTarget(): string | null { return '/'; }
  getPath(): string | null { return '/'; }
  getQuery(): string | null { return '?'; }
  getQueryParam(name: string): string | null {
    this.requestedQueryParamName = name;
    return this.queryParamValue;
  }
  getStatus(): string | null { return '200'; }
  hasBody(): boolean { return false; }
  hasField(name: string): boolean { return this.fields.has(name); }
  getField(name: string): string | null {
    return ComponentProvider.combineFieldValues(this.fields.get(name) ?? null);
  }
  getFieldValues(name: string): string[] | null { return this.fields.get(name) ?? null; }
  getFieldStructuredType(_name: string): 'list' | 'dictionary' | 'item' | null { return null; }
}

function parseComponent(value: string): StringItem {
  const item: ItemType = parseItem(value);
  if (!(item instanceof StringItem)) {
    throw new Error(`Expected StringItem: ${value}`);
  }
  return item;
}

export default function complianceValidationTest() {
  describe('Rfc9421_ComplianceValidation', () => {
    it('rejects unknown and inapplicable component parameters', 0, () => {
      const fixture = new ComplianceFixture();
      expect(() => fixture.getComponentValue(parseComponent('"@method";sf')))
        .assertThrowError(MalformedComponentIdentifierError);
      expect(() => fixture.getComponentValue(parseComponent('"@query-param";name="id";bs')))
        .assertThrowError(MalformedComponentIdentifierError);
      expect(() => fixture.getComponentValue(parseComponent('"content-type";name="x"')))
        .assertThrowError(MalformedComponentIdentifierError);
    });

    it('validates Boolean parameters and treats ?0 as disabled', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.fields.set('x-test', ['raw value']);
      expect(() => fixture.getComponentValue(parseComponent('"x-test";sf="yes"')))
        .assertThrowError(MalformedComponentIdentifierError);
      expect(() => fixture.getComponentValue(parseComponent('"x-test";bs=1')))
        .assertThrowError(MalformedComponentIdentifierError);
      expect(fixture.getComponentValue(parseComponent('"x-test";sf=?0')))
        .assertEqual('raw value');
      expect(fixture.getComponentValue(parseComponent('"@method";req=?0')))
        .assertEqual('GET');
      expect(() => fixture.getComponentValue(parseComponent('"@method";req')))
        .assertThrowError(UnsupportedComponentParameterError);
    });

    it('uses form-urlencoded decoding for query parameter names', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.getComponentValue(parseComponent('"@query-param";name="first+name"'));
      expect(fixture.requestedQueryParamName).assertEqual('first name');
    });

    it('rejects invalid values from derived component paths that return raw strings', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.method = ' GET';
      expect(() => fixture.getComponentValue(StringItem.valueOf('@method')))
        .assertThrowError(ComponentValueError);
      fixture.method = 'GET ';
      expect(() => fixture.getComponentValue(StringItem.valueOf('@method')))
        .assertThrowError(ComponentValueError);
      fixture.method = 'GE\tT';
      expect(() => fixture.getComponentValue(StringItem.valueOf('@method')))
        .assertThrowError(ComponentValueError);
    });

    it('@query-param encodes control characters instead of rejecting them', 0, () => {
      // getQueryParam() returns the *decoded* value (RFC 9421 §2.2.8 step 1); this class
      // performs the re-encoding (step 2) itself, so a raw NUL byte in the decoded value
      // is neutralized as "%00" before it ever reaches validateDerivedComponentValue() —
      // unlike @method above, which has no encoding step and so must reject a bad raw value.
      const fixture = new ComplianceFixture();
      fixture.queryParamValue = 'bad\u0000value';
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="id"')))
        .assertEqual('bad%00value');
    });

    // RFC 9421 §2.2.8's own worked example: given
    //   GET /parameters?var=this%20is%20a%20big%0Amultiline%20value&\
    //     bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something
    // the spec gives these exact expected outputs — used verbatim here to pin
    // formUrlEncode() to the precise WHATWG "application/x-www-form-urlencoded
    // percent-encode set", not an approximation like encodeURIComponent() (which would
    // leave "!'()*" unescaped and diverge from another implementation's output).
    it('§2.2.8 worked example: re-encodes a newline and internal spaces as %0A/%20', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.queryParamValue = 'this is a big\nmultiline value';
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="var"')))
        .assertEqual('this%20is%20a%20big%0Amultiline%20value');
    });

    it('§2.2.8 worked example: re-encodes decoded spaces as %20, not "+"', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.queryParamValue = 'with plus whitespace';
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="bar"')))
        .assertEqual('with%20plus%20whitespace');
    });

    it('§2.2.8 worked example: re-encodes non-ASCII and reserved characters (facade example)', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.queryParamValue = 'something';
      const value = fixture.getComponentValue(parseComponent('"@query-param";name="fa%C3%A7ade%22%3A%20"'));
      expect(fixture.requestedQueryParamName).assertEqual('fa\u00e7ade": ');
      expect(value).assertEqual('something');
    });

    it('formUrlEncode leaves only "*-._" and alphanumerics unescaped, unlike encodeURIComponent', 0, () => {
      // encodeURIComponent("!'()*~") leaves them all unescaped — the WHATWG application/
      // x-www-form-urlencoded percent-encode set requires "!'()~" to be escaped (only "*"
      // is left unescaped, alongside "-._" and alphanumerics).
      const fixture = new ComplianceFixture();
      fixture.queryParamValue = "!'()*~";
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="x"')))
        .assertEqual('%21%27%28%29*%7E');
    });

    // Consolidated encoding regression test: pins formUrlEncode()'s three distinct
    // encoding behaviors (reserved/punctuation characters, space, and multi-byte UTF-8)
    // in one place, each checked independently against its own decoded input.
    it('formUrlEncode regression: reserved chars, space, and UTF-8 are each encoded correctly', 0, () => {
      const fixture = new ComplianceFixture();

      // Reserved/punctuation characters not in the safe set [A-Za-z0-9*-._]: "!'()~" are
      // percent-encoded, "*" is left as-is.
      fixture.queryParamValue = "!'()~*";
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="a"')))
        .assertEqual('%21%27%28%29%7E*');

      // A decoded space is percent-encoded as %20, never substituted with "+".
      fixture.queryParamValue = 'a b';
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="b"')))
        .assertEqual('a%20b');

      // Multi-byte UTF-8 (é = U+00E9 = bytes 0xC3 0xA9) is percent-encoded byte-by-byte.
      fixture.queryParamValue = 'café';
      expect(fixture.getComponentValue(parseComponent('"@query-param";name="c"')))
        .assertEqual('caf%C3%A9');
    });

    it('rejects duplicate identifiers regardless of parameter order', 0, () => {
      const signatureParams = new SignatureParameters();
      signatureParams.addComponentIdentifier(parseComponent('"x-test";a;b'));
      expect(() => signatureParams.addComponentIdentifier(parseComponent('"x-test";b;a')))
        .assertThrowError(MalformedComponentIdentifierError);
      const dictionary: Dictionary = parseDictionary('sig1=("@method" "@method")');
      expect(() => SignatureParameters.fromDictionaryEntry(dictionary, 'sig1'))
        .assertThrowError(MalformedComponentIdentifierError);
    });

    it('returns copies of covered components and signature parameters', 0, () => {
      const signatureParams = new SignatureParameters()
        .addComponentIdentifier('@method')
        .setAlg('hmac-sha256');
      signatureParams.getComponentIdentifiers().push(StringItem.valueOf('@method'));
      signatureParams.getParameters().set('alg', 'changed');
      expect(signatureParams.getComponentIdentifiers().length).assertEqual(1);
      expect(signatureParams.getAlg()).assertEqual('hmac-sha256');
    });

    it('rejects newline and non-ASCII values in the signature base', 0, () => {
      const fixture = new ComplianceFixture();
      fixture.fields.set('x-test', ['safe\ninjected']);
      let signatureParams = new SignatureParameters().addComponentIdentifier('x-test');
      expect(() => new SignatureBaseBuilder(signatureParams, fixture).createSignatureBase())
        .assertThrowError(ComponentValueError);
      fixture.fields.set('x-test', ['caf\u00e9']);
      signatureParams = new SignatureParameters().addComponentIdentifier('x-test');
      expect(() => new SignatureBaseBuilder(signatureParams, fixture).createSignatureBase())
        .assertThrowError(ComponentValueError);
    });

    it('preserves custom signature parameter SFV types', 0, () => {
      const dictionary: Dictionary = parseDictionary('sig1=("@method");custom=token;count=2');
      const signatureParams = SignatureParameters.fromDictionaryEntry(dictionary, 'sig1');
      expect(signatureParams.getCustomParameter('custom') instanceof TokenItem).assertTrue();
      expect(signatureParams.getCustomParameter('count') instanceof IntegerItem).assertTrue();
      expect(signatureParams.toComponentValue().serialize())
        .assertEqual('("@method");custom=token;count=2');
    });

    it('rejects uppercase field identifiers parsed from Signature-Input', 0, () => {
      const dictionary: Dictionary = parseDictionary('sig1=("Content-Type")');
      expect(() => SignatureParameters.fromDictionaryEntry(dictionary, 'sig1'))
        .assertThrowError(MalformedComponentIdentifierError);
      expect(new SignatureParameters().addComponentIdentifier('Content-Type')
        .getComponentIdentifiers()[0].get()).assertEqual('content-type');
    });

    it('trims only HTTP OWS', 0, () => {
      expect(ComponentProvider.combineFieldValues(['\u00a0value\u00a0']))
        .assertEqual('\u00a0value\u00a0');
    });
  });
}
