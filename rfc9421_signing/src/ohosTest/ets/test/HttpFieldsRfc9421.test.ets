import { describe, it, expect } from '@ohos/hypium';
import { StringItem, SfvParameters } from '@approov/rfc8941_sfv';
import { ComponentProvider } from '../../../main/ets/ComponentProvider';
import { SignatureParameters } from '../../../main/ets/SignatureParameters';
import { SignatureBaseBuilder } from '../../../main/ets/SignatureBaseBuilder';
import {
  UnsupportedComponentParameterError,
  MalformedComponentIdentifierError,
  ComponentValueError,
} from '../../../main/ets/errors';

/**
 * Fixture ComponentProvider backed by a fixed set of HTTP header fields.
 *
 * `fields` holds the *raw*, per-instance field-line values exactly as they would appear on
 * the wire (one array entry per repeated header instance), so that both getField() (the
 * default combined value) and getFieldValues() (the raw per-instance values, used only by
 * ;bs) are derived from a single source of truth, just as a real implementation would.
 */
class HttpFieldsFixture extends ComponentProvider {
  private fields: Map<string, string[]>;

  constructor(fields: Map<string, string[]>) {
    super();
    this.fields = fields;
  }

  getMethod(): string | null { return null; }
  getAuthority(): string | null { return null; }
  getScheme(): string | null { return null; }
  getTargetUri(): string | null { return null; }
  getRequestTarget(): string | null { return null; }
  getPath(): string | null { return null; }
  getQuery(): string | null { return null; }
  getQueryParam(_name: string): string | null { return null; }
  getStatus(): string | null { return null; }
  hasBody(): boolean { return false; }

  hasField(name: string): boolean {
    return this.fields.has(name);
  }

  getField(name: string): string | null {
    return ComponentProvider.combineFieldValues(this.fields.get(name) ?? null);
  }

  getFieldValues(name: string): string[] | null {
    return this.fields.get(name) ?? null;
  }

  getFieldStructuredType(name: string): 'list' | 'dictionary' | 'item' | null {
    // "example-dict" is the RFC 9421 §2.1.1 worked example's Dictionary field name.
    return name === 'example-dict' ? 'dictionary' : null;
  }
}

function fieldId(name: string, params?: SfvParameters): StringItem {
  return params ? StringItem.valueOf(name).withParams(params) : StringItem.valueOf(name);
}

const SF: SfvParameters = SfvParameters.EMPTY.add('sf', true);
const BS: SfvParameters = SfvParameters.EMPTY.add('bs', true);
const TR: SfvParameters = SfvParameters.EMPTY.add('tr', true);
function keyParam(key: string): SfvParameters {
  return SfvParameters.EMPTY.add('key', key);
}

/**
 * Test cases transcribed from RFC 9421 §2.1 "HTTP Fields"
 * (https://www.rfc-editor.org/rfc/rfc9421.html#http-fields), covering every worked
 * example in that section and its subsections (§2.1.1-§2.1.4).
 */
export default function httpFieldsRfc9421Test() {
  describe('Rfc9421_HttpFields', () => {

    // §2.1 example HTTP message fragment:
    //   Host: www.example.com
    //   Date: Tue, 20 Apr 2021 02:07:56 GMT
    //   X-OWS-Header:   Leading and trailing whitespace.
    //   X-Obs-Fold-Header: Obsolete
    //       line folding.
    //   Cache-Control: max-age=60
    //   Cache-Control:    must-revalidate
    //   Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)
    const exampleMessageFields = new Map<string, string[]>([
      ['host', ['www.example.com']],
      ['date', ['Tue, 20 Apr 2021 02:07:56 GMT']],
      ['x-ows-header', ['   Leading and trailing whitespace.   ']],
      ['x-obs-fold-header', ['Obsolete\r\n    line folding.']],
      ['cache-control', ['max-age=60', '   must-revalidate']],
      ['example-dict', ['a=1,    b=2;x=1;y=2,   c=(a   b   c)']],
    ]);
    const exampleMessage = new HttpFieldsFixture(exampleMessageFields);

    it('§2.1 "host": www.example.com', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('host'))).assertEqual('www.example.com');
    });

    it('§2.1 "date": Tue, 20 Apr 2021 02:07:56 GMT', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('date')))
        .assertEqual('Tue, 20 Apr 2021 02:07:56 GMT');
    });

    it('§2.1 "x-ows-header": Leading and trailing whitespace.', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('x-ows-header')))
        .assertEqual('Leading and trailing whitespace.');
    });

    it('§2.1 "x-obs-fold-header": Obsolete line folding.', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('x-obs-fold-header')))
        .assertEqual('Obsolete line folding.');
    });

    it('§2.1 "cache-control": max-age=60, must-revalidate', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('cache-control')))
        .assertEqual('max-age=60, must-revalidate');
    });

    it('§2.1 "example-dict" (no params): a=1,    b=2;x=1;y=2,   c=(a   b   c)', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('example-dict')))
        .assertEqual('a=1,    b=2;x=1;y=2,   c=(a   b   c)');
    });

    // §2.1: "Empty HTTP fields can also be signed ... the canonicalized value is the empty
    // string" — given `X-Empty-Header:(SP)`, the signature base line is `"x-empty-header":(SP)`
    // (a colon, a single space, and nothing else).
    it('§2.1 empty field: "x-empty-header": (empty value)', 0, () => {
      const empty = new HttpFieldsFixture(new Map<string, string[]>([['x-empty-header', ['']]]));
      expect(empty.getComponentValue(fieldId('x-empty-header'))).assertEqual('');

      const params = new SignatureParameters().addComponentIdentifier('x-empty-header');
      const base = new SignatureBaseBuilder(params, empty).createSignatureBase();
      expect(base).assertEqual(
        '"x-empty-header": \n"@signature-params": ("x-empty-header")'
      );
    });

    // §2.1.1 Strict Serialization of HTTP Structured Fields:
    //   Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)
    //   "example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)
    it('§2.1.1 "example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c)', 0, () => {
      expect(exampleMessage.getComponentValue(fieldId('example-dict', SF)))
        .assertEqual('a=1, b=2;x=1;y=2, c=(a b c)');
    });

    // §2.1.2 Dictionary Structured Field Members:
    //   Example-Dict:  a=1, b=2;x=1;y=2, c=(a   b    c), d
    describe('§2.1.2 Dictionary Structured Field Members', () => {
      const dictMessage = new HttpFieldsFixture(new Map<string, string[]>([
        ['example-dict', ['a=1, b=2;x=1;y=2, c=(a   b    c), d']],
      ]));

      it('"example-dict";key="a": 1', 0, () => {
        expect(dictMessage.getComponentValue(fieldId('example-dict', keyParam('a')))).assertEqual('1');
      });

      it('"example-dict";key="d": ?1', 0, () => {
        expect(dictMessage.getComponentValue(fieldId('example-dict', keyParam('d')))).assertEqual('?1');
      });

      it('"example-dict";key="b": 2;x=1;y=2', 0, () => {
        expect(dictMessage.getComponentValue(fieldId('example-dict', keyParam('b')))).assertEqual('2;x=1;y=2');
      });

      it('"example-dict";key="c": (a b c)', 0, () => {
        expect(dictMessage.getComponentValue(fieldId('example-dict', keyParam('c')))).assertEqual('(a b c)');
      });

      // "If a Dictionary key is named as a covered component but it does not occur in the
      // Dictionary, this MUST cause an error in the signature base generation."
      it('"example-dict";key="missing" throws (RFC 9421 §2.1.2 MUST error)', 0, () => {
        expect(() => {
          dictMessage.getComponentValue(fieldId('example-dict', keyParam('missing')));
        }).assertThrowError(ComponentValueError);
      });
    });

    // §2.1.3 Binary-Wrapped HTTP Fields. Demonstrates the collision ;bs exists to prevent:
    // two separate field instances and one instance with an embedded comma are ambiguous
    // under the default combination algorithm, but distinct once ;bs is applied.
    describe('§2.1.3 Binary-Wrapped HTTP Fields', () => {
      const twoInstances = new HttpFieldsFixture(new Map<string, string[]>([
        ['example-header', ['value, with, lots', 'of, commas']],
      ]));
      const oneInstance = new HttpFieldsFixture(new Map<string, string[]>([
        ['example-header', ['value, with, lots, of, commas']],
      ]));

      it('default combination is identical for both cases (the ambiguity ;bs prevents)', 0, () => {
        const combinedTwo = twoInstances.getComponentValue(fieldId('example-header'));
        const combinedOne = oneInstance.getComponentValue(fieldId('example-header'));
        expect(combinedTwo).assertEqual('value, with, lots, of, commas');
        expect(combinedOne).assertEqual('value, with, lots, of, commas');
        expect(combinedTwo).assertEqual(combinedOne);
      });

      it('"example-header";bs (two instances): :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:', 0, () => {
        expect(twoInstances.getComponentValue(fieldId('example-header', BS)))
          .assertEqual(':dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:');
      });

      it('"example-header";bs (one instance): :dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:', 0, () => {
        expect(oneInstance.getComponentValue(fieldId('example-header', BS)))
          .assertEqual(':dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:');
      });

      it('the two ;bs-encoded values are distinct (collision prevented)', 0, () => {
        const bsTwo = twoInstances.getComponentValue(fieldId('example-header', BS));
        const bsOne = oneInstance.getComponentValue(fieldId('example-header', BS));
        expect(bsTwo === bsOne).assertFalse();
      });

      // "The bs parameter ... is not compatible with the use of the sf or key parameters."
      it('";bs" combined with ";sf" throws (RFC 9421 §2.1 incompatible parameters)', 0, () => {
        const both: SfvParameters = SfvParameters.EMPTY.add('bs', true).add('sf', true);
        expect(() => {
          oneInstance.getComponentValue(fieldId('example-header', both));
        }).assertThrowError(MalformedComponentIdentifierError);
      });

      it('";bs" combined with ";key" throws (RFC 9421 §2.1 incompatible parameters)', 0, () => {
        const both: SfvParameters = SfvParameters.EMPTY.add('bs', true).add('key', 'a');
        expect(() => {
          oneInstance.getComponentValue(fieldId('example-header', both));
        }).assertThrowError(MalformedComponentIdentifierError);
      });
    });

    // §2.1.4 Trailer Fields: "the signer MUST include the tr Boolean parameter". This
    // provider does not implement trailer access, so it fails loudly rather than silently
    // reading the header value instead of the trailer value.
    it('§2.1.4 "expires";tr throws (trailers not supported by this provider)', 0, () => {
      const withExpires = new HttpFieldsFixture(new Map<string, string[]>([
        ['expires', ['Wed, 9 Nov 2022 07:28:00 GMT']],
      ]));
      expect(() => {
        withExpires.getComponentValue(fieldId('expires', TR));
      }).assertThrowError(UnsupportedComponentParameterError);
    });
  });
}
