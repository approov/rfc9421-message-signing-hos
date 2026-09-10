import { ComponentProvider } from './ComponentProvider';
import { SignatureParameters } from './SignatureParameters';
import { ComponentValueError, MissingComponentValueError } from './errors';

// RFC 9421 §2: "Component values MUST NOT contain newline (\n) characters." A bare \n or \r
// inside a component value would let it inject an extra, attacker-controlled signature-base
// line (or corrupt the intended line), so this is checked regardless of whether the value
// came from a derived component or an HTTP field.
const PATTERN_VALUE_NEWLINE: RegExp = /[\n\r]/;
// RFC 9421 §2.5 step 4: "Produce an error if the output string contains any non-ASCII
// characters." The signature base as a whole must be a 7-bit ASCII string.
const PATTERN_NON_ASCII: RegExp = /[^\x00-\x7F]/;

/**
 * Builds the signature base string for an HTTP message signature (RFC 9421 Section 2.5).
 *
 * The signature base is the input to the signing algorithm and consists of a series of
 * component value lines followed by the @signature-params line.
 */
export class SignatureBaseBuilder {
  private readonly sigParams: SignatureParameters;
  private readonly ctx: ComponentProvider;

  constructor(sigParams: SignatureParameters, ctx: ComponentProvider) {
    this.sigParams = sigParams;
    this.ctx = ctx;
  }

  /**
   * Constructs and returns the signature base string.
   *
   * Format per RFC 9421 Section 2.5:
   *   "<component-id>": <component-value>\n
   *   ...
   *   "@signature-params": <inner-list-of-ids-with-params>
   */
  createSignatureBase(): string {
    let base = '';

    for (const componentIdentifier of this.sigParams.getComponentIdentifiers()) {
      const componentValue = this.ctx.getComponentValue(componentIdentifier);

      if (componentValue !== null && componentValue !== undefined) {
        // RFC 9421 §2: "Component values MUST NOT contain newline (\n) characters." A
        // component value that embeds \n/\r could otherwise inject a fabricated extra
        // signature-base line — reject it here rather than silently producing a base whose
        // line structure doesn't match what was actually requested to be signed.
        if (PATTERN_VALUE_NEWLINE.test(componentValue)) {
          throw new ComponentValueError(
            `SignatureBaseBuilder: value for ${componentIdentifier.serialize()} contains a newline character`);
        }
        // Append: "<component-id>": <value>\n
        base += componentIdentifier.serialize();
        base += ': ';
        base += componentValue;
        base += '\n';
      } else {
        throw new MissingComponentValueError(
          `SignatureBaseBuilder: Couldn't find a value for required parameter: ${componentIdentifier.serialize()}`);
      }
    }

    // Append @signature-params line
    base += this.sigParams.toComponentIdentifier().serialize();
    base += ': ';
    base += this.sigParams.toComponentValue().serialize();

    // RFC 9421 §2.5 step 4: the signature base as a whole must be pure ASCII.
    if (PATTERN_NON_ASCII.test(base)) {
      throw new ComponentValueError('SignatureBaseBuilder: signature base contains non-ASCII characters');
    }

    return base;
  }
}
