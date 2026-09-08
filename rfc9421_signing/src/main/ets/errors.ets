/**
 * Error types for building and parsing RFC 9421 HTTP Message Signature data
 * (component identifiers, signature bases, and Signature-Input entries).
 *
 */

/** Base class for all errors raised while building or parsing message-signature data. */
export class SignatureError extends Error {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'SignatureError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/** Thrown when a component identifier names an unknown derived component (e.g. "@bogus"). */
export class UnknownComponentError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'UnknownComponentError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/**
 * Thrown when a component identifier or one of its parameters is syntactically invalid
 * per RFC 9421 §2.1/§2.2 (e.g. a missing/mistyped `;name` or `;key` parameter, or an
 * invalid combination of parameters such as `;bs` with `;sf`/`;key`).
 */
export class MalformedComponentIdentifierError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'MalformedComponentIdentifierError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/** Thrown when a component identifier uses a parameter this provider does not implement (e.g. `;tr`, `;req`). */
export class UnsupportedComponentParameterError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'UnsupportedComponentParameterError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/** Thrown when a field's actual content does not satisfy what its component identifier requires (e.g. not a dictionary/structured field, or a missing dictionary key). */
export class ComponentValueError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'ComponentValueError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/** Thrown when the signature base cannot be built because a required component has no value. */
export class MissingComponentValueError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'MissingComponentValueError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}

/** Thrown when a Signature-Input dictionary entry is malformed (RFC 9421 §2.3/§4.1). */
export class MalformedSignatureInputError extends SignatureError {
  /** @param pMessage information describing the error cause */
  constructor(pMessage: string);
  /** @param pCause underlying cause of the error */
  constructor(pCause: Error);
  constructor(pMessageOrCause: string | Error) {
    if (typeof pMessageOrCause === 'string') {
      super(pMessageOrCause);
      this.name = 'MalformedSignatureInputError';
    } else {
      super(pMessageOrCause.message);
      this.name = pMessageOrCause.name;
      this.stack = pMessageOrCause.stack;
    }
  }
}
