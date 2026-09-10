# @approov/rfc9421-message-signing

English | [中文](readme-zh.md)

Repository: [https://github.com/approov/rfc9421-signing-hos](https://github.com/approov/rfc9421-signing-hos)

An ArkTS implementation of the message-component and signature-base machinery of [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) (RFC 9421 §2): component identifiers, HTTP field canonicalization, `Signature-Input` parameters, and signature base construction. It does not perform signing/verification itself (no key management or crypto) — it produces the exact byte string a signer hands to its signing algorithm, and that a verifier reconstructs to check a signature against.

Built on [@approov/rfc9651-sfv](https://github.com/approov/rfc8941-sfv-hos) for Structured Field Values (RFC 8941/9651) parsing and serialization.

## Installation

```
ohpm install @approov/rfc9421-message-signing
```

For more on setting up the OpenHarmony ohpm environment, see [How to install an OpenHarmony ohpm package](https://gitee.com/openharmony-tpc/docs/blob/master/OpenHarmony_har_usage.md).

## Usage

### Implementing a `ComponentProvider`

`ComponentProvider` is an abstract class: implement it once per transport (e.g. an HTTP client's request/response type) to expose derived components (`@method`, `@path`, ...) and HTTP fields to the signature base builder.

```typescript
import { ComponentProvider } from '@approov/rfc9421-message-signing';

class MyRequestComponentProvider extends ComponentProvider {
  getMethod(): string | null { return this.request.method; }
  getAuthority(): string | null { /* ... */ return null; }
  getScheme(): string | null { /* ... */ return null; }
  getTargetUri(): string | null { /* ... */ return null; }
  getRequestTarget(): string | null { /* ... */ return null; }
  getPath(): string | null { /* ... */ return null; }
  getQuery(): string | null { /* ... */ return null; }

  // The *decoded* query parameter value (RFC 9421 §2.2.8 step 1). Do not percent-encode
  // it yourself — ComponentProvider does that (step 2) before the value reaches the
  // signature base, using the exact "application/x-www-form-urlencoded" percent-encode set.
  getQueryParam(name: string): string | null { /* ... */ return null; }

  getStatus(): string | null { return null; } // requests only
  hasBody(): boolean { /* ... */ return false; }

  hasField(name: string): boolean { /* ... */ return false; }

  // The default, RFC 9421 §2.1-combined value of a field (used unless ;sf/;key/;bs applies).
  getField(name: string): string | null {
    return ComponentProvider.combineFieldValues(this.rawValuesOf(name));
  }

  // The *raw*, per-instance field values (one entry per repeated header), used only for
  // the ;bs (Byte Sequence) parameter — see "Binary-Wrapped Fields" below.
  getFieldValues(name: string): string[] | null {
    return this.rawValuesOf(name);
  }

  // Which kind of Structured Field (RFC 8941/9651) the named field is, if any — used only
  // for ;sf (Structured Field serialization). Return null for anything that isn't a
  // Structured Field, or whose type your application doesn't actually know; ComponentProvider
  // does NOT guess this from the field name (see "Structured Field types" below).
  getFieldStructuredType(name: string): 'list' | 'dictionary' | 'item' | null {
    return name === 'example-dict' ? 'dictionary' : null;
  }
}
```

Every accessor method here — including derived component values, field values, and
`@query-param` — is validated by `ComponentProvider` before it reaches the signature base:
derived values must be printable ASCII/space with no leading/trailing whitespace (RFC 9421
§2.2); field values must be HTAB/SP/printable-ASCII with no leading/trailing whitespace (RFC
9421 §2.5); and every value is checked for embedded newlines (`SignatureBaseBuilder`, RFC
9421 §2) so a misbehaving provider can't inject an extra signature-base line.

### Structured Field types

Whether a given HTTP field is a Structured Field — and which kind (List/Dictionary/Item) —
is *not* something `ComponentProvider` infers from the field name. RFC 9421 §2.1.1 is
explicit that this is application-specific knowledge ("If the application does not know the
type of the field ... the use of this flag will produce an error"), and which fields are
registered as Structured Fields is tracked in an external, evolving IANA registry — not
something safe to hardcode in this library. `getFieldStructuredType()` is how your provider
declares it; `;sf` on a field it returns `null` for always throws `ComponentValueError`.

### Building a signature base

```typescript
import { SignatureParameters, SignatureBaseBuilder, ComponentProvider } from '@approov/rfc9421-message-signing';

const params = new SignatureParameters()
  .addComponentIdentifier(ComponentProvider.DC_METHOD)
  .addComponentIdentifier(ComponentProvider.DC_AUTHORITY)
  .addComponentIdentifier('content-digest')
  .setCreated(Math.floor(Date.now() / 1000))
  .setKeyid('my-key')
  .setAlg('ecdsa-p256-sha256');

const provider = new MyRequestComponentProvider(request);
const base = new SignatureBaseBuilder(params, provider).createSignatureBase();
// base is the exact string to pass to your signing algorithm.
```

`addComponentIdentifier()` lowercases plain-string field names as a convenience, and rejects:
- a component identifier that's already covered — RFC 9421 §2 requires each covered
  component identifier to appear only once (parameter order does not affect this comparison);
- `'@signature-params'` — RFC 9421 §2.3 requires it never be enumerated as a covered
  component (it's always synthesized as the trailer line by `SignatureBaseBuilder`).

### Reconstructing parameters from a `Signature-Input` header

```typescript
import { parseDictionary } from '@approov/rfc9651-sfv';
import { SignatureParameters } from '@approov/rfc9421-message-signing';

const dict = parseDictionary(signatureInputHeaderValue);
const params = SignatureParameters.fromDictionaryEntry(dict, 'sig1');
```

Unlike the plain-string overload of `addComponentIdentifier()`, parsing rejects (rather than
normalizes) an uppercase field component name here — a `Signature-Input` header is untrusted
input, and an uppercase field name in it is itself non-compliant with RFC 9421 §2.1, not
something this library should silently "fix" on the caller's behalf.

### Query parameter encoding

`getQueryParam()` returns the *decoded* parameter value; `ComponentProvider` percent-encodes
it for you (RFC 9421 §2.2.8 step 2) using the exact "application/x-www-form-urlencoded"
percent-encode set — not `encodeURIComponent()`, which leaves `!'()*~` unescaped and would
disagree byte-for-byte with another RFC 9421 implementation's output for values containing
those characters:

```typescript
// Given a request for /search?q=caf%C3%A9%20%26%20cr%C3%A8me, a URL implementation's
// parsed/decoded search params already hand you "café & crème" for `q` — return it as-is:
getQueryParam(name: string): string | null {
  return this.url.searchParams.get(name); // already decoded by most URL implementations
}
```

```typescript
import { StringItem, SfvParameters } from '@approov/rfc9651-sfv';

const provider = new MyRequestComponentProvider(request); // q -> "café & crème"
const id = StringItem.valueOf('@query-param').withParams(SfvParameters.EMPTY.add('name', 'q'));
provider.getComponentValue(id); // "caf%C3%A9%20%26%20cr%C3%A8me" — space and & re-encoded, not left as "+"/"&"
```

If your transport instead only gives you the raw, still-percent-encoded query string,
decode it yourself before returning it (e.g. `decodeURIComponent(raw.replace(/\+/g, ' '))`,
matching how this library decodes the `;name` parameter's own value internally) — do not
return the encoded form directly.

### Error handling

Every error thrown by this library extends `SignatureError`, and each subclass can also wrap an underlying cause (adopting its message/name/stack):

```typescript
import { SignatureError, ComponentValueError } from '@approov/rfc9421-message-signing';

try {
  builder.createSignatureBase();
} catch (e) {
  if (e instanceof ComponentValueError) {
    // a covered field/dictionary-key was missing or malformed
  } else if (e instanceof SignatureError) {
    // any other signature-base construction error
  }
}
```

| Error | Thrown when |
| --- | --- |
| `SignatureError` | Base class for all errors in this library |
| `UnknownComponentError` | A component identifier names an unrecognized derived component (e.g. `@bogus`) |
| `MalformedComponentIdentifierError` | A component identifier or its parameters are syntactically invalid: missing/mistyped `;name`/`;key`, an unknown or inapplicable parameter (e.g. `;sf` on `@method`), a non-Boolean value for a Boolean-flag parameter (e.g. `;sf="yes"`), an incompatible combination such as `;bs` with `;sf`/`;key`, `'@signature-params'` used as a covered component, a duplicate covered component identifier, or (when parsing untrusted input) an uppercase field component name |
| `UnsupportedComponentParameterError` | A component identifier uses a parameter this provider does not implement (`;tr`, `;req`) |
| `ComponentValueError` | A field's or derived component's value does not satisfy what its identifier requires: not a dictionary/structured field, an unknown Structured Field type (`getFieldStructuredType()` returned `null`), a missing dictionary key, a derived component value outside printable-ASCII/space or a field value outside HTAB/SP/printable-ASCII (either with leading/trailing whitespace) (RFC 9421 §2.2/§2.5), or a component value containing a newline / the assembled signature base containing non-ASCII characters (RFC 9421 §2.5) |
| `MissingComponentValueError` | The signature base cannot be built because a required component has no value |
| `MalformedSignatureInputError` | A `Signature-Input` dictionary entry is malformed |

## API

| Type | Description |
| --- | --- |
| `ComponentProvider` | Abstract base: implement to expose derived components and HTTP fields; dispatches component identifiers via `getComponentValue()` |
| `SignatureParameters` | The covered-components list plus signature parameters (`alg`, `created`, `expires`, `keyid`, `nonce`, `tag`, custom); serializes to/from the `@signature-params` `Signature-Input` entry |
| `SignatureBaseBuilder` | Combines a `SignatureParameters` and a `ComponentProvider` into the final signature base string (RFC 9421 §2.5) |
| `SignatureError` and subclasses | Typed errors — see table above |

## Constraints and limitations

- Written in ArkTS, for use in HarmonyOS/OpenHarmony Stage-model projects.
- Only builds/parses signature *data* — no key management, signing, or verification is included.
- `;tr` (trailer fields) and `;req` (request-response binding, on both fields and derived components) are not implemented; a component identifier using either always throws `UnsupportedComponentParameterError` rather than silently producing an incorrect value.
- `ComponentProvider` has no notion of "is the target message a request or a response", so it cannot itself enforce rules that depend on that (e.g. "a request signature must not cover `@status`") — an application built on this library needs to enforce those itself.
- `getFieldValues()` (used for `;bs`) returns `string[]`; a field value that isn't valid UTF-8 to begin with can't be carried losslessly through this API. Acceptable for ASCII/UTF-8 field values (the common case), not a fully general implementation of RFC 9421 §2.1.3 for opaque binary field content.

## Testing

[`HttpFieldsRfc9421.test.ets`](src/ohosTest/ets/test/HttpFieldsRfc9421.test.ets) transcribes every worked example from [RFC 9421 §2.1 "HTTP Fields"](https://www.rfc-editor.org/rfc/rfc9421.html#http-fields) (including its subsections §2.1.1–§2.1.4) into runnable test cases against a fixture `ComponentProvider`. The table below is the same set of examples, for reference without reading the RFC itself.

[`ComplianceValidation.test.ets`](src/ohosTest/ets/test/ComplianceValidation.test.ets) covers everything else this library validates or enforces beyond §2.1's worked examples: rejecting unknown/inapplicable component parameters, Boolean-flag parameter typing and `?0` handling, `@query-param` form-urlencoded decoding of `;name` and re-encoding of the returned value (including RFC 9421 §2.2.8's own worked examples, and a dedicated regression test pinning the exact percent-encode set against `encodeURIComponent()`'s different one), rejecting invalid derived/field component values, duplicate covered-component-identifier detection, `getComponentIdentifiers()`/`getParameters()` returning copies, newline/non-ASCII rejection in the assembled signature base, custom `Signature-Input` parameter SFV-type round-tripping, and uppercase field identifiers being rejected when parsed from untrusted input.

Given the example message fragment from §2.1:

```
Host: www.example.com
Date: Tue, 20 Apr 2021 02:07:56 GMT
X-OWS-Header:   Leading and trailing whitespace.
X-Obs-Fold-Header: Obsolete
    line folding.
Cache-Control: max-age=60
Cache-Control:    must-revalidate
Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)
```

| Component identifier | Canonicalized value |
| --- | --- |
| `"host"` | `www.example.com` |
| `"date"` | `Tue, 20 Apr 2021 02:07:56 GMT` |
| `"x-ows-header"` | `Leading and trailing whitespace.` |
| `"x-obs-fold-header"` | `Obsolete line folding.` |
| `"cache-control"` | `max-age=60, must-revalidate` |
| `"example-dict"` | `a=1,    b=2;x=1;y=2,   c=(a   b   c)` |

**Empty fields** (§2.1): a field present with an empty value (`X-Empty-Header:` with nothing after it) canonicalizes to the empty string `""` — distinct from an absent field, which canonicalizes to no value at all (and, if covered, must fail signature base generation).

**Strict Structured Field serialization — `;sf`** (§2.1.1), given `Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)`:

| Component identifier | Canonicalized value |
| --- | --- |
| `"example-dict";sf` | `a=1, b=2;x=1;y=2, c=(a b c)` |

**Dictionary member selection — `;key`** (§2.1.2), given `Example-Dict:  a=1, b=2;x=1;y=2, c=(a   b    c), d`:

| Component identifier | Canonicalized value |
| --- | --- |
| `"example-dict";key="a"` | `1` |
| `"example-dict";key="d"` | `?1` |
| `"example-dict";key="b"` | `2;x=1;y=2` |
| `"example-dict";key="c"` | `(a b c)` |
| `"example-dict";key="<missing>"` | **MUST error** — the dictionary key does not occur in the field |

**Binary-wrapped fields — `;bs`** (§2.1.3): given a field sent as two separate instances vs. one instance with an equivalent comma-joined value —

```
Example-Header: value, with, lots
Example-Header: of, commas
```
```
Example-Header: value, with, lots, of, commas
```

— the *default* (no `;bs`) canonicalized value is identical for both (`value, with, lots, of, commas`), which is exactly the ambiguity `;bs` exists to resolve:

| Message | Component identifier | Canonicalized value |
| --- | --- | --- |
| two instances | `"example-header"` | `value, with, lots, of, commas` |
| two instances | `"example-header";bs` | `:dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:` |
| one instance | `"example-header"` | `value, with, lots, of, commas` |
| one instance | `"example-header";bs` | `:dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:` |

`;bs` is incompatible with `;sf`/`;key` (they require the parsed/combined value; `;bs` requires the raw per-instance bytes) — combining them is a malformed component identifier. All four of `;sf`/`;bs`/`;tr`/`;req` are Boolean-flag parameters (RFC 8941 §3.1.2: no `=value` defaults to `?1`); an explicit `;sf=?0` is treated the same as `;sf` being absent, and a non-Boolean value (e.g. `;bs=1`) is rejected as a malformed component identifier rather than silently treated as "enabled".

**Trailer fields — `;tr`** (§2.1.4): given a `200 OK` response with an `Expires` trailer field —

| Component identifier | Canonicalized value |
| --- | --- |
| `"@status"` | `200` |
| `"trailer"` | `Expires` |
| `"expires";tr` | `Wed, 9 Nov 2022 07:28:00 GMT` |

This library does not implement `;tr` (no trailer access in the `ComponentProvider` contract), so a covered `;tr` component always throws `UnsupportedComponentParameterError`.

## License

This project is licensed under the MIT License; see the `license` field in [oh-package.json5](oh-package.json5).
