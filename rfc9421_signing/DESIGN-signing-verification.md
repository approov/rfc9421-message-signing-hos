# Design: Signing, Verification, Algorithms, Signature/Signature-Input Headers, Accept-Signature

Status: **proposal, not implemented.** Covers RFC 9421 §3 (signing/verification/algorithms),
§4 (`Signature`/`Signature-Input` headers, §4.3 multiple signatures), §5 (`Accept-Signature`).
Builds on the existing `ComponentProvider` / `SignatureParameters` / `SignatureBaseBuilder` /
`errors.ets`, which already implement §2 (signature base construction) and are unchanged by
this design.

Decisions already made (per discussion):
- Crypto backend: HarmonyOS `@kit.CryptoArchitectureKit` (`cryptoFramework`), no other backend.
- Key lookup: **not** bundled in this library — callers supply a callback. This library only
  defines the callback's shape (`KeyResolver`), matching the existing `ComponentProvider`
  pattern of "abstract contract, caller supplies the concrete adapter".

## 1. New files

```
src/main/ets/
  algorithm/
    Algorithm.ets          # alg-id <-> cryptoFramework mapping, HTTP_SIGN/HTTP_VERIFY
  SignatureHeaders.ets      # Signature / Signature-Input Dictionary <-> {label -> entry} codec
  MessageSigner.ets         # signMessage() — §3.1, §4
  MessageVerifier.ets       # verifyMessage() — §3.2, §3.2.1, §4.3
  AcceptSignature.ets       # Accept-Signature parsing + fulfillment — §5
  errors.ets                 # extended with the new error types below (existing file)
```

Each stays a thin, single-purpose file, consistent with how `ComponentProvider` /
`SignatureBaseBuilder` / `SignatureParameters` are currently split.

## 2. §3.3 Algorithms — `Algorithm.ets`

RFC 9421 defines `HTTP_SIGN(M, Ks) -> S` and `HTTP_VERIFY(M, Kv, S) -> V` per algorithm. This
maps directly onto `cryptoFramework.createSign(algName)` / `createVerify(algName)` /
`createMac(algName)`, one adapter per registry `alg` value:

| RFC 9421 `alg` value | RFC section | `cryptoFramework` algName | Notes |
| --- | --- | --- | --- |
| `rsa-pss-sha512` | §3.3.1 | `"RSA_PSS\|SHA512"` (`RSA2048\|3072\|4096`) | MGF1-SHA512, salt length 64 — must be set via `RsaPssParamsSpec` at `init()`/`sign()` |
| `rsa-v1_5-sha256` | §3.3.2 | `"RSA...\|PKCS1\|SHA256"` | Deterministic |
| `hmac-sha256` | §3.3.3 | `createMac("HMAC\|SHA256")`, not `createSign`/`createVerify` | Verification = bytewise compare of two MACs, not a `Verify` call |
| `ecdsa-p256-sha256` | §3.3.4 | `"ECC256\|SHA256"` | **Raw r\|\|s (64 bytes), not DER.** `cryptoFramework`'s ECC sign output is DER by default — must post-process with `cryptoFramework.EccSignatureSpec`/`genEccSignature`(sign)/`genEccSignatureSpec`(verify) to convert DER<->fixed-width r\|\|s, per §3.3.4's explicit encoding requirement |
| `ecdsa-p384-sha384` | §3.3.5 | `"ECC384\|SHA384"` | Same DER<->raw r\|\|s conversion, 48-byte r/s (96 bytes total) |
| `ed25519` | §3.3.6 | `"Ed25519"` | No prehash; signature base is the direct input |

`rsa-v1_5-sha1` (cavage-era legacy, in the Node package for backcompat) and JWS algorithms
(§3.3.7) are **out of scope** for this design — no known HOS caller needs them; can be added
the same way later if needed.

```typescript
export interface Algorithm {
  readonly id: string;                 // the registry value, e.g. "ecdsa-p256-sha256"
  sign(base: Uint8Array, key: cryptoFramework.PriKey): Promise<Uint8Array>;
  verify(base: Uint8Array, signature: Uint8Array, key: cryptoFramework.PubKey): Promise<boolean>;
}

export function getAlgorithm(id: string): Algorithm; // throws UnsupportedAlgorithmError if unknown
```

Each concrete `Algorithm` wraps the `init()`/`update()`/`sign()`/`verify()` HUKS-style
lifecycle already used elsewhere in this codebase (see `ApproovDefaultMessageSigning.ets` in
the sibling `nethttp` project for the existing HOS crypto call pattern to reuse/mirror).

## 3. §3.1 + §4 Signing — `MessageSigner.ets`

```typescript
export interface Signer {
  /** RFC 9421 §2.3 alg value, e.g. "ecdsa-p256-sha256". Determines the Algorithm used. */
  readonly alg: string;
  /** RFC 9421 §2.3 keyid value to embed in Signature-Input, if the caller wants it embedded. */
  readonly keyid?: string;
  readonly key: cryptoFramework.PriKey;
}

export interface SignOptions {
  label?: string;              // defaults to "sig1", or next free "sigN" (§4.3)
  created?: Date | null;       // null = omit; default = now
  expires?: Date | null;       // default = omit unless caller sets one
  nonce?: string;
  tag?: string;
  customParams?: Map<string, SfvItemInput>;
}

export interface SignedHeaders {
  signatureInput: string;  // full Signature-Input field value (possibly multi-label, §4.3)
  signature: string;       // full Signature field value (possibly multi-label, §4.3)
}

/**
 * Builds the signature base (reusing SignatureBaseBuilder), signs it with `signer`, and
 * returns Signature/Signature-Input field values — merged with any pre-existing values the
 * caller passes in via `existing`, so calling this repeatedly on the same message adds
 * additional labeled signatures rather than overwriting (RFC 9421 §4.3).
 */
export async function signMessage(
  params: SignatureParameters,
  provider: ComponentProvider,
  signer: Signer,
  options?: SignOptions,
  existing?: SignedHeaders,
): Promise<SignedHeaders>;
```

Behavior:
- `options.label` uniqueness against `existing`: if omitted, auto-picks `sig1`, `sig2`, ... —
  mirrors the Node package's `augmentHeaders` label-collision handling.
- `created`/`keyid`/`alg` etc. are set on a **clone** of `params` (via the existing
  `SignatureParameters` copy constructor) so the caller's `params` object isn't mutated as a
  side effect — this differs from today's `SignatureParameters` methods, which mutate `this`;
  worth confirming that's the intended ergonomics before implementing.
- Uses the existing `SignatureBaseBuilder` unchanged for the base string.
- Serializing the merged `Signature-Input`/`Signature` Dictionaries reuses
  `@approov/rfc8941_sfv`'s `Dictionary`/`ByteSequenceItem`, matching how `SignatureParameters`
  already builds its `InnerList`.

## 4. §3.2 + §3.2.1 + §4.3 Verification — `MessageVerifier.ets`

```typescript
export interface KeyResolver {
  /** Resolve verification key material + the algorithm to use, given the signature's
   *  parsed parameters (keyid, alg, ...). Return null/throw UnknownKeyError if untrusted. */
  resolve(sigParams: SignatureParameters, label: string): Promise<ResolvedKey>;
}
export interface ResolvedKey {
  key: cryptoFramework.PubKey;
  alg: string;   // resolved algorithm id — see §3.2 step 6 reconciliation below
}

export interface VerificationPolicy {
  /** §3.2.1: component identifiers that MUST be covered (name-only or full identifier). */
  requiredComponents?: string[];
  /** §3.2.1: reject if `created` is missing. */
  requireCreated?: boolean;
  /** §3.2.1: max signature age in seconds from `created`, evaluated against "now". */
  maxAge?: number;
  /** §3.2.1: reject once `now > expires` (expires is only a hint per spec, but most apps enforce it). */
  enforceExpires?: boolean;
  /** Clock-skew tolerance in seconds applied to maxAge/expires checks. */
  clockToleranceSeconds?: number;
  /** §3.2 step 6.1: algorithms this application is willing to accept at all. */
  allowedAlgorithms?: string[];
  /** §3.2.1: required application-specific tag value. */
  requiredTag?: string;
  /** §2.5/malformed-input guards already enforced unconditionally by SignatureParameters/
   *  ComponentProvider — not repeated here. */
}

export interface VerifyOptions {
  /** §3.2 step 1.1: which label to verify when multiple signatures are present.
   *  Defaults to "verify every label present, all must pass" if omitted. */
  label?: string;
  policy?: VerificationPolicy;
}

/**
 * §3.2 steps 1-9. Parses Signature/Signature-Input, reconstructs each signature base via
 * the existing SignatureBaseBuilder/ComponentProvider, resolves keys via `keys`, and
 * verifies. Throws a SignatureError subclass (see §6 below) on any failure — RFC 9421 §3.2
 * "If any of the above steps fail or produce an error, the signature validation fails" (no
 * partial-success return value).
 */
export async function verifyMessage(
  signatureInputHeader: string,
  signatureHeader: string,
  provider: ComponentProvider,
  keys: KeyResolver,
  options?: VerifyOptions,
): Promise<void>;
```

Step-by-step mapping to RFC 9421 §3.2:

| RFC step | Implementation |
| --- | --- |
| 1, 1.1, 1.2 | Parse both headers as `Dictionary` (`@approov/rfc8941_sfv`); label-set mismatch (present in one but not the other) → `MalformedSignatureError`. `options.label` (or "all labels") selects which to process. |
| 2 | `SignatureParameters.fromDictionaryEntry()` — already implemented. |
| 3 | Extract the `ByteSequenceItem` value from the `Signature` Dictionary entry for the label. |
| 4 | Apply `VerificationPolicy` (see below). |
| 5 | `keys.resolve(sigParams, label)` → `UnknownKeyError` if it throws/returns null. |
| 6 | Algorithm reconciliation (see below) → `UnsupportedAlgorithmError` if not in `allowedAlgorithms`, or steps 6.5 conflict. |
| 7 | `SignatureBaseBuilder(sigParams, provider).createSignatureBase()` — already implemented, unchanged. Per RFC, the `@signature-params` line must reuse the *exact* Signature-Input field value's serialization, not a re-derived one — needs the raw parsed `InnerList`'s `.serialize()`, not a round-tripped reconstruction, to guarantee byte-for-byte fidelity (this is exactly why the `fromDictionaryEntry` round-trip-fidelity fix from this session — preserving `ItemType` for custom params — matters here). |
| 8, 9 | `Algorithm.verify(base, signature, resolvedKey)` → `VerificationError` (or subclass) on `false`/exception. |

§3.2 step 6 (algorithm reconciliation) as a small helper:
```typescript
function resolveAlgorithm(sigParams: SignatureParameters, resolved: ResolvedKey, policy?: VerificationPolicy): string {
  // 6.1 allowed-set check, 6.4 alg param, 6.5 conflict-detection between resolved.alg and
  // sigParams.getAlg() (only compared if both present — this library doesn't attempt 6.3
  // "determine from key material" since HOS PubKey doesn't expose an alg field generically).
}
```

§3.2.1 (`VerificationPolicy`) enforcement happens as one pass over `sigParams` before any
crypto runs (fail fast, matches "MUST fail immediately" framing used elsewhere in the RFC).

## 5. §4.3 Multiple signatures

No separate code path needed beyond what's above:
- **Signing**: `signMessage()`'s `existing` parameter + label auto-selection (§3 above) is
  exactly the mechanism — call it once per signature to add (client sig, then proxy sig, ...).
- **Verifying**: `verifyMessage()` parses the full label set every time; `options.label`
  lets a caller verify one specific signature (e.g. "just the proxy's `proxy_sig`") without
  requiring every other label present to also verify — matches §3.2 step 1.1 ("determine
  which signature should be processed... based on policy").

## 6. §5 `Accept-Signature` — `AcceptSignature.ets`

```typescript
export interface AcceptSignatureRequest {
  label: string;
  sigParams: SignatureParameters;  // covered components + requested metadata params (§5.1)
}

/** §5.1: parses the Accept-Signature Dictionary field value. */
export function parseAcceptSignature(headerValue: string): AcceptSignatureRequest[];

/**
 * §5.2 steps 2.3-2.7: validates each request's covered components against the target
 * message type (e.g. rejects @status in an Accept-Signature destined for a request), fills
 * in requested-but-unspecified metadata (created/expires per §5.1's "no associated value"
 * flag, nonce/alg/keyid), and produces the SignedHeaders for that label via signMessage().
 * Per §5.2 final paragraph: "MUST have the same label, MUST include the same set of covered
 * components, MUST process all requested parameters, and MAY have additional parameters."
 */
export async function fulfillAcceptSignature(
  requests: AcceptSignatureRequest[],
  provider: ComponentProvider,
  isResponseTarget: boolean,   // for the "@status only valid in a response" check (§5)
  signerFor: (req: AcceptSignatureRequest) => Signer | null,  // null = "ignore this request" (§5.2 allows this)
): Promise<SignedHeaders>;
```

This is the one part of this design with no Node-package precedent (Node's
`http-message-signatures` doesn't implement `Accept-Signature` at all) — API shape above is
my own proposal from reading §5/§5.2 directly and should get extra scrutiny before
implementation.

**Known gap carried over from the existing `ComponentProvider`:** §5's own text ("if the
target message is a request, the covered components cannot include the @status component
identifier") is exactly the message-type-awareness gap already flagged and accepted as
out-of-scope in this session's earlier review. `fulfillAcceptSignature`'s `isResponseTarget`
boolean is the minimum surface needed to implement *this one* check without a larger
`ComponentProvider` redesign — worth confirming that's an acceptable scope boundary.

## 7. New error types (extending `errors.ets`)

Mirrors `http-message-signatures`' `VerificationError` hierarchy, layered under the existing
`SignatureError` base rather than introducing a second hierarchy:

```
SignatureError (existing)
├── ... (existing 6 subclasses, unchanged)
└── VerificationError            # new base for everything below
    ├── MalformedSignatureError  # label mismatch, unparseable Signature/Signature-Input
    ├── ExpiredError             # maxAge/expires policy violation
    ├── UnacceptableSignatureError  # policy violation: missing required component/tag/created
    ├── UnknownKeyError          # KeyResolver couldn't resolve/trust the key
    └── UnsupportedAlgorithmError   # alg not in allowedAlgorithms, or §3.2 step 6.5 conflict
```

Plus one signing-side error:
```
SignatureError
└── UnsupportedAlgorithmError (reused)  # getAlgorithm(id) for an unregistered alg id
```

## 8. Testing plan

RFC 9421 Appendix B ("Examples") ships full worked signing/verification test vectors with
real key material (`test-key-rsa-pss`, `test-key-rsa`, `test-key-ecc-p256`,
`test-key-ed25519`) and expected signature-base + signature-output values for:
- §3.1's minimal example (RSA-PSS)
- §4.3's multi-signature (client + reverse-proxy) example (ECDSA P-256 + RSA v1.5)

These give byte-exact expected outputs and are the natural test suite for `MessageSigner`/
`MessageVerifier`/`Algorithm`, the same way this session's `HttpFieldsRfc9421.test.ets` used
§2.1's worked examples. `Accept-Signature` (§5) has no worked full-message example in the
RFC, only the field-value snippet quoted above — its tests would need to be hand-built
against `parseAcceptSignature`'s own output shape.

Not yet covered by this plan (flagging rather than silently omitting): RSA-PSS's
non-deterministic output means signing tests can only assert the signature *verifies*, not
that it matches Appendix B's literal bytes (the RFC says as much); ECDSA is likewise
non-deterministic. Only HMAC-SHA256 signing output is byte-reproducible against a fixed
input.

## 9. Open questions before implementation

1. `SignOptions`/verification: should `signMessage`/`verifyMessage` be free functions (as
   drafted) or methods on a class (e.g. `new MessageSigner(algorithm registry, ...)`), given
   this codebase's existing style is a mix of both (`SignatureBaseBuilder` is a class,
   `ComponentProvider.combineFieldValues` is a static)?
2. Confirm the mutating-vs-cloning question in §3 (does `signMessage` need to leave the
   caller's `SignatureParameters` untouched, or is in-place mutation fine, matching how
   `SignatureParameters`'s own setters already work)?
3. `cryptoFramework` key types (`PriKey`/`PubKey`) vs. raw key material (PEM/JWK) — does the
   caller always hand in an already-parsed HOS key object, or does this library need key
   import/parsing helpers too? (Leaning "caller's problem", consistent with "key lookup is a
   callback, not bundled" — but worth confirming explicitly, since it affects `Signer`/
   `KeyResolver`'s exact shape.)
