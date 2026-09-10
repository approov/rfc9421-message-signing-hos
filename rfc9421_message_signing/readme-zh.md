# @approov/rfc9421-message-signing

[English](README.md) | 中文

仓库地址:[https://github.com/approov/rfc9421-signing-hos](https://github.com/approov/rfc9421-signing-hos)

[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)(RFC 9421 §2)中"消息组件"与"签名基串"部分的 ArkTS 实现:组件标识符(component identifier)、HTTP 字段规范化、`Signature-Input` 参数、以及签名基串的构建。本库本身不做签名/验签(不涉及密钥管理或加解密算法)——它产出的是签名方交给签名算法的、验签方重建后用于校验签名的那个精确字节串。

依赖 [@approov/rfc9651-sfv](https://github.com/approov/rfc8941-sfv-hos) 完成 Structured Field Values(RFC 8941/9651)的解析与序列化。

## 安装

```
ohpm install @approov/rfc9421-message-signing
```

关于如何搭建 OpenHarmony ohpm 环境,参见 [How to install an OpenHarmony ohpm package](https://gitee.com/openharmony-tpc/docs/blob/master/OpenHarmony_har_usage.md)。

## 使用

### 实现 `ComponentProvider`

`ComponentProvider` 是一个抽象类:针对每种传输层(例如某个 HTTP 客户端的请求/响应类型)实现一次,向签名基串构建器暴露 derived component(`@method`、`@path` 等)和 HTTP 字段。

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

  // 查询参数的*解码后*的值(RFC 9421 §2.2.8 第 1 步)。不要自己做百分号编码——
  // ComponentProvider 会在值到达签名基串之前替你完成(第 2 步),用的是精确的
  // "application/x-www-form-urlencoded" percent-encode 字符集。
  getQueryParam(name: string): string | null { /* ... */ return null; }

  getStatus(): string | null { return null; } // 仅响应需要
  hasBody(): boolean { /* ... */ return false; }

  hasField(name: string): boolean { /* ... */ return false; }

  // 字段默认的、按 RFC 9421 §2.1 合并后的值(未使用 ;sf/;key/;bs 时采用)。
  getField(name: string): string | null {
    return ComponentProvider.combineFieldValues(this.rawValuesOf(name));
  }

  // 字段每个实例的*原始*值(同名字段出现几次就有几个数组元素),仅供
  // ;bs(Byte Sequence)参数使用——参见下文"二进制封装字段"一节。
  getFieldValues(name: string): string[] | null {
    return this.rawValuesOf(name);
  }

  // 该字段是哪种 Structured Field(RFC 8941/9651)——仅供 ;sf(Structured Field 序列化)
  // 使用。如果不是 Structured Field,或者你的应用其实并不知道它的类型,就返回 null;
  // ComponentProvider 不会根据字段名自己去猜(见下文"Structured Field 类型"一节)。
  getFieldStructuredType(name: string): 'list' | 'dictionary' | 'item' | null {
    return name === 'example-dict' ? 'dictionary' : null;
  }
}
```

这里的每个访问方法——包括 derived component 的值、字段值和 `@query-param`——在到达签名基串之前都会经过 `ComponentProvider` 的校验:derived 值必须是可打印 ASCII/空格,且首尾不能有空白(RFC 9421 §2.2);字段值必须是 HTAB/SP/可打印 ASCII,且首尾不能有空白(RFC 9421 §2.5);每个值都会被检查是否含有换行符(在 `SignatureBaseBuilder` 中,对应 RFC 9421 §2),防止行为异常的 provider 借此注入额外的签名基串行。

### Structured Field 类型

某个 HTTP 字段是不是 Structured Field、以及是哪一种(List/Dictionary/Item),**不是** `ComponentProvider` 根据字段名去推断出来的。RFC 9421 §2.1.1 明确写了这是应用相关的知识("If the application does not know the type of the field ... the use of this flag will produce an error"),而且哪些字段被注册为 Structured Field 是记录在一个外部、持续演进的 IANA 注册表里的——不是能安全硬编码进这个库里的东西。`getFieldStructuredType()` 就是让你的 provider 来声明这件事;对于它返回 `null` 的字段用 `;sf`,一律抛出 `ComponentValueError`。

### 构建签名基串

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
// base 就是要传给签名算法的那个精确字符串。
```

`addComponentIdentifier()` 对纯字符串形式的字段名会自动转小写,这是一个便利处理;但会拒绝以下两种情况:
- 传入的 component identifier 已经被覆盖过——RFC 9421 §2 要求每个被覆盖的 component identifier 只能出现一次(参数顺序不影响这个判断);
- `'@signature-params'`——RFC 9421 §2.3 要求它永远不能被列为被覆盖的 component(它始终是由 `SignatureBaseBuilder` 自动生成的结尾行)。

### 从 `Signature-Input` 头重建参数

```typescript
import { parseDictionary } from '@approov/rfc9651-sfv';
import { SignatureParameters } from '@approov/rfc9421-message-signing';

const dict = parseDictionary(signatureInputHeaderValue);
const params = SignatureParameters.fromDictionaryEntry(dict, 'sig1');
```

和 `addComponentIdentifier()` 的纯字符串重载不同,这里解析时遇到大写的字段 component 名称会直接拒绝(而不是规范化处理)——`Signature-Input` 头是不可信输入,其中出现大写字段名本身就不符合 RFC 9421 §2.1,不应该被本库静默"修正"。

### 查询参数编码

`getQueryParam()` 返回的是*解码后*的参数值;`ComponentProvider` 会替你做百分号编码(RFC 9421 §2.2.8 第 2 步),用的是精确的 "application/x-www-form-urlencoded" percent-encode 字符集——而不是 `encodeURIComponent()`(它会把 `!'()*~` 都留成不转义,对含有这些字符的值,和另一个 RFC 9421 实现的输出会逐字节对不上):

```typescript
// 假设请求是 /search?q=caf%C3%A9%20%26%20cr%C3%A8me,大多数 URL 实现解析出来的
// search params 已经是解码好的 "café & crème",对 `q` 直接原样返回即可:
getQueryParam(name: string): string | null {
  return this.url.searchParams.get(name); // 大多数 URL 实现已经帮你解码好了
}
```

```typescript
import { StringItem, SfvParameters } from '@approov/rfc9651-sfv';

const provider = new MyRequestComponentProvider(request); // q -> "café & crème"
const id = StringItem.valueOf('@query-param').withParams(SfvParameters.EMPTY.add('name', 'q'));
provider.getComponentValue(id); // "caf%C3%A9%20%26%20cr%C3%A8me" —— 空格和 & 都被重新编码,而不是留成 "+"/"&"
```

如果你的传输层只给你还没解码的原始查询字符串,那就自己先解码好再返回(例如
`decodeURIComponent(raw.replace(/\+/g, ' '))`,这也正是本库内部解码 `;name` 参数值时用的方式)——不要直接返回编码后的形式。

### 错误处理

本库抛出的所有错误都继承自 `SignatureError`,且每个子类都可以包装一个底层原因(会采用该原因的 message/name/stack):

```typescript
import { SignatureError, ComponentValueError } from '@approov/rfc9421-message-signing';

try {
  builder.createSignatureBase();
} catch (e) {
  if (e instanceof ComponentValueError) {
    // 某个被签名字段/字典 key 缺失或不合法
  } else if (e instanceof SignatureError) {
    // 其他任何签名基串构建错误
  }
}
```

| 错误类型 | 触发场景 |
| --- | --- |
| `SignatureError` | 本库所有错误的基类 |
| `MalformedComponentIdentifierError` | component identifier 或其参数语法不合法:`;name`/`;key` 缺失或类型错误、出现未知或不适用的参数(如给 `@method` 加 `;sf`)、Boolean 类型参数传了非 Boolean 值(如 `;sf="yes"`)、`;bs` 与 `;sf`/`;key` 这类互斥的参数组合、把 `'@signature-params'` 当作被覆盖的 component、被覆盖的 component identifier 重复,或者(解析不可信输入时)字段名出现大写 |
| `UnknownComponentError` | component identifier 指向一个无法识别的 derived component(例如 `@bogus`) |
| `UnsupportedComponentParameterError` | component identifier 使用了本 provider 未实现的参数(`;tr`、`;req`) |
| `ComponentValueError` | 字段或 derived component 的值不满足其 identifier 的要求:不是 dictionary/structured field、Structured Field 类型未知(`getFieldStructuredType()` 返回了 `null`)、字典 key 不存在、derived component 的值超出可打印 ASCII/空格范围,或字段值超出 HTAB/SP/可打印 ASCII 范围(两者都包括首尾带空白的情况)(RFC 9421 §2.2/§2.5),或者某个 component 值含换行符/拼装出的整个签名基串含非 ASCII 字符(RFC 9421 §2.5) |
| `MissingComponentValueError` | 因某个必需 component 取不到值,签名基串无法构建 |
| `MalformedSignatureInputError` | `Signature-Input` 字典条目本身不合法 |

## API

| 类型 | 说明 |
| --- | --- |
| `ComponentProvider` | 抽象基类:实现后即可暴露 derived component 和 HTTP 字段;通过 `getComponentValue()` 按 component identifier 分发 |
| `SignatureParameters` | 被签名 component 列表 + 签名参数(`alg`、`created`、`expires`、`keyid`、`nonce`、`tag`、自定义参数);可与 `@signature-params`(`Signature-Input` 条目)互相序列化/反序列化 |
| `SignatureBaseBuilder` | 将 `SignatureParameters` 与 `ComponentProvider` 组合成最终的签名基串字符串(RFC 9421 §2.5) |
| `SignatureError` 及其子类 | 类型化错误——见上表 |

## 限制与约束

- 使用 ArkTS 编写,用于 HarmonyOS/OpenHarmony Stage 模型工程。
- 只构建/解析签名相关的*数据*——不包含密钥管理、签名或验签逻辑。
- 未实现 `;tr`(trailer 字段)和 `;req`(请求-响应绑定,字段和 derived component 上都不支持);使用这两个参数的 component identifier 一律抛出 `UnsupportedComponentParameterError`,而不会静默产出一个错误的值。
- `ComponentProvider` 没有"目标消息是请求还是响应"这个概念,所以没法自己去强制那些依赖这个信息的规则(比如"请求签名不能覆盖 `@status`")——基于本库构建应用的一方需要自己去做这层校验。
- `getFieldValues()`(供 `;bs` 使用)返回的是 `string[]`;如果字段值本身就不是合法的 UTF-8,这个接口没法无损地把它带过去。对 ASCII/UTF-8 字段值(常见情形)是够用的,但不是 RFC 9421 §2.1.3 里"任意二进制字段内容"那部分的完整实现。

## 测试

[`HttpFieldsRfc9421.test.ets`](src/ohosTest/ets/test/HttpFieldsRfc9421.test.ets) 把 [RFC 9421 §2.1 "HTTP Fields"](https://www.rfc-editor.org/rfc/rfc9421.html#http-fields)(含其 §2.1.1–§2.1.4 子节)里的每一个 worked example 都转成了针对一个 fixture `ComponentProvider` 的可运行测试用例。下表是同一批例子,方便不查 RFC 原文也能直接参考。

[`ComplianceValidation.test.ets`](src/ohosTest/ets/test/ComplianceValidation.test.ets) 覆盖了 §2.1 worked example 之外本库校验/强制执行的其他所有规则:拒绝未知/不适用的 component 参数、Boolean 类型参数的类型校验和 `?0` 处理、`@query-param` 对 `;name` 的 form-urlencoded 解码以及对返回值的重新编码(含 RFC 9421 §2.2.8 自身的 worked example,以及一条专门把精确 percent-encode 字符集和 `encodeURIComponent()` 那套不同字符集钉死区分开的回归测试)、拒绝不合法的 derived/字段 component 值、重复 covered-component-identifier 检测、`getComponentIdentifiers()`/`getParameters()` 返回副本、签名基串里换行符/非 ASCII 字符的拒绝、自定义 `Signature-Input` 参数的 SFV 类型往返保真,以及从不可信输入解析时大写字段标识符被拒绝。

给定 §2.1 中的示例消息片段:

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

| Component identifier | 规范化后的值 |
| --- | --- |
| `"host"` | `www.example.com` |
| `"date"` | `Tue, 20 Apr 2021 02:07:56 GMT` |
| `"x-ows-header"` | `Leading and trailing whitespace.` |
| `"x-obs-fold-header"` | `Obsolete line folding.` |
| `"cache-control"` | `max-age=60, must-revalidate` |
| `"example-dict"` | `a=1,    b=2;x=1;y=2,   c=(a   b   c)` |

**空字段**(§2.1):字段存在但值为空(如 `X-Empty-Header:` 后面什么都没有)时,规范化值是空字符串 `""`——这和"字段根本不存在"是两回事,后者规范化后没有任何值(如果该字段被覆盖签名,必须导致签名基串构建失败)。

**Structured Field 的严格序列化 —— `;sf`**(§2.1.1),给定 `Example-Dict:  a=1,    b=2;x=1;y=2,   c=(a   b   c)`:

| Component identifier | 规范化后的值 |
| --- | --- |
| `"example-dict";sf` | `a=1, b=2;x=1;y=2, c=(a b c)` |

**Dictionary 成员选取 —— `;key`**(§2.1.2),给定 `Example-Dict:  a=1, b=2;x=1;y=2, c=(a   b    c), d`:

| Component identifier | 规范化后的值 |
| --- | --- |
| `"example-dict";key="a"` | `1` |
| `"example-dict";key="d"` | `?1` |
| `"example-dict";key="b"` | `2;x=1;y=2` |
| `"example-dict";key="c"` | `(a b c)` |
| `"example-dict";key="<不存在的 key>"` | **必须报错** —— 该 key 在字典中不存在 |

**二进制封装字段 —— `;bs`**(§2.1.3):同一个字段分别以"两个独立实例"和"一个带逗号的单实例"两种方式发送——

```
Example-Header: value, with, lots
Example-Header: of, commas
```
```
Example-Header: value, with, lots, of, commas
```

—— 默认(不带 `;bs`)情况下两者的规范化值完全相同(都是 `value, with, lots, of, commas`),而这正是 `;bs` 存在的意义——用来消除这种歧义:

| 消息 | Component identifier | 规范化后的值 |
| --- | --- | --- |
| 两个实例 | `"example-header"` | `value, with, lots, of, commas` |
| 两个实例 | `"example-header";bs` | `:dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:` |
| 单个实例 | `"example-header"` | `value, with, lots, of, commas` |
| 单个实例 | `"example-header";bs` | `:dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:` |

`;bs` 与 `;sf`/`;key` 互斥(它们需要解析/合并后的值,而 `;bs` 需要每个实例的原始字节)——两者组合属于 malformed component identifier。`;sf`/`;bs`/`;tr`/`;req` 这四个都是 Boolean 类型的标志参数(RFC 8941 §3.1.2:不带 `=value` 时默认值为 `?1`);显式写 `;sf=?0` 会被当作和 `;sf` 缺失一样处理,而非 Boolean 的值(如 `;bs=1`)会被当作 malformed component identifier 拒绝,而不是被静默当成"已启用"。

**Trailer 字段 —— `;tr`**(§2.1.4):给定一个带 `Expires` trailer 字段的 `200 OK` 响应——

| Component identifier | 规范化后的值 |
| --- | --- |
| `"@status"` | `200` |
| `"trailer"` | `Expires` |
| `"expires";tr` | `Wed, 9 Nov 2022 07:28:00 GMT` |

本库未实现 `;tr`(`ComponentProvider` 契约中没有 trailer 访问能力),因此覆盖了 `;tr` 的 component 一律抛出 `UnsupportedComponentParameterError`。

## 许可证

本项目基于 MIT 许可证发布;详见 [oh-package.json5](oh-package.json5) 中的 `license` 字段。
