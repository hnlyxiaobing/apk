# apk · 公开 API（API.md）

> 与 `pkg.generated.mbti` 逐项对账（2026-11-07）。**全部函数为真实实现**，
> 包内**没有 `declare` 存根**；`moon check --deny-warn` 0 error / 0 warning（原 `0068` 警告已消除）。
> 错误传播统一 `raise ApkError`；只产出字节与索引，**不返回任何下游解析类型**。
>
> **依赖**：`bobzhang/zip@0.1.2`（Apache-2.0，仅用其 `deflate` 解压，`moon.mod` 已锁版）。
> 五门槛审计（用途/许可/平台/维护 4 项通过、0 不通过、1 项风险登记：单人维护、star=0、
> 低 bus factor，登记不阻断）见 `DECISIONS.md` §3。
>
> **API 冻结前追认**：`pub impl ContainerIndex for Apk`（`entry` / `entries`）
> —— 冻结评审后补入 `pkg.generated.mbti` 的**加法性**变更，不改动既有签名，语义与 `Apk::entry` /
> `Apk::entries` 完全一致；标注为**冻结前追认**，冻结后新增实现视为破坏性变更。

## 类型

| 类型 | 种类 | 说明 |
|---|---|---|
| `Apk` | `pub(all) struct` | `source : Bytes` + `entries` + `signing_block_off : UInt64?` |
| `ZipEntryRef` | `pub(all) struct` | name / sizes / crc32 / `compression_method` / offset / `is_aligned` |
| `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef` | `pub(all) struct` | Blob Wire：名字 + `Bytes` |
| `SignatureInfo` | `pub(all) struct` | `scheme` / `block_id` / `certificates` / `verified` |
| `Abi` / `SignatureScheme` | `pub(all) enum` | ArmeabiV7a / Arm64V8a / X86 / X86_64 / Unknown；V1/V2/V3/V31 |
| `ApkError` | `pub suberror` | 8 个错误构造 |
| `EntryName` | `pub type` | `String` 别名 |
| `ContainerIndex` | `pub trait` | `entry` / `entries` 契约；`pub impl ContainerIndex for Apk`（**冻结前追认**，见文首） |

## 函数签名

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Apk::open(source : Bytes) -> Apk raise ApkError` | `source` 只读、调用方持有；索引只引用不转移 | `Apk` 纯值 / `ApkError` | 无句柄；惰性解压；索引只读可并发 | EOCD / ZIP64 / 对齐 / 签名块定位 |
| `Apk::entries(self) -> Array[ZipEntryRef]` | `self` 只读 | 中央目录顺序条目 | 无状态 | — |
| `Apk::manifest(self) -> ManifestRef raise ApkError` | `self` 只读 | **原始 AXML 字节**（交组合根给 axml） / `EntryNotFound` | 不缓存解压结果 | 不解释 manifest 语义 |
| `Apk::dex_files(self) -> Array[DexEntry] raise ApkError` | `self` 只读 | `classes*.dex` 列表（按名排序） | 不解析 DEX | — |
| `Apk::native_libs(self, abi : Abi?) -> Array[NativeLib] raise ApkError` | `abi = None` 返回全部并各自标注 | `lib/<abi>/*.so` 列表 | 无状态 | 未知 ABI 归入 `Unknown(String)` |
| `Apk::signatures(self) -> Array[SignatureInfo] raise ApkError` | `self` 只读 | 只读方案摘要；`verified=false` | 不做密码学校验 | v1/v2/v3/v3.1 识别（已实现） |
| `Apk::resource_table(self) -> ResourceTableRef? raise ApkError` | `self` 只读 | `None` = 无 arsc；否则仅全局字符串池 | 无状态 | 完整 arsc 不在范围 |
| `Apk::entry(self, name : EntryName) -> Bytes raise ApkError` | `self` 只读 | 解压后原始字节 / `EntryNotFound` | 每次独立分配，可并发 | 压缩方法/CRC 校验 |

## 错误构造速查

`UnexpectedEof` · `NotAZip` · `BadCentralDirectory(offset, detail)` · `Zip64Unsupported` · `EntryNotFound(name)` · `BadSigningBlock(offset, detail)` · `UnsupportedSignatureScheme` · `BadAlignment(name, offset)`

## 非目标

反编译 / 反汇编 / manifest 语义 / 签名写入 / 打包 / 修改 ZIP / 证书链校验 / arsc 完整展开。

## 状态

| 门禁 | 结果 |
|---|---|
| `moon check --deny-warn` | ✅ 0 error / 0 warning（无 `0068`） |
| `moon build` | ✅ |
| `moon test` | ✅ 53 / 53（含真实/受控样本冒烟 2 例、黄金差分 10 例〔apkparse 5 + sig 5〕、畸形派生 6 例、多 dex/签名变体冒烟 2 例；另有 4 个 `#skip` 用例不计入） |
| `moon fmt --check` | ✅ |

黄金差分（开发期验证，黄金期望值已内嵌 `fixtures_test.mbt` 等测试代码，`moon test` 即回归）：
tvshell-debug 与 base 两样本**工具侧 + 解析侧全通（退出码 0）**；
phone-1.6.0 / tv-2.6.1 许可不明未入库，开发期仅做工具侧复核，解析侧以 `#skip` 显式跳过。
manifest 语义字段（package/version/sdk/permissions/activity）的解析侧差分由 **axml 解析器**承担
（容器层不解释 manifest 语义，见 `DECISIONS.md` §1）。
API 快照：`pkg.generated.mbti`（`moon info` 生成/更新）。
