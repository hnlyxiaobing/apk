# apk · 公开 API（API.md）

> 与 `../pkg.generated.mbti` 逐项对账（2026-11-09 R4）。**全部函数为真实实现**，
> 包内**没有 `declare` 存根**；`moon check --deny-warn` 0 error / 0 warning。
> 错误传播统一 `raise ApkError`；只产出字节、索引与 apk 自有值类型，**不返回任何下游解析类型**。
>
> **签名 `verified` 语义（必读）**：`true` = 签名结构解析通过 **且** 本地可验证摘要全部一致
> （v1 MANIFEST 条目摘要 + `.SF` 清单摘要；v2/v3/v3.1 APK 内容分块 SHA-256 摘要）。
> **它不代表签名有效**——本库无 RSA/ECDSA/DSA 公钥验签、无证书链校验；
> `Apk::signature_checks()` 的 `signature_verified` 恒为 `false`。详见 `DECISIONS.md` §5。
>
> **依赖**：`bobzhang/zip@0.1.2`（Apache-2.0，仅用其 `deflate` 解压，`../moon.mod` 已锁版）。
> 五门槛审计（用途/许可/平台/维护 4 项通过、0 不通过、1 项风险登记：单人维护、star=0、
> 低 bus factor，登记不阻断）见 `DECISIONS.md` §3。
>
> **API 冻结前追认**：`pub impl ContainerIndex for Apk`（`entry` / `entries`）
> —— 冻结评审后补入 `../pkg.generated.mbti` 的**加法性**变更，不改动既有签名，语义与 `Apk::entry` /
> `Apk::entries` 完全一致；标注为**冻结前追认**，冻结后新增实现视为破坏性变更。
>
> **R4 加法性新增**（冻结语义见 本仓库 API 冻结约定（既有签名变更即破坏性变更；加法性新增须同步 `pkg.generated.mbti` 快照、在 `docs/API.md` 登记并经 CI 快照门禁校验））：`SignatureCheck`、
> `Apk::signature_checks`、`ResTable` / `ResPackage` / `ResTypeSpec` / `ResTypeConfig` /
> `ResEntry` / `ResEntryValue` / `ResBag` / `ResMap` / `ResValue` / `ResConfig` / `ResDataType` /
> `ResLookup`、`parse_resources_arsc`、`Apk::resource_table_full`、`ResConfig::is_default`、
> `ResTable::{package_by_id, lookup, lookup_all, find_id}`、`NativeLib::elf_abi`；
> `ApkError` 追加 `BadResourceTable` / `BadElf`。既有签名零改动。

## 类型

| 类型 | 种类 | 说明 |
|---|---|---|
| `Apk` | `pub(all) struct` | `source : Bytes` + `entries` + `signing_block_off : UInt64?` |
| `ZipEntryRef` | `pub(all) struct` | name / sizes / crc32 / `compression_method` / offset / `is_aligned` |
| `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef` | `pub(all) struct` | Blob Wire：名字 + `Bytes` |
| `SignatureInfo` | `pub(all) struct` | `scheme` / `block_id` / `certificates` / `verified`（结构+摘要语义） |
| `SignatureCheck` | `pub(all) struct` | `structure_ok` / `digest_ok` / `digest_algorithm` / `entries_checked` / `entries_failed` / `signature_verified`(恒 false) / `detail` |
| `ResTable` / `ResPackage` / `ResTypeSpec` / `ResTypeConfig` | `pub(all) struct` | arsc 完整展开：全局池 / 包 / 类型 / 配置变体 |
| `ResEntry` / `ResEntryValue` / `ResBag` / `ResMap` / `ResValue` / `ResConfig` | `pub(all) struct`/`enum` | 条目（simple/compact/complex bag）、bag 映射、`Res_value`、配置 |
| `ResLookup` | `pub(all) struct` | 资源 id 查询命中（包/类型/条目/配置） |
| `ResDataType` | `pub(all) enum` | `Res_value.dataType` 全集；`Unknown(Int32)` 保留未知值 |
| `Abi` / `SignatureScheme` | `pub(all) enum` | ArmeabiV7a / Arm64V8a / X86 / X86_64 / Unknown；V1/V2/V3/V31 |
| `ApkError` | `pub suberror` | 10 个错误构造 |
| `EntryName` | `pub type` | `String` 别名 |
| `ContainerIndex` | `pub trait` | `entry` / `entries` 契约；`pub impl ContainerIndex for Apk`（**冻结前追认**） |

## 函数签名

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Apk::open(source : Bytes) -> Apk raise ApkError` | `source` 只读、调用方持有；索引只引用不转移 | `Apk` 纯值 / `ApkError` | 无句柄；惰性解压；索引只读可并发 | EOCD / ZIP64 / 对齐 / 签名块定位 |
| `Apk::entries(self) -> Array[ZipEntryRef]` | `self` 只读 | 中央目录顺序条目 | 无状态 | — |
| `Apk::manifest(self) -> ManifestRef raise ApkError` | `self` 只读 | **原始 AXML 字节**（交组合根给 axml） / `EntryNotFound` | 不缓存解压结果 | 不解释 manifest 语义 |
| `Apk::dex_files(self) -> Array[DexEntry] raise ApkError` | `self` 只读 | `classes*.dex` 列表（按名排序） | 不解析 DEX | — |
| `Apk::native_libs(self, abi : Abi?) -> Array[NativeLib] raise ApkError` | `abi = None` 返回全部并各自标注 | `lib/<abi>/*.so` 列表（ABI 取自目录名） | 无状态 | 内容侧交叉校验用 `NativeLib::elf_abi` |
| `NativeLib::elf_abi(self) -> Abi raise ApkError` | `self` 只读 | ELF 头 ABI（magic/class/data/`e_machine`） / `BadElf` | 无状态 | 不替代 `NativeLib.abi` |
| `Apk::signatures(self) -> Array[SignatureInfo] raise ApkError` | `self` 只读 | 结构 + 摘要校验；`verified` 语义见文首 | 不缓存 | 不做公钥验签 |
| `Apk::signature_checks(self) -> Array[SignatureCheck] raise ApkError` | `self` 只读 | 逐项结构/摘要结论 | 不缓存 | `signature_verified` 恒 false |
| `Apk::resource_table(self) -> ResourceTableRef? raise ApkError` | `self` 只读 | `None` = 无 arsc；否则轻量索引（全局字符串池） | 无状态 | 完整展开见下 |
| `Apk::resource_table_full(self) -> ResTable? raise ApkError` | `self` 只读 | 完整展开 / `BadResourceTable` / `UnexpectedEof` | 无状态 | package/type/bag 全量 |
| `parse_resources_arsc(data : Bytes) -> ResTable raise ApkError` | 只读，不转移所有权 | arsc 原始字节 → `ResTable` | 无状态 | 不依赖容器 |
| `ResConfig::is_default(self) -> Bool` | 只读 | qualifier 是否全零 | 无状态 | — |
| `ResTable::package_by_id(self, Int32) -> ResPackage?` | 只读 | 未命中 `None` | 无状态 | — |
| `ResTable::lookup(self, UInt32) -> ResLookup?` / `lookup_all` | 只读 | 默认配置优先 / 全部命中 | 无状态 | 不做 locale/density 最优匹配 |
| `ResTable::find_id(self, String, String) -> UInt32?` | 只读 | (类型名, 条目名) → id | 无状态 | 多包时取第一个 |
| `Apk::entry(self, name : EntryName) -> Bytes raise ApkError` | `self` 只读 | 解压后原始字节 / `EntryNotFound` | 每次独立分配，可并发 | 压缩方法/CRC 校验 |

## ELF 只读侦察（加法性新增）

> 本节登记 P2 阶段的**加法性新增**：`ElfClass` / `ElfSymbol` / `ElfInfo` 三个 `pub(all)`
> 值类型与 `NativeLib::elf_info` / `needed_libraries` / `jni_exports` 三个方法。既有公开签名
> 零改动；错误**复用** R4 已有的 `ApkError::BadElf(offset, detail)`，**不新增**错误构造。
> 快照见 `../pkg.generated.mbti`，归模块边界决策见 `DECISIONS.md` §8。

### 新增类型

| 类型 | 字段 | 含义 |
|---|---|---|
| `ElfClass` | `Elf32` / `Elf64` | 位宽，来自 `EI_CLASS`（1 / 2） |
| `ElfSymbol` | `name : String` / `defined : Bool` | 动态符号名；`defined = st_shndx != SHN_UNDEF(0)`（未定义即导入） |
| `ElfInfo` | 见下表 | `NativeLib::elf_info()` 的只读结构化结果，全为 `apk` 自有值类型与 `String` |

`ElfInfo` 字段含义：

| 字段 | 类型 | 含义 |
|---|---|---|
| `elf_class` | `ElfClass` | ELF 位宽 |
| `machine` | `Int32` | `e_machine`（原样整数，不做 ABI 归类） |
| `needed` | `Array[String]` | `DT_NEEDED` 依赖库名，按 dynamic 段顺序 |
| `dynamic_symbols` | `Array[ElfSymbol]` | 动态符号表，按 dynsym 顺序；名字不可用（空 / 非 UTF-8 / 截断 / 含控制字符）的条目跳过 |
| `jni_exports` | `Array[String]` | `dynamic_symbols` 中 `defined == true` 且名字以 `Java_` 开头者，按 dynsym 顺序 |
| `dart_markers` | `Array[String]` | 命中的预设 Dart AOT marker 名，**去重、按预设顺序**；仅字节模式命中 |

### 函数签名

| 签名 | 返回 / 错误 | 说明 |
|---|---|---|
| `NativeLib::elf_info(self) -> ElfInfo raise ApkError` | 结构化只读结果 / `BadElf(offset, detail)` | 只读 `self.bytes` 的 ELF 头、program headers 与 `PT_DYNAMIC`；无状态、可并发 |
| `NativeLib::needed_libraries(self) -> Array[String] raise ApkError` | `elf_info().needed` | 便利函数，内部委托 `elf_info()`，不重复解析 |
| `NativeLib::jni_exports(self) -> Array[String] raise ApkError` | `elf_info().jni_exports` | 便利函数，内部委托 `elf_info()`，不重复解析 |

### 边界（必须如实对外表述）

- **只读索引**：只解析容器条目自身的 ELF 元数据（头 / program headers / `DT_*` / 动态符号名），
  产出 `apk` 自有值类型，**不返回任何下游模块类型**（`axml` / `dex` 等），不编排下游解析。
- **不做**反汇编 / 符号执行 / 重定位展开 / ELF 装载；与 `NativeLib::elf_abi()` 同构，
  是「容器条目自身元数据」索引的加深，不使 `apk` 成为中心节点（见 `DECISIONS.md` §8）。
- **不做** Dart AOT 快照格式解析：`dart_markers` 只是对字节做一次线性扫描的**字节模式命中**
  （预设名去重、按预设顺序），对象图 / 指令表 / 快照版本语义 `[仍需实测]`，
  不得据命中项断言任何 Dart 语义。
- **错误模型**：越界 / 截断 / 坏 magic / 坏 `EI_CLASS` / `EI_DATA` / 缺 `PT_DYNAMIC` /
  虚拟地址未落在 `PT_LOAD` / 坏 `DT_STRTAB` / 坏 `DT_HASH` 一律 `ApkError::BadElf`，
  不 panic、不返回带部分结果的静默成功。

## 错误构造速查

`UnexpectedEof` · `NotAZip` · `BadCentralDirectory(offset, detail)` · `Zip64Unsupported` · `EntryNotFound(name)` · `BadSigningBlock(offset, detail)` · `UnsupportedSignatureScheme` · `BadAlignment(name, offset)` · `BadResourceTable(offset, detail)` · `BadElf(offset, detail)`

## 非目标

反编译 / 反汇编 / manifest 语义 / 签名写入 / 打包 / 修改 ZIP / **公钥验签与证书链校验** / arsc 值渲染、主题求值与 bag 压平。

## 状态

| 门禁 | 结果 |
|---|---|
| `moon check --deny-warn` | ✅ 0 error / 0 warning（无 `0068`） |
| `moon build` | ✅ |
| `moon test` | ✅ 84 / 84（含真实/受控样本冒烟、黄金差分、合成 v1 签名、合成 arsc、合成 ELF、畸形派生；另有 5 个 `#skip` 用例不计入） |
| `moon fmt --check` | ✅ |
| 快照门禁（`moon info` + `git diff --exit-code`） | ✅ |

黄金差分（开发期验证，黄金期望值已内嵌测试代码，`moon test` 即回归）：
tvshell-debug 与 base 两样本**工具侧 + 解析侧全通（退出码 0）**；
`resources.arsc` 完整展开以 `aapt2 dump resources` 为工具侧基准（fx-multidex 逐值一致）；
签名结构与摘要以 `apksigner verify` 为工具侧基准（tvshell v1+v2+v3、fx-multidex-v1、fx-multidex-v2v3）；
phone-1.6.0 / tv-2.6.1 许可不明未入库，开发期仅做工具侧复核，解析侧以 `#skip` 显式跳过。
manifest 语义字段（package/version/sdk/permissions/activity）的解析侧差分由 **axml 解析器**承担
（容器层不解释 manifest 语义，见 `DECISIONS.md` §1）。
API 快照：`../pkg.generated.mbti`（`moon info` 生成/更新）。
