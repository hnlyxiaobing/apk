# apk · 设计契约（DESIGN.md）

> 2026-11-06 立约 ｜ 2026-11-09 更新（R4：签名摘要校验 / arsc 完整展开 / ELF ABI 交叉校验）
> 状态：**已实现**（ZIP 索引 / 签名结构与摘要校验 / 资源表完整展开 / 惰性解压均为真实实现），
> 门禁全绿（79/79，另有 5 个 `#skip` 不计入）。

## 1. 分层位置与职责

L1 逆向输入层的**容器/索引库**。职责：把 APK 字节流变成「ZIP 条目索引 + Android 专有结构定位 + 原始字节访问」。**不编排下游解析**（见 `DECISIONS.md` §1）。

## 2. 模块边界 / 依赖方向 / 数据流

```
APK Bytes ──► Apk::open ──► Apk(索引)
                 ├─ manifest()            -> ManifestRef{ raw: Bytes }   ──► 组合根 ──► axml::parse
                 ├─ dex_files()           -> Array[DexEntry{ bytes }]     ──► 组合根 ──► dex::parse
                 ├─ native_libs()         -> Array[NativeLib]
                 │    └─ NativeLib::elf_abi() -> Abi（ELF 头交叉校验）
                 ├─ resource_table()      -> ResourceTableRef?（轻量：全局字符串池）
                 ├─ resource_table_full() -> ResTable?（完整展开，apk 自有值类型）
                 ├─ signatures()          -> Array[SignatureInfo]（结构 + 摘要）
                 ├─ signature_checks()    -> Array[SignatureCheck]（逐项结论，验签恒 false）
                 └─ entry(name)           -> Bytes (惰性解压)
```

零跨模块 import。虚线数据流只经组合根，且与 `axml` / `dex` 无编译期关系。`apk` 不是中心节点。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `Apk { source, entries, signing_block_off }` | 纯值索引；`source` 保留原字节，条目惰性解压 |
| `ZipEntryRef` | 最小中央目录条目（含 `compression_method`、`is_aligned`） |
| `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef` | Blob Wire：名字 + 原始 `Bytes` |
| `SignatureInfo` | 方案摘要 + DER 证书原始字节 + `verified`（**结构 + 摘要级**，见 §5） |
| `SignatureCheck` | 逐项结构/摘要/算法/条目计数结论；`signature_verified` 恒 false |
| `ResTable` / `ResPackage` / `ResTypeSpec` / `ResTypeConfig` / `ResEntry` / `ResBag` / `ResValue` / `ResConfig` | arsc 完整展开的自有值类型（不 import axml） |
| `Abi` / `SignatureScheme` | ABI 与签名方案枚举（`Unknown(String)` 保留未知值） |
| `ContainerIndex` trait | `entry` / `entries` 只读索引契约 |
| `EntryName` | `String` 别名 |

## 4. 错误模型

`ApkError`：`UnexpectedEof(Int)`、`NotAZip(String)`、`BadCentralDirectory(Int, String)`、
`Zip64Unsupported(String)`、`EntryNotFound(String)`、`BadSigningBlock(Int, String)`、
`UnsupportedSignatureScheme(String)`、`BadAlignment(String, Int)`、
`BadResourceTable(Int, String)`（arsc 完整展开）、`BadElf(Int, String)`（ELF 头）。

全部 `raise ApkError`；`resource_table()` / `resource_table_full()` 返回 `Option`
（"无 arsc" 是正常结果，不是错误）。畸形输入只报错，不 panic。

## 5. 资源生命周期

全部纯值。`Apk::open` 不转移输入所有权；`Apk::entry` 惰性解压、不缓存解压结果。
**本模块没有 `close` / `detach`**：纯值无外部句柄，不存在释放或“二次释放”问题；同一 `Apk` 可被任意多次
查询/解压，重复调用不产生副作用（若未来引入句柄，必须满足“不会二次释放，重复调用返回明确错误”）。

## 6. 线程 / 并发边界

无可变全局状态；索引只读；`entry` 可并发调用（每次独立分配输出缓冲）。

## 7. 平台约束与外部依赖

- `preferred_target = "wasm"`（未改动），全后端。
- 实现期依赖 `bobzhang/zip@0.1.2`（仅 `deflate` 子包，见 `DECISIONS.md` §3）；不依赖 `axml` / `dex`。
- 事实约束：`zipalign` 必须先于 `apksigner`（属打包链，不在本库）；targetSdk 30+ 强制 v2+；签名块位于 Central Directory 之前，magic `"APK Sig Block 42"`。

## 8. 输入输出类型与错误传播（纯 MoonBit 库）

| 输入 | 输出 | 错误传播 |
|---|---|---|
| `Bytes`（完整 APK） | `Apk` 索引 | `NotAZip` / `BadCentralDirectory` / `Zip64Unsupported` |
| `Apk + EntryName` | `Bytes` | `EntryNotFound` |
| `Apk + Abi?` | `Array[NativeLib]` | 目录解析错误；`elf_abi` → `BadElf` |
| `Apk` | `Array[SignatureInfo]` / `Array[SignatureCheck]` | `BadSigningBlock`（`verified` 仅结构+摘要） |
| `Apk` | `ResTable?` | `BadResourceTable` / `UnexpectedEof` |
| `Bytes`（arsc） | `ResTable` | `BadResourceTable` / `UnexpectedEof` |

下游解析错误（`AxmlError` / `DexError`）**不会**穿过 `apk` 的 API 边界。

## 9. 可替换性与实现细节不泄漏

`ManifestRef.raw` / `DexEntry.bytes` 是 Blob Wire，上层可换成任意 AXML/DEX 解析器；`apk` 不返回 `AxmlDoc` / `DexFile`。ZIP 实现可换包而不改上层签名。

## 10. 测试策略

| 层次 | 内容 |
|---|---|---|
| 黑盒（L0 程序化 fixture） | 签名块魔数、ZIP64 拒绝、4 字节对齐、stored/deflate 条目、畸形中央目录；合成 v1 签名（DER/MANIFEST 现场构造）；合成 arsc（package/typeSpec/type/三种 offset 编码/compact/complex bag/坏结构）；合成 ELF（5 种 ABI + 坏 ELF） | ✅ |
| 黑盒（L1/L2 真实/受控样本） | 内嵌真实 `tvshell-debug.apk`（21208 B）与 `base.apk`（1179 B）及受控 `fx-multidex-*` 三变体；`aapt2 dump badging` + .NET `ZipFile` 中央目录规范化黄金 + `aapt2 dump resources` 资源表黄金 + `apksigner verify` 签名工具侧基准；期望值内嵌 `fixtures_test.mbt` / `arsc_test.mbt` | ✅ tvshell-debug、base、fx-multidex 三变体 |
| 畸形派生（`fixtures_malformed_test.mbt`） | 截断 / EOCD 签名污染 / 中央目录偏移污染 / 条目 CRC 污染 / 未知压缩方法 / 多 dex 截断与目录污染；断言报 `ApkError` 而非 panic | ✅ 6 例 |
| 白盒（`apk_wbtest.mbt`） | EOCD 定位、CRC-32、ABI/路径归类、SHA-256 NIST 向量 | ✅ |
| 门禁 | `moon fmt --check` / `moon check --deny-warn` / `moon build` / `moon test` / 快照 | ✅ 79/79 |

skip 机制：MoonBit 原生 `#skip` 属性（默认不计入 `Total tests`；`moon test --include-skipped` 才执行）。
许可不明/体积过大的样本用 `#skip` 显式标注，**绝不冒充通过**（当前 5 个 skip：phone/tv/partyr/L3/真实 .so 差分）。

## 11. 验收标准（实现阶段）

1. 真实 APK 的条目清单 / dex 数 / manifest·arsc 字节长 / ABI 与独立实现（.NET `ZipFile`、aapt2 `native-code`）一致 —— ✅（tvshell-debug、base）；
   manifest 语义字段（package/version/sdk/permissions/activity）按模块边界（`DECISIONS.md` §1）归 **axml 解析器**，其解析侧差分 ✅；
2. 畸形 APK / arsc / ELF 全部返回带偏移的 `ApkError` —— ✅（含真实样本派生的 6 例 + 合成错误路径）；
3. `--deny-warn` 转绿 —— ✅；
4. 签名「结构 + 摘要」校验与 `apksigner verify` 工具侧基准一致（v1+v2+v3、v1-only、v2+v3 三样本）—— ✅（`verified` 语义见 `DECISIONS.md` §5；**不是**签名有效）；
5. `resources.arsc` 完整展开与 `aapt2 dump resources` 逐值一致 —— ✅（fx-multidex 的 3 类型 + zh 配置；复杂 bag 由合成样本覆盖）；
6. 非空 `.so` 的 ABI/路径解析 —— ✅ 合成 ELF fixture；真实第三方 `.so` 差分 `[仍需实测]`。

## 12. 未解决问题 / 待验证假设

- `bobzhang/zip@0.1.2` 的 ZIP64 / 容错行为未完全验证 —— 五门槛审计已登记（见 `DECISIONS.md` §3，风险门槛为“登记不阻断”；aapt2 对齐填充类容器兼容性风险已实测登记并规避）。
- 签名**公钥验签**未实现（无 RSA/ECDSA/DSA）；`verified` 仅为结构+摘要。SHA-512 / verity 内容摘要未实现；v3.1 与多签名者真实样本未覆盖 —— `[仍需实测]`。
- 目标游戏 APK（phone/tv/partyr）许可不明、未入库 → 其容器解析侧差分 `[仍需实测]`。
- 真实第三方 `.so`（含压缩/多架构/错标 ABI）的解析侧差分未执行 —— `[仍需实测]`；合成 ELF 只覆盖结构路径。
- `apk` 与 `axml` 各有一份 arsc 解析器（`DECISIONS.md` §6），长期维护方式待主控裁决。

## 13. 当前状态与 TODO

`apk.mbt` / `arsc.mbt` / `signature.mbt` / `crypto.mbt` 已实现全部类型与公开函数（**无 `declare`、无 `0068`**），
公开 API 有 `///` 文档注释；字段 `method` 已改名 `compression_method`（避开保留字）。
`pub impl ContainerIndex for Apk` 为**冻结前追认**（API 冻结前的加法性变更，见 `API.md` 文首）。
R4 的加法性 API：`SignatureCheck` / `Apk::signature_checks` / `ResTable` 系列 / `parse_resources_arsc` /
`Apk::resource_table_full` / `NativeLib::elf_abi`；`ApkError` 追加 `BadResourceTable` / `BadElf` 两个变体。

## References

设计决策与依据见 `DECISIONS.md`；测试资产（来源 / 哈希 / 规范化口径）见 `tests/ASSETS.md`；
APK Signing Block 规范：`https://source.android.com/docs/security/features/apksigning/v2`。
