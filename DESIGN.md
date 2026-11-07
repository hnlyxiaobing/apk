# apk · 设计契约（DESIGN.md）

> Round-1 / 2026-11-06 ｜ R2 冻结前整改更新 2026-11-07 ｜ 状态：**已实现**（ZIP 索引 / 签名块只读识别 / 惰性解压均为真实实现），门禁全绿（42/42）

## 1. 分层位置与职责

L1 逆向输入层的**容器/索引库**。职责：把 APK 字节流变成「ZIP 条目索引 + Android 专有结构定位 + 原始字节访问」。**不编排下游解析**（ADR-0003）。

## 2. 模块边界 / 依赖方向 / 数据流

```
APK Bytes ──► Apk::open ──► Apk(索引)
                 ├─ manifest()      -> ManifestRef{ raw: Bytes }   ──► 组合根 ──► axml::parse
                 ├─ dex_files()     -> Array[DexEntry{ bytes }]     ──► 组合根 ──► dex::parse
                 ├─ native_libs()   -> Array[NativeLib]
                 ├─ resource_table()-> ResourceTableRef?
                 ├─ signatures()    -> Array[SignatureInfo]
                 └─ entry(name)     -> Bytes (惰性解压)
```

零跨模块 import。虚线数据流只经组合根，且与 `axml` / `dex` 无编译期关系。`apk` 不是中心节点。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `Apk { source, entries, signing_block_off }` | 纯值索引；`source` 保留原字节，条目惰性解压 |
| `ZipEntryRef` | 最小中央目录条目（含 `compression_method`、`is_aligned`） |
| `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef` | Blob Wire：名字 + 原始 `Bytes` |
| `SignatureInfo` | 方案摘要 + DER 证书原始字节 + `verified` 标志 |
| `Abi` / `SignatureScheme` | ABI 与签名方案枚举（`Unknown(String)` 保留未知值） |
| `ContainerIndex` trait | `entry` / `entries` 只读索引契约 |
| `EntryName` | `String` 别名 |

## 4. 错误模型

`ApkError`：`UnexpectedEof(Int)`、`NotAZip(String)`、`BadCentralDirectory(Int, String)`、`Zip64Unsupported(String)`、`EntryNotFound(String)`、`BadSigningBlock(Int, String)`、`UnsupportedSignatureScheme(String)`、`BadAlignment(String, Int)`。

全部 `raise ApkError`；`resource_table()` 返回 `Option`（"无 arsc" 是正常结果，不是错误）。

## 5. 资源生命周期

全部纯值。`Apk::open` 不转移输入所有权；`Apk::entry` 惰性解压、不缓存解压结果。
**本模块没有 `close` / `detach`**：纯值无外部句柄，不存在释放或“二次释放”问题；同一 `Apk` 可被任意多次
查询/解压，重复调用不产生副作用（若未来引入句柄，必须满足“不会二次释放，重复调用返回明确错误”）。

## 6. 线程 / 并发边界

无可变全局状态；索引只读；`entry` 可并发调用（每次独立分配输出缓冲）。

## 7. 平台约束与外部依赖

- `preferred_target = "wasm"`（未改动），全后端。
- 后续实现期依赖 `bobzhang/zip@0.1.2`（本轮未引入）；不依赖 `axml` / `dex`。
- 事实约束：`zipalign` 必须先于 `apksigner`（属打包链，不在本库）；targetSdk 30+ 强制 v2+；签名块位于 Central Directory 之前，magic `"APK Sig Block 42"`。

## 8. 输入输出类型与错误传播（纯 MoonBit 库）

| 输入 | 输出 | 错误传播 |
|---|---|---|
| `Bytes`（完整 APK） | `Apk` 索引 | `NotAZip` / `BadCentralDirectory` / `Zip64Unsupported` |
| `Apk + EntryName` | `Bytes` | `EntryNotFound` |
| `Apk + Abi?` | `Array[NativeLib]` | 目录解析错误 |
| `Apk` | `Array[SignatureInfo]` | `BadSigningBlock`（`verified=false`） |

下游解析错误（`AxmlError` / `DexError`）**不会**穿过 `apk` 的 API 边界。

## 9. 可替换性与实现细节不泄漏

`ManifestRef.raw` / `DexEntry.bytes` 是 Blob Wire，上层可换成任意 AXML/DEX 解析器；`apk` 不返回 `AxmlDoc` / `DexFile`。ZIP 实现可换包而不改上层签名。

## 10. 测试策略

| 层次 | 内容 |
|---|---|---|
| 黑盒（L0 程序化 fixture） | 签名块魔数、ZIP64 拒绝、4 字节对齐、stored/deflate 条目、畸形中央目录 | ✅ 33 例 |
| 黑盒（L1/L2 真实样本，R2 WP-G 新增） | 内嵌真实 `tvshell-debug.apk`（21208 B）与 `base.apk`（1179 B）；`aapt2 dump badging` + .NET `ZipFile` 中央目录规范化黄金与 `@apk.Apk` 输出逐字段差分 | ✅ 两样本工具侧+解析侧全通（退出码 0） |
| 畸形派生（R2 新增 `fixtures_malformed_test.mbt`） | 从真实 APK 派生：截断 / EOCD 签名污染 / 中央目录偏移污染 / 条目 CRC 污染 / 未知压缩方法；断言报 `ApkError` 而非 panic | ✅ 5 例 |
| 白盒 | EOCD 定位、签名块魔数、ZIP64、4 字节对齐 | ✅ |
| 门禁 | `moon fmt --check` / `moon check --deny-warn` / `moon build` / `moon test` | ✅ 全绿 |

skip 机制：MoonBit 原生 `#skip` 属性（默认不计入 `Total tests`；`moon test --include-skipped` 才执行）。
许可不明/体积过大的样本用 `#skip` 显式标注，**绝不冒充通过**。

## 11. 验收标准（实现轮）

1. 真实 APK 的条目清单 / dex 数 / manifest·arsc 字节长 / ABI 与独立实现（.NET `ZipFile`、aapt2 `native-code`）一致 —— ✅（tvshell-debug、base）；
   manifest 语义字段（package/version/sdk/permissions/activity）按 ADR-0003 归 **axml 链**，其解析侧差分 ✅；
2. 畸形 APK 全部返回带偏移的 `ApkError` —— ✅（含真实样本派生的 5 例）；
3. `--deny-warn` 转绿 —— ✅（原定 R4，已提前达成）。

## 12. 未解决问题 / 待验证假设

- `bobzhang/zip@0.1.2` 的 ZIP64 / 容错行为未验证（实现轮前置）—— 五门槛审计已登记（ADR-0010 §2 / COMPATIBILITY.md，风险门槛为“登记不阻断”）。
- `resources.arsc` 完整展开复杂度高，第一阶段只读全局字符串池。
- 目标游戏 APK（phone/tv/partyr）许可不明未入库 → 其容器解析侧差分 `[仍需实测]`（`../docs/open-questions.md` §2.1）。
- 内嵌样本均无 `.so` → `native_libs` 非空 ABI 的真实差分 `[仍需实测]`。

## 13. 当前状态与 TODO

`apk.mbt` 已实现全部类型与公开函数（**无 `declare`、无 `0068`**），公开 API 有 `///` 文档注释；字段 `method` 已改名 `compression_method`（避开保留字）。`pub impl ContainerIndex for Apk` 为**冻结前追认**（决策点 7 加法性变更，见 `API.md` 文首）。

## References

`../docs/research-and-verification.md` §2.1/§2.4 · `../docs/adr/ADR-0002`、`ADR-0003`、`ADR-0005` · `https://source.android.com/docs/security/features/apksigning/v2`
