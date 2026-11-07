# apk · 设计契约（DESIGN.md）

> Round-1 / 2026-11-06 ｜ 状态：架构与声明可评审，无业务逻辑

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

全部纯值。`Apk::open` 不转移输入所有权；`Apk::entry` 惰性解压、不缓存解压结果；无句柄、无 close。

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
|---|---|
| 黑盒 | 与 `aapt2 dump badging` 逐字段一致；dex 数量 / ABI 目录断言 |
| 白盒 | EOCD 定位、签名块魔数、ZIP64、4 字节对齐 |
| 畸形输入 | 截断、假 EOCD、未知签名方案、缺失条目、压缩方法异常 |
| 门禁 | `moon fmt --check` / `moon check` / `moon test --enable-coverage` / `moon info` |

## 11. 验收标准（实现轮）

1. 两个 APK 的 manifest 关键字段 / dex 数 / lib ABI 与 aapt2 一致；2. 畸形 APK 全部返回带偏移的 `ApkError`；3. R4 `--deny-warn` 转绿。

## 12. 未解决问题 / 待验证假设

- `bobzhang/zip@0.1.2` 的 ZIP64 / 容错行为未验证（实现轮前置）。
- `resources.arsc` 完整展开复杂度高，第一阶段只读全局字符串池。
- 真实 APK 样本不在工作区（Q1）。

## 13. 当前状态与 TODO

`apk.mbt` 已写入全部类型与 8 个 `declare` 函数，公开 API 有 `///` 文档注释与 `TODO(实现轮)`。**未实现任何解析逻辑**。字段 `method` 已改名 `compression_method`（避开保留字）。

## References

`../docs/research-and-verification.md` §2.1/§2.4 · `../docs/adr/ADR-0002`、`ADR-0003`、`ADR-0005` · `https://source.android.com/docs/security/features/apksigning/v2`
