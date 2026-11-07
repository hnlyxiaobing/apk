# apk · 公开 API（API.md）

> 与 `pkg.generated.mbti` 一致。全部函数为 `declare`（**无实现**，预期 `0068` 告警）。
> 错误传播统一 `raise ApkError`；只产出字节与索引，**不返回任何下游解析类型**。

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
| `ContainerIndex` | `pub trait` | `entry` / `entries` 契约 |

## 函数签名

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Apk::open(source : Bytes) -> Apk raise ApkError` | `source` 只读、调用方持有；索引只引用不转移 | `Apk` 纯值 / `ApkError` | 无句柄；惰性解压；索引只读可并发 | EOCD / ZIP64 / 对齐 / 签名块定位 |
| `Apk::entries(self) -> Array[ZipEntryRef]` | `self` 只读 | 中央目录顺序条目 | 无状态 | — |
| `Apk::manifest(self) -> ManifestRef raise ApkError` | `self` 只读 | **原始 AXML 字节**（交组合根给 axml） / `EntryNotFound` | 不缓存解压结果 | 不解释 manifest 语义 |
| `Apk::dex_files(self) -> Array[DexEntry] raise ApkError` | `self` 只读 | `classes*.dex` 列表（按名排序） | 不解析 DEX | — |
| `Apk::native_libs(self, abi : Abi?) -> Array[NativeLib] raise ApkError` | `abi = None` 返回全部并各自标注 | `lib/<abi>/*.so` 列表 | 无状态 | 未知 ABI 归入 `Unknown(String)` |
| `Apk::signatures(self) -> Array[SignatureInfo] raise ApkError` | `self` 只读 | 只读方案摘要；`verified=false` | 不做密码学校验 | v1/v2/v3/v3.1 识别（W3） |
| `Apk::resource_table(self) -> ResourceTableRef? raise ApkError` | `self` 只读 | `None` = 无 arsc；否则仅全局字符串池 | 无状态 | 完整 arsc 不在范围 |
| `Apk::entry(self, name : EntryName) -> Bytes raise ApkError` | `self` 只读 | 解压后原始字节 / `EntryNotFound` | 每次独立分配，可并发 | 压缩方法/CRC 校验 |

## 错误构造速查

`UnexpectedEof` · `NotAZip` · `BadCentralDirectory(offset, detail)` · `Zip64Unsupported` · `EntryNotFound(name)` · `BadSigningBlock(offset, detail)` · `UnsupportedSignatureScheme` · `BadAlignment(name, offset)`

## 非目标

反编译 / 反汇编 / manifest 语义 / 签名写入 / 打包 / 修改 ZIP / 证书链校验 / arsc 完整展开。

## 状态

`moon check`：✅ 0 error，8 × `0068`。API 快照：`pkg.generated.mbti`。实现：❌ 后续轮。
