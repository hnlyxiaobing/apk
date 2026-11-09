# apk · 测试资产清单（tests/ASSETS.md）

> 本文件登记 `tests/fixtures/` 下**已入库**测试样本的来源、生成方式、SHA-256 与规范化口径，
> 内容自足（开发期另有更完整的资产登记文档，本文只保留本仓库所需事实）。
> 证据标注：`[已复核]` = 开发期本机命令/文件实测 ｜ `[仍需实测]` = 尚未取得证据。

**许可规则（硬红线）**：许可不明的第三方 APK 二进制**禁止入库**；受控自建 / 自产样本允许入库。

---

## 1. 已入库样本总表（tests/fixtures/）

| 文件 | 字节 | SHA-256 | 来源与许可 | 生成 / 提取方式 |
|---|---|---|---|---|
| `base.apk` | 1179 | `D5824D09A5E9E3D6109D9298E72A9887566D35B9A8F89A56DE124D53AF0A94C3` | **受控自建**（开发期工具链构建的最小 shell APK），随本仓库 Apache-2.0 | 构建产物直接入库；条目 2 个（`AndroidManifest.xml` + `resources.arsc`），无签名（`SIG|NONE`） |
| `tvshell-debug.apk` | 21208 | `24FA4F0BE0731806612DAFC486AF3ECD5978BF22BB8272314FFC62A6B1492093` | **受控自建**（开发期工具链构建的调试 shell APK），随本仓库 Apache-2.0 | 构建产物直接入库；11 条目、单 `classes.dex`（4368 B，D8 8.6.2-dev 产出）；签名 **v1+v2+v3**（apksigner verify 实测 `[已复核]`） |
| `tvshell-debug.resources.arsc` | 40 | `1FA3CB291285348EC1B33C85E7317D989467707F4791C4E5302F2D312D1E18C8` | 同上（`tvshell-debug.apk` 的 `resources.arsc` 条目） | 从 `tvshell-debug.apk` 按条目提取（空资源表，仅 chunk 头） |
| `fx-multidex-unsigned.apk` | 6058 | `A3578B414CFC15BED61C999B30E185D5C2AE1385924B818FDC3F57DB257FA2E7` | **受控自产**（javac/d8/aapt2/zipalign 自建，多 dex、未签名），随本仓库 Apache-2.0 | 见 §2 构建流水线；含 `classes.dex`（2116 B）+ `classes2.dex`（1640 B） |
| `fx-multidex-v1.apk` | 8070 | `A046C50EAA5C654C6BE8C892A3AF1CE10A5818867B0A5A1B02151004E4A2FD72` | **受控自产**（v1 签名变体：apksigner 签名 + repack 固定 META-INF 时间戳） | 见 §2；`SIG|V1`，无 APK Signing Block |
| `fx-multidex-v2v3.apk` | 12550 | `E2A736C749636EA6F09172ED56EED43BD37DD6EFA816AD48775E419A85B4EB2B` | **受控自产**（v2/v3 签名变体） | 见 §2；`SIG|V2`+`SIG|V3`，无 META-INF 签名条目 |

> 以上 SHA-256 为开发期登记值，开发期以脚本比对「入库文件 == 来源资产 == 测试内嵌字节」
> （测试代码 `fixtures_test.mbt` 内嵌同样字节的字面量）`[已复核]`。
> 另注：`fx-multidex-unsigned.apk` 的 local 头 extra 区含 3B/2B 裸对齐填充（aapt2 生产者行为），
> 是 ZIP 容器宽容度的常驻回归样本（见仓库根 `DECISIONS.md` §3）。

## 2. 受控构建流水线（fx-multidex-* 三变体，可复现）

工具版本 `[已复核]`：javac/keytool = JDK 21（`--release 11`）、d8 = 8.6.2-dev、aapt2 = build-tools
2.19-11948202、zipalign = build-tools 35.0.0、apksigner = 0.9。

```
javac --release 11 → d8 --min-api 21（两个桶 → classes.dex / classes2.dex）
→ aapt2 compile / aapt2 link（manifest + 资源，产出基础 APK）
→ zip 组装（DEX 条目 STORED、固定时间戳 1980-01-01）
→ zipalign -f 4（4 字节对齐，必须先于签名）
→ keytool 测试密钥（RSA 2048，仅用于夹具签名、无信任价值）
→ apksigner sign：
     v1 变体   --v1-only + repack 固定 META-INF 时间戳（消墙钟时间戳，保证可复现）
     v2v3 变体 --v2 --v3（签名后不再改动字节）
```

**可复现性** `[已复核]`：同一命令序列 + 同一测试密钥连续两次全量构建，三个产物 SHA-256
完全一致（即上表值）。

## 3. 规范化口径（黄金期望值的比对格式）

黄金期望值**内嵌于 `fixtures_test.mbt` 等测试代码**（`golden_*` 常量），`moon test` 即回归；
开发期曾用差分脚本驱动工具侧输出与解析侧输出逐字段复核，该验证已完结，结论如下。

- **容器侧（apkparse）**：
  - `ENTR|name|usize|csize`：中央目录顺序的条目清单（.NET `System.IO.Compression.ZipFile`
    独立实现为工具侧基准）；
  - `DEX|name`：`classes*.dex` 列表（按名排序，多 dex 全列）；
  - `MANI|len` / `ARSC|len`：`AndroidManifest.xml` / `resources.arsc` 解压后字节长；
  - `LIB|目录ABI|ELF头ABI|path|bytes`：原生库 ABI 归类（目录 ABI = aapt2 `native-code`
    口径；ELF 头 ABI = `NativeLib::elf_abi()` 内容侧交叉校验）。**真实样本均无 `.so`，故其黄金
    无 `LIB` 行；非空 ABI 路径由测试内合成 ELF fixture 覆盖（`elf_test.mbt`）。**
- **签名侧（sig）**：固定顺序 `SIG|V1|V2|V3|V31`，无任何签名方案时 `SIG|NONE`；工具侧基准为
  `apksigner verify --verbose`（min-sdk 21/24/28 三个仿真层并集）；解析侧为
  `@apk.signatures()` 的方案存在性检测 + **结构/摘要**校验（`verified` 语义见 `DECISIONS.md` §5；
  **不做** RSA/ECDSA 验签，`signature_verified` 恒 false）。
- **规范化原则**：只保留结构化字段，去掉行号、时间戳、绝对路径等易变文本。

**开发期差分复核方法与结论**（开发期验证，黄金值已内嵌入库）：
证据链为「来源资产（SHA-256）→ `tests/fixtures/` 提取样本（字节相等）→ 测试内嵌字节
（SHA-256 相等）→ 解析输出 ↔ 工具侧规范化输出（逐字段差分）」。tvshell-debug 与 base
两样本**工具侧 + 解析侧全通**；三受控变体（含多 dex 与三类签名方案）解析侧全通。
R4 新增两条工具侧独立基准：`resources.arsc` 完整展开 ↔ `aapt2 dump resources`（fx-multidex
的 bool/color/string 三类型与 zh 配置逐值一致）；签名结构 + 摘要 ↔ `apksigner verify`
（tvshell v1+v2+v3、fx-multidex-v1、fx-multidex-v2v3）。**注意**：签名侧只核对摘要，
不做公钥验签（见 `DECISIONS.md` §5）。

## 4. 未入库的第三方样本

phone-1.6.0.apk、tv-2.6.1.apk、partyr-1.6.0.apk 等第三方目标样本许可不明、未入库，开发期做过差分复核。

## 5. 畸形派生样本（不入库，测试代码内现场构造）

`fixtures_malformed_test.mbt` 从 `tvshell-debug.apk` / `fx-multidex-v2v3.apk` 的字节级派生
截断、EOCD 污染、中央目录偏移污染、条目 CRC 污染、未知压缩方法等用例，断言报 `ApkError`
而非 panic。派生样本不落盘、不入库，由测试代码现场构造。

R4 新增的**纯合成**样本（同样不落盘、不入库，测试代码内构造）：

- `signature_test.mbt`：v1 JAR 签名（MANIFEST.MF / `.SF` / 最小 PKCS#7 DER），覆盖摘要一致、
  条目摘要不一致、清单摘要错误、PKCS#7 结构非法、缺 `.SF`；
- `arsc_test.mbt`：完整资源表（字符串池 / package / typeSpec / type / dense·OFFSET16·SPARSE
  offsets / compact·complex bag / 多配置 / 未知 chunk 跳过）与坏 table/package/typeSpec/
  entry offset/bag count 错误路径；
- `elf_test.mbt`：最小 ELF32/ELF64 头（arm64-v8a / armeabi-v7a / x86 / x86_64 / riscv64）
  与坏 ELF 头（magic/class/data/截断）。

## 6. 缺口登记

- **真实第三方 `.so`** 的解析侧 ABI 黄金差分 `[仍需实测]`：内嵌样本均无 `.so`；R4 用测试内
  合成 ELF fixture 补齐了非空 `.so` 的路径解析 / 目录 ABI / ELF 头交叉校验 / 坏 ELF 错误路径，
  但**不能替代**真实 `.so`（含压缩、多架构、错标）差分。
- 未入库第三方样本的解析侧差分 `[仍需实测]`（见 §4，`fixtures_test.mbt` 中以 `#skip` 显式跳过，
  绝不冒充通过）。
- 签名**公钥验签**与证书链：未实现；SHA-512 / verity 摘要、真实 v3.1 / 多签名者样本
  `[仍需实测]`。
