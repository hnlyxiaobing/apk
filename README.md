# hnlyxiaobing/apk

**APK 容器层解析库 —— ZIP 目录索引、签名结构与摘要校验、manifest 引用、dex 列表、native 库 ABI 归类与 resources.arsc 完整展开。**

> 状态：**已实现并门禁全绿**（2026-11-09 R4 复核）。`moon check --deny-warn` 0 error / 0 warning；
> `moon test` **84/84**（含真实样本、合成 v1 签名 / arsc / ELF 与畸形派生用例；另有 5 个 `#skip` 用例
> 显式跳过、不计通过）。

## 定位与为什么存在

2026-11-06 检索 mooncakes.io：`apk` 唯一命中是 `Xpeng/linuxpkg@0.5.0`（**Alpine Linux `.apk`**，非 Android），Android APK 容器层完全缺失；而 ZIP / ELF / PE / Mach-O 等通用容器已有包 → 纯 MoonBit 自研。APK 是所有 Android 逆向与审计工作的入口。

**关键设计决策（详见 `docs/DECISIONS.md` §1）**：曾有方案写「`apk` 依赖 `zip + axml + dex`，只做编排」，这会把 `apk` 变成中心节点、泄漏下游类型、并形成循环风险。本库改为——**容器层只产出原始字节与索引**，由组合根决定是否调用 `axml` / `dex`。因此 `apk` 可与两者并行开发，且任何使用者可只依赖 `apk` 做审计。

## 能力范围 / 非目标

- **做**：ZIP 中央目录索引（EOCD / ZIP64 / 对齐）、APK Signing Block 定位与 v1/v2/v3/v3.1
  **结构 + 摘要**校验、`AndroidManifest.xml` 原始字节引用、`classes*.dex` 列表、
  `lib/<abi>/*.so` ABI 归类（`NativeLib::elf_abi` 做 ELF 头交叉校验）、`resources.arsc`
  **完整展开**（package/typeSpec/type/复杂 bag）、按条目名惰性解压。
- **不做**：反编译、反汇编、manifest 语义解释、**签名写入**、打包、修改 ZIP、
  **RSA/ECDSA/DSA 公钥验签与证书链校验**、arsc 值渲染/主题求值/bag 压平。
- **签名校验边界（重要）**：`SignatureInfo.verified == true` 仅表示「结构解析通过 + 本地可验证
  摘要一致」（v1 MANIFEST 条目摘要 + `.SF` 清单摘要；v2/v3 内容分块 SHA-256 摘要），
  **不代表签名有效**；`Apk::signature_checks()` 的 `signature_verified` 恒为 `false`。
  详见 `docs/DECISIONS.md` §5 与 `docs/API.md` 文首。

## 公开接口（速览）

`Apk::open(Bytes)`、`Apk::{entries, manifest, dex_files, native_libs, signatures, signature_checks, resource_table, resource_table_full, entry}`、
`NativeLib::elf_abi`、`parse_resources_arsc(Bytes)`。完整签名见 `docs/API.md`。

## 依赖

- 依赖：**`bobzhang/zip@0.1.2`**（Apache-2.0，纯 MoonBit，全后端）—— 已在 `moon.mod` `import` 锁版，仅使用其 `deflate` 解压（`moon.pkg` 引 `bobzhang/zip/deflate`）。五门槛审计结论（用途/许可/平台/维护 4 项通过、0 不通过、1 项风险登记：**单人维护、star=0、低 bus factor，登记不阻断**）详见 `docs/DECISIONS.md` §3。独立 `moon.mod`，`moon check` 独立通过。

## 平台与许可风险

- 平台：全后端（`preferred_target = "wasm"`，未改动）；桌面即可测试。
- 许可：本仓库 Apache-2.0；APK Signing Block 规范来自 AOSP（CC-BY-4.0 文档 / Apache-2.0 代码）。无外部二进制。
- 风险：ZIP64 与 4 字节对齐；`"APK Sig Block 42"` 魔数与 ID-value 对（v2 `0x7109871a`、v3 `0xf05368c0`、v3.1 `0x1b93ad61`）；`resources.arsc` 复杂度（package / typeSpec / sparse-compact entry / overlay）——完整展开已实现并用 `aapt2 dump resources` 对账。
- **签名**：SHA-256 为纯 MoonBit 实现；v2/v3 内容摘要按 AOSP 分块口径（`0xa5`/`0x5a` 前缀）实测对齐。**未做**公钥验签、证书链、SHA-512 / verity 摘要；`verified` 不得对外表述为「已验签」。
- **注意**：`SignatureInfo.verified` 的严格语义见 `docs/DECISIONS.md` §5；需要机器可读边界时用 `signature_checks()[i].signature_verified`（恒 false）。

## 测试与验收

- **测试策略（现状）**：L0 程序化 fixture（stored/deflate 条目、签名块魔数、畸形中央目录、ZIP64 拒绝、对齐；合成 v1 JAR 签名、合成 arsc、合成 ELF）；L1 真实/受控样本内嵌（tvshell-debug.apk 21208 B、base.apk 1179 B、fx-multidex-* 三变体）+ L2 黄金：`aapt2 dump badging` 与 .NET `ZipFile` 中央目录规范化、`aapt2 dump resources` 资源表、`apksigner verify` 签名工具侧基准，**黄金期望值已内嵌测试代码，`moon test` 即回归**。畸形派生 6 例（截断 / EOCD 污染 / CD 偏移污染 / CRC 污染 / 未知压缩方法 / 多 dex 截断与目录污染，均断言报 `ApkError` 而非 panic）。
- **验收状态**：条目清单 / DEX 列表 / manifest 与 `resources.arsc` 字节长 / ABI（`native-code`）与独立实现一致；arsc 完整展开与 `aapt2 dump resources` 逐值一致；签名结构与摘要与 `apksigner verify` 方案并集一致。**package / version / sdk / permissions / activity 属 manifest 语义，不在本模块范围**，其解析侧差分由 axml 解析器承担。
- 依赖资产：受控自建与 AOSP 来源的提取样本已入库 `tests/fixtures/`（来源、哈希与规范化口径见 `tests/ASSETS.md`）；目标游戏 APK（phone/tv/partyr）许可不明、未入库，开发期做过差分复核；非空 `.so` 用测试内合成 ELF 覆盖，真实 `.so` 差分 `[仍需实测]`。

## 当前状态 / 交付产物

| 项 | 状态 |
|---|---|
| `apk.mbt` / `arsc.mbt` / `signature.mbt` / `crypto.mbt` 数据结构 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| ZIP 索引 / 签名结构与摘要 / arsc 完整展开 / ELF ABI 交叉校验 / 惰性解压 | ✅ 真实实现（无 `declare`） |
| `ContainerIndex for Apk`（API 冻结前加法性追认） | ✅ 见 `docs/API.md` |
| L1 真实样本 + L2 黄金 + 差分复核 | ✅ |
| `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` / 快照 | ✅ 全绿（84/84） |

## 开发排序说明

`apk` 提前到第一批开发（与 `axml` / `dex` 并行），不等待下游解析库完成——理由与后果见 `docs/DECISIONS.md` §4。

## 文档索引

`docs/DESIGN.md` · `docs/API.md` · `docs/DECISIONS.md` · `tests/ASSETS.md`
