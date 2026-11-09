# hnlyxiaobing/apk

**APK 容器层解析库 —— ZIP 目录索引、签名块、manifest 引用、dex 列表与 native 库 ABI 归类。**

> 状态：**已实现并门禁全绿**（2026-11-07 复核）。`moon check --deny-warn` 0 error / 0 warning（原 8 条 `0068` 警告已消除）；`moon test` 53/53（含真实样本与畸形派生用例；另有 4 个 `#skip` 用例显式跳过、不计通过）。

## 定位与为什么存在

2026-11-06 检索 mooncakes.io：`apk` 唯一命中是 `Xpeng/linuxpkg@0.5.0`（**Alpine Linux `.apk`**，非 Android），Android APK 容器层完全缺失；而 ZIP / ELF / PE / Mach-O 等通用容器已有包 → 纯 MoonBit 自研。APK 是所有 Android 逆向与审计工作的入口。

**关键设计决策（详见 `DECISIONS.md` §1）**：曾有方案写「`apk` 依赖 `zip + axml + dex`，只做编排」，这会把 `apk` 变成中心节点、泄漏下游类型、并形成循环风险。本库改为——**容器层只产出原始字节与索引**，由组合根决定是否调用 `axml` / `dex`。因此 `apk` 可与两者并行开发，且任何使用者可只依赖 `apk` 做审计。

## 能力范围 / 非目标

- **做**：ZIP 中央目录索引（EOCD / ZIP64 / 对齐）、APK Signing Block 定位与 v1/v2/v3/v3.1 只读识别、`AndroidManifest.xml` 原始字节引用、`classes*.dex` 列表、`lib/<abi>/*.so` ABI 归类、`resources.arsc` 全局字符串池（简版）、按条目名惰性解压。
- **不做**：反编译、反汇编、manifest 语义解释、**签名写入**、打包、修改 ZIP、证书链密码学校验、`resources.arsc` 完整展开。
- **签名块**：APK Signing Block 定位与 v1/v2/v3/v3.1 **只读识别**已实现（`SignatureInfo.verified` 恒为 `false`，不做密码学校验）。

## 公开接口（速览）

`Apk::open(Bytes)`、`Apk::{entries, manifest, dex_files, native_libs, signatures, resource_table, entry}`。完整签名见 `API.md`。

## 依赖

- 依赖：**`bobzhang/zip@0.1.2`**（Apache-2.0，纯 MoonBit，全后端）—— 已在 `moon.mod` `import` 锁版，仅使用其 `deflate` 解压（`moon.pkg` 引 `bobzhang/zip/deflate`）。五门槛审计结论（用途/许可/平台/维护 4 项通过、0 不通过、1 项风险登记：**单人维护、star=0、低 bus factor，登记不阻断**）详见 `DECISIONS.md` §3。独立 `moon.mod`，`moon check` 独立通过。

## 平台与许可风险

- 平台：全后端（`preferred_target = "wasm"`，未改动）；桌面即可测试。
- 许可：本仓库 Apache-2.0；APK Signing Block 规范来自 AOSP（CC-BY-4.0 文档 / Apache-2.0 代码）。无外部二进制。
- 风险：ZIP64 与 4 字节对齐；`"APK Sig Block 42"` 魔数与 ID-value 对（v2 `0x7109871a`、v3 `0xf05368c0`、v3.1 `0x1b93ad61`）；`resources.arsc` 复杂度远超 manifest（package / typeSpec / sparse-compact entry / overlay）。策略：先只读全局字符串池。
- **注意**：`SignatureInfo.verified` 恒为 `false` 直到将来接入密码学校验，避免被误当作"已验签"。

## 测试与验收

- **测试策略（现状）**：L0 程序化 fixture 33 例（stored/deflate 条目、签名块魔数、畸形中央目录、ZIP64 拒绝、对齐）；L1 真实/受控样本内嵌（tvshell-debug.apk 21208 B、base.apk 1179 B、fx-multidex-* 三变体）+ L2 黄金：开发期以 `aapt2 dump badging` 规范化输出与 .NET `ZipFile` 中央目录规范化输出做逐字段差分复核（**开发期验证**，方法与结论见 `tests/ASSETS.md`）；**黄金期望值已内嵌于 `fixtures_test.mbt` 等测试代码，`moon test` 即回归**。畸形派生 6 例（截断 / EOCD 污染 / CD 偏移污染 / CRC 污染 / 未知压缩方法 / 多 dex 截断与目录污染，均断言报 `ApkError` 而非 panic）。开发期差分复核中 tvshell-debug 与 base 两样本**工具侧+解析侧全通（退出码 0）**。
- **验收状态**：条目清单 / DEX 列表 / manifest 与 `resources.arsc` 字节长 / ABI（`native-code`）与独立实现一致；**package / version / sdk / permissions / activity 属 manifest 语义，不在本模块范围（容器层不解释 manifest 语义，见 `DECISIONS.md` §1），其解析侧差分由 axml 解析器承担**。
- 依赖资产：受控自建与 AOSP 来源的提取样本已入库 `tests/fixtures/`（来源、哈希与规范化口径见 `tests/ASSETS.md`）；目标游戏 APK（phone/tv/partyr）许可不明、未入库，开发期做过差分复核。

## 当前状态 / 交付产物

| 项 | 状态 |
|---|---|
| `apk.mbt` 数据结构 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| ZIP 索引 / 签名块 / 惰性解压 | ✅ 真实实现（无 `declare`） |
| `ContainerIndex for Apk`（API 冻结前加法性追认） | ✅ 见 `API.md` |
| L1 真实样本 + L2 黄金 + 差分复核 | ✅ |
| `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` | ✅ 全绿（53/53） |

## 开发排序说明

`apk` 提前到第一批开发（与 `axml` / `dex` 并行），不等待下游解析库完成——理由与后果见 `DECISIONS.md` §4。

## 文档索引

`DESIGN.md` · `API.md` · `DECISIONS.md` · `tests/ASSETS.md`
