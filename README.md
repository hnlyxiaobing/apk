# hnlyxiaobing/apk

**APK 容器层解析库 —— ZIP 目录索引、签名块、manifest 引用、dex 列表与 native 库 ABI 归类。**

> 状态：**Round-1 架构与声明可评审**。已写入数据结构与 `declare` 签名，`moon check` 0 error（8 条预期 `0068` 告警）。**无业务逻辑**。

## 定位与为什么存在

路线图「拼图一」复核（2026-11-06）：`apk` 唯一命中是 `Xpeng/linuxpkg@0.5.0`（**Alpine Linux `.apk`**，非 Android），Android APK 容器层完全缺失；而 ZIP / ELF / PE / Mach-O 等通用容器已有包。APK 是所有 Android 逆向与审计工作的入口。

**本轮关键设计修正（ADR-0003）**：原报告写「`apk` 依赖 `zip + axml + dex`，只做编排」，这会把 `apk` 变成中心节点、泄漏下游类型、并形成循环风险。本轮改为——**容器层只产出原始字节与索引**，由组合根决定是否调用 `axml` / `dex`。因此 `apk` 可与两者并行开发，且任何使用者可只依赖 `apk` 做审计。

## 能力范围 / 非目标

- **做**：ZIP 中央目录索引（EOCD / ZIP64 / 对齐）、APK Signing Block 定位与 v1/v2/v3/v3.1 只读识别、`AndroidManifest.xml` 原始字节引用、`classes*.dex` 列表、`lib/<abi>/*.so` ABI 归类、`resources.arsc` 全局字符串池（简版）、按条目名惰性解压。
- **不做**：反编译、反汇编、manifest 语义解释、**签名写入**、打包、修改 ZIP、证书链密码学校验、`resources.arsc` 完整展开。
- 签名块解析（原 APK-02）本轮只声明接口，实现延后到 W3。

## 公开接口（速览）

`Apk::open(Bytes)`、`Apk::{entries, manifest, dex_files, native_libs, signatures, resource_table, entry}`。完整签名见 `API.md`。

## 依赖

- **本轮零依赖**；独立 `moon.mod`，`moon check` 独立通过。
- 后续轮：实现期计划复用 `bobzhang/zip@0.1.2`（Apache-2.0，纯 MoonBit，全后端）。**本轮未 `moon add`**，且该包的 ZIP64 / 中央目录容错能力需先验证（ADR-0010 门槛）。

## 平台与许可风险

- 平台：全后端（`preferred_target = "wasm"`，未改动）；桌面即可测试。
- 许可：本仓库 Apache-2.0；APK Signing Block 规范来自 AOSP（CC-BY-4.0 文档 / Apache-2.0 代码）。无外部二进制。
- 风险：ZIP64 与 4 字节对齐；`"APK Sig Block 42"` 魔数与 ID-value 对（v2 `0x7109871a`、v3 `0xf05368c0`、v3.1 `0x1b93ad61`）；`resources.arsc` 复杂度远超 manifest（package / typeSpec / sparse-compact entry / overlay）。策略：先只读全局字符串池。
- **注意**：`SignatureInfo.verified` 恒为 `false` 直到实现轮接入密码学校验，避免被误当作"已验签"。

## 测试与验收

- **测试策略**：与 `aapt2 dump badging` 逐字段一致；dex 数量与 `lib/` ABI 目录断言；签名块魔数定位测试；ZIP64 / 畸形中央目录 / 条目缺失注入；`moon test --enable-coverage`。
- **验收标准**（实现轮）：列出两个 APK 的 manifest 关键字段、dex 数量、lib 目录 ABI，与 aapt2 一致。
- 依赖资产：真实 APK 不在本工作区（`docs/open-questions.md` Q1）。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `apk.mbt` 数据结构 + `declare` 签名 + 文档注释 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| ZIP 索引 / 签名块 / 惰性解压逻辑 | ❌ 后续轮，`TODO(实现轮)` |
| `moon check` | ✅ 0 error（8 × `0068`，预期） |

## 本轮顺序说明

APK-01 从原报告 M2 **提前到 W0**（任务表原标 P0，冲突 C1）；且因 ADR-0003 不再等待 `axml` / `dex` 完成，可三者并行。

## 文档索引

`DESIGN.md` · `API.md` · `../docs/architecture.md` · `../docs/adr/ADR-0002`、`ADR-0003`、`ADR-0005` · `../docs/moon-check-report.md`
