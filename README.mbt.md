# hnlyxiaobing/apk

> Round-1 · 架构与声明可评审（2026-11-06）。本包只有 ZIP 索引、Blob Wire 值类型与 `declare` 函数签名，**无 ZIP 解析 / 打包 / 签名逻辑**。`moon check`：0 error，8 × `[0068]`（预期）。

APK 容器层：只产出 `ManifestRef.raw` / `DexEntry.bytes` / `NativeLib.bytes` 等字节与索引，由组合根决定是否交给 `axml` / `dex` 解析（ADR-0003）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。

**当前状态：等待评审，不进入实现。**
