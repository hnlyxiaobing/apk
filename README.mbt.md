# hnlyxiaobing/apk

> R2 冻结前整改复核（2026-11-07）：本包 ZIP 索引、签名块只读识别与惰性解压**均为真实实现**（无 `declare`）。`moon check --deny-warn`：0 error / 0 warning；`moon test` 42/42。
> 依赖 `bobzhang/zip@0.1.2`（仅 `deflate`，已锁版；五门槛审计见 `../docs/adr/ADR-0010` §2 与 `../COMPATIBILITY.md`）。R2 WP-G 已加入真实 APK 样本与黄金差分（见 `../fixtures/golden/ASSETS.md`）。

APK 容器层：只产出 `ManifestRef.raw` / `DexEntry.bytes` / `NativeLib.bytes` 等字节与索引，由组合根决定是否交给 `axml` / `dex` 解析（ADR-0003）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。
