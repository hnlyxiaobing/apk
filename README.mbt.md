# hnlyxiaobing/apk

> 2026-11-07 复核：本包 ZIP 索引、签名块只读识别与惰性解压**均为真实实现**（无 `declare`）。`moon check --deny-warn`：0 error / 0 warning；`moon test` 53/53。
> 依赖 `bobzhang/zip@0.1.2`（仅 `deflate`，已锁版；五门槛审计结论见 `DECISIONS.md` §3）。真实 APK 样本与黄金差分已入库（见 `tests/ASSETS.md`；黄金期望值内嵌测试代码，`moon test` 即回归）。

APK 容器层：只产出 `ManifestRef.raw` / `DexEntry.bytes` / `NativeLib.bytes` 等字节与索引，由组合根决定是否交给 `axml` / `dex` 解析（见 `DECISIONS.md` §1）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；设计决策记录见 `DECISIONS.md`，测试资产清单见 `tests/ASSETS.md`。
