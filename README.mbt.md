# hnlyxiaobing/apk

> 2026-11-09 R4 复核：本包 ZIP 索引、签名**结构+摘要**校验、`resources.arsc` 完整展开、ELF ABI
> 交叉校验与惰性解压**均为真实实现**（无 `declare`）。`moon check --deny-warn`：0 error / 0 warning；
> `moon test` **79/79**（另有 5 个 `#skip`）。
> 依赖 `bobzhang/zip@0.1.2`（仅 `deflate`，已锁版；五门槛审计结论见 `DECISIONS.md` §3）。真实 APK 样本与黄金差分已入库（见 `tests/ASSETS.md`；黄金期望值内嵌测试代码，`moon test` 即回归）。
> **签名边界**：`verified == true` 仅表示结构 + 本地摘要一致，**不是**签名有效（无 RSA/ECDSA 验签；见 `DECISIONS.md` §5）。

APK 容器层：只产出 `ManifestRef.raw` / `DexEntry.bytes` / `NativeLib.bytes` 等字节与索引，
以及 apk 自有的 `ResTable` 值类型；由组合根决定是否交给 `axml` / `dex` 解析（见 `DECISIONS.md` §1）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；设计决策记录见 `DECISIONS.md`，测试资产清单见 `tests/ASSETS.md`。
