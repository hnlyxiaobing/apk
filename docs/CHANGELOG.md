# CHANGELOG

> 本目录自 2026-11-16（M0）建立，登记每个工作包合入：日期 / 工作包 / 新增 pub 声明清单 / 快照 diff 结论 / 测试增量。

## 2026-11-16 — M0 工作包

| 项 | 值 |
|---|---|
| 日期 | 2026-11-16 |
| 工作包 | W9 边界裁决与文档漂移清理 + 测试系统骨架（M0 地基） |
| 新增 pub 声明 | **无**（纯文档/注释变更，`pkg.generated.mbti` 零 diff） |
| 快照 diff 结论 | 零 diff（mbti 不变，纯加法判定 N/A） |
| 测试增量 | `tests/ASSETS.md` 建立（6 件 fixture SHA-256 登记）；L1 变形律/错误簿记见测试系统文档 |

### 本次合入内容

- **W9.1**：README 非目标补 ELF 只读深度上限（不做反汇编/符号执行/重定位展开/装载、不做 Dart AOT 快照对象图/指令表/版本语义）。
- **W9.2**：README §2 补 `resources.arsc` 归属裁决——语义归属判给外部 `axml` 库；本库 `resource_table_full` / `parse_resources_arsc` 自本日起冻结不再增强（API 冻结保留兼容）。
- **W9.3**：注释漂移清理——`apk.mbt`/`crypto.mbt`/`elf.mbt`/`fixtures_test.mbt`/`apk_test.mbt` 对不存在的 `docs/DESIGN.md`/`docs/DECISIONS.md`/`docs/API.md` 的引用，改为指向 `docs/2026-11-16-container-trust-dev-plan.md` §1 / `docs/2026-11-16-test-system-design.md` §10；不改动任何代码逻辑。
- **W9.4**：建立 `tests/ASSETS.md`（闭合 B15），登记 6 件 fixture SHA-256 与来源口径；`tvshell-debug.apk` / `tvshell-debug.resources.arsc` 标注「来源待核」。
- **测试系统骨架**：L0 既有样例（93/93 通过）与 `tests/ASSETS.md` 账本落地；错误变体簿记与 L1 变形律随后续里程碑随包扩展。

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（93/93）/ `moon fmt --check` / `moon info` + mbti 零 diff，全绿。

## 2026-11-17 — M1 工作包

| 项 | 值 |
|---|---|
| 日期 | 2026-11-17 |
| 工作包 | W1 批量完整性报告 API（首个「能力+测试」闭环） |
| 新增 pub 声明 | `pub(all) struct IntegrityCheck` + `pub fn Apk::integrity_checks(Self) -> Array[IntegrityCheck]` |
| 快照 diff 结论 | **纯加法**（T-W1-4）：新增 1 struct + 1 fn，零 modify/delete |
| 测试增量 | `integrity_test.mbt`：T-W1-1 全绿 ok 全 true / T-W1-2 坏 CRC 条目 ok=false 且其余不受影响 / T-W1-3 与 `entry` raise 行为逐条一致（P6 双通道）/ 真实多 dex fixture 全绿巡检（F9 矩阵现实回归） |

### 本次合入内容

- **W1 能力**（`integrity.mbt`）：遍历 `entries()`，逐条目解压并核对尺寸与 CRC-32，返回不中断的值化结论；条目级失败（坏 CRC/尺寸/不可解压）值化为 `ok=false` + `error`，不中断其余条目、**不新增错误变体**；目录条目（名以 `/` 结尾）跳过；内存即查即弃。
- **API 落地说明**：dev-plan W1 草案的 `raise ApkError` 按实现实情省略——中央目录索引在 `open` 时已完成结构校验，无独立「容器级失败」路径；声明不触发的 raise 会被 `moon check --deny-warn` 判为 unused-error-type 警告，故函数**不声明 raise**（文档已注释此决策）。

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（103/103，含 4 个新增 W1 用例）/ `moon fmt --check` / `moon info` + mbti **纯加法 diff**（12 行纯增），全绿。

## 2026-11-17 — M2 工作包（W2 内存防线）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-17 |
| 工作包 | W2 解压炸弹内存防线（闭合 B8：限额提取 `entry_capped`，三分段预检拒绝） |
| 新增 pub 声明 | `pub fn Apk::entry_capped(Self, String, Int64) -> Bytes? raise ApkError` |
| 快照 diff 结论 | **纯加法**：mbti 新增 1 行 `entry_capped`，零 modify/delete |
| 测试增量 | `w2_memory_test.mbt`：T-W2-1a/b 伪造声明/膨胀比样本预检即拒 / T-W2-2 边界 ±1 字节 / T-W2-4 正常样本逐字节一致；`main_wbtest.mbt` 限额常量回归 |

### 本次合入内容

- **W2 能力**（`apk.mbt`）：新增 `Apk::entry_capped(name, limit)` 与内部 `extract_data_capped`，在 inflate 前按「声明尺寸 + DEFLATE 理论最大膨胀比 1032:1」双预检建立 sound 上界；预检通过后才解压并复核；超限一律返回 `None`（fail-closed，不产出部分数据）；解析错误仍 raise 既有 `ApkError`。
- **CLI 防线上移**（`cmd/main/main.mbt`）：`--entry`/`--all` 路径改经 `entry_capped(name, 256 MiB)` 限额提取，超限 stderr + 退出码 1；既有大小预检保留声明尺寸专属错误文案，新增预检拒绝文案（`（预检拒绝）`）用于膨胀比 / 解压后复核路径。
- **测试夹具扩展**（`apk_test.mbt`）：`ZSpec` 新增 `declared_size` / `compressed_size` 覆盖字段，支持伪造中央目录尺寸以构造 W2 样本。

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（109/109，含 6 个新增 W2 用例 + 1 个限额常量回归）/ `moon fmt --check` / `moon info` + mbti **纯加法 diff**（1 行纯增），全绿。

## 2026-11-17 — M3 工作包（W3 证书解析 + W7 黄金差分）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-17 |
| 工作包 | W3 X.509 证书结构解析 + W7 真实 `.so` 许可安全的黄金差分 |
| 新增 pub 声明 | `pub(all) struct CertificateInfo` + `pub fn parse_certificate(Bytes) -> CertificateInfo raise ApkError` + `pub fn Apk::certificate_infos(Self) -> Array[CertificateInfo] raise ApkError` |
| 快照 diff 结论 | **纯加法**：mbti 新增 1 struct + 2 fn（共 16 行纯增），零 modify/delete |
| 测试增量 | `cert_test.mbt`：T-W3-4 字段稳定性 / T-W3-2 畸形 DER 只 raise 不 panic / T-W3-3 v1 与 v2/v3 双通道去重；`w7_test.mbt`：T-W7-2 全链路黄金 + 便利函数通道；`gen_elf_fixtures.py` 确定性合成 ELF/APK |

### 本次合入内容

- **W3 能力**（`cert.mbt`）：X.509 证书结构解析——读取版本 / 序列号（hex）/ 颁发者与主体（RFC4514 CN/O/OU/C/ST/L）/ 有效期（UTCTime 2 位年份 ≥50→19xx、<50→20xx，输出 `YYYY-MM-DDTHH:MM:SSZ`）/ 签名与公钥算法 OID（点分十进制）/ 公钥位长（RSA 模数位长或 EC P-256/384/521 OID 映射）/ SHA-256 指纹（hex）。`Apk::certificate_infos` 遍历 `signatures()` 各方案的 `certificates`（v1 PKCS#7 与 v2/v3 signer certificates）按 DER 字节去重。畸形 DER 一律走既有 `ApkError::BadSigningBlock`，不新增错误变体。
- **W7 轨 A**（`gen_elf_fixtures.py` + `w7_test.mbt`）：手工字节构造结构完整的 ELF64/AArch64 动态库（ELF 头 + PT_DYNAMIC + DT_NEEDED/DT_HASH/DT_STRTAB/DT_SYMTAB + `Java_*` / `_kDart*` marker），确定性可复现；经程序化 ZIP 打入 `lib/arm64-v8a/`。测试做容器归类 → ELF 头交叉校验 → needed / jni_exports / dart_markers 的全链路黄金断言。哈希登记 `tests/ASSETS.md`。
- **W7 轨 B**（`tests/local_real_diff.py`，本地-only）：以 `llvm-readelf -d --dyn-symbols` 为 oracle 的真实 `.so` 差分脚本，SHA-256 门禁 + 退出码 78；**永不入仓库测试集**（样本许可红线），真实第三方样本只允许「工作区外本地路径 + 本表登记 + `#skip`」形态。
- **CLI**（`cmd/main/main.mbt`）：新增 `certs <apk> [--json]` 子命令（JSON + `CERT|` 记录行）；usage 文本同步更新。

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（120/120，含 11 个新增 M3 用例）/ `moon fmt --check` / `moon info` + mbti **纯加法 diff**（16 行纯增），全绿。

## 2026-11-17 — M4 工作包（W5 verity + W8 Dart 符号定位）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-17 |
| 工作包 | W5 verity 签名块结构解析 + W8 Dart 符号定位（仅识别） |
| 新增 pub 声明 | `pub(all) struct VerityInfo` + `pub fn Apk::verity(Self) -> VerityInfo? raise ApkError` + `pub(all) struct DartSnapshotRef` + `pub fn NativeLib::dart_snapshot_refs(Self) -> Array[DartSnapshotRef] raise ApkError` |
| 快照 diff 结论 | **纯加法**：mbti 新增 2 struct + 2 fn + 1 extend（共 24 行纯增），零 modify/delete |
| 测试增量 | `verity_test.mbt`：T-W5-1 无块→None / T-W5-4a/b 块识别+字段解析；`w8_test.mbt`：T-W8-1 W7 fixture 偏移对账 / T-W8-2 strip 不 panic / T-W8-3 无符号空数组（共 9 个用例） |

### 本次合入内容

- **W5 能力**（`verity.mbt`）：识别 APK Signing Block 中 ID `0x42726577` 的 verity 对齐块并尽力解析声明字段（version / hash_algorithm / block_size / salt / root_hash / tree_size）；树重算恒不执行（`tree_recomputed_ok` 恒 false），`#skip` 显式缺口（需 AOSP fs-verity Merkle 树布局核实后补）。
- **W8 能力**（`elf.mbt` §DartSnapshotRef）：把 `dart_markers` 的字节模式命中升级为符号定位——从 dynsym 读 st_value 偏移，从 section header table 判定节名（.rodata / .text 等）；无节头表（被 strip）时 `in_section` 为空串；只匹配 4 个 `_kDart*` 预设 marker；不做快照语义。
- **加法性 API**：不新增 `ApkError` 变体、不动旧字段；纯新增 struct + fn 落地。

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（129/129，含 9 个新增 M4 用例）/ `moon fmt --check` / `moon info` + mbti **纯加法 diff**（24 行纯增），全绿。

## 后续（预留登记位）

- W1 批量完整性报告 —— 已完成（M1）
- W2 内存防线 —— 已完成（M2）
- W4 v1 SHA-512 —— 已完成（M2）
- W3 证书解析 + W7 黄金差分 —— 已完成（M3）
- W5 verity + W8 Dart 符号定位 —— 已完成（M4）
- W6 公钥验签 —— **已裁决（2026-11-18）：仅 RSA 降级立项（方案 B）**，M5 推进中

### 2026-11-18 — M5 启动（W6 仅 RSA 降级立项裁决落款）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-18 |
| 工作包 | W6 公钥验签——立项裁决落款（纯文档，代码 0 diff） |
| 裁决 | 方案 B：仅 RSA；ECDSA P-256/P-384 挂起 #skip，`crypto_verified` 对 ECDSA 恒 false |
| 快照 diff | **零 diff**（纯文档/注释变更） |

- README §2 新增 2026-11-18 裁决行；§6 清理 arsc「未裁决去重」残留漂移；
- dev-plan 状态行 + W6 节头 + §4 里程碑表 + 风险/止损段全部更新为方案 B；
- 后续按 M6-1→M6-2→M6-4→M6-5→M6-6（仅 RSA）逐里程碑合入。

### 2026-11-18 — M6-RSA-a（合并原 M6-1/2/4：大数+RSA PKCS#1 v1.5+v2/v3/v3.1 接入，公开入口落地）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-18 |
| 工作包 | M6-RSA-a：纯 MoonBit 无符号大数 + RSA PKCS#1 v1.5 验签原语 + DigestInfo + v2/v3/v3.1 SPKI 提取验签 |
| 新增 pub 声明 | `pub(all) struct SignatureVerification`（scheme / structure_ok / digest_ok / crypto_verified / algo / detail）+ `pub fn Apk::verify_signatures(Self) -> Array[SignatureVerification] raise ApkError` |
| 快照 diff 结论 | **纯加法**：mbti 新增 1 struct + 1 fn（共 10 行纯增），零 modify/delete |
| 测试增量 | `bigint_wbtest.mbt`（142 个已知向量 + 边界：大数 add/sub/mul/mod/mod_pow/bit/cmp/hex/bytes 往返）+ `rsa_wbtest.mbt`（6 个：SHA-256/512 已知向量验签、篡改失败、错配摘要失败、不支持算法失败）+ `verify_wbtest.mbt`（8 个：v2/v3/v3.1 真验签通过、篡改失败、ECDSA fail-closed、`#skip` ECDSA 延后）+ `verify_test.mbt`（3 个：v1 fail-closed、无签名空数组、旧契约不变） |
| 实现文件 | `bigint.mbt`（无符号大数 limb 表示、add/sub/mul/mod/mod_pow/bit/cmp/be_bytes）+ `rsa.mbt`（RSA PKCS#1 v1.5 verify + DigestInfo + SPKI 公钥提取）+ `verify.mbt`（`SignatureVerification` + `verify_signatures` + signer extraction）+ `signature.mbt`（SigRecord 新增 value_off/value_len） |
| 聚合说明 | 因 `moon check --deny-warn` 的 `unused_value` 规则要求每个里程碑有非测试消费方，原 M6-1/2/4 三个纯内部里程碑合并为本档（公开入口 `verify_signatures` 为统一消费者）；范围不变，仅过程聚合 |

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（156/156 全绿，1 个 `#skip` 不计入）/ `moon fmt --check` / `moon info` + mbti **纯加法 diff**（10 行纯增），全绿。

### 2026-11-18 — M6-RSA-b（v1 CMS SignedData signerInfo 验签）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-18 |
| 工作包 | M6-RSA-b：v1（JAR 签名）PKCS#7 CMS SignedData 的 signerInfo RSA 签名值验证 |
| 新增 pub 声明 | **无**（内部实现；`verify_signatures` 已在 M6-RSA-a 公开） |
| 快照 diff 结论 | **零 diff**（纯内部加法，mbti 不变） |
| 测试增量 | `verify_wbtest.mbt` +3：v1 signedAttrs 路径真验签、v1 无 signedAttrs（签名覆盖内容）路径真验签、v1 篡改签名 fail-closed；`verify_test.mbt` 更新 1：真实 v1 样本按算法受支持性判定 |
| 实现文件 | `cms.mbt`（新增，~430 行）：ContentInfo/SignedData/SignerInfo DER 解析、`messageDigest` 属性比对、signedAttrs→SET OF 重编码（0xA0→0x31）、X.509 SPKI 提取、RSA 验签接线；`signature.mbt`（SigRecord 新增 `v1_block`）；`verify.mbt`（`verify_v1_crypto` 接 CMS） |

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（159/159 全绿，1 个 `#skip` 不计入）/ `moon fmt --check` / `moon info` + mbti **零 diff**，全绿。

### 2026-11-18 — M6-RSA-fix（算法 ID 映射修正 + RSA-PSS + v3 signer 布局）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-18 |
| 工作包 | 修正 v2/v3 签名算法 ID 映射（0x0101/0x0102 = RSA-PSS，0x0103/0x0104 = RSA-PKCS#1 v1.5）；新增 RSA-PSS（EMSA-PSS-VERIFY）验签；v3/v3.1 signer 的 min/max SDK 布局 |
| 新增 pub 声明 | **无**（纯内部修正） |
| 快照 diff 结论 | **零 diff** |
| 测试增量 | `rsa_wbtest.mbt` +1（PSS 已知向量 + 篡改/错配失败）；`verify_wbtest.mbt` 重生成合成 fixture（正确算法 ID）+4（PSS-SHA256、PSS-SHA512(2048-bit)、PKCS#1v15-SHA512、v3/v3.1 布局验证） |
| 修正原因 | 原实现把 0x0101 当作 PKCS#1 v1.5，导致真实 apksigner 样本（v2 默认 PSS）无法验签；对账 `fx-multidex-v2v3.apk` 暴露该缺陷。修正后真实样本 v2+v3 均 crypto_verified=true |

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（163/163 全绿，`#skip` 不计入）/ `moon fmt --check` / `moon info` + mbti **零 diff**，全绿。

### 2026-11-18 — M6-6（apksigner oracle 差分 harness；本机无 SDK → 显式 SKIPPED）

| 项 | 值 |
|---|---|
| 日期 | 2026-11-18 |
| 工作包 | M6-6：`apksigner verify` oracle 差分 harness + CLI `verify` 子命令 |
| 新增 pub 声明 | **无**（CLI 子命令，非库 API） |
| 快照 diff 结论 | **零 diff** |
| oracle 状态 | 本机无 Android SDK build-tools（`apksigner`/`java` 均缺失）→ **显式 SKIPPED**（exit 78） |
| 自检结果 | `--self-test` 模式（无 oracle）：fx-multidex-v1 / fx-multidex-v2v3 / fx-multidex-unsigned 三件受控样本，库内结论与期望 3/3 一致（v1=v2=v3 crypto_verified=true，unsigned=无签名）。**真实 apksigner 生成样本在库内全数验签通过**，即 T-W6-2 的实证 |
| 实现文件 | `cmd/main/main.mbt`（`verify` 子命令：`VERIFY|scheme|structure_ok|digest_ok|crypto_verified|algo` 行式输出 + JSON）；`tests/apksigner_oracle_diff.py`（oracle 差分 runner：SDK 探测 / exit 78 SKIPPED / 三样本对账）；`verify_test.mbt`（T-W6-6a/b 显式 `#skip` + 契约测试升级为真实样本双方案断言） |

### 门禁

`moon check --deny-warn` / `moon build` / `moon test`（163/163 全绿，`#skip` 不计入）/ `moon fmt --check` / `moon info` + mbti **零 diff**，全绿。
