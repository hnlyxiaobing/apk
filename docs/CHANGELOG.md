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

## 后续（预留登记位）

- W1 批量完整性报告 —— 已完成（M1）
- W2 内存防线 —— 已完成（M2）
- W4 v1 SHA-512 —— 已完成（M2）
- W3 证书解析 + W7 黄金差分（待 M3）
- W5 verity + W8 Dart 符号定位（待 M4）
- W6 公钥验签（待裁决后另排）
