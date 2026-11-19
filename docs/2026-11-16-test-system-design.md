# apk 测试系统设计（第一性原理）

> 建立：2026-11-16 ｜ 状态：设计生效，随开发文档逐包落地 ｜ 适用仓库：本仓库（hnlyxiaobing/apk，独立自包含）
> 配套文档：[2026-11-16-container-trust-dev-plan.md](2026-11-16-container-trust-dev-plan.md)（工作包 W1–W9；本文 `T-W*-*` 验收 ID 与该文档一一对应）
> 本文回答一个问题：**怎样用一套可复验的测试系统，证明本库对「任意输入字节」都履行了它声明的全部契约**——包括已实现能力、三个预期使用场景、以及开发文档新增能力。

---

## 1. 第一性原理：本库的正确性是什么

本库的数学形态是一个纯函数：`Bytes → (索引值, 原始字节, 校验结论) | ApkError`。
它不持有设备、不执行代码、不产生副作用（CLI 写盘除外）。因此「正确」不可约简为六条断言，**每条断言都必须有对应的测试层承载，缺一即测试系统不完备**：

| # | 断言 | 含义 | 反例（测试必须能抓住） |
|---|---|---|---|
| A1 | **寻址忠实** | 索引与提取的字节 = 容器内真实字节；偏移/尺寸/顺序与 ZIP 规范一致 | 中央目录与 local 头不一致时取错数据区；aapt2 裸填充导致偏移漂移 |
| A2 | **完整性 fail-closed** | 凡声明可校验的（CRC/尺寸/摘要/对齐），不一致必被报告；「未校验」绝不冒充「通过」 | 坏 CRC 静默放行；`signature_verified` 出现 true；未知摘要算法被当作一致 |
| A3 | **边界纯净** | 只输出 Bytes+索引+结构事实；不产出下游语义结论；不加载/执行任何输入内容 | Dart marker 命中被表述为快照解析结论；ELF 侦察触发装载行为 |
| A4 | **输入安全** | 任意畸形/恶意字节：不 panic、不越界、内存有界、CLI 写盘不逃逸 `--out` | 截断输入 panic；伪造声明尺寸的 deflate 流耗尽内存；`../` 条目写出目录 |
| A5 | **契约稳定** | 公开 API 签名、CLI 记录行/JSON 字段、退出码 0/1/2 与文档逐项一致；变更只加法 | 快照 diff 出现修改/删除；JSON 字段改名；退出码语义漂移 |
| A6 | **平台等价** | wasm 与 native 对同一输入产出逐字节相同的值与输出 | 两目标整型回绕/字节序差异导致结果分叉 |

**设计推论**：
1. 断言 A1/A2 是「对合法与非法输入都成立的性质」→ 需要**性质测试与穷举扫描**，不能只靠样例（§4）。
2. 断言 A2 的「未校验≠通过」是语义契约 → 需要**恒等式断言**（如 `signature_verified == false` 在所有路径上成立）与**错误变体覆盖簿记**（§6）。
3. 断言 A4 的「任意输入」不可穷举 → 用**截断扫描 + 变异语料 + 边界值**三类生成器逼近，并以「无 panic」为全局不变量（§4.3）。
4. 断言 A5/A6 是元契约 → 用**门禁与差分**承载，不写进普通用例（§7/§8）。
5. 真实世界符合性（「和 Android 工具链看到的一致」）无法自证 → 需要**外部 oracle 差分层**，且受许可红线约束只能本地可选执行（§5）。

## 2. 测试分层总览

沿用并扩展本仓库既有三层（L0 程序化 fixture / L2 受控黄金 / 畸形语料），补齐性质层、oracle 层、CLI 场景层与元契约层：

```text
L0 单元与程序化 fixture   —— 每个 pub fn 的行为样例（既有 apk_test.mbt 模式）
L1 性质与变异             —— 变形律 / 截断扫描 / 位翻转 / 边界值（新增，A1/A2/A4 主力）
L2 受控黄金差分           —— 入库 fixture + 逐字段黄金记录（既有 fixtures_test.mbt 模式）
L3 外部 oracle 差分       —— aapt2 / apksigner / unzip / llvm-readelf（本地可选，SKIPPED 纪律）
L4 CLI 场景 E2E           —— 三个预期场景 + 安全拒绝语料 + 退出码矩阵（新增）
L5 元契约门禁             —— mbti 快照 / 错误变体簿记 / wasm-native 等价 / 变异自检（新增）
R  真实样本本地 runner    —— 工作区外样本 + SHA-256 门禁 + 显式 SKIPPED（既有纪律的形式化）
```

各层与断言的承载关系：

| 断言 | 主承载层 | 辅助层 |
|---|---|---|
| A1 寻址忠实 | L0、L1（变形律） | L2、L3 |
| A2 完整性 fail-closed | L1（位翻转）、L0（恒等式） | L2、L3、L5（簿记） |
| A3 边界纯净 | L0（输出类型/字段断言） | L5（快照）、代码评审 |
| A4 输入安全 | L1（截断扫描/变异）、L4（安全语料） | L2（畸形 fixture） |
| A5 契约稳定 | L5（快照门禁）、L4（输出契约） | L0 |
| A6 平台等价 | L5（双目标差分） | 全层双跑 |

## 3. fixture 体系（测试系统的物质基础）

### 3.1 四类 fixture 与许可边界

| 类 | 形态 | 入库 | 许可 | 现状 |
|---|---|---|---|---|
| F-A 程序化构造 | 测试代码内字节 builder（`build_zip`/`ZSpec`、合成 ELF、手写 MANIFEST/.SF） | 是（代码） | 随本仓库 Apache-2.0 | 已有，W4/W5 扩展 |
| F-B 受控文件 fixture | `tests/fixtures/*.apk` 等（自建或来源已核实） | 是 | 登记于 `tests/ASSETS.md`（**现状缺失**，开发文档 W9 建立） | 已有 6 件 |
| F-C 生成器资产 | `tests/fixtures/gen_elf_fixtures.py` 产出的确定性 ELF/APK（W7 轨 A） | 是（生成物+脚本） | 自产，Apache-2.0 | 已建（W7 轨A） |
| F-D 真实第三方样本 | 工作区外本地路径 | **否（红线）** | 许可不明，只本地差分 | R runner 承载 |

**红线**：F-D 永不入库；F-B 新增件必须先核来源再登记哈希；任何 fixture 的 SHA-256 变更须同步 `tests/ASSETS.md`（W9 建立后生效），黄金记录与哈希绑定（防「样本漂移假绿」）。

### 3.2 builder 能力清单（L0/L1 共用，随工作包扩展）

- ZIP：stored/deflate 条目、多 dex、`lib/<abi>/` 目录、签名块注入、裸对齐填充（1–3 B）、坏 CRC（`bad_crc` 已有）、ZIP64 标记、加密位、未知压缩方法、声明尺寸伪造（W2 需要：`declared_size_override`）、local/CD 尺寸不一致；
- 签名：v1 MANIFEST/.SF/PKCS#7 结构壳（SHA-256 已有，W4 增 SHA-512）、v2/v3/v3.1 signer 序列（含 SHA-512 摘要 ID）、verity 块（W5）、畸形长度前缀；
- ELF：ELF32/64 × 4 ABI e_machine、DT_NEEDED/dynsym/strtab、`Java_*` 与 `_kDart*` 符号（含 st_value 可控，W8 对账需要）、strip 节头表变体；
- arsc：package/typeSpec/type/bag/三种 offset 编码最小件（既有 `tvshell-debug.resources.arsc` + 程序化构造）。

## 4. L1 性质与变异测试（新增，A1/A2/A4 的主力）

### 4.1 变形律（metamorphic laws，对合法样本族成立）

| ID | 律 | 断言 |
|---|---|---|
| P1 | 裸填充不变性 | local 头 extra 区追加 1–3 B 填充，`entries()` 索引与 `entry()` 字节不变（aapt2 兼容回归的泛化） |
| P2 | 条目重排不变性 | 中央目录条目顺序重排（同步修正偏移），按名提取结果不变 |
| P3 | 无关条目追加不变性 | 追加无关键名条目，manifest/dex/arsc/native_libs 结论不变 |
| P4 | 幂等律 | 同一 Bytes 两次 `open`+全量查询，所有输出逐字节相等（纯函数性） |
| P5 | 签名块位移不变性 | 签名块整体平移（内容区随之重算摘要的样本族），结构解析结论不变 |
| P6 | 双通道一致律 | `integrity_checks()`（W1）逐条目结论与 `entry()` 的 raise/成功行为一致 |

### 4.2 位翻转与边界值（A2 主力）

- **CRC 单 bit 翻转**：对受控样本每个条目数据区翻转 1 bit，`entry()` 必 raise、`integrity_checks()` 对应 `ok=false`（抽样：每条目首/中/尾 3 点）；
- **摘要单 bit 翻转**：v1 MANIFEST 条目字节、v2/v3 内容区各翻转 1 bit → `digest_ok=false`；
- **边界值矩阵**：256 MiB 上限 ±1 字节（声明值与实际值两个维度）、空 APK、单条目、0 字节条目、名字长 1/65535、extra_len 0/65535、偏移恰在 EOF。

### 4.3 截断扫描与变异语料（A4 主力，「任意输入不 panic」的逼近）

- **截断扫描**：对每个 F-B/F-C fixture，遍历所有前缀长度 `0..len`（大样本按步长抽样 + 全部结构边界点：EOCD/CD/local 头/签名块/ELF 头/arsc chunk 边界），逐一 `open` 及后续查询：**允许任何 ApkError，不允许 panic/挂起**；
- **变异语料**：对 fixture 做随机字节替换/插入/删除（固定种子，可复现），每轮 ≥1000 变异体，同样只允许 ApkError；
- **结构感知畸形**（既有 `fixtures_malformed_test.mbt` 扩展）：坏魔数、长度前缀溢出、循环偏移、UTF-8 非法名、ZIP64 extra、加密位、未知压缩方法、DER 截断（W3）、verity 坏布局（W5）；
- 全局不变量断言写法：`try { ... } catch { ApkError => () }`，任何非 ApkError 逃逸即测试失败。

## 5. L3 外部 oracle 差分 + R 真实样本 runner

### 5.1 oracle 矩阵（本地可选执行，缺失显式 SKIPPED）

| oracle | 差分对象 | 规范化口径 |
|---|---|---|
| `aapt2 dump xmltree` / `aapt l -a` | manifest/arsc 定位与尺寸（本库只出字节，不比语义） | 条目名/长度集合 |
| `apksigner verify --print-certs` | `signature_checks()` 结构/摘要结论、W3 证书指纹 | 方案×结构×摘要布尔组 + 指纹 hex |
| `unzip -l` / Python zipfile | `entries()` 名称/尺寸/CRC/方法 | 逐条目四元组 |
| `llvm-readelf -d --dyn-symbols` | `elf_info()` needed/符号/JNI 导出（W7 轨 B） | 排序后名集合 |

纪律：oracle 差分**只比本库声明输出的字段**，不比下游语义（A3）；oracle 不存在 → 打印 SKIPPED + 原因，退出码 78 口径，**不得写成通过**；oracle 版本随结果登记（易变事实标日期）。

### 5.2 R runner（真实样本，形式化既有纪律）

`tests/local_real_diff.py`（W7 轨 B 交付）：输入样本路径 + ASSETS 登记哈希（`tests/ASSETS.md`，W9 建立）→ 哈希不符拒绝执行 → 本库输出 vs oracle 规范化差分 → 报告「本地已差分 + 哈希 + 日期」。入库测试中对应 `#skip` 用例**保留不删**，注释指向 runner；真实样本结论永远不进入 `moon test` 通过计数。

## 6. 覆盖矩阵与错误变体簿记（完备性的账本）

### 6.1 能力 × 场景 × 层覆盖矩阵

F = 申报核心功能，S = 预期使用场景，C = 安全约束。「现状」为 2026-11-16 实测；缺口列指向开发文档工作包。

| ID | 能力/场景 | L0 | L1 | L2 | L3 | L4 | 现状 | 缺口→包 |
|---|---|---|---|---|---|---|---|---|
| F1 | ZIP 索引/惰性解压 stored+deflate | ✅ | P1/P2/P4 | ✅ | unzip | ✅ | 已覆盖 | L1 新建 |
| F2 | 拒 ZIP64 + 4B 对齐 + 裸填充 | ✅ | P1 | ✅ | — | ✅ | 已覆盖 | L1 泛化 |
| F3 | manifest/arsc/dex 定位与原始字节 | ✅ | P3/P4 | ✅ | aapt2 | ✅ | 已覆盖 | — |
| F4 | 多 dex + ABI 归类 + ELF 头交叉校验 | ✅ | 截断 | ✅ | readelf | ✅ | 合成覆盖 | 真实链路→W7 |
| F5 | v1–v3.1 结构+摘要、恒不验签 | ✅ | 位翻转 | ✅ | apksigner | ✅ | SHA-256 覆盖 | v1 SHA-512→W4 |
| F6 | arsc 完整展开（bag/三 offset） | ✅ | 截断 | ✅ | — | — | 已覆盖（冻结） | 一致性归外部组合层 |
| F7 | ELF 侦察（needed/dynsym/JNI/Dart） | ✅ | 截断 | 合成 | readelf | ✅ | 合成覆盖 | 符号定位→W8（已实现，M4） |
| F8 | 10 类 ApkError、畸形不 panic | ✅ | §4.3 | ✅ | — | ✅ | 语料已有 | 扫描系统化 |
| F9 | 批量完整性报告 | — | P6 | — | unzip | ✅ | 已实现（W1，2026-11-17） | — |
| F10 | 证书结构事实 | — | DER 截断 | — | apksigner | ✅ | **已实现（W3，M3）** | — |
| F11 | verity 结构 | — | 位翻转 | — | — | — | **已实现（W5，M4）** | — |
| F12 | 公钥验签（新通道） | — | 向量 | — | apksigner | — | **已实现（W6·RSA + ECDSA，M6-RSA-a/b/fix + M6-6 + W6-hardening-1..5 + W6-后续 里程碑 a/b/c）** | apksigner oracle 已实跑（2026-11-18，build-tools r34）：3 真 RSA + 3 篡改，6/6 AGREE |
| S1 | 逆向摸底：list --json → extract --entry | — | — | ✅ | — | ✅ | 已覆盖（L4 cli_e2e.py 哈希对 zipfile 引用） | — |
| S2 | 合规初筛：signatures/signature_checks 批量 | ✅ | 恒等式 | ✅ | apksigner | ✅ | API 已有 + L4 verify/certs 契约 | — |
| S3 | 取证提取：extract --all + 安全拒绝 | ✅ | 边界值 | ✅ | — | ✅ | 已覆盖（L4 cli_e2e.py 落盘哈希 + 4 类恶意条目预检拒绝） | — |
| C1 | 路径穿越拒绝（绝对/`..`/`\`/盘符/控制字符） | ✅ | 语料 | — | — | ✅ | 已实现 + L4 固化 | — |
| C2 | 256 MiB 上限（声明+实际） | ✅ | ±1 | — | — | — | 已实现（W2 预检拒绝） | — |
| C3 | 解压炸弹内存有界 | — | 伪造流 | — | — | — | 已实现（W2 `entry_capped` inflate 前预检） | — |
| C4 | 退出码 0/1/2 矩阵 | — | — | — | — | ✅ | 已实现 + L4 逐条断言 | — |

### 6.2 错误变体覆盖簿记（A2/A5 的账本，10/10 强制）

每个 `ApkError` 变体 ≥1 个**显式触发**用例（断言变体名，不只是「报错了」）；新增解析路径（W3/W5/W8）合入时须更新本表：

| 变体 | 触发 fixture（现状） | 新增触发（待建） |
|---|---|---|
| UnexpectedEof | 截断归档（既有） | 截断扫描全覆盖 |
| NotAZip | 坏 EOCD 魔数（既有） | — |
| BadCentralDirectory | 坏 local 签名/尺寸/CRC/压缩方法（既有） | W2 伪造声明、W1 双通道 |
| Zip64Unsupported | ZIP64 标记（既有） | — |
| EntryNotFound | 不存在名（既有） | — |
| BadSigningBlock | 坏签名块长度前缀（既有） | W3 畸形 DER（已由 cert_test T-W3-2 覆盖）、W5 坏 verity |
| UnsupportedSignatureScheme | 未知方案 ID（既有） | — |
| BadAlignment | 未对齐声明（既有） | — |
| BadResourceTable | 坏 arsc chunk（既有） | — |
| BadElf | 坏 ELF 头（既有） | W8 strip 变体 |

### 6.3 恒等式断言（语义契约，全路径成立）

- `signature_checks()[*].signature_verified == false`（W6 合入后**仍成立**——验签走新类型）；
- `signatures()[*].verified == true ⇒ structure_ok && digest_ok`（语义蕴含）；
- `integrity_checks()[*].ok == true ⇒ entry(name) 成功且字节 CRC 一致`（W1）；
- `dart_markers / dart_snapshot_refs 非空 ⇒ 仅识别结论`（A3：输出类型中不存在任何快照语义字段，靠快照门禁锁定）。

## 7. L4 CLI 场景 E2E（三个预期场景的端到端固化）

形态：`tests/cli_e2e.py`（Python 驱动 `moon run cmd/main --target native`，或构建后二进制），对 F-B/F-C fixture 执行命令序列，断言**退出码 + stdout 记录行/JSON + stderr 文案关键词 + 落盘文件哈希**。

| 场景 | 命令序列 | 断言要点 |
|---|---|---|
| S1 摸底 | `list fx.apk --json` → `extract fx.apk --entry classes.dex --out d.dex` | JSON 含 entries/dex/manifest_bytes/resource_table_bytes/abis 五段且字段名冻结；d.dex 哈希 = 黄金值；退出码 0 |
| S2 初筛 | 库级批量（L0 承载）+ `list`/`certs`（W3）JSON | 每方案 structure_ok/digest_ok 布尔组 = 黄金；`signature_verified` 恒 false；证书指纹 = oracle/黄金 |
| S3 取证 | `extract fx.apk --all --out dir` | 落盘文件集合/哈希 = 黄金；目录条目不产生文件 |
| S3-拒 | 含 `../x`、`/abs`、`C:x`、`a\b`、控制字符名的构造 APK | **写盘前整体拒绝**：dir 不存在或为空；退出码 1；stderr 含「不安全」 |
| C2/C3 | 声明 256 MiB+1 / 实际超限 / 伪造小声明+巨大流（W2） | 退出码 1；W2 后进程内存有界（预检即拒） |
| C4 | 无参/未知子命令/缺 --out/--entry 与 --all 互斥/坏路径 | 退出码 2（用法）与 1（IO/解析）逐例断言 |

记录行契约（冻结口径，变更即破坏）：`ENTR|name|usize|csize`、`DEX|name`、`MANI|len`、`ARSC|len`、`LIB|abi`、`EXTR|name|bytes|dest`；W3 加法 `CERT|…`。JSON 单行、字段名只增不改。

## 8. L5 元契约门禁（A5/A6）

1. **快照门禁**（既有第 5 道）：`moon info` + `git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti`；diff 只允许纯加法，出现修改/删除即失败。
2. **双目标等价**：同一 fixture 集在 `--target wasm` 与 `--target native` 各跑一遍 L0/L2 的**值输出**（经 CLI JSON 或测试打印规范化），逐字节 diff=0；新增 `tools/parity-check.ps1` 承载，纳入 CI 可选 job（平台受限时显式 SKIPPED）。
3. **错误簿记门禁**：§6.2 表与测试代码双向核对（脚本 grep 变体名在测试中的断言出现），10/10 缺一即红。
4. **变异自检（test-of-the-tests）**：`tools/mutation-sanity.ps1`——临时注入 3 类缺陷（跳过 CRC 校验 / 放行 `..` 条目名 / 把 `signature_verified` 置 true），套件**必须变红**，随后还原并复绿；证明测试系统真的在守契约，而非空转。每轮大版本合入前执行一次，结果登记。
5. **计数纪律**：`#skip` 不计通过；`moon test -f` 过滤串以 `*` 结尾防空转假绿；测试总数变化随 CHANGELOG 登记。

## 9. CI 集成与执行入口

- 五门禁不变（check --deny-warn / build / test / fmt --check / info+快照 diff）；L0/L1/L2 全部 riding on `moon test`（第 3 道）；
- L3/L4/R/parity/mutation 为**脚本层**，本地与 CI 可选 job 执行；oracle/设备/真实样本缺失一律显式 SKIPPED + 退出码 78 口径，不得冒充通过；
- 复验入口（本仓库自包含）：

```text
moon clean ; moon check --deny-warn ; moon build ; moon test ; moon fmt --check
moon info ; git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti
python tests/cli_e2e.py            # L4（W1/W2/W3 合入后启用对应断言组；P1/2026-11-18 收口轮落地）
powershell tools/parity-check.ps1          # L5 双目标等价（A6；P2/2026-11-18，12/12 diff=0）
powershell tools/mutation-sanity.ps1       # L5 变异自检（A5；P2/2026-11-18，3/3 变红后复绿）
powershell tools/error-bookkeeping.ps1     # L5 错误簿记（A2；P2/2026-11-18，10/10 双向对齐）
python tests/local_real_diff.py …  # R（本地可选，哈希门禁）
```

## 10. 维护规则与验收清单

**维护规则**：
1. 新增 pub API ⇒ 同提交附带 L0 样例 + L1 性质（如适用）+ §6 矩阵/簿记行更新；无测试的 API 不合入。
2. 新增解析路径 ⇒ 必须进入截断扫描 fixture 集（A4 不留死角）。
3. fixture 哈希变更 ⇒ ASSETS 登记 + 黄金记录同提交更新；禁止只改黄金不改哈希。
4. 每个工作包合入 ⇒ 开发文档 DoD 勾选 + 本文矩阵「现状」列刷新 + CHANGELOG 测试增量行。
5. 任何「通过」表述须可复验：命令 + 日期 + 计数；SKIPPED 永远单列。

**测试系统落地验收（随 M0–M3 逐包勾选）**：
- [x] L1：P1–P6 变形律、位翻转、边界值矩阵、截断扫描（全 fixture）落地并绿（P1–P4/P6 + 位翻转/边界值/截断扫描已绿；P5 签名块位移不变性于收口轮 P3 白盒落地，见 `apk_wbtest.mbt`「whitebox: P5 signing-block shift invariance」，黑盒 `l1_property_test.mbt` 的 P5 `#skip` 已移除）
- [x] L4：S1/S2/S3 + 安全拒绝语料 + 退出码矩阵全绿；记录行/JSON 契约断言生效（收口轮 P1，2026-11-18，`tests/cli_e2e.py`：53/53 PASS；含 `verify --json` scheme 字段引用化修复 + `extract --all` 大小写/目录前缀冲突预检）
- [x] L5：错误簿记 10/10；双目标 diff=0；变异自检 3/3 变红后复绿（收口轮 P2，2026-11-18，`tools/error-bookkeeping.ps1` / `tools/parity-check.ps1` / `tools/mutation-sanity.ps1` 全绿）
- [x] R：哈希门禁拒绝错误样本演示一次；真实样本结论未进入通过计数（收口轮 P3，`tests/local_real_diff.py`：以未登记样本 `tests/fixtures/base.apk` 演示，`exit 78` 拒绝，消息含「未登记于 tests/ASSETS.md 白名单 → 拒绝」；因许可红线当前白名单为空，任何样本均被拒，真实第三方 .so 的差分结论从不进入 `moon test` 通过计数）
- [x] 覆盖矩阵 §6.1 中所有「待建/缺口」项随 W1–W8 合入转为已覆盖或显式 SKIPPED（F12 已随 W6 落地（2026-11-18）：RSA 真验签 186/186 全绿，ECDSA 随后由 W6-后续 里程碑 a/b/c 接入 v2/v3/v3.1 与 v1；apksigner oracle 已实跑 3 真 + 3 篡改 6/6 AGREE，M6-6 的 SKIPPED 已被覆盖）