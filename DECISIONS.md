# apk · 设计决策记录（DECISIONS.md）

> 本文整合本库开发期的关键设计决策，语言与事实自足：社区读者只凭本仓库即可理解每条决策的
> 背景、决策内容、理由与后果。个别条目注明「源自开发期决策记录 ADR-000X」仅为出处说明，
> **不指向本仓库之外的任何文件**。
>
> 条目：§1 容器层只产出字节与索引（ADR-0003）｜§2 11 模块零跨模块 import 与组合根（ADR-0002）｜
> §3 依赖引入五门槛与 `bobzhang/zip@0.1.2` 审计（ADR-0010）｜§4 开发排序（ADR-0005）。

---

## 1. 容器层只产出字节与索引，不编排下游解析（源自开发期决策记录 ADR-0003）

### 背景

早期方案把 `apk` 定义为「依赖 ZIP 读取 + `axml` + `dex`，本库只做编排」，即 `apk` 内部调用
manifest / DEX 解析器并返回解析结果。按字面实现会产生四个问题：

- `apk` 成为事实上的中心节点，形成模块间循环依赖风险；
- `apk` 的公开 API 必须返回 `AxmlDoc` / `DexFile` 等下游类型，把下游格式泄漏给容器层使用者；
- 只要下游解析库升级或报错，`apk` 的 API 被迫跟着变；
- 与「11 模块零跨模块 import」（§2）直接冲突。

业界做法同向：apktool 把「资源解码」与「DEX 反汇编」分开，jadx 用自研 zip reader 独立读取容器——
「容器读取」被普遍当作可独立复用的能力。错误处理上业界解析器普遍「严格校验 + 容错降级」：
按 `headerSize/size` 跳过未知结构，对畸形输入返回带偏移的显式错误而非崩溃（本库的
`ApkError` 契约由此而来）。

### 决策

`apk` 的职责收敛为「**ZIP 中央目录 + Android 专有结构索引**」：

| API | 返回 | 说明 |
|---|---|---|
| `Apk::open(Bytes)` | `Apk` | 纯值索引 |
| `Apk::manifest()` | `ManifestRef { entry_name, raw: Bytes }` | 只给原始 AXML 字节 |
| `Apk::dex_files()` | `Array[DexEntry { name, bytes }]` | 只给原始 DEX 字节 |
| `Apk::native_libs(Abi?)` | `Array[NativeLib { abi, path, bytes }]` | 只按 ABI 归类 |
| `Apk::resource_table()` | `ResourceTableRef?` | 第一阶段仅全局字符串池 |
| `Apk::signatures()` | `Array[SignatureInfo]` | 只读识别，`verified=false` |
| `Apk::entry(EntryName)` | `Bytes` | 惰性解压 |

组合根（见 §2）决定「先解析 manifest 还是先扫描 dex」，并把 `raw` / `bytes` 交给
`axml` / `dex` 解析器。`apk` 不 import、不调用、不返回任何下游类型。

补记（2026-11-07）：`resources.arsc` 的**完整解析器**归入 `axml`（与二进制 XML 共享字符串池与
ResChunk 头结构），`apk::resource_table()` 维持只产出原始字节/索引，与 `manifest()` 的分工完全同构——
本条决策（容器层不编排下游解析、不返回下游类型）不变。

### 理由

- `apk` 与 `axml` / `dex` 可并行开发，任何使用者可只依赖 `apk` 做审计 / 清单检查；
- `apk` 的接口稳定性不受下游格式演进影响；
- 容器层错误模型（`ApkError`）只处理 ZIP / 签名块，边界清晰；
- 下游解析错误（`AxmlError` / `DexError`）不会穿过 `apk` 的 API 边界。

### 后果

**正面**：见理由。**负面**：组合根需多写少量传递代码；`Apk::manifest()` 的调用方需要自己了解
AXML 格式（逆向工具链的合理知识）。

**被替代方案**：① `apk` 内部调用解析器并返回解析结果（已否决：耦合 + 循环风险 + 与零 import 冲突）；
② `apk` 提供 `manifest_doc()` 之类便利方法（会重新引入下游类型，否决；便利封装留给组合根）。

**风险与缓解**：`ManifestRef.raw` 是 `Bytes` 而非结构化结果，若上层忘记解析会拿到二进制字节——
`API.md` 写明调用顺序，组合根测试覆盖；签名块只识别不校验，`SignatureInfo.verified` 恒为
`false` 并在文档注释中明确，避免被误当作「已验签」。

---

## 2. 11 模块零跨模块 import，跨模块靠 Wire 契约 + 组合根（源自开发期决策记录 ADR-0002，仅摘与 `apk` 相关的边界）

### 背景

`apk` 与 `axml`、`dex` 等共 11 个项目**每个都有自己的 `moon.mod`**，是 11 个独立 MoonBit 模块
（不是同一模块内的 11 个包）。MoonBit 是名义类型系统：两个模块里结构完全相同的 `struct`
也不是同一类型。若把 `apk → axml + dex` 实现成编译期依赖，会产生循环依赖风险并把 `apk`
变成中心节点。

### 决策（与 `apk` 相关的边界）

1. **11 模块零跨模块 import**，全部可独立 `moon check`；`apk` 不依赖 `axml` / `dex`。
2. 跨模块只传**纯值**：`apk` 对外的 `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef`
   都是「名字 + 原始 `Bytes`」的 Blob Wire 值，与任何下游解析类型无关。
3. **组合根**（Composition Root）不是新库，而是未来 App 工程里的一段适配代码，负责：
   ① 用纯值在模块间构造目标类型；② 注入后端实现；③ 编排生命周期；④ 把下层错误映射为上层诊断。
   「是否调用 `axml` / `dex`、先解析什么后解析什么」全部由组合根决定（与 §1 一致）。
4. 抽象（trait，如 `ContainerIndex`）放在消费方，实现方不反向依赖。

### 理由

11 个模块可完全并行开发 / 评审；API 边界被迫写成中性值类型，天然满足「后端可替换、
实现细节不泄漏」（`ManifestRef.raw` / `DexEntry.bytes` 是 Blob Wire，上层可换成任意
AXML/DEX 解析器）；`moon check` 无外部依赖风险；避免模块循环。

### 后果

**正面**：并行开发；ZIP 实现可换包而不改上层签名。
**负面**：组合根需要少量显式适配代码；同构值类型存在结构漂移风险——由 `pkg.generated.mbti`
API 快照对比守护。
**被替代方案**：合并为一个多包模块（破坏既有骨架，禁止）；发布到 mooncakes.io 后用真实
import（引入版本耦合，暂不做）。

---

## 3. 依赖引入五门槛与 `bobzhang/zip@0.1.2` 审计（源自开发期决策记录 ADR-0010 §2 与依赖审计记录）

### 背景

约束：「不引入无依据的大型依赖（新增须说明用途 / 许可 / 维护风险）」「不破坏现有骨架与目录结构」。
`apk` 解析 APK 条目必须支持 DEFLATE 解压；自研 inflate 属实现工作量，非声明必需。

### 决策：依赖引入五门槛政策

新增依赖必须**同时**满足五条门槛并留痕：

1. **用途**：明确解决哪一层哪个能力，且现有模块无法以更小代价覆盖；
2. **许可**：SPDX 已核验、与 Apache-2.0 兼容；静态链接 / 再分发义务列明；
3. **维护**：版本、owner、最后更新、`build_status`、`yanked`、是否 legacy manifest；
4. **平台**：`supported_targets` 与目标后端一致，不破坏独立 `moon check`；
5. **风险**：登记风险与替代方案、移除成本（登记口径为「登记不阻断」）。

版本锁定：依赖在 `moon.mod` 的 `import` 中钉死版本（本库为 `bobzhang/zip@0.1.2`）；
`.mooncakes/` 是 moon 的本地依赖缓存目录，已被本仓库 `.gitignore` 忽略——**不入库、
不随仓库再分发**。

### `bobzhang/zip@0.1.2` 审计结论（2026-11-07 复验）

- **引入事实**：来源 mooncakes registry（`mooncakes.io`），上游 `https://github.com/bobzhang/zip.mbt`；
  许可 **Apache-2.0**；版本 `0.1.2` 未 yank、`build_status=success`。
- **使用面**：仅 `bobzhang/zip/deflate` **一个子包**的 DEFLATE 解压路径（stored 条目直接切片）；
  未使用其余子包（`zip`/`file`/`member`/`tar`/`gzip` 等）。
- **五门槛结果**：**用途 / 许可 / 平台 / 维护 4 项通过、0 不通过、1 项风险登记**——
  **风险登记：单人维护、star=0、低 bus factor，登记不阻断**。
- **再分发义务**（Apache-2.0）：若将来把依赖打进产物分发，须随产物保留 `LICENSE` 副本、
  标注修改、保留 NOTICE（该包未附 NOTICE）。当前仅开发期依赖，`.mooncakes/` 不入库，
  仓库本身不构成再分发；打进 APK / 可执行产物时才触发。
- **移除成本（低）**：只有 `apk` 一个模块 import、只用 `deflate` 一个子包；移除 = 改
  `moon.mod` + `moon.pkg` + 解压路径，替换为自研 inflate 或改用存储条目策略，影响面不外溢。

### ZIP 容器兼容性风险（实测登记，已规避）

- **风险（已实测证实，非理论）**：aapt2 在 ZIP local 头 extra 区写 1~3 字节**裸对齐填充**
  （不是合法 extra field 链，无 header id/size 头；实测某 52 MB 真实 APK 的 1028 个 local 头中
  403 个带此填充）。**严格遍历 extra field 链**的实现（如 `moonbitlang/core` 的 `archive/zip`
  `read_all`）会直接报 `zip: truncated extra field header`——这是格式宽容度缺陷类：
  逆向工具必须至少与格式生产者一样宽容。
- **本库规避**：定位条目数据时只读取 local 头的 `name_len` / `extra_len` **长度字段**并跳过负载，
  **不遍历 extra field 链**（对中央目录 extra 仅按 id 扫描检测 ZIP64），故对上述填充宽容；
  实测含该填充的真实大样本可正常读取。
- **永久回归**：受控产物 `fx-multidex-*.apk`（其中 unsigned 变体即含 3B/2B 裸填充）常驻
  `tests/fixtures/`，任何 ZIP 容器路径的实现改动必须过此回归样本（见 `tests/ASSETS.md`）。
- **状态**：依赖结论（`bobzhang/zip@0.1.2` 维持现状、仅用 `deflate` 解压面）不变；
  上游修复建议（对 <4 字节 extra 尾部按对齐填充容忍）留档。

### 后果

`apk` 全部可独立 `moon check`；无网络 / 许可 / legacy manifest 风险叠加；任何门槛不通过的
依赖不得引入。

---

## 4. 开发排序：`apk` 提前到第一批开发，不等 `axml` / `dex`（源自开发期决策记录 ADR-0005）

### 背景

开发期发现两处排期矛盾：任务优先级把 `apk`（连同 `dex`、`axml`）标为最高优先级（P0），
里程碑排期却把它放在靠后的批次；且早期方案让 `apk` 依赖 `axml` / `dex` 完成后才能开工。

### 决策

- `apk` **提前到第一批开发**（与 `yuv` / `pose` / `axml` / `dex` 等并行），不按原里程碑后置；
- 因 §1 的容器层决策（`apk` 不编排下游解析、对下游格式零知识），`apk` **不等待**
  `axml` / `dex` 完成，三者可并行开发。

### 理由

- APK 是所有 Android 逆向与审计工作的入口，越早可用，静态逆向链越早可验证；
- 零编译期依赖（§2）使「并行」在工程上成立——不存在谁阻塞谁；
- 静态逆向链与体感推理等其他价值链互不依赖，`apk` 提前不挤占它们的前置。

### 后果

各模块并行推进、互不阻塞；对组合根契约冻结的要求提高——并行实现前需先冻结 API，
否则并行项会互相等待（本库以 `pkg.generated.mbti` API 快照 + `API.md` 对账落实）。
