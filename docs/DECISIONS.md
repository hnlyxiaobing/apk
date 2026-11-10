# apk · 设计决策记录（DECISIONS.md）

> 本文记录本库的关键设计决策，语言与事实自足：社区读者只凭本仓库即可理解每条决策的
> 背景、决策内容、理由与后果。所有条目均已改写为完全自足的表述，
> **不指向本仓库之外的任何文件**。
>
> 条目：§1 容器层只产出字节与索引｜§2 零跨模块 import 与组合根｜
> §3 依赖引入五门槛与 `bobzhang/zip@0.1.2` 审计｜§4 开发排序｜
> §5 签名 `verified` 语义：结构 + 摘要 ≠ 签名有效｜§6 resources.arsc 完整展开留在 apk｜
> §7 原生库 ABI：目录归类 + ELF 头内容侧交叉校验｜
> §8 ELF 只读侦察归 `apk`：容器条目自身元数据的加法性加深。

---

## 1. 容器层只产出字节与索引，不编排下游解析

### 背景

早期方案把 `apk` 定义为「依赖 ZIP 读取 + `axml` + `dex`，本库只做编排」，即 `apk` 内部调用
manifest / DEX 解析器并返回解析结果。按字面实现会产生四个问题：

- `apk` 成为事实上的中心节点，形成模块间循环依赖风险；
- `apk` 的公开 API 必须返回 `AxmlDoc` / `DexFile` 等下游类型，把下游格式泄漏给容器层使用者；
- 只要下游解析库升级或报错，`apk` 的 API 被迫跟着变；
- 与「零跨模块 import」（§2）直接冲突。

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
| `Apk::native_libs(Abi?)` | `Array[NativeLib { abi, path, bytes }]` | 按 `lib/<abi>/` 目录归类；`NativeLib::elf_abi()` 做 ELF 头交叉校验 |
| `Apk::resource_table()` | `ResourceTableRef?` | 轻量索引：全局字符串池 chunk |
| `Apk::resource_table_full()` | `ResTable?` | 完整展开（package/typeSpec/type/bag），详见 §6 |
| `Apk::signatures()` | `Array[SignatureInfo]` | 结构 + 摘要校验；`verified` 语义见 §5（**≠ 签名有效**） |
| `Apk::signature_checks()` | `Array[SignatureCheck]` | 逐项结构与摘要结论；`signature_verified` 恒 false |
| `Apk::entry(EntryName)` | `Bytes` | 惰性解压 |

组合根（见 §2）决定「先解析 manifest 还是先扫描 dex」，并把 `raw` / `bytes` 交给
`axml` / `dex` 解析器。`apk` 不 import、不调用、不返回任何下游类型。

补记（2026-11-07）：`resources.arsc` 的**完整解析器**曾计划归入 `axml`（与二进制 XML 共享字符串池与
ResChunk 头结构），`apk::resource_table()` 只产出原始字节/索引。本轮范围调整后，按「不得 import `axml`、
在 `apk` 内提供完整展开」的要求，`apk` 自建了字节级资源表解析（自有 `ResTable` 值类型，不返回下游类型）；
本条「容器层不编排下游解析、不返回下游类型」的结论**不变**。取舍与重复实现风险见 §6。

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
`API.md` 写明调用顺序，组合根测试覆盖；签名验证只做结构 + 摘要，`SignatureInfo.verified` 的语义
按 §5 严格限定为「结构合法且摘要一致」，不代表签名有效。

---

## 2. 零跨模块 import，模块间靠 Wire 契约 + 组合根（仅摘与 `apk` 相关的边界）

### 背景

`apk` 与 `axml`、`dex` 等共 11 个项目**每个都有自己的 `../moon.mod`**，是 11 个独立 MoonBit 模块
（不是同一模块内的 11 个包）。MoonBit 是名义类型系统：两个模块里结构完全相同的 `struct`
也不是同一类型。若把 `apk → axml + dex` 实现成编译期依赖，会产生循环依赖风险并把 `apk`
变成中心节点。

### 决策（与 `apk` 相关的边界）

1. **零跨模块 import**，本库可独立 `moon check`；`apk` 不依赖 `axml` / `dex`。
2. 跨模块只传**纯值**：`apk` 对外的 `ManifestRef` / `DexEntry` / `NativeLib` / `ResourceTableRef`
   都是「名字 + 原始 `Bytes`」的 Blob Wire 值，与任何下游解析类型无关。
3. **组合根**（Composition Root）不是新库，而是未来 App 工程里的一段适配代码，负责：
   ① 用纯值在模块间构造目标类型；② 注入后端实现；③ 编排生命周期；④ 把下层错误映射为上层诊断。
   「是否调用 `axml` / `dex`、先解析什么后解析什么」全部由组合根决定（与 §1 一致）。
4. 抽象（trait，如 `ContainerIndex`）放在消费方，实现方不反向依赖。

### 理由

本库可独立开发 / 评审；API 边界写成中性值类型，天然满足「后端可替换、
实现细节不泄漏」（`ManifestRef.raw` / `DexEntry.bytes` 是 Blob Wire，上层可换成任意
AXML/DEX 解析器）；`moon check` 无外部依赖风险；避免模块循环。

### 后果

**正面**：并行开发；ZIP 实现可换包而不改上层签名。
**负面**：组合根需要少量显式适配代码；同构值类型存在结构漂移风险——由 `../pkg.generated.mbti`
API 快照对比守护。
**被替代方案**：合并为一个多包模块（破坏既有骨架，禁止）；发布到 mooncakes.io 后用真实
import（引入版本耦合，暂不做）。

---

## 3. 依赖引入五门槛与 `bobzhang/zip@0.1.2` 审计

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

版本锁定：依赖在 `../moon.mod` 的 `import` 中钉死版本（本库为 `bobzhang/zip@0.1.2`）；
`.mooncakes/` 是 moon 的本地依赖缓存目录，已被本仓库 `../.gitignore` 忽略——**不入库、
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
  `../moon.mod` + `../moon.pkg` + 解压路径，替换为自研 inflate 或改用存储条目策略，影响面不外溢。

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
  `../tests/fixtures/`，任何 ZIP 容器路径的实现改动必须过此回归样本（见 `../tests/ASSETS.md`）。
- **状态**：依赖结论（`bobzhang/zip@0.1.2` 维持现状、仅用 `deflate` 解压面）不变；
  上游修复建议（对 <4 字节 extra 尾部按对齐填充容忍）留档。

### 后果

`apk` 全部可独立 `moon check`；无网络 / 许可 / legacy manifest 风险叠加；任何门槛不通过的
依赖不得引入。

---

## 4. 开发排序：`apk` 提前到第一批开发，不等 `axml` / `dex`

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

本库与其它模块可独立推进、互不阻塞；对调用方契约冻结的要求提高——实现前需先冻结 API，
否则并行项会互相等待（本库以 `../pkg.generated.mbti` API 快照 + `API.md` 对账落实）。

---

## 5. 签名 `verified` 语义：结构 + 摘要校验通过 **≠** 签名有效

### 背景

早期实现只做「签名块定位 + 方案识别」，`SignatureInfo.verified` 恒为 `false`。这避免了误报，
但没有利用本地可验证的信息：APK 签名方案本身包含**内容摘要**（v2/v3）与 JAR 清单摘要（v1），
这些摘要不依赖私钥即可重算比对。另一方面，MoonBit 没有密码学 stdlib，本库也没有实现
RSA/ECDSA/DSA 公钥运算，无法完成真正的验签。

### 决策

`SignatureInfo.verified` 的语义被严格定义为：

> **`verified == true` ⟺ 签名结构解析通过 **且** 本地可验证的摘要全部一致。**
> 它**不代表签名有效**：本库不做 RSA/ECDSA/DSA 公钥验签、不做证书链校验、不校验证书信任。

同时新增 `Apk::signature_checks() -> Array[SignatureCheck]` 暴露逐项结论：
`structure_ok` / `digest_ok` / `digest_algorithm` / `entries_checked` / `entries_failed`，
以及**恒为 `false`** 的 `signature_verified`（机器可读的边界标记）。

本地实际执行的校验：

- **v1（JAR）**：解析 `META-INF/MANIFEST.MF`（section / 续行 / CRLF）、逐条目重算
  `SHA-256-Digest` 并与清单比对；解析 `META-INF/*.SF` 的 `SHA-256-Digest-Manifest`
  并与整份 MANIFEST.MF 比对；解析 `META-INF/*.RSA|DSA|EC` 的 PKCS#7 DER 外层结构并提取证书。
- **v2/v3/v3.1**：解析 signer 的 `digests` 序列（算法 ID + 摘要），按 AOSP 规范重算 APK
  内容分块摘要：section1 = 条目区、section2 = 中央目录、section3 = 改写 CD 偏移后的 EOCD；
  每 1 MiB 分片摘要 = `SHA-256(0xa5 || chunk_len_u32le || chunk)`，
  内容摘要 = `SHA-256(0x5a || chunk_count_u32le || concat(chunk_digests))`；与签名块中
  SHA-256 摘要比对。
- **SHA-256**：纯 MoonBit 实现（FIPS 180-4，NIST 向量白盒测试）。

### 边界（**必须如实对外表述**）

- **不做** RSA/ECDSA/DSA 验签；`verified == true` 不能表述为「签名有效 / 已验签」。
- **不做**证书链、信任锚、吊销、时间戳校验；`certificates` 只是 DER 原始字节。
- SHA-512 / verity / 其他内容摘要算法：算法字段可解析，但**未实现摘要**，`digest_ok=false`
  并在 `detail` 说明（`[仍需实测]` 真实 SHA-512 样本）。
- v1 摘要算法只实现 SHA-256；`SHA-1-Digest` / `SHA-512-Digest` 清单条目会标记为不支持。
- 摘要通过只证明「文件内容与签名块/清单中记录的摘要一致」；攻击者若能同时改写内容与摘要
  （例如重新签名），摘要仍会一致——这正是必须公钥验签的原因。

### 证据

- 真实受控样本 `tvshell-debug.apk`（v1+v2+v3）与 `fx-multidex-v2v3.apk`：`structure_ok` 与
  `digest_ok` 全为 true；`fx-multidex-v1.apk` 的 4 个清单条目摘要 + MANIFEST 摘要全通过。
  工具侧独立基准：`apksigner verify --verbose` 对同一样本输出 `Verifies`（开发期复核）。
- 合成 v1 样本（测试内 DER/MANIFEST 构造）覆盖：摘要不一致、MANIFEST 摘要错误、PKCS#7 结构
  非法、缺 `.SF` 四条失败路径，均如实返回 false 而非抛错/panic。
- **未做**：真实 SHA-512 签名样本、真实 v3.1 / 多签名者、证书链验证 → `[仍需实测]`。

---

## 6. resources.arsc 完整展开留在 `apk`（本轮范围取舍）

### 背景

`resources.arsc` 与二进制 XML 共享字符串池 / ResChunk 头，曾计划把完整解析器放在 `axml`，
`apk::resource_table()` 只给原始字节与全局字符串池。本轮任务要求在 `apk` 内完整展开
（package / typeSpec / type 条目 / 复杂 bag），且明确**不得 import `axml`**（零跨模块 import 约定）。

### 决策

- 在 `apk` 内新增**自有字节解析器**（`../arsc.mbt`）与**自有值类型**（`ResTable` / `ResPackage` /
  `ResTypeSpec` / `ResTypeConfig` / `ResEntry` / `ResBag` / `ResValue` / `ResConfig`），
  不 import、不调用、不返回 `axml` 的任何类型。
- 新增 `Apk::resource_table_full()` 与 `parse_resources_arsc(Bytes)`；保留 `resource_table()`
  的轻量路径（只切全局字符串池）以维持既有 API 与性能特征。
- 语义对齐 AOSP `ResourceTypes.h` / `LoadedArsc.cpp` 与 `axml` 的资源表实现：dense / OFFSET16 /
  SPARSE 三种 entry offset、compact entry、complex bag、config qualifier、未知 chunk 跳过。

### 理由

- 满足本轮「apk 内完整展开 + 零 import」的硬约束；消费方仍可只依赖 `apk` 获得完整资源索引。
- 与 §1 的「不返回下游类型」不冲突：`ResTable` 是 `apk` 自己的值类型，不是 `axml::ResTable`。

### 后果与风险

- **重复实现**：`apk` 与 `axml` 各有一套 arsc 解析代码，存在语义漂移风险。缓解：
  两侧都以 AOSP 结构为准；`apk` 侧用 `aapt2 dump resources` 作为工具侧独立基准做真实样本差分
  （`fx-multidex` 的 bool/color/string 三类型与 zh 配置逐值一致）。
- `apk` 侧不提供 aapt2 风格的值渲染、主题求值、bag 压平、动态包改写；这些仍属 `axml` 能力。
- 该取舍与既有「arsc 完整解析器归 axml」的排期判断不同，**已登记为本仓库待决项**（是否长期保留
  两份实现、或由组合根在两者间选择）。

---

## 7. 原生库 ABI：目录归类为权威，ELF 头做内容侧交叉校验

### 背景

`native_libs()` 的 ABI 一直来自 `lib/<abi>/` 目录名（与 aapt2 `native-code` 口径一致），
但既有内嵌样本均无 `.so`，非空路径缺乏测试证据；真实第三方 `.so` 因许可不明不能入库。

### 决策

1. `NativeLib.abi` **继续以目录名为权威**（容器层不解析 ELF 语义，保持 `native_libs` 轻量）。
2. 新增 `NativeLib::elf_abi() -> Abi raise ApkError`：只读 ELF 头（magic / EI_CLASS / EI_DATA /
   `e_machine`），给出内容侧 ABI；非法 ELF 报 `BadElf(offset, detail)`。
3. 两者不一致（如目录写 `x86_64`、ELF 头是 AArch64）**不改写 `NativeLib.abi`**，由调用方通过
   两个值发现错标；这是审计场景需要的事实，而不是静默纠错。
4. 测试用**测试内构造的最小 ELF fixture**（不引入第三方二进制）覆盖 arm64-v8a / armeabi-v7a /
   x86 / x86_64 / riscv64 与坏 ELF 错误路径；真实第三方 `.so` 差分仍 `[仍需实测]`。

### 后果

- 非空 `.so` 的路径解析、ABI 归类、字节完整性、过滤、ELF 头一致性均有回归。
- 真实 `.so`（含压缩/加密/多架构混合）的行为仍未验证；目录名与 ELF 头不一致的真实样本也未取得。

---

## 8. ELF 只读侦察归 `apk`：容器条目自身元数据的加法性加深

### 背景

P2 阶段需要读出 `NativeLib.bytes`（即 `lib/<abi>/*.so` 条目字节）里的 ELF 结构：
`DT_NEEDED` 依赖库名、动态符号表（名字 / 是否已定义）、JNI 导出名、以及 Dart AOT
字节 marker。问题是：这类「读 ELF」能力应放在 `apk` 内，还是为它新建一个第 12 个模块？
同时，`ApkError` 是否需要为新增错误路径追加构造？

### 决策

1. **归 `apk`，不新增第 12 个模块**。本仓库的模块边界约定（记为 **ADR-0002**：模块集合冻结，
   不为单一能力新建第 12 模块；记为 **ADR-0003**：容器层禁止编排下游解析、禁止在公开 API
   返回下游类型、禁止成为模块图的中心节点）禁止的是「跨模块编排 + 下游类型泄漏 + 中心化」，
   **并不禁止** `apk` 读取自己条目里的字节。ELF 头 / `PT_DYNAMIC` / 动态符号表是
   `NativeLib.bytes` 这一**容器条目自身的元数据**，与 R4 已落地的
   `NativeLib::elf_abi()`（只读 ELF 头做 ABI 交叉校验，见 §7）**同构**：都是对同一份
   条目字节做只读索引，只是本节把索引从「头」加深到「动态段 / 符号表」。
   因此实现留在 `apk`（新增自有 `../elf.mbt` 与自有值类型 `ElfClass` / `ElfSymbol` /
   `ElfInfo`），不 import、不调用、不返回 `axml` / `dex` 等下游类型，`apk` 的容器层
   边界（§1 / §2）不变，也没有变成中心节点。
2. **不新增 `ApkError` 构造**（冻结纪律）。`../pkg.generated.mbti` 的公开错误集合属 API
   冻结面，追加错误变体是破坏性变更；R4 已为 ELF 头解析加入 `BadElf(offset, detail)`（见 §7），
   本节所有越界 / 截断 / 坏 magic / 坏 `EI_CLASS` / `EI_DATA` / 缺 `PT_DYNAMIC` /
   虚拟地址未落在 `PT_LOAD` / 坏 `DT_STRTAB` / 坏 `DT_HASH` 一律**复用**它，
   `offset` 取 `NativeLib.bytes` 内偏移、`detail` 写具体原因。这样 `../pkg.generated.mbti`
   相对 R4 只新增类型与方法（纯插入），既有签名与错误构造零改动。
3. **vaddr→offset 映射（`elf_vaddr_to_off`）是必需的**。`DT_STRTAB` / `DT_SYMTAB` /
   `DT_HASH` 的 `d_val` 是**虚拟地址**，而 `Bytes` 只有文件偏移；真实 `.so` 普遍带非零
   装载基址，`p_vaddr` 与 `p_offset` 并不相等。必须经过 `PT_LOAD` 的
   `[p_vaddr, p_vaddr + p_filesz)` 区间把虚拟地址映射为 `p_offset + (vaddr - p_vaddr)`，
   并校验结果落在文件内，否则会把整份文件读错或越界。（对比：`DT_NEEDED` 的 `d_val`
   是 strtab 内索引，不是虚拟地址，两者语义不同，不可混用。）测试用带非零装载基址
   `0x10000` 的合成 fixture 覆盖该映射，防止实现退化成 `vaddr == offset` 的平凡假设。

### 理由

- 归 `apk`：零跨模块 import（§2）保持成立；消费方仍可只依赖 `apk` 得到结构化只读索引；
  与 `elf_abi()` 同源，避免为「读 ELF」单开模块造成模块膨胀与重复解析。
- 不新增错误构造：遵守 API 冻结纪律，快照 diff 维持纯插入，CI 快照门禁可通过。
- vaddr→offset：ELF 装载语义的正确性前提；缺了它，任何带装载基址的真实 `.so` 都会被误读。

### 后果

- **正面**：`needed_libraries()` / `jni_exports()` / `elf_info()` 三个加法性 API 与三个
  `pub(all)` 值类型落地，既有签名零改动、错误集合零改动；ELF32 / ELF64 小端、
  非零基址、坏结构错误路径均有测试内合成 fixture 回归，不入库任何真实 `.so`。
- **负面 / 边界**：能力仍是**只读索引**——不做反汇编 / 符号执行 / 重定位展开 / ELF 装载；
  `dart_markers` 只是字节模式命中，不是 Dart AOT 快照格式解析（对象图 / 指令表语义
  `[仍需实测]`）；真实第三方 `.so` 的解析侧黄金差分仍 `[仍需实测]`。

