# apk 容器信任与功能补齐开发文档

> 建立：2026-11-16 ｜ 状态：W1 ✓ W2 ✓ W3 ✓ W4 ✓ W5 ✓ W7 ✓ W8 ✓（M4，2026-11-17）＋ W6 已裁决（仅 RSA 降级）｜ M6-RSA-a ✓ + M6-RSA-b ✓ + M6-RSA-fix ✓ + M6-6 ✓（2026-11-18，v1/v2/v3/v3.1 RSA 真验签 163/163 全绿）｜ W6-hardening-1..5 ✓（2026-11-18，oracle 6/6 AGREE，186/186 全绿）｜ W5-后续 ✓（2026-11-18，fs-verity 树重算 + v2/v3 verity 摘要比对，211/211 全绿）｜ W6-后续 里程碑 a/b/c ✓（2026-11-18，ECDSA P-256/P-384 曲线原语 + RFC 6979 向量 + 接入 v2/v3/v3.1 与 v1 CMS，`ecdsa_verify_raw` 公开入口；当前 `moon test` 221/221 全绿） ｜ 适用仓库：本仓库（hnlyxiaobing/apk，独立自包含）
> 配套文档：[2026-11-16-test-system-design.md](2026-11-16-test-system-design.md)（测试系统设计，工作包验收测试 ID 以 `T-` 开头者均出自该文档）
> 本文所有「现状」结论均为 2026-11-16 对本仓库源码的实测核对，非转述历史文档。

---

## 0. 现状基线（实测核对，开发前必读）

| # | 事实 | 证据位置 |
|---|---|---|
| B1 | **CRC32 已逐条目校验**：`extract_data` 解压后计算 `crc32_of(out)` 与中央目录 `crc32` 比对，不一致 raise `BadCentralDirectory`（fail-closed） | `apk.mbt` `extract_data` 末段 |
| B2 | stored/deflate 尺寸一致性、加密条目拒绝、未知压缩方法拒绝均已实现 | `apk.mbt` `extract_data` |
| B3 | **SHA-512 已实现并接入 v2/v3/v3.1 内容摘要**（算法 ID 0x0102/0x0105）；`crypto.mbt` 含 FIPS 180-4 已知向量测试 | `crypto.mbt`、`signature.mbt` `content_digest_algorithm_name` |
| B4 | **v1 摘要仅支持 SHA-256**；其他算法计入 `unsupported`，`digest_ok=false`（fail-closed） | `signature.mbt` v1 校验分支 |
| B5 | `signature_verified` 恒 false（三处构造点硬编码 + 测试断言）；`SignatureInfo.verified` 语义 = 结构合法且摘要一致，**不是签名有效** | `signature.mbt`、`apk.mbt` `SignatureInfo`  doc 注释 |
| B6 | `SignatureInfo.certificates : Array[Bytes]` 只含 DER 原始字节，**无结构化证书解析** | `pkg.generated.mbti` |
| B7 | CLI `extract --all` 已有写盘前整体路径安全预检 + 声明大小预检 + 解压后大小复核（256 MiB） | `cmd/main/main.mbt` |
| B8 | **解压后大小复核发生在 `@deflate.inflate` 完整解压之后**：伪造小声明size + 巨大 deflate 流可先耗尽内存再被拒 | `cmd/main/main.mbt`、`apk.mbt` |
| B9 | `@deflate.inflate`（bobzhang/zip@0.1.2，版本钉死）是**一次性解压接口**，无流式/限额参数，不可修改依赖 | `apk.mbt` 调用点 |
| B10 | ELF 侦察深度上限已写在代码注释（不做反汇编/重定位/装载/Dart 快照语义），但 **README「非目标」未收录** | `elf.mbt` 文件头 |
| B11 | `resources.arsc` 完整展开在本库与外部 axml 库各有一份实现，归属未裁决 | `arsc.mbt`、README §2 |
| B12 | 真实第三方 `.so` ABI 黄金差分、真实 APK 容器差分均为 `#skip`，**未执行**（许可不明样本不入库） | `elf_test.mbt`、`fixtures_test.mbt` 末尾 |
| B13 | `apk/docs/` 此前为空目录，但 `apk.mbt`/`apk_test.mbt` 等注释引用了不存在的 `docs/DESIGN.md`、`docs/DECISIONS.md`、`docs/API.md` | 源码注释 vs 目录实测 |
| B14 | verity 签名块（ID 0x42726577）与公钥验签均未实现 | `signature.mbt` 全文 |
| B15 | `tests/ASSETS.md` 被 `fixtures_test.mbt`/`elf_test.mbt`/CLI 帮助文本引用，但**实际不存在**（`tests/` 下仅有 `fixtures/` 6 件样本，无哈希登记文件） | 目录实测 |

**对历史口径的修正**：外部兼容性文档中「zipmin 无 CRC 校验」描述的是其他模块 CLI 的最小 ZIP 解析器，**不适用本库**（见 B1）。本库真正的完整性缺口是 B8（内存上限时序）与「无批量完整性报告 API」，不是 CRC 本身。

---

## 1. 硬约束（每个工作包都必须满足）

1. **API 冻结**：`pkg.generated.mbti` 为冻结基线。只允许**纯加法**（新增 pub fn / 新增 struct / 新增 enum）。
   - 禁止给既有 `pub(all)` struct 加字段（下游构造/模式匹配会破坏）；
   - 禁止新增 `ApkError` 变体——按冻结语义属破坏性变更，须「ADR + 用户裁决 + API-CHANGELOG + 主版本提升」四件齐备才可例外。**本文所有设计均规避新错误变体**：校验失败一律用**值字段**（Bool/枚举状态）表达，解析失败复用既有变体。
2. **加法三件套**：每个工作包合入须 ① `moon info` 快照随源码同提交且 diff 纯加法；② API-CHANGELOG 登记（本仓库自包含口径：在 README §2 追加决策行 + 本目录 CHANGELOG 小节，见 §5）；③ CI 第 5 道快照门禁绿。
3. **依赖不动**：`bobzhang/zip@0.1.2` 仅用 deflate，版本钉死，不 fork、不升级、不新增第三方依赖。密码学（SHA-256/512 已有）与大数运算（W6）一律纯 MoonBit 自研。
4. **许可红线**：第三方 APK / `.so` / 模型一律不入库；真实样本差分只允许「工作区外本地路径 + SHA-256 登记 + `#skip` 显式跳过」形态（沿用 `tests/ASSETS.md` 既有纪律）。
5. **五门禁**：`moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` + 快照 diff，全绿才可合入；`#skip` 不得写成通过。
6. **边界不变量**：不解析 AXML/DEX 语义、不 import 其他模块、不修改 APK、不写签名；`signature_checks()` 的 `signature_verified` **恒 false 语义永不改变**（W6 用新函数承载验签结论，见 §3.W6）。
7. **文档自包含**：本仓库文档不引用、不假定可访问工作区其他目录；跨库事务（如 arsc 一致性差分）只声明归属，不在本仓库实现。

---

## 2. 工作包总览

| 包 | 名称 | 优先级 | 规模 | API 影响 | 对应缺口 |
|---|---|---|---|---|---|
| W1 | 批量完整性报告 API | P0 | S | 加法：1 struct + 1 fn | B1 的值化出口 |
| W2 | 解压炸弹内存防线加固 | P0 | S | 加法：1 fn；CLI 内部增强 | B8/B9 |
| W3 | X.509 证书结构解析 | P1 | M | 加法：1 struct + 2 fn；CLI 新子命令 | B6 |
| W4 | v1 SHA-512 摘要支持 | P1 | S | 无（内部增强） | B4 |
| W5 | verity 签名块结构解析 | P2 | M | 加法：1 struct + 1 fn | B14 |
| W6 | 公钥验签（RSA/ECDSA，分阶段） | P3·须裁决 | XL | 加法：新 struct + 新 fn；旧语义不动 | B5/B14 |
| W7 | 真实 .so ABI 黄金差分（许可安全路径） | P1 | M | 无（测试资产） | B12 |
| W8 | Dart AOT 识别深化（仅识别） | P2 | S | 加法：1 struct + 1 fn | 目标样本为 Flutter/Dart AOT |
| W9 | 边界裁决与文档漂移清理 | P0 | S | 无（纯文档/注释） | B10/B11/B13 |

规模口径：S ≤ 1 个工作日；M ≤ 3 日；L ≤ 1 周；XL > 1 周且须里程碑拆分。

---

## 3. 工作包详细设计

### W1 批量完整性报告 API（P0/S）

**目标**：把「逐条目解压即校验、失败即 raise」的现状，补一个**不中断的批量巡检出口**，供 CI 合规初筛一次拿到全容器完整性结论。对齐 `SignatureCheck` 的既有值化风格。

**非目标**：不改变 `Apk::entry` 的 raise 语义；不做修复/重打包。

**新增 API（mbti 草案）**：

```text
pub(all) struct IntegrityCheck {
  name : String
  declared_size : UInt64
  actual_size : UInt64?      // None = 未能解压（错误原因见 error）
  crc32_expected : UInt32
  crc32_actual : UInt32?
  ok : Bool                  // 解压成功 且 尺寸一致 且 CRC 一致
  aligned : Bool             // 数据区 4 字节对齐（复用 ZipEntryRef.is_aligned 口径）
  error : String             // 失败时的人类可读原因；成功为空串
}
pub fn Apk::integrity_checks(Self) -> Array[IntegrityCheck] raise ApkError
```

**实现要点**：
- 新文件 `integrity.mbt`；遍历 `entries()`，逐条目调用既有 `extract_data` 并 `catch` 既有 `ApkError` 转为 `error` 字符串 + `ok=false`，**不新增错误变体**；
- 目录条目（name 以 `/` 结尾）跳过；
- `raise ApkError` 仅用于容器级失败（索引本身不可用），条目级失败一律值化；
- 内存注意：逐条目解压、即查即弃，不聚合全部字节。

**验收**：T-W1-1 全绿样本 `ok` 全 true；T-W1-2 坏 CRC 样本对应条目 `ok=false` 且其余条目不受影响；T-W1-3 与 `Apk::entry` 的 raise 行为逐条目一致（同一 fixture 双通道对照）；T-W1-4 快照 diff 纯加法。

### W2 解压炸弹内存防线加固（P0/S）

**目标**：闭合 B8——在**调用一次性 inflate 之前**建立可证明的内存上界，使伪造声明尺寸的恶意条目无法先耗尽内存。

**设计依据**：DEFLATE 理论最大膨胀比约 1032:1（RFC 1951 长度/距离编码上界 [已知常识，实现前用构造样本复核]）。因此 `compressed_size × 1032` 是该条目解压输出的** sound 上界**，无需流式接口即可在解压前拒绝。

**新增 API（mbti 草案）**：

```text
/// 限额提取：输出超过 limit 时返回 None（fail-closed，不产出部分数据）。
/// 解析错误仍 raise 既有 ApkError；limit <= 0 视为用法错误按 EntryNotFound 之外的
/// 既有变体 BadCentralDirectory(0, "invalid limit") 报告。
pub fn Apk::entry_capped(Self, String, Int64) -> Bytes? raise ApkError
```

**实现要点**：
- `apk.mbt` 内部新增 `extract_data_capped`（不动既有 `extract_data` 签名）：
  1. 声明尺寸预检：`uncompressed_size > limit` → 返回 None；
  2. 膨胀比预检（仅 method 8）：`compressed_size > limit / 1032`（整除向下取整，避免溢出用 UInt64 比较）→ 返回 None；
  3. 通过预检后才调用 `@deflate.inflate`，解压后复核 `actual <= limit`，超限返回 None；
  4. CRC/尺寸一致性校验复用既有逻辑；
- `cmd/main/main.mbt`：`--entry`/`--all` 路径改调 `entry_capped(name, 256 MiB)`，None → stderr + 退出码 1（对外契约不变，CLI 输出格式不变）；
- 既有 `Apk::entry` 行为完全不变（无默认限额，保持向后兼容）。

**验收**：T-W2-1 构造「声明 1 KiB、实际 deflate 流 > 256 MiB」样本，`entry_capped` 返回 None 且**进程峰值内存不随实际流大小增长**（预检即拒）；T-W2-2 边界 ±1 字节；T-W2-3 CLI 退出码/错误文案回归；T-W2-4 正常样本 `entry_capped` 与 `entry` 输出逐字节一致。

### W3 X.509 证书结构解析（P1/M）

**目标**：把 `SignatureInfo.certificates` 的 DER 字节变成可合规初筛的结构化事实（主体/颁发者/有效期/指纹/公钥算法）。**只解结构，不验签、不验证书链、不判信任**。

**新增 API（mbti 草案）**：

```text
pub(all) struct CertificateInfo {
  version : Int32                  // v1=0 / v3=2（X.509 原始编码值）
  serial_hex : String
  issuer : String                  // RFC 4514 风格 DN 字符串
  subject : String
  not_before : String              // "YYYY-MM-DDTHH:MM:SSZ"（UTCTime/GeneralizedTime 归一化）
  not_after : String
  signature_algo_oid : String      // 证书内签名算法 OID（点分十进制）
  public_key_algo_oid : String
  public_key_bits : Int32          // RSA 模长 / EC 曲线位长；无法判定为 -1
  sha256_fingerprint_hex : String  // 整份 DER 的 SHA-256，小写 hex
}
pub fn parse_certificate(Bytes) -> CertificateInfo raise ApkError
pub fn Apk::certificate_infos(Self) -> Array[CertificateInfo] raise ApkError
```

**实现要点**：
- 新文件 `cert.mbt`：最小 DER TLV 读取器（tag/len 短长型、构造位），只实现 Certificate 外层序列所需路径；未知扩展一律跳过不报错；
- 畸形 DER → 复用 `BadSigningBlock(off, reason)`；
- OID 解码为点分字符串；DN 只支持常见 RDN 类型（CN/O/OU/C/ST/L），未知类型输出 OID=hex 值，不 panic；
- `certificate_infos` 聚合 v1（PKCS#7 内证书）与 v2/v3/v3.1（signer certificates）去重输出（按 DER 字节相等去重）；
- CLI 加法：`apk-cli certs <apk> [--json]`，记录行 `CERT|subject|issuer|not_after|fingerprint`；退出码契约沿用 0/1/2；
- 时间解析不引入时区库，UTCTime 两位年按 X.509 规则（≥50 → 19xx，<50 → 20xx）[已知常识]。

**验收**：T-W3-1 受控样本证书指纹与 `apksigner verify --print-certs` 输出本地差分一致（oracle 可选执行，缺失显式 SKIPPED）；T-W3-2 畸形 DER 语料全数 raise 不 panic；T-W3-3 v1/v2/v3 三通道证书去重正确；T-W3-4 CLI JSON 字段稳定。

### W4 v1 SHA-512 摘要支持（P1/S）

**目标**：闭合 B4。v1 分支接受 `SHA-512-Digest` 条目属性与 `SHA-512-Digest-Manifest` 清单属性，与 SHA-256 并存（同一 MANIFEST 可混用，逐条目按各自算法校验）。

**实现要点**：
- `signature.mbt` v1 分支：`entry_digest_attr` 扩展识别 SHA-512 属性名；`alg == "SHA-512"` 时走既有 `sha512`（crypto.mbt 已有）；`unsupported` 计数逻辑保留给其余算法；
- `digest_algorithm` 字段已支持报告 "SHA-512"，无 API 变化；混合算法时报告首个识别算法并在 `detail` 注明混合；
- 不触碰 `signature_verified` 恒 false。

**验收**：T-W4-1 程序化构造 SHA-512 v1 样本（MANIFEST/.SF 手写 + PKCS#7 结构壳，无需真实私钥——本库不验签）`digest_ok=true`；T-W4-2 篡改一字节 → `entries_failed>0`；T-W4-3 SHA-256 既有回归零漂移；T-W4-4 未知算法仍 fail-closed。

### W5 verity 签名块结构解析（P2/M）

**目标**：识别并展开 APK Signing Block 中的 verity 块（ID `0x42726577`），输出 Merkle 树参数与根哈希，并可选重算全树比对。服务增量安装/分发完整性场景的**结构事实**，不做安装语义。

**新增 API（mbti 草案）**：

```text
pub(all) struct VerityInfo {
  block_id : UInt32
  version : Int32
  hash_algorithm : String      // "SHA-256" / "SHA-512" / "unknown"
  block_size : Int32           // 数据分块大小（字节）
  salt_hex : String
  root_hash_hex : String
  tree_size : UInt64
  tree_recomputed_ok : Bool    // 重算 Merkle 根与声明一致；未重算/失败均 false
}
pub fn Apk::verity(Self) -> VerityInfo? raise ApkError   // None = 无 verity 块
```

**实现要点**：
- `signature.mbt` 既有签名块遍历处加法挂接新 ID 分支（不改既有 v1/v2/v3/v3.1 路径）；
- 树重算：按 fs-verity 口径对 APK 内容区（签名块外字节）分块哈希、逐层聚合（SHA-256/512 已有）；盐前缀、块大小取块内声明；
- 结构畸形 → `BadSigningBlock`；算法未知 → `hash_algorithm="unknown"` 且 `tree_recomputed_ok=false`（fail-closed）；
- 实现前须以 AOSP 规范原文核对块内字段布局 [需联网核实：fs-verity Merkle 树在 APK 签名块内的确切序列化布局]，布局未核实前只交付「块识别 + 原始字节 + 声明字段」，树重算挂 `#skip` 显式缺口。

**验收**：T-W5-1 无 verity 块样本返回 None；T-W5-2 程序化构造合法 verity 块（自算根哈希）重算一致；T-W5-3 篡改任一内容块 → 重算不一致；T-W5-4 畸形块 raise 不 panic。

#### W5-后续：verity 树重算落地（2026-11-18 交付）

> **前置核实（2026-11-18 完成）**：联网核实 AOSP 源码确认块 ID `0x42726577` 为 `VERITY_PADDING_BLOCK_ID`（零填充对齐块），**不承载** root hash 或任何 Merkle 参数。APK 真实的 fs-verity Merkle 根位于 v2/v3/v3.1 **signed data 的 verity 内容摘要**中（签名算法 ID `0x0421`/`0x0423`/`0x0425`，40 字节 = `root_hash[32] || source_len(int64 LE)`）。fs-verity Merkle 树口径：SHA-256、8 字节全零 salt、4096 字节块、apk-verity 变体（源数据 = APK 字节扣除签名块区间，EOCD 中央目录偏移字段改写为 signing block offset），叶子层逐块加盐哈希、逐层聚合至 ≤4096 字节，根 = `sha256(salt || zero_pad(top))`，与 AOSP `VerityBuilder.generateApkVerityTree` 一致。

> **口径修正**：草案原计划“重算 Merkle 根与块内声明 `root_hash_hex` 比对”因前置核实确认块内无 `root_hash_hex` 而不可行；正确落地点为与 v2/v3/v3.1 **signed data verity 摘要根**比对。既有 `VerityInfo`（`Apk::verity()`）保留原语义不修改（`root_hash_hex` 恒为空、`tree_recomputed_ok` 恒 false），新增独立 API `Apk::verity_tree_check()` 承载真重算比对。

- **交付物**：新增 `verity_tree.mbt`（fs-verity Merkle 根重算实现 + `Apk::verity_tree_check` + 新结构 `VerityTreeCheck`）；扩展 `signature.mbt` 私有 `content_digest_algorithm_name` 识别 verity 摘要算法 ID；新增 `apk_test.mbt` fixture builder `scheme_value_with_verity_digest`；测试 `verity_tree_test.mbt`（黑盒：普通 v2 无 verity 摘要 → None、篡改声明根 fail-closed）+ `verity_tree_wbtest.mbt`（白盒：单/多块 Merkle 根独立核对、端到端 `tree_recomputed_ok==true` 成立、内容篡改 fail-closed）。
- **API 影响（纯加法）**：`pub(all) struct VerityTreeCheck` + `pub fn Apk::verity_tree_check(Self) -> VerityTreeCheck? raise ApkError`。
- **测试增量**：5 个新用例（W5-后续 T-W5-5/6/7/8 + 篡改用例，`verity_tree_test.mbt` + `verity_tree_wbtest.mbt`）。
- **独立交叉校验**：`docs/verify_verity_ref.py` Python 1:1 对照验证 Merkle 树算法（单块/多块/内部层），与 AOSP `calculateVerityLevelOffset` 分层一致；`docs/verify_verity_e2e.py` 端到端自洽构造含真实 verity 摘要的 APK（程序化构造 → 求根 → 嵌入摘要 → 再验根自洽）。
- **风险回顾**：草案标注的“最易重算通过但口径错误”风险已通过前置 AOSP 实时源码核实 + Python 对照消除；遵循真实 AOSP apk-verity 变体（盐 8 字节全零、偏移改写、分层聚合），不与任何自创口径混淆。

### W6 公钥验签（P3/XL，已裁决 2026-11-18：仅 RSA 降级立项）

> **裁决结论（2026-11-18，方案 B）**：立项，但**降级为仅 RSA**。ECDSA P-256/P-384 挂起不实现，`crypto_verified` 对 ECDSA 恒 false（fail-closed），显式 `#skip` 缺口。里程碑序列据此裁剪：M6-1→M6-2→M6-4(RSA 分支)→M6-5→M6-6（仅 RSA 样本）；M6-3（ECDSA 原语）与 v2/v3/v3.1 的 ECDSA 分支移除出本轮范围，留作独立后续裁决点。**（后续进展：ECDSA 已由下方 W6-后续 里程碑 a/b/c 全量实现并接入调度链，2026-11-18。）**

**目标**：在**不改变任何既有语义**的前提下，新增真验签通道：v1 CMS/PKCS#7 SignedData 签名值验证 + v2/v3/v3.1 signer 签名值验证（RSA PKCS#1 v1.5 与 ECDSA P-256/P-384）。

**语义防火墙（本包最重要的设计决策）**：
- `signature_checks()` / `SignatureCheck.signature_verified` **恒 false 永不改变**——它是历史契约与 fail-closed 基线；
- 验签结论走**新函数新类型**：

```text
pub(all) struct SignatureVerification {
  scheme : SignatureScheme
  structure_ok : Bool
  digest_ok : Bool
  crypto_verified : Bool     // 公钥验签通过；本类型独有，旧类型永不出现 true
  algo : String              // 如 "SHA256withRSA" / "SHA256withECDSA"
  detail : String
}
pub fn Apk::verify_signatures(Self) -> Array[SignatureVerification] raise ApkError
```

**里程碑（每个独立合入、独立门禁）**：
> **门禁现实（2026-11-18 记录）**：`moon check --deny-warn` 会把「仅被 `_wbtest`/`_test` 引用、无非测试消费方」的内部函数判为 `unused_value`（白盒测试不计入未用分析），因此**任何纯内部里程碑（如孤立的大数模块）都无法独立过门禁**。W6 唯一合法的非测试消费方是公开入口 `verify_signatures`，故 RSA 降级路径必须按「公开入口所在里程碑」聚合，原 M6-1/2/4/5 四等分合并为两档（各含公开入口 + 测试），见下。这不是范围缩减，仅过程聚合，最终交付物不变。
- **M6-RSA-a（合并原 M6-1/2/4，公开入口 v2/v3/v3.1）**：纯 MoonBit 无符号大数（Array[UInt32] limb：加/减/乘/模/模幂）+ RSA PKCS#1 v1.5 验证原语 + DigestInfo ASN.1 比对（SHA-256/512）+ v2/v3/v3.1 接入（signed data 按**长度前缀序列化字节**重序列化后验签）。随本档落公开 API：`SignatureVerification` 结构 + `Apk::verify_signatures`（**先只打通 RSA 分支**；v1 本期返回 fail-closed、后续档接入）。FIPS/已知向量测试（大数 + RSA）。
- **M6-RSA-b（原 M6-5）**：v1 接入：CMS SignedData 的 signerInfo 签名值验证（复用 W3 DER 读取器），并入 `verify_signatures` 的 v1 分支。已知向量测试。
- **M6-6 与 `apksigner verify` 本地 oracle 差分（真/假样本各 ≥3；2026-11-18 已实跑 6/6 AGREE）**。

**风险与止损**：大数/曲线实现是安全敏感代码，侧信道不在本库威胁模型内（离线分析工具），但**正确性必须向量全覆盖**；任一里程碑向量不过即停，不得带病推进。W6 主轮按方案 B 降级为仅 RSA（2026-11-18 裁决），风险压缩至大数模幂 + RSA 原语一处；ECDSA 曲线运算与 v2/v3/v1 接入随后经 W6-后续 里程碑 a/b/c 落地，并以 RFC 6979 向量 + 端到端调度链测试覆盖。

**验收**：T-W6-1 各算法 NIST/已知向量 100%；T-W6-2 apksigner 判 Verifies 的受控样本 `crypto_verified=true`；T-W6-3 篡改样本 false；T-W6-4 旧 API 行为逐字节回归零漂移；T-W6-5 不支持算法 fail-closed。

**W6 加固与验证补完（2026-11-18，M6 之后；不新增公开 API）**：

- **畸形/位翻转回归**：签名块头与长度字段、CMS SignedData（`sd_len`/`sigs_len`/`rec_len`/signers 序列）、X.509 SPKI（`pk_len`/算法标识/非 RSA）、DER INTEGER 与大数输入、签名长度 ≠ 模数长度、v1 `.SF` 位翻转/缺 `.SF` 均纳入 L1 语料（`fixtures_malformed_test.mbt` + `verify_wbtest.mbt` + `rsa_wbtest.mbt`）。口径：任意变异后只允许 `raise ApkError` 或 `structure_ok=false` / `crypto_verified=false`；未变异基线必须验签通过（防「全 false 假绿」）。实测未发现 panic。
- **模数上限**：RSA 验签入口（PKCS#1 / PSS / v1 CMS / v2-v3）对模数 bit 长设 8192 位硬上限，超限值化返回 `crypto_verified=false`，detail=`"key too large"`，不新增 `ApkError` 变体、不进入模幂；65544 位模数用例有界返回。
- **真实 oracle**：build-tools r34 / apksigner 0.9 实跑 6 件样本（3 真 RSA + 3 篡改），**6/6 AGREE**（`compared=6 mismatches=0`，明细见 CHANGELOG W6-hardening-3）。M6-6 的「SKIPPED」状态由实跑结果覆盖；`fx-multidex-v2v3.apk` 缺 `META-INF/MANIFEST.MF`，apksigner 直接拒绝，仅做库内自一致校验。发现的真实缺陷：CLI `verify` 过去只要求 `crypto_verified`，已改为 `structure_ok && digest_ok && crypto_verified`。
- **fixture 可复现**：`tests/fixtures/gen_w6_fixtures.py`（仅标准库 + `cryptography`）生成 11 件 inline 样本，`--check` 与 `verify_wbtest.mbt` 字节一致；SHA-256 与来源口径登记在 `tests/ASSETS.md`。
- **覆盖率巡检**（`moon coverage report -- -f caret`；`moon coverage analyze` 因 `cms.mbt` 解析失败不可用）：四个安全敏感文件剩余 5 行，逐条登记为不可达防御分支：
  - `rsa.mbt:298`（`ps_len < 0`）：被 `em_len >= h_len + salt_len + 2` 守卫支配，代入 `salt_len = h_len` 后 `ps_len >= 0` 恒成立；
  - `rsa.mbt:329`（PSS 未知 hash）：未知 hash 时 `mgf1` 已返回空并在 `db_mask.length() != db_len` 处失败，无法到达；
  - `verify.mbt:59/63`（v1 `v1_sf`/`v1_block` 为 None）：`collect_signature_records` 对 V1 记录恒填 `Some`，属纵深防御；
  - `verify.mbt:111`（`content_digest` 返回 None）：v2/v3 记录存在即 `signing_block_off` 为 Some，且循环已过滤为 SHA-256/SHA-512。

**已知限制（本轮不解决，如实登记）**：

- PSS 的 salt 长度硬编码等于摘要长度（hLen，Android 口径）；RFC 8017 允许其他 salt 长度，本库对非 hLen salt 的签名判失败，属已知严格性限制（见 `rsa.mbt` `rsa_verify_pss` 注释）。
- 现有「已知向量」是与 `cryptography` 等二手实现交叉验证的结果，**不是 FIPS/NIST 权威向量**，不得表述为权威向量通过。
- `--self-test` 只是库内自洽（库对比自设期望值），不是外部裁判；T-W6-2/T-W6-3 的独立性依据是 W6-hardening-3 的 6 件 apksigner 实跑样本（3 真 + 3 篡改），样本规模有限，不构成全面保证。

#### W6-后续：ECDSA P-256/P-384 真验签（2026-11-18 里程碑 a/b/c 全部交付）

> **现状**：W6 原裁决降级为"仅 RSA"（方案 B），ECDSA 曲线运算（原 M6-3）不实现。本后续为解决该 `#skip` 的路径，分三档里程碑落地；截至 2026-11-18，**里程碑 a/b/c 全部实现并接入调度链**，`crypto_verified` 对真 ECDSA 签名可置 true（fail-closed 语义仅在签名非法/曲线不匹配/SPKI 解析失败时保持）。

**里程碑 a ✓（2026-11-18 交付）：曲线原语 + NIST 向量**

- **交付物**：`ecdsa.mbt`（secp256r1/P-256 + secp384r1/P-384 域参数、Jacobian 坐标点加/双倍/标量点乘、ECDSA 验签原语、公开入口 `ecdsa_verify_raw`）；`ecdsa_test.mbt`（黑盒：RFC 6979 A.2.5/A.2.6 真签名通过 / 篡改 fail-closed / 畸形十六进制 fail-closed / r=s=n 越界拒绝 / 未知曲线拒绝）；`ecdsa_wbtest.mbt`（白盒：域参数位长 p/n、基点与公钥在曲线判定、标量点乘 x·G==公钥、模逆自洽、真验签原语通过 / r/s 篡改失败 / 越界与坏公钥 fail-closed）。
- **API 影响（纯加法）**：`pub(all) enum EcCurve { P256 P384 Unknown }` + `pub fn ecdsa_verify_raw(EcCurve, String, String, String, String, String) -> Bool`。
- **向量来源**：RFC 6979 A.2.5（P-256，"sample" 消息的 SHA-256）与 A.2.6（P-384，"sample" 消息的 SHA-384），公钥 U、签名 (r,s) 均为标准值；SHA-256/SHA-384 消息哈希经 .NET 独立核算一致。
- **门禁现实满足**：`ecdsa_verify_raw` 本身即合法的公开入口，内部曲线原语通过它被公开引用，通过 `moon check --deny-warn` 的 `unused_value`（与 M6-RSA 的 `verify_signatures` 公开入口模式一致）。
- **性能**：Jacobian 坐标实现（1 次模逆/标量点乘），wasm debug 目标。

**里程碑 b ✓（2026-11-18 交付）：ECDSA 接入 v2/v3/v3.1**

`ecdsa.mbt` 新增 `ec_public_key_from_spki`（解析 EC SPKI，P-256/P-384）与 `ec_sig_from_der`（解析 DER `SEQUENCE{INTEGER r, INTEGER s}`）；`verify.mbt` `verify_v2_signers` 在 RSA 解析失败后尝试 EC SPKI，支持 `0x0201`(SHA256withECDSA) / `0x0202`(SHA512withECDSA)，两者皆失败才 fail-closed。`ecdsa_wbtest.mbt` 覆盖 SPKI/DER 正反用例 + RFC 6979 A.2.5 向量走 v2 调度链端到端（`crypto_verified=true`）+ 非 EC SPKI / 截断签名 / 篡改 r fail-closed（git `be5aad9`，`.mbti` 零 diff）。

**里程碑 c ✓（2026-11-18 交付）：ECDSA 接入 v1 CMS SignedData**

`cms.mbt` `cms_sig_alg_name` 识别 ecdsa-with-SHA256/SHA512（含 4.1 通配与 1.3.132.0.35 别名）置 `sig_alg=ECDSA`；`verify_v1_signer_info` 在 RSA SPKI 失败后尝试 EC SPKI，新增 ECDSA 分支（signedAttrs SET OF / .SF 内容），新增私有 `cms_ecdsa_verify`。`cms_wbtest.mbt` 覆盖 RFC 6979 A.2.5 向量手工装配 PKCS#7 走 v1 调度链（`crypto_verified=true`）+ DSA SPKI / RSA 密钥配 ECDSA / 截断 DER / 曲线不匹配 fail-closed（git `d26d1ff`，`.mbti` 零 diff）。

**修复（2026-11-18，git `1a7b732`）**：新增 `ec_hash_to_e`，按曲线阶 n 位长截取哈希最左侧 n_bits 位，修复 SHA-512 摘要（如 P-384+`0x0202`）直接取模导致的验签假阴性。

### W7 真实 .so ABI 黄金差分——许可安全路径（P1/M）

**目标**：闭合 B12 的 `#skip` 缺口，且不违反许可红线。双轨：

**轨 A（入库，确定性合成资产）**：
- 新增 `tests/fixtures/gen_elf_fixtures.py`：纯 Python 手工字节构造**结构完整的 ELF64/ELF32 动态库镜像**（ELF 头 + PT_DYNAMIC + DT_NEEDED/DT_SYMTAB/DT_STRTAB + 符号表含 `Java_*` 与 4 个 `_kDart*` marker + 正确 e_machine），不依赖任何工具链、字节确定可复现；
- 用既有程序化 ZIP builder 把生成的 `.so` 打进 `lib/<abi>/`，形成受控 APK fixture（入库，随本仓库 Apache-2.0）；
- 黄金记录：ABI 归类 × ELF 头交叉校验 × needed × JNI 导出 × marker 命中，逐字段断言；
- 与既有合成 ELF 测试的区别：既有测试只覆盖解析路径片段，本轨覆盖**容器→归类→侦察全链路**且 fixture 是文件形态（可被 CLI E2E 复用）。

**轨 B（不入库，真实样本本地差分）**：
- 新增 `tests/local_real_diff.py`（或 .ps1）：输入工作区外样本路径 + `tests/ASSETS.md`（W9 建立）登记的 SHA-256；哈希不符即拒绝执行（fail-closed）；
- 差分 oracle：`llvm-readelf -d --dyn-symbols`（存在时）规范化输出 vs 本库 `elf_info`；oracle 缺失 → 显式 SKIPPED 并打印原因，退出码 78 口径沿用仓库纪律；
- 真实样本结论只写「本地已差分 + 哈希 + 日期」，**不得**写成入库测试通过。

**验收**：T-W7-1 轨 A fixture 生成确定（两次运行 SHA-256 相同）；T-W7-2 全链路黄金断言绿；T-W7-3 轨 B 哈希门禁拒绝错误样本；T-W7-4 `elf_test.mbt` 既有 `#skip` 用例改注「轨 A 已覆盖结构链路；真实第三方样本差分仍 SKIPPED」——**#skip 不删除、不冒充**。

### W8 Dart AOT 识别深化——仅识别（P2/S）

**目标**：目标样本为 Flutter/Dart AOT，本库把「marker 命中」升级为「marker 符号定位」，为外部 Dart 快照解析器提供字节偏移。**绝不进入快照语义**（对象图/指令表/版本语义一律不做，与 `elf.mbt` 既有上限一致）。

**新增 API（mbti 草案）**：

```text
pub(all) struct DartSnapshotRef {
  marker : String     // 如 "_kDartIsolateSnapshotData"
  offset : UInt64     // 符号 st_value（文件内虚拟地址口径，文档注明）
  in_section : String // 所在节名（.rodata/.text 等；无法判定为空串）
}
pub fn NativeLib::dart_snapshot_refs(Self) -> Array[DartSnapshotRef] raise ApkError
```

**实现要点**：
- `elf.mbt` 内部解析 dynsym 时已读 st_value（新函数内部复用/扩展私有解析，不改 `ElfSymbol` 公开结构）；
- 只匹配既有 4 个 `_kDart*` 预设名；未定义符号（st_shndx=0）跳过；
- 节名由节头表区间判定；无节头表（被 strip）时 `in_section=""`，offset 仍输出。

**验收**：T-W8-1 W7 轨 A fixture 中偏移与生成器写入值逐一对账；T-W8-2 strip 节头表样本不 panic；T-W8-3 无 Dart 符号样本返回空数组；T-W8-4 快照 diff 纯加法。

### W9 边界裁决与文档漂移清理（P0/S，纯文档/注释）

1. **ELF 深度上限入 README**：把 `elf.mbt` 文件头既有声明（不做反汇编/符号执行/重定位展开/装载/Dart 快照语义）逐句收录进 README §1「非目标」；W8 合入时同步追加「不做快照对象图/指令表/版本语义」。
2. **arsc 归属裁决登记**：README §2 追加决策行——「`resources.arsc` 完整展开的**语义归属判给外部 axml 库**；本库 `resource_table_full`/`parse_resources_arsc` 自 2026-11-16 起**冻结不再增强**（API 冻结语义禁止删除，保留兼容）；跨库展开一致性差分由外部组合层承担，不在本仓库范围」。本包不改任何 arsc 代码。
3. **注释漂移清理**：`apk.mbt`/`apk_test.mbt`/`fixtures_test.mbt` 等对不存在的 `docs/DESIGN.md`、`docs/DECISIONS.md`、`docs/API.md` 的引用，改为指向 README 对应小节或本目录两份 2026-11-16 文档；逐处 grep 核对，不改动任何代码逻辑。
4. **建立 `tests/ASSETS.md`**（闭合 B15）：对现有 6 件 fixture 逐一计算 SHA-256，登记「文件名 / 哈希 / 来源口径（受控自建或待核）/ 登记日期」；来源不明的既有件（如 `tvshell-debug.apk`）标注「来源待核」而非追认自产；此后 fixture 变更须同提交更新登记。
5. **申报口径修正建议**（供仓库维护者向上游申报文档反馈，不在本仓库代写）：「后续：SHA-512/verity」应收紧为「后续：verity、v1 侧 SHA-512（W4）、公钥验签（W6）」；「防止解压炸弹耗尽内存」在 W2 合入前限定为「声明预检+解压后复核」。

**验收**：T-W9-1 `grep -r "docs/DESIGN\|docs/DECISIONS\|docs/API" *.mbt` 零命中（或全部指向实存文件）；T-W9-2 README 非目标含 ELF 上限与 arsc 冻结行；T-W9-3 `tests/ASSETS.md` 存在且 6 件 fixture 哈希与实测一致；T-W9-4 五门禁绿（纯注释/文档变更也须过快照门禁，确认 mbti 零 diff）。

---

## 4. 里程碑与合入顺序

```text
M0（第 1 日）      W9 文档裁决                       ← 零风险先行，确立值化风格
M1（第 2–3 日）    W1 批量完整性报告                  ← 首个能力+测试闭环
M2（第 4–6 日）    W2 内存防线 + W4 v1 SHA-512        ← 安全与摘要半环闭合
M3（第 7–9 日）    W3 证书解析 + W7 黄金差分双轨       ← 合规初筛能力成型
M4（当前）         W5 verity + W8 Dart 符号定位       ← 识别层纵深
M6（W6 公钥验签·仅 RSA，2026-11-18）  ← M6-RSA-a ✓ + M6-RSA-b ✓ + M6-RSA-fix ✓（算法 ID/PSS/v3 布局修正）+ M6-6 ✓（oracle 实跑 6/6 AGREE）+ W6-hardening-1..5 ✓；ECDSA 分支后续见 W6-后续
W5-后续（2026-11-18）  ← fs-verity Merkle 根重算 + v2/v3 verity 摘要比对 ✓（`Apk::verity_tree_check` + `VerityTreeCheck`，AOSP 布局核实后落地，口径修正见 §3.W5-后续）
W6-后续 里程碑 a/b/c（2026-11-18）  ← ECDSA P-256/P-384 曲线原语 + RFC 6979 向量 ✓（`ecdsa_verify_raw` + `EcCurve`，Jacobian 坐标 pure-MoonBit）＋ 接入 v2/v3/v3.1（b ✓）与 v1 CMS（c ✓）＋ 超长摘要截断修复 ✓；当前 `moon test` 221/221 全绿
```

排序判据：先零风险文档、再安全缺口、再高价值低成本能力、最后安全敏感大工程。每个工作包独立提交（一个包 ≥1 条实质 commit），独立过五门禁，互不阻塞。

## 5. 簿记与变更管理（本仓库自包含口径）

- 本目录新增 `CHANGELOG.md`（随 M0 建立）：每个工作包合入登记一条「日期 / 工作包 / 新增 pub 声明清单 / 快照 diff 结论（纯加法）/ 测试增量」；
- README §3 公开 API 索引随 `moon info` 快照同步更新（自动抽取，禁手编 mbti）；
- 破坏性变更需求（含新增 ApkError 变体）一律走「ADR + 用户裁决 + CHANGELOG + 主版本提升」四件例外流程，本文设计已全量规避。

## 6. 完成定义（DoD，逐包勾选）

- [ ] 新增 API 与本文 mbti 草案一致（偏差须回写本文并说明理由）
- [ ] 快照 diff 纯加法，CHANGELOG 已登记
- [ ] 对应 T-W*-* 验收测试全绿；`#skip` 项显式标注原因，未冒充通过
- [ ] 五门禁全绿；CLI 对外契约（记录行格式/退出码 0/1/2）零意外漂移
- [ ] 畸形语料下无 panic（测试系统 L1 截断扫描覆盖新增解析路径）
- [ ] 未引入新第三方依赖；未入库任何许可不明二进制
- [ ] README 能力/非目标同步更新；本文状态行更新为「已交付 + 日期」

## 7. 风险登记

| 风险 | 等级 | 缓解 |
|---|---|---|
| W2 膨胀比常数 1032 与实现不符 | 中 | 实现前构造最坏 deflate 流复核；预检取保守整除，宁拒勿爆 |
| W5 verity 块布局无权威样本 | 中 | 布局核实前只交付识别+声明字段，树重算 #skip 显式缺口 |
| W6 大数/曲线正确性 | 高 | NIST 向量全覆盖 + apksigner 差分 + 逐里程碑止损；旧语义防火墙隔离 |
| W3 畸形 DER 攻击面 | 中 | TLV 读取器全长度边界检查 + 畸形语料截断扫描（测试系统 L1） |
| 冻结语义误判（struct 加字段等） | 中 | 本文 §1 硬约束 + 快照门禁 fail-closed 兜底 |