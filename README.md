# apk · APK 容器解析

> 独立发布单元 ｜ L1 逆向输入 ｜ `preferred_target = wasm` ｜ Apache-2.0
> 状态：`moon test` **156/156** 通过（2026-11-18 本机实测，另有 `#skip` 用例不计入）；本文件是本仓库**唯一**说明文档。
> 公开 API 以 `pkg.generated.mbti` 为准（由 `moon info` 生成，禁手工编辑）；加法性变更须登记簿记 + 快照审阅 + 快照门禁。

## 1. 定位与边界

把 APK（ZIP 容器）读成可信的条目索引与原始字节，供上层清单与代码解析消费。

**能力**

- 中央目录 / local 头索引与条目提取，支持多 dex（`classes*.dex`），拒绝 ZIP64
- aapt2 裸对齐填充兼容（`zipmin.mbt`）；v1 / v2 / v3 / v3.1 签名块结构解析与摘要校验
- **RSA 公钥验签**（W6，2026-11-18 加法子能力）：`Apk::verify_signatures()` 对 v1 的 CMS signerInfo 与 v2/v3/v3.1 的 RSA PKCS#1 v1.5 签名值做真实公钥验签
- `AndroidManifest.xml`、`resources.arsc`、`classes.dex` 等条目的定位与字节提取
- ELF 只读侦察：`DT_NEEDED`、`Java_*` JNI 导出、Dart AOT 标记（2026-11-10 加法性子能力）
- `apk-cli list` / `extract`（`--all` / `--entry` / `--json`）

**非目标**

- 不解析 AXML / DEX 语义，不编排下游解析，不返回下游类型
- 不做 Java 反编译、CFG、签名写入；不修改 APK
- `signature_verified` 恒为 false，只是结构字段，**不是签名有效性结论**
- 不 import 任何其他工作区模块
- ELF 只读侦察**不做**反汇编 / 符号执行 / 重定位展开 / ELF 装载；`dart_markers` 仅是字节模式命中，**不做** Dart AOT 快照对象图 / 指令表 / 版本语义解析
- `resources.arsc` 完整展开的**语义归属**判给外部 `axml` 库；本库 `resource_table_full` / `parse_resources_arsc` 自 2026-11-16 起**冻结不再增强**（API 冻结语义禁止删除，保留兼容）

## 2. 关键设计决策（本仓库自足记录）

- 容器层只产出 `Bytes` 与索引值（ADR-0003 主决策）；下游靠 Wire `Blob` 承接。
- 2026-11-16 裁决：`resources.arsc` 完整展开的**语义归属判给外部 `axml` 库**；本库 `resource_table_full` / `parse_resources_arsc` 自本日起**冻结不再增强**（API 冻结语义禁止删除，保留兼容）；跨库展开一致性差分由外部组合层承担，不在本仓库范围（详见 `docs/2026-11-16-container-trust-dev-plan.md` W9）。
- 2026-11-10 ELF 只读侦察以纯插入方式落地，不改原决策、`ApkError` 复用 `BadElf`。
- 2026-11-18 裁决（W6）：公钥验签立项但降级为**仅 RSA**（方案 B）。`verify_signatures()` 新增承载真验签结论；ECDSA P-256/P-384 挂起 `#skip`，对 ECDSA 签名 `crypto_verified` 恒 false（fail-closed）；`signature_verified` 恒 false 语义永不改变（详见 `docs/2026-11-16-container-trust-dev-plan.md` W6）。
- 唯一第三方依赖 `bobzhang/zip@0.1.2`（仅 deflate）；aapt2 在 1,028 个 local 头中 403 个写 1~3 B 裸填充，已规避并转永久回归。

## 3. 公开 API 索引（自动抽取 `pkg.generated.mbti` 的 `pub` 声明行；完整字段见快照）

```text
pub fn parse_certificate(Bytes) -> CertificateInfo raise ApkError
pub fn parse_resources_arsc(Bytes) -> ResTable raise ApkError
pub(all) enum Abi {
pub(all) struct Apk {
pub fn Apk::certificate_infos(Self) -> Array[CertificateInfo] raise ApkError
pub fn Apk::dex_files(Self) -> Array[DexEntry] raise ApkError
pub fn Apk::entries(Self) -> Array[ZipEntryRef]
pub fn Apk::entry(Self, String) -> Bytes raise ApkError
pub fn Apk::manifest(Self) -> ManifestRef raise ApkError
pub fn Apk::native_libs(Self, Abi?) -> Array[NativeLib] raise ApkError
pub fn Apk::open(Bytes) -> Self raise ApkError
pub fn Apk::resource_table(Self) -> ResourceTableRef? raise ApkError
pub fn Apk::resource_table_full(Self) -> ResTable? raise ApkError
pub fn Apk::signature_checks(Self) -> Array[SignatureCheck] raise ApkError
pub fn Apk::signatures(Self) -> Array[SignatureInfo] raise ApkError
pub fn Apk::verify_signatures(Self) -> Array[SignatureVerification] raise ApkError
pub(all) struct CertificateInfo {
pub(all) struct DexEntry {
pub(all) enum ElfClass {
pub(all) struct ElfInfo {
pub(all) struct ElfSymbol {
pub(all) struct ManifestRef {
pub(all) struct NativeLib {
pub fn NativeLib::elf_abi(Self) -> Abi raise ApkError
pub fn NativeLib::elf_info(Self) -> ElfInfo raise ApkError
pub fn NativeLib::jni_exports(Self) -> Array[String] raise ApkError
pub fn NativeLib::needed_libraries(Self) -> Array[String] raise ApkError
pub(all) struct ResBag {
pub(all) struct ResConfig {
pub fn ResConfig::is_default(Self) -> Bool
pub(all) enum ResDataType {
pub(all) struct ResEntry {
pub(all) enum ResEntryValue {
pub(all) struct ResLookup {
pub(all) struct ResMap {
pub(all) struct ResPackage {
pub(all) struct ResTable {
pub fn ResTable::find_id(Self, String, String) -> UInt32?
pub fn ResTable::lookup(Self, UInt32) -> ResLookup?
pub fn ResTable::lookup_all(Self, UInt32) -> Array[ResLookup]
pub fn ResTable::package_by_id(Self, Int32) -> ResPackage?
pub(all) struct ResTypeConfig {
pub(all) struct ResTypeSpec {
pub(all) struct ResValue {
pub(all) struct ResourceTableRef {
pub(all) struct SignatureCheck {
pub(all) struct SignatureInfo {
pub(all) enum SignatureScheme {
pub(all) struct SignatureVerification {
pub(all) struct ZipEntryRef {
```

## 4. 依赖、平台与许可

`bobzhang/zip@0.1.2`（唯一第三方依赖，仅用 deflate）；`preferred_target = wasm`；Apache-2.0。

## 5. 命令行与验证

- `moon run cmd/main --target native -- list <apk> [--json]` / `extract <apk> --entry <name> --out <file>` / `certs <apk> [--json]`；输出行 `ENTR|` `DEX|` `MANI|` `ARSC|` `LIB|` `CERT|`。
- 复验：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` 后检查 `pkg.generated.mbti` 无意外 diff。
- 本仓库为独立 Git 仓库，文档与 CI 均自包含，不依赖工作区其他目录。

## 6. 风险与未决

- `resources.arsc` 完整展开的**语义归属**已裁决判给外部 `axml` 库（见 §2 决策行）；本库 `resource_table_full` / `parse_resources_arsc` 冻结不再增强，无「未裁决去重」遗留。
- `verify_signatures()`（W6，公钥验签）已于 2026-11-18 裁决立项，采用**仅 RSA 降级**（方案 B）：M6-RSA-a/b 已落地 v2/v3/v3.1 与 v1 CMS signerInfo 的 RSA PKCS#1 v1.5 真验签；apksigner oracle 差分随后续档（M6-6）；ECDSA 分支 `crypto_verified` 恒 false（fail-closed，`#skip` 立项），`signature_verified` 恒 false 语义不变。
- 第三方 APK 许可不明，禁止入库；受控自建样本与哈希登记见本仓库 `tests/fixtures/`。
- `zip@0.1.2` 单人维护、star=0 的 bus factor 风险已登记，不阻断使用。

