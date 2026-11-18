# tests/ASSETS.md — fixture 哈希登记

> 本文件登记 `tests/fixtures/` 下全部受控样本的 SHA-256，作为黄金记录与许可红线的账本。
> 建立：2026-11-16 ｜ 口径：任何 fixture 变更须同步更新本表；哈希与黄金记录绑定（防「样本漂移假绿」）。
> 纪律：真实第三方样本（许可不明）**永不入库**，只允许「工作区外本地路径 + 本表登记 + `#skip`」形态。

## 现状（2026-11-16 实测 8 件）

| 文件名 | SHA-256 | 大小 (B) | 来源口径 |
|---|---|---|---|
| `base.apk` | `d5824d09a5e9e3d6109d9298e72a9887566d35b9a8f89a56de124d53af0a94c3` | 1179 | 受控自建 |
| `fx-multidex-unsigned.apk` | `a3578b414cfc15bed61c999b30e185d5c2ae1385924b818fdc3f57db257fa2e7` | 6058 | 受控自建 |
| `fx-multidex-v1.apk` | `a046c50eaa5c654c6be8c892a3af1ce10a5818867b0a5a1b02151004e4a2fd72` | 8070 | 受控自建 |
| `fx-multidex-v2v3.apk` | `e2a736c749636ea6f09172ed56eed43bd37dd6efa816ad48775e419a85b4eb2b` | 12550 | 受控自建 |
| `tvshell-debug.apk` | `24fa4f0be0731806612dafc486af3ecd5978bf22bb8272314ffc62a6b1492093` | 21208 | **来源待核** |
| `tvshell-debug.resources.arsc` | `1fa3cb291285348ec1b33c85e7317d989467707f4791c4e5302f2d312d1e18c8` | 40 | **来源待核** |
| `w7-arm64-v8a.so` | `b592662c7ff2744cbaa8392ed1a2de2616af0e6424958d4e3513e9d67e11118d` | 510 | 受控自建（`gen_elf_fixtures.py`） |
| `w7-libs.apk` | `b9c3e80d2e6630e355febd33ab1e64ef8b26d3f1b3222cb1664b3e55c79c296b` | 798 | 受控自建（`gen_elf_fixtures.py`） |

来源口径说明：
- 「受控自建」= 由本仓库测试生成器/脚本构造，Apache-2.0，可复现。
- 「来源待核」= 现有真实形态样本，来源未核实；**不追认为自产**，在来源核实前仅用于既有 L2 受控差分，不扩大其用途。
- W7 轨 A 的 `w7-arm64-v8a.so` / `w7-libs.apk` 由 `tests/fixtures/gen_elf_fixtures.py` 确定性合成（纯 Python 手工字节，无工具链依赖），Apache-2.0，可复现；嵌入在 `w7_test.mbt` 的内嵌字节与其逐字节一致。

## W6 inline 签名样本（`verify_wbtest.mbt` 内嵌，2026-11-18 实测 11 件）

> 这些样本不是独立文件，而是以十六进制内嵌在 `verify_wbtest.mbt` 的
> `fixture_apk_*()` 中；下表哈希对「字节串本身」计算，口径为内嵌字节。
> 生成器：`tests/fixtures/gen_w6_fixtures.py`（Python 标准库 + `cryptography`，
> 固定测试私钥 `TEST_KEY_PEM`，确定性；PSS 使用固定 salt = hLen）。
> 校验命令：`python tests/fixtures/gen_w6_fixtures.py --check verify_wbtest.mbt`
> （逐字节一致才返回 0）。来源口径：**受控自建**（Apache-2.0，可复现）。

| 名称（inline 函数） | SHA-256 | 大小 (B) |
|---|---|---|
| `fixture_apk_v2_ok` | `e55fced1cf9732a1fbc70c4dc36805f6a74095ee97317c9c246632cc15007554` | 1435 |
| `fixture_apk_v2_bad` | `4978a441c2c3bc0f9840bbd052d2e3c95d55ae0ee173dc30c3f83f11c2855eca` | 1435 |
| `fixture_apk_v2_pss256` | `487db2cddf45fa0c330b2a27d152f2c8ab01e771c758cc693a2bae8287f5cd4d` | 1435 |
| `fixture_apk_v2_pss512` | `b06a88065ed1f769af7855b90755c687d7d6f28ceb745e0f9e4a137d8b79b0e6` | 1467 |
| `fixture_apk_v2_sha512` | `b34d81a5cd394eba099f0f608432064ef02696ac5fe0bdde5e015529ed3ecdf6` | 1467 |
| `fixture_apk_v3_ok` | `37989ecb4b5275ca91683dfe8c60eee3ea95ebe67bdd59bbf0c13c2272796ba5` | 1443 |
| `fixture_apk_v31_ok` | `e1378c4de7bde5d8d0938f260b06575c189f28a71497874edf47ce350c75bcd2` | 1443 |
| `fixture_apk_ecdsa` | `b7546823180e5b890788f63b5f6d5ae6190a953191b9f9fd27ae70a8e6ae7d46` | 1307 |
| `fixture_apk_v1_ok` | `a9de89f18334742fbc929484380b41574016c1292e7570f48b667523177977c9` | 2102 |
| `fixture_apk_v1_bad` | `fc2446062b6a0564086ec846727faf77d0abab8c857abaf04079a225690d2a29` | 2102 |
| `fixture_apk_v1_noattr` | `a6ea6f4a2dabdb5af46d5b355a57a1e957bf8e8d33bd29f6a034c1b7c4f7abdc` | 1931 |

## 变更规则

1. 新增 fixture 必须先核来源、再登记哈希，与黄金记录同提交。
2. 任何 fixture 字节变更（含重生成）须同步更新本表，禁止只改黄金不改哈希。
3. 真实第三方样本（F-D 类）只在 `tests/local_real_diff.py`（W7 轨 B）中以工作区外路径 + 本表登记哈希形式承载，永不入库。
