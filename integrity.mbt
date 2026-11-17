///|
/// 单条目完整性巡检结论（W1 批量完整性报告的值化出口）。
///
/// 语义：`ok == true` 当且仅当「解压成功 **且** 尺寸一致 **且** CRC-32 一致」；
/// 与 `Apk::entry` 的 raise 行为逐条目一致——`ok == false` 的条目，其 `entry(name)`
/// 必然 raise 对应的 `ApkError`，反之亦然。
pub(all) struct IntegrityCheck {
  /// 条目名（ZIP 内 `/` 分隔相对路径）。
  name : String
  /// 中央目录声明的未压缩字节数。
  declared_size : UInt64
  /// 实际解压字节数；`None` 表示未能解压（原因见 `error`）。
  actual_size : UInt64?
  /// 中央目录声明的 CRC-32。
  crc32_expected : UInt32
  /// 实际解压数据的 CRC-32；`None` 表示未能解压。
  crc32_actual : UInt32?
  /// 解压成功 且 尺寸一致 且 CRC-32 一致。
  ok : Bool
  /// 数据区 4 字节对齐（复用 `ZipEntryRef::is_aligned` 口径）。
  aligned : Bool
  /// 失败时的人类可读原因；成功为空串。
  error : String
}

///|
/// 批量完整性巡检：遍历全部条目，逐条目解压并核对尺寸与 CRC-32，返回不中断的值化结论，
/// 供 CI 合规初筛一次拿到全容器完整性。对齐 `SignatureCheck` 的既有值化风格。
///
/// - 条目级失败（坏 CRC、尺寸不符、不可解压等）**值化**为 `ok == false` + `error`，
///   不中断其余条目、**不新增错误变体**（复用既有 `extract_data` 的 `ApkError`）；
/// - 目录条目（名以 `/` 结尾）**跳过**（不计入返回数组）。
///
/// 关于 `raise`：本函数**不声明 raise**。中央目录索引在 `Apk::open` 时已完成结构校验，
/// 此后的逐条目解压失败均可值化为 `ok == false`，不存在独立于条目的「容器级失败」路径；
/// 声明一个永不触发的 raise 类型会被 `moon check --deny-warn` 判为 unused-error-type 警告，
/// 故按实现实情省略（dev-plan W1 草案的 `raise ApkError` 在此落地为「不 raise」）。
///
/// 内存口径：逐条目解压、即查即弃，不聚合全部字节；返回数组只持有标量结论，
/// 不持有解压内容。
pub fn Apk::integrity_checks(self : Apk) -> Array[IntegrityCheck] {
  let out : Array[IntegrityCheck] = []
  for e in self.entries {
    if e.name.has_suffix("/") {
      continue
    }
    let check = try {
      let data = extract_data(self.source, e)
      {
        name: e.name,
        declared_size: e.uncompressed_size,
        actual_size: Some(data.length().to_uint64()),
        crc32_expected: e.crc32,
        crc32_actual: Some(crc32_of(data)),
        ok: true,
        aligned: e.is_aligned,
        error: "",
      }
    } catch {
      err =>
        {
          name: e.name,
          declared_size: e.uncompressed_size,
          actual_size: None,
          crc32_expected: e.crc32,
          crc32_actual: None,
          ok: false,
          aligned: e.is_aligned,
          error: err.to_repr().to_string(),
        }
    }
    out.push(check)
  }
  out
}
