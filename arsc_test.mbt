// resources.arsc 完整展开测试。
//
// L0：测试内程序化构造 arsc chunk（字符串池 / package / typeSpec / type / 三种 entry
// offset 编码 / simple / compact / complex bag / 多配置 / 未知 chunk 跳过）。
// L1：受控构建样本 fx-multidex-unsigned.apk 的真实资源表，期望值来自
//      `aapt2 dump resources`（工具侧独立基准）：
//        Package name=com.fx.multidex id=7f
//          bool  fx_flag  () true
//          color fx_tint  () #ff2255aa
//          string app_name () "Fx Multidex" / (zh) "Fx 多维"
//          string fx_action () "press"
// 错误路径：坏 table/chunk/typeSpec/entry offset/bag count/config 均报 ApkError 而非 panic。

///|
/// 写 u32 到 Array[Byte] 指定偏移（测试侧）。
fn a_set_u32(a : Array[Byte], off : Int32, v : Int32) -> Unit {
  a[off] = (v & 0xFF).to_byte()
  a[off + 1] = ((v >> 8) & 0xFF).to_byte()
  a[off + 2] = ((v >> 16) & 0xFF).to_byte()
  a[off + 3] = ((v >> 24) & 0xFF).to_byte()
}

///|
/// 写 u16 到 Array[Byte] 指定偏移（测试侧）。
fn a_set_u16(a : Array[Byte], off : Int32, v : Int32) -> Unit {
  a[off] = (v & 0xFF).to_byte()
  a[off + 1] = ((v >> 8) & 0xFF).to_byte()
}

///|
/// UTF-8 字符串池 chunk（测试样本使用 ASCII，字符数 == 字节数）。
fn a_pool(strings : Array[String]) -> Bytes {
  let data : Array[Byte] = []
  let offs : Array[Int32] = []
  for s in strings {
    offs.push(data.length())
    let b = @encoding/utf8.encode(s)
    data.push(b.length().to_byte())
    data.push(b.length().to_byte())
    push_bytes(data, b)
    data.push(b'\x00')
  }
  while data.length() % 4 != 0 {
    data.push(b'\x00')
  }
  let count = strings.length()
  let strings_start = 28 + 4 * count
  let size = strings_start + data.length()
  let out : Array[Byte] = []
  push_u16(out, 0x0001)
  push_u16(out, 28)
  push_u32(out, size)
  push_u32(out, count)
  push_u32(out, 0)
  push_u32(out, 0x100)
  push_u32(out, strings_start)
  push_u32(out, 0)
  for o in offs {
    push_u32(out, o)
  }
  push_bytes(out, Bytes::from_array(data[:]))
  Bytes::from_array(out[:])
}

///|
/// 顶层 RES_TABLE_TYPE（0x0002）。
fn a_table(global_pool : Bytes, packages : Array[Bytes]) -> Bytes {
  let body : Array[Byte] = []
  push_bytes(body, global_pool)
  for p in packages {
    push_bytes(body, p)
  }
  let out : Array[Byte] = []
  push_u16(out, 0x0002)
  push_u16(out, 12)
  push_u32(out, 12 + body.length())
  push_u32(out, packages.length())
  push_bytes(out, Bytes::from_array(body[:]))
  Bytes::from_array(out[:])
}

///|
/// RES_TABLE_PACKAGE_TYPE（0x0200，headerSize=288）。
fn a_package(
  id : Int32,
  name : String,
  type_pool : Bytes,
  key_pool : Bytes,
  children : Array[Bytes],
) -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, 0x0200)
  push_u16(out, 288)
  push_u32(out, 0)
  push_u32(out, id)
  let nb = @encoding/utf8.encode(name)
  for i = 0; i < 128; i = i + 1 {
    if i < nb.length() {
      push_u16(out, nb[i].to_int())
    } else {
      push_u16(out, 0)
    }
  }
  let ts = 288
  let ks = 288 + type_pool.length()
  push_u32(out, ts)
  push_u32(out, 0)
  push_u32(out, ks)
  push_u32(out, 0)
  push_u32(out, 0)
  push_bytes(out, type_pool)
  push_bytes(out, key_pool)
  for c in children {
    push_bytes(out, c)
  }
  a_set_u32(out, 4, out.length())
  Bytes::from_array(out[:])
}

///|
/// RES_TABLE_TYPE_SPEC_TYPE（0x0202）。
fn a_typespec(id : Int32, entry_count : Int32, flags : Array[Int32]) -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, 0x0202)
  push_u16(out, 16)
  push_u32(out, 16 + 4 * entry_count)
  out.push(id.to_byte())
  out.push(b'\x00')
  push_u16(out, 1)
  push_u32(out, entry_count)
  for f in flags {
    push_u32(out, f)
  }
  Bytes::from_array(out[:])
}

///|
/// RES_TABLE_TYPE_TYPE（0x0201）：`offsets` 为 dense u32 entry offsets（-1 = NO_ENTRY）。
fn a_type(
  id : Int32,
  flags : Int32,
  config : Bytes,
  offsets : Array[Int32],
  entries : Bytes,
) -> Bytes {
  let entry_count = offsets.length()
  let header_size = 20 + config.length()
  let entries_start = header_size + 4 * entry_count
  let out : Array[Byte] = []
  push_u16(out, 0x0201)
  push_u16(out, header_size)
  push_u32(out, entries_start + entries.length())
  out.push(id.to_byte())
  out.push(flags.to_byte())
  push_u16(out, 0)
  push_u32(out, entry_count)
  push_u32(out, entries_start)
  push_bytes(out, config)
  for o in offsets {
    push_u32(out, o)
  }
  push_bytes(out, entries)
  Bytes::from_array(out[:])
}

///|
/// 简单 ResTable_entry（size=8 + Res_value 8）。
fn a_entry_simple(key : Int32, data_type : Int32, data : Int32) -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, 8)
  push_u16(out, 0)
  push_u32(out, key)
  push_u16(out, 8)
  out.push(b'\x00')
  out.push(data_type.to_byte())
  push_u32(out, data)
  Bytes::from_array(out[:])
}

///|
/// compact ResTable_entry（FLAG_COMPACT，8 字节，key 为 u16、dataType 在 flags 高字节）。
fn a_entry_compact(key : Int32, data_type : Int32, data : Int32) -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, key)
  push_u16(out, 0x0008 | (data_type << 8))
  push_u32(out, data)
  Bytes::from_array(out[:])
}

///|
/// 复杂 ResTable_entry（bag）：parent + count + map 数组。
fn a_entry_complex(
  key : Int32,
  parent : Int32,
  maps : Array[(Int32, Int32, Int32)],
) -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, 16)
  push_u16(out, 0x0001)
  push_u32(out, key)
  push_u32(out, parent)
  push_u32(out, maps.length())
  for (name, dt, data) in maps {
    push_u32(out, name)
    push_u16(out, 8)
    out.push(b'\x00')
    out.push(dt.to_byte())
    push_u32(out, data)
  }
  Bytes::from_array(out[:])
}

///|
/// 默认 ResTable_config（size=4，无 qualifier）。
fn a_config_default() -> Bytes {
  let out : Array[Byte] = []
  push_u32(out, 4)
  Bytes::from_array(out[:])
}

///|
/// `zh` 语言 ResTable_config（size=12：mcc/mnc=0 + language="zh" + country=0）。
fn a_config_zh() -> Bytes {
  let out : Array[Byte] = []
  push_u32(out, 12)
  push_u32(out, 0)
  out.push(b'z')
  out.push(b'h')
  out.push(b'\x00')
  out.push(b'\x00')
  Bytes::from_array(out[:])
}

///|
/// 未知包内 chunk（0x0204 overlayable 占位）：解析器应跳过。
fn a_unknown_chunk() -> Bytes {
  let out : Array[Byte] = []
  push_u16(out, 0x0204)
  push_u16(out, 8)
  push_u32(out, 12)
  push_u32(out, 0)
  Bytes::from_array(out[:])
}

///|
/// 标准合成表：包 0x7f "com.test"，两类型（简单/多配置 + 复杂 bag）。
fn a_synthetic_table() -> Bytes {
  let global = a_pool(["hello", "zh-hello", "world"])
  let type_pool = a_pool(["string", "style"])
  let key_pool = a_pool(["name", "title", "k0", "k1"])
  let spec1 = a_typespec(1, 2, [0x40000000, 0x0])
  let simple_entries = s_cat(
    a_entry_simple(0, 0x03, 0),
    a_entry_simple(1, 0x12, 1),
  )
  let type1 = a_type(1, 0, a_config_default(), [0, 16], simple_entries)
  let type1_zh = a_type(
    1,
    0,
    a_config_zh(),
    [0, -1],
    a_entry_simple(0, 0x03, 1),
  )
  let spec2 = a_typespec(2, 1, [0x0])
  let complex_entry = a_entry_complex(2, 0x7f010000, [
    (0x7f010000, 0x03, 0),
    (0x7f010001, 0x10, 42),
  ])
  let type2 = a_type(2, 0, a_config_default(), [0], complex_entry)
  let pkg = a_package(0x7f, "com.test", type_pool, key_pool, [
    a_unknown_chunk(),
    spec1,
    type1,
    type1_zh,
    spec2,
    type2,
  ])
  a_table(global, [pkg])
}

///|
/// 展开标准合成表：包/类型/字符串池/条目/复杂 bag/多配置。
test "arsc expands package typeSpec type entries and bags" {
  let t = @apk.parse_resources_arsc(a_synthetic_table())
  assert_eq(t.package_count, 1)
  assert_eq(t.global_strings.length(), 3)
  assert_eq(t.global_strings[0], "hello")
  assert_eq(t.packages.length(), 1)
  let p = t.packages[0]
  assert_eq(p.id, 0x7f)
  assert_eq(p.name, "com.test")
  assert_eq(p.type_id_offset, 0)
  assert_eq(p.type_strings.length(), 2)
  assert_eq(p.type_strings[0], "string")
  assert_eq(p.type_strings[1], "style")
  assert_eq(p.key_strings.length(), 4)
  assert_eq(p.key_strings[3], "k1")
  assert_eq(p.types.length(), 2)
  // typeSpec 1：两条 spec flags + 两个配置变体。
  assert_eq(p.types[0].id, 1)
  assert_eq(p.types[0].entry_count, 2)
  assert_eq(p.types[0].spec_flags[0], 0x40000000U)
  assert_eq(p.types[0].configs.length(), 2)
  // 默认配置 + zh 配置。
  assert_true(p.types[0].configs[0].config.is_default())
  assert_eq(p.types[0].configs[1].config.language, "zh")
  assert_true(!p.types[0].configs[1].config.is_default())
  // 默认配置条目：name = string "hello"，title = bool true。
  match p.types[0].configs[0].entries[0] {
    Some(e) => {
      assert_eq(e.key_name, "name")
      match e.value {
        @apk.ResEntryValue::Simple(v) => {
          assert_true(v.data_type is @apk.ResDataType::String)
          assert_eq(v.data, 0U)
        }
        _ => fail("expected simple entry")
      }
    }
    None => fail("entry 0 missing")
  }
  match p.types[0].configs[0].entries[1] {
    Some(e) => {
      assert_eq(e.key_name, "title")
      match e.value {
        @apk.ResEntryValue::Simple(v) => {
          assert_true(v.data_type is @apk.ResDataType::IntBoolean)
          assert_eq(v.data, 1U)
        }
        _ => fail("expected simple entry")
      }
    }
    None => fail("entry 1 missing")
  }
  // zh 配置：entry 0 指向 "zh-hello"，entry 1 不存在。
  match p.types[0].configs[1].entries[0] {
    Some(e) =>
      match e.value {
        @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 1U)
        _ => fail("expected simple entry")
      }
    None => fail("zh entry 0 missing")
  }
  assert_true(p.types[0].configs[1].entries[1] is None)
  // 复杂 bag。
  match p.types[1].configs[0].entries[0] {
    Some(e) =>
      match e.value {
        @apk.ResEntryValue::Complex(bag) => {
          assert_eq(bag.parent, 0x7f010000U)
          assert_eq(bag.maps.length(), 2)
          assert_eq(bag.maps[0].name, 0x7f010000U)
          match bag.maps[0].value.data_type {
            @apk.ResDataType::String => assert_eq(bag.maps[0].value.data, 0U)
            _ => fail("expected string map value")
          }
          assert_eq(bag.maps[1].name, 0x7f010001U)
          assert_true(bag.maps[1].value.data_type is @apk.ResDataType::IntDec)
          assert_eq(bag.maps[1].value.data, 42U)
        }
        _ => fail("expected complex entry")
      }
    None => fail("complex entry missing")
  }
}

///|
/// 查询接口：lookup（默认配置优先）/ lookup_all / find_id / package_by_id。
test "arsc lookup and find_id follow default-config priority" {
  let t = @apk.parse_resources_arsc(a_synthetic_table())
  assert_true(t.package_by_id(0x7f) is Some(_))
  assert_true(t.package_by_id(0x7e) is None)
  let hit = match t.lookup(0x7f010000U) {
    Some(h) => h
    None => fail("lookup miss")
  }
  assert_eq(hit.package_name, "com.test")
  assert_eq(hit.type_name, "string")
  assert_eq(hit.entry_name, "name")
  match hit.entry.value {
    @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 0U)
    _ => fail("expected simple")
  }
  // app 名的第二个配置（zh）可在 lookup_all 中观察到。
  let all = t.lookup_all(0x7f010000U)
  assert_eq(all.length(), 2)
  assert_true(all[0].config.is_default())
  assert_eq(all[1].config.language, "zh")
  match all[1].entry.value {
    @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 1U)
    _ => fail("expected simple")
  }
  assert_true(t.find_id("string", "title") == Some(0x7f010001U))
  assert_true(t.find_id("style", "k1") is None)
  assert_true(t.lookup(0x7f020000U) is Some(_))
}

///|
/// compact entry（FLAG_COMPACT）解析。
test "arsc decodes compact entries" {
  let global = a_pool(["x"])
  let type_pool = a_pool(["integer"])
  let key_pool = a_pool(["answer"])
  let spec = a_typespec(1, 1, [0])
  let ty = a_type(1, 0, a_config_default(), [0], a_entry_compact(0, 0x10, 7))
  let pkg = a_package(0x7f, "com.compact", type_pool, key_pool, [spec, ty])
  let t = @apk.parse_resources_arsc(a_table(global, [pkg]))
  let e = match t.packages[0].types[0].configs[0].entries[0] {
    Some(e) => e
    None => fail("compact entry missing")
  }
  assert_eq(e.key_name, "answer")
  assert_true(e.flags == 0x1008)
  match e.value {
    @apk.ResEntryValue::Simple(v) => {
      assert_true(v.data_type is @apk.ResDataType::IntDec)
      assert_eq(v.data, 7U)
    }
    _ => fail("expected simple")
  }
}

///|
/// FLAG_OFFSET16 entry offsets（u16 * 4）。
test "arsc decodes FLAG_OFFSET16 entry offsets" {
  let global = a_pool(["a", "b"])
  let type_pool = a_pool(["string"])
  let key_pool = a_pool(["k0", "k1"])
  let spec = a_typespec(1, 2, [0, 0])
  let entries = s_cat(a_entry_simple(0, 0x03, 0), a_entry_simple(1, 0x03, 1))
  // offsets 为 u16 槽（raw*4）：entry0=0、entry1=4（即字节偏移 16）。
  let out : Array[Byte] = []
  let config = a_config_default()
  let header_size = 20 + config.length()
  let entries_start = header_size + 2 * 2
  push_u16(out, 0x0201)
  push_u16(out, header_size)
  push_u32(out, entries_start + entries.length())
  out.push(1)
  out.push(0x02)
  push_u16(out, 0)
  push_u32(out, 2)
  push_u32(out, entries_start)
  push_bytes(out, config)
  push_u16(out, 0)
  push_u16(out, 4)
  push_bytes(out, entries)
  let ty = Bytes::from_array(out[:])
  let pkg = a_package(0x7f, "com.o16", type_pool, key_pool, [spec, ty])
  let t = @apk.parse_resources_arsc(a_table(global, [pkg]))
  let cfg = t.packages[0].types[0].configs[0]
  match (cfg.entries[0], cfg.entries[1]) {
    (Some(a), Some(b)) => {
      assert_eq(a.key_name, "k0")
      assert_eq(b.key_name, "k1")
    }
    _ => fail("expected both entries")
  }
}

///|
/// FLAG_SPARSE entry offsets（(idx:u16, offset:u16) 表，offset*4）。
test "arsc decodes FLAG_SPARSE entry offsets" {
  let global = a_pool(["sparse"])
  let type_pool = a_pool(["string"])
  let key_pool = a_pool(["k0"])
  let spec = a_typespec(1, 2, [0, 0])
  let entries = a_entry_simple(0, 0x03, 0)
  let entries2 = s_cat(entries, entries)
  let config = a_config_default()
  let header_size = 20 + config.length()
  let entries_start = header_size + 4 * 2
  let out : Array[Byte] = []
  push_u16(out, 0x0201)
  push_u16(out, header_size)
  push_u32(out, entries_start + entries2.length())
  out.push(1)
  out.push(0x01)
  push_u16(out, 0)
  push_u32(out, 2)
  push_u32(out, entries_start)
  push_bytes(out, config)
  // (idx=3, offset=0), (idx=0, offset=4) —— sparse 表不要求有序。
  push_u16(out, 3)
  push_u16(out, 0)
  push_u16(out, 0)
  push_u16(out, 4)
  push_bytes(out, entries2)
  let ty = Bytes::from_array(out[:])
  let pkg = a_package(0x7f, "com.sparse", type_pool, key_pool, [spec, ty])
  let t = @apk.parse_resources_arsc(a_table(global, [pkg]))
  let cfg = t.packages[0].types[0].configs[0]
  assert_eq(cfg.entries.length(), 4)
  assert_true(cfg.entries[0] is Some(_))
  assert_true(cfg.entries[1] is None)
  assert_true(cfg.entries[2] is None)
  assert_true(cfg.entries[3] is Some(_))
}

///|
/// 真实受控样本 fx-multidex-unsigned.apk 的资源表（aapt2 工具侧基准）。
test "arsc real fixture fx-multidex matches aapt2 dump resources" {
  let apk = @apk.Apk::open(fixture_fx_multidex_unsigned_apk())
  let t = match apk.resource_table_full() {
    Some(t) => t
    None => fail("resources.arsc missing")
  }
  assert_eq(t.package_count, 1)
  assert_eq(t.packages.length(), 1)
  let p = t.packages[0]
  assert_eq(p.id, 0x7f)
  assert_eq(p.name, "com.fx.multidex")
  assert_eq(p.type_id_offset, 0)
  assert_eq(p.type_strings.length(), 3)
  assert_eq(p.type_strings[0], "bool")
  assert_eq(p.type_strings[1], "color")
  assert_eq(p.type_strings[2], "string")
  assert_eq(p.key_strings.length(), 4)
  assert_eq(p.key_strings[0], "fx_flag")
  assert_eq(p.key_strings[1], "fx_tint")
  assert_eq(p.key_strings[2], "app_name")
  assert_eq(p.key_strings[3], "fx_action")
  assert_eq(p.types.length(), 3)
  assert_eq(t.global_strings.length(), 3)
  assert_eq(t.global_strings[0], "Fx Multidex")
  assert_eq(t.global_strings[1], "press")
  assert_eq(t.global_strings[2], "Fx 多维")
  // bool/fx_flag = true
  let bool_hit = match t.lookup(0x7f010000U) {
    Some(h) => h
    None => fail("bool miss")
  }
  assert_eq(bool_hit.entry_name, "fx_flag")
  match bool_hit.entry.value {
    @apk.ResEntryValue::Simple(v) => {
      assert_true(v.data_type is @apk.ResDataType::IntBoolean)
      assert_eq(v.data, 0xFFFFFFFFU)
    }
    _ => fail("bool should be simple")
  }
  // color/fx_tint = #ff2255aa
  let color_hit = match t.lookup(0x7f020000U) {
    Some(h) => h
    None => fail("color miss")
  }
  match color_hit.entry.value {
    @apk.ResEntryValue::Simple(v) => {
      assert_true(v.data_type is @apk.ResDataType::IntColorArgb8)
      assert_eq(v.data, 0xFF2255AAU)
    }
    _ => fail("color should be simple")
  }
  // string/app_name：默认 "Fx Multidex"，zh "Fx 多维"；默认配置优先。
  let app_hit = match t.lookup(0x7f030000U) {
    Some(h) => h
    None => fail("app_name miss")
  }
  assert_true(app_hit.config.is_default())
  match app_hit.entry.value {
    @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 0U)
    _ => fail("app_name should be simple")
  }
  let app_all = t.lookup_all(0x7f030000U)
  assert_eq(app_all.length(), 2)
  assert_eq(app_all[1].config.language, "zh")
  match app_all[1].entry.value {
    @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 2U)
    _ => fail("zh app_name should be simple")
  }
  // string/fx_action = "press"（global pool index 1）
  let action_hit = match t.lookup(0x7f030001U) {
    Some(h) => h
    None => fail("fx_action miss")
  }
  match action_hit.entry.value {
    @apk.ResEntryValue::Simple(v) => assert_eq(v.data, 1U)
    _ => fail("fx_action should be simple")
  }
  assert_true(t.find_id("string", "fx_action") == Some(0x7f030001U))
}

///|
/// 空资源表（tvshell/base 的 40 字节 arsc）：完整展开应成功且 0 包。
test "arsc parses empty tables from real fixtures" {
  for
    apk in [
      @apk.Apk::open(fixture_tvshell_apk()),
      @apk.Apk::open(fixture_base_apk()),
    ] {
    let t = match apk.resource_table_full() {
      Some(t) => t
      None => fail("resources.arsc missing")
    }
    assert_eq(t.package_count, 0)
    assert_eq(t.packages.length(), 0)
    assert_eq(t.global_strings.length(), 0)
  }
}

///|
/// 无 resources.arsc 的 APK 返回 None。
test "arsc returns none without resources.arsc" {
  let apk = @apk.Apk::open(build_zip([zspec("a.txt", b"x")], None))
  assert_true(apk.resource_table_full() is None)
}

///|
/// 错误路径：坏顶层类型 / 截断 / 坏包头 / 坏 typeSpec / 坏 entry offset / 坏 bag。
test "arsc malformed inputs raise ApkError not panic" {
  // 非 RES_TABLE_TYPE。
  try
    ignore(
      @apk.parse_resources_arsc(
        b"\x03\x00\x0c\x00\x0c\x00\x00\x00\x00\x00\x00\x00",
      ),
    )
  catch {
    @apk.ApkError::BadResourceTable(0, _) => ()
    _ => fail("expected BadResourceTable for non-table chunk")
  } noraise {
    _ => fail("expected BadResourceTable")
  }
  // 截断：完整表切掉尾部 32 字节。
  let good = a_synthetic_table()
  let cut = good[0:good.length() - 32].to_owned()
  let mut raised = false
  try ignore(@apk.parse_resources_arsc(cut)) catch {
    _ => raised = true
  } noraise {
    _ => ()
  }
  assert_true(raised, msg="truncated arsc must raise")
  // 包头 headerSize 过小。
  let gp = a_pool(["hello", "zh-hello", "world"])
  let pkg_off = 12 + gp.length()
  let bad_pkg = good.to_array()
  a_set_u16(bad_pkg, pkg_off + 2, 8)
  let mut pkg_raised = false
  try ignore(@apk.parse_resources_arsc(Bytes::from_array(bad_pkg))) catch {
    _ => pkg_raised = true
  } noraise {
    _ => ()
  }
  assert_true(pkg_raised, msg="bad package header must raise")
  // typeSpec entryCount 超出 chunk。
  let spec_entries = a_entry_simple(0, 0x10, 1)
  let spec = a_typespec(1, 1, [0])
  let ty = a_type(1, 0, a_config_default(), [0], spec_entries)
  let gp2 = a_pool(["x"])
  let tp = a_pool(["t"])
  let kp = a_pool(["k"])
  let pkg = a_package(0x7f, "com.bad", tp, kp, [spec, ty])
  let table = a_table(gp2, [pkg]).to_array()
  let spec_at = 12 + gp2.length() + 288 + tp.length() + kp.length()
  a_set_u32(table, spec_at + 12, 0x10000)
  let mut spec_raised = false
  try ignore(@apk.parse_resources_arsc(Bytes::from_array(table))) catch {
    _ => spec_raised = true
  } noraise {
    _ => ()
  }
  assert_true(spec_raised, msg="bad typeSpec entryCount must raise")
  // entry offset 指向 chunk 外。
  let bad_type = a_type(
    1,
    0,
    a_config_default(),
    [0x100],
    a_entry_simple(0, 0x10, 1),
  )
  let pkg2 = a_package(0x7f, "com.bad2", a_pool(["t"]), a_pool(["k"]), [
    a_typespec(1, 1, [0]),
    bad_type,
  ])
  let mut off_raised = false
  try ignore(@apk.parse_resources_arsc(a_table(a_pool(["x"]), [pkg2]))) catch {
    _ => off_raised = true
  } noraise {
    _ => ()
  }
  assert_true(off_raised, msg="entry offset beyond chunk must raise")
  // bag map count 超出 chunk。
  let bad_bag = a_entry_complex(0, 0, [(0x7f010000, 0x10, 1)])
  let bag_arr = bad_bag.to_array()
  a_set_u32(bag_arr, 12, 1000)
  let pkg3 = a_package(0x7f, "com.bad3", a_pool(["t"]), a_pool(["k"]), [
    a_typespec(1, 1, [0]),
    a_type(1, 0, a_config_default(), [0], Bytes::from_array(bag_arr)),
  ])
  let mut bag_raised = false
  try ignore(@apk.parse_resources_arsc(a_table(a_pool(["x"]), [pkg3]))) catch {
    _ => bag_raised = true
  } noraise {
    _ => ()
  }
  assert_true(bag_raised, msg="bag count beyond chunk must raise")
}
