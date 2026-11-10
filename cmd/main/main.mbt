///|
/// apk-cli：APK 容器 CLI（hnlyxiaobing/apk 公开 API 驱动）。
/// 契约（根 README.md）：退出码 0=成功 / 1=解析或IO错误 / 2=用法错误；
/// 默认记录行输出（规范化口径见 tests/ASSETS.md），`--json` 机器可读。

///|
let tool_name = "apk-cli"

///|
/// 帮助文本（stdout，exit 0）。
fn usage_text() -> String {
  join_lines([
    "\{tool_name} —— APK 容器工具（hnlyxiaobing/apk 公开 API 驱动）",
    "",
    "用法:",
    "  \{tool_name} list <apk> [--json]",
    "      列举条目：ENTR|name|usize|csize（中央目录顺序）、DEX|name（dex 条目，含多 dex）、",
    "      MANI|len 与 ARSC|len（manifest/resources.arsc 解压后字节长）、LIB|abi（原生库 ABI）",
    "  \{tool_name} extract <apk> --entry <name> --out <file> [--json]",
    "      按条目名提取单个条目（classes.dex / classes2.dex / 任意条目均可）",
    "  \{tool_name} extract <apk> --all --out <dir> [--json]",
    "      提取全部条目到目录（保留条目内路径，自动建子目录；",
    "      绝对路径 / .. / 反斜杠 / 盘符等不安全条目名一律拒绝，退出码 1；",
    "      单个条目解压后大小上限 256 MiB，超出退出码 1）",
    "  \{tool_name} --help",
    "",
    "输出: 默认人类可读记录行（规范化口径见 tests/ASSETS.md）；",
    "      --json 输出单行 JSON（stdout）；错误信息一律走 stderr。",
    "退出码: 0=成功 1=解析或IO错误 2=用法错误",
  ])
}

///|
/// 数组是否含某字符串。
fn arr_contains(arr : Array[String], s : String) -> Bool {
  for x in arr {
    if x == s {
      return true
    }
  }
  false
}

///|
/// 路径的父目录（最后一个 `/` 或 `\` 之前的部分；无分隔符时返回 `.`）。
fn parent_dir(path : String) -> String {
  let mut cut = -1
  let mut i = 0
  while i < path.length() {
    let c = path[i:i + 1].to_owned()
    if c == "/" || c == "\\" {
      cut = i
    }
    i = i + 1
  }
  if cut < 0 {
    "."
  } else if cut == 0 {
    path[0:1].to_owned()
  } else {
    path[0:cut].to_owned()
  }
}

///|
/// 单个条目解压后大小上限（256 MiB）。
let max_extract_bytes : Int32 = 256 * 1024 * 1024

///|
/// 检查 `size` 是否未超过 `max_extract_bytes`，供 extract 路径与回归测试共用。
fn is_extract_size_allowed(size : Int32) -> Bool {
  size <= max_extract_bytes
}

///|
/// ZIP 条目名是否可安全拼接到 `--all` 的输出目录下：拒绝绝对路径、盘符 /
/// 备用数据流（`:`）、反斜杠与控制字符，以及空段 / `.` / `..` 段。
/// 不安全的条目名会让写入逃逸 `--out`（路径穿越）。
fn is_safe_entry_name(name : String) -> Bool {
  if name == "" {
    return false
  }
  let mut segment = ""
  for c in name.iter() {
    let v = c.to_int()
    if v < 0x20 || v == 0x7F || c == '\\' || c == ':' {
      return false
    }
    if c == '/' {
      if segment == "" || segment == "." || segment == ".." {
        return false
      }
      segment = ""
    } else {
      segment = segment + c.to_string()
    }
  }
  segment != "" && segment != "." && segment != ".."
}

///|
/// 在中央目录索引中按名查找条目元数据（供 extract 大小预检）。
fn find_entry_ref(
  entries : Array[@apk.ZipEntryRef],
  name : String,
) -> @apk.ZipEntryRef? {
  for e in entries {
    if e.name == name {
      return Some(e)
    }
  }
  None
}

///|
/// 读取输入文件；路径为空或不可读时返回 `ok=false`（退出码 1 由调用方返回）。
async fn read_input(path : String) -> (Bytes, Bool) {
  if path == "" {
    return (b"", false)
  }
  if !@fs.exists(path) {
    eprintln("error: 无法读取文件：\{path}")
    return (b"", false)
  }
  (@fs.read_binary(path), true)
}

///|
/// `list` 子命令。
async fn cmd_list(rest : ArrayView[String]) -> Int32 {
  let mut apk_path = ""
  let mut json = false
  for xs = rest {
    match xs {
      ["--json", .. r] => {
        json = true
        continue r
      }
      ["--help", ..] => {
        println(usage_text())
        return 0
      }
      ["-h", ..] => {
        println(usage_text())
        return 0
      }
      [p, .. r] => {
        if p.has_prefix("-") {
          eprintln("error: 未知选项：\{p}")
          eprintln("用法: \{tool_name} list <apk> [--json]")
          return 2
        }
        if apk_path != "" {
          eprintln("error: 多余的位置参数：\{p}")
          return 2
        }
        apk_path = p
        continue r
      }
      [] => break
    }
  }
  if apk_path == "" {
    eprintln("error: list 需要 <apk> 参数")
    eprintln("用法: \{tool_name} list <apk> [--json]")
    return 2
  }
  let (data, ok) = read_input(apk_path)
  if !ok {
    return 1
  }
  let a = @apk.Apk::open(data)
  if json {
    let parts : Array[String] = []
    parts.push(
      "{\"tool\":\"\{tool_name}\",\"apk\":\{json_escape(apk_path)},\"entries\":[",
    )
    let mut first = true
    for e in a.entries() {
      if !first {
        parts.push(",")
      }
      first = false
      parts.push(
        "{\"name\":\{json_escape(e.name)},\"uncompressed_size\":\{e.uncompressed_size},\"compressed_size\":\{e.compressed_size},\"crc32\":\{e.crc32},\"compression_method\":\{e.compression_method}}",
      )
    }
    parts.push("],\"dex\":[")
    first = true
    for d in a.dex_files() {
      if !first {
        parts.push(",")
      }
      first = false
      parts.push("\{json_escape(d.name)}")
    }
    parts.push(
      "],\"manifest_bytes\":\{a.manifest().raw.length()},\"resource_table_bytes\":",
    )
    match a.resource_table() {
      Some(r) => parts.push("\{r.raw.length()}")
      None => parts.push("null")
    }
    parts.push(",\"abis\":[")
    let seen : Array[String] = []
    first = true
    for l in a.native_libs(None) {
      let name = abi_name(l.abi)
      if !arr_contains(seen, name) {
        seen.push(name)
        if !first {
          parts.push(",")
        }
        first = false
        parts.push("\{json_escape(name)}")
      }
    }
    parts.push("]}")
    println(str_join(parts))
  } else {
    for e in a.entries() {
      println("ENTR|\{e.name}|\{e.uncompressed_size}|\{e.compressed_size}")
    }
    for d in a.dex_files() {
      println("DEX|\{d.name}")
    }
    println("MANI|\{a.manifest().raw.length()}")
    match a.resource_table() {
      Some(r) => println("ARSC|\{r.raw.length()}")
      None => ()
    }
    let seen : Array[String] = []
    for l in a.native_libs(None) {
      let name = abi_name(l.abi)
      if !arr_contains(seen, name) {
        seen.push(name)
        println("LIB|\{name}")
      }
    }
  }
  0
}

///|
/// `extract` 子命令：`--entry <name> --out <file>` 或 `--all --out <dir>`。
async fn cmd_extract(rest : ArrayView[String]) -> Int32 {
  let mut apk_path = ""
  let mut entry : String? = None
  let mut all = false
  let mut out : String? = None
  let mut json = false
  for xs = rest {
    match xs {
      ["--json", .. r] => {
        json = true
        continue r
      }
      ["--entry", v, .. r] => {
        entry = Some(v)
        continue r
      }
      ["--all", .. r] => {
        all = true
        continue r
      }
      ["--out", v, .. r] => {
        out = Some(v)
        continue r
      }
      ["--help", ..] => {
        println(usage_text())
        return 0
      }
      ["-h", ..] => {
        println(usage_text())
        return 0
      }
      [p, .. r] => {
        if p.has_prefix("-") {
          eprintln("error: 未知选项：\{p}")
          eprintln(
            "用法: \{tool_name} extract <apk> (--entry <name> | --all) --out <path> [--json]",
          )
          return 2
        }
        if apk_path != "" {
          eprintln("error: 多余的位置参数：\{p}")
          return 2
        }
        apk_path = p
        continue r
      }
      [] => break
    }
  }
  if apk_path == "" {
    eprintln("error: extract 需要 <apk> 参数")
    return 2
  }
  if all && entry is Some(_) {
    eprintln("error: --entry 与 --all 互斥")
    return 2
  }
  if !all && entry is None {
    eprintln("error: 需要 --entry <name> 或 --all")
    return 2
  }
  let out_path = match out {
    Some(v) => v
    None => {
      eprintln("error: 需要 --out <path>")
      return 2
    }
  }
  let (data, ok) = read_input(apk_path)
  if !ok {
    return 1
  }
  let a = @apk.Apk::open(data)
  let names : Array[String] = []
  if all {
    for e in a.entries() {
      if !e.name.has_suffix("/") {
        names.push(e.name)
      }
    }
  } else {
    match entry {
      Some(v) => names.push(v)
      None => ()
    }
  }
  let out_names : Array[String] = []
  let out_sizes : Array[Int32] = []
  let out_dests : Array[String] = []
  if all {
    // 先整体预检：任何不安全条目都直接失败，避免写出部分条目后才发现。
    for name in names {
      if !is_safe_entry_name(name) {
        eprintln(
          "error: 拒绝不安全的条目名（可能逃逸 --out）：\{name}",
        )
        return 1
      }
    }
  }
  for name in names {
    match find_entry_ref(a.entries(), name) {
      Some(e) =>
        if e.uncompressed_size > max_extract_bytes.to_uint64() {
          eprintln(
            "error: 条目 '\{name}' 声明的解压大小 \{e.uncompressed_size} 超过上限 \{max_extract_bytes}",
          )
          return 1
        }
      None => ()
    }
    let bytes = a.entry(name)
    if !is_extract_size_allowed(bytes.length()) {
      eprintln(
        "error: 条目 '\{name}' 解压后大小 \{bytes.length()} 超过上限 \{max_extract_bytes}",
      )
      return 1
    }
    let dest = if all { out_path + "/" + name } else { out_path }
    @fs.mkdir(parent_dir(dest), recursive=true, allow_exist=true)
    @fs.write_binary(dest, bytes)
    out_names.push(name)
    out_sizes.push(bytes.length())
    out_dests.push(dest)
  }
  if json {
    let parts : Array[String] = []
    parts.push(
      "{\"tool\":\"\{tool_name}\",\"apk\":\{json_escape(apk_path)},\"extracted\":[",
    )
    let mut i = 0
    while i < out_names.length() {
      if i > 0 {
        parts.push(",")
      }
      parts.push(
        "{\"entry\":\{json_escape(out_names[i])},\"bytes\":\{out_sizes[i]},\"out\":\{json_escape(out_dests[i])}}",
      )
      i = i + 1
    }
    parts.push("]}")
    println(str_join(parts))
  } else {
    let mut i = 0
    while i < out_names.length() {
      println("EXTR|\{out_names[i]}|\{out_sizes[i]}|\{out_dests[i]}")
      i = i + 1
    }
  }
  0
}

///|
/// 运行入口：返回进程退出码；库抛出的解析错误统一按“解析错误”返回 1。
async fn run(args : Array[String]) -> Int32 {
  if args.length() <= 1 {
    eprintln("error: 缺少子命令（list / extract）")
    eprintln("运行 \{tool_name} --help 查看用法")
    return 2
  }
  let sub = args[1]
  let rest = args[2:]
  if sub == "list" {
    cmd_list(rest) catch {
      e => {
        eprintln("error: \{e}")
        1
      }
    }
  } else if sub == "extract" {
    cmd_extract(rest) catch {
      e => {
        eprintln("error: \{e}")
        1
      }
    }
  } else if sub == "--help" || sub == "-h" || sub == "help" {
    println(usage_text())
    0
  } else {
    eprintln("error: 未知子命令：\{sub}")
    eprintln("运行 \{tool_name} --help 查看用法")
    2
  }
}

///|
async fn main {
  let code = run(@env.args())
  if code != 0 {
    @env.exit(code)
  }
}
