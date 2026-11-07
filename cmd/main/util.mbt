///|
/// WP-3 CLI 公共辅助（apk-cli）：JSON 转义、十六进制渲染、记录行拼接。
/// 仅使用 moonbitlang/core 与本模块公开 API。

///|
/// JSON 字符串转义（RFC 8259 最小充分子集：引号、反斜杠、控制字符）。
fn json_escape(s : String) -> String {
  let out : Array[String] = []
  out.push("\"")
  for c in s.iter() {
    let v = c.to_int()
    if c == '"' {
      out.push("\\\"")
    } else if c == '\\' {
      out.push("\\\\")
    } else if c == '\n' {
      out.push("\\n")
    } else if c == '\r' {
      out.push("\\r")
    } else if c == '\t' {
      out.push("\\t")
    } else if v < 0x20 {
      out.push("\\u" + json_hex4(v))
    } else {
      out.push(c.to_string())
    }
  }
  out.push("\"")
  str_join(out)
}

///|
/// 四位小写十六进制（JSON \uXXXX 用）。
fn json_hex4(v : Int32) -> String {
  let digits = "0123456789abcdef"
  let mut s = ""
  let mut x = v
  let mut n = 0
  while n < 4 {
    let d = x & 0xF
    s = digits[d:d + 1].to_owned() + s
    x = x >> 4
    n = n + 1
  }
  s
}

///|
/// 片段拼接为字符串（无分隔符；JSON 构造用）。
fn str_join(parts : Array[String]) -> String {
  let mut s = ""
  for l in parts {
    s = s + l
  }
  s
}

///|
/// 文本行拼接（`\n` 分隔；帮助文本用）。
fn join_lines(lines : Array[String]) -> String {
  let mut s = ""
  let mut first = true
  for l in lines {
    if first {
      first = false
    } else {
      s = s + "\n"
    }
    s = s + l
  }
  s
}

///|
/// ABI 渲染（与 aapt2 badging 的 `native-code` 名称对齐）。
fn abi_name(a : @apk.Abi) -> String {
  match a {
    ArmeabiV7a => "armeabi-v7a"
    Arm64V8a => "arm64-v8a"
    X86 => "x86"
    X86_64 => "x86_64"
    Unknown(s) => s
  }
}
