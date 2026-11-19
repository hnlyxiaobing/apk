// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "hnlyxiaobing/apk"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/hnlyxiaobing/apk"

license = "Apache-2.0"

keywords = [ "apk", "android", "zip", "signature", "verity" ]

preferred_target = "wasm"

description = "Read-only APK (ZIP) container parser: entry index and raw bytes, v1/v2/v3/v3.1 signature verification, resources.arsc and ELF recon, for Android package tooling."

import {
  "bobzhang/zip@0.1.2",
}
