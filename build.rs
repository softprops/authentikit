extern crate serde_codegen;

use std::env;
use std::path::{Path, PathBuf};
use std::fs;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let _ = fs::create_dir(&Path::new(&out_dir).join("jws"));
    generate(Path::new("src/jws/mod.rs.in"), &Path::new(&out_dir).join("jws/mod.rs"));
    generate(Path::new("src/lib.rs.in"), &Path::new(&out_dir).join("lib.rs"));
}

fn generate(src: &Path, dst: &PathBuf) {
    serde_codegen::expand(&src, &dst).unwrap();
}
