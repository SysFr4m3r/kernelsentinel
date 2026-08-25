//! Compiles the BPF object and generates its Rust skeleton.
//!
//! Gated on the `bpf` feature so a server-only build needs none of the BPF
//! toolchain. Without the feature this script does nothing at all: no clang, no
//! libbpf headers, and no host-specific `vmlinux.h` -- which is what makes it
//! possible to build the central server on a box that has none of them.

#[cfg(feature = "bpf")]
fn main() {
    use std::env;
    use std::path::PathBuf;

    use libbpf_cargo::SkeletonBuilder;

    const SRC: &str = "bpf/kernelsentinel.bpf.c";

    let mut out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    out.push("kernelsentinel.skel.rs");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        Ok(other) => panic!("unsupported target arch: {other}"),
        Err(e) => panic!("CARGO_CFG_TARGET_ARCH: {e}"),
    };

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            "-I./bpf".to_string(),
            format!("-D__TARGET_ARCH_{arch}"),
            "-Wno-compare-distinct-pointer-types".to_string(),
        ])
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=bpf/events.h");
}

#[cfg(not(feature = "bpf"))]
fn main() {}
