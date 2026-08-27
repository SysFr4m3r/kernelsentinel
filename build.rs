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

    // Watch every BPF source, not just the entry point. The sensors are
    // included into one translation unit, so editing sensors/file.bpf.h changes
    // the object without touching kernelsentinel.bpf.c -- and cargo would
    // happily keep serving a stale skeleton, which is the kind of build bug
    // that costs an afternoon.
    println!("cargo:rerun-if-changed={SRC}");
    for dir in ["bpf", "bpf/sensors"] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            // vmlinux.h is generated and enormous; it has its own trigger via
            // the toolchain, and hashing it on every build is wasted work.
            if path.file_name().is_some_and(|n| n == "vmlinux.h") {
                continue;
            }
            if path.extension().is_some_and(|x| x == "h" || x == "c") {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

#[cfg(not(feature = "bpf"))]
fn main() {}
