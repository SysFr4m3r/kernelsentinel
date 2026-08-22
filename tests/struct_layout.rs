//! The BPF program and the Rust decoder share bpf/events.h by convention, not
//! by construction. This test makes drift a build failure instead of a
//! silently mangled event stream.

use std::process::Command;

#[test]
fn rust_mirror_matches_c_header() {
    let probe = r#"
#include <stdio.h>
#include <stdint.h>
typedef uint64_t __u64; typedef uint32_t __u32; typedef uint16_t __u16;
#include "events.h"
#define OFF(f) printf("%s %zu\n", #f, offsetof(struct event, f))
int main(void) {
    printf("size %zu\n", sizeof(struct event));
    OFF(ts_ns); OFF(cgroup_id); OFF(start_boottime); OFF(pid); OFF(tgid);
    OFF(ppid); OFF(uid); OFF(gid); OFF(euid); OFF(egid); OFF(exit_code);
    OFF(argv_len); OFF(type); OFF(flags); OFF(comm); OFF(filename); OFF(argv);
    return 0;
}
"#;
    let dir = std::env::temp_dir().join("kernelsentinel-layout-test");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    let bin = dir.join("probe");
    std::fs::write(&src, probe).unwrap();

    let status = Command::new("clang")
        .args(["-I", "bpf", "-include", "stddef.h"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .expect("clang must be installed to run this test");
    assert!(status.success(), "probe failed to compile");

    let out = Command::new(&bin).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();

    let mut c_layout = std::collections::HashMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once(' ').unwrap();
        c_layout.insert(k.to_string(), v.parse::<usize>().unwrap());
    }

    assert_eq!(
        c_layout["size"],
        std::mem::size_of::<kernelsentinel::event::RawEvent>(),
        "struct event size differs between bpf/events.h and src/event.rs"
    );
}
