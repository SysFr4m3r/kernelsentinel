//! `struct event` is written by BPF and read by Rust as raw bytes. Nothing in
//! the build checks that the two declarations agree: `RawEvent::from_bytes` is
//! a `read_unaligned` over whatever the ring buffer produced, so a field added
//! on one side and not the other does not fail to compile, does not panic, and
//! does not drop events. It shifts every subsequent field by a few bytes and
//! the agent keeps running, reporting uids that are halves of timestamps.
//!
//! So the C header is parsed here and the layout it describes is compared
//! against the Rust mirror, field by field. This is the one place in the project
//! where two separately-compiled languages have to agree on a byte layout, and
//! it is the only one where a mistake is invisible at every other level.

use std::collections::HashMap;
use std::mem::{align_of, offset_of, size_of};

use kernelsentinel::event::RawEvent;

/// (name, size, alignment) for each field of `struct event`, in declaration
/// order, from the header itself.
fn c_fields() -> Vec<(String, usize, usize)> {
    let src = std::fs::read_to_string("bpf/events.h").expect("bpf/events.h");

    // #define constants used as array bounds.
    let mut defines: HashMap<&str, usize> = HashMap::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("#define ") else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let (Some(name), Some(val)) = (it.next(), it.next()) else {
            continue;
        };
        if let Ok(n) = val.parse::<usize>() {
            defines.insert(name, n);
        }
    }

    let start = src.find("struct event {").expect("struct event");
    let body = &src[start + "struct event {".len()..];
    let end = body.find("\n};").expect("end of struct event");
    let body = &body[..end];

    // Strip block comments before splitting on `;`: the comments in this header
    // contain semicolons, so splitting first tears them in half and the
    // fragments parse as fields.
    let mut clean = String::new();
    let mut depth = 0usize;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if depth == 0 && c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            depth = 1;
        } else if depth == 1 && c == '*' && chars.peek() == Some(&'/') {
            chars.next();
            depth = 0;
        } else if depth == 0 {
            clean.push(c);
        }
    }
    assert_eq!(depth, 0, "unterminated comment in struct event");

    let mut fields = Vec::new();
    for decl in clean.split(';') {
        let decl = decl.trim();
        if decl.is_empty() {
            continue;
        }

        let mut parts = decl.split_whitespace();
        let ctype = parts.next().expect("type").to_string();
        let name = parts
            .next()
            .unwrap_or_else(|| panic!("no name in `{decl}`"));

        let scalar = match ctype.as_str() {
            "__u64" | "__s64" => 8,
            "__u32" | "__s32" => 4,
            "__u16" | "__s16" => 2,
            "__u8" | "__s8" | "char" => 1,
            other => panic!("unhandled C type `{other}` in struct event"),
        };

        if let Some((bare, bound)) = name.split_once('[') {
            let bound = bound.trim_end_matches(']');
            let n = bound
                .parse::<usize>()
                .unwrap_or_else(|_| *defines.get(bound).unwrap_or_else(|| panic!("{bound}?")));
            fields.push((bare.to_string(), scalar * n, scalar));
        } else {
            fields.push((name.to_string(), scalar, scalar));
        }
    }
    fields
}

/// Lay the parsed fields out under the C rules the compiler uses: each field at
/// the next offset satisfying its alignment, the struct padded to its own.
fn c_layout(fields: &[(String, usize, usize)]) -> (Vec<(String, usize)>, usize, usize) {
    let mut offsets = Vec::new();
    let mut off = 0usize;
    let mut max_align = 1usize;
    for (name, size, align) in fields {
        off = off.div_ceil(*align) * align;
        offsets.push((name.clone(), off));
        off += size;
        max_align = max_align.max(*align);
    }
    let size = off.div_ceil(max_align) * max_align;
    (offsets, size, max_align)
}

/// Every field of the Rust mirror, by the name the C header uses.
fn rust_offsets() -> HashMap<&'static str, usize> {
    HashMap::from([
        ("ts_ns", offset_of!(RawEvent, ts_ns)),
        ("cgroup_id", offset_of!(RawEvent, cgroup_id)),
        ("start_boottime", offset_of!(RawEvent, start_boottime)),
        ("cap_effective", offset_of!(RawEvent, cap_effective)),
        ("old_cap_effective", offset_of!(RawEvent, old_cap_effective)),
        (
            "child_start_boottime",
            offset_of!(RawEvent, child_start_boottime),
        ),
        ("exe_ino", offset_of!(RawEvent, exe_ino)),
        ("pid", offset_of!(RawEvent, pid)),
        ("tgid", offset_of!(RawEvent, tgid)),
        ("ppid", offset_of!(RawEvent, ppid)),
        ("uid", offset_of!(RawEvent, uid)),
        ("gid", offset_of!(RawEvent, gid)),
        ("euid", offset_of!(RawEvent, euid)),
        ("egid", offset_of!(RawEvent, egid)),
        ("old_uid", offset_of!(RawEvent, old_uid)),
        ("old_gid", offset_of!(RawEvent, old_gid)),
        ("old_euid", offset_of!(RawEvent, old_euid)),
        ("old_egid", offset_of!(RawEvent, old_egid)),
        ("exit_code", offset_of!(RawEvent, exit_code)),
        ("argv_len", offset_of!(RawEvent, argv_len)),
        ("child_pid", offset_of!(RawEvent, child_pid)),
        ("file_mode", offset_of!(RawEvent, file_mode)),
        ("old_file_mode", offset_of!(RawEvent, old_file_mode)),
        ("watch_id", offset_of!(RawEvent, watch_id)),
        ("target_pid", offset_of!(RawEvent, target_pid)),
        ("aux", offset_of!(RawEvent, aux)),
        ("mnt_ns", offset_of!(RawEvent, mnt_ns)),
        ("pid_ns", offset_of!(RawEvent, pid_ns)),
        ("net_ns", offset_of!(RawEvent, net_ns)),
        ("exe_dev", offset_of!(RawEvent, exe_dev)),
        ("type", offset_of!(RawEvent, r#type)),
        ("flags", offset_of!(RawEvent, flags)),
        ("comm", offset_of!(RawEvent, comm)),
        ("filename", offset_of!(RawEvent, filename)),
        ("argv", offset_of!(RawEvent, argv)),
        ("cgroup_name", offset_of!(RawEvent, cgroup_name)),
    ])
}

#[test]
fn the_rust_mirror_declares_every_c_field() {
    let c = c_fields();
    let rust = rust_offsets();

    let c_names: Vec<&str> = c.iter().map(|(n, _, _)| n.as_str()).collect();
    for name in &c_names {
        assert!(
            rust.contains_key(name),
            "bpf/events.h declares `{name}`, which src/event.rs does not mirror. \
             A field present on only one side shifts every field after it."
        );
    }
    for name in rust.keys() {
        assert!(
            c_names.contains(name),
            "src/event.rs declares `{name}`, which bpf/events.h does not."
        );
    }
}

#[test]
fn every_field_sits_at_the_same_offset_on_both_sides() {
    let (c, _, _) = c_layout(&c_fields());
    let rust = rust_offsets();
    for (name, c_off) in &c {
        let r_off = rust[name.as_str()];
        assert_eq!(
            *c_off, r_off,
            "field `{name}` is at byte {c_off} in bpf/events.h but {r_off} in src/event.rs"
        );
    }
}

#[test]
fn the_struct_is_the_same_size_on_both_sides() {
    let (_, c_size, c_align) = c_layout(&c_fields());
    assert_eq!(
        c_size,
        size_of::<RawEvent>(),
        "struct event is {c_size} bytes in C and {} in Rust",
        size_of::<RawEvent>()
    );
    assert_eq!(c_align, align_of::<RawEvent>(), "alignment differs");
}

/// The ring buffer hands over exactly `sizeof(struct event)` bytes. A record
/// shorter than the mirror must be rejected rather than read past.
#[test]
fn a_short_record_is_rejected() {
    let buf = vec![0u8; size_of::<RawEvent>() - 1];
    assert!(RawEvent::from_bytes(&buf).is_none());
    let buf = vec![0u8; size_of::<RawEvent>()];
    assert!(RawEvent::from_bytes(&buf).is_some());
}
