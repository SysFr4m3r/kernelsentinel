//! YARA content scanning, triggered by behaviour.
//!
//! This is identification, not detection. The engine already decides *that*
//! something is suspicious; YARA answers *what it is* -- turning "a payload
//! executed from memory" into "that payload matches Meterpreter". It will not
//! catch anything the behavioural engine missed.
//!
//! Which is exactly why it only ever runs on a target a signal already named.
//! Scanning every file open would rebuild the signature firehose this project
//! exists to avoid, and put a pattern matcher in the path of every open on the
//! box. Rules here are an enrichment pass over a handful of files per incident.
//!
//! Matches raise confidence on an existing incident; they never mint a score of
//! their own. One over-broad rule should not be able to manufacture an incident.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

/// Largest file worth reading into memory for a scan.
pub const MAX_SCAN_BYTES: usize = 32 * 1024 * 1024;

/// What happened when we tried to look at a target.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum Outcome {
    /// Rules matched. `rules` names them.
    Matched { rules: Vec<String> },
    /// Read and scanned, nothing matched.
    Clean,
    /// The target was gone by the time we looked. Reported rather than hidden:
    /// a memfd lives only as long as its process, so this is a routine and
    /// expected result, and silently omitting it would read as "clean".
    Raced { reason: String },
}

#[derive(Serialize, Clone, Debug)]
pub struct ScanResult {
    /// The signal whose target this was.
    pub signal: String,
    pub target: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

pub struct Scanner {
    rules: yara_x::Rules,
    count: usize,
}

impl Scanner {
    /// Compile every `.yar`/`.yara` file in `dir`.
    pub fn load(dir: &str) -> Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut count = 0usize;
        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("reading YARA rules directory {dir}"))?;
        let mut paths: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yar") | Some("yara")
                )
            })
            .collect();
        // Deterministic order: rule identifiers must not collide differently
        // from one run to the next.
        paths.sort();
        for path in paths {
            let src = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            compiler
                .add_source(src.as_str())
                .map_err(|e| anyhow::anyhow!("compiling {}: {e}", path.display()))?;
            count += 1;
        }
        if count == 0 {
            anyhow::bail!("no .yar/.yara files in {dir}");
        }
        Ok(Self {
            rules: compiler.build(),
            count,
        })
    }

    pub fn rule_files(&self) -> usize {
        self.count
    }

    /// Scan one path. Never returns an error for an absent or unreadable
    /// target: losing the race is a normal outcome here, not a failure.
    pub fn scan_path(&self, target: &str) -> Outcome {
        let bytes = match read_capped(target) {
            Ok(b) => b,
            Err(e) => {
                return Outcome::Raced {
                    reason: e.to_string(),
                };
            }
        };
        let mut scanner = yara_x::Scanner::new(&self.rules);
        match scanner.scan(&bytes) {
            Ok(results) => {
                let rules: Vec<String> = results
                    .matching_rules()
                    .map(|r| r.identifier().to_string())
                    .collect();
                if rules.is_empty() {
                    Outcome::Clean
                } else {
                    Outcome::Matched { rules }
                }
            }
            Err(e) => Outcome::Raced {
                reason: format!("scan failed: {e}"),
            },
        }
    }
}

/// Read at most `MAX_SCAN_BYTES`. A /proc/<pid>/exe for a memfd reports size 0
/// while still being readable, so this reads rather than trusting metadata.
fn read_capped(path: &str) -> Result<Vec<u8>> {
    let p = Path::new(path);
    let file = std::fs::File::open(p).with_context(|| format!("opening {path}"))?;
    let mut buf = Vec::new();
    file.take(MAX_SCAN_BYTES as u64)
        .read_to_end(&mut buf)
        .with_context(|| format!("reading {path}"))?;
    if buf.is_empty() {
        anyhow::bail!("{path} was empty or already gone");
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn rules_dir(body: &str) -> tempdir::Dir {
        let d = tempdir::Dir::new();
        let mut f = std::fs::File::create(d.path().join("t.yar")).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        d
    }

    /// A tiny scratch directory helper; the project has no tempfile dependency
    /// and one test module does not justify adding one.
    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let n = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let p = std::env::temp_dir()
                    .join(format!("ks-yara-{n}-{:?}", std::thread::current().id()));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn matching_rule_is_named() {
        let d = rules_dir(r#"rule ks_test_marker { strings: $a = "TOTALLY_EVIL" condition: $a }"#);
        let s = Scanner::load(d.path().to_str().unwrap()).unwrap();
        assert_eq!(s.rule_files(), 1);

        let f = d.path().join("sample.bin");
        std::fs::write(&f, b"harmless prefix TOTALLY_EVIL harmless suffix").unwrap();
        match s.scan_path(f.to_str().unwrap()) {
            Outcome::Matched { rules } => assert_eq!(rules, ["ks_test_marker"]),
            other => panic!("expected a match, got {other:?}"),
        }
    }

    #[test]
    fn non_matching_content_is_clean_not_a_match() {
        let d = rules_dir(r#"rule ks_test_marker { strings: $a = "TOTALLY_EVIL" condition: $a }"#);
        let s = Scanner::load(d.path().to_str().unwrap()).unwrap();
        let f = d.path().join("ok.bin");
        std::fs::write(&f, b"nothing to see here").unwrap();
        assert_eq!(s.scan_path(f.to_str().unwrap()), Outcome::Clean);
    }

    /// A target that vanished must be distinguishable from one that was clean.
    /// Reporting a lost race as "clean" would be the dangerous failure.
    #[test]
    fn a_vanished_target_reports_raced_not_clean() {
        let d = rules_dir(r#"rule x { condition: true }"#);
        let s = Scanner::load(d.path().to_str().unwrap()).unwrap();
        match s.scan_path("/proc/999999/exe") {
            Outcome::Raced { .. } => {}
            other => panic!("expected Raced, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_target_is_raced_not_clean() {
        let d = rules_dir(r#"rule x { condition: true }"#);
        let s = Scanner::load(d.path().to_str().unwrap()).unwrap();
        let f = d.path().join("empty.bin");
        std::fs::write(&f, b"").unwrap();
        match s.scan_path(f.to_str().unwrap()) {
            Outcome::Raced { .. } => {}
            other => panic!("expected Raced for an empty file, got {other:?}"),
        }
    }

    #[test]
    fn a_directory_with_no_rules_is_an_error_not_a_silent_no_op() {
        let d = tempdir::Dir::new();
        assert!(
            Scanner::load(d.path().to_str().unwrap()).is_err(),
            "loading no rules must fail loudly, not scan nothing forever"
        );
    }

    #[test]
    fn outcome_serializes_with_a_readable_tag() {
        let v = serde_json::to_value(Outcome::Matched {
            rules: vec!["meterpreter".into()],
        })
        .unwrap();
        assert_eq!(v["outcome"], "matched");
        assert_eq!(v["rules"][0], "meterpreter");
        assert_eq!(
            serde_json::to_value(Outcome::Clean).unwrap()["outcome"],
            "clean"
        );
    }
}
