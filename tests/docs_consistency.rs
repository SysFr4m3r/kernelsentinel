//! Documentation that cannot silently drift from the code.
//!
//! Every fact in here was wrong at some point in this project's history: the
//! kernel floor said 5.8 in three files while the code required 5.11, the test
//! count was stale twice, the install commands pinned a version two releases
//! old, and a detection count came from a bad grep. Each was found by someone
//! noticing, which does not scale.
//!
//! These run in `cargo test`, not only in CI, so the failure arrives before the
//! push rather than after it.

use std::collections::BTreeSet;
use std::fs;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

/// Every signal id the detectors can emit, taken from the source.
fn signal_ids() -> BTreeSet<String> {
    let src = read("src/detect/detectors.rs");
    let mut ids = BTreeSet::new();
    let ident = |t: &str| !t.is_empty() && t.chars().all(|c| c.is_ascii_lowercase() || c == '_');

    let mut lines = src.lines().peekable();
    while let Some(line) = lines.next() {
        // Pattern one: the id is a string literal, first argument to
        // Signal::new, on the line directly below.
        if line.contains("Signal::new(") {
            if let Some(next) = lines.peek() {
                let t = next.trim().trim_end_matches(',');
                // Must be a *quoted* literal. `Signal::new(id, ..)` passes a
                // variable, and reading that as an id yields the useless "id".
                if t.starts_with('"') && t.ends_with('"') {
                    let t = t.trim_matches('"');
                    if ident(t) {
                        ids.insert(t.to_string());
                    }
                }
            }
        }
        // Pattern two: sensitive_write and credential_read pick their id from a
        // (score, "literal") tuple and pass it as a variable, so the literals
        // never appear next to Signal::new at all.
        let t = line.trim();
        if t.starts_with('(') && t.contains(", \"") {
            if let Some(lit) = t.split(", \"").nth(1).and_then(|r| r.split('"').next()) {
                if ident(lit) {
                    ids.insert(lit.to_string());
                }
            }
        }
    }
    assert!(ids.len() > 5, "signal extraction broke: found {ids:?}");
    ids
}

/// A detection nobody documented is a detection nobody can tune, and the
/// false-positive and evasion notes are the most useful thing in that file.
#[test]
fn every_detection_is_documented() {
    let doc = read("docs/DETECTIONS.md");
    let missing: Vec<_> = signal_ids()
        .into_iter()
        .filter(|id| !doc.contains(&format!("`{id}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "these signals are emitted but absent from docs/DETECTIONS.md: {missing:?}"
    );
}

/// A detector with no attack scenario is one nothing proves still works. That is
/// how a container escape detection reached a public release broken.
#[test]
fn every_detection_has_an_attack_scenario() {
    // The one exception, and why. module_autoload exists to *suppress* -- it is
    // the kernel pulling in a driver, which must never alert. Proving it works
    // means proving silence, which is the noise suite's job
    // (tests/noise/container_lifecycle.sh), not an attack scenario's.
    const SUPPRESSION_ONLY: &[&str] = &["module_autoload"];

    let scenarios: String = fs::read_dir("tests/scenarios")
        .expect("tests/scenarios")
        .flatten()
        .map(|e| fs::read_to_string(e.path()).unwrap_or_default())
        .collect();

    let missing: Vec<_> = signal_ids()
        .into_iter()
        .filter(|id| !SUPPRESSION_ONLY.contains(&id.as_str()))
        .filter(|id| !scenarios.contains(&format!("ks-expect: {id}")))
        .collect();
    assert!(
        missing.is_empty(),
        "these detections have no scenario in tests/scenarios/, so nothing runs the \
         real attack against them: {missing:?}"
    );
}

/// The floor lives in doctor.rs and is repeated in two documents. It was wrong
/// in all three simultaneously -- 5.8, when every program needs 5.11.
#[test]
fn the_kernel_floor_agrees_everywhere() {
    let doctor = read("src/doctor.rs");
    let (maj, min) = doctor
        .split_once("(maj, min) >= (")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(nums, _)| {
            let mut p = nums.split(',').map(|n| n.trim().parse::<u32>().unwrap());
            (p.next().unwrap(), p.next().unwrap())
        })
        .expect("could not find the kernel check in src/doctor.rs");
    let floor = format!("{maj}.{min}");

    for path in ["README.md", "docs/COMPATIBILITY.md"] {
        let text = read(path);
        assert!(
            text.contains(&floor),
            "{path} does not mention the kernel floor {floor} that src/doctor.rs enforces"
        );
        // The previous, wrong floor must not linger anywhere as a claim.
        assert!(
            !text.contains("5.8+"),
            "{path} still claims kernel 5.8+, but doctor.rs requires {floor}"
        );
    }
}

/// The README quoted a test count that went stale twice.
#[test]
fn the_readme_test_count_is_current() {
    let mut actual = 0usize;
    for dir in ["src", "tests"] {
        let mut stack = vec![std::path::PathBuf::from(dir)];
        while let Some(p) = stack.pop() {
            for e in fs::read_dir(&p).into_iter().flatten().flatten() {
                let path = e.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    actual += read(path.to_str().unwrap()).matches("#[test]").count();
                }
            }
        }
    }

    let readme = read("README.md");
    let claimed: usize = readme
        .split_once(" unit and integration tests")
        .and_then(|(before, _)| {
            before
                .rsplit(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
        .expect("README should state 'N unit and integration tests'");

    assert_eq!(
        claimed, actual,
        "README claims {claimed} tests, the tree has {actual}. Update the README."
    );
}

/// Install commands that pin a version go stale on the next release, and a
/// copy-pasted stale command simply fails.
#[test]
fn docs_do_not_pin_a_stale_version() {
    let version = read("Cargo.toml")
        .lines()
        .find(|l| l.starts_with("version = "))
        .and_then(|l| l.split('"').nth(1).map(str::to_string))
        .expect("Cargo.toml version");

    for path in ["README.md", "docs/COMPATIBILITY.md"] {
        for (n, line) in read(path).lines().enumerate() {
            if !line.contains("_amd64.deb") && !line.contains("-linux.tar.gz") {
                continue;
            }
            let pinned = line.contains(&format!("_{version}_")) || line.contains("_*_");
            assert!(
                pinned || line.contains('*'),
                "{path}:{} pins a package version that is not {version}; glob it instead: {}",
                n + 1,
                line.trim()
            );
        }
    }
}

/// The README quotes scenario counts too, and those drift the moment a
/// detection is added -- which is exactly when the number matters most.
#[test]
fn the_readme_scenario_counts_are_current() {
    let count = |dir: &str| {
        fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{dir}: {e}"))
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "sh"))
            .count()
    };
    let attacks = count("tests/scenarios");
    let noise = count("tests/noise");
    // Flatten markdown links first: the prose reads
    // "Nineteen [attack scenarios](#testing)", and a literal search for
    // "Nineteen attack scenarios" would miss it and fail for the wrong reason.
    let raw = read("README.md");
    let mut readme = String::with_capacity(raw.len());
    let mut rest = raw.as_str();
    while let Some(open) = rest.find('[') {
        readme.push_str(&rest[..open]);
        rest = &rest[open + 1..];
        match (rest.find(']'), rest.find('(')) {
            (Some(close), _) => {
                readme.push_str(&rest[..close]);
                rest = &rest[close + 1..];
                if rest.starts_with('(') {
                    if let Some(end) = rest.find(')') {
                        rest = &rest[end + 1..];
                    }
                }
            }
            _ => break,
        }
    }
    readme.push_str(rest);

    let words = [
        "Zero",
        "One",
        "Two",
        "Three",
        "Four",
        "Five",
        "Six",
        "Seven",
        "Eight",
        "Nine",
        "Ten",
        "Eleven",
        "Twelve",
        "Thirteen",
        "Fourteen",
        "Fifteen",
        "Sixteen",
        "Seventeen",
        "Eighteen",
        "Nineteen",
        "Twenty",
    ];
    let spelled = |n: usize| words.get(n).map(|w| w.to_string()).unwrap_or_default();

    assert!(
        readme.contains(&format!("{attacks} attack scenarios"))
            || readme.contains(&format!("{} attack scenarios", spelled(attacks))),
        "README should say there are {attacks} attack scenarios ({})",
        spelled(attacks)
    );
    assert!(
        readme.contains(&format!("{noise} noise scenarios"))
            || readme.contains(&format!(
                "{} noise scenarios",
                spelled(noise).to_lowercase()
            )),
        "README should say there are {noise} noise scenarios"
    );
}

/// A `ks-compat:` line as `compat-probe.sh` prints it.
struct CompatResult {
    distro: String,
    sensors: u32,
    total: u32,
}

fn recorded_results() -> Vec<CompatResult> {
    read("docs/compat-results.txt")
        .lines()
        .filter(|l| l.trim_start().starts_with("ks-compat:"))
        .map(|line| {
            let field = |k: &str| -> String {
                line.split_whitespace()
                    .find_map(|t| t.strip_prefix(k).map(str::to_string))
                    .unwrap_or_else(|| panic!("result line has no {k}: {line}"))
            };
            let sensors = field("sensors=");
            let (have, want) = sensors
                .split_once('/')
                .unwrap_or_else(|| panic!("malformed sensors= in {line}"));
            CompatResult {
                distro: field("distro="),
                sensors: have.parse().expect("sensor count"),
                total: want.parse().expect("sensor total"),
            }
        })
        .collect()
}

/// Rows in the COMPATIBILITY table claiming to be verified, as
/// `(distro id, sensors observed)` taken from the row's own text.
fn verified_rows() -> Vec<(String, u32)> {
    read("docs/COMPATIBILITY.md")
        .lines()
        .filter(|l| l.trim_start().starts_with('|') && l.contains("**verified**"))
        .map(|line| {
            // The id is the backticked token immediately after **verified**;
            // rows carry other backticked text, so anchor on that.
            let after = line
                .split("**verified**")
                .nth(1)
                .expect("checked by the filter");
            let id = after
                .split('`')
                .nth(1)
                .unwrap_or_else(|| {
                    panic!("a verified row must name the distro the probe reported: {line}")
                })
                .to_string();
            let sensors = after
                .split_whitespace()
                .find_map(|t| t.split_once('/').and_then(|(a, _)| a.parse::<u32>().ok()))
                .unwrap_or_else(|| panic!("a verified row must state its sensor count: {line}"));
            (id, sensors)
        })
        .collect()
}

/// "Verified" has to mean a probe ran somewhere, not that someone was confident.
///
/// Thirteen of the table's rows are inferred and say so. The risk is not that
/// they are wrong -- they are labelled -- but that one gets promoted to verified
/// because it looked right, which is how a table of guesses acquires authority
/// it has not earned.
#[test]
fn every_verified_row_has_a_recorded_probe_result() {
    let results = recorded_results();
    assert!(
        !results.is_empty(),
        "docs/compat-results.txt records no probe output, so no row can be verified"
    );
    for (distro, claimed) in verified_rows() {
        let found = results
            .iter()
            .find(|r| r.distro == distro)
            .unwrap_or_else(|| {
                panic!(
                    "COMPATIBILITY.md marks `{distro}` verified, but no ks-compat line in \
                 docs/compat-results.txt reports that distro. Run scripts/compat-probe.sh \
                 there and record its output, or mark the row inferred."
                )
            });
        assert_eq!(
            claimed, found.sensors,
            "COMPATIBILITY.md says {distro} attaches {claimed} sensors; the recorded probe \
             says {}. The evidence wins.",
            found.sensors
        );
    }
}

/// The probe reports `N of M`, where M is however many programs the agent tried
/// to attach. If a sensor is added and a result is not re-measured, the recorded
/// total silently disagrees with the code and every row built on it is stale.
#[test]
fn recorded_results_cover_the_current_sensor_count() {
    let sensors = read("src/sensors.rs")
        .lines()
        .filter(|l| l.trim_start().starts_with("attach!("))
        .count() as u32;
    assert!(
        sensors > 0,
        "no attach! invocations found in src/sensors.rs"
    );
    for r in recorded_results() {
        assert_eq!(
            r.total, sensors,
            "docs/compat-results.txt has a result for {} against {} sensors, but \
             src/sensors.rs now attaches {sensors}. Re-run the probe there.",
            r.distro, r.total
        );
    }
}
