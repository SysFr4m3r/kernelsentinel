//! The individual checks. Each one names its own false-positive rule, because
//! every one of them was measured on a real host before it was written and
//! every one needed a rule.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::Finding;
use super::packages::Manifest;

/// Directories worth walking for a setuid binary. Deliberately not `/`: a sweep
/// that takes ten minutes is a sweep nobody runs, and a setuid bit only means
/// anything on a filesystem mounted without `nosuid`.
const SUID_ROOTS: &[&str] = &["/usr", "/opt", "/srv", "/var", "/home", "/root", "/tmp"];

/// Storage belonging to container and package images, which is on this host's
/// disk but is not this host's filesystem.
///
/// Measured, and the reason this list exists at all: run as an unprivileged
/// user the setuid check reported 43 files, none unpackaged. Run as root -- the
/// only way it will ever actually run -- it reported **132 files, 88 unpackaged**,
/// and all 88 were under `/var/lib/docker/overlay2/*/diff`. Every Debian image
/// ships a setuid `su`, `mount` and `passwd`; they are the image's business and
/// they are not executable in the host's context until a container runs them.
///
/// Checking as the wrong user is how a check gets validated in conditions it
/// will never meet. The first measurement was not wrong about what it saw; it
/// was wrong about what it could see.
///
/// A setuid binary planted inside an image is a real thing, and it is a
/// different question with a different answer -- scan the image, or catch the
/// container at runtime, which the sensors already do.
const IMAGE_STORES: &[&str] = &[
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/containers",
    "/var/lib/lxc",
    "/var/lib/lxd",
    "/var/lib/machines",
    "/var/lib/snapd",
    "/snap",
];

fn is_image_store(path: &Path) -> bool {
    path.to_str().is_some_and(|p| {
        IMAGE_STORES
            .iter()
            .any(|s| p == *s || p.starts_with(&format!("{s}/")))
            // Rootless podman keeps its store per-user.
            || p.contains("/.local/share/containers/")
    })
}

/// Visit every regular file under `root`, without collecting them.
///
/// The first version pushed every path into a `Vec` and then stat'd each one
/// again. On this host that is 1,029,000 files across /usr and /home -- a
/// hundred megabytes of `PathBuf` and two million syscalls, and it did not
/// finish inside two minutes. The visitor form stats each file once and keeps
/// nothing it does not need.
///
/// `dev` pins the walk to one filesystem, the way `find -xdev` does. Without it
/// a sweep descends into container overlays, network mounts and anything else
/// that happens to be mounted under a scanned directory -- which is both slow
/// and wrong, since those are not this host's files to judge.
fn walk_files(root: &Path, depth: usize, dev: u64, visit: &mut dyn FnMut(&Path, &fs::Metadata)) {
    if depth > 16 {
        return;
    }
    let Ok(dir) = fs::read_dir(root) else { return };
    for entry in dir.flatten() {
        // d_type from the directory entry: no syscall, unlike metadata().
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        if ft.is_dir() {
            if is_image_store(&path) {
                continue;
            }
            if fs::symlink_metadata(&path).map(|m| m.dev()).ok() == Some(dev) {
                walk_files(&path, depth + 1, dev, visit);
            }
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        if let Ok(md) = fs::symlink_metadata(&path) {
            visit(&path, &md);
        }
    }
}

/// Every file *and symlink* under `root`, at any depth.
///
/// Symlinks are the point in a persistence directory, not noise to skip:
/// `systemctl enable` works by linking a unit into a `.wants` subdirectory, so
/// a link there is how a unit gets turned on. The first version of this
/// collected symlinks only at the top level and would have missed an
/// enable-link in `multi-user.target.wants/` pointing at an attacker's unit --
/// found by reading the report on this host, where two such links point at
/// units that no longer exist.
fn list_entries(root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 8 {
        return;
    }
    let Ok(dir) = fs::read_dir(root) else { return };
    for entry in dir.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let path = entry.path();
        if ft.is_symlink() || ft.is_file() {
            out.push(path);
        } else if ft.is_dir() {
            list_entries(&path, depth + 1, out);
        }
    }
}

/// Collecting form, for the small directories where the list is the point.
fn list_files(root: &Path) -> Vec<PathBuf> {
    let Ok(dev) = fs::symlink_metadata(root).map(|m| m.dev()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk_files(root, 0, dev, &mut |p, _| out.push(p.to_path_buf()));
    out
}

/// A setuid or setgid binary that no package owns.
///
/// Measured before it was written: 43 setuid/setgid files on a working Kali
/// install, **every one of them packaged**. That is what makes this check
/// worth having -- the signal is not "a setuid binary exists" but "one exists
/// that the distribution never shipped", and on a real desktop that set is
/// empty.
pub fn suid(manifest: &Manifest) -> Finding {
    if !manifest.knows() {
        return Finding::Unknown("no package manifests to compare against".into());
    }
    let mut total = 0usize;
    let mut unowned = Vec::new();
    for root in SUID_ROOTS {
        let root = Path::new(root);
        let Ok(dev) = fs::symlink_metadata(root).map(|m| m.dev()) else {
            continue;
        };
        walk_files(root, 0, dev, &mut |path, md| {
            if md.mode() & 0o6000 == 0 {
                return;
            }
            total += 1;
            if !manifest.owns(path) {
                unowned.push(format!(
                    "{} mode {:04o} uid {}",
                    path.display(),
                    md.mode() & 0o7777,
                    md.uid()
                ));
            }
        });
    }
    let skipped: Vec<&str> = IMAGE_STORES
        .iter()
        .copied()
        .filter(|s| Path::new(s).is_dir())
        .collect();
    let note = if skipped.is_empty() {
        String::new()
    } else {
        // Named, not silently dropped. A narrower claim that does not say it is
        // narrower is the same failure as a check that cannot run pretending it
        // passed.
        format!(" (image stores not examined: {})", skipped.join(", "))
    };
    if unowned.is_empty() {
        Finding::Clear(format!(
            "{total} setuid/setgid files, all package-owned{note}"
        ))
    } else {
        Finding::Suspect(
            format!(
                "{total} setuid/setgid files, {} owned by no package{note}",
                unowned.len()
            ),
            unowned,
        )
    }
}

/// Persistence directories: somewhere a program is named that the system will
/// later run on its own.
const PERSISTENCE_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/etc/systemd/system",
    "/usr/local/lib/systemd/system",
    "/etc/pam.d",
    "/etc/profile.d",
    "/etc/ld.so.conf.d",
    "/etc/update-motd.d",
    "/etc/sudoers.d",
    "/etc/init.d",
];

/// Is a symlink in a systemd unit directory one systemd made itself?
///
/// Split out from `explained` so it can be tested without being root and
/// without a real /etc. `systemctl mask` links a unit to /dev/null; `systemctl
/// enable` links it to the unit it turns on. Anything else -- including a link
/// whose target is gone, or one pointing at a unit no package owns -- is
/// somebody's doing and belongs in the report.
fn systemd_link_explained(target: &Path, target_is_packaged: bool) -> bool {
    if target == Path::new("/dev/null") {
        return true;
    }
    target_is_packaged
}

/// Is this unpackaged file explained by something other than a package?
///
/// Every rule here replaced a measured false positive, and each defers to an
/// authority the host already keeps rather than to a list maintained in here.
///
/// - **systemd**: `/etc/systemd/system` was 50 files and 50 of them unpackaged,
///   which would have made the check useless. 49 were symlinks: `systemctl
///   enable` links a packaged unit into a `.wants` directory, and `systemctl
///   mask` links one to `/dev/null`. Neither is a file anybody wrote. Only a
///   *regular* file there is somebody's doing.
/// - **PAM**: `/etc/pam.d/common-auth` and its four siblings are generated by
///   `pam-auth-update`, which records what it generated in `/var/lib/pam/`.
///   Asking that directory is better than hardcoding five names, because it is
///   the generator's own account of its work.
fn explained(path: &Path, manifest: &Manifest) -> bool {
    let Some(s) = path.to_str() else { return false };

    if s.starts_with("/etc/systemd/system") || s.starts_with("/usr/local/lib/systemd/system") {
        if let Ok(md) = fs::symlink_metadata(path) {
            if md.is_symlink() {
                let target = fs::read_link(path).unwrap_or_default();
                // canonicalize fails on a dangling link, which is the answer we
                // want: a link to a unit that no longer exists cannot be
                // explained as "enabled".
                let resolved = fs::canonicalize(path).ok();
                let packaged = resolved.as_deref().is_some_and(|r| manifest.owns(r));
                return systemd_link_explained(&target, packaged);
            }
        }
    }

    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if s.starts_with("/etc/pam.d/") {
            if let Some(stem) = name.strip_prefix("common-") {
                return Path::new("/var/lib/pam").join(stem).exists();
            }
        }
    }

    false
}

pub fn persistence(manifest: &Manifest) -> Finding {
    if !manifest.knows() {
        return Finding::Unknown("no package manifests to compare against".into());
    }
    let mut total = 0usize;
    let mut found = Vec::new();
    for dir in PERSISTENCE_DIRS {
        let root = Path::new(dir);
        if !root.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        list_entries(root, 0, &mut files);
        for path in files {
            total += 1;
            if manifest.owns(&path) || explained(&path, manifest) {
                continue;
            }
            let age = fs::symlink_metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| format!("{}d old", d.as_secs() / 86_400))
                .unwrap_or_else(|| "age unknown".into());
            found.push(format!("{} ({age})", path.display()));
        }
    }
    if found.is_empty() {
        Finding::Clear(format!(
            "{total} files across {} directories, all accounted for",
            PERSISTENCE_DIRS.len()
        ))
    } else {
        // A notice rather than a suspect: locally-installed units and scripts
        // are ordinary on a working machine. What matters is that the list is
        // short enough to read, which is what the rules above are for.
        Finding::Notice(
            format!("{total} files, {} not from a package", found.len()),
            found,
        )
    }
}

/// A process whose executable is gone from disk, or never was on it.
///
/// Close to conclusive on its own. Legitimate software does get upgraded out
/// from under itself, which is why the path is shown -- a deleted `/usr/bin/foo`
/// after an upgrade reads very differently from a deleted `/tmp/.x` or a memfd.
pub fn deleted_executables() -> Finding {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Finding::Unknown("/proc is not readable".into());
    };
    let mut total = 0usize;
    let mut found = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
        else {
            continue;
        };
        total += 1;
        let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let exe = exe.to_string_lossy().to_string();
        if exe.ends_with(" (deleted)") || exe.contains("memfd:") {
            let cmd = fs::read_to_string(format!("/proc/{pid}/cmdline"))
                .unwrap_or_default()
                .replace('\0', " ")
                .trim()
                .chars()
                .take(60)
                .collect::<String>();
            found.push(format!("pid {pid} {exe} [{cmd}]"));
        }
    }
    if found.is_empty() {
        Finding::Clear(format!("{total} processes, every executable still on disk"))
    } else {
        Finding::Suspect(
            format!(
                "{total} processes, {} running a deleted or anonymous executable",
                found.len()
            ),
            found,
        )
    }
}

/// A loaded module with no file behind it.
///
/// The module tree for the running kernel is the authority: anything in
/// /proc/modules that has no `.ko` under /lib/modules/$(uname -r) was not
/// loaded from this kernel's own set. Out-of-tree modules installed by DKMS do
/// live there, so they are not false positives.
pub fn modules() -> Finding {
    let Ok(text) = fs::read_to_string("/proc/modules") else {
        return Finding::Unknown("/proc/modules is not readable".into());
    };
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let base = format!("/lib/modules/{release}");
    if !Path::new(&base).is_dir() {
        return Finding::Unknown(format!("{base} is absent, so modules cannot be checked"));
    }

    // Walk the tree once. Doing it per module would be quadratic over ~90
    // modules and a few thousand files.
    let files = list_files(Path::new(&base));
    let on_disk: std::collections::HashSet<String> = files
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .filter_map(|n| n.split('.').next())
        // A module's file name and its name in /proc differ by - vs _, in
        // either direction depending on the module. Normalise both sides.
        .map(|stem| stem.replace('-', "_"))
        .collect();

    let mut total = 0usize;
    let mut missing = Vec::new();
    for line in text.lines() {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        total += 1;
        if !on_disk.contains(&name.replace('-', "_")) {
            missing.push(name.to_string());
        }
    }
    if missing.is_empty() {
        Finding::Clear(format!("{total} loaded, every one backed by a file"))
    } else {
        Finding::Suspect(
            format!(
                "{total} loaded, {} with no file under /lib/modules",
                missing.len()
            ),
            missing,
        )
    }
}

/// The files whose contents the kernel executes as root.
pub fn escape_hatches() -> Finding {
    let mut set = Vec::new();
    let mut checked = 0usize;
    for path in crate::watchlist::ESCAPE_HATCHES {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        checked += 1;
        let v = content.trim();
        // The kernel's own compiled-in defaults are not findings. Measured:
        // reporting "names a program" flagged modprobe=/sbin/modprobe and
        // poweroff_cmd=/sbin/poweroff on an untouched host, which is every host
        // -- a check that fires on the default state teaches an operator to
        // ignore it.
        const DEFAULTS: &[(&str, &str)] = &[
            ("/proc/sys/kernel/modprobe", "/sbin/modprobe"),
            ("/proc/sys/kernel/poweroff_cmd", "/sbin/poweroff"),
            ("/proc/sys/kernel/core_pattern", "core"),
        ];
        if DEFAULTS.iter().any(|(p, d)| *p == *path && *d == v) {
            continue;
        }
        // Anything else that pipes to a program, or names a path, is a program
        // the kernel will run as root. systemd-coredump is the common
        // legitimate case and is still printed, because reading it is how an
        // operator confirms it is that and not something else.
        if !v.is_empty() && (v.starts_with('|') || v.contains('/')) {
            set.push(format!("{path} = {v}"));
        }
    }
    if checked == 0 {
        return Finding::Unknown("no escape hatches readable on this kernel".into());
    }
    if set.is_empty() {
        Finding::Clear(format!("{checked} checked, none naming a program"))
    } else {
        Finding::Notice(
            format!("{checked} checked, {} naming a program", set.len()),
            set,
        )
    }
}

/// Every SSH key that can log into this host.
///
/// Listed, never judged. This project cannot know which of your keys is yours,
/// and a tool that guesses would be wrong in the direction that matters. What
/// it can do is put them in one place with their age, which is the form in
/// which a person can recognise one that should not be there.
pub fn authorized_keys() -> Finding {
    let mut homes = vec![PathBuf::from("/root")];
    if let Ok(dir) = fs::read_dir("/home") {
        homes.extend(dir.flatten().map(|e| e.path()));
    }
    let mut keys = Vec::new();
    let mut files = 0usize;
    for home in homes {
        for name in ["authorized_keys", "authorized_keys2"] {
            let path = home.join(".ssh").join(name);
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            files += 1;
            let age = fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|d| format!("{}d", d.as_secs() / 86_400))
                .unwrap_or_else(|| "?".into());
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // The comment field is the only human-meaningful part; the key
                // body is noise in a report a person has to read.
                let comment = line.split_whitespace().nth(2).unwrap_or("(no comment)");
                let kind = line.split_whitespace().next().unwrap_or("?");
                keys.push(format!(
                    "{} — {kind} {comment} (file {age} old)",
                    path.display()
                ));
            }
        }
    }
    if keys.is_empty() {
        Finding::Clear(format!("{files} authorized_keys files, no keys"))
    } else {
        Finding::Notice(format!("{} keys across {files} files", keys.len()), keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Measured on a working host: /etc/systemd/system held 50 files and every
    /// one of them was unpackaged, which would have made the whole check
    /// useless. 49 were systemd's own links -- 45 enabling a packaged unit, one
    /// masking a unit to /dev/null. Only a regular file, or a link systemd did
    /// not make, is somebody's doing.
    #[test]
    fn systemd_links_that_systemd_made_are_not_findings() {
        // systemctl enable: a link to the packaged unit it turns on.
        assert!(systemd_link_explained(
            Path::new("/lib/systemd/system/ssh.service"),
            true
        ));
        // systemctl mask.
        assert!(systemd_link_explained(Path::new("/dev/null"), false));
        // A link to a unit no package owns: the attacker's shape, and also how
        // a locally-installed unit looks. Reported either way.
        assert!(!systemd_link_explained(
            Path::new("/tmp/evil.service"),
            false
        ));
        // A dangling link resolves to nothing, so it cannot be packaged. Found
        // on the development host: two .wants links pointing at units that had
        // been removed, invisible until symlinks were walked recursively.
        assert!(!systemd_link_explained(Path::new("/gone.service"), false));
    }

    /// The escape-hatch check fired on an untouched host until the kernel's own
    /// defaults were recognised. A check that fires on the default state of
    /// every host teaches its operator to ignore it.
    #[test]
    fn the_kernel_defaults_are_not_escape_hatch_findings() {
        let f = escape_hatches();
        if let Finding::Notice(_, items) | Finding::Suspect(_, items) = f {
            for item in &items {
                assert!(
                    !item.contains("= /sbin/modprobe") && !item.contains("= /sbin/poweroff"),
                    "reported a kernel default as a finding: {item}"
                );
            }
        }
    }

    /// A check that cannot run must say so rather than reporting success.
    /// "0 findings" and "could not look" are the same output and opposite
    /// meanings, which is the failure this whole project keeps finding.
    #[test]
    fn a_check_without_an_authority_is_unknown_not_clear() {
        let empty = Manifest::default_for_test();
        assert!(matches!(suid(&empty), Finding::Unknown(_)));
        assert!(matches!(persistence(&empty), Finding::Unknown(_)));
    }
}

#[cfg(test)]
mod store_tests {
    use super::*;

    /// Run unprivileged the setuid check saw 43 files and none unpackaged. Run
    /// as root -- the only way it ever actually runs -- it saw 132 and 88
    /// unpackaged, every one of them a container image layer under
    /// /var/lib/docker/overlay2. 88 false positives is not a noisy check, it is
    /// an unusable one.
    #[test]
    fn container_image_layers_are_not_this_hosts_files() {
        for p in [
            "/var/lib/docker/overlay2/abc/diff/usr/bin/su",
            "/var/lib/docker",
            "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
            "/var/lib/containers/storage/overlay",
            "/home/kali/.local/share/containers/storage/overlay/x/diff",
            "/snap/core/current",
            "/var/lib/snapd/snaps",
        ] {
            assert!(is_image_store(Path::new(p)), "{p} should be skipped");
        }
    }

    /// The prune must not swallow the directories the check exists for. A
    /// prefix match on "/var/lib" or a substring match on "docker" would take
    /// /var/lib/dockerish, /var/tmp and /var/www with it.
    #[test]
    fn the_prune_does_not_swallow_the_host() {
        for p in [
            "/var/tmp",
            "/var/www",
            "/var/lib/dpkg",
            "/var/lib/dockerish",
            "/usr/bin",
            "/home/kali/bin",
            "/opt/thing",
        ] {
            assert!(!is_image_store(Path::new(p)), "{p} must still be scanned");
        }
    }
}
