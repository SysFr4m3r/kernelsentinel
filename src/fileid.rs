//! File identity: the `(device, inode)` pair the kernel uses to say "this exact
//! file", independent of the path it was reached through.
//!
//! This exists because names are attacker-controlled and identities are not.
//! A path can be bind-mounted elsewhere, a `comm` can be set with one `prctl`,
//! but an inode is what the kernel actually opened. Every matching rule that
//! decides whether something is trusted belongs here rather than on a string.
//!
//! # The device number is encoded twice, differently
//!
//! `stat(2)` through glibc hands back a `dev_t` in glibc's own encoding, which
//! splits major and minor across non-contiguous bit ranges. The kernel's
//! `super_block::s_dev` -- what BPF reads, and what a BPF map key must contain
//! -- is the 32-bit `MKDEV` form: `(major << 20) | minor`.
//!
//! For anything on a pseudo-filesystem the two agree by accident: procfs and
//! sysfs have major 0 and a small minor, so both encodings are just the minor
//! number. That is exactly the range the escape-hatch map covers, which is why
//! comparing a raw glibc `dev_t` against `s_dev` appeared to work. It does not
//! generalise: `/usr/bin/sudo` on this machine is major 8, minor 1, which is
//! 2049 to glibc and 8388609 to the kernel. Anything on a real disk compared in
//! the wrong encoding silently never matches -- a lookup that always misses, in
//! the direction that produces no alert.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

/// Bits the kernel gives the minor number in a 32-bit `dev_t` (`MINORBITS`).
const MINOR_BITS: u32 = 20;

/// Convert a glibc `dev_t` into the kernel's `s_dev` encoding.
///
/// `libc::major`/`libc::minor` unpack glibc's layout; `MKDEV` repacks it the way
/// the kernel stores it on a superblock.
pub fn kernel_dev(glibc_dev: u64) -> u32 {
    let (major, minor) = (libc::major(glibc_dev) as u64, libc::minor(glibc_dev) as u64);
    ((major << MINOR_BITS) | (minor & ((1 << MINOR_BITS) - 1))) as u32
}

/// A file's identity in the kernel's own terms. Mirrors `struct file_id` in
/// `bpf/events.h`, whose `dev` is a `s_dev`, not a glibc `dev_t`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct FileId {
    pub dev: u32,
    pub ino: u64,
}

impl FileId {
    pub fn new(dev: u32, ino: u64) -> Self {
        Self { dev, ino }
    }

    /// Identify the file at `path`, following symlinks. `None` when it does not
    /// exist or cannot be stat'd -- an unresolvable path is never guessed at.
    pub fn of(path: &str) -> Option<Self> {
        let md = std::fs::metadata(path).ok()?;
        Some(Self {
            dev: kernel_dev(md.dev()),
            ino: md.ino(),
        })
    }

    /// True for the zero identity, which is what an unknown or unreadable file
    /// decodes to. A zero id must never match anything.
    pub fn is_unknown(&self) -> bool {
        self.ino == 0
    }

    /// The raw bytes of `struct file_id { u64 ino; u32 dev; u32 _pad; }`, for a
    /// BPF map key.
    pub fn to_map_key(self) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&self.ino.to_ne_bytes());
        key[8..12].copy_from_slice(&self.dev.to_ne_bytes());
        key
    }
}

/// What a known system binary is trusted to do. A program earns a role by being
/// the file at a known system path, never by being *named* like one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Reads the credential store as its actual job: every authentication on the
    /// host goes through one, so a read by one of these is not evidence.
    CredentialReader,
    /// Faces the network and has no legitimate reason to spawn a shell.
    NetworkDaemon,
}

/// One trusted program: a canonical name, what it is trusted for, and the paths
/// it might live at. Distributions disagree about `/usr/bin` vs `/usr/sbin` and
/// about which of these exist at all, so every plausible location is listed and
/// the ones that are absent are simply skipped.
pub struct Trusted {
    pub name: &'static str,
    pub role: Role,
    pub paths: &'static [&'static str],
}

/// Programs whose whole job is to read the credential store.
///
/// Previously matched on `comm`, which the process itself controls: one
/// `prctl(PR_SET_NAME, "sudo")`, or a binary copied to `/tmp/sudo`, suppressed
/// the credential-read signal outright. Resolving these to file identities
/// means an attacker has to *be* the real `/usr/bin/sudo` -- which requires
/// write access to a system directory they should not have.
const CREDENTIAL_READERS: &[Trusted] = &[
    t(
        "unix_chkpwd",
        Role::CredentialReader,
        &["/usr/sbin/unix_chkpwd", "/sbin/unix_chkpwd"],
    ),
    t(
        "sshd",
        Role::CredentialReader,
        &["/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"],
    ),
    t(
        "sudo",
        Role::CredentialReader,
        &["/usr/bin/sudo", "/bin/sudo"],
    ),
    t("su", Role::CredentialReader, &["/usr/bin/su", "/bin/su"]),
    t(
        "login",
        Role::CredentialReader,
        &["/usr/bin/login", "/bin/login"],
    ),
    t(
        "passwd",
        Role::CredentialReader,
        &["/usr/bin/passwd", "/bin/passwd"],
    ),
    t(
        "chpasswd",
        Role::CredentialReader,
        &["/usr/sbin/chpasswd", "/sbin/chpasswd"],
    ),
    t(
        "gpasswd",
        Role::CredentialReader,
        &["/usr/bin/gpasswd", "/bin/gpasswd"],
    ),
    t(
        "newgrp",
        Role::CredentialReader,
        &["/usr/bin/newgrp", "/bin/newgrp"],
    ),
    t(
        "usermod",
        Role::CredentialReader,
        &["/usr/sbin/usermod", "/sbin/usermod"],
    ),
    t(
        "useradd",
        Role::CredentialReader,
        &["/usr/sbin/useradd", "/sbin/useradd"],
    ),
    t(
        "userdel",
        Role::CredentialReader,
        &["/usr/sbin/userdel", "/sbin/userdel"],
    ),
    t(
        "vipw",
        Role::CredentialReader,
        &["/usr/sbin/vipw", "/sbin/vipw"],
    ),
    t(
        "systemd-logind",
        Role::CredentialReader,
        &[
            "/usr/lib/systemd/systemd-logind",
            "/lib/systemd/systemd-logind",
            "/usr/sbin/systemd-logind",
        ],
    ),
    t(
        "sssd",
        Role::CredentialReader,
        &[
            "/usr/sbin/sssd",
            "/usr/libexec/sssd/sssd_pam",
            "/usr/libexec/sssd/sssd_nss",
        ],
    ),
    t(
        "agetty",
        Role::CredentialReader,
        &["/usr/sbin/agetty", "/sbin/agetty"],
    ),
    t(
        "gdm-session-worker",
        Role::CredentialReader,
        &[
            "/usr/libexec/gdm-session-worker",
            "/usr/lib/gdm3/gdm-session-worker",
            "/usr/lib/gdm/gdm-session-worker",
        ],
    ),
    t(
        "lightdm",
        Role::CredentialReader,
        &["/usr/sbin/lightdm", "/usr/bin/lightdm"],
    ),
    t(
        "accounts-daemon",
        Role::CredentialReader,
        &[
            "/usr/libexec/accounts-daemon",
            "/usr/lib/accountsservice/accounts-daemon",
        ],
    ),
    t(
        "polkitd",
        Role::CredentialReader,
        &[
            "/usr/lib/polkit-1/polkitd",
            "/usr/libexec/polkitd",
            "/usr/sbin/polkitd",
        ],
    ),
];

/// Web and database servers. `sshd` is deliberately absent: it spawns the login
/// shell, which is the whole point of it.
///
/// Same reasoning as the credential readers, mirrored. Here the name decided
/// whether a signal *fires* rather than whether it is suppressed, so an attacker
/// with code execution inside nginx could rename the process before spawning a
/// shell and the detection would not fire at all. Identity comes from the
/// process's mapped executable, which renaming does not touch.
const NETWORK_DAEMONS: &[Trusted] = &[
    t(
        "nginx",
        Role::NetworkDaemon,
        &[
            "/usr/sbin/nginx",
            "/usr/bin/nginx",
            "/usr/local/nginx/sbin/nginx",
        ],
    ),
    t(
        "apache2",
        Role::NetworkDaemon,
        &[
            "/usr/sbin/apache2",
            "/usr/sbin/httpd",
            "/usr/local/apache2/bin/httpd",
        ],
    ),
    t(
        "php-fpm",
        Role::NetworkDaemon,
        &[
            "/usr/sbin/php-fpm",
            "/usr/sbin/php-fpm8.2",
            "/usr/sbin/php-fpm8.3",
            "/usr/sbin/php-fpm7.4",
            "/usr/bin/php-fpm",
        ],
    ),
    t(
        "tomcat",
        Role::NetworkDaemon,
        &[
            "/usr/share/tomcat/bin/catalina.sh",
            "/opt/tomcat/bin/catalina.sh",
        ],
    ),
    t(
        "node",
        Role::NetworkDaemon,
        &["/usr/bin/node", "/usr/local/bin/node", "/usr/bin/nodejs"],
    ),
    t(
        "gunicorn",
        Role::NetworkDaemon,
        &["/usr/bin/gunicorn", "/usr/local/bin/gunicorn"],
    ),
    t(
        "uwsgi",
        Role::NetworkDaemon,
        &["/usr/bin/uwsgi", "/usr/local/bin/uwsgi"],
    ),
    t(
        "mysqld",
        Role::NetworkDaemon,
        &["/usr/sbin/mysqld", "/usr/libexec/mysqld"],
    ),
    t(
        "mariadbd",
        Role::NetworkDaemon,
        &["/usr/sbin/mariadbd", "/usr/bin/mariadbd"],
    ),
    t(
        "postgres",
        Role::NetworkDaemon,
        &[
            "/usr/lib/postgresql/16/bin/postgres",
            "/usr/lib/postgresql/15/bin/postgres",
            "/usr/bin/postgres",
            "/usr/pgsql/bin/postgres",
        ],
    ),
    t(
        "redis-server",
        Role::NetworkDaemon,
        &["/usr/bin/redis-server", "/usr/local/bin/redis-server"],
    ),
    t(
        "mongod",
        Role::NetworkDaemon,
        &["/usr/bin/mongod", "/usr/local/bin/mongod"],
    ),
    t(
        "memcached",
        Role::NetworkDaemon,
        &["/usr/bin/memcached", "/usr/local/bin/memcached"],
    ),
];

const fn t(name: &'static str, role: Role, paths: &'static [&'static str]) -> Trusted {
    Trusted { name, role, paths }
}

/// Every trusted program, resolved to the identities it actually has on *this*
/// host. Built once at startup: the map is what turns "a process called sudo"
/// into "the process running the file that is /usr/bin/sudo here".
#[derive(Default)]
pub struct TrustedBinaries {
    by_id: HashMap<FileId, (&'static str, Role)>,
    /// Programs whose every candidate path was absent. Not an error -- most
    /// hosts do not run postgres -- but worth reporting, because a credential
    /// reader that fails to resolve becomes a source of alerts.
    unresolved: Vec<&'static str>,
}

impl TrustedBinaries {
    /// Empty: nothing is trusted, so nothing is suppressed and no daemon is
    /// recognised. This is the fail-open-toward-alerting default, and it is what
    /// replay uses -- see `resolve` on the decoded event.
    pub fn none() -> Self {
        Self::default()
    }

    /// Resolve the built-in tables against this host's filesystem.
    pub fn resolve_host() -> Self {
        let mut by_id = HashMap::new();
        let mut unresolved = Vec::new();
        for entry in CREDENTIAL_READERS.iter().chain(NETWORK_DAEMONS) {
            let mut found = false;
            for path in entry.paths {
                if let Some(id) = FileId::of(path) {
                    // A hardlinked or identically-inoded path resolving twice is
                    // fine; first name wins and they are the same program.
                    by_id.entry(id).or_insert((entry.name, entry.role));
                    found = true;
                }
            }
            if !found {
                unresolved.push(entry.name);
            }
        }
        Self { by_id, unresolved }
    }

    /// The canonical name and role of the program with this identity.
    pub fn lookup(&self, id: FileId) -> Option<(&'static str, Role)> {
        if id.is_unknown() {
            return None;
        }
        self.by_id.get(&id).copied()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    pub fn unresolved(&self) -> &[&'static str] {
        &self.unresolved
    }

    /// Is `name` a program the given role's table lists?
    ///
    /// Takes a canonical name that was itself produced by an identity lookup --
    /// `ProcNode::trusted`, never a `comm`. The tables stay the single source of
    /// truth for which program plays which role, so a detector asks this rather
    /// than carrying its own copy of the list.
    pub fn has_role(name: &str, role: Role) -> bool {
        if name.is_empty() {
            return false;
        }
        CREDENTIAL_READERS
            .iter()
            .chain(NETWORK_DAEMONS)
            .any(|e| e.name == name && e.role == role)
    }

    /// Does this *name alone* look like a network daemon?
    ///
    /// The one place a bare name is still consulted, and only because of what it
    /// can do: this decides whether a signal **fires**, never whether one is
    /// suppressed. A process falsely called `nginx` accuses itself; a process
    /// falsely called `sudo` must never be able to excuse itself. Names may
    /// accuse, never exonerate.
    ///
    /// It buys back the daemons identity cannot see. `gunicorn` and `uwsgi` are
    /// usually shebang scripts, so the kernel's mapped executable is the Python
    /// interpreter and identity resolves to `python3` -- correct, and useless
    /// here. `comm` is the script name, so the name path still catches them.
    pub fn name_looks_like_daemon(comm: &str) -> bool {
        if comm.is_empty() {
            return false;
        }
        NETWORK_DAEMONS
            .iter()
            .any(|e| e.name == comm || comm.starts_with(e.name))
    }

    /// One line for the startup banner. The unresolved count matters to an
    /// operator: those programs are not recognised on this host, so if one of
    /// them is a credential reader that is actually installed somewhere else,
    /// its reads will alert until the path is added.
    pub fn summary(&self) -> String {
        format!(
            "{} trusted system binaries resolved by identity, {} not present",
            self.by_id.len(),
            self.unresolved.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug this module exists to prevent. Both encodings agree for major 0,
    /// which is every pseudo-filesystem -- and is why comparing a glibc dev_t
    /// against a kernel s_dev looked correct for as long as the only identities
    /// being matched lived in /proc and /sys.
    #[test]
    fn encodings_agree_only_on_pseudo_filesystems() {
        // major 0, minor 23: procfs. glibc and kernel forms coincide.
        let procfs = libc::makedev(0, 23);
        assert_eq!(kernel_dev(procfs), 23);
        assert_eq!(procfs as u32, 23, "the accident this relied on");

        // major 8, minor 1: the first SCSI/SATA disk, where they diverge.
        let sda1 = libc::makedev(8, 1);
        assert_eq!(kernel_dev(sda1), (8 << 20) | 1);
        assert_ne!(
            sda1 as u32,
            kernel_dev(sda1),
            "a raw glibc dev_t must not be usable as an s_dev"
        );
    }

    #[test]
    fn kernel_dev_round_trips_the_kernel_macro() {
        for (major, minor) in [(0u64, 0u64), (0, 23), (8, 1), (259, 5), (253, 0)] {
            let d = libc::makedev(major as _, minor as _);
            assert_eq!(
                kernel_dev(d),
                ((major << MINOR_BITS) | minor) as u32,
                "major {major} minor {minor}"
            );
        }
    }

    #[test]
    fn identity_of_a_real_file_is_stable_and_specific() {
        let a = FileId::of("/proc/self/stat").expect("procfs is mounted");
        let b = FileId::of("/proc/self/stat").unwrap();
        assert_eq!(a, b, "same file, same identity");
        assert!(!a.is_unknown());
        assert_eq!(FileId::of("/nonexistent/definitely"), None);
    }

    #[test]
    fn map_key_matches_the_bpf_struct_layout() {
        let id = FileId::new(0x0080_0001, 0x1234_5678_9abc_def0);
        let key = id.to_map_key();
        assert_eq!(u64::from_ne_bytes(key[..8].try_into().unwrap()), id.ino);
        assert_eq!(u32::from_ne_bytes(key[8..12].try_into().unwrap()), id.dev);
        assert_eq!(&key[12..], &[0, 0, 0, 0], "_pad must be zeroed");
    }

    #[test]
    fn an_unknown_identity_matches_nothing() {
        let t = TrustedBinaries::resolve_host();
        assert_eq!(t.lookup(FileId::default()), None);
        assert_eq!(t.lookup(FileId::new(0, 0)), None);
    }

    /// The empty set trusts nothing, which must mean "no suppression", never
    /// "everything suppressed".
    #[test]
    fn the_empty_set_trusts_nothing() {
        let t = TrustedBinaries::none();
        assert!(t.is_empty());
        assert_eq!(t.lookup(FileId::new(8 << 20, 42)), None);
    }

    /// Not an assertion about which programs exist -- that varies per host --
    /// but that resolution works at all and never invents an identity.
    #[test]
    fn host_resolution_finds_something_and_invents_nothing() {
        let t = TrustedBinaries::resolve_host();
        for (id, (name, _)) in &t.by_id {
            assert!(!id.is_unknown(), "{name} resolved to a zero identity");
        }
        // /bin/su or /usr/bin/su exists on every system this runs on.
        let su = FileId::of("/usr/bin/su").or_else(|| FileId::of("/bin/su"));
        if let Some(su) = su {
            assert_eq!(t.lookup(su).map(|(n, _)| n), Some("su"));
        }
    }
}
