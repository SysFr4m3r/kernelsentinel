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
    /// Tracked paths as they exist on *this* host, including where the listed
    /// path resolves to.
    ///
    /// The table lists `/usr/sbin/unix_chkpwd`, and on a usr-merged host --
    /// Arch, and every distribution that followed -- `/usr/sbin` is a symlink
    /// to `/usr/bin`. `stat` resolves the listed path happily, so the program
    /// appears in `by_id` and `doctor` reports it found; but the kernel reports
    /// the *real* path at exec, `/usr/bin/unix_chkpwd`, which matches no listed
    /// string. Comparing the literal list against an exec's filename therefore
    /// missed on exactly the hosts where the identity also needed relearning.
    by_path: HashMap<String, (&'static str, Role)>,
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
        let mut by_path: HashMap<String, (&'static str, Role)> = HashMap::new();
        let mut unresolved = Vec::new();
        for entry in CREDENTIAL_READERS.iter().chain(NETWORK_DAEMONS) {
            let mut found = false;
            for path in entry.paths {
                if let Some(id) = FileId::of(path) {
                    // A hardlinked or identically-inoded path resolving twice is
                    // fine; first name wins and they are the same program.
                    by_id.entry(id).or_insert((entry.name, entry.role));
                    by_path.insert(path.to_string(), (entry.name, entry.role));
                    // And where it really lives, which is what an exec event
                    // will name on a usr-merged host.
                    if let Ok(real) = std::fs::canonicalize(path) {
                        if let Some(r) = real.to_str() {
                            by_path.insert(r.to_string(), (entry.name, entry.role));
                        }
                    }
                    found = true;
                }
            }
            if !found {
                unresolved.push(entry.name);
            }
        }
        Self {
            by_id,
            by_path,
            unresolved,
        }
    }

    /// Re-resolve one path whose identity the table no longer recognises.
    ///
    /// The table is built once, by `stat`, at startup. A package upgrade
    /// replaces binaries in place: the path is the same and the inode is not,
    /// so every entry the upgrade touched silently stops matching. The failure
    /// direction is the bad one -- suppression turns *off* and the program
    /// starts alerting -- and it is permanent until the daemon restarts.
    ///
    /// Measured, not theorised. In a 1.4-hour capture containing one
    /// `apt upgrade`:
    ///
    /// ```text
    /// unix_chkpwd  ino=4850166  trusted="unix_chkpwd"   18 execs   0-24 min
    /// unix_chkpwd  ino=4853411  trusted=""              19 execs  30-80 min
    /// ```
    ///
    /// Nineteen false `credential_store_read` signals, each feeding a CRITICAL
    /// incident, from PAM's own password checker doing its job.
    ///
    /// Re-resolving the whole table on a timer would work and would also stat
    /// thirty-odd paths forever, on every host, to catch an event that happens
    /// on upgrade day. This is called only when an exec's path is one the table
    /// knows and its identity did not match -- precisely the replaced-binary
    /// case -- so the steady-state cost is one hash lookup that already had to
    /// happen.
    ///
    /// Returns the name and role now at that path, if it is one this table
    /// tracks and it currently exists.
    pub fn rebind(&mut self, path: &str) -> Option<(&'static str, Role)> {
        let id = FileId::of(path)?;
        self.bind(path, id)
    }

    /// Learn the identity *the kernel reports* for a tracked path.
    ///
    /// `stat` and the kernel do not always agree about a file's device, and
    /// when they disagree every identity comparison fails silently and in the
    /// direction that generates alerts. Measured on a btrfs host, for the same
    /// file:
    ///
    /// ```text
    /// stat()  dev = 37  ino = 17746   /usr/bin/unix_chkpwd
    /// BPF     dev = 35  ino = 17746
    /// ```
    ///
    /// btrfs allocates an anonymous block device per subvolume. Userspace gets
    /// the subvolume's, while an LSM or tracepoint program reading
    /// `inode->i_sb->s_dev` gets the superblock's. Neither is wrong; they are
    /// different numbers for different things, and nothing in the encoding
    /// says so -- both have major 0, so the glibc/kernel conversion that fixed
    /// an earlier bug of this shape leaves them untouched.
    ///
    /// The cost was 33 of 43 incidents on one desktop in a day: PAM's password
    /// checker reading /etc/shadow at every screen unlock, scored CRITICAL,
    /// because the suppression that exists for exactly that case could not
    /// recognise the binary. Default on CachyOS, Fedora and openSUSE.
    ///
    /// `rebind` alone cannot fix it -- it re-stats the path, gets the same
    /// unmatchable device, and relearns the wrong thing forever. So the
    /// identity is taken from the event instead.
    ///
    /// **The inode must still match.** Only the device may differ, and only
    /// because the two sides genuinely name different objects. An attacker
    /// wanting to poison this would have to place their binary *at the trusted
    /// path*, which needs write access to a system directory -- the same bar
    /// that already protects the table, and the reason a path is allowed to
    /// identify a program at all while a `comm` is not.
    pub fn rebind_from_kernel(&mut self, path: &str, seen: FileId) -> Option<(&'static str, Role)> {
        if seen.is_unknown() {
            return None;
        }
        // The file at that path, right now, must be the one that just ran.
        let on_disk = FileId::of(path)?;
        if on_disk.ino != seen.ino {
            return None;
        }
        self.bind(path, seen)
    }

    /// Point a tracked path's program at one identity, replacing any other.
    fn bind(&mut self, path: &str, id: FileId) -> Option<(&'static str, Role)> {
        let entry = *self.by_path.get(path)?;
        let entry = Trusted {
            name: entry.0,
            role: entry.1,
            paths: &[],
        };
        // Drop any stale identity still claiming this program, so the table
        // does not grow an entry per upgrade for the lifetime of the daemon.
        self.by_id.retain(|_, (name, _)| *name != entry.name);
        self.by_id.insert(id, (entry.name, entry.role));
        self.unresolved.retain(|n| *n != entry.name);
        Some((entry.name, entry.role))
    }

    /// Does the table track this path at all? Cheap enough to ask per exec, and
    /// the gate that keeps `rebind` off the hot path.
    pub fn tracks_path(&self, path: &str) -> bool {
        self.by_path.contains_key(path)
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

#[cfg(test)]
mod rebind_tests {
    use super::*;

    /// A package upgrade replaces a binary in place: same path, new inode. The
    /// table was built once by `stat`, so the entry stops matching and the
    /// program silently loses its trusted identity -- which turns *off* the
    /// suppression that keeps PAM's own password checker from alerting.
    ///
    /// Measured in a 1.4-hour capture containing one `apt upgrade`:
    /// `/usr/sbin/unix_chkpwd` went from ino=4850166 (trusted, 18 execs) to
    /// ino=4853411 (untrusted, 19 execs), and each of those 19 reads of
    /// /etc/shadow fed a CRITICAL incident.
    #[test]
    fn a_replaced_binary_is_rebound_rather_than_silently_untrusted() {
        // Resolve against a real tracked path, whichever this host has.
        let mut t = TrustedBinaries::resolve_host();
        let Some(path) = CREDENTIAL_READERS
            .iter()
            .flat_map(|e| e.paths.iter())
            .find(|p| std::path::Path::new(p).exists())
            .copied()
        else {
            // No tracked credential reader installed; nothing to rebind.
            return;
        };

        let real = FileId::of(path).expect("path exists");
        assert!(t.lookup(real).is_some(), "{path} must resolve at startup");

        // The upgrade: forget the identity the table learned, exactly as a
        // replaced inode does.
        let (name, role) = t.lookup(real).unwrap();
        t.by_id.remove(&real);
        assert!(
            t.lookup(real).is_none(),
            "precondition: the stale table must not match"
        );

        // What the daemon now does on the next exec of that path.
        assert!(t.tracks_path(path), "{path} must be recognised as tracked");
        let (again, role_again) = t.rebind(path).expect("rebind must resolve it");
        assert_eq!(again, name);
        assert_eq!(role_again, role);
        assert!(
            t.lookup(real).is_some(),
            "after rebinding, the identity must match again"
        );
    }

    /// Rebinding must not leave the previous identity behind. A daemon running
    /// across several upgrades would otherwise accumulate one dead entry per
    /// upgrade, each still claiming to be the trusted program.
    #[test]
    fn rebinding_drops_the_identity_it_replaces() {
        let mut t = TrustedBinaries::resolve_host();
        let Some(path) = CREDENTIAL_READERS
            .iter()
            .flat_map(|e| e.paths.iter())
            .find(|p| std::path::Path::new(p).exists())
            .copied()
        else {
            return;
        };
        let (name, _) = t.rebind(path).expect("resolves");
        let before = t.by_id.values().filter(|(n, _)| *n == name).count();
        t.rebind(path);
        let after = t.by_id.values().filter(|(n, _)| *n == name).count();
        assert_eq!(before, 1, "one identity per program");
        assert_eq!(after, 1, "rebinding must not add a second");
    }

    /// Measured on a btrfs host, for one file, at the same moment:
    ///
    /// ```text
    /// stat()  dev = 37  ino = 17746   /usr/bin/unix_chkpwd
    /// BPF     dev = 35  ino = 17746
    /// ```
    ///
    /// btrfs gives each subvolume its own anonymous block device. Userspace
    /// sees the subvolume's; a BPF program reading `inode->i_sb->s_dev` sees
    /// the superblock's. Both have major 0, so the glibc/kernel device
    /// conversion leaves them alone and nothing in the numbers says they are
    /// different things.
    ///
    /// That cost 33 of 43 incidents on one desktop in a day, and `rebind`
    /// could not repair it: re-stating the path returns 37 again, so the table
    /// relearns the identity that cannot match.
    #[test]
    fn an_identity_the_kernel_reports_is_learned_even_when_stat_disagrees() {
        let mut t = TrustedBinaries::resolve_host();
        let Some(path) = CREDENTIAL_READERS
            .iter()
            .flat_map(|e| e.paths.iter())
            .find(|p| std::path::Path::new(p).exists())
            .copied()
        else {
            return;
        };
        let from_stat = FileId::of(path).expect("path exists");

        // What a btrfs kernel would report for the same file: same inode, the
        // superblock's device instead of the subvolume's.
        let from_kernel = FileId::new(from_stat.dev.wrapping_sub(2), from_stat.ino);
        assert!(
            t.lookup(from_kernel).is_none(),
            "precondition: the kernel's identity must not match the table yet"
        );

        let (name, _) = t
            .rebind_from_kernel(path, from_kernel)
            .expect("a tracked path must be learnable from the kernel's identity");
        assert!(
            t.lookup(from_kernel).is_some(),
            "{name} must now be recognised by the identity events actually carry"
        );
    }

    /// Only the *device* may disagree. A different inode at the trusted path is
    /// a different file, and learning it would let anything that manages to run
    /// as the trusted program inherit its suppression.
    #[test]
    fn a_different_inode_is_never_learned() {
        let mut t = TrustedBinaries::resolve_host();
        let Some(path) = CREDENTIAL_READERS
            .iter()
            .flat_map(|e| e.paths.iter())
            .find(|p| std::path::Path::new(p).exists())
            .copied()
        else {
            return;
        };
        let real = FileId::of(path).expect("exists");
        let impostor = FileId::new(real.dev, real.ino ^ 0xbeef);
        assert!(t.rebind_from_kernel(path, impostor).is_none());
        assert!(t.lookup(impostor).is_none(), "must not be trusted");
        // An unknown identity carries no information and must not be learned.
        assert!(t.rebind_from_kernel(path, FileId::new(0, 0)).is_none());
    }

    /// A usr-merged host reports a different path than the table lists, and
    /// that difference silently disabled the fix above.
    ///
    /// The table lists `/usr/sbin/unix_chkpwd`. On Arch -- and every
    /// distribution that followed usr-merge -- `/usr/sbin` is a symlink to
    /// `/usr/bin`. `stat` resolves the listed path, so the program lands in
    /// the identity index and `doctor` reports it found; but the kernel names
    /// the real path at exec, `/usr/bin/unix_chkpwd`, which matches no listed
    /// string. Comparing the literal list against an exec's filename missed on
    /// exactly the hosts that also needed their identity relearned, so the
    /// btrfs repair could never run and the alerts continued.
    #[test]
    fn a_path_is_tracked_by_where_it_resolves_not_only_by_how_it_is_listed() {
        let t = TrustedBinaries::resolve_host();
        let mut checked = 0;
        for entry in CREDENTIAL_READERS.iter().chain(NETWORK_DAEMONS) {
            for listed in entry.paths {
                let Ok(real) = std::fs::canonicalize(listed) else {
                    continue;
                };
                let Some(real) = real.to_str() else { continue };
                checked += 1;
                assert!(
                    t.tracks_path(listed),
                    "{listed} is listed and present, so it must be tracked"
                );
                assert!(
                    t.tracks_path(real),
                    "{listed} really lives at {real}, which is the path an exec \
                     event carries -- it must be tracked too"
                );
            }
        }
        assert!(checked > 0, "no trusted binary present to check");
    }

    /// An untracked path is never stat'd. This is what keeps the check off the
    /// hot path: every exec asks, and only the handful of tracked paths cost
    /// anything.
    #[test]
    fn an_untracked_path_is_not_rebound() {
        let mut t = TrustedBinaries::resolve_host();
        assert!(!t.tracks_path("/usr/bin/ls"));
        assert!(t.rebind("/usr/bin/ls").is_none());
        assert!(!t.tracks_path("/tmp/sudo"));
        assert!(t.rebind("/tmp/sudo").is_none());
    }
}
