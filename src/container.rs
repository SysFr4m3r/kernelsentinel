//! Container resolution. A cgroup id from the kernel (bpf_get_current_cgroup_id)
//! is the kernfs inode of the process's cgroup directory. Walking
//! /sys/fs/cgroup and statting each directory therefore yields a
//! cgroup_id -> container map, which is resolved at capture time and stored on
//! the event -- so a replayed capture carries container context even though the
//! original cgroups are long gone.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerRef {
    pub runtime: &'static str,
    /// Short container id (first 12 chars), as users see in `docker ps`.
    pub id: String,
}

impl ContainerRef {
    pub fn label(&self) -> String {
        format!("{}:{}", self.runtime, self.id)
    }
}

/// Extract a container reference from a cgroup path component, if it names one.
/// Handles the common runtimes across cgroup v1 and v2 layouts.
pub fn parse_container(path: &str) -> Option<ContainerRef> {
    // Fast path: container scopes carry a runtime prefix ("docker-", ...) so
    // they contain '-', or are a bare >=32-char hex id. Host leaf names like
    // "init.scope" or "user.slice" have neither -- skip the scan for them, since
    // this runs on every event.
    if !path.contains('-') && path.len() < 32 {
        return None;
    }
    for part in path.split('/') {
        // systemd-driver scopes: docker-<hex>.scope, cri-containerd-<hex>.scope,
        // libpod-<hex>.scope, crio-<hex>.scope.
        let stem = part.strip_suffix(".scope").unwrap_or(part);
        for (prefix, runtime) in [
            ("docker-", "docker"),
            ("cri-containerd-", "containerd"),
            ("containerd-", "containerd"),
            ("libpod-", "podman"),
            ("crio-", "crio"),
        ] {
            if let Some(id) = stem.strip_prefix(prefix) {
                if is_hex_id(id) {
                    return Some(ContainerRef {
                        runtime,
                        id: short(id),
                    });
                }
            }
        }
        // cgroupfs-driver: a bare 64-hex path component (…/docker/<hex>, or the
        // kubepods pod path ending in a container id).
        if is_hex_id(stem) && stem.len() >= 32 {
            return Some(ContainerRef {
                runtime: "container",
                id: short(stem),
            });
        }
    }
    None
}

fn is_hex_id(s: &str) -> bool {
    s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_systemd_scope() {
        let c = parse_container(
            "/system.slice/docker-3b9e8f2a1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f.scope",
        )
        .unwrap();
        assert_eq!(c.runtime, "docker");
        assert_eq!(c.id, "3b9e8f2a1c4d");
    }

    #[test]
    fn parses_podman_and_containerd() {
        assert_eq!(
            parse_container("/machine.slice/libpod-aaaa1111bbbb2222cccc3333dddd4444.scope")
                .unwrap()
                .runtime,
            "podman"
        );
        assert_eq!(
            parse_container("/kubepods/cri-containerd-ffff0000ffff0000ffff0000ffff0000.scope")
                .unwrap()
                .runtime,
            "containerd"
        );
    }

    #[test]
    fn parses_cgroupfs_bare_hex() {
        let c = parse_container(
            "/docker/3b9e8f2a1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f",
        )
        .unwrap();
        assert_eq!(c.id, "3b9e8f2a1c4d");
    }

    #[test]
    fn ignores_host_cgroups() {
        assert!(parse_container("/user.slice/user-1000.slice").is_none());
        assert!(parse_container("/system.slice/docker.service").is_none());
        assert!(parse_container("/init.scope").is_none());
        assert!(parse_container("/").is_none());
    }
}
