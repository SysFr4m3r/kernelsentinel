#!/usr/bin/env bash
# Build the two Debian packages from already-built binaries.
#
#   ./packaging/build-deb.sh            # builds the binaries too
#   ./packaging/build-deb.sh --no-build # reuse target/release + target/server
#
# Two packages rather than one, because the two roles want different things
# installed. They can coexist on one host (the reference single-box setup runs
# both), so they use different binary names rather than conflicting.
#
#   kernelsentinel-agent   /usr/bin/kernelsentinel         (eBPF collector, root)
#   kernelsentinel-server  /usr/bin/kernelsentinel-server  (panel, unprivileged)
#
# Neither package enables its service. An agent with no ingest key, or a server
# with no admin password, would crash-loop on boot; a package that leaves you
# with a broken unit is worse than one that tells you what to configure.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
ARCH="$(dpkg --print-architecture)"
OUT="$REPO/dist"
# Attribution follows the repository's own git identity rather than being
# hardcoded, so a fork does not ship someone else's name.
MAINT="$(git config user.name || echo kernelsentinel) <$(git config user.email || echo dev@localhost)>"

if [[ "${1:-}" != "--no-build" ]]; then
	echo "==> building agent (full, with eBPF)"
	cargo build --release
	echo "==> building server (no BPF toolchain needed)"
	cargo build --release --no-default-features --target-dir target/server
fi

AGENT_BIN="$REPO/target/release/kernelsentinel"
SERVER_BIN="$REPO/target/server/release/kernelsentinel"
for b in "$AGENT_BIN" "$SERVER_BIN"; do
	[[ -x "$b" ]] || { echo "missing $b -- run without --no-build" >&2; exit 1; }
done

rm -rf "$OUT" && mkdir -p "$OUT"

# --- shared helpers ---------------------------------------------------------

# Rewrite a shipped unit for the packaged binary path. The units under deploy/
# stay the single source of truth; packaging only adjusts the path, because
# /usr/local/bin is for hand-installed binaries and a package belongs in /usr/bin.
unit() { # unit <src> <dest> <binary-path>
	sed "s#/usr/local/bin/kernelsentinel#$3#g" "$REPO/deploy/$1" > "$2"
}

build_deb() { # build_deb <name> <root>
	chmod -R g-w "$2"
	find "$2" -type d -exec chmod 755 {} +
	# --root-owner-group stamps root:root without needing real or faked root, so
	# no fakeroot dependency -- one less thing that has to exist on a CI runner.
	dpkg-deb --build --root-owner-group "$2" "$OUT/$1_${VERSION}_${ARCH}.deb" >/dev/null
}

# --- agent ------------------------------------------------------------------

A="$OUT/agent"
mkdir -p "$A/DEBIAN" "$A/usr/bin" "$A/lib/systemd/system" "$A/usr/share/doc/kernelsentinel-agent"
install -m755 "$AGENT_BIN" "$A/usr/bin/kernelsentinel"
unit kernelsentinel-agent.service "$A/lib/systemd/system/kernelsentinel-agent.service" /usr/bin/kernelsentinel
install -m644 "$REPO/README.md" "$A/usr/share/doc/kernelsentinel-agent/README.md"

cat > "$A/DEBIAN/control" <<EOF
Package: kernelsentinel-agent
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: libc6 (>= 2.35), libelf1, zlib1g
Recommends: kernelsentinel-server
Maintainer: $MAINT
Description: eBPF runtime detection agent for Linux post-exploitation behaviour
 Collects process, credential, file and network events with eBPF CO-RE sensors,
 correlates them in a live process graph, and raises scored, MITRE-mapped
 incidents. Ships them to a central KernelSentinel server, or emits NDJSON.
 .
 Requires kernel 5.8+ with BTF, and BPF-LSM for the file and ptrace sensors.
 Run "kernelsentinel doctor" to check this host.
EOF

cat > "$A/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
	mkdir -p /etc/kernelsentinel
	systemctl daemon-reload >/dev/null 2>&1 || true
	cat <<'MSG'

kernelsentinel-agent installed. It is NOT started: an agent with no ingest key
would crash-loop, so configure it first.

  1. check this kernel is supported:   kernelsentinel doctor
  2. set the key issued by the server: /etc/kernelsentinel/agent.env
       KS_INGEST_KEY=<key from the server's agents.keys>
  3. point the unit at your server:    /lib/systemd/system/kernelsentinel-agent.service
  4. start it:                         systemctl enable --now kernelsentinel-agent

MSG
fi
EOF
chmod 755 "$A/DEBIAN/postinst"

cat > "$A/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
	systemctl stop kernelsentinel-agent >/dev/null 2>&1 || true
	systemctl disable kernelsentinel-agent >/dev/null 2>&1 || true
fi
EOF
chmod 755 "$A/DEBIAN/prerm"
build_deb kernelsentinel-agent "$A"

# --- server -----------------------------------------------------------------

S="$OUT/server"
mkdir -p "$S/DEBIAN" "$S/usr/bin" "$S/lib/systemd/system" "$S/usr/share/doc/kernelsentinel-server"
install -m755 "$SERVER_BIN" "$S/usr/bin/kernelsentinel-server"
unit kernelsentinel-server.service "$S/lib/systemd/system/kernelsentinel-server.service" "/usr/bin/kernelsentinel-server"
install -m644 "$REPO/README.md" "$S/usr/share/doc/kernelsentinel-server/README.md"

cat > "$S/DEBIAN/control" <<EOF
Package: kernelsentinel-server
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: libc6 (>= 2.35)
Maintainer: $MAINT
Description: central fleet server and web panel for KernelSentinel
 Receives incidents from KernelSentinel agents over TLS, stores them in sqlite,
 and serves a read-only web dashboard ranking hosts by risk. Telemetry flows one
 way: there is no channel from the panel back to a monitored host.
 .
 Built without the eBPF collector, so this package needs no kernel headers, no
 BTF and no BPF toolchain.
EOF

cat > "$S/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
	if ! getent passwd kernelsentinel >/dev/null; then
		adduser --system --group --no-create-home \
			--home /var/lib/kernelsentinel --shell /usr/sbin/nologin \
			kernelsentinel >/dev/null
	fi
	mkdir -p /etc/kernelsentinel /var/lib/kernelsentinel
	chown kernelsentinel:kernelsentinel /var/lib/kernelsentinel
	chmod 750 /var/lib/kernelsentinel
	systemctl daemon-reload >/dev/null 2>&1 || true
	cat <<'MSG'

kernelsentinel-server installed. It is NOT started: the server refuses to run
without an admin password, so configure it first.

  1. admin password:  echo "KS_ADMIN_PASSWORD=$(openssl rand -hex 12)" > /etc/kernelsentinel/server.env
                      chmod 640 /etc/kernelsentinel/server.env
                      chown root:kernelsentinel /etc/kernelsentinel/server.env
  2. TLS cert + key:  /etc/kernelsentinel/server.pem, server.key
  3. per-agent keys:  /etc/kernelsentinel/agents.keys   ("<hostname> <key>" per line)
  4. start it:        systemctl enable --now kernelsentinel-server

MSG
fi
EOF
chmod 755 "$S/DEBIAN/postinst"

cat > "$S/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
	systemctl stop kernelsentinel-server >/dev/null 2>&1 || true
	systemctl disable kernelsentinel-server >/dev/null 2>&1 || true
fi
EOF
chmod 755 "$S/DEBIAN/prerm"

# Purge removes data only on explicit purge, never on remove: an audit trail
# must not vanish because someone upgraded awkwardly.
cat > "$S/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = purge ]; then
	rm -rf /var/lib/kernelsentinel
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF
chmod 755 "$S/DEBIAN/postrm"
build_deb kernelsentinel-server "$S"

# --- tarballs + checksums ---------------------------------------------------

tar -C "$(dirname "$AGENT_BIN")" -czf "$OUT/kernelsentinel-${VERSION}-${ARCH}-linux.tar.gz" kernelsentinel
tar -C "$OUT/server/usr/bin" -czf "$OUT/kernelsentinel-server-${VERSION}-${ARCH}-linux.tar.gz" kernelsentinel-server
rm -rf "$A" "$S"
( cd "$OUT" && sha256sum ./*.deb ./*.tar.gz > SHA256SUMS )

echo
echo "==> $OUT"
ls -1sh "$OUT"
