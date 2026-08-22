# kernelsentinel lab: a disposable container for running post-exploitation
# scenarios while the daemon watches from the host.
#
# Docker shares the host kernel, so host-side eBPF sensors see the container's
# syscalls. Filesystem and process effects stay inside the container; kernel
# effects (module loading) do NOT -- those belong in a VM, never here.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
	python3 \
	libcap2-bin \
	procps \
	&& rm -rf /var/lib/apt/lists/*

# Directories the write-watch scenarios target. A slim image omits these, and
# a scenario that writes to a nonexistent path fails silently -- testing
# nothing. Pre-create them so a "no event" result means the sensor missed it,
# not that the write never happened.
RUN mkdir -p /etc/cron.d /root/.ssh /etc/systemd/system /etc/sudoers.d

# Marker the runner checks, alongside KS_LAB=1, so a scenario cannot run
# anywhere but here.
RUN touch /.ks-lab

WORKDIR /scenarios
ENTRYPOINT ["/bin/bash"]
