#!/usr/bin/env bash
# kernelsentinel Docker lab runner.
#
#   tests/lab/run.sh build            build the lab image
#   tests/lab/run.sh shell            interactive shell in the lab
#   tests/lab/run.sh run <cmd...>     run a command in the lab
#
# The daemon runs on the HOST (it needs CAP_BPF), not in here. Typical use:
#   terminal 1:  sudo ./target/debug/kernelsentinel run
#   terminal 2:  tests/lab/run.sh run 'cp /bin/sh /tmp/.x && chmod u+s /tmp/.x'
#
# The host sensors observe the container because they share a kernel.
set -euo pipefail

IMAGE="kernelsentinel-lab"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Least privilege by design. A scenario that needs more must ask for it
# explicitly via KS_CAPS, which documents exactly what the attack requires.
#   --cap-drop=ALL         start from nothing
#   --security-opt no-new-privileges  cannot regain privilege by accident
#   --network none         a test scenario has no business reaching the network
#   --pids-limit           a runaway fork bomb in a scenario cannot take the box
# Deliberately NOT here: --privileged (that is a host compromise), and never a
# bind mount of the real docker.sock (that mount IS the escape being tested).
run_container() {
	local extra_caps=()
	if [[ -n "${KS_CAPS:-}" ]]; then
		IFS=',' read -ra caps <<<"$KS_CAPS"
		for c in "${caps[@]}"; do extra_caps+=(--cap-add="$c"); done
	fi

	# Allocate a TTY only when stdin is one; otherwise piping and CI break with
	# "the input device is not a TTY".
	local tty=()
	[[ -t 0 ]] && tty=(-it)

	exec docker run --rm "${tty[@]}" \
		--cap-drop=ALL \
		"${extra_caps[@]}" \
		--security-opt no-new-privileges \
		--network none \
		--pids-limit 256 \
		--memory 256m \
		--env KS_LAB=1 \
		--tmpfs /tmp:exec \
		--tmpfs /dev/shm:exec \
		"$IMAGE" "$@"
}

require_image() {
	if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
		echo "lab image not built. Run: $0 build" >&2
		exit 1
	fi
}

case "${1:-}" in
build)
	docker build -t "$IMAGE" "$LAB_DIR"
	echo "built $IMAGE"
	;;
shell)
	require_image
	run_container
	;;
run)
	require_image
	shift
	[[ $# -gt 0 ]] || { echo "usage: $0 run <command...>" >&2; exit 1; }
	run_container -c "$*"
	;;
*)
	sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
	exit 1
	;;
esac
