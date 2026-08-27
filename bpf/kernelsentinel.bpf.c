// SPDX-License-Identifier: GPL-2.0
/* KernelSentinel BPF sensors.
 *
 * GPL-2.0 is not a formality here: bpf_probe_read_kernel_str() and later
 * bpf_d_path() are GPL-only helpers and the verifier rejects the program
 * without this license string. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

#include "maps.h"
#include "common.h"

/* Sensors. Each header holds the programs for one area and nothing else; this
 * file exists to give them a single translation unit, because every program
 * here shares the maps in maps.h. Splitting them into separate .bpf.c files
 * would produce separate objects, and with them separate ring buffers and a
 * watched-paths trie that would have to be populated more than once.
 */
#include "sensors/process.bpf.h"
#include "sensors/creds.bpf.h"
#include "sensors/file.bpf.h"
#include "sensors/ptrace.bpf.h"
#include "sensors/exec_anon.bpf.h"
#include "sensors/module.bpf.h"
#include "sensors/net.bpf.h"
