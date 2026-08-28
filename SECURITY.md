# Security

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/SysFr4m3r/kernelsentinel/security/advisories/new),
not a public issue.

This is a tool people run as root with `CAP_BPF` on hosts they are trying to
defend, so a vulnerability in it is worth more to an attacker than most. That
includes anything that would let a monitored host reach the fleet server, let
the panel reach a monitored host, or make the agent report a host as healthy
while it is not.

## What is in scope

- Anything that gets code execution or privilege escalation via the agent or server
- Anything that lets a compromised **monitored host** affect the server or other hosts
- Anything that lets the **panel** reach a monitored host — telemetry is one-way by
  design, and a path back is a design break, not a feature
- Making the agent report a host as healthy while its sensors are detached or blind
- Leaking credentials from the server, or secrets out of a monitored host's telemetry

## Known limitations, not vulnerabilities

These are documented, deliberate, and not secrets. Reporting them is welcome as
an issue, but they are not advisories:

- **Detect-only by default.** `--enforce` covers one narrow case and fails open
  everywhere it is uncertain.
- **Root can unload the sensors.** This is a detection tool, not a rootkit
  defence. The agent attests that its sensors still observe it, so tampering is
  *visible* — but an attacker who blinds it and accepts the alert has still
  blinded it.
- **`comm`-based suppression is attacker-controlled.** Two detections suppress on
  process name; a payload named `sshd` evades them. Documented per detection in
  `docs/DETECTIONS.md`.
- **Documented evasions.** Every detection lists what defeats it. That list is
  published on purpose: a tool that hides its blind spots is worse than one that
  has them.

## What the tool collects

Worth knowing before deploying it, and before pasting an incident into an issue:
incident records carry process command lines, file paths, and the hostname.
Secrets passed as command-line arguments are redacted before they leave the host
(`mysql -p<redacted>`), but paths, hostnames and argument *structure* are not.
