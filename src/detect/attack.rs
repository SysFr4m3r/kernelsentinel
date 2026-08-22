//! MITRE ATT&CK technique names, for turning the bare technique ids a signal
//! carries into something a human reads. Only the techniques this tool actually
//! emits are listed.

pub fn name(technique: &str) -> &'static str {
    match technique {
        "T1003" => "OS Credential Dumping",
        "T1003.008" => "/etc/passwd and /etc/shadow",
        "T1036" => "Masquerading",
        "T1055.008" => "Ptrace System Calls",
        "T1068" => "Exploitation for Privilege Escalation",
        "T1098" => "Account Manipulation",
        "T1543" => "Create or Modify System Process",
        "T1547.006" => "Kernel Modules and Extensions",
        "T1548" => "Abuse Elevation Control Mechanism",
        "T1548.001" => "Setuid and Setgid",
        "T1552" => "Unsecured Credentials",
        "T1552.001" => "Credentials In Files",
        "T1574.006" => "Dynamic Linker Hijacking",
        "T1620" => "Reflective Code Loading",
        _ => "Unknown Technique",
    }
}
