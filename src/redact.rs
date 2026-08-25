//! Redaction of secrets passed on the command line.
//!
//! Command lines are the most useful field in an incident -- they answer "what
//! actually ran" -- and they are also where people put passwords. Once argv
//! reaches the panel it is also in the sqlite journal, in webhook bodies posted
//! to a third party, and in syslog. A single `mysql -phunter2` in a flagged
//! chain would otherwise be replicated into all four.
//!
//! The rule is: keep the flag, drop the value. `mysql -p<redacted>` still tells
//! a responder that a password was passed inline, which is itself worth knowing,
//! without carrying the secret. Over-redacting would destroy the forensic value
//! this field exists for, so the match list is deliberately specific rather than
//! a broad keyword sweep.

pub const REDACTED: &str = "<redacted>";

/// Long flags whose value is a secret. Matched case-insensitively, both as
/// `--flag=value` and as `--flag value`.
const SECRET_FLAGS: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "token",
    "auth-token",
    "access-token",
    "refresh-token",
    "api-key",
    "apikey",
    "secret",
    "secret-key",
    "secret-access-key",
    "client-secret",
    "private-key",
    "credential",
    "credentials",
];

/// `-p` means "password" to the mysql family and "port" to psql, and it is the
/// leading letter of openssl's `-passin`. So the short-flag rule is keyed on the
/// program being run rather than applied blind -- redacting a port number or
/// mangling `-passin` into `-p<redacted>` would corrupt the record while
/// protecting nothing.
const SHORT_P_TOOLS: &[&str] = &[
    "mysql",
    "mysqldump",
    "mysqladmin",
    "mariadb",
    "mariadb-dump",
];

fn uses_short_p(args: &[String]) -> bool {
    let Some(cmd) = args.first() else {
        return false;
    };
    let base = cmd.rsplit('/').next().unwrap_or(cmd);
    SHORT_P_TOOLS.contains(&base)
}

fn is_secret_flag(name: &str) -> bool {
    let n = name.trim_start_matches('-').to_ascii_lowercase();
    SECRET_FLAGS.contains(&n.as_str())
}

/// Redact secrets in one argv vector, preserving structure and length.
pub fn argv(mut args: Vec<String>) -> Vec<String> {
    let short_p = uses_short_p(&args);
    let mut i = 0;
    let mut redact_next = false;
    while i < args.len() {
        if redact_next {
            args[i] = REDACTED.to_string();
            redact_next = false;
            i += 1;
            continue;
        }
        let arg = args[i].clone();

        // --flag=value
        if arg.starts_with("--") {
            if let Some((flag, _)) = arg.split_once('=') {
                if is_secret_flag(flag) {
                    args[i] = format!("{flag}={REDACTED}");
                    i += 1;
                    continue;
                }
            } else if is_secret_flag(&arg) {
                // --flag value
                redact_next = true;
                i += 1;
                continue;
            }
        }

        // Single-dash long options (`-password secret`, openssl's `-passin`).
        if arg.starts_with('-') && !arg.starts_with("--") && is_secret_flag(&arg) {
            redact_next = true;
            i += 1;
            continue;
        }

        // -pSECRET (attached) or -p SECRET (separate), for the mysql family
        // only. A bare "-p" followed by another flag is a prompt, not a secret.
        if short_p && arg.starts_with("-p") && !arg.starts_with("--") {
            if arg.len() > 2 {
                args[i] = format!("-p{REDACTED}");
                i += 1;
                continue;
            }
            if args
                .get(i + 1)
                .is_some_and(|next| !next.starts_with('-') && !next.is_empty())
            {
                redact_next = true;
            }
            i += 1;
            continue;
        }

        // An Authorization / Cookie header value, however it was spelled.
        if let Some(cut) = header_secret_cut(&arg) {
            args[i] = format!("{}{REDACTED}", &arg[..cut]);
            i += 1;
            continue;
        }

        // openssl-style `pass:secret` / `file:` is a path and stays.
        if let Some(rest) = arg.strip_prefix("pass:") {
            if !rest.is_empty() {
                args[i] = format!("pass:{REDACTED}");
                i += 1;
                continue;
            }
        }

        // Credentials embedded in a URL: scheme://user:pass@host
        if let Some(red) = redact_url_userinfo(&arg) {
            args[i] = red;
            i += 1;
            continue;
        }

        i += 1;
    }
    args
}

/// Byte offset just past the header name, if this argument carries a secret
/// header value (`Authorization: Bearer x`, `Cookie: ...`).
fn header_secret_cut(arg: &str) -> Option<usize> {
    const HEADERS: &[&str] = &[
        "authorization:",
        "cookie:",
        "x-api-key:",
        "proxy-authorization:",
    ];
    let lower = arg.to_ascii_lowercase();
    for h in HEADERS {
        if let Some(pos) = lower.find(h) {
            // Only when the header starts the argument (possibly after a quote),
            // so a path that merely contains the word is untouched.
            if arg[..pos]
                .chars()
                .all(|c| c == '"' || c == '\'' || c == ' ')
            {
                return Some(pos + h.len());
            }
        }
    }
    None
}

/// `scheme://user:pass@host` -> `scheme://user:<redacted>@host`.
fn redact_url_userinfo(arg: &str) -> Option<String> {
    let scheme_end = arg.find("://")? + 3;
    let rest = &arg[scheme_end..];
    let at = rest.find('@')?;
    let userinfo = &rest[..at];
    let colon = userinfo.find(':')?;
    // A port is not userinfo: "host:8080/path" has no '@' before it, so the
    // '@' check above already excludes that case.
    Some(format!(
        "{}{}:{REDACTED}{}",
        &arg[..scheme_end],
        &userinfo[..colon],
        &rest[at..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(args: &[&str]) -> Vec<String> {
        argv(args.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn mysql_attached_short_password() {
        assert_eq!(
            r(&["mysql", "-uroot", "-phunter2"]),
            ["mysql", "-uroot", "-p<redacted>"]
        );
    }

    #[test]
    fn bare_dash_p_is_a_prompt_and_stays_readable() {
        // `mysql -p` prompts; there is no secret to hide, and blanking the next
        // token would destroy the database name.
        assert_eq!(r(&["mysql", "-p", "-h", "db"]), ["mysql", "-p", "-h", "db"]);
        assert_eq!(r(&["mysql", "-p", "mydb"]), ["mysql", "-p", "<redacted>"]);
        assert_eq!(r(&["mysql", "-uroot", "-p"]), ["mysql", "-uroot", "-p"]);
    }

    #[test]
    fn long_flags_both_spellings() {
        assert_eq!(
            r(&[
                "app",
                "--password=s3cr3t",
                "--token",
                "abc123",
                "--user",
                "bob"
            ]),
            [
                "app",
                "--password=<redacted>",
                "--token",
                "<redacted>",
                "--user",
                "bob"
            ]
        );
    }

    #[test]
    fn authorization_header_value() {
        assert_eq!(
            r(&[
                "curl",
                "-H",
                "Authorization: Bearer eyJhbGciOi",
                "https://api/x"
            ]),
            ["curl", "-H", "Authorization:<redacted>", "https://api/x"]
        );
    }

    #[test]
    fn url_credentials() {
        assert_eq!(
            r(&["git", "clone", "https://bob:tokenvalue@github.com/x.git"]),
            ["git", "clone", "https://bob:<redacted>@github.com/x.git"]
        );
    }

    /// openssl spells it with one dash and passes the secret as `pass:VALUE`.
    /// The flag and the `pass:` form both survive -- `-p<redacted>` would be a
    /// corrupted record, not a redacted one, and `pass:` vs `file:` is the part
    /// that tells a responder whether a secret was inline or on disk.
    #[test]
    fn openssl_pass_argument() {
        assert_eq!(
            r(&["openssl", "rsa", "-passin", "pass:abc"]),
            ["openssl", "rsa", "-passin", "pass:<redacted>"]
        );
        // A file reference is a path, not a secret.
        assert_eq!(
            r(&["openssl", "rsa", "-passin", "file:/etc/key.pw"]),
            ["openssl", "rsa", "-passin", "file:/etc/key.pw"]
        );
    }

    /// `-p` is a port to psql and a password to mysql. Keying on the program
    /// keeps a port number readable.
    #[test]
    fn short_p_is_scoped_to_the_mysql_family() {
        assert_eq!(
            r(&["psql", "-p", "5432", "-h", "db"]),
            ["psql", "-p", "5432", "-h", "db"]
        );
        assert_eq!(
            r(&["/usr/bin/mysql", "-phunter2"]),
            ["/usr/bin/mysql", "-p<redacted>"]
        );
        assert_eq!(
            r(&["ssh", "-p", "2222", "host"]),
            ["ssh", "-p", "2222", "host"]
        );
    }

    /// The whole point of keeping argv is knowing what ran. Redaction must not
    /// eat the parts that carry the forensic signal.
    #[test]
    fn ordinary_commands_are_untouched() {
        assert_eq!(r(&["chmod", "u+s", "/tmp/.x"]), ["chmod", "u+s", "/tmp/.x"]);
        assert_eq!(
            r(&["sh", "-c", "cp /bin/true /tmp/.x && chmod u+s /tmp/.x"]),
            ["sh", "-c", "cp /bin/true /tmp/.x && chmod u+s /tmp/.x"]
        );
        assert_eq!(
            r(&["curl", "https://host:8443/path"]),
            ["curl", "https://host:8443/path"]
        );
        // A path that merely mentions a password file is a path, not a secret.
        assert_eq!(
            r(&["ansible-playbook", "--vault-password-file", "/etc/vault"]),
            ["ansible-playbook", "--vault-password-file", "/etc/vault"]
        );
    }

    #[test]
    fn structure_and_length_are_preserved() {
        let out = r(&["app", "--password", "x", "--flag"]);
        assert_eq!(out.len(), 4, "argv length must not change");
        assert_eq!(out[3], "--flag");
    }

    #[test]
    fn empty_and_degenerate_inputs() {
        assert!(argv(vec![]).is_empty());
        assert_eq!(r(&["-"]), ["-"]);
        assert_eq!(
            r(&["--password"]),
            ["--password"],
            "trailing flag with no value"
        );
    }
}
