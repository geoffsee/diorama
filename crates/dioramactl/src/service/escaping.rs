//! Shell escaping and sanitization utilities matching `KubeSolo` characterization.

/// Quotes a string argument for POSIX shell command lines (`'val'`).
/// Replaces internal single quotes with `'\''`.
pub fn shell_quote(s: &str) -> String {
    let sanitized = sanitize_newlines(s);
    if sanitized.is_empty() {
        return "''".to_string();
    }
    // If it only contains safe characters, we could leave it bare, but KubeSolo
    // characters always wrap or single-quote:
    // strings.ReplaceAll(s, "'", "'\\''") -> "'" + s + "'"
    format!("'{}'", sanitized.replace('\'', r"'\''"))
}

/// Double-quotes a string value for shell assignment (e.g. in `OpenRC` / `SysVinit` env vars).
/// Escapes `\`, `"`, `$`, and `` ` ``.
pub fn escape_openrc_double_quote(s: &str) -> String {
    let sanitized = sanitize_newlines(s);
    let mut escaped = String::with_capacity(sanitized.len() + 8);
    for c in sanitized.chars() {
        match c {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str(r#"\""#),
            '$' => escaped.push_str(r"\$"),
            '`' => escaped.push_str(r"\`"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Escapes environment variable values for systemd unit `Environment="KEY=VAL"` directives.
/// Systemd requires escaping `\` as `\\`, `"` as `\"`, and `%` as `%%` (specifier escaping).
pub fn escape_systemd_env(s: &str) -> String {
    let sanitized = sanitize_newlines(s);
    let mut escaped = String::with_capacity(sanitized.len() + 8);
    for c in sanitized.chars() {
        match c {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str(r#"\""#),
            '%' => escaped.push_str("%%"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Quotes one systemd command argument and suppresses specifier/environment expansion.
pub fn systemd_quote(s: &str) -> String {
    format!("\"{}\"", escape_systemd_env(s).replace('$', "$$"))
}

/// Strips carriage returns and newlines to prevent service file / template header injection.
pub fn sanitize_newlines(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_quote() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("hello"), "'hello'");
        assert_eq!(shell_quote("foo bar"), "'foo bar'");
        assert_eq!(shell_quote("it's cool"), "'it'\\''s cool'");
        assert_eq!(shell_quote("line1\nline2\r"), "'line1line2'");
    }

    #[test]
    fn test_escape_openrc_double_quote() {
        assert_eq!(
            escape_openrc_double_quote("http://proxy:8080"),
            "http://proxy:8080"
        );
        assert_eq!(
            escape_openrc_double_quote(r#"foo "bar" $baz `cmd` \test"#),
            r#"foo \"bar\" \$baz \`cmd\` \\test"#
        );
        assert_eq!(escape_openrc_double_quote("multi\nline"), "multiline");
    }

    #[test]
    fn test_escape_systemd_env() {
        assert_eq!(escape_systemd_env("normal"), "normal");
        assert_eq!(
            escape_systemd_env(r#"value with "quotes" and \backslash and %specifier"#),
            r#"value with \"quotes\" and \\backslash and %%specifier"#
        );
        assert_eq!(escape_systemd_env("inject\nnewline"), "injectnewline");
    }
}
