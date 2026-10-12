use dioramactl::{DownloadOptions, InstallOptions, UpgradeOptions};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn partial_installer_copy_preserves_previous_executable_and_cleans_temporary_file() {
    use std::io::Write;
    let dir = tempfile::TempDir::new().unwrap();
    let installer = dir.path().join("dioramactl");
    std::fs::write(&installer, "previous installer").unwrap();
    let result = dioramactl::download::stage_installer(&installer, |file| {
        file.write_all(b"partial")?;
        Err(std::io::Error::other("copy failure"))
    });
    assert!(result.is_err());
    assert_eq!(
        std::fs::read_to_string(&installer).unwrap(),
        "previous installer"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    dioramactl::download::stage_installer(&installer, |file| file.write_all(b"complete installer"))
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&installer).unwrap(),
        "complete installer"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(installer).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}

#[test]
fn proxy_selection_uses_final_url_scheme_and_preserves_explicit_overrides() {
    use dioramactl::{Command, parse_command};
    let env = BTreeMap::from([
        ("HTTP_PROXY".into(), "http-specific".into()),
        ("HTTPS_PROXY".into(), "https-specific".into()),
    ]);
    for command in ["download", "install"] {
        for (extra, expected) in [
            (vec![], "https-specific"),
            (
                vec!["--custom-url=http://example.test/archive"],
                "http-specific",
            ),
            (
                vec!["--custom-url=https://example.test/archive"],
                "https-specific",
            ),
            (vec!["--proxy=explicit"], "explicit"),
            (vec!["--proxy="], ""),
        ] {
            let args: Vec<String> = std::iter::once(command)
                .chain(extra)
                .map(str::to_owned)
                .collect();
            let proxy = match parse_command(&args, &env).unwrap() {
                Command::Download(options) => options.proxy,
                Command::Install(options) => options.proxy,
                _ => panic!("expected download or install"),
            };
            assert_eq!(proxy.as_deref(), Some(expected));
        }
    }
    let mut env = env;
    env.insert("KUBESOLO_PROXY".into(), "distribution-specific".into());
    let Command::Download(options) = parse_command(&["download".into()], &env).unwrap() else {
        panic!("download")
    };
    assert_eq!(options.proxy.as_deref(), Some("distribution-specific"));
}

#[test]
fn url_and_proxy_credentials_are_redacted_in_all_command_debug_output() {
    let url = Some("https://user:url-secret@example.test/archive?token=query-secret".into());
    let proxy = Some("https://user:proxy-secret@example.test".into());
    let outputs = [
        format!(
            "{:?}",
            DownloadOptions {
                custom_url: url.clone(),
                proxy: proxy.clone(),
                ..Default::default()
            }
        ),
        format!(
            "{:?}",
            InstallOptions {
                custom_url: url.clone(),
                proxy: proxy.clone(),
                ..Default::default()
            }
        ),
        format!(
            "{:?}",
            UpgradeOptions {
                custom_url: url,
                proxy,
                ..Default::default()
            }
        ),
    ];
    for output in outputs {
        assert!(output.contains("<redacted>"));
        for secret in ["url-secret", "query-secret", "proxy-secret"] {
            assert!(!output.contains(secret));
        }
    }
}

#[test]
fn failed_download_preserves_bundle_and_cleans_owned_staging() {
    let root = tempfile::TempDir::new().unwrap();
    let staging = root.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(staging.join("unrelated"), "retain").unwrap();
    let dest = root.path().join("bundle");
    std::fs::write(&dest, "old").unwrap();
    let error = dioramactl::download::stage_download(&dest, Some(&staging), |path| {
        assert!(path.starts_with(&staging));
        std::fs::write(path, "partial")?;
        Err(std::io::Error::other("transfer failed"))
    });
    assert!(error.is_err());
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "old");
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 1);
    dioramactl::download::stage_download(&dest, Some(&staging), |path| {
        std::fs::write(path, "complete")
    })
    .unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "complete");
    assert_eq!(std::fs::read_dir(staging).unwrap().count(), 1);
}

#[test]
fn custom_url_cannot_inject_curl_options_or_change_protocol_policy() {
    let command =
        dioramactl::download::curl_download_command("-K/etc/private", Path::new("out"), None);
    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_str().unwrap())
        .collect();
    assert_eq!(&args[args.len() - 2..], &["--config", "-"]);
    assert!(!args.contains(&"-K/etc/private"));
    for setting in [
        ["--connect-timeout", "30"],
        ["--speed-limit", "1"],
        ["--speed-time", "120"],
    ] {
        assert!(args.windows(2).any(|pair| pair == setting));
    }
    assert_eq!(
        dioramactl::download::curl_download_config("-K/etc/private", None),
        "url = \"-K/etc/private\"\n"
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--proto", "=https,http"])
    );
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--proto-redir", "=https"])
    );
}

#[test]
fn sudo_recovery_does_not_restore_privileged_execution_controls() {
    let mut env = BTreeMap::from([("SUDO_USER".into(), "alice".into())]);
    dioramactl::recover_sudo_env_from_bytes(&mut env, b"KUBESOLO_INSTALL_PREREQS=true\0KUBESOLO_CUSTOM_URL=file:///private\0KUBESOLO_PATH=/root\0KUBESOLO_PORTAINER_EDGE_KEY=key\0KUBESOLO_PORTAINER_EDGE_ID=id\0");
    assert_eq!(env.get("KUBESOLO_PORTAINER_EDGE_KEY").unwrap(), "key");
    assert_eq!(env.get("KUBESOLO_PORTAINER_EDGE_ID").unwrap(), "id");
    assert_eq!(env.len(), 3);
}

#[cfg(unix)]
#[test]
fn unrelated_non_utf8_environment_does_not_panic() {
    use std::os::unix::ffi::OsStringExt;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dioramactl"))
        .arg("version")
        .env_clear()
        .env("UNRELATED", std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dioramactl"))
        .arg("version")
        .env_clear()
        .env("KUBESOLO_PATH", std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must be UTF-8"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn download_secrets_are_only_in_protected_config_and_cannot_inject_lines() {
    let url = "https://example.invalid/file?token=private-token";
    let proxy = "https://user:private-password@proxy";
    let command = dioramactl::download::curl_download_command(url, Path::new("out"), Some(proxy));
    let args = command.get_args().collect::<Vec<_>>();
    assert!(!format!("{args:?}").contains("private-"));
    let config = dioramactl::download::curl_download_config(url, Some(proxy));
    assert!(config.contains(url));
    assert!(config.contains(proxy));
    let injection =
        dioramactl::download::curl_download_config("https://x/\"\noutput = /private\r", None);
    assert_eq!(injection.lines().count(), 1);
    assert!(injection.contains("\\\"\\noutput"));
}
