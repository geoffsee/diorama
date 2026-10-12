use dioramactl::kubeconfig::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

#[cfg(unix)]
#[test]
fn publication_rejects_symlinked_and_foreign_owned_parents() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let destination = real.join("config");
    fs::write(&destination, b"unrelated credentials").unwrap();
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap();
    let owner = fs::metadata(&real).unwrap().uid();
    let mut user = InvokingUser {
        username: "test".into(),
        home_dir: dir.path().to_owned(),
        uid: Some(owner),
        gid: None,
    };
    assert!(atomic_write_secure(&link.join("config"), b"new", &user).is_err());
    user.uid = Some(owner.wrapping_add(1));
    assert!(atomic_write_secure(&destination, b"new", &user).is_err());
    assert_eq!(fs::read(destination).unwrap(), b"unrelated credentials");
}

#[test]
fn test_invoking_user_resolution_sudo() {
    let mut env = BTreeMap::new();
    env.insert("SUDO_USER".to_string(), "alice".to_string());
    env.insert("SUDO_UID".to_string(), "1001".to_string());
    env.insert("SUDO_GID".to_string(), "1001".to_string());
    env.insert("USER".to_string(), "root".to_string());

    let passwd = "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n";
    let user = resolve_invoking_user_with_passwd(&env, passwd);

    assert_eq!(user.username, "alice");
    assert_eq!(user.uid, Some(1001));
    assert_eq!(user.gid, Some(1001));
    assert_eq!(user.home_dir, PathBuf::from("/home/alice"));
}

#[test]
fn test_invoking_user_resolution_doas() {
    let mut env = BTreeMap::new();
    env.insert("DOAS_USER".to_string(), "bob".to_string());
    env.insert("USER".to_string(), "root".to_string());

    let passwd = "bob:x:1002:1002:Bob:/custom/bob:/bin/sh\n";
    let user = resolve_invoking_user_with_passwd(&env, passwd);

    assert_eq!(user.username, "bob");
    assert_eq!(user.uid, Some(1002));
    assert_eq!(user.gid, Some(1002));
    assert_eq!(user.home_dir, PathBuf::from("/custom/bob"));
}

#[test]
fn test_invoking_user_resolution_fallback_to_env() {
    let mut env = BTreeMap::new();
    env.insert("USER".to_string(), "carol".to_string());
    env.insert("HOME".to_string(), "/home/carol".to_string());

    let user = resolve_invoking_user_with_passwd(&env, "");
    assert_eq!(user.username, "carol");
    assert_eq!(user.home_dir, PathBuf::from("/home/carol"));
}

#[test]
fn test_premerge_backup_timestamp_formatting() {
    // 2026-03-29 08:30:15 UTC = 1_774_773_015 unix seconds
    // Breakdown:
    // 1_774_773_015 seconds
    let time = UNIX_EPOCH + Duration::from_secs(1_774_773_015);
    let formatted = format_backup_timestamp(time);
    assert_eq!(formatted, "20260329083015");
}

#[test]
fn test_premerge_backup_creation() {
    let temp_dir =
        std::env::temp_dir().join(format!("dioramactl_test_backup_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let target_file = temp_dir.join("config");
    fs::write(&target_file, "existing content").unwrap();

    let time = UNIX_EPOCH + Duration::from_secs(1_774_773_015);
    let backup_path = create_premerge_backup(&target_file, time).unwrap();

    assert!(backup_path.is_some());
    let path = backup_path.unwrap();
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        "config.backup-20260329083015"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "existing content");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_kubeconfig_merge_preserves_unrelated() {
    let existing_yaml = r"apiVersion: v1
kind: Config
current-context: dev-context
clusters:
- cluster:
    server: https://dev.example.com
  name: dev-cluster
contexts:
- context:
    cluster: dev-cluster
    user: dev-user
  name: dev-context
users:
- name: dev-user
  user:
    token: devtoken
";

    let incoming_yaml = r"apiVersion: v1
kind: Config
current-context: default
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
users:
- name: default
  user:
    client-certificate-data: LS0t...
";

    let mut target = parse_kubeconfig_content(existing_yaml).unwrap();
    let incoming = parse_kubeconfig_content(incoming_yaml).unwrap();

    merge_kubeconfigs(&mut target, &incoming);

    let merged_yaml = serialize_kubeconfig(&target);
    let re_parsed = parse_kubeconfig_content(&merged_yaml).unwrap();

    assert_eq!(
        re_parsed.get("current-context").and_then(Value::as_str),
        Some("default")
    );

    let clusters = re_parsed.get("clusters").and_then(Value::as_array).unwrap();
    assert_eq!(clusters.len(), 2);
    let names: Vec<&str> = clusters
        .iter()
        .filter_map(|c| c.get("name").and_then(Value::as_str))
        .collect();
    assert!(names.contains(&"dev-cluster"));
    assert!(names.contains(&"default"));

    let contexts = re_parsed.get("contexts").and_then(Value::as_array).unwrap();
    assert_eq!(contexts.len(), 2);

    let users = re_parsed.get("users").and_then(Value::as_array).unwrap();
    assert_eq!(users.len(), 2);
}

#[test]
fn test_kubeconfig_merge_idempotent() {
    let existing_yaml = r"apiVersion: v1
kind: Config
current-context: default
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
users:
- name: default
  user:
    token: old-token
";

    let incoming_yaml = r"apiVersion: v1
kind: Config
current-context: default
clusters:
- cluster:
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
users:
- name: default
  user:
    token: new-token
";

    let mut target = parse_kubeconfig_content(existing_yaml).unwrap();
    let incoming = parse_kubeconfig_content(incoming_yaml).unwrap();

    // First merge
    merge_kubeconfigs(&mut target, &incoming);

    // Second merge (idempotent)
    merge_kubeconfigs(&mut target, &incoming);

    let merged_yaml = serialize_kubeconfig(&target);
    let re_parsed = parse_kubeconfig_content(&merged_yaml).unwrap();

    let users = re_parsed.get("users").and_then(Value::as_array).unwrap();
    assert_eq!(users.len(), 1);
    let user_token = users[0]
        .get("user")
        .and_then(Value::as_object)
        .and_then(|u| u.get("token"))
        .and_then(Value::as_str);
    assert_eq!(user_token, Some("new-token"));
}

#[test]
fn test_atomic_write_secure_permissions() {
    let temp_dir =
        std::env::temp_dir().join(format!("dioramactl_test_perm_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);

    let dest = temp_dir.join("sub").join("kubeconfig");
    let user = InvokingUser {
        username: "test".to_string(),
        home_dir: temp_dir.clone(),
        uid: None,
        gid: None,
    };

    atomic_write_secure(&dest, b"secure content", &user).unwrap();

    assert_eq!(fs::read_to_string(&dest).unwrap(), "secure content");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_meta = fs::metadata(&dest).unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);

        let parent_meta = fs::metadata(dest.parent().unwrap()).unwrap();
        assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn full_yaml_document_survives_merge_and_serialization() {
    let original = parse_kubeconfig_content(
        r#"
apiVersion: v1
kind: Config
preferences: {colors: true}
extensions: [{name: custom, extension: {nested: [1, true, "123"]}}]
users:
- name: "true"
  user:
    exec:
      command: "a: b # c"
      args: ["*literal", "123", "true"]
      env: [{name: SPECIAL, value: "&literal"}]
    token: |
      multiline
      token
clusters: []
contexts: []
"#,
    )
    .unwrap();
    let mut merged = original.clone();
    merge_kubeconfigs(
        &mut merged,
        &serde_json::json!({"current-context": "new", "users": [{"name": "new", "user": {"token": "new"}}]}),
    );
    let roundtrip = parse_kubeconfig_content(&serialize_kubeconfig(&merged)).unwrap();
    assert_eq!(roundtrip["users"][0], original["users"][0]);
    assert_eq!(roundtrip["preferences"], original["preferences"]);
    assert_eq!(roundtrip["extensions"], original["extensions"]);
    assert_eq!(roundtrip, merged);
    assert!(parse_kubeconfig_content("[not, a, mapping]").is_err());
}

#[cfg(unix)]
#[test]
fn backup_rejects_source_symlinks_and_preserves_existing_backup_links() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("unrelated");
    fs::write(&victim, "private").unwrap();
    let dest = dir.path().join("config");
    symlink(&victim, &dest).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(1_774_773_015);
    assert!(create_premerge_backup(&dest, now).is_err());
    fs::remove_file(&dest).unwrap();
    fs::write(&dest, "config").unwrap();
    let backup = dir.path().join("config.backup-20260329083015");
    symlink(&victim, &backup).unwrap();
    let new_backup = create_premerge_backup(&dest, now).unwrap().unwrap();
    assert_ne!(new_backup, backup);
    assert_eq!(fs::read_to_string(new_backup).unwrap(), "config");
    assert_eq!(fs::read_to_string(victim).unwrap(), "private");
}
