use diorama_config::legacy::{
    extract_service_flags, flags_to_config, has_config_flag, rewrite_service_content,
};

#[test]
fn unrelated_config_flags_do_not_mark_node_arguments_as_migrated() {
    let service = "# use --config=/etc/example\nDescription=--config=example\nExecStartPre=/usr/bin/helper --config=/etc/helper.conf\nExecStart=/usr/local/bin/diorama --debug\n";
    assert!(!has_config_flag(service));
    assert!(has_config_flag(&rewrite_service_content(
        service,
        "/etc/diorama/config.yaml"
    )));
}

#[test]
fn manager_dependent_expansions_are_rejected_before_conversion() {
    for service in [
        "ExecStart=/usr/local/bin/diorama --path=/var/lib/%H",
        "command_args=\"--path=$DATA_DIR\"",
        "ExecStart=/usr/local/bin/diorama --portainer-edge-key=${EDGE_KEY}",
        "exec kubesolo --path=`pwd`",
        "exec kubesolo --path=/var/lib/escaped\\ path",
    ] {
        assert!(
            flags_to_config(&extract_service_flags(service), None).is_err(),
            "service expansion must not be frozen: {service}"
        );
    }
}

#[test]
fn extraction_preserves_separate_and_explicit_empty_values() {
    let flags = extract_service_flags(
        "--node-ip 10.0.0.1 --mtu 1400 --path '/var/lib/custom path' --portainer-edge-key= --debug",
    );
    assert_eq!(flags.flags["node-ip"], "10.0.0.1");
    assert_eq!(flags.flags["mtu"], "1400");
    assert_eq!(flags.flags["path"], "/var/lib/custom path");
    assert_eq!(flags.flags["portainer-edge-key"], "");
    assert_eq!(flags.flags["debug"], "true");
    assert!(flags.missing_values.is_empty());
    assert!(flags_to_config(&extract_service_flags("--node-ip --debug"), None).is_err());
}

#[test]
fn rewrite_targets_arguments_and_removes_complete_quoted_tokens() {
    let layouts = [
        "# kubesolo documentation\nDescription=kubesolo\nExecStart=/usr/local/bin/diorama '--debug' '--node-ip=10.0.0.1'\n",
        "name=\"kubesolo\"\ncommand=\"/usr/local/bin/diorama\"\ncommand_args=\"--debug --node-ip=10.0.0.1\"\n",
        "DAEMON=\"/usr/local/bin/diorama\"\nDAEMON_ARGS=\"--debug --node-ip 10.0.0.1\"\n",
        "start-stop-daemon --start --quiet --pidfile /var/run/diorama.pid \\\n --exec /usr/local/bin/diorama -- \\\n --debug --node-ip=10.0.0.1\n",
        "exec /usr/local/bin/diorama '--debug' --node-ip=10.0.0.1\n",
    ];
    for original in layouts {
        let rewritten = rewrite_service_content(original, "/etc/diorama/config.yaml");
        assert_eq!(rewritten.matches("--config=").count(), 1);
        assert!(!rewritten.contains("--debug"));
        assert!(!rewritten.contains("--node-ip"));
        assert!(!rewritten.contains("''"));
        if original.contains("command_args=") {
            assert!(rewritten.contains(
                "name=\"kubesolo\"\ncommand=\"/usr/local/bin/diorama\"\ncommand_args=\"--config="
            ));
        }
        if original.starts_with("start-stop-daemon") {
            assert!(rewritten.find("-- ").unwrap() < rewritten.find("--config=").unwrap());
        }
        if original.starts_with('#') {
            assert!(
                rewritten.starts_with("# kubesolo documentation\nDescription=kubesolo\nExecStart=")
            );
        }
    }
}
