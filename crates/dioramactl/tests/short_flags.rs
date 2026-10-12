use dioramactl::{ParseError, parse_command};
use std::collections::BTreeMap;

fn parse(values: &[&str]) -> Result<dioramactl::Command, ParseError> {
    let arguments = values
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    parse_command(&arguments, &BTreeMap::new())
}

#[test]
fn documented_path_aliases_match_long_flags() {
    for (command, short, long) in [
        ("config", "-f", "--file"),
        ("kubeconfig", "-o", "--output"),
        ("d2k", "-o", "--output"),
    ] {
        assert_eq!(
            parse(&[command, short, "selected-path"]),
            parse(&[command, long, "selected-path"]),
        );
        assert_eq!(
            parse(&[command, &format!("{short}=selected-path")]),
            parse(&[command, long, "selected-path"]),
        );
        assert!(parse(&[command, short]).is_err());
        assert!(parse(&[command, short, "--help"]).is_err());
    }
}

#[test]
fn path_aliases_remain_scoped_to_their_commands() {
    for arguments in [["download", "-f"], ["config", "-o"], ["reset", "-o"]] {
        assert_eq!(parse(&arguments), Err(ParseError::UnknownFlag));
    }
}
