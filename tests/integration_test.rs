use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn test_help() {
    Command::cargo_bin("threatlens")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("log threat analyzer"));
}

#[test]
fn test_analyze_subcommand_help() {
    Command::cargo_bin("threatlens")
        .unwrap()
        .args(["analyze", "--help"])
        .assert()
        .success()
        .stdout(contains("log file"));
}
