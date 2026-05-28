use assert_cmd::Command;
use predicates::str::contains;
use std::io::Write;
use tempfile::NamedTempFile;
use threatlens::detector;
use threatlens::parser;
use threatlens::report;

// --- CLI tests ---

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

// --- Parser unit tests ---

#[test]
fn test_parse_auth_failed_login() {
    let line =
        "May 18 10:01:01 server sshd[1234]: Failed password for root from 192.168.1.1 port 22";
    let events = parser::parse(line, "auth");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action.as_deref(), Some("failed_login"));
    assert_eq!(events[0].ip.as_deref(), Some("192.168.1.1"));
}

#[test]
fn test_parse_auth_successful_login() {
    let line =
        "May 18 10:01:01 server sshd[1234]: Accepted password for admin from 10.0.0.1 port 22";
    let events = parser::parse(line, "auth");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action.as_deref(), Some("successful_login"));
}

#[test]
fn test_parse_auto_detects_auth_type() {
    let line = "May 18 10:01:01 server sshd[1234]: Failed password for root from 1.2.3.4 port 22";
    let events = parser::parse(line, "auto");
    assert_eq!(events[0].log_type, "auth");
}

#[test]
fn test_parse_auto_detects_nginx_type() {
    let line = r#"192.168.1.1 - - [18/May/2026] "GET /index.html HTTP/1.1" 200 1234"#;
    let events = parser::parse(line, "auto");
    assert_eq!(events[0].log_type, "nginx");
}

// --- Detector unit tests ---

#[test]
fn test_brute_force_detected_at_5_failures() {
    let log = (0..5)
        .map(|_| "May 18 10:01:01 server sshd: Failed password for root from 10.0.0.1 port 22")
        .collect::<Vec<_>>()
        .join("\n");

    let events = parser::parse(&log, "auth");
    let findings = detector::detect(&events);
    assert!(findings.iter().any(|f| f.rule == "BRUTE_FORCE"));
}

#[test]
fn test_brute_force_not_triggered_at_4_failures() {
    let log = (0..4)
        .map(|_| "May 18 10:01:01 server sshd: Failed password for root from 10.0.0.1 port 22")
        .collect::<Vec<_>>()
        .join("\n");

    let events = parser::parse(&log, "auth");
    let findings = detector::detect(&events);
    assert!(!findings.iter().any(|f| f.rule == "BRUTE_FORCE"));
}

#[test]
fn test_secret_in_logs_detected() {
    let log = "2026-05-18 curl -H 'Authorization: Bearer supersecrettoken' http://api.example.com";
    let events = parser::parse(log, "generic");
    let findings = detector::detect(&events);
    assert!(findings.iter().any(|f| f.rule == "SECRET_IN_LOGS"));
}

#[test]
fn test_no_findings_gives_low_risk() {
    let log = "May 18 10:01:01 server sshd: Connection from 1.2.3.4 port 22";
    let events = parser::parse(log, "auth");
    let findings = detector::detect(&events);
    let rep = report::build("test.log", "auth", &events, &findings);
    assert!(matches!(rep.risk_level, threatlens::report::RiskLevel::Low));
}

#[test]
fn test_brute_force_gives_critical_risk() {
    let log = (0..5)
        .map(|_| "May 18 10:01:01 server sshd: Failed password for root from 10.0.0.1 port 22")
        .collect::<Vec<_>>()
        .join("\n");

    let events = parser::parse(&log, "auth");
    let findings = detector::detect(&events);
    let rep = report::build("test.log", "auth", &events, &findings);
    assert!(matches!(
        rep.risk_level,
        threatlens::report::RiskLevel::Critical
    ));
}

// --- CLI integration with real file ---

#[test]
fn test_analyze_real_file_json_output() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        "May 18 10:01:01 server sshd: Failed password for root from 10.0.0.1 port 22"
    )
    .unwrap();

    Command::cargo_bin("threatlens")
        .unwrap()
        .args(["analyze", file.path().to_str().unwrap(), "--json"])
        .assert()
        .success()
        .stdout(contains("total_events"));
}

#[test]
fn test_cli_custom_brute_force_threshold_can_reduce_noise() {
    let mut file = NamedTempFile::new().unwrap();
    for _ in 0..5 {
        writeln!(
            file,
            "May 18 10:01:01 server sshd: Failed password for root from 10.0.0.1 port 22"
        )
        .unwrap();
    }

    Command::cargo_bin("threatlens")
        .unwrap()
        .args([
            "analyze",
            file.path().to_str().unwrap(),
            "--brute-force-threshold",
            "6",
            "--json",
        ])
        .assert()
        .success()
        .stdout(contains("\"findings\": []"));
}
