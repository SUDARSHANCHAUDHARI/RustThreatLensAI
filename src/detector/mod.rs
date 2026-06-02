use crate::parser::LogEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub rule: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn detect(events: &[LogEvent]) -> Vec<Finding> {
    detect_with_brute_force_threshold(events, 5)
}

pub fn detect_with_brute_force_threshold(
    events: &[LogEvent],
    brute_force_threshold: usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let brute_force_threshold = brute_force_threshold.max(1);

    if let Some(f) = detect_brute_force(events, brute_force_threshold) {
        findings.push(f);
    }
    if let Some(f) = detect_secret_in_logs(events) {
        findings.push(f);
    }
    if let Some(f) = detect_suspicious_ips(events) {
        findings.push(f);
    }

    findings
}

fn detect_brute_force(events: &[LogEvent], threshold: usize) -> Option<Finding> {
    let mut ip_failures: HashMap<String, Vec<String>> = HashMap::new();

    for event in events {
        if event.action.as_deref() == Some("failed_login") {
            if let Some(ip) = &event.ip {
                ip_failures
                    .entry(ip.clone())
                    .or_default()
                    .push(event.line.clone());
            }
        }
    }

    let offenders: Vec<(String, Vec<String>)> = ip_failures
        .into_iter()
        .filter(|(_, lines)| lines.len() >= threshold)
        .collect();

    if offenders.is_empty() {
        return None;
    }

    let evidence: Vec<String> = offenders
        .iter()
        .map(|(ip, lines)| format!("{}: {} failed attempts", ip, lines.len()))
        .collect();

    Some(Finding {
        rule: "BRUTE_FORCE".to_string(),
        severity: Severity::Critical,
        description: format!(
            "{} IP(s) with {}+ failed login attempts detected",
            offenders.len(),
            threshold
        ),
        evidence,
    })
}

fn detect_secret_in_logs(events: &[LogEvent]) -> Option<Finding> {
    let patterns = [
        "password=",
        "api_key=",
        "token=",
        "secret=",
        "Authorization: Bearer",
    ];

    let matches: Vec<String> = events
        .iter()
        .filter(|e| {
            let lower = e.line.to_lowercase();
            patterns
                .iter()
                .any(|p| lower.contains(&p.to_lowercase() as &str))
        })
        .map(|e| e.line.clone())
        .collect();

    if matches.is_empty() {
        return None;
    }

    Some(Finding {
        rule: "SECRET_IN_LOGS".to_string(),
        severity: Severity::High,
        description: format!("{} line(s) may contain exposed secrets", matches.len()),
        evidence: matches.into_iter().take(3).collect(),
    })
}

fn detect_suspicious_ips(events: &[LogEvent]) -> Option<Finding> {
    let suspicious = ["0.0.0.0", "127.0.0.1"];

    let matches: Vec<String> = events
        .iter()
        .filter(|e| {
            e.ip.as_ref()
                .map(|ip| suspicious.contains(&ip.as_str()))
                .unwrap_or(false)
        })
        .map(|e| e.line.clone())
        .collect();

    if matches.is_empty() {
        return None;
    }

    Some(Finding {
        rule: "SUSPICIOUS_IP".to_string(),
        severity: Severity::Medium,
        description: format!("{} event(s) from suspicious IPs", matches.len()),
        evidence: matches.into_iter().take(3).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::LogEvent;

    fn auth_event(ip: &str, action: &str) -> LogEvent {
        LogEvent {
            line: format!("Failed password for root from {ip}"),
            log_type: "auth".to_string(),
            ip: Some(ip.to_string()),
            user: Some("root".to_string()),
            action: Some(action.to_string()),
        }
    }

    fn secret_event(content: &str) -> LogEvent {
        LogEvent {
            line: content.to_string(),
            log_type: "generic".to_string(),
            ip: None,
            user: None,
            action: None,
        }
    }

    #[test]
    fn detects_brute_force_above_threshold() {
        let events: Vec<LogEvent> = (0..5).map(|_| auth_event("1.2.3.4", "failed_login")).collect();
        let findings = detect_with_brute_force_threshold(&events, 5);
        assert!(findings.iter().any(|f| f.rule == "BRUTE_FORCE"));
    }

    #[test]
    fn no_brute_force_below_threshold() {
        let events: Vec<LogEvent> = (0..4).map(|_| auth_event("1.2.3.4", "failed_login")).collect();
        let findings = detect_with_brute_force_threshold(&events, 5);
        assert!(!findings.iter().any(|f| f.rule == "BRUTE_FORCE"));
    }

    #[test]
    fn detects_secret_in_logs() {
        let events = vec![secret_event("api_key=supersecret123")];
        let findings = detect(&events);
        assert!(findings.iter().any(|f| f.rule == "SECRET_IN_LOGS"));
    }

    #[test]
    fn detects_suspicious_ip() {
        let events = vec![LogEvent {
            line: "request from 127.0.0.1".to_string(),
            log_type: "generic".to_string(),
            ip: Some("127.0.0.1".to_string()),
            user: None,
            action: None,
        }];
        let findings = detect(&events);
        assert!(findings.iter().any(|f| f.rule == "SUSPICIOUS_IP"));
    }

    #[test]
    fn no_findings_for_clean_events() {
        let events = vec![LogEvent {
            line: "INFO server started ok".to_string(),
            log_type: "generic".to_string(),
            ip: Some("10.0.0.1".to_string()),
            user: None,
            action: None,
        }];
        assert!(detect(&events).is_empty());
    }
}
