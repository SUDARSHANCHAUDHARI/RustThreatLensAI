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
