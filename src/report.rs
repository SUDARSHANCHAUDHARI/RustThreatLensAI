use serde::{Deserialize, Serialize};
use crate::parser::LogEvent;
use crate::detector::Finding;

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatReport {
    pub file: String,
    pub log_type: String,
    pub total_events: usize,
    pub findings: Vec<Finding>,
    pub risk_level: RiskLevel,
    pub summary: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

pub fn build(file: &str, log_type: &str, events: &[LogEvent], findings: &[Finding]) -> ThreatReport {
    let risk_level = if findings.iter().any(|f| matches!(f.severity, crate::detector::Severity::Critical)) {
        RiskLevel::Critical
    } else if findings.iter().any(|f| matches!(f.severity, crate::detector::Severity::High)) {
        RiskLevel::High
    } else if findings.iter().any(|f| matches!(f.severity, crate::detector::Severity::Medium)) {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let summary = if findings.is_empty() {
        "No threats detected.".to_string()
    } else {
        format!("{} threat(s) detected. Immediate review recommended.", findings.len())
    };

    ThreatReport {
        file: file.to_string(),
        log_type: log_type.to_string(),
        total_events: events.len(),
        findings: findings.to_vec(),
        risk_level,
        summary,
    }
}
