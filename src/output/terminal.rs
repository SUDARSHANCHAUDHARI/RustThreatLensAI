use colored::Colorize;
use crate::report::{RiskLevel, ThreatReport};
use crate::detector::Severity;

pub fn print(report: &ThreatReport) {
    println!("\n{}", "ThreatLens Report".bold().underline());
    println!("{} {}", "File:".bold(), report.file);
    println!("{} {}", "Log Type:".bold(), report.log_type);
    println!("{} {}", "Total Events:".bold(), report.total_events);

    let risk_colored = match report.risk_level {
        RiskLevel::Low => report.risk_level.to_string().green(),
        RiskLevel::Medium => report.risk_level.to_string().yellow(),
        RiskLevel::High => report.risk_level.to_string().red(),
        RiskLevel::Critical => report.risk_level.to_string().red().bold(),
    };
    println!("{} {}", "Risk:".bold(), risk_colored);
    println!("{} {}", "Summary:".bold(), report.summary);

    if report.findings.is_empty() {
        println!("\n{}", "No threats found.".green());
        return;
    }

    println!("\n{}", "Findings:".bold());
    for finding in &report.findings {
        let sev = match finding.severity {
            Severity::Low => finding.rule.yellow(),
            Severity::Medium => finding.rule.yellow(),
            Severity::High => finding.rule.red(),
            Severity::Critical => finding.rule.red().bold(),
        };
        println!("  {} — {}", sev, finding.description);
        for evidence in finding.evidence.iter().take(2) {
            println!("    {}", evidence.dimmed());
        }
    }
    println!();
}
