use anyhow::Result;
use crate::report::ThreatReport;

pub fn print(report: &ThreatReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
