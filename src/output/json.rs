use anyhow::Result;
use threatlens::report::ThreatReport;

pub fn print(report: &ThreatReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
