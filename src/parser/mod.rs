use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEvent {
    pub line: String,
    pub log_type: String,
    pub ip: Option<String>,
    pub user: Option<String>,
    pub action: Option<String>,
}

pub fn parse(content: &str, log_type: &str) -> Vec<LogEvent> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| parse_line(line, log_type))
        .collect()
}

fn parse_line(line: &str, log_type: &str) -> LogEvent {
    let detected_type = if log_type == "auto" {
        detect_type(line)
    } else {
        log_type.to_string()
    };

    let ip = extract_ip(line);
    let user = extract_user(line, &detected_type);
    let action = extract_action(line, &detected_type);

    LogEvent {
        line: line.to_string(),
        log_type: detected_type,
        ip,
        user,
        action,
    }
}

fn detect_type(line: &str) -> String {
    if line.contains("sshd") || line.contains("Failed password") || line.contains("Accepted password") {
        "auth".to_string()
    } else if line.contains("HTTP/") || line.contains("GET ") || line.contains("POST ") {
        "nginx".to_string()
    } else if line.contains("container") || line.contains("docker") {
        "docker".to_string()
    } else {
        "generic".to_string()
    }
}

fn extract_ip(line: &str) -> Option<String> {
    let re = regex::Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b").ok()?;
    re.find(line).map(|m| m.as_str().to_string())
}

fn extract_user(line: &str, log_type: &str) -> Option<String> {
    if log_type == "auth" {
        let re = regex::Regex::new(r"(?:for|user) (\w+)").ok()?;
        re.captures(line)?.get(1).map(|m| m.as_str().to_string())
    } else {
        None
    }
}

fn extract_action(line: &str, log_type: &str) -> Option<String> {
    match log_type {
        "auth" => {
            if line.contains("Failed") { Some("failed_login".to_string()) }
            else if line.contains("Accepted") { Some("successful_login".to_string()) }
            else { None }
        }
        "nginx" => {
            let re = regex::Regex::new(r#""(GET|POST|PUT|DELETE|PATCH)"#).ok()?;
            re.captures(line)?.get(1).map(|m| m.as_str().to_lowercase())
        }
        _ => None,
    }
}
