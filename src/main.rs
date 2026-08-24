use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

const LOG_FILE_PATH: &str = "/home/pikachu/aegira/system.log";
const INCIDENT_LOG_PATH: &str = "/home/pikachu/aegira/incident.log";

const BUILTIN_RULES_DIR: &str = "/home/pikachu/aegira/rules/builtin";
const CUSTOM_RULES_DIR: &str = "/home/pikachu/aegira/rules/custom";

const POLL_INTERVAL_SECS: u64 = 2;
const COMMAND_TIMEOUT_SECS: u64 = 20;
const COMPOSIO_TIMEOUT_SECS: u64 = 15;
const MIN_MATCH_SCORE: i32 = 60;
const PAID_MODE: bool = true;

const COMPOSIO_BASE_URL: &str = "https://backend.composio.dev/api/v3.1";
const COMPOSIO_GMAIL_TOOL: &str = "GMAIL_SEND_EMAIL";

fn log_incident(msg: &str) {
    println!("{}", msg);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(INCIDENT_LOG_PATH)
    {
        let _ = writeln!(file, "{}", msg);
    }
}

#[derive(Debug, Deserialize, Clone)]
struct Rule {
    id: String,
    name: String,

    #[serde(default)]
    severity: String,

    #[serde(default)]
    error_patterns: Vec<String>,

    #[serde(default)]
    context_patterns: Vec<String>,

    remediation: Remediation,
    verification: Verification,

    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Remediation {
    #[serde(rename = "service_restart")]
    ServiceRestart { service: String },

    #[serde(rename = "container_restart")]
    ContainerRestart { container: String },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type")]
enum Verification {
    #[serde(rename = "service_active")]
    ServiceActive { service: String },

    #[serde(rename = "container_running")]
    ContainerRunning { container: String },
}

fn load_rules_from_directory(path: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let directory = Path::new(path);

    if !directory.exists() {
        log_incident(&format!("[RULES] Directory does not exist: {}", path));
        return rules;
    }

    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) => {
            log_incident(&format!("[RULES ERROR] Failed to read {}: {}", path, e));
            return rules;
        }
    };

    for entry in entries.flatten() {
        let file_path = entry.path();

        if file_path.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }

        let contents = match fs::read_to_string(&file_path) {
            Ok(contents) => contents,
            Err(e) => {
                log_incident(&format!(
                    "[RULES ERROR] Failed reading {:?}: {}",
                    file_path, e
                ));
                continue;
            }
        };

        match serde_json::from_str::<Rule>(&contents) {
            Ok(rule) => {
                log_incident(&format!("[RULES] Loaded: {}", rule.id));
                rules.push(rule);
            }
            Err(e) => {
                log_incident(&format!(
                    "[RULES ERROR] Invalid rule {:?}: {}",
                    file_path, e
                ));
            }
        }
    }

    rules
}

fn load_all_rules() -> Vec<Rule> {
    log_incident("[RULES] Loading built-in rules...");

    let mut rules = load_rules_from_directory(BUILTIN_RULES_DIR);

    log_incident(&format!(
        "[RULES] Built-in rules loaded: {}",
        rules.len()
    ));

    log_incident("[RULES] Loading custom rules...");

    let custom_rules = load_rules_from_directory(CUSTOM_RULES_DIR);

    log_incident(&format!(
        "[RULES] Custom rules loaded: {}",
        custom_rules.len()
    ));

    rules.extend(custom_rules);

    log_incident(&format!(
        "[RULES] Total rules available: {}",
        rules.len()
    ));

    rules
}

fn contains_case_insensitive(text: &str, pattern: &str) -> bool {
    text.to_lowercase().contains(&pattern.to_lowercase())
}

fn calculate_match_score(rule: &Rule, incident: &str) -> i32 {
    let mut score = 0;

    for pattern in &rule.error_patterns {
        if contains_case_insensitive(incident, pattern) {
            score += 50;
        }
    }

    for pattern in &rule.context_patterns {
        if contains_case_insensitive(incident, pattern) {
            score += 20;
        }
    }

    score + rule.priority
}

fn find_best_rule<'a>(
    rules: &'a [Rule],
    incident: &str,
) -> Option<(&'a Rule, i32)> {
    let mut best_rule = None;
    let mut best_score = 0;

    for rule in rules {
        let score = calculate_match_score(rule, incident);

        if score >= MIN_MATCH_SCORE && score > best_score {
            best_score = score;
            best_rule = Some(rule);
        }
    }

    best_rule.map(|rule| (rule, best_score))
}

fn execute_command(
    executable: &str,
    args: &[&str],
) -> Result<(), String> {
    log_incident(&format!(
        "[EXEC] {} {}",
        executable,
        args.join(" ")
    ));

    let (program, program_args): (&str, Vec<&str>) =
        if executable == "systemctl" {
            let mut sudo_args = vec!["/bin/systemctl"];
            sudo_args.extend_from_slice(args);
            ("sudo", sudo_args)
        } else {
            (executable, args.to_vec())
        };

    let mut child = Command::new(program)
        .args(&program_args)
        .spawn()
        .map_err(|e| format!("Failed to start {}: {}", executable, e))?;

    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }

                return Err(format!(
                    "{} exited with status {}",
                    executable, status
                ));
            }

            Ok(None) => {
                if start.elapsed() > Duration::from_secs(COMMAND_TIMEOUT_SECS) {
                    let _ = child.kill();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable, COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(Duration::from_millis(200));
            }

            Err(e) => {
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable, e
                ));
            }
        }
    }
}

fn is_aegira_service(service: &str) -> bool {
    let normalized = service
        .trim()
        .trim_end_matches(".service")
        .to_lowercase();

    normalized == "aegira"
}

fn perform_remediation(
    remediation: &Remediation,
) -> Result<(), String> {
    match remediation {
        Remediation::ServiceRestart { service } => {
            if is_aegira_service(service) {
                return Err(
                    "Refusing remediation: rule attempts to restart aegira.service"
                        .to_string(),
                );
            }

            log_incident(&format!(
                "[RECOVERY] Restarting service: {}",
                service
            ));

            execute_command("systemctl", &["restart", service])
        }

        Remediation::ContainerRestart { container } => {
            log_incident(&format!(
                "[RECOVERY] Restarting container: {}",
                container
            ));

            execute_command("docker", &["restart", container])
        }
    }
}

fn verify_recovery(
    verification: &Verification,
) -> bool {
    match verification {
        Verification::ServiceActive { service } => {
            log_incident(&format!(
                "[VERIFY] Checking service: {}",
                service
            ));

            match Command::new("sudo")
                .arg("/bin/systemctl")
                .args(["is-active", service])
                .output()
            {
                Ok(output) => {
                    let active =
                        output.status.success()
                            && String::from_utf8_lossy(&output.stdout)
                                .trim()
                                == "active";

                    if active {
                        log_incident("[VERIFY] Service is active");
                    } else {
                        log_incident("[VERIFY] Service is NOT active");
                    }

                    active
                }

                Err(e) => {
                    log_incident(&format!("[VERIFY ERROR] {}", e));
                    false
                }
            }
        }

        Verification::ContainerRunning { container } => {
            log_incident(&format!(
                "[VERIFY] Checking container: {}",
                container
            ));

            match Command::new("docker")
                .args([
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    container,
                ])
                .output()
            {
                Ok(output) => {
                    let running =
                        output.status.success()
                            && String::from_utf8_lossy(&output.stdout)
                                .trim()
                                == "true";

                    if running {
                        log_incident("[VERIFY] Container is running");
                    } else {
                        log_incident("[VERIFY] Container is NOT running");
                    }

                    running
                }

                Err(e) => {
                    log_incident(&format!("[VERIFY ERROR] {}", e));
                    false
                }
            }
        }
    }
}

fn recover_with_rule(
    rule: &Rule,
) -> Result<(), String> {
    log_incident(&format!("[MATCH] Rule: {}", rule.name));
    log_incident(&format!("[MATCH] Rule ID: {}", rule.id));

    perform_remediation(&rule.remediation)?;

    sleep(Duration::from_secs(2));

    for attempt in 1..=5 {
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/5",
            attempt
        ));

        if verify_recovery(&rule.verification) {
            return Ok(());
        }

        sleep(Duration::from_secs(2));
    }

    Err("Remediation executed but health verification failed".to_string())
}

fn get_env(name: &str) -> Result<String, String> {
    env::var(name)
        .map_err(|_| format!("Missing environment variable: {}", name))
}

fn hostname() -> String {
    env::var("HOSTNAME").unwrap_or_else(|_| {
        Command::new("hostname")
            .output()
            .ok()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .trim()
                    .to_string()
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "unknown-host".to_string())
    })
}

fn send_composio_gmail(
    incident: &str,
    reason: &str,
) -> Result<(), String> {
    let api_key = get_env("COMPOSIO_API_KEY")?;
    let connected_account_id =
        get_env("COMPOSIO_CONNECTED_ACCOUNT_ID")?;
    let recipient =
        get_env("AEGIRA_ALERT_EMAIL")?;

    let host = hostname();

    let subject = format!(
        "[AEGIRA ALERT] Recovery failed on {}",
        host
    );

    let body = format!(
        "Aegira requires developer attention.\n\n\
Host: {}\n\
Incident: {}\n\
Reason: {}\n\n\
Automated recovery was not completed successfully.",
        host,
        incident,
        reason
    );

    let payload = json!({
        "connected_account_id": connected_account_id,
        "version": "latest",
        "arguments": {
            "recipient_email": recipient,
            "subject": subject,
            "body": body,
            "is_html": false
        }
    });

    let client = Client::builder()
        .timeout(Duration::from_secs(COMPOSIO_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!(
        "{}/tools/execute/{}",
        COMPOSIO_BASE_URL,
        COMPOSIO_GMAIL_TOOL
    );

    let response = client
        .post(&url)
        .header("x-api-key", api_key)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .map_err(|e| format!("Composio request failed: {}", e))?;

    let status = response.status();
    let response_text = response
        .text()
        .map_err(|e| format!("Failed reading Composio response: {}", e))?;

    if !status.is_success() {
        return Err(format!(
            "Composio returned HTTP {}: {}",
            status,
            response_text
        ));
    }

    let response_json: Value = serde_json::from_str(&response_text)
        .map_err(|e| {
            format!(
                "Invalid Composio response: {} | {}",
                e,
                response_text
            )
        })?;

    if response_json
        .get("successful")
        .and_then(Value::as_bool)
        != Some(true)
    {
        let error = response_json
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("Unknown Composio error");

        return Err(error.to_string());
    }

    Ok(())
}

fn escalate_to_developer(
    incident: &str,
    reason: &str,
) {
    log_incident("[ESCALATION] Automated recovery failed");

    match send_composio_gmail(incident, reason) {
        Ok(()) => {
            log_incident(
                "[ESCALATION] Developer notified successfully via Gmail"
            );
        }

        Err(e) => {
            log_incident(&format!(
                "[ESCALATION FAILED] Gmail notification failed: {}",
                e
            ));
        }
    }
}

fn process_incident(
    rules: &[Rule],
    incident: &str,
) {
    let start = Instant::now();

    log_incident("================ INCIDENT ================");
    log_incident(incident);

    let (rule, score) =
        match find_best_rule(rules, incident) {
            Some(result) => result,

            None => {
                log_incident(
                    "[MATCH] No known remediation rule found"
                );

                if PAID_MODE {
                    escalate_to_developer(
                        incident,
                        "Unknown incident",
                    );
                } else {
                    log_incident(
                        "[FREE] Unknown incident. No automated remediation."
                    );
                }

                return;
            }
        };

    log_incident(&format!(
        "[MATCH] Confidence score: {}",
        score
    ));

    match recover_with_rule(rule) {
        Ok(()) => {
            log_incident(&format!(
                "[RESOLVED] Incident automatically recovered in {:.2?}",
                start.elapsed()
            ));
        }

        Err(e) => {
            log_incident(&format!(
                "[RECOVERY FAILED] {}",
                e
            ));

            if PAID_MODE {
                escalate_to_developer(
                    incident,
                    &format!(
                        "Rule '{}' failed: {}",
                        rule.id,
                        e
                    ),
                );
            } else {
                log_incident(
                    "[FREE] Recovery failed. Developer intervention required."
                );
            }
        }
    }
}

fn main() {
    log_incident(
        "[INFO] Aegira Local Recovery Engine Started"
    );

    log_incident(&format!(
        "[INFO] Mode: {}",
        if PAID_MODE { "PAID" } else { "FREE" }
    ));

    let rules = load_all_rules();

    if rules.is_empty() {
        log_incident("[WARNING] No remediation rules loaded");
    } else {
        log_incident(&format!(
            "[INFO] {} remediation rules ready",
            rules.len()
        ));
    }

    let file = match File::open(LOG_FILE_PATH) {
        Ok(file) => file,
        Err(e) => {
            log_incident(&format!(
                "[FATAL] Failed to open monitored log: {}",
                e
            ));
            return;
        }
    };

    let mut reader = BufReader::new(file);

    let mut position =
        match reader.seek(SeekFrom::End(0)) {
            Ok(position) => position,
            Err(e) => {
                log_incident(&format!(
                    "[FATAL] Failed to seek log: {}",
                    e
                ));
                return;
            }
        };

    log_incident("[INFO] Monitoring new log entries...");

    loop {
        let metadata =
            match fs::metadata(LOG_FILE_PATH) {
                Ok(metadata) => metadata,
                Err(e) => {
                    log_incident(&format!(
                        "[ERROR] Failed to stat log: {}",
                        e
                    ));

                    sleep(Duration::from_secs(
                        POLL_INTERVAL_SECS
                    ));

                    continue;
                }
            };

        let file_size = metadata.len();

        if file_size < position {
            log_incident(
                "[INFO] Log rotation/truncation detected"
            );
            position = 0;
        }

        if file_size == position {
            sleep(Duration::from_secs(
                POLL_INTERVAL_SECS
            ));
            continue;
        }

        let file = match File::open(LOG_FILE_PATH) {
            Ok(file) => file,
            Err(e) => {
                log_incident(&format!(
                    "[ERROR] Failed to open log: {}",
                    e
                ));

                sleep(Duration::from_secs(
                    POLL_INTERVAL_SECS
                ));

                continue;
            }
        };

        let mut reader = BufReader::new(file);

        if let Err(e) =
            reader.seek(SeekFrom::Start(position))
        {
            log_incident(&format!(
                "[ERROR] Failed to seek log: {}",
                e
            ));

            sleep(Duration::from_secs(
                POLL_INTERVAL_SECS
            ));

            continue;
        }

        loop {
            let mut line = String::new();

            let bytes_read =
                match reader.read_line(&mut line) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        log_incident(&format!(
                            "[ERROR] Failed reading log: {}",
                            e
                        ));
                        break;
                    }
                };

            if bytes_read == 0 {
                break;
            }

            position += bytes_read as u64;

            let trimmed = line.trim();

            if !trimmed.contains("[ERROR]")
                && !trimmed.contains("[CRITICAL]")
            {
                continue;
            }

            log_incident(&format!(
                "[WATCHER] Incident detected: {}",
                trimmed
            ));

            process_incident(
                &rules,
                trimmed
            );
        }

        sleep(Duration::from_secs(
            POLL_INTERVAL_SECS
        ));
    }
}
