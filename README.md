# CyberTrace

**CyberTrace** is a lightweight Python-based SSH security monitoring and incident detection tool for Linux systems.

It collects SSH authentication events from `systemd-journald`, parses authentication activity, detects potential SSH brute-force attacks, correlates related events, classifies incident severity, and generates human-readable and machine-readable security reports.

---

## Overview

CyberTrace demonstrates an end-to-end defensive security monitoring workflow:

```text
Linux systemd-journald
        │
        ▼
SSH Event Collection
        │
        ▼
SSH Event Parsing
        │
        ▼
Brute-Force Detection
        │
        ▼
Event Correlation
        │
        ▼
Incident Generation
        │
        ▼
Severity Classification
        │
        ├──────────────► Human-Readable Report
        │
        └──────────────► JSON Report
```

The project was designed as a cybersecurity portfolio project to demonstrate practical skills in log analysis, detection engineering, event correlation, incident handling, configuration management, testing, and Python development.

---

## Features

- SSH authentication event collection using `journalctl`
- Structured JSON journal processing
- SSH authentication event parsing
- Failed-login detection
- SSH brute-force detection
- Configurable detection thresholds
- Configurable detection time windows
- Source-IP based attack grouping
- Multiple-source attack separation
- Detection cooldown handling
- Out-of-order event handling
- Successful-login correlation
- Security incident generation
- Automatic severity classification
- Human-readable security reports
- Machine-readable JSON reports
- YAML configuration
- CLI argument validation
- Configuration validation
- Journal collection error handling
- Automated test coverage

---

## Detection Pipeline

CyberTrace processes SSH activity through several stages.

### 1. Log Collection

CyberTrace collects recent SSH records from `systemd-journald` using:

```bash
journalctl -u sshd
```

The journal records are requested in JSON format so they can be processed as structured data.

### 2. Event Parsing

Raw journal records are converted into normalized authentication events.

The parser handles events such as:

- Invalid SSH users
- Failed passwords
- Successful SSH logins
- Missing timestamps
- Invalid timestamps
- Unrecognized SSH messages

Invalid or unsupported records are ignored safely.

### 3. Brute-Force Detection

Failed authentication activity is evaluated using a configurable threshold and time window.

For example:

```yaml
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5
```

With this configuration, three qualifying failed authentication attempts from the same source within five minutes can trigger a brute-force detection.

The detection engine also handles:

- Attempts below the threshold
- Attempts outside the configured window
- Multiple source IP addresses
- Multiple usernames from the same source
- Events arriving out of chronological order
- Repeated failures within the same attack sequence
- Separate attack sequences after cooldown

### 4. Event Correlation

After a detection occurs, CyberTrace correlates related authentication events from the same attack window.

A successful SSH login occurring within the relevant detection window can be associated with the incident.

### 5. Incident Generation

Detections are converted into structured security incidents containing information such as:

- Incident ID
- Detection type
- Severity
- Source IP
- Username
- Service
- First-seen timestamp
- Last-seen timestamp
- Attack duration
- Attempt count
- Successful-login status
- Successful-login timestamp
- Evidence

### 6. Severity Classification

Current severity classification:

| Condition | Severity |
|---|---|
| 3–5 failed attempts | Low |
| 6–9 failed attempts | Medium |
| 10+ failed attempts | High |
| Associated successful login | Critical |

A successful login associated with a detected brute-force sequence raises the incident to **Critical**.

---

## Configuration

CyberTrace uses YAML configuration.

The default configuration file is:

```text
config/cybertrace.yaml
```

Example:

```yaml
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5

reporting:
  json:
    enabled: true
    output: reports/cybertrace_report.json
```

### SSH Detection Configuration

```yaml
ssh:
  brute_force:
    threshold: 3
    window_minutes: 5
```

| Setting | Description |
|---|---|
| `threshold` | Minimum number of qualifying failed authentication attempts |
| `window_minutes` | Time window used when evaluating attempts |

Both values must be positive integers.

### JSON Reporting Configuration

```yaml
reporting:
  json:
    enabled: true
    output: reports/cybertrace_report.json
```

| Setting | Description |
|---|---|
| `enabled` | Enables or disables JSON report generation |
| `output` | Path where the JSON report is written |

---

## Command-Line Interface

CyberTrace provides a command-line interface.

### Show help

```bash
python main.py --help
```

Example:

```text
usage: cybertrace [-h] [--config CONFIG] [--limit LIMIT] [--no-json]

CyberTrace SSH security monitoring and detection tool.

options:
  -h, --help       show this help message and exit
  --config CONFIG  Path to the CyberTrace YAML configuration file.
  --limit LIMIT    Maximum number of SSH journal records to collect.
  --no-json        Disable JSON report generation for this run.
```

### Run with the default configuration

```bash
python main.py
```

### Specify a configuration file

```bash
python main.py --config config/cybertrace.yaml
```

### Limit collected journal records

```bash
python main.py --limit 100
```

The default collection limit is `50`.

The CLI rejects invalid values such as:

```text
0
-1
-50
abc
```

### Disable JSON reporting

```bash
python main.py --no-json
```

### Combine options

```bash
python main.py \
    --config config/cybertrace.yaml \
    --limit 100 \
    --no-json
```

---

## Example Execution

Example output from a real local run:

```text
=== CYBERTRACE PIPELINE ===

=== ACTIVE CONFIGURATION ===
SSH brute-force threshold : 3
SSH detection window      : 5 minutes
Event collection limit    : 50
JSON reporting enabled    : True
JSON report output        : reports/cybertrace_report.json

Collected: 42
Parsed: 9
Detected: 2
Incidents: 2

CYBERTRACE SECURITY REPORT
Total Incidents: 2

CYBERTRACE SECURITY SUMMARY
Total Incidents       : 2
Critical Incidents    : 0
High Incidents        : 0
Medium Incidents      : 0
Low Incidents         : 2
Successful Compromise : 0
Unique Source IPs     : 1
```

Example incident:

```text
============================================================
CYBERTRACE SECURITY INCIDENT
============================================================
Incident ID      : INC-ssh-...
Detection Type   : ssh_bruteforce
Severity         : low
Source IP        : ::1
Username         : nonexistent_test_user
Service          : ssh
First Seen       : ...
Last Seen        : ...
Duration         : ...
Attempts         : 3
Successful Login : False
Success Time     : None

Evidence:
  [1] Invalid user ...
  [2] Failed password ...
  [3] Failed password ...
============================================================
```

---

## JSON Reporting

When JSON reporting is enabled, CyberTrace generates:

```text
reports/cybertrace_report.json
```

The JSON report contains structured information including:

- Tool information
- Total incident count
- Incident summary
- Severity statistics
- Successful-compromise statistics
- Unique source IP statistics
- Detailed incident records
- Evidence
- Timestamps

This makes the output suitable for machine processing and future integration with other security tooling.

---

## Error Handling

CyberTrace handles expected operational errors without producing uncontrolled tracebacks for normal CLI usage.

### Missing configuration

Example:

```text
=== CONFIGURATION ERROR ===
Configuration file not found: /tmp/does-not-exist.yaml
```

The CLI returns a non-zero exit status for configuration errors.

### Invalid configuration

Invalid values such as:

```yaml
threshold: 0
```

or:

```yaml
window_minutes: -1
```

are rejected during configuration validation.

### Journal collection failure

If `journalctl` cannot be executed or returns an error, CyberTrace reports the collection failure:

```text
=== COLLECTION ERROR ===
journalctl command was not found.
```

The collection layer uses a dedicated `JournalCollectionError` exception so operational failures can be handled separately from configuration errors.

---

## Testing

CyberTrace includes an automated test suite covering the major components of the application.

Test coverage includes:

### CLI

- End-to-end pipeline execution
- JSON reporting behavior
- Collection failure handling
- Default CLI arguments
- Invalid `--limit` values
- Valid `--limit` values
- Custom configuration paths
- `--no-json`

### Collection

- JSON journal parsing
- Blank-line handling
- Invalid JSON handling
- Non-mapping JSON handling
- Missing `journalctl`
- `journalctl` command failures
- Collection error messages

### Configuration

- Valid configuration loading
- Missing configuration files
- Invalid configuration structures
- Invalid thresholds
- Invalid detection windows
- Boolean validation

### Detection

- Threshold detection
- Below-threshold activity
- Detection windows
- Exact window boundaries
- Multiple source IPs
- Multiple usernames
- Successful-login exclusion
- Cooldown behavior
- Out-of-order events
- Long attack sequences

### Incident Generation

- Incident creation
- Successful-login correlation
- Correlation window handling
- Source-IP correlation
- Incident duration
- Severity classification
- Critical severity for successful compromise

### Parser

- Failed SSH passwords
- Invalid SSH users
- Successful SSH logins
- Empty records
- Unrecognized messages
- Missing timestamps
- Invalid timestamps

### Reporting

- Incident serialization
- Human-readable reports
- Empty reports
- JSON reports
- Timestamp preservation
- Report summaries
- Severity statistics

### Run the complete test suite

```bash
python -m pytest -v
```

Current project test result:

```text
73 passed
```

### Run CLI tests only

```bash
python -m pytest tests/test_cli.py -v
```

### Check for whitespace errors

```bash
git diff --check
```

---

## Project Structure

```text
CyberTrace/
│
├── cybertrace/
│   ├── cli.py
│   │
│   ├── collector/
│   │   └── journal.py
│   │
│   ├── config/
│   │   └── loader.py
│   │
│   ├── detection/
│   │   └── ssh.py
│   │
│   ├── incident/
│   │   └── generator.py
│   │
│   ├── parser/
│   │   └── ssh.py
│   │
│   └── reporting/
│       └── report.py
│
├── config/
│   └── cybertrace.yaml
│
├── reports/
│
├── tests/
│   ├── test_cli.py
│   ├── test_collector.py
│   ├── test_config.py
│   ├── test_detection.py
│   ├── test_incident.py
│   ├── test_parser.py
│   └── test_reporting.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

## Technologies

CyberTrace is built using:

- **Python**
- **PyYAML**
- **pytest**
- **systemd-journald**
- **journalctl**
- **JSON**
- **YAML**

---

## Security Concepts Demonstrated

CyberTrace demonstrates several practical defensive-security concepts:

- Security log collection
- Authentication monitoring
- Log normalization
- Detection engineering
- Brute-force detection
- Time-window analysis
- Source-IP correlation
- Event correlation
- Incident generation
- Incident severity classification
- Security evidence collection
- Structured security reporting
- Configuration validation
- CLI validation
- Error handling
- Automated testing

The overall workflow is representative of a simplified SOC detection pipeline:

```text
Collect
   ↓
Parse
   ↓
Detect
   ↓
Correlate
   ↓
Classify
   ↓
Report
```

---

## Limitations

CyberTrace currently focuses on SSH authentication activity obtained from `systemd-journald`.

It is a lightweight portfolio and learning project and is **not intended to replace** production security platforms such as:

- SIEM platforms
- EDR platforms
- IDS/IPS systems
- Enterprise SOC monitoring infrastructure

The current implementation focuses specifically on demonstrating the underlying detection and incident-processing workflow.

---

## Future Improvements

Potential future development areas include:

- Additional Linux log sources
- More authentication detection rules
- Privilege-escalation detection
- Suspicious process detection
- Alerting integrations
- Email or webhook notifications
- Persistent incident storage
- Web dashboard
- Historical incident analytics
- Additional output formats
- Scheduled monitoring
- Integration with external security platforms

---

## Development Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate the environment:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the test suite:

```bash
python -m pytest -v
```

Run CyberTrace:

```bash
python main.py
```

---

## Portfolio Context

CyberTrace was built to demonstrate practical cybersecurity engineering skills through a complete defensive-security application rather than isolated scripts.

The project combines:

```text
Python Development
        +
Linux Log Analysis
        +
Detection Engineering
        +
Event Correlation
        +
Incident Response Concepts
        +
Automated Testing
        +
CLI/Application Design
        +
Security Reporting
```

---

## License

This project is intended as a cybersecurity portfolio and learning project.
