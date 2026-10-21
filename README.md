
# Enterprise SIEM Log Analyzer and Dashboard

**Project:** Malini S. — Enterprise SIEM Lab  
**Category:** Cybersecurity / Security Operations  
**Technology:** Python, CSV, HTML, CSS, JavaScript

## 1. Project Overview

This project is a lightweight Security Information and Event Management (SIEM) lab tool. It analyzes security logs exported in CSV format, identifies suspicious activity using predefined rules, generates alerts, and displays the results in a local web dashboard.

## 2. Features

- Reads Wazuh-style security logs from CSV files.
- Detects possible malware and virus-related events.
- Identifies privilege-related and suspicious network activity.
- Flags events with Wazuh rule levels of 10 or higher.
- Detects repeated failed logins using a configurable threshold.
- Avoids duplicate threshold alerts for IP/username pairs already covered by recognized brute-force alerts.
- Exports findings to `siem_alerts.csv`.
- Displays imported alerts in a red-and-white dashboard.
- Includes command-line arguments and basic error handling.

## 3. Project Files

| File | Purpose |
|---|---|
| `MaliniS_EnterpriseSIEMLab.py` | Python log analyzer |
| `requirements.txt` | Python dependencies |
| `sample_security_logs.csv` | Sample security events |
| `siem_alerts.csv` | Generated alert report |
| `MaliniS_SIEM_Dashboard.html` | Local web dashboard |
| `MaliniS_ProjectReport.docx` | Project documentation |

## 4. Requirements

- Windows, Linux, or another Python-compatible operating system
- Python 3
- A modern web browser
- CSV-formatted security logs

The analyzer uses Python's standard library and does not require third-party Python packages.

## 5. How to Run

Open PowerShell or a terminal in the project folder.

Run the analyzer:

```powershell
python .\MaliniS_EnterpriseSIEMLab.py
```

Use a custom failed-login threshold:

```powershell
python .\MaliniS_EnterpriseSIEMLab.py --threshold 2
```

Specify input and output files:

```powershell
python .\MaliniS_EnterpriseSIEMLab.py --input sample_security_logs.csv --output siem_alerts.csv
```

The program analyzes the input logs and creates or overwrites `siem_alerts.csv`.

## 6. Open the Dashboard

On Windows, run:

```powershell
Start-Process .\MaliniS_SIEM_Dashboard.html
```

In the dashboard:

1. Choose the generated `siem_alerts.csv` file.
2. Click **Load Analyzer Results**.
3. Review the alert counts and imported security alert records.

The dashboard reads the selected CSV locally in the browser.

## 7. Detection Logic

The analyzer uses predefined, rule-based checks to identify selected suspicious events. Repeated failed authentication attempts are grouped by source IP address and username. When a recognized brute-force alert already covers the same pair, the threshold detector skips creating another alert for that pair.

## 8. Current Test Results

Latest execution with the supplied sample dataset:

- Events analyzed: 8
- Alerts generated: 2
- High-severity alerts: 2

Results may change if the input CSV or detection threshold changes.

## 9. Limitations

- This is an educational lab project, not a production SIEM deployment.
- It analyzes CSV files and does not connect directly to a live Wazuh server.
- Detection depends on the available log fields and predefined rules.
- Findings require investigation and validation before being treated as confirmed incidents.
- The dashboard displays imported data; it does not perform live monitoring or automatic incident response.

## 10. Conclusion

This project demonstrates foundational SIEM workflows, including log parsing, rule-based detection, alert generation, CSV reporting, and browser-based visualization. It provides a starting point for further cybersecurity and SOC analyst practice.
