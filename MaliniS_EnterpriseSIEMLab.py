
#!/usr/bin/env python3
"""Wazuh-focused SIEM log analyzer using Python's standard library."""

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

DEFAULT_INPUT = "sample_security_logs.csv"
DEFAULT_OUTPUT = "siem_alerts.csv"

# Supports Wazuh-exported CSV and generic CSV formats.
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "@timestamp"],
    "source_ip": ["source_ip", "src_ip"],
    "username": ["username", "user"],
    "event_type": ["event_type", "rule_description"],
    "status": ["status"],
    "details": ["details", "rule_description"],
    "rule_id": ["rule_id"],
    "rule_level": ["rule_level"],
    "agent_name": ["agent_name"],
    "destination_ip": ["dst_ip", "destination_ip"],
}


def get_value(row, field):
    """Get a field using its supported column aliases."""
    for name in COLUMN_ALIASES.get(field, [field]):
        value = row.get(name)
        if value is not None and value.strip():
            return value.strip()
    return ""


def load_logs(filename):
    """Load CSV logs without changing the source file."""
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header.")

        required = {"timestamp", "source_ip", "username", "status"}
        available = set(reader.fieldnames)

        missing = [
            field for field in required
            if not any(
                alias in available
                for alias in COLUMN_ALIASES[field]
            )
        ]

        if missing:
            raise ValueError(
                "CSV is missing required fields: " + ", ".join(missing)
            )

        return list(reader)


def make_alert(row, severity, message):
    """Normalize a security event into an alert."""
    existing_details = get_value(row, "details")

    return {
        "timestamp": get_value(row, "timestamp"),
        "severity": severity,
        "source_ip": get_value(row, "source_ip"),
        "destination_ip": get_value(row, "destination_ip"),
        "username": get_value(row, "username"),
        "rule_id": get_value(row, "rule_id"),
        "rule_level": get_value(row, "rule_level"),
        "agent_name": get_value(row, "agent_name"),
        "event_type": get_value(row, "event_type"),
        "status": get_value(row, "status"),
        "details": f"{message} | {existing_details}".strip(" |"),
    }


def is_bruteforce_alert(alert):
    """Identify alerts that already describe repeated SSH failures."""
    text = (
        str(alert.get("details", "")) + " " +
        str(alert.get("event_type", ""))
    ).lower()

    return any(
        phrase in text
        for phrase in (
            "brute force",
            "multiple sshd authentication failures",
            "multiple failed login",
        )
    )


def detect_alerts(rows, threshold=3):
    """Detect suspicious events and repeated failed logins."""
    alerts = []
    failed_logins = Counter()
    failed_rows = defaultdict(list)

    for row in rows:
        description = get_value(row, "event_type").lower()
        status = get_value(row, "status").lower()
        rule_level_text = get_value(row, "rule_level")

        try:
            rule_level = int(rule_level_text) if rule_level_text else 0
        except ValueError:
            rule_level = 0

        source_ip = get_value(row, "source_ip")
        username = get_value(row, "username")
        key = (source_ip, username)

        # Track failed authentication events.
        if status in {"failed", "failure", "denied"}:
            failed_logins[key] += 1
            failed_rows[key].append(row)

        # Detect suspicious security events.
        if "malware" in description or "virus" in description:
            alerts.append(
                make_alert(row, "CRITICAL", "Possible malware event")
            )

        elif any(
            word in description
            for word in ("privilege escalation", "privilege change")
        ):
            alerts.append(
                make_alert(row, "HIGH", "Privilege-related event")
            )

        elif any(
            word in description
            for word in ("port scan", "network scan", "suspicious process")
        ):
            alerts.append(
                make_alert(row, "HIGH", "Suspicious activity event")
            )

        elif rule_level >= 10:
            alerts.append(
                make_alert(
                    row,
                    "HIGH",
                    "Wazuh rule level is 10 or higher",
                )
            )

    # Record IP/user pairs already covered by Wazuh brute-force alerts.
    existing_bruteforce_pairs = {
        (alert["source_ip"], alert["username"])
        for alert in alerts
        if is_bruteforce_alert(alert)
    }

    # Add threshold-based alerts only when they are not duplicates.
    for key, count in failed_logins.items():
        if count < threshold:
            continue

        if key in existing_bruteforce_pairs:
            continue

        row = failed_rows[key][-1]

        alerts.append(
            make_alert(
                row,
                "HIGH",
                f"{count} failed logins for this source IP and user",
            )
        )

    return alerts


def save_alerts(alerts, filename):
    """Save alerts separately from the input log file."""
    fields = [
        "timestamp",
        "severity",
        "source_ip",
        "destination_ip",
        "username",
        "rule_id",
        "rule_level",
        "agent_name",
        "event_type",
        "status",
        "details",
    ]

    with Path(filename).open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)


def main():
    """Run the SIEM analyzer from the command line."""
    parser = argparse.ArgumentParser(
        description="Analyze Wazuh-exported security logs."
    )

    parser.add_argument(
        "-i", "--input",
        default=DEFAULT_INPUT,
        help="Input security log CSV file",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT,
        help="Output alert CSV file",
    )
    parser.add_argument(
        "-t", "--threshold",
        type=int,
        default=3,
        help="Failed-login threshold for generating alerts (default: 3)",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    try:
        rows = load_logs(args.input)
        alerts = detect_alerts(rows, args.threshold)
        save_alerts(alerts, args.output)

        print("Wazuh Enterprise SIEM Lab")
        print("-------------------------")
        print(f"Events analyzed : {len(rows)}")
        print(f"Alerts generated: {len(alerts)}")
        print(f"Output report   : {args.output}")

        counts = Counter(alert["severity"] for alert in alerts)

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts[severity]:
                print(f"{severity} alerts: {counts[severity]}")

        print("\nNote: These are rule-based findings for lab analysis.")
        print("Verify alerts in Wazuh before drawing incident conclusions.")

    except (OSError, csv.Error, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
