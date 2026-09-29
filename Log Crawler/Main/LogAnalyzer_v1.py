## Stefan West || init 9/28/2026 || LogAnalyzer v1.0 ##
## Analyzes JSONL web logs into counts, statistics, and evidence-based signals. ##
## Log 1: baseline; Log 2: ddos; Log 3: idor; Log 4: password spraying; Log 5: mixed ##

import argparse
import json
import math
from collections import Counter
from pathlib import Path


# Required input-field names are used to report omissions, not reject the whole record.
KNOWN_FIELDS = (
    "timestamp",
    "source_ip",
    "user_agent",
    "endpoint",
    "method",
    "status_code",
    "username",
    "response_time",
)
HIGH_REQUEST_RATE_THRESHOLD = 100


# Load JSONL records, keeping parse errors and missing-field warnings as evidence.
class LogAnalyzer:
    def __init__(self, filepath):
        # Keep valid objects, parse errors, and field warnings separately for the report.
        self.filepath = Path(filepath).expanduser()
        self.records = []
        self.errors = []
        self.warnings = []
        self._load_records()

    def _load_records(self):
        if not self.filepath.exists():
            raise FileNotFoundError(f"Log file not found: {self.filepath}")

        # Each nonblank line is independent, so one malformed line does not stop the scan.
        with self.filepath.open("r", encoding="utf-8", errors="replace") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    self.errors.append({
                        "line": line_number,
                        "error": f"Invalid JSON: {error.msg}",
                    })
                    continue

                if not isinstance(record, dict):
                    self.errors.append({
                        "line": line_number,
                        "error": "JSON value must be an object",
                    })
                    continue

                missing_fields = [
                    field for field in KNOWN_FIELDS if field not in record
                ]
                if missing_fields:
                    # Missing data is a warning; the available record remains analyzable.
                    self.warnings.append({
                        "line": line_number,
                        "warning": "Missing fields",
                        "fields": missing_fields,
                    })

                self.records.append(record)

    # Aggregation helpers keep report construction focused on output shape.
    def _count(self, field):
        return dict(Counter(
            record[field]
            for record in self.records
            if field in record and record[field] is not None
        ))

    def _top(self, values, limit):
        return Counter(values).most_common(limit)

    def _timestamps(self):
        return [
            record["timestamp"]
            for record in self.records
            if isinstance(record.get("timestamp"), str)
        ]

    def _response_times(self):
        return [
            record["response_time"]
            for record in self.records
            if isinstance(record.get("response_time"), (int, float))
            and not isinstance(record["response_time"], bool)
        ]

    # Generate evidence-based signals from request concentration and supplied rates.
    def _detection_signals(self):
        signals = []
        ip_counts = Counter(
            record["source_ip"]
            for record in self.records
            if record.get("source_ip")
        )

        # Flag concentration only when one IP accounts for half the records and at least 20.
        if self.records:
            highest_ip, highest_count = ip_counts.most_common(1)[0] if ip_counts else (None, 0)
            if highest_count >= max(20, len(self.records) * 0.5):
                signals.append({
                    "type": "high_request_concentration",
                    "source_ip": highest_ip,
                    "request_count": highest_count,
                    "basis": "One source IP generated at least half of all valid records.",
                })

        # This signal uses an input-provided rate; it does not derive a rate from timestamps.
        peak_rate_by_ip = {}
        high_rate_records_by_ip = Counter()
        for record in self.records:
            source_ip = record.get("source_ip")
            request_rate = record.get("request_count_per_second")
            if (
                not source_ip
                or not isinstance(request_rate, (int, float))
                or isinstance(request_rate, bool)
                or not math.isfinite(request_rate)
                or request_rate < HIGH_REQUEST_RATE_THRESHOLD
            ):
                continue

            peak_rate_by_ip[source_ip] = max(
                request_rate,
                peak_rate_by_ip.get(source_ip, request_rate),
            )
            high_rate_records_by_ip[source_ip] += 1

        for source_ip, peak_rate in sorted(
            peak_rate_by_ip.items(), key=lambda item: (-item[1], item[0])
        ):
            signals.append({
                "type": "high_reported_request_rate",
                "source_ip": source_ip,
                "peak_requests_per_second": peak_rate,
                "records_at_or_above_threshold": high_rate_records_by_ip[source_ip],
                "threshold_requests_per_second": HIGH_REQUEST_RATE_THRESHOLD,
                "basis": "Input records reported request_count_per_second at or above the configured threshold.",
            })

        return signals

    # Query helpers used by the analyzer's optional command-line filters.
    def ip_occurrences(self, ip):
        return sum(1 for record in self.records if record.get("source_ip") == ip)

    def timestamp_occurrences(self, timestamp):
        return sum(1 for record in self.records if record.get("timestamp") == timestamp)

    def http_action_occurrences(self, method):
        return sum(1 for record in self.records if record.get("method") == method)

    def status_code_occurrences(self, status):
        return sum(1 for record in self.records if record.get("status_code") == status)

    def top_n_ips(self, limit):
        counts = Counter(record["source_ip"] for record in self.records if record.get("source_ip"))
        return counts.most_common(limit)

    def all_status_codes(self):
        return dict(Counter(
            str(record["status_code"])
            for record in self.records
            if record.get("status_code") is not None
        ))

    def top_n_status_codes(self, limit):
        counts = Counter(
            str(record["status_code"])
            for record in self.records
            if record.get("status_code") is not None
        )
        return counts.most_common(limit)

    def top_n_ip_with_action_status(self, method, status, limit):
        counts = Counter(
            record["source_ip"]
            for record in self.records
            if record.get("source_ip")
            and record.get("method") == method
            and record.get("status_code") == status
        )
        return counts.most_common(limit)

    # Assemble the serializable summary consumed by the workflow coordinator.
    def report(self):
        timestamps = self._timestamps()
        response_times = self._response_times()
        records_by_ip = [
            record["source_ip"]
            for record in self.records
            if record.get("source_ip")
        ]

        # Timestamp min/max assumes comparable timestamp strings (for example, normalized ISO 8601).
        return {
            "top_source_ips": self._top(records_by_ip, 10),
            "source_file": str(self.filepath),
            "records_total": len(self.records) + len(self.errors),
            "records_valid": len(self.records),
            "records_invalid": len(self.errors),
            "parse_errors": self.errors,
            "field_warnings": self.warnings,
            "field_counts": {
                field: sum(field in record for record in self.records)
                for field in KNOWN_FIELDS
            },
            "counts": {
                field: self._count(field)
                for field in KNOWN_FIELDS
                if field not in {"timestamp", "response_time", "source_ip"}
            },
            "time_range": {
                "first": min(timestamps) if timestamps else None,
                "last": max(timestamps) if timestamps else None,
            },
            "response_time": {
                "count": len(response_times),
                "minimum": min(response_times) if response_times else None,
                "maximum": max(response_times) if response_times else None,
                "average": sum(response_times) / len(response_times) if response_times else None,
            },
            "detection_signals": self._detection_signals(),
        }


# Reject negative limits while allowing zero as a valid request.
def nonnegative_int(value):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error

    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


# Keep all command-line options together so parsing is easy to inspect and test.
def build_parser():
    parser = argparse.ArgumentParser(description="Analyze a JSONL log file")
    parser.add_argument("--file", required=True, help="Path to a JSONL log file")
    parser.add_argument("--ip", help="Find total occurrences of a specific IP")
    parser.add_argument("--timestamp", help="Find total occurrences of a timestamp")
    parser.add_argument("--action", help="Find total occurrences of an HTTP action (e.g., GET, POST)")
    parser.add_argument("--status", type=int, help="Find total occurrences of a status code (e.g., 200, 404)")
    parser.add_argument("--topips", type=nonnegative_int, help="Show top N IP users")
    parser.add_argument("--allcodes", action="store_true", help="Show all status codes and their counts")
    parser.add_argument("--topcodes", type=nonnegative_int, help="Show top N status codes")
    parser.add_argument("--combo", nargs=3, metavar=("ACTION", "STATUS", "N"),
                        help="Show top N IPs with HTTP action and status code")
    return parser


# Run each requested query; multiple query options can be combined.
def run_queries(analyzer, args):
    if args.ip:
        print(f"Occurrences of IP {args.ip}: {analyzer.ip_occurrences(args.ip)}")
    if args.timestamp:
        print(f"Occurrences of timestamp {args.timestamp}: {analyzer.timestamp_occurrences(args.timestamp)}")
    if args.action:
        print(f"Occurrences of action {args.action}: {analyzer.http_action_occurrences(args.action)}")
    if args.status is not None:
        print(f"Occurrences of status {args.status}: {analyzer.status_code_occurrences(args.status)}")
    if args.topips is not None:
        print(f"Top {args.topips} IPs: {analyzer.top_n_ips(args.topips)}")
    if args.allcodes:
        print("All status codes:", analyzer.all_status_codes())
    if args.topcodes is not None:
        print(f"Top {args.topcodes} status codes: {analyzer.top_n_status_codes(args.topcodes)}")
    if args.combo is not None:
        action, raw_status, raw_limit = args.combo
        try:
            status = int(raw_status)
            limit = nonnegative_int(raw_limit)
        except (ValueError, argparse.ArgumentTypeError) as error:
            raise ValueError("--combo STATUS must be an integer and N must be zero or greater") from error
        print(f"Top {limit} IPs with action {action} and status {status}:")
        print(analyzer.top_n_ip_with_action_status(action, status, limit))


# The entry point connects parsing, analyzer construction, and query execution.
def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    analyzer = LogAnalyzer(args.file)

    try:
        run_queries(analyzer, args)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()