## Stefan West || init 9/28/2026 || LogCrawler v2.0 ##
## Processes pending JSONL logs, saves readable reports, and archives completed files. ##
## Log 1: baseline; Log 2: ddos; Log 3: idor; Log 4: password spraying; Log 5: mixed ##

import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from LogAnalyzer_v2 import LogAnalyzer


# Anchor runtime folders to the workspace so scheduled runs work from any current directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "Logs"
NEW_LOGS_DIR = LOGS_DIR / "new_logs"
OLD_LOGS_DIR = LOGS_DIR / "old_logs"
REPORTS_DIR = PROJECT_ROOT / "Reports"


# Create the runtime folders on demand so a fresh data directory is ready to use.
def ensure_directories():
    for directory in (NEW_LOGS_DIR, OLD_LOGS_DIR, REPORTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# Keep unrelated filenames out and process numbered logs predictably.
def get_log_files():
    if not NEW_LOGS_DIR.exists():
        return []

    files = [
        path for path in NEW_LOGS_DIR.iterdir()
        if path.is_file() and path.name.startswith("log_") and path.suffix == ".jsonl"
    ]
    return sorted(files, key=lambda p: extract_log_number(p.name))


# Invalid or non-numbered names sort after valid numbered logs.
def extract_log_number(filename):
    parts = Path(filename).stem.split("_")
    try:
        if parts[0] != "log":
            return 10**9
        return int(parts[1])
    except (ValueError, IndexError):
        return 10**9


# Avoid overwriting an archived log when its name is already taken.
def unique_destination(target_dir, original_name):
    destination = target_dir / original_name
    if not destination.exists():
        return destination

    base = Path(original_name).stem
    suffix = Path(original_name).suffix
    counter = 1
    while True:
        renamed = target_dir / f"{base}_dupe_rename_{counter}{suffix}"
        if not renamed.exists():
            return renamed
        counter += 1


# Add workflow metadata to the analyzer's facts before formatting the report.
def analyze_one(file_path):
    analyzer = LogAnalyzer(str(file_path))
    report = analyzer.report()
    report["source_log"] = file_path.name
    report["archive_name"] = file_path.name
    report["processed_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["analyzer_version"] = "loganalyzer_v1"
    return report


# Turn analyzer results into a compact, human-readable text report.
def _format_count_section(title, counts, limit=10):
    lines = [f"{title}:"]
    if not counts:
        return lines + ["  None"]

    # Use count first, then the label, so ties are displayed consistently.
    ranked_counts = sorted(
        counts.items(), key=lambda item: (-item[1], str(item[0]))
    )
    for value, count in ranked_counts[:limit]:
        lines.append(f"  {value}: {count}")
    if len(ranked_counts) > limit:
        lines.append(f"  ... {len(ranked_counts) - limit} more")
    return lines


def format_report(report):
    # Show provenance first, followed by the quickest-to-scan finding.
    lines = [
        f"Input file: {report.get('source_file', 'unknown')}",
        f"Archived file: {report.get('archive_file', 'unknown')}",
        f"Processed at (UTC): {report.get('processed_at_utc', 'unknown')}",
        f"Analyzer version: {report.get('analyzer_version', 'unknown')}",
        "",
        "Top Source IPs:",
    ]
    top_source_ips = report.get("top_source_ips", [])
    if top_source_ips:
        lines.extend(
            f"  {source_ip}: {request_count} requests"
            for source_ip, request_count in top_source_ips
        )
    else:
        lines.append("  None")

    time_range = report.get("time_range", {})
    response_time = report.get("response_time", {})
    lines.extend([
        "",
        "Record summary:",
        f"  Total: {report.get('records_total', 0)}",
        f"  Valid: {report.get('records_valid', 0)}",
        f"  Invalid: {report.get('records_invalid', 0)}",
        f"  Time range: {time_range.get('first')} to {time_range.get('last')}",
        f"  Response time (ms): min {response_time.get('minimum')}, "
        f"max {response_time.get('maximum')}, average {response_time.get('average')}",
        "",
        "Counts (top 10 per field):",
    ])

    for field in ("method", "status_code", "endpoint", "username", "user_agent"):
        lines.extend(_format_count_section(field.replace("_", " ").title(), report.get("counts", {}).get(field, {})))

    lines.extend(["", "Detection signals:"])
    detection_signals = report.get("detection_signals", [])
    if detection_signals:
        for signal in detection_signals:
            lines.append(f"  - {signal.get('type', 'signal')}")
            for key, value in signal.items():
                if key not in {"type", "basis"}:
                    lines.append(f"      {key.replace('_', ' ')}: {value}")
            if signal.get("basis"):
                lines.append(f"      Basis: {signal['basis']}")
    else:
        lines.append("  None")

    parse_errors = report.get("parse_errors", [])
    lines.extend(["", f"Parse errors: {len(parse_errors)}"])
    # Keep large error lists readable while retaining the complete count.
    for error in parse_errors[:10]:
        lines.append(f"  Line {error.get('line')}: {error.get('error')}")
    if len(parse_errors) > 10:
        lines.append(f"  ... {len(parse_errors) - 10} more")

    # Summarize repeated missing-field warnings instead of repeating every line.
    warning_counts = Counter(
        field
        for warning in report.get("field_warnings", [])
        for field in warning.get("fields", [])
    )
    lines.append("Missing-field warnings:")
    if warning_counts:
        lines.extend(
            f"  {field}: {count} records"
            for field, count in sorted(warning_counts.items())
        )
    else:
        lines.append("  None")

    return "\n".join(lines) + "\n"


def save_report(report, log_number):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"log_{log_number}_report.txt"
    # Text output is intended for direct reading, not machine round-tripping.
    report_path.write_text(format_report(report), encoding="utf-8")
    return report_path


# Save the report before archiving each successfully analyzed input file.
def process_new_logs():
    ensure_directories()
    results = []
    for file_path in get_log_files():
        log_number = extract_log_number(file_path.name)
        try:
            # Pick the final archive name first so the report records the actual destination.
            archive_path = OLD_LOGS_DIR / file_path.name
            if archive_path.exists():
                archive_path = unique_destination(OLD_LOGS_DIR, file_path.name)

            report = analyze_one(file_path)
            report["archive_name"] = archive_path.name
            report["archive_file"] = str(archive_path)
            # Preserve the report before moving the source file.
            save_report(report, log_number)
            file_path.replace(archive_path)
            results.append({"status": "success", "file": file_path.name, "report": f"log_{log_number}_report.txt"})
        except Exception as exc:
            # A problem with one file should not prevent the remaining files from processing.
            results.append({"status": "failed", "file": file_path.name, "error": str(exc)})

    for result in results:
        if result["status"] == "success":
            print(f"OK: {result['file']} -> {result['report']}")
        else:
            print(f"FAIL: {result['file']} - {result['error']}")

    return results


# Display saved reports without reopening or reanalyzing archived logs.
def show_report():
    ensure_directories()
    reports = sorted(REPORTS_DIR.glob("log_*_report.txt"), key=lambda p: extract_log_number(p.name))
    if not reports:
        print("No saved reports found.")
        return

    for report_path in reports:
        print(f"Report: {report_path.name}")
        print(report_path.read_text(encoding="utf-8").rstrip())
        print()


# CLI arguments are parsed here; workflow helpers above remain independently callable.
def main():
    parser = argparse.ArgumentParser(description="Log crawler workflow coordinator")
    parser.add_argument("command", nargs="?", choices=["/NewLogs", "/Report", "/Help"], default="/Help")
    args = parser.parse_args()

    if args.command == "/NewLogs":
        process_new_logs()
        return

    if args.command == "/Report":
        show_report()
        return

    print("Usage:")
    print("  python LogCrawler.py /NewLogs")
    print("  python LogCrawler.py /Report")
    print("  python LogCrawler.py /Help")


if __name__ == "__main__":
    main()
