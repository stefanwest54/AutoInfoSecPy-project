##
Author: Stefan West
Date: 09/28/2026
LogAnalyzer Ver: 1.0
LogCrawler Ver: 1.0

# Log Crawler

A small, scheduled batch tool for analyzing JSON Lines (JSONL) web request logs. Place exported logs in `Logs/new_logs`; the crawler analyzes each eligible file, writes a readable text report to `Reports`, and moves successfully processed logs to `Logs/old_logs`.

## Workflow

1. Export or convert IDS, firewall, or web-server events into JSONL files in `Logs/new_logs`. Write one JSON object per line and finish writing each file before the scheduled run starts.
2. Name files `log_<number>.jsonl`, for example `log_6.jsonl`. The crawler scans files beginning with `log_` and ending with `.jsonl`; numbered names are processed in numeric order.
3. Run the crawler with `/NewLogs`. Each log is analyzed and a report named `log_<number>_report.txt` is written to `Reports`.
4. After a successful analysis and report write, the input file is moved to `Logs/old_logs`. If that archive filename already exists, the archived copy receives a `_dupe_rename_<number>` suffix.

The crawler runs only when invoked; it does not continuously watch the input directory or connect directly to an IDS/firewall. The log source must deliver files in the expected JSONL format.

## Project Layout

```text
Log Crawler/
|-- Logs/
|   |-- new_logs/    # Pending JSONL input
|   `-- old_logs/    # Processed input archive
|-- Main/
|   |-- LogAnalyzer_v2.py
|   `-- LogCrawler_v2.py
|-- Reports/         # Generated text reports
`-- README.md
```

The crawler derives these locations from the project directory, so it does not depend on the shell's current working directory.

## Requirements

- Python 3
- No third-party packages; the scripts use the Python standard library.

## Run the Crawler

From PowerShell:

```powershell
cd "C:\Log Crawler"
py .\Main\LogCrawler_v2.py /NewLogs
```

Use `/Report` to print the saved reports in the terminal, or `/Help` to print the command summary:

```powershell
py .\Main\LogCrawler_v2.py /Report
py .\Main\LogCrawler_v2.py /Help
```

If `py` is not available, use `python` in its place. Running `/NewLogs` moves successfully processed files out of `new_logs`.

## Schedule a Batch Run

In Windows Task Scheduler, create a task with an action that runs the installed Python executable and passes these arguments:

```text
"C:\Log Crawler\Main\LogCrawler_v2.py" /NewLogs
```

Set the task's **Start in** directory to `C:\Log Crawler` if desired. The paths are script-relative, but setting the project directory can make task configuration and logs easier to understand. Choose a schedule that allows the log source to finish writing its files before the task starts.

## Expected Log Format

Each nonblank line must contain one JSON object. The analyzer recognizes these fields:

| Field | Description |
|---|---|
| `timestamp` | Event timestamp, preferably normalized ISO 8601 |
| `source_ip` | Client or source IP address |
| `user_agent` | Request user-agent string |
| `endpoint` | Requested path or endpoint |
| `method` | HTTP method |
| `status_code` | HTTP response status |
| `username` | Associated username, when available |
| `response_time` | Response time in milliseconds |
| `request_count_per_second` | Optional supplied rate used by one detection signal |

The first eight fields are checked for omissions. Missing fields generate warnings, but the record is still analyzed. Malformed JSON lines and JSON values that are not objects are counted as parse errors; other valid records in the file are still analyzed.

Example:

```json
{"timestamp":"2026-09-17T09:00:00Z","source_ip":"203.0.113.83","user_agent":"Chrome/128","endpoint":"/profile","method":"GET","status_code":200,"username":"emma","response_time":44}
```

## Reports and Detection Signals

Reports include record totals, time range, response-time summary, top source IPs, counts for common request fields, parse errors, missing-field warnings, and detection signals.

The current analyzer can flag:

- A source IP responsible for at least half of valid records, with a minimum of 20 records.
- An input-reported `request_count_per_second` of at least 100. This value is read from the log; the analyzer does not calculate request rates from timestamps.

These are simple indicators for investigation, not a substitute for a production IDS or security review.

Reports use the input log number in their filename. Use a unique number for each log if you need to retain every report; processing another `log_<number>.jsonl` will overwrite an existing report with the same report filename.

## Analyze a Single File

`LogAnalyzer_v2.py` can also be run independently. This analyzes and prints selected query results; it does not archive the file or generate the crawler's text report.

```powershell
py .\Main\LogAnalyzer_v2.py --file .\Logs\new_logs\log_1.jsonl --topips 10 --allcodes
```

Additional query options include `--ip`, `--timestamp`, `--action`, `--status`, `--topcodes`, and `--combo ACTION STATUS N`. Run the script with `--help` to see their arguments.
