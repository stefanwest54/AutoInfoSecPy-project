# AutoInfoSecPy-project

A collection of Python scripting and information security projects. This repository began as a final project for IT 170, Scripting Languages and Automation, completed in December 2024. It now also includes a batch log-analysis tool.

## Projects

### LogCrawler

`LogCrawler` analyzes JSON Lines (JSONL) web request logs exported or converted from IDS, firewall, or web-server sources. It summarizes request data, reports parse and missing-field issues, records simple detection signals, archives successfully processed input, and writes readable text reports.

The crawler is a scheduled batch tool. It does not connect directly to security devices or monitor a directory continuously. See [`LogCrawler/README.md`](LogCrawler/README.md) for setup, input format, report details, and Task Scheduler instructions.

## Repository Layout

```text
AutoInfoSecPy-project/
|-- README.md
|-- LICENSE
`-- LogCrawler/
    |-- README.md
    |-- Main/
    |   |-- LogAnalyzer_v1.py
    |   `-- LogCrawler_v1.py
    `-- Logs/
        `-- new_logs/          # Sanitized sample logs; operational logs should stay local
```

The crawler creates `LogCrawler/Logs/old_logs` and `LogCrawler/Reports` as needed when it runs.

## Run LogCrawler

Requirements: Python 3. No third-party packages are required.

From PowerShell at the repository root:

```powershell
py .\LogCrawler\Main\LogCrawler_v1.py /NewLogs
```

This processes eligible `log_*.jsonl` files from `LogCrawler/Logs/new_logs`. Successful files are moved to `LogCrawler/Logs/old_logs`, and reports are written to `LogCrawler/Reports`. Use `/Report` to print saved reports:

```powershell
py .\LogCrawler\Main\LogCrawler_v1.py /Report
```

Running `/NewLogs` moves successfully processed files out of the input folder. Use only sanitized sample logs in this public repository; do not commit logs containing real IP addresses, usernames, tokens, or other sensitive data.

## Detection Scope

Current signals are intentionally basic indicators for further investigation:

- One source IP accounts for at least half of valid records, with a minimum of 20 records.
- An input-provided `request_count_per_second` value is at least 100. The analyzer does not calculate request rates from timestamps.

These heuristics are not a replacement for a production IDS, incident-response process, or security review.

## License

This project is distributed under the MIT License. See [`LICENSE`](LICENSE).
