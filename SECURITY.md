# Security policy

## Intended use

LogSentinel is a defensive educational project for local analysis of synthetic
or properly de-identified authentication events. Use it only with data you are
authorized to handle.

## Privacy boundary

- Files are read by browser `FileReader` and are not uploaded by this project.
- No external resources, analytics, cookies, or reputation services are used.
- Processing is in memory; refreshing the page clears the current report.
- Export is an explicit local download containing incident evidence.

Do not put production logs, credentials, tokens, student identifiers, private
IP inventories, or regulated data into a hosted public demo. Local browser
extensions, operating-system software, and a modified build remain outside this
project's control.

## Detection limitations

The rules are transparent heuristics. False positives and false negatives are
expected. Input country labels are not validated, time zones are treated as UTC,
and source IP equality does not establish identity. The tool performs no threat
intelligence lookup, malware detection, account action, or network monitoring.

## Reporting a vulnerability

Open a GitHub security advisory with a minimal synthetic reproduction. Do not
include real logs, secrets, personal data, or active malicious infrastructure.
