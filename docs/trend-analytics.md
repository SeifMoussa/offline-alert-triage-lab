# Trend Analytics

The trend analytics module aggregates local triage report runs over time. It is
read-only: it does not run its own detection logic and does not add a database
or background service. It reads report files the existing `report` command
already writes.

## How Local Run History Works

There is no new persistence mechanism. The existing `report` command already
writes a fixed pair of filenames into whatever `--output` directory it is
given. Trend analytics builds on that by expecting one local directory per
run:

```text
history/
  2026-06-01/
    security_alert_triage_report.json
    triage_outcomes.json        (optional)
  2026-06-08/
    security_alert_triage_report.json
```

To build history, run `report` into a new dated directory for each triage
run, for example:

```bash
python -m triage_lab report --input alerts/sample_alerts.json --output history/2026-06-01 --format json
python -m triage_lab report --input alerts/sample_alerts.json --output history/2026-06-08 --format json
```

Then aggregate across all of them:

```bash
python -m triage_lab trend-report --history-dir history --format json
```

Run subdirectories are read in sorted directory-name order, and the trend
series themselves are ordered by each run's `generated_at` timestamp. A run
directory without a `security_alert_triage_report.json` file, or with one that
is not valid JSON or is missing required summary fields, is skipped and
recorded as a structured error rather than failing the whole trend report.

## False-Positive Rate

Nothing else in this project tracks whether a triage decision was a true or
false positive, so trend analytics does not assume one. False-positive rate is
only computed for a run that has an optional local `triage_outcomes.json` file
next to its report:

```json
{
  "alerts": {
    "alert-0001": "true_positive",
    "alert-0002": "false_positive",
    "alert-0003": "unreviewed"
  }
}
```

This file is meant to be hand-authored by an analyst after reviewing a run's
output, the same way `alerts/sample_alerts.json` is a hand-authored local
fixture. Supported dispositions are `true_positive`, `false_positive`, and
`unreviewed`. The false-positive rate for a run is
`false_positive_count / (true_positive_count + false_positive_count)`;
`unreviewed` alerts are excluded from that denominator. A run without an
outcomes file, or where every alert is still `unreviewed`, reports a `null`
false-positive rate instead of assuming zero false positives.

An invalid `triage_outcomes.json` file (bad JSON, an unsupported disposition
value, non-string alert IDs) does not fail the run; the run's report data is
still used, the outcomes file is treated as unavailable, and a structured
error is recorded.

## Trend Report Output

`trend-report` produces:

- `alert_volume_trend`: alerts loaded per run, ordered by time.
- `top_mitre_techniques`: MITRE technique IDs ranked by how many runs they
  appeared in.
- `false_positive_rate_trend`: false-positive rate per run, with
  `outcomes_available` so a missing-data run is distinguishable from a
  zero-false-positive run.
- `average_false_positive_rate`: averaged only over runs that have a
  computable rate.
- `errors`: structured errors for any run directory that could not be loaded.

## Safety

Trend analytics only reads local files under the given `--history-dir` and
rejects URLs, network paths, and parent-directory traversal for that path, the
same as every other local input path in this project. It performs no network
calls, no external AI or LLM calls, and no external enrichment. Because its
input is the already-redacted `report` output, trend output contains no raw
messages, raw source or destination IPs, raw usernames, or approved fake
sensitive marker constants, and CLI output is routed through the same final
redaction serializer as every other command.
