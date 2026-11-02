# LogDiver

LogDiver is a small SIEM (Security Information and Event Management) tool for the console. It reads security-relevant
logs (SSH auth logs and web server access logs), detects suspicious activity such as brute-force logins, web scanning
and known attack patterns, and prints a report of the alerts. Everything runs locally, so no log data leaves the machine.

More detail on the design and how the course requirements are met: [docs/PLAN.md](docs/PLAN.md).

## Features

- Reads Linux SSH auth logs (`auth.log`) and Apache/Nginx access logs. The format of each file is detected automatically.
- Reads several files in parallel, streaming them line by line, so even very large logs use little memory.
- Three detection rules:

  | Rule | Detects | Default threshold | Severity |
  |------|---------|-------------------|----------|
  | `BruteForce` | Many failed SSH logins from one IP | 10 within 60 seconds | High |
  | `WebScanner` | Many "404 Not Found" from one IP | 30 within 60 seconds | Medium |
  | `SuspiciousRequest` | Path traversal, SQL injection, cross-site scripting, probes for `.env`/`.git`/`wp-admin`, attack tools such as `sqlmap` | Any single match | High (attack tool: Medium) |

- Merges repeated alerts: the same rule and IP within 10 minutes become one alert with a count.
- Shows a summary per file, a table of alerts and statistics (alerts per severity, top source IPs).
- Saves the alerts to `alerts.jsonl` (JSON Lines: one alert per line).
- Treats every log line as untrusted input: hostile text can't crash the parser, fake its source IP, mess up the
  terminal or break the alerts file.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (10.0.100 or newer, pinned in `global.json`)
- Optional: JetBrains Rider 2025.3+ or Visual Studio 2026

Check the installed SDK with:

```bash
dotnet --version
```

## Build

```bash
dotnet build
```

## Run

Pass one or more log files from the solution folder:

```bash
dotnet run --project src/LogDiver.Cli -- path/to/auth.log path/to/access.log
```

Try it with the demo logs in `samples/`, which contain planted attacks:

```bash
dotnet run --project src/LogDiver.Cli -- samples/demo-auth.log samples/demo-access.log
```

In Rider, choose the run configuration **LogDiver (completed demo build)** and press Run. It does the same.

The demo finds 4 alerts (5 before repeats are merged): a brute-force attack, a web scanner, SQL injection plus path
traversal from one IP, and a probe for `/.env`. The alerts are also added to `alerts.jsonl` in the current folder,
shown in Rider under **output**. Press Ctrl+C to stop a long analysis.

## Test

```bash
dotnet test
```

## How it works

```
log files → FileLogSource → parser → IngestionPipeline → DetectionEngine → AlertRaised event
           (read lines)    (line →   (one task per file,  (runs every       ├─▶ AlertDeduplicator → table + alerts.jsonl
                           LogEvent)  bounded channel,     IDetectionRule)   └─▶ AlertStatistics   → summary
                                      one consumer)
```

## Design patterns

- **Strategy (main pattern):** every detection rule is its own class behind the `IDetectionRule` interface
  (`BruteForceRule`, `WebScannerRule`, `SuspiciousRequestRule`). The `DetectionEngine` only loops over its rules and
  doesn't know how any of them work, so rules can be added, removed and tested one at a time without changing the engine.
- **Observer:** the engine announces alerts through the `AlertRaised` event. `AlertDeduplicator` and `AlertStatistics`
  subscribe in their constructor and unsubscribe in `Dispose`.
- Also used: **Factory** (`LogParserFactory` picks the right parser) and **Repository** (`IAlertRepository` hides how
  alerts are stored).

## Technologies used

- C# 14 / .NET 10
- [Spectre.Console](https://spectreconsole.net/) for the tables in the console
- `System.Threading.Channels`, `System.Text.Json` (source-generated) and `[GeneratedRegex]` from .NET
- xUnit and `Microsoft.Extensions.TimeProvider.Testing` for the tests
- GitHub Actions to build and test on every push

## Project structure

| Path | Purpose |
|------|---------|
| `src/LogDiver.Core/Events` | `LogEvent`: the common shape every log line is turned into |
| `src/LogDiver.Core/Sources` | Reading log files line by line, with a line-length limit |
| `src/LogDiver.Core/Parsing` | SSH and web log parsers, input sanitising, format detection |
| `src/LogDiver.Core/Ingestion` | The parallel pipeline: one producer per file, one consumer |
| `src/LogDiver.Core/Detection` | Detection engine, rules (`Rules/`), sliding-window counter, alerts, de-duplication, statistics |
| `src/LogDiver.Core/Storage` | Saving alerts to a JSON Lines file |
| `src/LogDiver.Cli` | The console program (`logdiver`): reads the arguments, runs everything and prints the results |
| `tests/LogDiver.Tests` | xUnit tests for each part |
| `samples/` | Demo logs with planted attacks (made up, using documentation-only IP addresses) |
| `docs/PLAN.md` | Design, scope and how the course requirements are met |
| `Directory.Build.props` | Shared build settings: .NET 10, nullable reference types, warnings as errors, analyzers |
| `Directory.Packages.props` | Central NuGet package versions |
| `.github/workflows/ci.yml` | Builds and tests on every push to GitHub |

## Known limitations

- Only SSH auth logs and Apache/Nginx access logs are supported.
- Thresholds are set in code, not in a configuration file.
- Syslog lines of the form `message repeated N times` are skipped.
- A live mode that follows a log while it is being written was built and later cut to reduce scope; it is in the Git
  history (phase 3).

## AI usage

This project was built by me with help from Claude (AI). AI was used to help plan the project, write and explain code,
generate some of the tests and restructure this README. All code has been reviewed, built and run by me.
