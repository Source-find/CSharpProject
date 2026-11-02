# LogDiver: Design and Project Plan

LogDiver is a small SIEM (Security Information and Event Management) console application in C# / .NET 10. It reads
security-relevant log files, detects suspicious activity with three detection rules, prints a report of the alerts
and saves them to a JSON Lines file. Everything runs locally, so no log data leaves the machine.

Solo project. This document describes the finished design, how each course requirement is met, and how the scope
changed during the project.

---

## 1. Scope

### Built
- Parsing of two log formats: **Linux SSH auth logs** and **Apache/Nginx access logs** ("common" and "combined").
- Automatic format detection per file.
- Streaming, parallel reading of several files at once.
- **Three detection rules**: brute force, web scanner and suspicious request.
- Merging of repeated alerts, alert statistics, and a console report with tables.
- Saving alerts to `alerts.jsonl`.
- Hand-made demo logs with planted attacks in `samples/`.
- Unit tests for each part, and a GitHub Actions build.

### Cut during the project (possible future work)
| Feature | Why it was cut |
|---------|----------------|
| Local AI (Ollama) that explains alerts | Scope: the project focuses on the application and security logic |
| Live mode (`watch`): following a log while it is written, with a live dashboard | Scope. A working, tested version exists in the Git history (phase 3 commit) |
| Two extra rules (password spraying, success after brute force) | Three rules are enough to show the design; the others are more of the same |
| `rules.json` with configurable thresholds and an IP allowlist | Scope. Thresholds are constructor parameters with defaults instead |
| A `generate` command for demo logs | Replaced by two hand-made sample logs |
| An `alerts` command that lists saved alerts | Scope. The repository can read alerts back, but the program doesn't use it yet |
| Handling of syslog's `message repeated N times` lines | Scope. Such lines are skipped |

### Out of scope
- Network capture, active scanning or anything offensive. LogDiver is a defensive tool.

---

## 2. Usage

```
dotnet run --project src/LogDiver.Cli -- samples/demo-auth.log samples/demo-access.log
```

Output: a table per file (lines, events, skipped), a table of alerts, statistics, and the path of `alerts.jsonl`.
The demo finds 4 alerts (5 before repeats are merged).

---

## 3. Architecture

### Solution layout
```
LogDiver.slnx
src/
  LogDiver.Core/     class library: all logic (events, sources, parsing, ingestion, detection, storage)
  LogDiver.Cli/      console app: reads the arguments, wires everything together, prints the results
tests/
  LogDiver.Tests/    xUnit tests
samples/             demo logs with planted attacks
```
All logic lives in `Core`, so it can be tested without the console.

### Data flow
```
log files → FileLogSource → ILogParser → IngestionPipeline → DetectionEngine → AlertRaised event
           (read lines)    (line →      (one task per file,  (runs every       ├─▶ AlertDeduplicator → table + alerts.jsonl
                           LogEvent)     bounded channel,     IDetectionRule)   └─▶ AlertStatistics   → summary
                                         one consumer)
```

### Key types
| Type | Responsibility |
|------|----------------|
| `LogEvent` (record) | One normalised event: time, kind, IP, user, and for web requests method, path, status code and user agent |
| `ILogSource` / `FileLogSource` | Streams the lines of a file with `IAsyncEnumerable<string>` |
| `BoundedLineReader` | Splits text into lines with a 16 KB limit per line, using a pooled buffer |
| `ILogParser` / `SshAuthLogParser` / `WebAccessLogParser` | `TryParse` one line into a `LogEvent`; never throws on bad input |
| `SpanTokenizer` (ref struct) | Splits a line into fields without copying it |
| `InputSanitizer` | Shortens attacker-controlled text and replaces dangerous characters |
| `LogParserFactory` | Creates the right parser and detects the format of a file |
| `IngestionPipeline` | One producer task per file, a bounded `Channel<LogEvent>`, one consumer |
| `IDetectionRule` + `BruteForceRule`, `WebScannerRule`, `SuspiciousRequestRule` | The detection rules (Strategy pattern) |
| `SlidingWindowCounter<TKey>` | Counts events per key within a moving time window, and forgets quiet keys |
| `DetectionEngine` | Runs every rule on each event and raises `AlertRaised` |
| `Alert` (record) | One finding: rule, severity, time, IP, description, occurrences, last seen |
| `AlertDeduplicator` | Merges repeats of the same rule and IP within 10 minutes |
| `AlertStatistics` | Counts alerts per severity and per source IP |
| `JsonLinesAlertRepository` | Saves alerts to and reads them from a JSON Lines file |

### Detection rules
| Rule | Detects | Default threshold | Severity |
|------|---------|-------------------|----------|
| `BruteForceRule` | Many failed logins from one IP | 10 within 60 s | High |
| `WebScannerRule` | Many 404 Not Found from one IP | 30 within 60 s | Medium |
| `SuspiciousRequestRule` | Path traversal, SQL injection, cross-site scripting, probes for sensitive files, attack tools in the user agent | Any single match | High (attack tool: Medium) |

Time always comes from the log, not the clock: "60 seconds" means 60 seconds in the log.

---

## 4. Design patterns

### Strategy (main pattern)
Each detection rule is its own class behind the `IDetectionRule` interface:
```csharp
public interface IDetectionRule
{
    string Name { get; }
    Alert? Evaluate(LogEvent logEvent);   // an alert, or null
}
```
`DetectionEngine` only holds a list of rules and asks each of them about every event. It doesn't know how any rule
works.

**Before and after.** The first version (phase 5 commit) had all three detections in one long `Process` method. That
version broke the Single Responsibility and Open/Closed principles, duplicated the "count per IP in a time window"
code, could only be tested as a whole, and never forgot IPs that had gone quiet. The refactored version:
- has one small class per rule, and an engine of a few lines,
- lets a new rule be added without changing the engine (Open/Closed),
- shares the counting code in the generic `SlidingWindowCounter<TKey>`, which also forgets quiet IPs,
- lets each rule be tested on its own, with small thresholds (for example 3 instead of 10).

The engine tests were not changed by the refactoring; they still pass, which shows the behaviour stayed the same.

### Observer
The engine raises `AlertRaised` for every alert. `AlertDeduplicator` and `AlertStatistics` subscribe (`+=`) in their
constructor and unsubscribe (`-=`) in `Dispose`, and `Program` uses them with `using`. They depend on the small
`IAlertPublisher` interface, not on the engine itself.

### Also used
- **Factory**: `LogParserFactory` creates the right parser, so the rest of the code never creates parsers itself.
- **Producer/consumer** (a concurrency pattern): `IngestionPipeline`.

---

## 5. Requirement mapping

### Supported .NET version
.NET 10 (LTS, supported until November 2028), pinned in `global.json`.

### Advanced C# concepts
| Concept | Where | Why |
|---------|-------|-----|
| Collections & generics | `SlidingWindowCounter<TKey>` (`Dictionary<TKey, Queue<DateTimeOffset>>`), tuple-keyed `Dictionary` in `AlertDeduplicator`, generic `Increment<TKey>` in `AlertStatistics` | O(1) lookup per IP; one counter class for every rule |
| Asynchronous programming | `IAsyncEnumerable` + `yield return` + `await foreach`, `CancellationToken`, `await using`, `ValueTask`, async LINQ (`Take`/`ToListAsync`) | Reading files is I/O-bound; Ctrl+C stops a run cleanly |
| Multithreading | `Task.Run` per file, bounded `Channel<T>`, one consumer, linked `CancellationTokenSource` | Files are read in parallel while the rules run on one thread, so they need no locks |
| Delegates, events, lambdas | `Action<LogEvent>`, `AlertRaised` event, `Console.CancelKeyPress`, LINQ | Decouples detection from what happens with the alerts |
| Records & pattern matching | `LogEvent`, `Alert` (with `with`), `IpAlertCount`; `is { } x`, `switch` expressions, relational patterns | Immutable data, short and clear checks |
| Spans & `ref struct` | `SpanTokenizer`, both parsers, `InputSanitizer` (`stackalloc`) | Parsing creates no temporary strings |
| Source generators | `[GeneratedRegex]` in `SuspiciousRequestRule`, `JsonSerializerContext` for alerts | Regex and JSON code is generated at build time |

### Mindful memory usage
- Logs are streamed line by line with `IAsyncEnumerable`, never loaded whole.
- `BoundedLineReader` caps each line at 16 KB and rents its buffer from `ArrayPool<char>`, returning it in `Dispose`.
- Parsers work on `ReadOnlySpan<char>` and only create strings for fields that are kept.
- `FileStream`'s own buffer is turned off, because `StreamReader` already buffers.
- The bounded channel (10 000 events) makes fast producers wait instead of filling memory (backpressure).
- `SlidingWindowCounter` and `AlertDeduplicator` forget keys whose time window has passed.
- The engine only creates a list when a rule actually finds something.
- Files and streams are closed with `using` / `await using`; event handlers are removed with `-=` (in `Dispose` and in
  a `finally` block for `Console.CancelKeyPress`).

### Code quality (Nakov chapter 21)
- `Directory.Build.props`: nullable reference types, warnings treated as errors, recommended .NET analyzers.
- `.editorconfig` with naming rules (`_camelCase` fields, `I` prefix for interfaces, PascalCase constants).
- Small classes with one responsibility, descriptive names, named constants instead of magic numbers.
- Guard clauses (`ArgumentNullException.ThrowIfNull` and similar).
- Exceptions only for exceptional cases: parsers use the `TryParse` pattern, because broken log lines are expected.
- Central package versions (`Directory.Packages.props`) and a GitHub Actions build on every push.

### Unit tests
15 xUnit test methods, at least one per part of the program:
| Area | What is tested |
|------|----------------|
| Parsing | SSH failed login; a fake "from <IP>" inside the username doesn't change the source IP; web combined format |
| Sources | Every line is read in order; a huge line without a line break is cut at the limit |
| Ingestion | Several files deliver every event, in order per file; the handler never runs on two threads at once; a crashing handler stops the run instead of hanging it |
| Detection rules | Brute-force and web-scanner rules alert exactly at their threshold and ignore events that don't count |
| Detection engine | All three rules through the engine; unsubscribing from `AlertRaised` works |
| Storage | An alert with hostile text stays on one line in the file and comes back unchanged |

### README
`README.md` explains how to build, run and test the project, and describes features, design and limitations.

---

## 6. Security: logs are untrusted input

Every log line can be written by an attacker (a username, a URL, a user agent). LogDiver treats it as hostile data:
- **Log injection:** a username like `x from 6.6.6.6 port 1` can't fake the source IP; the parser uses the *last*
  "from" in the line.
- **Terminal manipulation:** ANSI escape codes and Unicode bidi overrides are replaced by `InputSanitizer`.
- **Output injection:** text from logs is escaped before it is shown in Spectre.Console tables, and JSON escaping
  keeps hostile text from breaking `alerts.jsonl` or adding fake alerts.
- **Denial of service:** lines are limited to 16 KB, and the regex patterns avoid nested repetition (ReDoS).
- **Robustness:** parsers never throw on malformed input.

---

## 7. Packages

| Package | Purpose |
|---------|---------|
| `Spectre.Console` | Tables and colours in the console |
| `Microsoft.Extensions.TimeProvider.Testing` | `FakeTimeProvider` in the SSH parser test |
| xUnit | Tests |

---

## 8. Phases

| # | Phase | Result |
|---|-------|--------|
| 1 | Setup | .NET 10 solution with Core/Cli/Tests projects, shared build settings, CI |
| 2 | Domain & parsers | `LogEvent`, SSH and web parsers with span-based parsing and input sanitising |
| 3 | Log sources | Streaming file reader with a line-length limit, format detection (live tailing built, then cut) |
| 4 | Pipeline | Parallel producers, bounded channel, one consumer, cancellation |
| 5 | Detection | Three rules, first in one class, later refactored to the Strategy pattern |
| 6 | Alerts | `AlertRaised` event, de-duplication, statistics, JSON Lines storage |
| 7 | Demo & wrap-up | Demo logs, Rider run configuration, trimmed tests, documentation |

Keep a time log (date, phase, hours) next to this plan as evidence for the roughly 80 hours of work.
