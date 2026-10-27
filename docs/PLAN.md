# LogDiver: Project Plan

A mini-SIEM (Security Information and Event Management) console application in C# / .NET 10.
It reads security-relevant logs, detects suspicious activity with configurable rules, and raises alerts
in a live dashboard. Everything runs locally, so no log data ever leaves the machine.

Solo project, ~80 hours. Focus: the application and the security detection logic.

---

## 1. Scope

### Must have (the graded core)
- Parse two log formats: **Linux SSH auth log** (`auth.log`) and **web server access log** (Apache/Nginx "combined" format).
- Read logs either as a one-off analysis of a file or by **live tailing** a file that is being written to.
- Detection engine with **5 rules**, thresholds configured in `rules.json`.
- Alerts shown in a live console dashboard and saved to a JSON Lines file.
- **Sample data generator** that writes realistic logs with hidden attacks, so anyone can run the demo without real servers.
- Unit tests for parsers, rules and the engine.

### Should have
- Summary report after `analyze`: alerts by severity, top attacking IPs, most targeted usernames and paths.
- IP allowlist in `rules.json` (e.g. your own monitoring server) so known-good sources never raise alerts.

### Could have (only if time is left)
- Windows Security Event Log source (requires admin rights).
- Avalonia GUI on top of the same core library.

### Out of scope
- AI / LLM integration (dropped from the original plan).
- Network capture, active scanning, or anything offensive. This is a defensive tool.

---

## 2. User experience

```
logdiver generate --out samples/ --minutes 60          # create demo logs with embedded attacks
logdiver analyze samples/auth.log samples/access.log   # batch analysis + summary report
logdiver watch samples/auth.log                        # live dashboard, Ctrl+C to stop
logdiver alerts                                        # list saved alerts
```

---

## 3. Architecture

### Solution layout
```
LogDiver.slnx
src/
  LogDiver.Core/          class library: domain, parsing, pipeline, rules, alerts
  LogDiver.Cli/           console app: commands, Spectre.Console dashboard, composition root
tests/
  LogDiver.Tests/         xUnit + NSubstitute + FakeTimeProvider
samples/                  small committed sample logs (generated, never real data)
```
All logic lives in `Core` so it can be tested without the console. `Cli` only wires things together and draws.

### Data flow
```
 ILogSource ──lines──▶ ILogParser ──LogEvent──▶ Channel<LogEvent> ──▶ DetectionEngine ──▶ AlertRaised (event)
 (file / tail)        (per format)              (bounded, async)       (runs IDetectionRule[])        │
                                                                                                       ├─▶ Dashboard
                                                                                                       ├─▶ AlertRepository (JSONL)
                                                                                                       └─▶ Statistics
```

### Key types (Core)

| Type | Responsibility |
|------|----------------|
| `record LogEvent` | Normalised event: timestamp, source, host, user, source IP, `EventKind` (LoginFailed, LoginSucceeded, HttpRequest, ...), status code, path, raw line. |
| `ILogSource` | `IAsyncEnumerable<string> ReadLinesAsync(CancellationToken)`. Implementations: `FileLogSource`, `TailingFileLogSource`. |
| `ILogParser` | `bool TryParse(ReadOnlySpan<char> line, out LogEvent? evt)`. Implementations: `SshAuthLogParser`, `WebAccessLogParser`. |
| `LogParserFactory` | Chooses the parser for a file (by option or by sniffing the first lines). |
| `IngestionPipeline` | Producers per source write into a bounded `Channel<LogEvent>`; one consumer feeds the engine. Handles cancellation and graceful shutdown. |
| `IDetectionRule` | **Strategy**: `Alert? Evaluate(LogEvent evt)`. Each rule keeps its own state. |
| `SlidingWindowCounter<TKey>` | Generic time-window counter (e.g. failed logins per IP in the last 60 s). Evicts old entries. |
| `DetectionEngine` | Runs all rules on each event, applies the allowlist, de-duplicates alerts, raises `event EventHandler<AlertRaisedEventArgs> AlertRaised`. |
| `record Alert` | Id, rule name, severity, time, summary, related IPs/users, sample of raw lines. |
| `IAlertRepository` | `JsonLinesAlertRepository`: append/read alerts as JSON Lines. |
| `AlertStatistics` | Subscribes to `AlertRaised` and builds the summary report (counts per severity, top IPs, users, paths). |

### Detection rules

| Rule | Detects | Default threshold |
|------|---------|-------------------|
| `BruteForceRule` | Many failed logins from one IP | 10 failures / 60 s |
| `PasswordSprayRule` | One IP trying many different usernames | 5 users / 5 min |
| `SuccessAfterFailuresRule` | A successful login right after a brute-force burst (likely compromise) | success within 5 min of a brute-force alert, same IP |
| `WebScannerRule` | Many 404s from one IP (directory/vulnerability scanning) | 30 × 404 / 60 s |
| `SuspiciousRequestRule` | Known attack patterns in URL or user agent: `../`, `UNION SELECT`, `<script>`, `/wp-admin`, `sqlmap`, `nikto` | any match |

---

## 4. Design pattern

**Primary pattern (individual assignment): Strategy.**
Each detection rule is a strategy behind `IDetectionRule`. The `DetectionEngine` doesn't know which rules exist, so new rules can be added without changing the engine (Open/Closed principle), and each rule can be tested on its own.

Patterns that also come up naturally (mention in the report, but Strategy is the one to document in depth):
- **Observer**: the `AlertRaised` C# event, with the dashboard, repository and statistics as subscribers.
- **Factory**: `LogParserFactory` picks the right parser.
- **Repository**: `IAlertRepository` hides how alerts are stored.

---

## 5. Requirement mapping

### Advanced C# concepts (each one solves a real problem)
| Concept | Where | Why it's there |
|---------|-------|----------------|
| Collections & generics | `SlidingWindowCounter<TKey>` (`Dictionary<TKey, Queue<DateTimeOffset>>`), `HashSet` for distinct users and the allowlist | O(1) lookup per IP; generic so it can count by IP, user or path |
| Async programming | `IAsyncEnumerable` log reading, `Channel<T>` pipeline, `CancellationToken` throughout | Reading files is I/O-bound; tailing runs until Ctrl+C |
| Multithreading | One producer task per log source running in parallel, one consumer | Several logs can be watched at the same time |
| Delegates, events, lambdas | `AlertRaised` event; LINQ in the summary report and rules | Decouples detection from presentation |
| Records & pattern matching | `LogEvent`, `Alert`; `switch` expressions on `EventKind` and severity | Immutable data, concise logic |
| Spans & `ref struct` | `SpanTokenizer` and both parsers work on `ReadOnlySpan<char>` slices of the line | Parsing allocates nothing until a field is kept |
| Source-generated regex | `[GeneratedRegex]` in `SuspiciousRequestRule` | Regex compiled at build time, no runtime cost |
| `TimeProvider` | Injected into rules | Lets tests control time (FakeTimeProvider) |

### Mindful memory usage
- Stream logs line by line with `IAsyncEnumerable`. Never `File.ReadAllLines` on a log that could be gigabytes.
- Parsers work on `ReadOnlySpan<char>` and only allocate strings for the fields that are kept.
- **Bounded** channel (e.g. capacity 10 000) so a fast producer can't fill memory; it waits instead (backpressure).
- Sliding windows evict old timestamps, and a cap on tracked keys prevents unbounded growth from many unique IPs.
- Alerts store at most N sample raw lines, not every matching line.
- `FileStream` and `StreamReader` are disposed (`using` / `await using`), and the pipeline implements `IAsyncDisposable`.
- Event subscribers unsubscribe (`-=`) in `Dispose`. This is the classic event-handler memory leak; mention it in the report.
- Verify with Rider's dotMemory or `dotnet-counters` during a long `watch` run, and include a screenshot in the report.

### Code quality (Nakov ch. 21)
- `Directory.Build.props`: nullable enabled, warnings as errors, recommended analyzers (already set up).
- Small classes with one responsibility, descriptive names, no magic numbers (thresholds come from config).
- Guard clauses with `ArgumentNullException.ThrowIfNull`, etc.
- Exceptions only for exceptional cases. Parsers use the `TryParse` pattern because a malformed log line is expected, not exceptional.

### Unit tests
- Parsers: `[Theory]` with valid lines, malformed lines and edge cases.
- Each rule: feed events using `FakeTimeProvider`, check that it fires exactly at the threshold and not one event before.
- `SlidingWindowCounter`: eviction and key cap.
- `DetectionEngine`: raises `AlertRaised`, de-duplicates, respects the allowlist.
- `AlertStatistics`: correct counts and top-N ordering.
- One end-to-end test: generated sample logs → `analyze` finds exactly the planted attacks.

### Security talking point: logs are untrusted input
Every log line can be written by an attacker (a username, a URL, a user agent). LogDiver treats it as hostile data:
parsers never throw on malformed input, long fields are truncated, and values are escaped before being shown in the
console (Spectre markup injection, e.g. a username like `[red]admin[/]`). Worth a paragraph in the report, since it
shows security awareness beyond the detection rules themselves.

---

## 6. Packages

| Package | Purpose |
|---------|---------|
| `Spectre.Console`, `Spectre.Console.Cli` | Commands, tables, live dashboard |
| `Microsoft.Extensions.TimeProvider.Testing` | `FakeTimeProvider` in tests |
| xUnit, NSubstitute | Tests (already set up) |

---

## 7. Work plan (~80 hours)

Ordered so there's a working, demonstrable product after phase 6. Memory review and documentation are part of phase 8,
because the README and memory requirements are graded.

| # | Phase | Deliverable | Hours |
|---|-------|-------------|------:|
| 1 | Setup | Rename skeleton to LogDiver, Core/Cli/Tests projects, packages, README skeleton, CI | 3 |
| 2 | Domain & parsers | `LogEvent`, `EventKind`, SSH and web parsers with span-based parsing, hostile-input handling + tests | 11 |
| 3 | Log sources | File reader and tailing reader with `IAsyncEnumerable`, cancellation, file rotation handling | 7 |
| 4 | Pipeline | Bounded channel, parallel producers, graceful shutdown, `IAsyncDisposable` + tests | 9 |
| 5 | Detection | `IDetectionRule`, `SlidingWindowCounter<TKey>`, 5 rules, `rules.json` with validation, allowlist, engine + tests | 19 |
| 6 | Alerts | `AlertRaised` event, de-duplication, JSON Lines repository, `AlertStatistics` + tests | 8 |
| 7 | Sample generator | `generate` command producing normal traffic with planted attacks (seeded `Random`), end-to-end test | 6 |
| 8 | CLI, dashboard & wrap-up | `analyze`, `watch`, `alerts` commands, Spectre live dashboard, summary report, memory/disposal audit with dotMemory, README and pattern write-up | 17 |
| | **Total** | | **80** |

**Milestones**
- **M1 (after phase 4):** `analyze` prints parsed events from both log types.
- **M2 (after phase 6):** detection works end to end. This is a submittable project already.
- **M3 (after phase 8):** full demo with generated data, live dashboard, documentation. Done.

Tip: keep a simple time log (date, phase, hours) in the repo or a spreadsheet. It's useful evidence for the 80-hour requirement.
