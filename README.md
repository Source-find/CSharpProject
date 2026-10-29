# LogDiver

LogDiver is a tiny SIEM(Security Information and Event Manager) for the console. It reads security-relevant logs (SSH auth logs and web server
access logs), detects suspicious activity such as brute-force logins, web scanning and known attack patterns,
and prints a report of the alerts. Everything runs locally, so no log data leaves the machine.

> Status: in development. See [docs/PLAN.md](docs/PLAN.md) for the full plan.

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

```bash
dotnet run --project src/LogDiver.Cli
```

## Test

```bash
dotnet test
```
## Technologies used

## Project structure

| Path | Purpose |
|------|---------|
| `src/LogDiver.Core` | Class library: log parsing, ingestion pipeline, detection rules, alerts |
| `src/LogDiver.Cli` | Console application (`logdiver`): commands and result tables |
| `tests/LogDiver.Tests` | xUnit tests, with NSubstitute and `FakeTimeProvider` |
| `docs/PLAN.md` | Project plan, architecture and requirement mapping |
| `Directory.Build.props` | Shared build settings: .NET 10, nullable reference types, warnings as errors, analyzers |
| `Directory.Packages.props` | Central NuGet package versions |
| `.github/workflows/ci.yml` | Builds and tests on every push to GitHub |


ReadMe restructured by AI
