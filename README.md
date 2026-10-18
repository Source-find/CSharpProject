# LogSentinel

LogSentinel is a mini-SIEM for the console. It reads security-relevant logs (SSH auth logs and web server
access logs), detects suspicious activity such as brute-force logins, password spraying and web scanning,
and shows alerts in a live dashboard. Alerts can be explained by a **local** AI model through Ollama, so
no log data leaves the machine.

> Status: in development. See [docs/PLAN.md](docs/PLAN.md) for the full plan.

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (10.0.100 or newer, pinned in `global.json`)
- Optional: JetBrains Rider 2025.3+ or Visual Studio 2026
- Optional, for AI explanations: [Ollama](https://ollama.com) with a small model (`ollama pull llama3.2`)

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
dotnet run --project src/LogSentinel.Cli
```

## Test

```bash
dotnet test
```

## Project structure

| Path | Purpose |
|------|---------|
| `src/LogSentinel.Core` | Class library: log parsing, ingestion pipeline, detection rules, alerts, AI abstraction |
| `src/LogSentinel.Cli` | Console application (`logsentinel`): commands and live dashboard |
| `tests/LogSentinel.Tests` | xUnit tests, with NSubstitute and `FakeTimeProvider` |
| `docs/PLAN.md` | Project plan, architecture and requirement mapping |
| `Directory.Build.props` | Shared build settings: .NET 10, nullable reference types, warnings as errors, analyzers |
| `Directory.Packages.props` | Central NuGet package versions |
| `.github/workflows/ci.yml` | Builds and tests on every push to GitHub |
