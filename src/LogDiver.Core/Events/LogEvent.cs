using System.Net;

namespace LogDiver.Core.Events;

// One normalised, security-relevant event parsed from a log line.
// All text fields come from the log and must be treated as attacker-controlled. Parsers truncate them and
// replace control characters, but they are still raw text: escape them before rendering (for example with
// Spectre.Console's <c>Markup.Escape</c>).
public sealed record LogEvent
{
    // When the event happened, with the offset from the log (or the local offset if the log has none)
    public required DateTimeOffset Timestamp { get; init; }

    // The log format the event was parsed from.
    public required LogFormat Format { get; init; }

    // What happened during the parsing
    public required EventKind Kind { get; init; }

    // The original line, truncated and with control characters replaced.
    public required string RawLine { get; init; }

    // The host that wrote the log line, when the format includes it.
    public string? Host { get; init; }

    // The user name involved, when known.
    public string? User { get; init; }

    //The remote address that caused the event.
    public IPAddress? SourceIp { get; init; }

    // HTTP status code, for web events.
    public int? StatusCode { get; init; }

    // HTTP method such as <c>GET</c>, for web events. Null when the request line was malformed.
    public string? HttpMethod { get; init; }

    //Requested path including the query string, for web events.
    public string? RequestPath { get; init; }

    //The client's User-Agent header, for web events in the combined format.
    public string? UserAgent { get; init; }

    // How many times this event happened. Syslog collapses identical lines into
    // <c>message repeated N times</c>, and detection rules must count all of them.
    public int OccurrenceCount { get; init; } = 1;
}
