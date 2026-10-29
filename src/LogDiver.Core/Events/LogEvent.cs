using System.Net;

namespace LogDiver.Core.Events;

// One security-relevant event read from a log line.
// All text comes from the log and may be written by an attacker. It is shortened and cleaned,
// but must still be escaped before it is shown in the console.
public sealed record LogEvent
{
    // When it happened.
    public required DateTimeOffset Timestamp { get; init; }

    // Which log format it came from.
    public required LogFormat Format { get; init; }

    // What happened.
    public required EventKind Kind { get; init; }

    // The original line (shortened and cleaned).
    public required string RawLine { get; init; }

    // The server that wrote the line, if the log includes it.
    public string? Host { get; init; }

    // The user name, if known.
    public string? User { get; init; }

    // The IP address the login or request came from.
    public IPAddress? SourceIp { get; init; }

    // HTTP status code (web logs only).
    public int? StatusCode { get; init; }

    // HTTP method such as GET (web logs only). Null if the request was garbage.
    public string? HttpMethod { get; init; }

    // Requested path and query string (web logs only).
    public string? RequestPath { get; init; }

    // The client's User-Agent (web logs only, combined format).
    public string? UserAgent { get; init; }
}
