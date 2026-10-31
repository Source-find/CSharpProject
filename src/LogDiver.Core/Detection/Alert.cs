using System.Net;

namespace LogDiver.Core.Detection;

// Something suspicious that a detection rule found.
public sealed record Alert(
    string RuleName,
    AlertSeverity Severity,
    DateTimeOffset Timestamp,
    IPAddress? SourceIp,
    string Description)
{
    // How many times this alert happened. Above 1 when AlertDeduplicator merged repeats into it.
    public int Occurrences { get; init; } = 1;

    // When the last repeat happened. The same as Timestamp until repeats are merged in.
    public DateTimeOffset LastSeen { get; init; } = Timestamp;
}
