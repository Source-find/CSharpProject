using System.Net;

namespace LogDiver.Core.Detection;

// Something suspicious that a detection rule found.
public sealed record Alert(
    string RuleName,
    AlertSeverity Severity,
    DateTimeOffset Timestamp,
    IPAddress? SourceIp,
    string Description);
