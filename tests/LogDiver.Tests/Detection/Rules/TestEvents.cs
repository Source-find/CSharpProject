using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Tests.Detection.Rules;

// Builds log events for the rule tests.
internal static class TestEvents
{
    public static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);
    public static readonly IPAddress Attacker = IPAddress.Parse("203.0.113.5");

    public static LogEvent Login(EventKind kind, double seconds) => new()
    {
        Timestamp = Start.AddSeconds(seconds),
        Format = LogFormat.SshAuth,
        Kind = kind,
        RawLine = "test",
        User = "root",
        SourceIp = Attacker,
    };

    public static LogEvent WebRequest(double seconds, int statusCode, string path, string userAgent = "Mozilla/5.0") => new()
    {
        Timestamp = Start.AddSeconds(seconds),
        Format = LogFormat.WebAccess,
        Kind = EventKind.HttpRequest,
        RawLine = "test",
        SourceIp = Attacker,
        StatusCode = statusCode,
        HttpMethod = "GET",
        RequestPath = path,
        UserAgent = userAgent,
    };
}
