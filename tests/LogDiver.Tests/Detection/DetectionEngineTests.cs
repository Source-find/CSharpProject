using System.Net;
using LogDiver.Core.Detection;
using LogDiver.Core.Events;

namespace LogDiver.Tests.Detection;

// These tests only look at what goes into the engine and which alerts come out, not at how the engine is
// built, so they keep working if the engine is refactored later.
public class DetectionEngineTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress Attacker = IPAddress.Parse("203.0.113.5");

    private readonly DetectionEngine _engine = new();

    [Fact]
    public void Process_TenFailedLoginsWithinAMinute_RaisesOneHighBruteForceAlert()
    {
        var events = Enumerable.Range(0, 10).Select(i => SshFailedLogin(Start.AddSeconds(i)));

        var alert = Assert.Single(ProcessAll(events));

        Assert.Equal("BruteForce", alert.RuleName);
        Assert.Equal(AlertSeverity.High, alert.Severity);
        Assert.Equal(Attacker, alert.SourceIp);
    }

    [Fact]
    public void Process_ThirtyNotFoundWithinAMinute_RaisesWebScannerAlert()
    {
        var events = Enumerable.Range(0, 30).Select(i => WebRequest(Start.AddSeconds(i), 404, $"/page{i}"));

        var alert = Assert.Single(ProcessAll(events));

        Assert.Equal("WebScanner", alert.RuleName);
        Assert.Equal(AlertSeverity.Medium, alert.Severity);
    }

    [Theory]
    [InlineData("/../../etc/passwd")]
    [InlineData("/products?id=1 UNION SELECT username, password FROM users")]
    [InlineData("/search?q=<script>alert(1)</script>")]
    [InlineData("/.env")]
    public void Process_AttackPatternInPath_RaisesSuspiciousRequestAlert(string path)
    {
        var alert = Assert.Single(ProcessAll([WebRequest(Start, 200, path)]));

        Assert.Equal("SuspiciousRequest", alert.RuleName);
    }

    [Fact]
    public void AlertRaised_AfterUnsubscribing_IsNoLongerReceived()
    {
        var raisedCount = 0;
        void Handler(object? sender, AlertRaisedEventArgs e) => raisedCount++;
        _engine.AlertRaised += Handler;
        ProcessAll([WebRequest(Start, 200, "/.env")]);

        _engine.AlertRaised -= Handler;
        ProcessAll([WebRequest(Start, 200, "/.git/config")]);

        Assert.Equal(1, raisedCount);
    }

    private List<Alert> ProcessAll(IEnumerable<LogEvent> events) =>
        events.SelectMany(e => _engine.Process(e)).ToList();

    private static LogEvent SshFailedLogin(DateTimeOffset time) => new()
    {
        Timestamp = time,
        Format = LogFormat.SshAuth,
        Kind = EventKind.LoginFailed,
        RawLine = "test",
        User = "root",
        SourceIp = Attacker,
    };

    private static LogEvent WebRequest(DateTimeOffset time, int statusCode, string path) => new()
    {
        Timestamp = time,
        Format = LogFormat.WebAccess,
        Kind = EventKind.HttpRequest,
        RawLine = "test",
        SourceIp = Attacker,
        StatusCode = statusCode,
        HttpMethod = "GET",
        RequestPath = path,
        UserAgent = "Mozilla/5.0",
    };
}
