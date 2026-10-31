using System.Net;
using LogDiver.Core.Detection;
using LogDiver.Core.Events;

namespace LogDiver.Tests.Detection;

// These tests only look at what goes into the engine and which alerts come out, not at how the engine
// is built. That way they keep working when the engine is refactored to the Strategy pattern.
public class DetectionEngineTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress Attacker = IPAddress.Parse("203.0.113.5");
    private static readonly IPAddress OtherIp = IPAddress.Parse("198.51.100.7");

    private readonly DetectionEngine _engine = new();

    // ---- Brute force ----

    [Fact]
    public void Process_NineFailedLogins_NoAlert()
    {
        var alerts = ProcessAll(FailedLogins(Attacker, count: 9, interval: TimeSpan.FromSeconds(1)));

        Assert.Empty(alerts);
    }

    [Fact]
    public void Process_TenFailedLoginsWithinAMinute_RaisesOneHighBruteForceAlert()
    {
        var alerts = ProcessAll(FailedLogins(Attacker, count: 10, interval: TimeSpan.FromSeconds(1)));

        var alert = Assert.Single(alerts);
        Assert.Equal("BruteForce", alert.RuleName);
        Assert.Equal(AlertSeverity.High, alert.Severity);
        Assert.Equal(Attacker, alert.SourceIp);
        Assert.Equal(Start.AddSeconds(9), alert.Timestamp);
    }

    [Fact]
    public void Process_TenFailedLoginsSpreadOverTwoMinutes_NoAlert()
    {
        var alerts = ProcessAll(FailedLogins(Attacker, count: 10, interval: TimeSpan.FromSeconds(12)));

        Assert.Empty(alerts);
    }

    [Fact]
    public void Process_FailedLoginsFromDifferentIps_AreCountedSeparately()
    {
        var events = FailedLogins(Attacker, count: 5, interval: TimeSpan.FromSeconds(1))
            .Concat(FailedLogins(OtherIp, count: 5, interval: TimeSpan.FromSeconds(1)));

        Assert.Empty(ProcessAll(events));
    }

    [Fact]
    public void Process_TwentyFailedLogins_RaisesTwoAlerts()
    {
        var alerts = ProcessAll(FailedLogins(Attacker, count: 20, interval: TimeSpan.FromSeconds(1)));

        Assert.Equal(2, alerts.Count);
    }

    [Fact]
    public void Process_SuccessfulLogins_AreNotCounted()
    {
        var events = Enumerable.Range(0, 20).Select(i => SshEvent(EventKind.LoginSucceeded, Attacker, Start.AddSeconds(i)));

        Assert.Empty(ProcessAll(events));
    }

    // ---- Web scanner ----

    [Fact]
    public void Process_TwentyNineNotFound_NoAlert()
    {
        Assert.Empty(ProcessAll(Requests(Attacker, count: 29, statusCode: 404)));
    }

    [Fact]
    public void Process_ThirtyNotFoundWithinAMinute_RaisesWebScannerAlert()
    {
        var alert = Assert.Single(ProcessAll(Requests(Attacker, count: 30, statusCode: 404)));

        Assert.Equal("WebScanner", alert.RuleName);
        Assert.Equal(AlertSeverity.Medium, alert.Severity);
        Assert.Equal(Attacker, alert.SourceIp);
    }

    [Fact]
    public void Process_ManySuccessfulRequests_NoAlert()
    {
        Assert.Empty(ProcessAll(Requests(Attacker, count: 100, statusCode: 200)));
    }

    // ---- Suspicious request ----

    [Theory]
    [InlineData("/../../etc/passwd")]
    [InlineData("/download?file=..%2f..%2fetc%2fpasswd")]
    [InlineData("/products?id=1 UNION SELECT username, password FROM users")]
    [InlineData("/products?id=1%20union%20all%20select%201,2")]
    [InlineData("/login?user=' OR '1'='1")]
    [InlineData("/search?q=<script>alert(1)</script>")]
    [InlineData("/.env")]
    [InlineData("/.git/config")]
    [InlineData("/wp-admin/install.php")]
    public void Process_AttackPatternInPath_RaisesHighSuspiciousRequestAlert(string path)
    {
        var alert = Assert.Single(ProcessAll([WebEvent(Attacker, Start, 200, path, "Mozilla/5.0")]));

        Assert.Equal("SuspiciousRequest", alert.RuleName);
        Assert.Equal(AlertSeverity.High, alert.Severity);
    }

    [Theory]
    [InlineData("sqlmap/1.8#stable (https://sqlmap.org)")]
    [InlineData("Mozilla/5.00 (Nikto/2.5.0)")]
    public void Process_AttackToolUserAgent_RaisesMediumSuspiciousRequestAlert(string userAgent)
    {
        var alert = Assert.Single(ProcessAll([WebEvent(Attacker, Start, 200, "/", userAgent)]));

        Assert.Equal("SuspiciousRequest", alert.RuleName);
        Assert.Equal(AlertSeverity.Medium, alert.Severity);
    }

    [Theory]
    [InlineData("/index.html")]
    [InlineData("/blog/2026/10/how-to-secure-ssh")]
    [InlineData("/search?q=union+station+opening+hours")]
    public void Process_NormalRequest_NoAlert(string path)
    {
        Assert.Empty(ProcessAll([WebEvent(Attacker, Start, 200, path, "Mozilla/5.0")]));
    }

    // ---- General ----

    [Fact]
    public void Process_EventWithoutIp_IsIgnoredByCountingRules()
    {
        var events = Enumerable.Range(0, 20).Select(i => SshEvent(EventKind.LoginFailed, ip: null, Start.AddSeconds(i)));

        Assert.Empty(ProcessAll(events));
    }

    [Fact]
    public void Process_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _engine.Process(null!));
    }

    // ---- AlertRaised event ----

    [Fact]
    public void AlertRaised_WhenAlertIsFound_IsRaisedOnceWithTheSameAlertAndTheEngineAsSender()
    {
        var raised = new List<(object? Sender, Alert Alert)>();
        _engine.AlertRaised += (sender, e) => raised.Add((sender, e.Alert));

        var returned = ProcessAll(FailedLogins(Attacker, count: 10, interval: TimeSpan.FromSeconds(1)));

        var (sender, alert) = Assert.Single(raised);
        Assert.Same(_engine, sender);
        Assert.Same(Assert.Single(returned), alert);
    }

    [Fact]
    public void AlertRaised_WhenNothingIsFound_IsNotRaised()
    {
        var raisedCount = 0;
        _engine.AlertRaised += (_, _) => raisedCount++;

        ProcessAll(FailedLogins(Attacker, count: 9, interval: TimeSpan.FromSeconds(1)));

        Assert.Equal(0, raisedCount);
    }

    [Fact]
    public void AlertRaised_WithSeveralSubscribers_ReachesEveryOne()
    {
        var first = 0;
        var second = 0;
        _engine.AlertRaised += (_, _) => first++;
        _engine.AlertRaised += (_, _) => second++;

        ProcessAll([WebEvent(Attacker, Start, 200, "/.env", "Mozilla/5.0")]);

        Assert.Equal(1, first);
        Assert.Equal(1, second);
    }

    [Fact]
    public void AlertRaised_AfterUnsubscribing_IsNoLongerReceived()
    {
        var raisedCount = 0;
        void Handler(object? sender, AlertRaisedEventArgs e) => raisedCount++;
        _engine.AlertRaised += Handler;
        ProcessAll([WebEvent(Attacker, Start, 200, "/.env", "Mozilla/5.0")]);

        _engine.AlertRaised -= Handler;
        ProcessAll([WebEvent(Attacker, Start, 200, "/.git/config", "Mozilla/5.0")]);

        Assert.Equal(1, raisedCount);
    }

    [Fact]
    public void Process_WithoutSubscribers_StillReturnsAlerts()
    {
        Assert.Single(ProcessAll([WebEvent(Attacker, Start, 200, "/.env", "Mozilla/5.0")]));
    }

    [Fact]
    public void AlertRaisedEventArgs_NullAlert_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AlertRaisedEventArgs(null!));
    }

    private List<Alert> ProcessAll(IEnumerable<LogEvent> events) =>
        events.SelectMany(e => _engine.Process(e)).ToList();

    private static IEnumerable<LogEvent> FailedLogins(IPAddress ip, int count, TimeSpan interval) =>
        Enumerable.Range(0, count).Select(i => SshEvent(EventKind.LoginFailed, ip, Start + (interval * i)));

    private static IEnumerable<LogEvent> Requests(IPAddress ip, int count, int statusCode) =>
        Enumerable.Range(0, count).Select(i => WebEvent(ip, Start.AddSeconds(i), statusCode, $"/page{i}", "Mozilla/5.0"));

    private static LogEvent SshEvent(EventKind kind, IPAddress? ip, DateTimeOffset time) => new()
    {
        Timestamp = time,
        Format = LogFormat.SshAuth,
        Kind = kind,
        RawLine = "test",
        User = "root",
        SourceIp = ip,
    };

    private static LogEvent WebEvent(IPAddress ip, DateTimeOffset time, int statusCode, string path, string userAgent) => new()
    {
        Timestamp = time,
        Format = LogFormat.WebAccess,
        Kind = EventKind.HttpRequest,
        RawLine = "test",
        SourceIp = ip,
        StatusCode = statusCode,
        HttpMethod = "GET",
        RequestPath = path,
        UserAgent = userAgent,
    };
}
