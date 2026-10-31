using System.Net;
using LogDiver.Core.Detection;
using LogDiver.Core.Events;

namespace LogDiver.Tests.Detection;

public class AlertStatisticsTests
{
    private readonly FakeAlertPublisher _publisher = new();

    [Fact]
    public void CountsAlertsInTotalPerSeverityAndPerRule()
    {
        using var statistics = new AlertStatistics(_publisher);

        _publisher.Raise(TestAlerts.Create("BruteForce", severity: AlertSeverity.High));
        _publisher.Raise(TestAlerts.Create("BruteForce", severity: AlertSeverity.High));
        _publisher.Raise(TestAlerts.Create("WebScanner", severity: AlertSeverity.Medium));

        Assert.Equal(3, statistics.TotalAlerts);
        Assert.Equal(2, statistics.BySeverity[AlertSeverity.High]);
        Assert.Equal(1, statistics.BySeverity[AlertSeverity.Medium]);
        Assert.False(statistics.BySeverity.ContainsKey(AlertSeverity.Low));
        Assert.Equal(2, statistics.ByRule["BruteForce"]);
        Assert.Equal(1, statistics.ByRule["WebScanner"]);
    }

    [Fact]
    public void TopSourceIps_AreSortedByCountThenByIp_AndLimited()
    {
        using var statistics = new AlertStatistics(_publisher);
        RaiseTimes("198.51.100.9", 1);
        RaiseTimes("203.0.113.5", 3);
        RaiseTimes("198.51.100.2", 2);
        RaiseTimes("198.51.100.1", 2);

        var top = statistics.TopSourceIps(3);

        Assert.Equal(
            "203.0.113.5=3|198.51.100.1=2|198.51.100.2=2",
            string.Join('|', top.Select(row => $"{row.Ip}={row.AlertCount}")));
    }

    [Fact]
    public void AlertWithoutIp_IsCountedButNotInTopSourceIps()
    {
        using var statistics = new AlertStatistics(_publisher);

        _publisher.Raise(TestAlerts.Create(ip: null));

        Assert.Equal(1, statistics.TotalAlerts);
        Assert.Empty(statistics.TopSourceIps(5));
    }

    [Fact]
    public void Dispose_Unsubscribes_SoLaterAlertsAreNotCounted()
    {
        var statistics = new AlertStatistics(_publisher);
        Assert.Equal(1, _publisher.SubscriberCount);
        _publisher.Raise(TestAlerts.Create());

        statistics.Dispose();
        _publisher.Raise(TestAlerts.Create());

        Assert.Equal(0, _publisher.SubscriberCount);
        Assert.Equal(1, statistics.TotalAlerts);
    }

    [Fact]
    public void TopSourceIps_NegativeCount_Throws()
    {
        using var statistics = new AlertStatistics(_publisher);

        Assert.Throws<ArgumentOutOfRangeException>(() => statistics.TopSourceIps(-1));
    }

    [Fact]
    public void Constructor_NullPublisher_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new AlertStatistics(null!));
    }

    [Fact]
    public void WorksWithTheRealEngine()
    {
        var engine = new DetectionEngine();
        using var statistics = new AlertStatistics(engine);

        engine.Process(new LogEvent
        {
            Timestamp = TestAlerts.Start,
            Format = LogFormat.WebAccess,
            Kind = EventKind.HttpRequest,
            RawLine = "test",
            SourceIp = IPAddress.Parse("203.0.113.90"),
            StatusCode = 404,
            RequestPath = "/.env",
        });

        Assert.Equal(1, statistics.ByRule["SuspiciousRequest"]);
    }

    private void RaiseTimes(string ip, int times)
    {
        for (var i = 0; i < times; i++)
        {
            _publisher.Raise(TestAlerts.Create(ip: ip));
        }
    }
}
