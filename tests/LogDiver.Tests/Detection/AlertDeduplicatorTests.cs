using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

public class AlertDeduplicatorTests
{
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

    private readonly FakeAlertPublisher _publisher = new();

    [Fact]
    public void FirstAlert_IsKeptAsItIs()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);
        var alert = TestAlerts.Create();

        _publisher.Raise(alert);

        Assert.Same(alert, Assert.Single(deduplicator.Alerts));
        Assert.Equal(1, alert.Occurrences);
        Assert.Equal(alert.Timestamp, alert.LastSeen);
    }

    [Fact]
    public void RepeatWithinCooldown_IsMergedIntoFirstAlert()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        _publisher.Raise(TestAlerts.Create(minutes: 0));
        _publisher.Raise(TestAlerts.Create(minutes: 3));
        _publisher.Raise(TestAlerts.Create(minutes: 5));

        var merged = Assert.Single(deduplicator.Alerts);
        Assert.Equal(3, merged.Occurrences);
        Assert.Equal(TestAlerts.Start, merged.Timestamp);
        Assert.Equal(TestAlerts.Start.AddMinutes(5), merged.LastSeen);
    }

    [Fact]
    public void CooldownCountsFromTheLastRepeat_SoAnOngoingAttackStaysOneAlert()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        // Every repeat comes 6 minutes after the previous one: 0, 6, 12, ..., 60.
        for (var minutes = 0; minutes <= 60; minutes += 6)
        {
            _publisher.Raise(TestAlerts.Create(minutes: minutes));
        }

        Assert.Equal(11, Assert.Single(deduplicator.Alerts).Occurrences);
    }

    [Fact]
    public void RepeatAfterCooldown_StartsANewAlert()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        _publisher.Raise(TestAlerts.Create(minutes: 0));
        _publisher.Raise(TestAlerts.Create(minutes: 11));

        Assert.Equal(2, deduplicator.Alerts.Count);
        Assert.All(deduplicator.Alerts, alert => Assert.Equal(1, alert.Occurrences));
    }

    [Fact]
    public void DifferentIpsOrRules_AreNotMerged()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        _publisher.Raise(TestAlerts.Create("BruteForce", "203.0.113.5"));
        _publisher.Raise(TestAlerts.Create("BruteForce", "198.51.100.7"));
        _publisher.Raise(TestAlerts.Create("WebScanner", "203.0.113.5"));

        Assert.Equal(
            "BruteForce 203.0.113.5|BruteForce 198.51.100.7|WebScanner 203.0.113.5",
            string.Join('|', deduplicator.Alerts.Select(a => $"{a.RuleName} {a.SourceIp}")));
    }

    [Fact]
    public void MergedAlert_KeepsTheHighestSeverity()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        _publisher.Raise(TestAlerts.Create("SuspiciousRequest", severity: AlertSeverity.Medium));
        _publisher.Raise(TestAlerts.Create("SuspiciousRequest", minutes: 1, severity: AlertSeverity.High));

        Assert.Equal(AlertSeverity.High, Assert.Single(deduplicator.Alerts).Severity);
    }

    [Fact]
    public void ExpiredGroups_AreForgotten_SoMemoryDoesNotGrowWithEveryIp()
    {
        using var deduplicator = new AlertDeduplicator(_publisher, Cooldown);
        for (var i = 1; i <= 100; i++)
        {
            _publisher.Raise(TestAlerts.Create(ip: $"198.51.100.{i}"));
        }

        Assert.Equal(100, deduplicator.OpenGroupCount);

        _publisher.Raise(TestAlerts.Create(ip: "203.0.113.5", minutes: 60));

        Assert.Equal(1, deduplicator.OpenGroupCount);
        Assert.Equal(101, deduplicator.Alerts.Count); // The alerts themselves are still all reported.
    }

    [Fact]
    public void Dispose_Unsubscribes()
    {
        var deduplicator = new AlertDeduplicator(_publisher, Cooldown);

        deduplicator.Dispose();
        _publisher.Raise(TestAlerts.Create());

        Assert.Equal(0, _publisher.SubscriberCount);
        Assert.Empty(deduplicator.Alerts);
    }

    [Fact]
    public void Constructor_ZeroCooldown_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AlertDeduplicator(_publisher, TimeSpan.Zero));
    }

    [Fact]
    public void DefaultCooldown_IsTenMinutes()
    {
        Assert.Equal(TimeSpan.FromMinutes(10), AlertDeduplicator.DefaultCooldown);
    }
}
