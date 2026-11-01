using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

public class AlertDeduplicatorTests
{
    [Fact]
    public void RepeatsWithinCooldown_AreMergedIntoTheFirstAlert()
    {
        var publisher = new FakeAlertPublisher();
        using var deduplicator = new AlertDeduplicator(publisher, TimeSpan.FromMinutes(10));

        publisher.Raise(TestAlerts.Create(minutes: 0));
        publisher.Raise(TestAlerts.Create(minutes: 3));
        publisher.Raise(TestAlerts.Create(minutes: 5));

        var merged = Assert.Single(deduplicator.Alerts);
        Assert.Equal(3, merged.Occurrences);
        Assert.Equal(TestAlerts.Start, merged.Timestamp);
        Assert.Equal(TestAlerts.Start.AddMinutes(5), merged.LastSeen);
    }
}
