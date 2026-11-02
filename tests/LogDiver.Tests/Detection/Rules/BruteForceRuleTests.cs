using LogDiver.Core.Detection;
using LogDiver.Core.Detection.Rules;
using LogDiver.Core.Events;

namespace LogDiver.Tests.Detection.Rules;
// Test built by me.
public class BruteForceRuleTests
{
    [Fact]
    public void Evaluate_AlertsWhenFailedLoginsReachThreshold()
    {
        var rule = new BruteForceRule(threshold: 3, window: TimeSpan.FromSeconds(60));

        Assert.Null(rule.Evaluate(TestEvents.Login(EventKind.LoginFailed, 0)));
        Assert.Null(rule.Evaluate(TestEvents.Login(EventKind.LoginSucceeded, 1)));
        Assert.Null(rule.Evaluate(TestEvents.Login(EventKind.LoginFailed, 2)));
        var alert = rule.Evaluate(TestEvents.Login(EventKind.LoginFailed, 3));

        Assert.NotNull(alert);
        Assert.Equal("BruteForce", alert.RuleName);
        Assert.Equal(AlertSeverity.High, alert.Severity);
        Assert.Equal(TestEvents.Attacker, alert.SourceIp);

    }
}
