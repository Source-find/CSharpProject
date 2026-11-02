using LogDiver.Core.Detection;
using LogDiver.Core.Detection.Rules;

namespace LogDiver.Tests.Detection.Rules;

public class WebScannerRuleTests
{
    [Fact]
    public void Evaluate_CountsOnlyNotFoundResponses()
    {
        var rule = new WebScannerRule(threshold: 3, window: TimeSpan.FromSeconds(60));

        Assert.Null(rule.Evaluate(TestEvents.WebRequest(seconds: 0, statusCode: 404, "/a")));
        Assert.Null(rule.Evaluate(TestEvents.WebRequest(seconds: 1, statusCode: 200, "/"))); // Normal pages don't count.
        Assert.Null(rule.Evaluate(TestEvents.WebRequest(seconds: 2, statusCode: 404, "/b")));
        var alert = rule.Evaluate(TestEvents.WebRequest(seconds: 3, statusCode: 404, "/c"));

        Assert.NotNull(alert);
        Assert.Equal("WebScanner", alert.RuleName);
        Assert.Equal(AlertSeverity.Medium, alert.Severity);
    }
}
