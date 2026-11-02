using LogDiver.Core.Detection;
using LogDiver.Core.Detection.Rules;

namespace LogDiver.Tests.Detection.Rules;

public class SuspiciousRequestRuleTests
{
    private readonly SuspiciousRequestRule _rule = new();

    [Theory]
    [InlineData("/../../etc/passwd", "Mozilla/5.0", AlertSeverity.High)]
    [InlineData("/products?id=1 UNION SELECT password FROM users", "Mozilla/5.0", AlertSeverity.High)]
    [InlineData("/", "sqlmap/1.8#stable (https://sqlmap.org)", AlertSeverity.Medium)]
    public void Evaluate_AttackPatternOrTool_RaisesAlertWithTheRightSeverity(
        string path, string userAgent, AlertSeverity expectedSeverity)
    {
        var alert = _rule.Evaluate(TestEvents.WebRequest(seconds: 0, statusCode: 200, path, userAgent));

        Assert.NotNull(alert);
        Assert.Equal(expectedSeverity, alert.Severity);
    }

    [Fact]
    public void Evaluate_NormalSearchThatLooksSimilar_IsNotAnAlert()
    {
        // "union" without "select" is just a word, not SQL injection.
        Assert.Null(_rule.Evaluate(TestEvents.WebRequest(seconds: 0, statusCode: 200, "/search?q=union+station")));
    }
}
