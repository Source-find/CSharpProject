namespace LogSentinel.Tests;

/// <summary>
/// Verifies that the test project is wired up correctly.
/// Delete this file once real tests exist (phase 2).
/// </summary>
public class SetupSmokeTests
{
    [Fact]
    public void Runtime_IsDotNet10OrNewer()
    {
        Assert.True(Environment.Version.Major >= 10);
    }
}
