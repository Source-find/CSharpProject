using System.Net;
using LogDiver.Core.Detection;
using LogDiver.Core.Storage;
using LogDiver.Tests.Sources;

namespace LogDiver.Tests.Storage;

public sealed class JsonLinesAlertRepositoryTests : IDisposable
{
    private readonly TempLogFile _file = new();

    [Fact]
    public async Task HostileDescription_StaysOnOneLineAndComesBackUnchanged()
    {
        // An attacker-controlled path with a quote, a line break and an ANSI escape code: written by hand
        // as CSV, this could break the file or add a fake second alert.
        const string hostile = "GET /\"x\"\n{\"ruleName\":\"Fake\"}\u001b[31m";
        var alert = new Alert(
            "SuspiciousRequest",
            AlertSeverity.High,
            new DateTimeOffset(2026, 10, 27, 9, 0, 0, TimeSpan.FromHours(1)),
            IPAddress.Parse("203.0.113.5"),
            hostile) with { Occurrences = 3 };
        var repository = new JsonLinesAlertRepository(_file.Path);

        await repository.SaveAsync([alert]);

        Assert.Single(await File.ReadAllLinesAsync(_file.Path));
        var read = new List<Alert>();
        await foreach (var saved in repository.ReadAllAsync())
        {
            read.Add(saved);
        }

        Assert.Equal(alert, Assert.Single(read));
    }

    public void Dispose() => _file.Dispose();
}
