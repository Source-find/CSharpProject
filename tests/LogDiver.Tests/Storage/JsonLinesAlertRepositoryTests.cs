using System.Net;
using LogDiver.Core.Detection;
using LogDiver.Core.Storage;
using LogDiver.Tests.Sources;

namespace LogDiver.Tests.Storage;

public sealed class JsonLinesAlertRepositoryTests : IDisposable
{
    private static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.FromHours(1));

    private readonly TempLogFile _file = new();
    private readonly JsonLinesAlertRepository _repository;

    public JsonLinesAlertRepositoryTests()
    {
        _repository = new JsonLinesAlertRepository(_file.Path);
    }

    [Fact]
    public async Task SaveThenRead_ReturnsEqualAlerts()
    {
        var alerts = new[] { CreateAlert("BruteForce", AlertSeverity.High), CreateAlert("WebScanner", AlertSeverity.Medium) };

        await _repository.SaveAsync(alerts);
        var read = await ReadAllAsync();

        Assert.Equal(2, read.Count);
        Assert.Equal(alerts[0], read[0]);
        Assert.Equal(alerts[1], read[1]);
    }

    [Fact]
    public async Task SaveThenRead_KeepsMergedCountsAndMissingIp()
    {
        var alert = CreateAlert("SuspiciousRequest", AlertSeverity.High, ip: null) with
        {
            Occurrences = 57,
            LastSeen = Start.AddMinutes(30),
        };

        await _repository.SaveAsync([alert]);
        var read = Assert.Single(await ReadAllAsync());

        Assert.Equal(57, read.Occurrences);
        Assert.Equal(Start.AddMinutes(30), read.LastSeen);
        Assert.Null(read.SourceIp);
    }

    [Fact]
    public async Task SavingTwice_AppendsInsteadOfOverwriting()
    {
        await _repository.SaveAsync([CreateAlert("BruteForce", AlertSeverity.High)]);
        await _repository.SaveAsync([CreateAlert("WebScanner", AlertSeverity.Medium)]);

        var read = await ReadAllAsync();

        Assert.Equal("BruteForce|WebScanner", string.Join('|', read.Select(a => a.RuleName)));
    }

    [Fact]
    public async Task HostileDescription_StaysOnOneLineAndComesBackUnchanged()
    {
        // An attacker-controlled path with a quote, a line break and an ANSI escape code: written by hand
        // as CSV, this could break the file or add a fake second alert.
        const string hostile = "GET /\"x\"\n{\"ruleName\":\"Fake\"}\u001b[31m";
        var alert = CreateAlert("SuspiciousRequest", AlertSeverity.High) with { Description = hostile };

        await _repository.SaveAsync([alert]);

        Assert.Single(await File.ReadAllLinesAsync(_file.Path));
        Assert.Equal(hostile, Assert.Single(await ReadAllAsync()).Description);
    }

    [Fact]
    public async Task File_UsesCamelCaseNamesAndSeverityAsText()
    {
        await _repository.SaveAsync([CreateAlert("BruteForce", AlertSeverity.High)]);

        var json = await File.ReadAllTextAsync(_file.Path);

        Assert.Contains("\"ruleName\":\"BruteForce\"", json, StringComparison.Ordinal);
        Assert.Contains("\"severity\":\"High\"", json, StringComparison.Ordinal);
        Assert.Contains("\"sourceIp\":\"203.0.113.5\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAll_WhenNothingWasSaved_ReturnsNothing()
    {
        Assert.Empty(await ReadAllAsync());
    }

    [Fact]
    public async Task ReadAll_CorruptLine_ThrowsInvalidDataWithLineNumber()
    {
        await _repository.SaveAsync([CreateAlert("BruteForce", AlertSeverity.High)]);
        await File.AppendAllTextAsync(_file.Path, "this is not json\n");

        var error = await Assert.ThrowsAsync<InvalidDataException>(ReadAllAsync);

        Assert.Contains("Line 2", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Constructor_EmptyPath_Throws(string path)
    {
        Assert.Throws<ArgumentException>(() => new JsonLinesAlertRepository(path));
    }

    public void Dispose() => _file.Dispose();

    private static Alert CreateAlert(string rule, AlertSeverity severity, string? ip = "203.0.113.5") =>
        new(rule, severity, Start, ip is null ? null : IPAddress.Parse(ip), $"{rule} test alert");

    private async Task<List<Alert>> ReadAllAsync()
    {
        var alerts = new List<Alert>();
        await foreach (var alert in _repository.ReadAllAsync())
        {
            alerts.Add(alert);
        }

        return alerts;
    }
}
