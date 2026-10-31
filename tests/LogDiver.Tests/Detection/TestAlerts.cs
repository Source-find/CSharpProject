using System.Net;
using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

// Builds alerts for tests. Time is given in minutes after a fixed start.
internal static class TestAlerts
{
    public static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);

    public static Alert Create(
        string rule = "BruteForce",
        string? ip = "203.0.113.5",
        double minutes = 0,
        AlertSeverity severity = AlertSeverity.High) =>
        new(rule, severity, Start.AddMinutes(minutes), ip is null ? null : IPAddress.Parse(ip), $"{rule} test alert");
}
