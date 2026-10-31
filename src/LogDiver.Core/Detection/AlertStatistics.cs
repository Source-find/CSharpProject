using System.Net;

namespace LogDiver.Core.Detection;

// One row of the "top source IPs" list.
public readonly record struct IpAlertCount(IPAddress Ip, int AlertCount);

// Counts every alert a publisher raises: in total, per severity, per rule and per source IP.
// Subscribes in the constructor and unsubscribes in Dispose, so use it with "using".
public sealed class AlertStatistics : IDisposable
{
    private readonly IAlertPublisher _publisher;
    private readonly Dictionary<AlertSeverity, int> _bySeverity = new();
    private readonly Dictionary<string, int> _byRule = new(StringComparer.Ordinal);
    private readonly Dictionary<IPAddress, int> _bySourceIp = new();

    public AlertStatistics(IAlertPublisher publisher)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        _publisher = publisher;
        _publisher.AlertRaised += OnAlertRaised;
    }

    public int TotalAlerts { get; private set; }

    public IReadOnlyDictionary<AlertSeverity, int> BySeverity => _bySeverity;

    public IReadOnlyDictionary<string, int> ByRule => _byRule;

    // The IPs with the most alerts, most first. Equal counts are sorted by IP, so the order is always the same.
    public IReadOnlyList<IpAlertCount> TopSourceIps(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        return _bySourceIp
            .OrderByDescending(pair => pair.Value)
            .ThenBy(pair => pair.Key.ToString(), StringComparer.Ordinal)
            .Take(count)
            .Select(pair => new IpAlertCount(pair.Key, pair.Value))
            .ToList();
    }

    // Stops listening. The numbers counted so far can still be read afterwards.
    public void Dispose() => _publisher.AlertRaised -= OnAlertRaised;

    private void OnAlertRaised(object? sender, AlertRaisedEventArgs e)
    {
        var alert = e.Alert;
        TotalAlerts++;
        Increment(_bySeverity, alert.Severity);
        Increment(_byRule, alert.RuleName);

        if (alert.SourceIp is not null)
        {
            Increment(_bySourceIp, alert.SourceIp);
        }
    }

    // Generic, so the same helper works for all three dictionaries.
    private static void Increment<TKey>(Dictionary<TKey, int> counts, TKey key)
        where TKey : notnull
    {
        counts[key] = counts.GetValueOrDefault(key) + 1;
    }
}
