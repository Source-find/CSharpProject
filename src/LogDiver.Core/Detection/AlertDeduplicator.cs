using System.Net;

namespace LogDiver.Core.Detection;

// Merges repeated alerts, F.example sqlmaps, usually returning thousands of alerts in this context, but with the repeated alert manager it shortens it to only one.
// Alerts from the same rule and source IP count as one while each repeat comes within the cooldown of the
// previous one; the merged alert gets a higher Occurrences and a later LastSeen. Time comes from the log.
// Subscribes in the constructor and unsubscribes in Dispose, so use it with "using".
public sealed class AlertDeduplicator : IDisposable
{
    private readonly IAlertPublisher _publisher;
    private readonly TimeSpan _cooldown;

    // Every merged alert, in the order they were first seen.
    private readonly List<Alert> _alerts = [];

    // Groups that can still receive repeats: (rule, IP) -> position in _alerts.
    private readonly Dictionary<(string Rule, IPAddress? Ip), int> _openGroups = new();

    public AlertDeduplicator(IAlertPublisher publisher)
        : this(publisher, DefaultCooldown)
    {
    }

    public AlertDeduplicator(IAlertPublisher publisher, TimeSpan cooldown)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(cooldown, TimeSpan.Zero);

        _publisher = publisher;
        _cooldown = cooldown;
        _publisher.AlertRaised += OnAlertRaised;
    }

    public static TimeSpan DefaultCooldown { get; } = TimeSpan.FromMinutes(10);

    // The merged alerts, in the order they were first seen.
    public IReadOnlyList<Alert> Alerts => _alerts;

    // Stops listening. The merged alerts can still be read afterwards.
    public void Dispose() => _publisher.AlertRaised -= OnAlertRaised;

    private void OnAlertRaised(object? sender, AlertRaisedEventArgs e)
    {
        var alert = e.Alert;
        var key = (alert.RuleName, alert.SourceIp);

        if (_openGroups.TryGetValue(key, out var index) && alert.Timestamp - _alerts[index].LastSeen <= _cooldown)
        {
            // Records are immutable, so "with" makes an updated copy.
            var existing = _alerts[index];
            _alerts[index] = existing with
            {
                Occurrences = existing.Occurrences + 1,
                LastSeen = alert.Timestamp > existing.LastSeen ? alert.Timestamp : existing.LastSeen,
                Severity = alert.Severity > existing.Severity ? alert.Severity : existing.Severity,
            };
            return;
        }

        _openGroups[key] = _alerts.Count;
        _alerts.Add(alert);
        CloseExpiredGroups(alert.Timestamp);
    }

    // Forgets groups whose cooldown has passed, so the lookup table doesn't grow with every IP ever seen.
    private void CloseExpiredGroups(DateTimeOffset now)
    {
        foreach (var (key, index) in _openGroups)
        {
            if (now - _alerts[index].LastSeen > _cooldown)
            {
                _openGroups.Remove(key); // Allowed while looping over a Dictionary since .NET Core 3.0.
            }
        }
    }
}
