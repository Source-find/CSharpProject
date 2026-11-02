using LogDiver.Core.Detection.Rules;
using LogDiver.Core.Events;

namespace LogDiver.Core.Detection;

// The detection engine: runs every detection rule on each event and announces what they find.
// - Strategy pattern: each rule is its own class behind IDetectionRule. The engine doesn't know how any
//   rule works, so rules can be added or removed without changing this class.
// - Observer pattern: alerts are announced through the AlertRaised event.
public sealed class DetectionEngine : IAlertPublisher
{
    private readonly IDetectionRule[] _rules;

    // Uses the three built-in rules.
    public DetectionEngine()
        : this([new BruteForceRule(), new WebScannerRule(), new SuspiciousRequestRule()])
    {
    }

    // Uses the given rules, for example only one rule in a test.
    public DetectionEngine(IEnumerable<IDetectionRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);
        _rules = rules.ToArray();
    }

    // Raised once for every alert a rule finds (Observer pattern). Handlers run inside the analysis,
    // so they should be quick. Subscribers must unsubscribe (-=) when done, or the engine keeps them alive.
    public event EventHandler<AlertRaisedEventArgs>? AlertRaised;

    // Asks every rule about one event, raises AlertRaised for each alert and returns them.
    public IReadOnlyList<Alert> Process(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);

        // Most events cause no alert, so the list is only created when there is something to put in it.
        List<Alert>? alerts = null;
        foreach (var rule in _rules)
        {
            if (rule.Evaluate(logEvent) is { } alert)
            {
                (alerts ??= []).Add(alert);
                OnAlertRaised(alert);
            }
        }

        return alerts is null ? Array.Empty<Alert>() : alerts;
    }

    // "?." means nothing happens when nobody has subscribed.
    private void OnAlertRaised(Alert alert) => AlertRaised?.Invoke(this, new AlertRaisedEventArgs(alert));
}
