using LogDiver.Core.Events;

namespace LogDiver.Core.Detection;

// Strategy pattern: every detection rule is its own class behind this interface. The engine only knows
// this interface, so rules can be added, removed and tested one at a time without touching the engine.
public interface IDetectionRule
{
    // The name shown in alerts, for example "BruteForce".
    string Name { get; }

    // Looks at one event and returns an alert if it is suspicious, otherwise null.
    // A rule may remember earlier events, for example to count failed logins per IP.
    Alert? Evaluate(LogEvent logEvent);
}
