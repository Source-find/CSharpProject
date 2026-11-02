using System.Globalization;
using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Core.Detection.Rules;

// All done by Ai, comments added by me
// Brute force: many failed logins from the same IP within a short time (default 10 within 60 seconds).
public sealed class BruteForceRule : IDetectionRule
{
    public const int DefaultThreshold = 10;

    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly SlidingWindowCounter<IPAddress> _failuresByIp;

    public BruteForceRule()
        : this(DefaultThreshold, DefaultWindow)
    {
    }
    
    // Creates a new instance of the BruteForceRule with the given threshold and window.
    public BruteForceRule(int threshold, TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);
        _threshold = threshold;
        _window = window;
        _failuresByIp = new SlidingWindowCounter<IPAddress>(window);
    }

    public static TimeSpan DefaultWindow { get; } = TimeSpan.FromSeconds(60);

    public string Name => "BruteForce";
    
    // Evaluates the given log event and returns an alert if it matches the rule. Returns null if it does not match.
    public Alert? Evaluate(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (logEvent.Kind != EventKind.LoginFailed || logEvent.SourceIp is null)
        {
            return null;
        }

        var failures = _failuresByIp.Add(logEvent.SourceIp, logEvent.Timestamp);
        if (failures < _threshold)
        {
            return null;
        }
        
        // If we reach this point, we have detected a brute force attack. 
        // We reset the counter for this IP so that we don't generate multiple alerts for the same burst of failed logins.
        _failuresByIp.Reset(logEvent.SourceIp);
        return new Alert(
            Name,
            AlertSeverity.High,
            logEvent.Timestamp,
            logEvent.SourceIp,
            string.Create(
                CultureInfo.InvariantCulture,
                $"{failures} failed logins from {logEvent.SourceIp} within {_window.TotalSeconds} seconds"));
    }
}
