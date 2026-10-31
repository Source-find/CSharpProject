using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using LogDiver.Core.Events;

namespace LogDiver.Core.Detection;

// This is the detection engine, which is meant to build an engine for detection of suspicious activitiy
public sealed partial class DetectionEngine
{
    private const int BruteForceThreshold = 10;
    private const int ScannerThreshold = 30;
    private const int NotFoundStatusCode = 404;

    private static readonly TimeSpan BruteForceWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ScannerWindow = TimeSpan.FromSeconds(60);

    private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _failedLoginsByIp = new();
    private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _notFoundByIp = new();

    // Raised once for every alert Process finds (Observer pattern). Handlers run inside the analysis,
    // so they should be quick. Subscribers must unsubscribe (-=) when done, or the engine keeps them alive.
    public event EventHandler<AlertRaisedEventArgs>? AlertRaised;

    // Checks one event against all rules and returns the alerts caused.
    // Time is taken from the log, so "60 seconds" means 60 seconds in the log.
    public IReadOnlyList<Alert> Process(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        var alerts = new List<Alert>();

        if (logEvent.Kind == EventKind.LoginFailed && logEvent.SourceIp is not null)
        {
            // Brute force: many failed logins from one IP
            if (!_failedLoginsByIp.TryGetValue(logEvent.SourceIp, out var failures))
            {
                failures = new Queue<DateTimeOffset>();
                _failedLoginsByIp[logEvent.SourceIp] = failures;
            }

            failures.Enqueue(logEvent.Timestamp);
            while (failures.Count > 0 && failures.Peek() < logEvent.Timestamp - BruteForceWindow)
            {
                failures.Dequeue();
            }

            if (failures.Count >= BruteForceThreshold)
            {
                alerts.Add(new Alert(
                    "BruteForce",
                    AlertSeverity.High,
                    logEvent.Timestamp,
                    logEvent.SourceIp,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"{failures.Count} failed logins from {logEvent.SourceIp} within {BruteForceWindow.TotalSeconds} seconds")));
                failures.Clear(); // Start counting again, so the next alert needs a new burst.
            }
        }
        else if (logEvent.Kind == EventKind.HttpRequest)
        {
            // Web scanner: many 404 Not Found from one IP (copy of the brute-force code)
            if (logEvent.StatusCode == NotFoundStatusCode && logEvent.SourceIp is not null)
            {
                if (!_notFoundByIp.TryGetValue(logEvent.SourceIp, out var notFound))
                {
                    notFound = new Queue<DateTimeOffset>();
                    _notFoundByIp[logEvent.SourceIp] = notFound;
                }

                notFound.Enqueue(logEvent.Timestamp);
                while (notFound.Count > 0 && notFound.Peek() < logEvent.Timestamp - ScannerWindow)
                {
                    notFound.Dequeue();
                }

                if (notFound.Count >= ScannerThreshold)
                {
                    alerts.Add(new Alert(
                        "WebScanner",
                        AlertSeverity.Medium,
                        logEvent.Timestamp,
                        logEvent.SourceIp,
                        string.Create(
                            CultureInfo.InvariantCulture,
                            $"{notFound.Count} requests for missing pages from {logEvent.SourceIp} within {ScannerWindow.TotalSeconds} seconds")));
                    notFound.Clear();
                }
            }
            // A lot of help gotten from AI
            // Suspicious request: known attack patterns in the path or user agent
            string? attack = null;
            var path = logEvent.RequestPath ?? string.Empty;
            var userAgent = logEvent.UserAgent ?? string.Empty;

            if (PathTraversalRegex().IsMatch(path))
            {
                attack = "path traversal";
            }
            else if (SqlInjectionRegex().IsMatch(path))
            {
                attack = "SQL injection";
            }
            else if (CrossSiteScriptingRegex().IsMatch(path))
            {
                attack = "cross-site scripting";
            }
            else if (SensitiveFileRegex().IsMatch(path))
            {
                attack = "probe for a sensitive file";
            }
            else if (ScannerToolRegex().IsMatch(userAgent))
            {
                attack = "known attack tool";
            }

            if (attack is not null)
            {
                alerts.Add(new Alert(
                    "SuspiciousRequest",
                    attack == "known attack tool" ? AlertSeverity.Medium : AlertSeverity.High,
                    logEvent.Timestamp,
                    logEvent.SourceIp,
                    $"Possible {attack}: {logEvent.HttpMethod} {path}"));
            }
        }

        foreach (var alert in alerts)
        {
            OnAlertRaised(alert);
        }

        return alerts;
    }

    // "?." means nothing happens when nobody has subscribed.
    private void OnAlertRaised(Alert alert) => AlertRaised?.Invoke(this, new AlertRaisedEventArgs(alert));

    // The patterns are kept simple (no nested repetition), so a hostile path can't make them slow (ReDoS).
    [GeneratedRegex(@"\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e(%2f|%5c|/)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PathTraversalRegex();

    [GeneratedRegex(@"union(\s|%20|\+)+(all(\s|%20|\+)+)?select|information_schema|sleep\(|'(\s|%20|\+)*or(\s|%20|\+)*'?1'?(\s|%20|\+)*=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlInjectionRegex();

    [GeneratedRegex(@"<script|%3cscript|javascript:|onerror\s*=", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CrossSiteScriptingRegex();

    [GeneratedRegex(@"/\.env|/\.git/|/wp-admin|/wp-login\.php|/phpmyadmin", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveFileRegex();

    [GeneratedRegex(@"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScannerToolRegex();
}
