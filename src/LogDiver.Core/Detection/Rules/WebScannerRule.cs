using System.Globalization;
using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Core.Detection.Rules;

// Web scanner: many requests for pages that don't exist (404 Not Found) from the same IP within a short
// time (default 30 within 60 seconds). Tools that guess file and folder names cause exactly this pattern.
public sealed class WebScannerRule : IDetectionRule
{
    public const int DefaultThreshold = 30;

    private const int NotFoundStatusCode = 404;

    private readonly int _threshold;
    private readonly TimeSpan _window;
    private readonly SlidingWindowCounter<IPAddress> _notFoundByIp;

    public WebScannerRule()
        : this(DefaultThreshold, DefaultWindow)
    {
    }

    public WebScannerRule(int threshold, TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);
        _threshold = threshold;
        _window = window;
        _notFoundByIp = new SlidingWindowCounter<IPAddress>(window);
    }

    public static TimeSpan DefaultWindow { get; } = TimeSpan.FromSeconds(60);

    public string Name => "WebScanner";

    public Alert? Evaluate(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (logEvent.Kind != EventKind.HttpRequest
            || logEvent.StatusCode != NotFoundStatusCode
            || logEvent.SourceIp is null)
        {
            return null;
        }

        var notFound = _notFoundByIp.Add(logEvent.SourceIp, logEvent.Timestamp);
        if (notFound < _threshold)
        {
            return null;
        }

        _notFoundByIp.Reset(logEvent.SourceIp);
        return new Alert(
            Name,
            AlertSeverity.Medium,
            logEvent.Timestamp,
            logEvent.SourceIp,
            string.Create(
                CultureInfo.InvariantCulture,
                $"{notFound} requests for missing pages from {logEvent.SourceIp} within {_window.TotalSeconds} seconds"));
    }
}
