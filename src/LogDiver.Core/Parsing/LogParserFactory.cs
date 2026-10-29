using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

// Factory pattern: creates the right parser for a log format, and can guess the format of a file.
public sealed class LogParserFactory
{
    // How many lines DetectFormat looks at.
    public const int DetectionSampleSize = 100;

    private static readonly LogFormat[] KnownFormats = [LogFormat.SshAuth, LogFormat.WebAccess];

    private readonly TimeProvider _timeProvider;

    // Uses the system clock.
    public LogParserFactory()
        : this(TimeProvider.System)
    {
    }

    // Uses the given clock (tests pass in a fake one).
    public LogParserFactory(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    // Returns a parser for the given format.
    public ILogParser Create(LogFormat format) => format switch
    {
        LogFormat.SshAuth => new SshAuthLogParser(_timeProvider),
        LogFormat.WebAccess => new WebAccessLogParser(),
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, "There is no parser for this log format."),
    };

    // Tries every parser on the first lines and picks the one that understands the most.
    // Returns Unknown if none of them understands anything.
    public LogFormat DetectFormat(IEnumerable<string> sampleLines)
    {
        ArgumentNullException.ThrowIfNull(sampleLines);

        var sample = sampleLines.Take(DetectionSampleSize).ToList();
        var bestFormat = LogFormat.Unknown;
        var bestMatches = 0;

        foreach (var format in KnownFormats)
        {
            var parser = Create(format);
            var matches = sample.Count(line => parser.TryParse(line, out _));
            if (matches > bestMatches)
            {
                bestFormat = format;
                bestMatches = matches;
            }
        }

        return bestFormat;
    }
}
