using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

// Creates the right <see cref="ILogParser"/> for a log format, and can guess the format from sample lines.
public sealed class LogParserFactory
{
    // How many lines <see cref="DetectFormat"/> looks at.
    public const int DetectionSampleSize = 100;

    private static readonly LogFormat[] KnownFormats = [LogFormat.SshAuth, LogFormat.WebAccess];

    private readonly TimeProvider _timeProvider;

    //Creates a factory whose parsers use the system clock.
    public LogParserFactory()
        : this(TimeProvider.System)
    {
    }

    // Creates a factory whose parsers use <paramref name="timeProvider"/>.
    public LogParserFactory(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    // Creates a parser for <paramref name="format"/>.
    public ILogParser Create(LogFormat format) => format switch
    {
        LogFormat.SshAuth => new SshAuthLogParser(_timeProvider),
        LogFormat.WebAccess => new WebAccessLogParser(),
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, "There is no parser for this log format."),
    };

    // Guesses the format by trying every parser on the first <see cref="DetectionSampleSize"/> lines and picking
    // the one that understands the most. Returns <see cref="LogFormat.Unknown"/> if no parser understands any line.
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
