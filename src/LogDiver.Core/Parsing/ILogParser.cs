using System.Diagnostics.CodeAnalysis;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

// Turns one log line into a LogEvent.
public interface ILogParser
{
    // The log format this parser reads.
    LogFormat Format { get; }

    // Returns false for broken lines and for lines we don't care about.
    // Never throws, because log lines can't be trusted.
    bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent);
}
