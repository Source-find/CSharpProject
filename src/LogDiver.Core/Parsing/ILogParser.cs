using System.Diagnostics.CodeAnalysis;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

// Turns one log line into a LogEvent.
public interface ILogParser
{
    // AI used to understand the log format and write this parser.
    // Returns false for broken or invalid lines.
    // Never throws, because log lines can't be trusted.
    bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent);
}
