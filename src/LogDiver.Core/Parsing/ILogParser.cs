using System.Diagnostics.CodeAnalysis;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

/// <summary>
/// Turns a single log line into a <see cref="LogEvent"/>.
/// </summary>
public interface ILogParser
{
    /// <summary>The log format this parser understands.</summary>
    LogFormat Format { get; }

    /// <summary>
    /// Tries to parse one line. Returns <c>false</c> for malformed lines and for lines that are valid but not
    /// security-relevant. Never throws on bad input, because log lines are untrusted.
    /// </summary>
    bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent);
}
