using System.Diagnostics.CodeAnalysis;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;


//Turns a single log line into a <see cref="LogEvent"/>.
public interface ILogParser
{
    //Gets the valid log format.
    LogFormat Format { get; }

    // Tries to parse one line. Returns <c>false</c> for malformed lines and for lines that are valid but not
    // security-relevant. Never throws on bad input, because log lines are untrusted.
    bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent);
}
