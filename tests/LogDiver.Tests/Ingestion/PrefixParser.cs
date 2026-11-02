using System.Diagnostics.CodeAnalysis;
using LogDiver.Core.Events;
using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Ingestion;
// AI generated test
// A test parser: lines starting with "ok" become events (with the line as RawLine), others are skipped.
internal sealed class PrefixParser : ILogParser
{
    public bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent)
    {
        if (!line.StartsWith("ok", StringComparison.Ordinal))
        {
            logEvent = null;
            return false;
        }

        logEvent = new LogEvent
        {
            Timestamp = DateTimeOffset.UnixEpoch,
            Format = LogFormat.Unknown,
            Kind = EventKind.Unknown,
            RawLine = line.ToString(),
        };
        return true;
    }
}
