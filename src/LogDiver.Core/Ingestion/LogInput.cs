using LogDiver.Core.Parsing;
using LogDiver.Core.Sources;

namespace LogDiver.Core.Ingestion;

// A log to analyse: where the lines come from, and the parser that understands them.
public sealed record LogInput(ILogSource Source, ILogParser Parser);
