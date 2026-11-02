using LogDiver.Core.Parsing;
using LogDiver.Core.Sources;

namespace LogDiver.Core.Ingestion;

// The log input is a combination of a log source and a log parser. 
// The log source is responsible for providing the raw log data, while the log parser is responsible for parsing the raw log data.
public sealed record LogInput(ILogSource Source, ILogParser Parser);
