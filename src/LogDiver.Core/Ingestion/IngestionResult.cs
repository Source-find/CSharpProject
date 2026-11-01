namespace LogDiver.Core.Ingestion;

// How much was read from one log.
public sealed record SourceSummary(string SourceName, long LinesRead, long EventsParsed)
{
    // Lines that were broken or not security-relevant.
    public long LinesSkipped => LinesRead - EventsParsed;
}

// The outcome of a pipeline run: one summary per log in order.
public sealed record IngestionResult(IReadOnlyList<SourceSummary> Sources)
{
    public long TotalEventsParsed => Sources.Sum(source => source.EventsParsed);
}
