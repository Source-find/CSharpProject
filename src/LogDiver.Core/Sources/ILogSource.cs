namespace LogDiver.Core.Sources;

// Somewhere log lines come from, such as a file on disk.
public interface ILogSource
{
    // A human-readable name for the source, for example the file path.
    string Name { get; }

    // Streams the lines of the source one at a time, without line breaks. Nothing is read until the
    // enumeration starts, and resources are released when the enumeration ends or is disposed.
    IAsyncEnumerable<string> ReadLinesAsync(CancellationToken cancellationToken = default);
}
