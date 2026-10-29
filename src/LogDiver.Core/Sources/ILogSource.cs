namespace LogDiver.Core.Sources;

// Something log lines come from, such as a file.
public interface ILogSource
{
    // A name to show the user, such as the file path.
    string Name { get; }

    // Returns the lines one by one. Nothing is read until you start looping,
    // and the file is closed when the loop ends.
    IAsyncEnumerable<string> ReadLinesAsync(CancellationToken cancellationToken = default);
}
