using System.Runtime.CompilerServices;

namespace LogDiver.Core.Sources;

// Reads a log file once, from the first line to the last. Used by the <c>analyze</c> command.
public sealed class FileLogSource : ILogSource
{
    private readonly string _path;
    private readonly int _maxLineLength;

    // Creates a source for the file at <paramref name="path"/>. The file is not opened until enumeration starts.
    public FileLogSource(string path)
        : this(path, BoundedLineReader.DefaultMaxLineLength)
    {
    }

    internal FileLogSource(string path, int maxLineLength)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = path;
        _maxLineLength = maxLineLength;
    }

    /// <inheritdoc />
    public string Name => _path;

    /// <inheritdoc />
    public async IAsyncEnumerable<string> ReadLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await using var stream = LogFile.OpenForReading(_path);
        using var textReader = LogFile.CreateReader(stream);
        using var lineReader = new BoundedLineReader(textReader, returnPartialLineAtEnd: true, _maxLineLength);

        while (await lineReader.ReadLineAsync(cancellationToken) is { } line)
        {
            yield return line;
        }
    }
}
