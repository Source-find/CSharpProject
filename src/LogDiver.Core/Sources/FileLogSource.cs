using System.Runtime.CompilerServices;
using System.Text;

namespace LogDiver.Core.Sources;

// Reads a log file once, from top to bottom. Used by the analyze command.
public sealed class FileLogSource : ILogSource
{
    private const int ReaderBufferSize = 4096;

    // The sharing flags let a server keep writing to the file (or rotate it) while we read.
    // FileStream's own buffer is off, because StreamReader already has one.
    private static readonly FileStreamOptions ReadOptions = new()
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.ReadWrite | FileShare.Delete,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        BufferSize = 0,
    };

    private readonly string _path;
    private readonly int _maxLineLength;

    // The file isn't opened until someone starts reading lines.
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

    public string Name => _path;

    public async IAsyncEnumerable<string> ReadLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(_path, ReadOptions);
        using var textReader = new StreamReader(
            stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, ReaderBufferSize, leaveOpen: true);
        using var lineReader = new BoundedLineReader(textReader, _maxLineLength);

        while (await lineReader.ReadLineAsync(cancellationToken) is { } line)
        {
            yield return line;
        }
    }
}
