using System.Runtime.CompilerServices;

namespace LogDiver.Core.Sources;

// Follows a log file and returns new lines as they are written, like <c>tail -f</c>.
// Used by the <c>watch</c> command.
// The file is polled instead of watched with <see cref="FileSystemWatcher"/>, which can lose or duplicate
// events and does not work reliably on network drives. Polling costs one size check per interval while idle.

// Log rotation (the file being renamed and recreated, or truncated in place) is detected by the file at the
// path becoming shorter than what has already been read. The file is then reopened from the start.
// The enumeration only ends when the cancellation token is cancelled.
public sealed class TailingFileLogSource : ILogSource
{
    private readonly string _path;
    private readonly TailOptions _options;

    // Creates a source that follows the file at <paramref name="path"/>.
    public TailingFileLogSource(string path, TailOptions? options = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        options ??= TailOptions.Default;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(options.PollInterval, TimeSpan.Zero);

        _path = path;
        _options = options;
    }

    /// <inheritdoc />
    public string Name => _path;

    /// <inheritdoc />
    public async IAsyncEnumerable<string> ReadLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var isFirstOpen = true;

        while (true)
        {
            // The first open fails loudly if the file is missing. After a rotation, wait for the new file.
            await using var stream = isFirstOpen
                ? LogFile.OpenForReading(_path)
                : await WaitForFileAsync(cancellationToken);

            if (isFirstOpen && _options.StartAtEnd)
            {
                stream.Seek(0, SeekOrigin.End);
            }

            isFirstOpen = false;

            using var textReader = LogFile.CreateReader(stream);
            using var lineReader = new BoundedLineReader(textReader, returnPartialLineAtEnd: false);

            while (true)
            {
                var line = await lineReader.ReadLineAsync(cancellationToken);
                if (line is not null)
                {
                    yield return line;
                    continue;
                }

                if (WasRotated(stream))
                {
                    break; // Dispose this file and reopen the new one from the start.
                }

                await Task.Delay(_options.PollInterval, cancellationToken);
            }
        }
    }

    // The file at the path is shorter than what we have read: it was truncated, or renamed and replaced
    // by a new file. A missing file means rotation is still in progress, so keep reading the old one for now.
    private bool WasRotated(FileStream stream) =>
        LogFile.TryGetLength(_path) is { } currentLength && currentLength < stream.Position;

    private async Task<FileStream> WaitForFileAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var stream = LogFile.TryOpenForReading(_path);
            if (stream is not null)
            {
                return stream;
            }

            await Task.Delay(_options.PollInterval, cancellationToken);
        }
    }
}
