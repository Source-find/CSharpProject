using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace LogDiver.Core.Sources;

// Reads lines from a <see cref="TextReader"/> with a hard limit on line length.
// <see cref="TextReader.ReadLineAsync()"/> has no limit, so a single hostile line without a line break
// (for example a multi-gigabyte HTTP request) would be built into one huge string. This reader keeps at most
// <c>maxLineLength</c> characters of a line and silently drops the rest of it.

// When tailing a file, the writer may not have finished the last line yet. With
// <c>returnPartialLineAtEnd: false</c> an unfinished line is held back until its line break arrives.
//The reader does not own the <see cref="TextReader"/>; the caller disposes it.
internal sealed class BoundedLineReader : IDisposable
{
    public const int DefaultMaxLineLength = 16 * 1024;
    public const int DefaultBufferSize = 4096;

    private readonly TextReader _reader;
    private readonly bool _returnPartialLineAtEnd;
    private readonly int _maxLineLength;
    private readonly int _bufferSize;
    private readonly StringBuilder _line = new();
    private char[] _buffer;
    private int _bufferPosition;
    private int _bufferLength;
    private bool _disposed;

    public BoundedLineReader(
        TextReader reader,
        bool returnPartialLineAtEnd,
        int maxLineLength = DefaultMaxLineLength,
        int bufferSize = DefaultBufferSize)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLineLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 1);

        _reader = reader;
        _returnPartialLineAtEnd = returnPartialLineAtEnd;
        _maxLineLength = maxLineLength;
        _bufferSize = bufferSize;

        // Borrow the buffer instead of allocating it; it goes back to the pool in Dispose.
        _buffer = ArrayPool<char>.Shared.Rent(bufferSize);
    }

    // Returns the next complete line without its line break, or <c>null</c> when no complete line is
    // available yet (end of the data).
    public async ValueTask<string?> ReadLineAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (TryTakeLineFromBuffer(out var line))
            {
                return line;
            }

            _bufferLength = await _reader.ReadAsync(_buffer.AsMemory(0, _bufferSize), cancellationToken);
            _bufferPosition = 0;

            if (_bufferLength == 0)
            {
                return _returnPartialLineAtEnd && _line.Length > 0 ? TakeLine() : null;
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        ArrayPool<char>.Shared.Return(_buffer);
        _buffer = [];
    }

    // Moves buffered characters into the current line. Returns true when a line break completed the line.
    // Kept synchronous because spans cannot live across an <c>await</c>.
    private bool TryTakeLineFromBuffer([NotNullWhen(true)] out string? line)
    {
        var available = _buffer.AsSpan(_bufferPosition, _bufferLength - _bufferPosition);
        var newlineIndex = available.IndexOf('\n');

        if (newlineIndex < 0)
        {
            AppendBounded(available);
            _bufferPosition += available.Length;
            line = null;
            return false;
        }

        AppendBounded(available[..newlineIndex]);
        _bufferPosition += newlineIndex + 1;
        line = TakeLine();
        return true;
    }

    //Appends as much of <paramref name="text"/> as fits; the rest of an over-long line is dropped.
    private void AppendBounded(ReadOnlySpan<char> text)
    {
        var room = _maxLineLength - _line.Length;
        if (room > 0)
        {
            _line.Append(text.Length > room ? text[..room] : text);
        }
    }

    // Returns the current line (without a trailing <c>\r</c> from Windows line endings) and clears it.
    private string TakeLine()
    {
        var length = _line.Length;
        if (length > 0 && _line[length - 1] == '\r')
        {
            length--;
        }

        var line = _line.ToString(0, length);
        _line.Clear();
        return line;
    }
}
