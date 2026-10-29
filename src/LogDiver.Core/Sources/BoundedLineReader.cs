using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace LogDiver.Core.Sources;

// Reads lines with a maximum length, so one huge hostile line can't use up all the memory.
// Anything past the limit is dropped. The caller owns the TextReader and disposes it.
internal sealed class BoundedLineReader : IDisposable
{
    public const int DefaultMaxLineLength = 16 * 1024;
    public const int DefaultBufferSize = 4096;

    private readonly TextReader _reader;
    private readonly int _maxLineLength;
    private readonly int _bufferSize;
    private readonly StringBuilder _line = new();
    private char[] _buffer;
    private int _bufferPosition;
    private int _bufferLength;
    private bool _disposed;

    public BoundedLineReader(
        TextReader reader,
        int maxLineLength = DefaultMaxLineLength,
        int bufferSize = DefaultBufferSize)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxLineLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 1);

        _reader = reader;
        _maxLineLength = maxLineLength;
        _bufferSize = bufferSize;

        // Borrow the buffer from a shared pool; it is given back in Dispose.
        _buffer = ArrayPool<char>.Shared.Rent(bufferSize);
    }

    // Returns the next line, or null at the end of the file.
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
                // The last line may have no line break; return it anyway.
                return _line.Length > 0 ? TakeLine() : null;
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

    // Moves buffered text into the current line. Returns true when the line is complete.
    // Not async, because spans can't be used across an await.
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

    // Adds as much text as fits. The rest of a too-long line is thrown away.
    private void AppendBounded(ReadOnlySpan<char> text)
    {
        var room = _maxLineLength - _line.Length;
        if (room > 0)
        {
            _line.Append(text.Length > room ? text[..room] : text);
        }
    }

    // Returns the current line (without a Windows \r at the end) and clears it.
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
