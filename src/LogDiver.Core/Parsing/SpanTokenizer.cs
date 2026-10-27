namespace LogDiver.Core.Parsing;

/// <summary>
/// Reads space-separated, quoted and bracketed fields from a line without allocating.
/// Every value it returns is a slice of the original line.
/// </summary>
internal ref struct SpanTokenizer
{
    private ReadOnlySpan<char> _remaining;

    public SpanTokenizer(ReadOnlySpan<char> text)
    {
        _remaining = text;
    }

    /// <summary>The part of the line that has not been read yet.</summary>
    public readonly ReadOnlySpan<char> Remaining => _remaining;

    /// <summary>Reads the next field up to a space. Repeated spaces are skipped.</summary>
    public bool TryReadToken(out ReadOnlySpan<char> token)
    {
        _remaining = _remaining.TrimStart(' ');
        if (_remaining.IsEmpty)
        {
            token = default;
            return false;
        }

        var end = _remaining.IndexOf(' ');
        if (end < 0)
        {
            token = _remaining;
            _remaining = default;
            return true;
        }

        token = _remaining[..end];
        _remaining = _remaining[(end + 1)..];
        return true;
    }

    /// <summary>Reads a field wrapped in <paramref name="open"/> and <paramref name="close"/>, such as <c>[...]</c>.</summary>
    public bool TryReadDelimited(char open, char close, out ReadOnlySpan<char> value)
    {
        value = default;
        var text = _remaining.TrimStart(' ');
        if (text.IsEmpty || text[0] != open)
        {
            return false;
        }

        var end = text.IndexOf(close);
        if (end < 0)
        {
            return false;
        }

        value = text[1..end];
        _remaining = text[(end + 1)..];
        return true;
    }

    /// <summary>
    /// Reads a field wrapped in double quotes. A quote preceded by an odd number of backslashes is escaped
    /// and belongs to the value, which is how Apache and Nginx log quotes inside a field.
    /// </summary>
    public bool TryReadQuoted(out ReadOnlySpan<char> value)
    {
        value = default;
        var text = _remaining.TrimStart(' ');
        if (text.IsEmpty || text[0] != '"')
        {
            return false;
        }

        for (var i = 1; i < text.Length; i++)
        {
            if (text[i] == '"' && !IsEscaped(text, i))
            {
                value = text[1..i];
                _remaining = text[(i + 1)..];
                return true;
            }
        }

        return false;
    }

    private static bool IsEscaped(ReadOnlySpan<char> text, int index)
    {
        var backslashes = 0;
        for (var i = index - 1; i > 0 && text[i] == '\\'; i--)
        {
            backslashes++;
        }

        return backslashes % 2 == 1;
    }
}
