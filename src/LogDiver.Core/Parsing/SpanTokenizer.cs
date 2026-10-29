namespace LogDiver.Core.Parsing;

// Splits a line into fields (words, "quoted" and [bracketed] text) without copying it.
// Every field is a slice of the original line, so nothing new is allocated.
internal ref struct SpanTokenizer
{
    private ReadOnlySpan<char> _remaining;

    public SpanTokenizer(ReadOnlySpan<char> text)
    {
        _remaining = text;
    }

    // The part of the line that hasn't been read yet.
    public readonly ReadOnlySpan<char> Remaining => _remaining;

    // Reads the next word. Extra spaces are skipped.
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

    // Reads text between two characters, for example [ and ].
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

    // Reads text between double quotes. A quote with a backslash in front belongs to the text.
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
