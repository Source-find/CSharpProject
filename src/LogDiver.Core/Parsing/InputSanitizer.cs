namespace LogDiver.Core.Parsing;

// Makes text from a log safe to store and show: shortens it and replaces characters
// that could mess with the terminal (escape codes) or flip the text direction (bidi).
internal static class InputSanitizer
{
    public const int MaxRawLineLength = 4096;
    public const int MaxHostLength = 255;
    public const int MaxUserLength = 64;
    public const int MaxHttpMethodLength = 32;
    public const int MaxRequestPathLength = 2048;
    public const int MaxUserAgentLength = 512;
    public const char ReplacementCharacter = '?';

    private const int StackAllocThreshold = 256;

    // Shortens the text to maxLength and replaces unsafe characters with '?'.
    public static string Sanitize(ReadOnlySpan<char> value, int maxLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxLength);

        var text = value.Length > maxLength ? value[..maxLength] : value;
        if (IndexOfUnsafeCharacter(text) < 0)
        {
            return text.ToString();
        }

        // Only needed when there is something to replace. Small texts use the stack, large ones the heap.
        Span<char> buffer = text.Length <= StackAllocThreshold
            ? stackalloc char[text.Length]
            : new char[text.Length];

        for (var i = 0; i < text.Length; i++)
        {
            buffer[i] = IsUnsafe(text[i]) ? ReplacementCharacter : text[i];
        }

        return new string(buffer);
    }

    private static int IndexOfUnsafeCharacter(ReadOnlySpan<char> text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            if (IsUnsafe(text[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool IsUnsafe(char c) =>
        char.IsControl(c)
        || c is >= '‪' and <= '‮'
        || c is >= '⁦' and <= '⁩';
}
