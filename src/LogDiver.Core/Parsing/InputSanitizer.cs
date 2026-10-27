namespace LogDiver.Core.Parsing;

/// <summary>
/// Makes attacker-controlled log text safe to store and display: limits its length and replaces characters
/// that can manipulate a terminal (ANSI escape sequences) or reverse how text is displayed (Unicode bidi overrides).
/// </summary>
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

    /// <summary>
    /// Returns <paramref name="value"/> cut to <paramref name="maxLength"/> characters, with unsafe characters
    /// replaced by <see cref="ReplacementCharacter"/>. Allocates exactly one string.
    /// </summary>
    public static string Sanitize(ReadOnlySpan<char> value, int maxLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxLength);

        var text = value.Length > maxLength ? value[..maxLength] : value;
        if (IndexOfUnsafeCharacter(text) < 0)
        {
            return text.ToString();
        }

        // Rare path: copy into a temporary buffer, on the stack when it is small enough.
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
