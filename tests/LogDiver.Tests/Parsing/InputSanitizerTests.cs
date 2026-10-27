using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;

public class InputSanitizerTests
{
    [Fact]
    public void Sanitize_PlainText_ReturnsSameText()
    {
        Assert.Equal("GET /index.html", InputSanitizer.Sanitize("GET /index.html", 100));
    }

    [Fact]
    public void Sanitize_ControlCharacters_AreReplaced()
    {
        Assert.Equal("a?b?c?", InputSanitizer.Sanitize("a\tb\u001bc\u007f", 100));
    }

    [Theory]
    [InlineData("‮")]
    [InlineData("⁦")]
    public void Sanitize_BidiControlCharacters_AreReplaced(string bidiCharacter)
    {
        Assert.Equal("abc?txt", InputSanitizer.Sanitize($"abc{bidiCharacter}txt", 100));
    }

    [Fact]
    public void Sanitize_TextLongerThanMax_IsTruncated()
    {
        Assert.Equal("abc", InputSanitizer.Sanitize("abcdef", 3));
    }

    [Fact]
    public void Sanitize_LongTextWithControlCharacter_UsesHeapBufferAndReplaces()
    {
        var input = new string('x', 300) + "\u0007";

        var result = InputSanitizer.Sanitize(input, 1000);

        Assert.Equal(301, result.Length);
        Assert.Equal(InputSanitizer.ReplacementCharacter, result[^1]);
    }

    [Fact]
    public void Sanitize_NegativeMaxLength_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => InputSanitizer.Sanitize("abc", -1));
    }
}
