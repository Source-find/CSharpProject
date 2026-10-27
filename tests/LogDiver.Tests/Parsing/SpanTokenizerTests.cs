using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;

public class SpanTokenizerTests
{
    [Fact]
    public void TryReadToken_SkipsRepeatedSpaces()
    {
        var tokenizer = new SpanTokenizer("Oct  7 08:00:00");

        Assert.True(tokenizer.TryReadToken(out var month));
        Assert.True(tokenizer.TryReadToken(out var day));
        Assert.True(tokenizer.TryReadToken(out var time));
        Assert.False(tokenizer.TryReadToken(out _));

        Assert.Equal("Oct", month.ToString());
        Assert.Equal("7", day.ToString());
        Assert.Equal("08:00:00", time.ToString());
    }

    [Fact]
    public void TryReadQuoted_EscapedQuote_IsPartOfValue()
    {
        var tokenizer = new SpanTokenizer("\"a \\\"b\\\" c\" rest");

        Assert.True(tokenizer.TryReadQuoted(out var value));
        Assert.Equal("a \\\"b\\\" c", value.ToString());
        Assert.Equal(" rest", tokenizer.Remaining.ToString());
    }

    [Fact]
    public void TryReadQuoted_EscapedBackslashBeforeQuote_EndsValue()
    {
        var tokenizer = new SpanTokenizer("\"a\\\\\" rest");

        Assert.True(tokenizer.TryReadQuoted(out var value));
        Assert.Equal("a\\\\", value.ToString());
    }

    [Fact]
    public void TryReadQuoted_Unterminated_ReturnsFalseAndKeepsPosition()
    {
        var tokenizer = new SpanTokenizer("\"never closed");

        Assert.False(tokenizer.TryReadQuoted(out _));
        Assert.Equal("\"never closed", tokenizer.Remaining.ToString());
    }

    [Fact]
    public void TryReadDelimited_ReadsBracketedValueWithSpaces()
    {
        var tokenizer = new SpanTokenizer("[27/Oct/2026:14:03:11 +0100] \"GET /\"");

        Assert.True(tokenizer.TryReadDelimited('[', ']', out var value));
        Assert.Equal("27/Oct/2026:14:03:11 +0100", value.ToString());
    }
}
