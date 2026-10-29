using LogDiver.Core.Sources;

namespace LogDiver.Tests.Sources;

public class BoundedLineReaderTests
{
    [Fact]
    public async Task ReadLineAsync_UnixAndWindowsLineEndings_ReturnsLinesWithoutLineBreaks()
    {
        using var reader = CreateReader("first\nsecond\r\n\nfourth\n", returnPartialLineAtEnd: true);

        Assert.Equal("first", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("second", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal(string.Empty, await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("fourth", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LinesLongerThanBuffer_AreJoinedCorrectly()
    {
        using var reader = CreateReader("abcdefghij\nklmnop\n", returnPartialLineAtEnd: true, bufferSize: 4);

        Assert.Equal("abcdefghij", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("klmnop", await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LastLineWithoutLineBreak_ReturnedWhenPartialLinesAllowed()
    {
        using var reader = CreateReader("complete\nunfinished", returnPartialLineAtEnd: true);

        Assert.Equal("complete", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("unfinished", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LastLineWithoutLineBreak_HeldBackWhenTailing()
    {
        using var reader = CreateReader("complete\nunfinished", returnPartialLineAtEnd: false);

        Assert.Equal("complete", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LineLongerThanMaximum_IsTruncatedAndNextLineIsIntact()
    {
        using var reader = CreateReader(
            new string('x', 100) + "\nnext\n", returnPartialLineAtEnd: true, maxLineLength: 10, bufferSize: 7);

        Assert.Equal(new string('x', 10), await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("next", await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_CancelledToken_Throws()
    {
        using var reader = CreateReader("line\n", returnPartialLineAtEnd: true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await reader.ReadLineAsync(new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task ReadLineAsync_AfterDispose_Throws()
    {
        var reader = CreateReader("line\n", returnPartialLineAtEnd: true);
        reader.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await reader.ReadLineAsync(CancellationToken.None));
    }

    private static BoundedLineReader CreateReader(
        string text,
        bool returnPartialLineAtEnd,
        int maxLineLength = BoundedLineReader.DefaultMaxLineLength,
        int bufferSize = BoundedLineReader.DefaultBufferSize) =>
        new(new StringReader(text), returnPartialLineAtEnd, maxLineLength, bufferSize);
}
