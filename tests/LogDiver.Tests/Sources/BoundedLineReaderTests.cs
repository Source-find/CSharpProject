using LogDiver.Core.Sources;

namespace LogDiver.Tests.Sources;

public class BoundedLineReaderTests
{
    [Fact]
    public async Task ReadLineAsync_UnixAndWindowsLineEndings_ReturnsLinesWithoutLineBreaks()
    {
        using var reader = CreateReader("first\nsecond\r\n\nfourth\n");

        Assert.Equal("first", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("second", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal(string.Empty, await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("fourth", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LinesLongerThanBuffer_AreJoinedCorrectly()
    {
        using var reader = CreateReader("abcdefghij\nklmnop\n", bufferSize: 4);

        Assert.Equal("abcdefghij", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("klmnop", await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LastLineWithoutLineBreak_IsReturned()
    {
        using var reader = CreateReader("complete\nunfinished");

        Assert.Equal("complete", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("unfinished", await reader.ReadLineAsync(CancellationToken.None));
        Assert.Null(await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_LineLongerThanMaximum_IsTruncatedAndNextLineIsIntact()
    {
        using var reader = CreateReader(
            new string('x', 100) + "\nnext\n", maxLineLength: 10, bufferSize: 7);

        Assert.Equal(new string('x', 10), await reader.ReadLineAsync(CancellationToken.None));
        Assert.Equal("next", await reader.ReadLineAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ReadLineAsync_CancelledToken_Throws()
    {
        using var reader = CreateReader("line\n");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await reader.ReadLineAsync(new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task ReadLineAsync_AfterDispose_Throws()
    {
        var reader = CreateReader("line\n");
        reader.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => await reader.ReadLineAsync(CancellationToken.None));
    }

    private static BoundedLineReader CreateReader(
        string text,
        int maxLineLength = BoundedLineReader.DefaultMaxLineLength,
        int bufferSize = BoundedLineReader.DefaultBufferSize) =>
        new(new StringReader(text), maxLineLength, bufferSize);
}
