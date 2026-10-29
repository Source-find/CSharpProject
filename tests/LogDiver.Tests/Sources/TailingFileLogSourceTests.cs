using LogDiver.Core.Sources;

namespace LogDiver.Tests.Sources;

public sealed class TailingFileLogSourceTests : IDisposable
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TailerStartupDelay = TimeSpan.FromMilliseconds(300);

    private static readonly TailOptions FromStart = new()
    {
        PollInterval = TimeSpan.FromMilliseconds(20),
        StartAtEnd = false,
    };

    private readonly TempLogFile _file = new();
    private readonly CancellationTokenSource _timeout = new(TestTimeout);

    [Fact]
    public async Task ReadLinesAsync_ReturnsExistingLinesThenAppendedLines()
    {
        await File.WriteAllTextAsync(_file.Path, "one\ntwo\n");
        await using var lines = Tail(FromStart);

        Assert.Equal("one", await NextAsync(lines));
        Assert.Equal("two", await NextAsync(lines));

        await File.AppendAllTextAsync(_file.Path, "three\n");

        Assert.Equal("three", await NextAsync(lines));
    }

    [Fact]
    public async Task ReadLinesAsync_LineWrittenInTwoParts_ReturnedAsOneLine()
    {
        await File.WriteAllTextAsync(_file.Path, "203.0.113.9 - - [27/Oct");
        await using var lines = Tail(FromStart);

        var next = NextAsync(lines);
        await Task.Delay(TailerStartupDelay);
        await File.AppendAllTextAsync(_file.Path, "/2026]\n");

        Assert.Equal("203.0.113.9 - - [27/Oct/2026]", await next);
    }

    [Fact]
    public async Task ReadLinesAsync_StartAtEnd_SkipsExistingLines()
    {
        await File.WriteAllTextAsync(_file.Path, "old\n");
        await using var lines = Tail(FromStart with { StartAtEnd = true });

        var next = NextAsync(lines);
        await Task.Delay(TailerStartupDelay); // Let the tailer open the file and seek to the end first.
        await File.AppendAllTextAsync(_file.Path, "new\n");

        Assert.Equal("new", await next);
    }

    [Fact]
    public async Task ReadLinesAsync_FileTruncated_ReadsNewContentFromStart()
    {
        await File.WriteAllTextAsync(_file.Path, "first line\nsecond line\n");
        await using var lines = Tail(FromStart);
        Assert.Equal("first line", await NextAsync(lines));
        Assert.Equal("second line", await NextAsync(lines));

        await File.WriteAllTextAsync(_file.Path, "fresh\n"); // copytruncate-style rotation

        Assert.Equal("fresh", await NextAsync(lines));
    }

    [Fact]
    public async Task ReadLinesAsync_FileRenamedAndRecreated_FollowsNewFile()
    {
        await File.WriteAllTextAsync(_file.Path, "first line\nsecond line\n");
        await using var lines = Tail(FromStart);
        Assert.Equal("first line", await NextAsync(lines));
        Assert.Equal("second line", await NextAsync(lines));

        File.Move(_file.Path, _file.RotatedPath); // logrotate-style rotation
        await File.WriteAllTextAsync(_file.Path, "new\n");

        Assert.Equal("new", await NextAsync(lines));
    }

    [Fact]
    public async Task ReadLinesAsync_Cancelled_ThrowsOperationCanceled()
    {
        await File.WriteAllTextAsync(_file.Path, string.Empty);
        using var cancellation = new CancellationTokenSource();
        await using var lines = new TailingFileLogSource(_file.Path, FromStart)
            .ReadLinesAsync(cancellation.Token)
            .GetAsyncEnumerator();

        var next = lines.MoveNextAsync().AsTask();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => next);
    }

    [Fact]
    public async Task ReadLinesAsync_MissingFile_Throws()
    {
        await using var lines = Tail(FromStart);

        await Assert.ThrowsAsync<FileNotFoundException>(() => NextAsync(lines));
    }

    [Fact]
    public void Constructor_ZeroPollInterval_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new TailingFileLogSource(_file.Path, new TailOptions { PollInterval = TimeSpan.Zero }));
    }

    public void Dispose()
    {
        _timeout.Dispose();
        _file.Dispose();
    }

    private IAsyncEnumerator<string> Tail(TailOptions options) =>
        new TailingFileLogSource(_file.Path, options).ReadLinesAsync(_timeout.Token).GetAsyncEnumerator();

    private static async Task<string> NextAsync(IAsyncEnumerator<string> lines)
    {
        Assert.True(await lines.MoveNextAsync());
        return lines.Current;
    }
}
