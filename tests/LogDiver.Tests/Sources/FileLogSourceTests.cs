using LogDiver.Core.Sources;

namespace LogDiver.Tests.Sources;

public sealed class FileLogSourceTests : IDisposable
{
    private readonly TempLogFile _file = new();

    [Fact]
    public async Task ReadLinesAsync_ReturnsEveryLineInOrder()
    {
        await File.WriteAllTextAsync(_file.Path, "one\ntwo\nthree");
        var source = new FileLogSource(_file.Path);

        var lines = await ReadAllAsync(source);

        Assert.Equal("one|two|three", string.Join('|', lines));
    }

    [Fact]
    public async Task ReadLinesAsync_EmptyFile_ReturnsNothing()
    {
        await File.WriteAllTextAsync(_file.Path, string.Empty);

        var lines = await ReadAllAsync(new FileLogSource(_file.Path));

        Assert.Empty(lines);
    }

    [Fact]
    public async Task ReadLinesAsync_HugeLineWithoutLineBreak_IsTruncated()
    {
        await File.WriteAllTextAsync(_file.Path, new string('A', 50_000) + "\nnext\n");

        var lines = await ReadAllAsync(new FileLogSource(_file.Path, maxLineLength: 1000));

        Assert.Equal(2, lines.Count);
        Assert.Equal(1000, lines[0].Length);
        Assert.Equal("next", lines[1]);
    }

    [Fact]
    public async Task ReadLinesAsync_MissingFile_ThrowsWhenEnumerationStarts()
    {
        var source = new FileLogSource(_file.Path); // Creating the source does not touch the file.

        await Assert.ThrowsAsync<FileNotFoundException>(() => ReadAllAsync(source));
    }

    [Fact]
    public async Task ReadLinesAsync_CancelledToken_Throws()
    {
        await File.WriteAllTextAsync(_file.Path, "one\ntwo\n");
        var source = new FileLogSource(_file.Path);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => ReadAllAsync(source, new CancellationToken(canceled: true)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyPath_Throws(string path)
    {
        Assert.Throws<ArgumentException>(() => new FileLogSource(path));
    }

    public void Dispose() => _file.Dispose();

    private static async Task<List<string>> ReadAllAsync(
        FileLogSource source, CancellationToken cancellationToken = default)
    {
        var lines = new List<string>();
        await foreach (var line in source.ReadLinesAsync(cancellationToken))
        {
            lines.Add(line);
        }

        return lines;
    }
}
