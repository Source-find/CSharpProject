using LogDiver.Core.Sources;

namespace LogDiver.Tests.Sources;

public sealed class FileLogSourceTests : IDisposable
{
    private readonly TempLogFile _file = new();

    [Fact]
    public async Task ReadLinesAsync_ReturnsEveryLineInOrder()
    {
        await File.WriteAllTextAsync(_file.Path, "one\ntwo\r\nthree");

        var lines = await ReadAllAsync(new FileLogSource(_file.Path));

        Assert.Equal("one|two|three", string.Join('|', lines));
    }

    [Fact]
    public async Task ReadLinesAsync_HugeLineWithoutLineBreak_IsTruncated()
    {
        // One hostile line must not be able to use up all the memory.
        await File.WriteAllTextAsync(_file.Path, new string('A', 50_000) + "\nnext\n");

        var lines = await ReadAllAsync(new FileLogSource(_file.Path, maxLineLength: 1000));

        Assert.Equal(2, lines.Count);
        Assert.Equal(1000, lines[0].Length);
        Assert.Equal("next", lines[1]);
    }

    public void Dispose() => _file.Dispose();

    private static async Task<List<string>> ReadAllAsync(FileLogSource source)
    {
        var lines = new List<string>();
        await foreach (var line in source.ReadLinesAsync())
        {
            lines.Add(line);
        }

        return lines;
    }
}
