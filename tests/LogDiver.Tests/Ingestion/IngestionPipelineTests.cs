using System.Collections.Concurrent;
using LogDiver.Core.Events;
using LogDiver.Core.Ingestion;
using LogDiver.Core.Parsing;
using LogDiver.Core.Sources;
using LogDiver.Tests.Sources;

namespace LogDiver.Tests.Ingestion;

public class IngestionPipelineTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task RunAsync_SingleSource_DeliversParsedEventsInOrderAndCountsLines()
    {
        var received = new List<string>();
        var input = Input("auth.log", ["ok 1", "noise", "ok 2", "ok 3"]);

        var result = await new IngestionPipeline().RunAsync([input], e => received.Add(e.RawLine));

        Assert.Equal("ok 1|ok 2|ok 3", string.Join('|', received));
        var summary = Assert.Single(result.Sources);
        Assert.Equal("auth.log", summary.SourceName);
        Assert.Equal(4, summary.LinesRead);
        Assert.Equal(3, summary.EventsParsed);
        Assert.Equal(1, summary.LinesSkipped);
    }

    [Fact]
    public async Task RunAsync_SeveralSources_DeliversEveryEventAndKeepsOrderPerSource()
    {
        var received = new List<string>();
        LogInput[] inputs = [Input("a", NumberedLines("a", 200)), Input("b", NumberedLines("b", 300))];

        var result = await new IngestionPipeline().RunAsync(inputs, e => received.Add(e.RawLine));

        Assert.Equal(500, received.Count);
        Assert.Equal(500, result.TotalEventsParsed);
        Assert.Equal("a|b", string.Join('|', result.Sources.Select(s => s.SourceName)));
        Assert.True(IsInOrder(received, "a"));
        Assert.True(IsInOrder(received, "b"));
    }

    [Fact]
    public async Task RunAsync_ManySources_NeverCallsHandlerFromTwoThreadsAtOnce()
    {
        var inputs = Enumerable.Range(0, 8).Select(i => Input($"log{i}", NumberedLines($"log{i}", 200))).ToList();
        var active = 0;
        var overlapped = false;

        await new IngestionPipeline().RunAsync(inputs, _ =>
        {
            if (Interlocked.Increment(ref active) > 1)
            {
                overlapped = true;
            }

            Thread.SpinWait(50);
            Interlocked.Decrement(ref active);
        });

        Assert.False(overlapped);
    }

    [Fact]
    public async Task RunAsync_ChannelOfSizeOne_StillDeliversEverything()
    {
        var count = 0;

        await new IngestionPipeline(channelCapacity: 1)
            .RunAsync([Input("big", NumberedLines("big", 2000))], _ => count++);

        Assert.Equal(2000, count);
    }

    [Fact]
    public async Task RunAsync_SourceFails_ThrowsItsException()
    {
        LogInput[] inputs =
        [
            Input("good", NumberedLines("good", 1000)),
            new(new InMemoryLogSource("broken", ["ok 1"], failAtEnd: true), new PrefixParser()),
        ];

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new IngestionPipeline().RunAsync(inputs, _ => { }).WaitAsync(TestTimeout));

        Assert.Contains("broken", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_HandlerFails_StopsProducersInsteadOfHanging()
    {
        // A full channel of size 1 and a consumer that crashes: without "stopAll" the producer would wait forever.
        var pipeline = new IngestionPipeline(channelCapacity: 1);
        var input = Input("big", NumberedLines("big", 10_000));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => pipeline.RunAsync([input], _ => throw new InvalidOperationException("handler failed"))
                .WaitAsync(TestTimeout));
    }

    [Fact]
    public async Task RunAsync_Cancelled_ThrowsOperationCanceled()
    {
        var input = Input("big", NumberedLines("big", 10_000));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new IngestionPipeline().RunAsync([input], _ => { }, new CancellationToken(canceled: true)));
    }

    [Fact]
    public async Task RunAsync_NoSources_ReturnsEmptyResult()
    {
        var result = await new IngestionPipeline().RunAsync([], _ => { });

        Assert.Empty(result.Sources);
        Assert.Equal(0, result.TotalLinesRead);
    }

    [Fact]
    public async Task RunAsync_RealFileAndParser_ProducesWebEvents()
    {
        using var file = new TempLogFile();
        await File.WriteAllTextAsync(file.Path,
            "203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 200 512\n" +
            "this line is garbage\n" +
            "203.0.113.9 - - [27/Oct/2026:14:03:12 +0100] \"GET /admin HTTP/1.1\" 404 0\n");
        var events = new ConcurrentQueue<LogEvent>();

        var result = await new IngestionPipeline().RunAsync(
            [new LogInput(new FileLogSource(file.Path), new WebAccessLogParser())], events.Enqueue);

        Assert.Equal(3, result.TotalLinesRead);
        Assert.Equal("/|/admin", string.Join('|', events.Select(e => e.RequestPath)));
    }

    [Fact]
    public void Constructor_CapacityBelowOne_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new IngestionPipeline(channelCapacity: 0));
    }

    private static LogInput Input(string name, string[] lines) =>
        new(new InMemoryLogSource(name, lines), new PrefixParser());

    private static string[] NumberedLines(string prefix, int count) =>
        Enumerable.Range(0, count).Select(i => $"ok {prefix} {i}").ToArray();

    // True if the events from one source arrived in the same order as its lines.
    private static bool IsInOrder(List<string> received, string prefix)
    {
        var numbers = received
            .Where(line => line.StartsWith($"ok {prefix} ", StringComparison.Ordinal))
            .Select(line => int.Parse(line[(prefix.Length + 4)..], System.Globalization.CultureInfo.InvariantCulture))
            .ToList();
        return numbers.SequenceEqual(Enumerable.Range(0, numbers.Count));
    }
}
