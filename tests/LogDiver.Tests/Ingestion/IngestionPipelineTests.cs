using System.Globalization;
using LogDiver.Core.Ingestion;

namespace LogDiver.Tests.Ingestion;

// I had AI generate all the tests.
public class IngestionPipelineTests
{
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(5);

    [Fact]
    public async Task RunAsync_SeveralSources_DeliversEveryEventAndKeepsOrderPerSource()
    {
        var received = new List<string>();
        LogInput[] inputs = [Input("a", NumberedLines("a", 200)), Input("b", NumberedLines("b", 300))];

        var result = await new IngestionPipeline().RunAsync(inputs, e => received.Add(e.RawLine));

        Assert.Equal(500, received.Count);
        Assert.Equal(500, result.TotalEventsParsed);
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
    public async Task RunAsync_HandlerFails_StopsProducersInsteadOfHanging()
    {
        // A channel of size 1 and a consumer that crashes: without "stopAll" the producer would wait forever.
        var pipeline = new IngestionPipeline(channelCapacity: 1);
        var input = Input("big", NumberedLines("big", 10_000));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => pipeline.RunAsync([input], _ => throw new InvalidOperationException("handler failed"))
                .WaitAsync(TestTimeout));
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
            .Select(line => int.Parse(line[(prefix.Length + 4)..], CultureInfo.InvariantCulture))
            .ToList();
        return numbers.SequenceEqual(Enumerable.Range(0, numbers.Count));
    }
}
