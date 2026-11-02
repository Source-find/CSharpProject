using System.Threading.Channels;
using LogDiver.Core.Events;

namespace LogDiver.Core.Ingestion;

// Mostly done by AI. Comments added by me.
// Reads several logs in parallel and hands every parsed event to one consumer.
//
//   file 1 --[producer task]--+
//                             +--> bounded Channel<LogEvent> --> [one consumer] --> onEvent(event)
//   file 2 --[producer task]--+
//
// One producer per file makes reading parallel. A single consumer means onEvent is never called from
// two threads at once, so the detection rules don't need locks. The channel is bounded, when it is
// full, producers wait instead of filling memory with unhandled events. Thus saving memory.
public sealed class IngestionPipeline
{
    public const int DefaultChannelCapacity = 10_000;

    private readonly int _channelCapacity;

    public IngestionPipeline(int channelCapacity = DefaultChannelCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(channelCapacity, 1);
        _channelCapacity = channelCapacity;
    }

    // Runs until every log has been read and every event handled. If a log can't be read or onEvent
    // throws, everything else is stopped and that exception is thrown. Cancelling the token stops the run.
    public async Task<IngestionResult> RunAsync(
        IEnumerable<LogInput> inputs, Action<LogEvent> onEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(onEvent);

        var channel = Channel.CreateBounded<LogEvent>(new BoundedChannelOptions(_channelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
        });

        // Cancelled by the caller, or by us when one part fails, so the other parts stop too.
        using var stopAll = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var producers = inputs
            .Select(input => Task.Run(() => ProduceAsync(input, channel.Writer, stopAll), stopAll.Token))
            .ToList();

        var producing = WaitForProducersAsync(producers, channel.Writer);
        var consuming = ConsumeAsync(channel.Reader, onEvent, stopAll);

        await Task.WhenAll(producing, consuming);
        return new IngestionResult(await producing);
    }

    // Reads one log, parses each line and writes the events into the channel.
    private static async Task<SourceSummary> ProduceAsync(
        LogInput input, ChannelWriter<LogEvent> writer, CancellationTokenSource stopAll)
    {
        long linesRead = 0;
        long eventsParsed = 0;

        try
        {
            await foreach (var line in input.Source.ReadLinesAsync(stopAll.Token))
            {
                linesRead++;
                if (input.Parser.TryParse(line, out var logEvent))
                {
                    eventsParsed++;
                    await writer.WriteAsync(logEvent, stopAll.Token); // Waits while the channel is full.
                }
            }
        }
        catch
        {
            await stopAll.CancelAsync(); // Stop the other producers and the consumer, then report the error.
            throw;
        }

        return new SourceSummary(input.Source.Name, linesRead, eventsParsed);
    }

    // Waits for all producers, then tells the consumer that no more events are coming.
    private static async Task<SourceSummary[]> WaitForProducersAsync(
        List<Task<SourceSummary>> producers, ChannelWriter<LogEvent> writer)
    {
        try
        {
            return await Task.WhenAll(producers);
        }
        finally
        {
            writer.TryComplete();
        }
    }

    // Hands each event to onEvent, one at a time, until the channel is empty and completed.
    private static async Task ConsumeAsync(
        ChannelReader<LogEvent> reader, Action<LogEvent> onEvent, CancellationTokenSource stopAll)
    {
        try
        {
            await foreach (var logEvent in reader.ReadAllAsync(stopAll.Token))
            {
                onEvent(logEvent);
            }
        }
        catch
        {
            await stopAll.CancelAsync(); // Otherwise producers could wait forever on a full channel.
            throw;
        }
    }
}
