namespace LogDiver.Core.Detection;

// Counts how many times something happened per key (for example per IP address) within a time window
// that moves forward with the log, such as "the last 60 seconds".
// Keys that have been quiet for longer than the window are forgotten, so memory depends on how many keys
// are active right now, not on how many were ever seen.
public sealed class SlidingWindowCounter<TKey>
    where TKey : notnull
{
    private readonly TimeSpan _window;

    // For each key: the times it happened, oldest first.
    private readonly Dictionary<TKey, Queue<DateTimeOffset>> _timesByKey = new();

    // When quiet keys were last removed. Starts at the earliest possible time, so the first Add cleans up.
    private DateTimeOffset _lastCleanup;

    public SlidingWindowCounter(TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        _window = window;
    }

    // Records that something happened for this key at this time, and returns how many times it has
    // happened within the window. Time comes from the log, not the clock.
    public int Add(TKey key, DateTimeOffset time)
    {
        if (!_timesByKey.TryGetValue(key, out var times))
        {
            times = new Queue<DateTimeOffset>();
            _timesByKey[key] = times;
        }

        times.Enqueue(time);
        RemoveOlderThan(times, time - _window);
        RemoveQuietKeys(time);
        return times.Count;
    }

    // Forgets everything about this key, so counting starts over (used after an alert).
    public void Reset(TKey key) => _timesByKey.Remove(key);

    // Drops times from the front of the queue that have slid out of the window.
    private static void RemoveOlderThan(Queue<DateTimeOffset> times, DateTimeOffset cutoff)
    {
        while (times.Count > 0 && times.Peek() < cutoff)
        {
            times.Dequeue();
        }
    }

    // Removes keys with nothing left in the window. Checking every key on every Add would be slow,
    // so this runs at most once per window length.
    private void RemoveQuietKeys(DateTimeOffset now)
    {
        if (now - _lastCleanup < _window)
        {
            return;
        }

        _lastCleanup = now;
        var cutoff = now - _window;
        foreach (var (key, times) in _timesByKey)
        {
            RemoveOlderThan(times, cutoff);
            if (times.Count == 0)
            {
                _timesByKey.Remove(key); // Allowed while looping over a Dictionary since .NET Core 3.0.
            }
        }
    }
}
