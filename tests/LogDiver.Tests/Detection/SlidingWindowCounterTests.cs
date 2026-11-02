using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

public class SlidingWindowCounterTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 27, 9, 0, 0, TimeSpan.Zero);

    private readonly SlidingWindowCounter<string> _counter = new(TimeSpan.FromSeconds(60));

    [Fact]
    public void Add_CountsOnlyTimesInsideTheWindow()
    {
        Assert.Equal(1, _counter.Add("a", Start));
        Assert.Equal(2, _counter.Add("a", Start.AddSeconds(10)));
        Assert.Equal(3, _counter.Add("a", Start.AddSeconds(20)));

        // At 75 s the window is 15-75 s, so only the times at 20 s and 75 s are left.
        Assert.Equal(2, _counter.Add("a", Start.AddSeconds(75)));

        // Other keys are counted separately.
        Assert.Equal(1, _counter.Add("b", Start.AddSeconds(75)));
    }

    [Fact]
    public void Reset_StartsCountingAgain()
    {
        _counter.Add("a", Start);
        _counter.Add("a", Start.AddSeconds(1));

        _counter.Reset("a");

        Assert.Equal(1, _counter.Add("a", Start.AddSeconds(2)));
    }

    [Fact]
    public void QuietKeys_AreForgotten_SoMemoryDoesNotGrowWithEveryKeyEverSeen()
    {
        for (var i = 0; i < 100; i++)
        {
            _counter.Add($"ip{i}", Start);
        }

        Assert.Equal(100, _counter.TrackedKeyCount);

        _counter.Add("new", Start.AddMinutes(2));

        Assert.Equal(1, _counter.TrackedKeyCount);
    }
}
