using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

// Raises whatever alerts a test wants, without running any detection.
internal sealed class FakeAlertPublisher : IAlertPublisher
{
    public event EventHandler<AlertRaisedEventArgs>? AlertRaised;

    public void Raise(Alert alert) => AlertRaised?.Invoke(this, new AlertRaisedEventArgs(alert));
}
