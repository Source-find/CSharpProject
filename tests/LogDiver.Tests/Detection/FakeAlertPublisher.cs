using LogDiver.Core.Detection;

namespace LogDiver.Tests.Detection;

// Raises whatever alerts a test wants, and can tell how many handlers are subscribed.
internal sealed class FakeAlertPublisher : IAlertPublisher
{
    public event EventHandler<AlertRaisedEventArgs>? AlertRaised;

    public int SubscriberCount => AlertRaised?.GetInvocationList().Length ?? 0;

    public void Raise(Alert alert) => AlertRaised?.Invoke(this, new AlertRaisedEventArgs(alert));
}
