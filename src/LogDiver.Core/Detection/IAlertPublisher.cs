namespace LogDiver.Core.Detection;

// Anything that raises alerts, such as the DetectionEngine. Subscribers depend on this interface instead of
// the engine itself, so they keep working when the engine changes, and tests can raise alerts directly.
public interface IAlertPublisher
{
    event EventHandler<AlertRaisedEventArgs>? AlertRaised;
}
