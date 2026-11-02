namespace LogDiver.Core.Detection;

// Sent with the DetectionEngine.AlertRaised event. Means that the alert that was just picked up by the detection engine.
public sealed class AlertRaisedEventArgs : EventArgs
{
    public AlertRaisedEventArgs(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        Alert = alert;
    }

    public Alert Alert { get; }
}
