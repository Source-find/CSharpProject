namespace LogDiver.Core.Detection;

// Sent with the DetectionEngine.AlertRaised event: the alert that was just found.
public sealed class AlertRaisedEventArgs : EventArgs
{
    public AlertRaisedEventArgs(Alert alert)
    {
        ArgumentNullException.ThrowIfNull(alert);
        Alert = alert;
    }

    public Alert Alert { get; }
}
