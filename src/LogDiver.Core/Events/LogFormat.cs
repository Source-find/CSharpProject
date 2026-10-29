namespace LogDiver.Core.Events;

// The log formats LogDiver can read.
public enum LogFormat
{
    // Default value. Parsers never return this.
    Unknown = 0,

    // SSH login lines from a Linux auth log (/var/log/auth.log).
    SshAuth,

    // Apache/Nginx access log ("common" or "combined" format).
    WebAccess,
}
