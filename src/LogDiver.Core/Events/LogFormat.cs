namespace LogDiver.Core.Events;

/// The log formats LogDiver can read.
public enum LogFormat
{
    // Not set. Parsers never produce this value.
    Unknown = 0,

    // OpenSSH server lines from a syslog auth log, for example <c>/var/log/auth.log</c>
    SshAuth,

    // Apache/Nginx access log in the "common" or "combined" format
    WebAccess,
}
