namespace LogDiver.Core.Events;

// What happened in a single log line, independent of the log format it came from.
public enum EventKind
{
    //Not set. Parsers never produce this value.
    Unknown = 0,

    //A login attempt was rejected (wrong password, unknown user, rejected key).
    LoginFailed,

    //Login attempt was accepted.
    LoginSucceeded,

    //An HTTP request was served by a web server.
    HttpRequest,
}
