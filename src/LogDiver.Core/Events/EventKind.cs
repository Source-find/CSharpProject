namespace LogDiver.Core.Events;

// What happened in a log line, no matter which log format it came from.
public enum EventKind
{
    // Default value. Parsers never return this.
    Unknown = 0,

    // A login was rejected (wrong password, unknown user or rejected key).
    LoginFailed,

    // A login succeeded.
    LoginSucceeded,

    // A web server handled an HTTP request.
    HttpRequest,
}
