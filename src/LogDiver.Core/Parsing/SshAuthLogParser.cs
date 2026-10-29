using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

// Reads SSH logins from a Linux auth log (/var/log/auth.log).
// Handles both the old timestamp style (Oct 27 14:03:11, no year) and the newer one
// (2026-10-27T14:03:11+01:00). Only failed and successful logins become events.
public sealed class SshAuthLogParser : ILogParser
{
    private const string FailedPrefix = "Failed ";
    private const string AcceptedPrefix = "Accepted ";
    private const string ForSeparator = " for ";
    private const string InvalidUserPrefix = "invalid user ";
    private const string FromSeparator = " from ";
    private const string PortKeyword = "port";
    private const string ClassicTimeFormat = "HH:mm:ss";
    private const int AllowedClockSkewDays = 1;

    private static readonly string[] MonthAbbreviations =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    private readonly TimeProvider _timeProvider;

    // Uses the system clock to work out the year (the old timestamp style has none).
    public SshAuthLogParser()
        : this(TimeProvider.System)
    {
    }

    // Uses the given clock (tests pass in a fake one).
    public SshAuthLogParser(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    public LogFormat Format => LogFormat.SshAuth;

    public bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent)
    {
        logEvent = null;
        var tokenizer = new SpanTokenizer(line);

        if (!TryReadTimestamp(ref tokenizer, out var timestamp)
            || !tokenizer.TryReadToken(out var host)
            || !tokenizer.TryReadToken(out var program)
            || !IsSshDaemon(program))
        {
            return false;
        }

        var message = tokenizer.Remaining.Trim();
        if (!TryParseLoginMessage(message, out var kind, out var user, out var sourceIp))
        {
            return false;
        }

        logEvent = new LogEvent
        {
            Timestamp = timestamp,
            Format = LogFormat.SshAuth,
            Kind = kind,
            RawLine = InputSanitizer.Sanitize(line, InputSanitizer.MaxRawLineLength),
            Host = InputSanitizer.Sanitize(host, InputSanitizer.MaxHostLength),
            User = InputSanitizer.Sanitize(user, InputSanitizer.MaxUserLength),
            SourceIp = sourceIp,
        };
        return true;
    }

    private bool TryReadTimestamp(ref SpanTokenizer tokenizer, out DateTimeOffset timestamp)
    {
        timestamp = default;
        if (!tokenizer.TryReadToken(out var first))
        {
            return false;
        }

        if (char.IsAsciiDigit(first[0]))
        {
            return DateTimeOffset.TryParse(
                first, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out timestamp);
        }

        return TryParseMonth(first, out var month)
            && tokenizer.TryReadToken(out var dayToken)
            && int.TryParse(dayToken, NumberStyles.None, CultureInfo.InvariantCulture, out var day)
            && tokenizer.TryReadToken(out var timeToken)
            && TimeOnly.TryParseExact(
                timeToken, ClassicTimeFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)
            && TryBuildClassicTimestamp(month, day, time, out timestamp);
    }

    // The old timestamp style has no year. Use this year, unless the date is in the future,
    // which means the line is from last year (a December log read in January).
    private bool TryBuildClassicTimestamp(int month, int day, TimeOnly time, out DateTimeOffset timestamp)
    {
        timestamp = default;
        var now = _timeProvider.GetLocalNow();
        var year = IsLaterInYear(month, day, now) ? now.Year - 1 : now.Year;
        if (day < 1 || day > DateTime.DaysInMonth(year, month))
        {
            return false;
        }

        var localTime = new DateOnly(year, month, day).ToDateTime(time);
        timestamp = new DateTimeOffset(localTime, _timeProvider.LocalTimeZone.GetUtcOffset(localTime));
        return true;
    }

    private static bool IsLaterInYear(int month, int day, DateTimeOffset now) =>
        month > now.Month || (month == now.Month && day > now.Day + AllowedClockSkewDays);

    private static bool TryParseMonth(ReadOnlySpan<char> token, out int month)
    {
        for (var i = 0; i < MonthAbbreviations.Length; i++)
        {
            if (token.SequenceEqual(MonthAbbreviations[i].AsSpan()))
            {
                month = i + 1;
                return true;
            }
        }

        month = 0;
        return false;
    }

    // Newer OpenSSH versions (9.8+) log as "sshd-session" instead of "sshd".
    private static bool IsSshDaemon(ReadOnlySpan<char> program) =>
        program.StartsWith("sshd[", StringComparison.Ordinal)
        || program.StartsWith("sshd-session[", StringComparison.Ordinal)
        || program.SequenceEqual("sshd:".AsSpan());

    // Reads "Failed/Accepted <method> for [invalid user] <user> from <ip> port <port>".
    private static bool TryParseLoginMessage(
        ReadOnlySpan<char> message,
        out EventKind kind,
        out ReadOnlySpan<char> user,
        [NotNullWhen(true)] out IPAddress? sourceIp)
    {
        user = default;
        sourceIp = null;

        ReadOnlySpan<char> rest;
        if (message.StartsWith(FailedPrefix, StringComparison.Ordinal))
        {
            kind = EventKind.LoginFailed;
            rest = message[FailedPrefix.Length..];
        }
        else if (message.StartsWith(AcceptedPrefix, StringComparison.Ordinal))
        {
            kind = EventKind.LoginSucceeded;
            rest = message[AcceptedPrefix.Length..];
        }
        else
        {
            kind = EventKind.Unknown;
            return false;
        }

        var forIndex = rest.IndexOf(ForSeparator, StringComparison.Ordinal);
        if (forIndex <= 0)
        {
            return false;
        }

        rest = rest[(forIndex + ForSeparator.Length)..];
        if (rest.StartsWith(InvalidUserPrefix, StringComparison.Ordinal))
        {
            rest = rest[InvalidUserPrefix.Length..];
        }

        // The attacker chooses the user name and can make it contain " from 1.2.3.4 port 1".
        // sshd always writes the real address last, so split on the LAST " from ".
        var fromIndex = rest.LastIndexOf(FromSeparator, StringComparison.Ordinal);
        if (fromIndex < 0)
        {
            return false;
        }

        user = rest[..fromIndex];
        var address = new SpanTokenizer(rest[(fromIndex + FromSeparator.Length)..]);
        if (!address.TryReadToken(out var ipToken)
            || !address.TryReadToken(out var portKeyword)
            || !portKeyword.SequenceEqual(PortKeyword.AsSpan())
            || !address.TryReadToken(out var portToken)
            || !ushort.TryParse(portToken, NumberStyles.None, CultureInfo.InvariantCulture, out _))
        {
            return false;
        }

        return IPAddress.TryParse(ipToken, out sourceIp);
    }
}
