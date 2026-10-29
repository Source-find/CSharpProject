using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

/// Parses OpenSSH server lines from a syslog auth log, for example <c>/var/log/auth.log</c>.
/// Supports the classic syslog timestamp (<c>Oct 27 14:03:11</c>, which has no year or time zone) and the
/// RFC 3339 timestamp used by newer rsyslog defaults (<c>2026-10-27T14:03:11.123456+01:00</c>).
/// Only failed and accepted logins become events; every other line returns <c>false</c>.
public sealed class SshAuthLogParser : ILogParser
{
    private const string FailedPrefix = "Failed ";
    private const string AcceptedPrefix = "Accepted ";
    private const string ForSeparator = " for ";
    private const string InvalidUserPrefix = "invalid user ";
    private const string FromSeparator = " from ";
    private const string PortKeyword = "port";
    private const string RepeatedPrefix = "message repeated ";
    private const string RepeatedBodyStart = "times: [";
    private const string ClassicTimeFormat = "HH:mm:ss";
    private const int AllowedClockSkewDays = 1;

    private static readonly string[] MonthAbbreviations =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    private readonly TimeProvider _timeProvider;

    // Creates a parser that uses the system clock to guess the year of classic syslog timestamps.</summary>
    public SshAuthLogParser()
        : this(TimeProvider.System)
    {
    }

    // Creates a parser that uses <paramref name="timeProvider"/> for the current year and local time zone.</summary>
    public SshAuthLogParser(TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    public LogFormat Format => LogFormat.SshAuth;

    /// <inheritdoc />
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
        if (!TryUnwrapRepeatedMessage(ref message, out var occurrences)
            || !TryParseLoginMessage(message, out var kind, out var user, out var sourceIp))
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
            OccurrenceCount = occurrences,
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

    // Classic syslog timestamps have no year. Assume the current year, unless the date is later than today,
    // which means the line was written last year (a December log read in January).
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

    // OpenSSH 9.8+ logs from <c>sshd-session</c> instead of <c>sshd</c>.</summary>
    private static bool IsSshDaemon(ReadOnlySpan<char> program) =>
        program.StartsWith("sshd[", StringComparison.Ordinal)
        || program.StartsWith("sshd-session[", StringComparison.Ordinal)
        || program.SequenceEqual("sshd:".AsSpan());

    // Unwraps <c>message repeated 3 times: [ Failed password ... ]</c>. Lines without the wrapper are
    // left unchanged with an occurrence count of 1.
    private static bool TryUnwrapRepeatedMessage(ref ReadOnlySpan<char> message, out int occurrences)
    {
        occurrences = 1;
        if (!message.StartsWith(RepeatedPrefix, StringComparison.Ordinal))
        {
            return true;
        }

        var rest = message[RepeatedPrefix.Length..];
        var countEnd = rest.IndexOf(' ');
        if (countEnd <= 0
            || !int.TryParse(rest[..countEnd], NumberStyles.None, CultureInfo.InvariantCulture, out occurrences)
            || occurrences < 1)
        {
            return false;
        }

        rest = rest[(countEnd + 1)..];
        var bodyEnd = rest.LastIndexOf(']');
        if (!rest.StartsWith(RepeatedBodyStart, StringComparison.Ordinal) || bodyEnd < RepeatedBodyStart.Length)
        {
            return false;
        }

        message = rest[RepeatedBodyStart.Length..bodyEnd].Trim();
        return true;
    }

    /// Parses <c>Failed|Accepted &lt;method&gt; for [invalid user ]&lt;user&gt; from &lt;ip&gt; port &lt;port&gt; ...</c>.
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

        // The user name is chosen by the attacker and can itself contain " from 1.2.3.4 port 1".
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
