using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using LogDiver.Core.Events;

namespace LogDiver.Core.Parsing;

/// <summary>
/// Parses Apache/Nginx access log lines in the "common" or "combined" format:
/// <c>203.0.113.9 - frank [27/Oct/2026:14:03:11 +0100] "GET /index.html HTTP/1.1" 200 2326 "referer" "user agent"</c>.
/// </summary>
public sealed class WebAccessLogParser : ILogParser
{
    private const string TimestampFormat = "dd/MMM/yyyy:HH:mm:ss";
    private const string EmptyField = "-";
    private const int UtcOffsetLength = 5;
    private const int MinStatusCode = 100;
    private const int MaxStatusCode = 599;

    private static readonly TimeSpan MaxUtcOffset = TimeSpan.FromHours(14);

    /// <inheritdoc />
    public LogFormat Format => LogFormat.WebAccess;

    /// <inheritdoc />
    public bool TryParse(ReadOnlySpan<char> line, [NotNullWhen(true)] out LogEvent? logEvent)
    {
        logEvent = null;
        var tokenizer = new SpanTokenizer(line);

        if (!tokenizer.TryReadToken(out var ipToken)
            || !IPAddress.TryParse(ipToken, out var sourceIp)
            || !tokenizer.TryReadToken(out _) // identd field, "-" in practice
            || !tokenizer.TryReadToken(out var userToken)
            || !tokenizer.TryReadDelimited('[', ']', out var timeToken)
            || !TryParseTimestamp(timeToken, out var timestamp)
            || !tokenizer.TryReadQuoted(out var request)
            || !tokenizer.TryReadToken(out var statusToken)
            || !TryParseStatusCode(statusToken, out var statusCode))
        {
            return false;
        }

        // Response size and referer are not used. The user agent only exists in the combined format.
        _ = tokenizer.TryReadToken(out _);
        var userAgent = tokenizer.TryReadQuoted(out _) && tokenizer.TryReadQuoted(out var userAgentToken)
            ? userAgentToken
            : default;

        SplitRequestLine(request, out var method, out var path);

        logEvent = new LogEvent
        {
            Timestamp = timestamp,
            Format = LogFormat.WebAccess,
            Kind = EventKind.HttpRequest,
            RawLine = InputSanitizer.Sanitize(line, InputSanitizer.MaxRawLineLength),
            SourceIp = sourceIp,
            User = SanitizeOptional(userToken, InputSanitizer.MaxUserLength),
            HttpMethod = SanitizeOptional(method, InputSanitizer.MaxHttpMethodLength),
            RequestPath = InputSanitizer.Sanitize(path, InputSanitizer.MaxRequestPathLength),
            StatusCode = statusCode,
            UserAgent = SanitizeOptional(userAgent, InputSanitizer.MaxUserAgentLength),
        };
        return true;
    }

    /// <summary>Parses <c>27/Oct/2026:14:03:11 +0100</c>.</summary>
    private static bool TryParseTimestamp(ReadOnlySpan<char> text, out DateTimeOffset timestamp)
    {
        timestamp = default;
        var separator = text.IndexOf(' ');
        if (separator < 0
            || !DateTime.TryParseExact(
                text[..separator], TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.None, out var localTime)
            || !TryParseUtcOffset(text[(separator + 1)..], out var offset))
        {
            return false;
        }

        timestamp = new DateTimeOffset(localTime, offset);
        return true;
    }

    /// <summary>Parses an offset such as <c>+0100</c> or <c>-0530</c>.</summary>
    private static bool TryParseUtcOffset(ReadOnlySpan<char> text, out TimeSpan offset)
    {
        offset = TimeSpan.Zero;
        if (text.Length != UtcOffsetLength
            || (text[0] != '+' && text[0] != '-')
            || !int.TryParse(text.Slice(1, 2), NumberStyles.None, CultureInfo.InvariantCulture, out var hours)
            || !int.TryParse(text.Slice(3, 2), NumberStyles.None, CultureInfo.InvariantCulture, out var minutes)
            || minutes >= 60)
        {
            return false;
        }

        offset = new TimeSpan(hours, minutes, 0);
        if (offset > MaxUtcOffset)
        {
            return false;
        }

        if (text[0] == '-')
        {
            offset = offset.Negate();
        }

        return true;
    }

    private static bool TryParseStatusCode(ReadOnlySpan<char> text, out int statusCode) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out statusCode)
        && statusCode is >= MinStatusCode and <= MaxStatusCode;

    /// <summary>
    /// Splits <c>GET /path?q=1 HTTP/1.1</c> into method and path. Scanners often send garbage such as a TLS
    /// handshake (<c>\x16\x03\x01</c>); then there is no method and the whole request is kept as the path.
    /// </summary>
    private static void SplitRequestLine(
        ReadOnlySpan<char> request, out ReadOnlySpan<char> method, out ReadOnlySpan<char> path)
    {
        var firstSpace = request.IndexOf(' ');
        if (firstSpace <= 0)
        {
            method = default;
            path = request;
            return;
        }

        method = request[..firstSpace];
        var target = request[(firstSpace + 1)..];
        var lastSpace = target.LastIndexOf(' ');
        path = lastSpace >= 0 ? target[..lastSpace] : target;
    }

    /// <summary>Returns null for missing fields (empty or <c>-</c>), otherwise the sanitized value.</summary>
    private static string? SanitizeOptional(ReadOnlySpan<char> value, int maxLength) =>
        value.IsEmpty || value.SequenceEqual(EmptyField.AsSpan())
            ? null
            : InputSanitizer.Sanitize(value, maxLength);
}
