using System.Net;
using LogDiver.Core.Events;
using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;

public class WebAccessLogParserTests
{
    private static readonly WebAccessLogParser Parser = new();

    [Fact]
    public void TryParse_CombinedFormat_ReturnsAllFields()
    {
        const string line =
            "203.0.113.9 - frank [27/Oct/2026:14:03:11 +0100] \"GET /admin/login.php?id=1 HTTP/1.1\" 404 512 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"";

        var logEvent = ParseValid(line);

        Assert.Equal(EventKind.HttpRequest, logEvent.Kind);
        Assert.Equal(LogFormat.WebAccess, logEvent.Format);
        Assert.Equal(IPAddress.Parse("203.0.113.9"), logEvent.SourceIp);
        Assert.Equal("frank", logEvent.User);
        Assert.Equal(new DateTimeOffset(2026, 10, 27, 14, 3, 11, TimeSpan.FromHours(1)), logEvent.Timestamp);
        Assert.Equal("GET", logEvent.HttpMethod);
        Assert.Equal("/admin/login.php?id=1", logEvent.RequestPath);
        Assert.Equal(404, logEvent.StatusCode);
        Assert.Equal("Mozilla/5.0 (X11; Linux x86_64)", logEvent.UserAgent);
        Assert.Null(logEvent.Host);
        Assert.Equal(line, logEvent.RawLine);
    }

    [Fact]
    public void TryParse_CommonFormatWithoutUserAgent_LeavesOptionalFieldsNull()
    {
        var logEvent = ParseValid(
            "198.51.100.7 - - [27/Oct/2026:14:03:11 -0500] \"POST /api/login HTTP/1.1\" 200 -");

        Assert.Null(logEvent.User);
        Assert.Null(logEvent.UserAgent);
        Assert.Equal("POST", logEvent.HttpMethod);
        Assert.Equal(TimeSpan.FromHours(-5), logEvent.Timestamp.Offset);
    }

    [Fact]
    public void TryParse_EscapedQuotesInUserAgent_KeepsWholeUserAgent()
    {
        var logEvent = ParseValid(
            "203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 200 10 \"-\" \"sqlmap/1.8 \\\"x\\\"\"");

        Assert.Equal("sqlmap/1.8 \\\"x\\\"", logEvent.UserAgent);
    }

    [Fact]
    public void TryParse_TlsHandshakeSentToHttpPort_KeepsRawRequestAsPath()
    {
        var logEvent = ParseValid(
            @"203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] ""\x16\x03\x01\x02"" 400 226 ""-"" ""-""");

        Assert.Null(logEvent.HttpMethod);
        Assert.Equal(@"\x16\x03\x01\x02", logEvent.RequestPath);
        Assert.Equal(400, logEvent.StatusCode);
        Assert.Null(logEvent.UserAgent);
    }

    [Fact]
    public void TryParse_Ipv6Client_ParsesAddress()
    {
        var logEvent = ParseValid(
            "2001:db8::42 - - [27/Oct/2026:14:03:11 +0000] \"GET /robots.txt HTTP/2.0\" 200 68");

        Assert.Equal(IPAddress.Parse("2001:db8::42"), logEvent.SourceIp);
    }

    [Fact]
    public void TryParse_BidiOverrideInPath_IsReplaced()
    {
        var logEvent = ParseValid(
            "203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET /invoice‮fdp.exe HTTP/1.1\" 200 10");

        Assert.Equal("/invoice?fdp.exe", logEvent.RequestPath);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a log line")]
    [InlineData("999.1.1.1 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 200 1")]
    [InlineData("203.0.113.9 - - 27/Oct/2026:14:03:11 +0100 \"GET / HTTP/1.1\" 200 1")]
    [InlineData("203.0.113.9 - - [32/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 200 1")]
    [InlineData("203.0.113.9 - - [27/Oct/2026:14:03:11 +2500] \"GET / HTTP/1.1\" 200 1")]
    [InlineData("203.0.113.9 - - [27/Oct/2026:14:03:11 0100] \"GET / HTTP/1.1\" 200 1")]
    [InlineData("203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1 200 1")]
    [InlineData("203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" abc 1")]
    [InlineData("203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 999 1")]
    public void TryParse_MalformedLine_ReturnsFalse(string line)
    {
        var parsed = Parser.TryParse(line, out var logEvent);

        Assert.False(parsed);
        Assert.Null(logEvent);
    }

    private static LogEvent ParseValid(string line)
    {
        Assert.True(Parser.TryParse(line, out var logEvent), $"Expected line to parse: {line}");
        Assert.NotNull(logEvent);
        return logEvent;
    }
}
