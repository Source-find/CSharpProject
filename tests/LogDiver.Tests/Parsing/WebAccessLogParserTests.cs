using System.Net;
using LogDiver.Core.Events;
using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;
// AI generated test to try parsing a full web access log line in the combined format.
public class WebAccessLogParserTests
{
    [Fact]
    public void TryParse_CombinedFormat_ReturnsAllFields()
    {
        const string line =
            "203.0.113.9 - frank [27/Oct/2026:14:03:11 +0100] \"GET /admin/login.php?id=1 HTTP/1.1\" 404 512 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"";

        var parsed = new WebAccessLogParser().TryParse(line, out var logEvent);

        Assert.True(parsed);
        Assert.NotNull(logEvent);
        Assert.Equal(EventKind.HttpRequest, logEvent.Kind);
        Assert.Equal(IPAddress.Parse("203.0.113.9"), logEvent.SourceIp);
        Assert.Equal("frank", logEvent.User);
        Assert.Equal(new DateTimeOffset(2026, 10, 27, 14, 3, 11, TimeSpan.FromHours(1)), logEvent.Timestamp);
        Assert.Equal("GET", logEvent.HttpMethod);
        Assert.Equal("/admin/login.php?id=1", logEvent.RequestPath);
        Assert.Equal(404, logEvent.StatusCode);
        Assert.Equal("Mozilla/5.0 (X11; Linux x86_64)", logEvent.UserAgent);
    }
}
