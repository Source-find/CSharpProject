using LogDiver.Core.Events;
using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;

public class LogParserFactoryTests
{
    private readonly LogParserFactory _factory = new();

    [Fact]
    public void Create_SshAuth_ReturnsSshParser()
    {
        Assert.IsType<SshAuthLogParser>(_factory.Create(LogFormat.SshAuth));
    }

    [Fact]
    public void Create_WebAccess_ReturnsWebParser()
    {
        Assert.IsType<WebAccessLogParser>(_factory.Create(LogFormat.WebAccess));
    }

    [Fact]
    public void Create_Unknown_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _factory.Create(LogFormat.Unknown));
    }

    [Fact]
    public void DetectFormat_AuthLogWithOtherServices_ReturnsSshAuth()
    {
        string[] lines =
        [
            "Oct 27 09:15:01 web01 CRON[999]: pam_unix(cron:session): session opened for user root",
            "Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2",
            "Oct 27 09:15:44 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2",
        ];

        Assert.Equal(LogFormat.SshAuth, _factory.DetectFormat(lines));
    }

    [Fact]
    public void DetectFormat_AccessLog_ReturnsWebAccess()
    {
        string[] lines =
        [
            "203.0.113.9 - - [27/Oct/2026:14:03:11 +0100] \"GET / HTTP/1.1\" 200 512",
            "203.0.113.9 - - [27/Oct/2026:14:03:12 +0100] \"GET /favicon.ico HTTP/1.1\" 404 0",
        ];

        Assert.Equal(LogFormat.WebAccess, _factory.DetectFormat(lines));
    }

    [Fact]
    public void DetectFormat_UnrecognisedLines_ReturnsUnknown()
    {
        string[] lines = ["hello", "world", "Oct 27 09:15:01 web01 CRON[999]: job started"];

        Assert.Equal(LogFormat.Unknown, _factory.DetectFormat(lines));
    }

    [Fact]
    public void DetectFormat_NoLines_ReturnsUnknown()
    {
        Assert.Equal(LogFormat.Unknown, _factory.DetectFormat([]));
    }
}
