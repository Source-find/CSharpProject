using System.Net;
using LogDiver.Core.Events;
using LogDiver.Core.Parsing;
using Microsoft.Extensions.Time.Testing;

namespace LogDiver.Tests.Parsing;

public class SshAuthLogParserTests
{
    private readonly SshAuthLogParser _parser =
        new(new FakeTimeProvider(new DateTimeOffset(2026, 10, 27, 12, 0, 0, TimeSpan.Zero)));

    [Fact]
    public void TryParse_FailedPassword_ReturnsLoginFailedEvent()
    {
        const string line = "Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2";

        var logEvent = ParseValid(line);

        Assert.Equal(EventKind.LoginFailed, logEvent.Kind);
        Assert.Equal(LogFormat.SshAuth, logEvent.Format);
        Assert.Equal("root", logEvent.User);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), logEvent.SourceIp);
        Assert.Equal(new DateTimeOffset(2026, 10, 27, 9, 15, 42, TimeSpan.Zero), logEvent.Timestamp);
        Assert.Equal(line, logEvent.RawLine);
    }

    [Fact]
    public void TryParse_UserNameContainingFakeFromClause_UsesRealSourceAddress()
    {
        // Log injection: the attacker picks a user name that looks like the rest of the message.
        var logEvent = ParseValid(
            "Oct 27 09:15:42 web01 sshd[1234]: Failed password for invalid user x from 6.6.6.6 port 1 from 203.0.113.5 port 52144 ssh2");

        Assert.Equal(IPAddress.Parse("203.0.113.5"), logEvent.SourceIp);
        Assert.Equal("x from 6.6.6.6 port 1", logEvent.User);
    }

    private LogEvent ParseValid(string line)
    {
        Assert.True(_parser.TryParse(line, out var logEvent), $"Expected line to parse: {line}");
        Assert.NotNull(logEvent);
        return logEvent;
    }
}
