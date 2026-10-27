using System.Net;
using LogDiver.Core.Events;
using LogDiver.Core.Parsing;
using Microsoft.Extensions.Time.Testing;

namespace LogDiver.Tests.Parsing;

public class SshAuthLogParserTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    private readonly SshAuthLogParser _parser = new(new FakeTimeProvider(Now));

    [Fact]
    public void TryParse_FailedPassword_ReturnsLoginFailedEvent()
    {
        const string line = "Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2";

        var logEvent = ParseValid(line);

        Assert.Equal(EventKind.LoginFailed, logEvent.Kind);
        Assert.Equal(LogFormat.SshAuth, logEvent.Format);
        Assert.Equal("root", logEvent.User);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), logEvent.SourceIp);
        Assert.Equal("web01", logEvent.Host);
        Assert.Equal(new DateTimeOffset(2026, 10, 27, 9, 15, 42, TimeSpan.Zero), logEvent.Timestamp);
        Assert.Equal(1, logEvent.OccurrenceCount);
        Assert.Equal(line, logEvent.RawLine);
    }

    [Fact]
    public void TryParse_FailedPasswordForInvalidUser_ExtractsUserName()
    {
        var logEvent = ParseValid(
            "Oct 27 09:15:42 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52144 ssh2");

        Assert.Equal(EventKind.LoginFailed, logEvent.Kind);
        Assert.Equal("admin", logEvent.User);
    }

    [Fact]
    public void TryParse_AcceptedPublicKey_ReturnsLoginSucceededEvent()
    {
        var logEvent = ParseValid(
            "Oct 27 09:20:01 web01 sshd[1301]: Accepted publickey for alice from 198.51.100.7 port 50022 ssh2: ED25519 SHA256:Zm9vYmFy");

        Assert.Equal(EventKind.LoginSucceeded, logEvent.Kind);
        Assert.Equal("alice", logEvent.User);
        Assert.Equal(IPAddress.Parse("198.51.100.7"), logEvent.SourceIp);
    }

    [Fact]
    public void TryParse_Rfc3339TimestampAndIpv6_KeepsOffsetAndAddress()
    {
        var logEvent = ParseValid(
            "2026-10-27T09:15:42.123456+01:00 web01 sshd-session[1234]: Failed password for root from 2001:db8::1 port 22 ssh2");

        Assert.Equal(new DateTimeOffset(2026, 10, 27, 8, 15, 42, TimeSpan.Zero).AddTicks(1_234_560), logEvent.Timestamp);
        Assert.Equal(TimeSpan.FromHours(1), logEvent.Timestamp.Offset);
        Assert.Equal(IPAddress.Parse("2001:db8::1"), logEvent.SourceIp);
    }

    [Fact]
    public void TryParse_SingleDigitDayPaddedWithSpace_ParsesDay()
    {
        var logEvent = ParseValid(
            "Oct  7 08:00:00 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2");

        Assert.Equal(7, logEvent.Timestamp.Day);
    }

    [Fact]
    public void TryParse_DecemberLineReadInJanuary_UsesPreviousYear()
    {
        var parser = new SshAuthLogParser(new FakeTimeProvider(new DateTimeOffset(2027, 1, 2, 8, 0, 0, TimeSpan.Zero)));

        var parsed = parser.TryParse(
            "Dec 31 23:59:59 web01 sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2", out var logEvent);

        Assert.True(parsed);
        Assert.NotNull(logEvent);
        Assert.Equal(2026, logEvent.Timestamp.Year);
    }

    [Fact]
    public void TryParse_MessageRepeated_SetsOccurrenceCount()
    {
        var logEvent = ParseValid(
            "Oct 27 09:15:45 web01 sshd[1234]: message repeated 3 times: [ Failed password for root from 203.0.113.5 port 52144 ssh2]");

        Assert.Equal(EventKind.LoginFailed, logEvent.Kind);
        Assert.Equal(3, logEvent.OccurrenceCount);
        Assert.Equal(IPAddress.Parse("203.0.113.5"), logEvent.SourceIp);
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

    [Fact]
    public void TryParse_UserNameWithAnsiEscape_ReplacesControlCharacter()
    {
        var logEvent = ParseValid(
            "Oct 27 09:15:42 web01 sshd[1234]: Failed password for invalid user \u001b[31madmin from 203.0.113.5 port 1 ssh2");

        Assert.Equal("?[31madmin", logEvent.User);
        Assert.DoesNotContain("\u001b", logEvent.RawLine, StringComparison.Ordinal);
    }

    [Fact]
    public void TryParse_VeryLongUserName_IsTruncated()
    {
        var longName = new string('a', 500);

        var logEvent = ParseValid(
            $"Oct 27 09:15:42 web01 sshd[1234]: Failed password for invalid user {longName} from 203.0.113.5 port 1 ssh2");

        Assert.Equal(InputSanitizer.MaxUserLength, logEvent.User?.Length);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a log line")]
    [InlineData("Oct 27")]
    [InlineData("Oct 27 09:15:42 web01 CRON[999]: pam_unix(cron:session): session opened for user root")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: Invalid user admin from 203.0.113.5 port 52144")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: Connection closed by 203.0.113.5 port 52144 [preauth]")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from not-an-ip port 52144 ssh2")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 99999 ssh2")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5")]
    [InlineData("Foo 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 1 ssh2")]
    [InlineData("Feb 30 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 1 ssh2")]
    [InlineData("Oct 27 25:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 1 ssh2")]
    [InlineData("Oct 27 09:15:42 web01 sshd[1234]: message repeated many times: [ Failed password for root from 203.0.113.5 port 1 ssh2]")]
    public void TryParse_IrrelevantOrMalformedLine_ReturnsFalse(string line)
    {
        var parsed = _parser.TryParse(line, out var logEvent);

        Assert.False(parsed);
        Assert.Null(logEvent);
    }

    private LogEvent ParseValid(string line)
    {
        Assert.True(_parser.TryParse(line, out var logEvent), $"Expected line to parse: {line}");
        Assert.NotNull(logEvent);
        return logEvent;
    }
}
