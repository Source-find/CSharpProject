using LogDiver.Core.Events;
using LogDiver.Core.Parsing;

namespace LogDiver.Tests.Parsing;

public class LogParserFactoryTests
{
    [Fact]
    public void DetectFormat_AuthLogWithOtherServices_ReturnsSshAuth()
    {
        string[] lines =
        [
            "Oct 27 09:15:01 web01 CRON[999]: pam_unix(cron:session): session opened for user root",
            "Oct 27 09:15:42 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2",
            "Oct 27 09:15:44 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52144 ssh2",
        ];

        Assert.Equal(LogFormat.SshAuth, new LogParserFactory().DetectFormat(lines));
    }
}
