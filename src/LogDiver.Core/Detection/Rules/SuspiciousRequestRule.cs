using System.Text.RegularExpressions;
using LogDiver.Core.Events;

namespace LogDiver.Core.Detection.Rules;

// Suspicious request: a single web request that contains a known attack pattern in its path, or comes
// from a known attack tool. The patterns are compiled at build time ([GeneratedRegex]), which is why the
// class is "partial": the compiler writes the other part.
public sealed partial class SuspiciousRequestRule : IDetectionRule
{
    public string Name => "SuspiciousRequest";

    public Alert? Evaluate(LogEvent logEvent)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        if (logEvent.Kind != EventKind.HttpRequest)
        {
            return null;
        }

        var path = logEvent.RequestPath ?? string.Empty;
        var attack = FindAttack(path, logEvent.UserAgent ?? string.Empty);
        if (attack is null)
        {
            return null;
        }

        var (attackName, severity) = attack.Value;
        return new Alert(
            Name,
            severity,
            logEvent.Timestamp,
            logEvent.SourceIp,
            $"Possible {attackName}: {logEvent.HttpMethod} {path}");
    }

    // A lot of help gotten from AI
    // The first matching pattern wins. An attack tool in the user agent is Medium: it shows intent,
    // while the other patterns are actual attack attempts and therefore High.
    private static (string Name, AlertSeverity Severity)? FindAttack(string path, string userAgent)
    {
        if (PathTraversalRegex().IsMatch(path))
        {
            return ("path traversal", AlertSeverity.High);
        }

        if (SqlInjectionRegex().IsMatch(path))
        {
            return ("SQL injection", AlertSeverity.High);
        }

        if (CrossSiteScriptingRegex().IsMatch(path))
        {
            return ("cross-site scripting", AlertSeverity.High);
        }

        if (SensitiveFileRegex().IsMatch(path))
        {
            return ("probe for a sensitive file", AlertSeverity.High);
        }

        if (ScannerToolRegex().IsMatch(userAgent))
        {
            return ("known attack tool", AlertSeverity.Medium);
        }

        return null;
    }

    // The patterns are kept simple (no nested repetition), so a hostile path can't make them slow (ReDoS).
    [GeneratedRegex(@"\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e(%2f|%5c|/)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PathTraversalRegex();

    [GeneratedRegex(@"union(\s|%20|\+)+(all(\s|%20|\+)+)?select|information_schema|sleep\(|'(\s|%20|\+)*or(\s|%20|\+)*'?1'?(\s|%20|\+)*=",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SqlInjectionRegex();

    [GeneratedRegex(@"<script|%3cscript|javascript:|onerror\s*=", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex CrossSiteScriptingRegex();

    [GeneratedRegex(@"/\.env|/\.git/|/wp-admin|/wp-login\.php|/phpmyadmin", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitiveFileRegex();

    [GeneratedRegex(@"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ScannerToolRegex();
}
