using Spectre.Console;

namespace LogDiver.Cli;

// Entry point of the app. Will show the analysis results, such as failed logins and brute-force attempts.
internal static class Program
{
    private static int Main()
    {
        AnsiConsole.Write(new FigletText("LogDiver").Color(Color.Green));
        AnsiConsole.MarkupLine($"[grey]Local log analysis and threat detection - .NET {Environment.Version}[/]");
        AnsiConsole.MarkupLine("[yellow]Commands are added in phase 8. See docs/PLAN.md.[/]");
        return 0;
    }
}
