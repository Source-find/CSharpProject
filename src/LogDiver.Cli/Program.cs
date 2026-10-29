using Spectre.Console;

namespace LogDiver.Cli;

// The program itself, will work as its own interface and should show different things like attempted logins, brute force and so on.
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
