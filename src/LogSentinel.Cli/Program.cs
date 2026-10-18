using Spectre.Console;

namespace LogSentinel.Cli;

internal static class Program
{
    private static int Main()
    {
        AnsiConsole.Write(new FigletText("LogSentinel").Color(Color.Green));
        AnsiConsole.MarkupLine($"[grey]Local log analysis and threat detection - .NET {Environment.Version}[/]");
        AnsiConsole.MarkupLine("[yellow]Commands are added in phase 8. See docs/PLAN.md.[/]");
        return 0;
    }
}
