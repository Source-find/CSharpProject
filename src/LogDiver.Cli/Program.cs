using System.Globalization;
using LogDiver.Core.Events;
using LogDiver.Core.Ingestion;
using LogDiver.Core.Parsing;
using LogDiver.Core.Sources;
using Spectre.Console;

namespace LogDiver.Cli;

// Entry point of the app. For now it reads the given log files and shows how many lines and events
// each one had. Later it will show the analysis results, such as failed logins and brute-force attempts.
internal static class Program
{
    private const int ExitSuccess = 0;
    private const int ExitError = 1;
    private const int ExitCancelled = 130;

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            AnsiConsole.Write(new FigletText("LogDiver").Color(Color.Green));
            AnsiConsole.MarkupLine("Usage: logdiver <log file> [[<log file> ...]]");
            return ExitError;
        }

        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancelKey = (_, e) =>
        {
            e.Cancel = true; // Don't kill the process; stop the analysis cleanly instead.
            cancellation.Cancel();
        };
        Console.CancelKeyPress += onCancelKey;

        try
        {
            var inputs = await CreateInputsAsync(args, cancellation.Token);
            if (inputs is null)
            {
                return ExitError;
            }

            var result = await new IngestionPipeline().RunAsync(inputs, _ => { }, cancellation.Token);
            PrintSummary(result);
            return ExitSuccess;
        }
        catch (FileNotFoundException ex)
        {
            // This had to be done with current culture to make sure it runs with norwegian/swedish rules. 1234,5 istead of 1234.5
            AnsiConsole.MarkupLineInterpolated(CultureInfo.CurrentCulture, $"[red]File not found:[/] {ex.FileName ?? ex.Message}");
            return ExitError;
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[yellow]Cancelled.[/]");
            return ExitCancelled;
        }
        finally
        {
            // Unsubscribe, so this static event doesn't keep the handler (and the token source) alive.
            Console.CancelKeyPress -= onCancelKey;
        }
    }

    // Pairs every file with the right parser, based on its first lines. Returns null if a format is unknown.
    private static async Task<List<LogInput>?> CreateInputsAsync(string[] paths, CancellationToken cancellationToken)
    {
        var factory = new LogParserFactory();
        var inputs = new List<LogInput>(paths.Length);

        foreach (var path in paths)
        {
            var source = new FileLogSource(path);
            var sample = await source.ReadLinesAsync(cancellationToken)
                .Take(LogParserFactory.DetectionSampleSize)
                .ToListAsync(cancellationToken);

            var format = factory.DetectFormat(sample);
            if (format == LogFormat.Unknown)
            {
                AnsiConsole.MarkupLineInterpolated(CultureInfo.CurrentCulture, $"[red]Could not tell what kind of log this is:[/] {path}");
                return null;
            }

            inputs.Add(new LogInput(source, factory.Create(format)));
        }

        return inputs;
    }

    private static void PrintSummary(IngestionResult result)
    {
        var table = new Table()
            .AddColumn("File")
            .AddColumn(new TableColumn("Lines").RightAligned())
            .AddColumn(new TableColumn("Events").RightAligned())
            .AddColumn(new TableColumn("Skipped").RightAligned());

        foreach (var source in result.Sources)
        {
            // Escape the name: Spectre would read "[" and "]" in a file name as colour markup.
            table.AddRow(
                Markup.Escape(source.SourceName),
                FormatCount(source.LinesRead),
                FormatCount(source.EventsParsed),
                FormatCount(source.LinesSkipped));
        }

        AnsiConsole.Write(table);
    }

    private static string FormatCount(long count) => count.ToString("N0", CultureInfo.CurrentCulture);
}
