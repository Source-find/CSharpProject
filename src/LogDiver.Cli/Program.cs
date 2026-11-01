using System.Globalization;
using LogDiver.Core.Detection;
using LogDiver.Core.Events;
using LogDiver.Core.Ingestion;
using LogDiver.Core.Parsing;
using LogDiver.Core.Sources;
using LogDiver.Core.Storage;
using Spectre.Console;

namespace LogDiver.Cli;

// Entry point of the app. Reads the given log files, shows how many lines and events each one had,
// and lists the alerts the detection engine found.
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
            AnsiConsole.WriteLine("Run LogDiver (completed demo build) to see alerts");
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

            await AnalyzeAsync(inputs, cancellation.Token);
            return ExitSuccess;
        }
        catch (FileNotFoundException ex)
        {
            // This had to be done with current culture to make sure it runs with norwegian/swedish number-rules. 1234,5 instead of 1234.5
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

    // Runs every event through the detection engine and prints what was found.
    private static async Task AnalyzeAsync(List<LogInput> inputs, CancellationToken cancellationToken)
    {
        var engine = new DetectionEngine();

        // Both subscribe to engine.AlertRaised now, and "using" unsubscribes them when this method ends.
        // The pipeline has a single consumer, so their handlers never run on two threads at once.
        using var statistics = new AlertStatistics(engine);
        using var deduplicator = new AlertDeduplicator(engine);

        var result = await new IngestionPipeline().RunAsync(
            inputs, logEvent => engine.Process(logEvent), cancellationToken);

        PrintSummary(result);
        PrintAlerts(deduplicator.Alerts);
        PrintStatistics(statistics);
        await SaveAlertsAsync(deduplicator.Alerts, cancellationToken);
    }

    // Adds the merged alerts to alerts.jsonl in the current folder, so they can be looked at later.
    private static async Task SaveAlertsAsync(IReadOnlyList<Alert> alerts, CancellationToken cancellationToken)
    {
        if (alerts.Count == 0)
        {
            return;
        }

        var repository = new JsonLinesAlertRepository(JsonLinesAlertRepository.DefaultFileName);
        await repository.SaveAsync(alerts, cancellationToken);

        AnsiConsole.MarkupLineInterpolated(
            CultureInfo.CurrentCulture,
            $"[grey]Saved {alerts.Count} alert(s) to {Path.GetFullPath(JsonLinesAlertRepository.DefaultFileName)}[/]");
    }

    // Pairs every file with the right parser, based on its first lines. Returns null if format is unknown.
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

    private static void PrintAlerts(IReadOnlyList<Alert> alerts)
    {
        if (alerts.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No alerts.[/]");
            return;
        }

        var table = new Table()
            .AddColumn("Time")
            .AddColumn("Severity")
            .AddColumn("Rule")
            .AddColumn("Source IP")
            .AddColumn(new TableColumn("Count").RightAligned())
            .AddColumn("Description");

        foreach (var alert in alerts.OrderBy(alert => alert.Timestamp))
        {
            // Everything except the severity comes from the log, so escape it before Spectre reads it as markup.
            table.AddRow(
                alert.Timestamp.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                SeverityMarkup(alert.Severity),
                Markup.Escape(alert.RuleName),
                Markup.Escape(alert.SourceIp?.ToString() ?? "-"),
                FormatCount(alert.Occurrences),
                Markup.Escape(alert.Description));
        }

        AnsiConsole.MarkupLineInterpolated(CultureInfo.CurrentCulture, $"[bold]{alerts.Count} alert(s):[/]");
        AnsiConsole.Write(table);
    }

    private static void PrintStatistics(AlertStatistics statistics)
    {
        if (statistics.TotalAlerts == 0)
        {
            return;
        }

        AlertSeverity[] severities = [AlertSeverity.High, AlertSeverity.Medium, AlertSeverity.Low];
        var bySeverity = string.Join(", ", severities.Select(severity =>
            $"{SeverityMarkup(severity)} {FormatCount(statistics.BySeverity.GetValueOrDefault(severity))}"));
        AnsiConsole.MarkupLineInterpolated(
            CultureInfo.CurrentCulture, $"[bold]{statistics.TotalAlerts} alert(s) before merging repeats.[/]");
        AnsiConsole.MarkupLine(bySeverity);

        var table = new Table()
            .AddColumn("Top source IPs")
            .AddColumn(new TableColumn("Alerts").RightAligned());

        foreach (var (ip, alertCount) in statistics.TopSourceIps(5))
        {
            table.AddRow(Markup.Escape(ip.ToString()), FormatCount(alertCount));
        }

        AnsiConsole.Write(table);
    }

    private static string SeverityMarkup(AlertSeverity severity) => severity switch
    {
        AlertSeverity.High => "[red]High[/]",
        AlertSeverity.Medium => "[yellow]Medium[/]",
        _ => "[blue]Low[/]",
    };

    private static string FormatCount(long count) => count.ToString("N0", CultureInfo.CurrentCulture);
}
