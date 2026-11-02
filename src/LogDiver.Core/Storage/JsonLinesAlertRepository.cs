using System.Runtime.CompilerServices;
using System.Text.Json;
using LogDiver.Core.Detection;
using LogDiver.Core.Sources;

namespace LogDiver.Core.Storage;

// Stores alerts in a JSON Lines file: one alert per line, as JSON. Saving only appends to the end,
// and reading streams one line at a time. JSON escapes quotes, line breaks and control characters,
// so text from an attacker can't break the file or sneak in fake alerts.
public sealed class JsonLinesAlertRepository
{
    public const string DefaultFileName = "alerts.jsonl";

    private const int WriteBufferSize = 4096;
    private static readonly byte[] NewLine = [(byte)'\n'];

    public JsonLinesAlertRepository(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        FilePath = filePath;
    }

    public string FilePath { get; }

    public async Task SaveAsync(IEnumerable<Alert> alerts, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(alerts);

        // Opened once per save and closed by "await using", also if saving fails or is cancelled.
        await using var stream = new FileStream(
            FilePath, FileMode.Append, FileAccess.Write, FileShare.Read, WriteBufferSize, useAsync: true);

        foreach (var alert in alerts)
        {
            await JsonSerializer.SerializeAsync(stream, alert, AlertJsonContext.Default.Alert, cancellationToken);
            await stream.WriteAsync(NewLine, cancellationToken);
        }
    }

    public async IAsyncEnumerable<Alert> ReadAllAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!File.Exists(FilePath))
        {
            yield break; // Nothing saved yet.
        }

        // Reuses the log reader, so a huge or tampered file gets the same line-length limit as logs.
        var lineNumber = 0;
        await foreach (var line in new FileLogSource(FilePath).ReadLinesAsync(cancellationToken))
        {
            lineNumber++;
            if (!string.IsNullOrWhiteSpace(line))
            {
                yield return ParseLine(line, lineNumber);
            }
        }
    }

    // Kept separate because "yield return" isn't allowed inside a try block that has a catch.
    private Alert ParseLine(string line, int lineNumber)
    {
        try
        {
            return JsonSerializer.Deserialize(line, AlertJsonContext.Default.Alert)
                ?? throw new JsonException("The line is empty JSON (null).");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"Line {lineNumber} of {FilePath} is not a valid alert.", ex);
        }
    }
}
