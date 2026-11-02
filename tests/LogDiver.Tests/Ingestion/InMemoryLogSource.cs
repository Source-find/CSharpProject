using System.Runtime.CompilerServices;
using LogDiver.Core.Sources;

namespace LogDiver.Tests.Ingestion;
// Ai generated.
// A log source whose lines come from memory instead of a file. Used by IngestionPipelineTests (Input method),
// so the pipeline can be tested without creating real files.
internal sealed class InMemoryLogSource(string name, string[] lines) : ILogSource
{
    public string Name => name;

    public async IAsyncEnumerable<string> ReadLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var line in lines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield();
            yield return line;
        }
    }
}
