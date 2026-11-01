using System.Runtime.CompilerServices;
using LogDiver.Core.Sources;

namespace LogDiver.Tests.Ingestion;

// A log source whose lines come from memory instead of a file.
internal sealed class InMemoryLogSource(string name, string[] lines) : ILogSource
{
    public string Name => name;

    public async IAsyncEnumerable<string> ReadLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var line in lines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await Task.Yield(); // Behave like real I/O, so producers really interleave.
            yield return line;
        }
    }
}
