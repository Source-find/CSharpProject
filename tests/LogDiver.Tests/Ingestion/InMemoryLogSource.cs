using System.Runtime.CompilerServices;
using LogDiver.Core.Sources;

namespace LogDiver.Tests.Ingestion;

// A log source whose lines come from memory. Can throw after the last line to simulate a read error.
internal sealed class InMemoryLogSource(string name, string[] lines, bool failAtEnd = false) : ILogSource
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

        if (failAtEnd)
        {
            throw new InvalidOperationException($"Could not read {name}.");
        }
    }
}
