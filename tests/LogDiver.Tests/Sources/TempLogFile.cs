namespace LogDiver.Tests.Sources;

// A temp file with a unique name. Deleted again on dispose.
internal sealed class TempLogFile : IDisposable
{
    public string Path { get; } =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "logdiver-" + System.IO.Path.GetRandomFileName());

    public void Dispose()
    {
        File.Delete(Path);
    }
}
