namespace LogDiver.Tests.Sources;

// A uniquely named file in the temp folder that is deleted again on dispose, together with any rotated copy.
internal sealed class TempLogFile : IDisposable
{
    public string Path { get; } =
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "logdiver-" + System.IO.Path.GetRandomFileName());

    public string RotatedPath => Path + ".1";

    public void Dispose()
    {
        File.Delete(Path);
        File.Delete(RotatedPath);
    }
}
