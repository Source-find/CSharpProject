using System.Text;

namespace LogDiver.Core.Sources;

// Shared helpers for opening log files that another process is still writing to.
internal static class LogFile
{
    private const int ReaderBufferSize = 4096;

    // ReadWrite and Delete sharing let the web server keep writing and let log rotation rename the file
    // while we have it open. FileStream's own buffer is off because StreamReader already buffers.
    private static readonly FileStreamOptions ReadOptions = new()
    {
        Mode = FileMode.Open,
        Access = FileAccess.Read,
        Share = FileShare.ReadWrite | FileShare.Delete,
        Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
        BufferSize = 0,
    };

    // Opens the file for reading. Throws <see cref="FileNotFoundException"/> if it does not exist.
    public static FileStream OpenForReading(string path) => new(path, ReadOptions);

    // Opens the file for reading, or returns null if it does not exist (for example during rotation).
    public static FileStream? TryOpenForReading(string path)
    {
        try
        {
            return OpenForReading(path);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    // Returns the current size of the file in bytes, or null if it does not exist.
    public static long? TryGetLength(string path)
    {
        try
        {
            using var handle = File.OpenHandle(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return RandomAccess.GetLength(handle);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    // Creates a UTF-8 reader that leaves the stream open, so the caller controls its lifetime.
    public static StreamReader CreateReader(Stream stream) =>
        new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, ReaderBufferSize, leaveOpen: true);
}
