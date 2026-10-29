namespace LogDiver.Core.Sources;

// Settings for <see cref="TailingFileLogSource"/>.
public sealed record TailOptions
{
    // The default settings.
    public static TailOptions Default { get; } = new();

    // How long to wait before checking the file again when there is no new data.
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromMilliseconds(500);

    // Start at the end of the file and only return lines written after tailing started, like <c>tail -f</c>.
    // When false, existing lines are returned first.
    public bool StartAtEnd { get; init; } = true;
}
