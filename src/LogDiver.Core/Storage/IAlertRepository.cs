using LogDiver.Core.Detection;

namespace LogDiver.Core.Storage;

// Saves alerts and reads them back (Repository pattern): the rest of the code doesn't know how or where.
public interface IAlertRepository
{
    // Adds the alerts after the ones already saved.
    Task SaveAsync(IEnumerable<Alert> alerts, CancellationToken cancellationToken = default);

    // Returns every saved alert, oldest save first, one at a time.
    IAsyncEnumerable<Alert> ReadAllAsync(CancellationToken cancellationToken = default);
}
