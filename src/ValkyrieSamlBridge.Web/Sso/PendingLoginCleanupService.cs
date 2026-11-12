using Microsoft.Extensions.DependencyInjection;
using ValkyrieSamlBridge.Data;

namespace ValkyrieSamlBridge.Web.Sso;

// Deletes pending logins past their ExpiresAt, consumed or not. Registered after BridgeStartup, so the
// database is migrated before the first tick.
public sealed partial class PendingLoginCleanupService(IServiceProvider services, TimeProvider time, ILogger<PendingLoginCleanupService> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = services.CreateAsyncScope();
                var store = scope.ServiceProvider.GetRequiredService<PendingLoginStore>();
                var purged = await store.PurgeExpiredAsync(stoppingToken);
                if (purged > 0)
                {
                    LogPurged(purged);
                }
            }
            catch (Exception error) when (!stoppingToken.IsCancellationRequested)
            {
                LogPurgeFailed(error);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Purged {Count} expired pending logins.")]
    private partial void LogPurged(int count);

    [LoggerMessage(Level = LogLevel.Error, Message = "Purging expired pending logins failed. The next run will try again.")]
    private partial void LogPurgeFailed(Exception error);
}
