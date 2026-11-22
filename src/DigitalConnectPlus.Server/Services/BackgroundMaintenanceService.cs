using DigitalConnectPlus.Server.Data;

namespace DigitalConnectPlus.Server.Services;

/// <summary>
/// Periodic 15-second background sweeper enforcing the strict 5-minute command timeout,
/// pruning >24h terminal commands, and pruning >10m replay nonces.
/// </summary>
public sealed class BackgroundMaintenanceService : BackgroundService
{
    private readonly RelayDatabase _db;
    private readonly CarPollNotifier _notifier;
    private readonly MetricsTracker _metrics;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<BackgroundMaintenanceService> _logger;

    public BackgroundMaintenanceService(
        RelayDatabase db,
        CarPollNotifier notifier,
        MetricsTracker metrics,
        TimeProvider timeProvider,
        ILogger<BackgroundMaintenanceService> logger)
    {
        _db = db;
        _notifier = notifier;
        _metrics = metrics;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                long nowMs = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
                var (expired, prunedCmds, prunedNonces) = await _db.RunMaintenanceSweepAsync(nowMs, stoppingToken);
                _notifier.PruneIdleChannels();

                if (expired > 0 || prunedCmds > 0)
                {
                    _metrics.LogEvent("SWEEP", $"Expired {expired} overdue command(s); pruned {prunedCmds} >24h record(s), {prunedNonces} nonce(s).");
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during background maintenance sweep.");
            }
        }
    }
}
