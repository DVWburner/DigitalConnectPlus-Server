using System.Collections.Concurrent;

namespace DigitalConnectPlus.Server.Services;

/// <summary>
/// Race-free generation-numbered in-memory event hub keyed by carId.
/// Wakes waiting /api/v1/car/poll long-polls immediately when /api/v1/commands enqueues a command.
/// </summary>
public sealed class CarPollNotifier
{
    private sealed class CarChannel
    {
        public readonly object Sync = new();
        public long Generation;
        public TaskCompletionSource<bool> Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ActiveWaiters;
        public long LastTouchedTicks = Environment.TickCount64;
    }

    private readonly ConcurrentDictionary<string, CarChannel> _channels = new(StringComparer.Ordinal);
    private int _totalActivePolls;

    public int ActivePollCount => Volatile.Read(ref _totalActivePolls);

    public long GetGeneration(string carId)
    {
        CarChannel ch = _channels.GetOrAdd(carId, _ => new CarChannel());
        lock (ch.Sync)
        {
            ch.LastTouchedTicks = Environment.TickCount64;
            return ch.Generation;
        }
    }

    public void NotifyCommandQueued(string carId)
    {
        CarChannel ch = _channels.GetOrAdd(carId, _ => new CarChannel());
        TaskCompletionSource<bool> toSignal;
        lock (ch.Sync)
        {
            ch.Generation++;
            ch.LastTouchedTicks = Environment.TickCount64;
            toSignal = ch.Tcs;
            ch.Tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        toSignal.TrySetResult(true);
    }

    public async Task<bool> WaitForNextGenerationAsync(
        string carId,
        long observedGeneration,
        TimeSpan timeout,
        CancellationToken ct)
    {
        if (timeout <= TimeSpan.Zero)
            return false;

        CarChannel ch = _channels.GetOrAdd(carId, _ => new CarChannel());
        Task<bool> waitTask;

        lock (ch.Sync)
        {
            ch.LastTouchedTicks = Environment.TickCount64;
            if (ch.Generation != observedGeneration)
                return true;

            ch.ActiveWaiters++;
            waitTask = ch.Tcs.Task;
        }

        Interlocked.Increment(ref _totalActivePolls);
        try
        {
            return await waitTask.WaitAsync(timeout, ct);
        }
        catch (TimeoutException)
        {
            return false;
        }
        finally
        {
            Interlocked.Decrement(ref _totalActivePolls);
            lock (ch.Sync)
            {
                ch.ActiveWaiters--;
                ch.LastTouchedTicks = Environment.TickCount64;
            }
        }
    }

    public void PruneIdleChannels()
    {
        long nowTicks = Environment.TickCount64;
        foreach (var kvp in _channels)
        {
            CarChannel ch = kvp.Value;
            bool shouldRemove = false;
            lock (ch.Sync)
            {
                if (ch.ActiveWaiters == 0 && nowTicks - ch.LastTouchedTicks > 600_000)
                    shouldRemove = true;
            }
            if (shouldRemove)
                _channels.TryRemove(kvp.Key, out _);
        }
    }
}
