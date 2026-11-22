namespace DigitalConnectPlus.Server.Services;

public sealed class MetricsTracker
{
    private const int BucketCount = 60;
    private const int MaxRecentEvents = 120;

    private readonly long[] _secondEpoch = new long[BucketCount];
    private readonly int[] _secondHits = new int[BucketCount];
    private readonly object _bucketLock = new();

    private readonly LinkedList<string> _recentEvents = new();
    private readonly object _eventLock = new();

    private long _totalRequests;
    private readonly DateTimeOffset _startedAtUtc = DateTimeOffset.UtcNow;

    public long TotalRequests => Interlocked.Read(ref _totalRequests);
    public long UptimeSeconds => Math.Max(0, (long)(DateTimeOffset.UtcNow - _startedAtUtc).TotalSeconds);

    public void RecordRequest()
    {
        Interlocked.Increment(ref _totalRequests);
        long nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        int idx = (int)(nowSec % BucketCount);

        lock (_bucketLock)
        {
            if (_secondEpoch[idx] != nowSec)
            {
                _secondEpoch[idx] = nowSec;
                _secondHits[idx] = 1;
            }
            else
            {
                _secondHits[idx]++;
            }
        }
    }

    public int GetRequestsInLastMinute()
    {
        long nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        int sum = 0;
        lock (_bucketLock)
        {
            for (int i = 0; i < BucketCount; i++)
            {
                if (nowSec - _secondEpoch[i] < 60)
                    sum += _secondHits[i];
            }
        }
        return sum;
    }

    public void LogEvent(string category, string sanitizedMessage)
    {
        string line = $"[{DateTime.Now:HH:mm:ss}] [{category}] {sanitizedMessage}";
        lock (_eventLock)
        {
            _recentEvents.AddFirst(line);
            while (_recentEvents.Count > MaxRecentEvents)
                _recentEvents.RemoveLast();
        }
    }

    public List<string> GetRecentEvents()
    {
        lock (_eventLock)
        {
            return [.. _recentEvents];
        }
    }
}
