using System.Collections.Concurrent;
using System.Net;
using DigitalConnectPlus.Server.Configuration;

namespace DigitalConnectPlus.Server.Security;

public sealed class RateLimitService
{
    private sealed class SlidingCounter
    {
        public readonly object Sync = new();
        public long CurrentMinute;
        public int CurrentCount;
        public int PreviousCount;
        public long LastTouchedMinute;
    }

    private readonly ConcurrentDictionary<string, SlidingCounter> _ipCounters = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SlidingCounter> _carCounters = new(StringComparer.Ordinal);
    private readonly SettingsManager _settings;
    private readonly TimeProvider _timeProvider;
    private int _cleanupTick;

    public RateLimitService(SettingsManager settings, TimeProvider timeProvider)
    {
        _settings = settings;
        _timeProvider = timeProvider;
    }

    public bool TryAcquireIp(string clientIp)
    {
        int limit = Math.Max(5, _settings.Current.RateLimitPerIpPerMinute);
        return TryAcquire(_ipCounters, clientIp, limit);
    }

    public bool TryAcquireCar(string carId)
    {
        int limit = Math.Max(5, _settings.Current.RateLimitPerCarPerMinute);
        return TryAcquire(_carCounters, carId, limit);
    }

    private bool TryAcquire(ConcurrentDictionary<string, SlidingCounter> map, string key, int limitPerMinute)
    {
        DateTimeOffset now = _timeProvider.GetUtcNow();
        long nowMs = now.ToUnixTimeMilliseconds();
        long minute = nowMs / 60_000;
        double elapsedFraction = (nowMs % 60_000) / 60_000.0;

        if ((Interlocked.Increment(ref _cleanupTick) & 0x3FF) == 0)
            PruneOldEntries(map, minute);

        SlidingCounter c = map.GetOrAdd(key, _ => new SlidingCounter { CurrentMinute = minute, LastTouchedMinute = minute });
        lock (c.Sync)
        {
            if (c.CurrentMinute != minute)
            {
                c.PreviousCount = (c.CurrentMinute == minute - 1) ? c.CurrentCount : 0;
                c.CurrentCount = 0;
                c.CurrentMinute = minute;
            }

            c.LastTouchedMinute = minute;
            double estimated = c.PreviousCount * (1.0 - elapsedFraction) + c.CurrentCount;
            if (estimated >= limitPerMinute)
                return false;

            c.CurrentCount++;
            return true;
        }
    }

    private static void PruneOldEntries(ConcurrentDictionary<string, SlidingCounter> map, long currentMinute)
    {
        foreach (var kvp in map)
        {
            if (currentMinute - kvp.Value.LastTouchedMinute > 5)
                map.TryRemove(kvp.Key, out _);
        }
    }

    public string ResolveClientIp(HttpContext http)
    {
        IPAddress? remoteIp = http.Connection.RemoteIpAddress;
        ServerSettings s = _settings.Current;

        if (s.TrustForwardedHeaders && remoteIp != null && IsTrustedProxy(remoteIp, s.TrustedProxyIps))
        {
            string? cfIp = http.Request.Headers["CF-Connecting-IP"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(cfIp) && IPAddress.TryParse(cfIp.Trim(), out IPAddress? parsedCf))
                return NormalizeIp(parsedCf);

            string? xff = http.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(xff))
            {
                string firstHop = xff.Split(',')[0].Trim();
                if (IPAddress.TryParse(firstHop, out IPAddress? parsedXff))
                    return NormalizeIp(parsedXff);
            }
        }

        return remoteIp != null ? NormalizeIp(remoteIp) : "127.0.0.1";
    }

    private static bool IsTrustedProxy(IPAddress remoteIp, List<string> trustedIps)
    {
        IPAddress normalizedRemote = remoteIp.IsIPv4MappedToIPv6 ? remoteIp.MapToIPv4() : remoteIp;
        foreach (string raw in trustedIps)
        {
            string entry = raw.Trim();
            if (string.IsNullOrEmpty(entry)) continue;

            if (entry.Contains('/') && IPNetwork.TryParse(entry, out IPNetwork net))
            {
                if (net.BaseAddress.AddressFamily == normalizedRemote.AddressFamily && net.Contains(normalizedRemote))
                    return true;
                continue;
            }

            if (IPAddress.TryParse(entry, out IPAddress? candidate))
            {
                IPAddress normCand = candidate.IsIPv4MappedToIPv6 ? candidate.MapToIPv4() : candidate;
                if (normCand.Equals(normalizedRemote))
                    return true;
            }
        }
        return false;
    }

    private static string NormalizeIp(IPAddress ip) =>
        (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
}
