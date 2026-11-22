using DigitalConnectPlus.Server.Configuration;
using DigitalConnectPlus.Server.Data;
using DigitalConnectPlus.Server.Models;

namespace DigitalConnectPlus.Server.Cli;

/// <summary>
/// Built-in CLI commands for headless server operators:
///   DigitalConnectPlus.Server.exe token create &lt;label&gt; [--max-cars N]
///   DigitalConnectPlus.Server.exe token list
///   DigitalConnectPlus.Server.exe token revoke &lt;id&gt;
///   DigitalConnectPlus.Server.exe config show
/// </summary>
public static class AdminCliHandler
{
    public static bool IsCliCommand(string[] args)
    {
        if (args.Length == 0) return false;
        string first = args[0].Trim().ToLowerInvariant();
        return first is "token" or "config" or "--help" or "-h" or "help";
    }

    public static async Task<int> ExecuteAsync(string[] args)
    {
        string cmd = args[0].Trim().ToLowerInvariant();
        if (cmd is "--help" or "-h" or "help")
        {
            PrintUsage();
            return 0;
        }

        var settingsManager = new SettingsManager();
        using var db = new RelayDatabase(settingsManager.ResolveDatabasePath());
        await db.InitializeAsync();
        long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        if (cmd == "config")
        {
            ServerSettings s = settingsManager.Current;
            Console.WriteLine($"Digital Connect+ Server v{ServerConstants.Version}");
            Console.WriteLine($"Config File : {settingsManager.ConfigFilePath}");
            Console.WriteLine($"Database    : {db.DatabasePath}");
            Console.WriteLine($"Public URL  : {(string.IsNullOrEmpty(s.PublicUrl) ? "(blank - not configured yet)" : s.PublicUrl)}");
            Console.WriteLine($"Listener    : {s.ListenerEngine} on {s.ListenInterface}:{s.Port} (TLS: {s.TlsMode})");
            Console.WriteLine($"Auth Mode   : {s.AuthMode}");
            return 0;
        }

        if (cmd == "token")
        {
            if (args.Length < 2)
            {
                PrintUsage();
                return 1;
            }

            string sub = args[1].Trim().ToLowerInvariant();
            if (sub == "create")
            {
                string label = args.Length >= 3 && !args[2].StartsWith("--", StringComparison.Ordinal)
                    ? args[2]
                    : "CLI Token";

                int maxCars = settingsManager.Current.MaxCarsPerAccount;
                for (int i = 2; i < args.Length - 1; i++)
                {
                    if (args[i] == "--max-cars" && int.TryParse(args[i + 1], out int parsed))
                        maxCars = Math.Max(1, parsed);
                }

                var (plain, rec) = await db.CreateApiTokenAsync(label, maxCars, nowMs);
                Console.WriteLine($"Created API Token #{rec.Id} ({rec.Label}, maxCars={rec.MaxCars}):");
                Console.WriteLine(plain);
                return 0;
            }

            if (sub == "list")
            {
                List<ApiTokenSummaryDto> tokens = await db.ListApiTokensAsync();
                if (tokens.Count == 0)
                {
                    Console.WriteLine("No API tokens issued.");
                    return 0;
                }

                Console.WriteLine("ID\tSTATUS\tMAX_CARS\tPREFIX\t\tLABEL");
                foreach (ApiTokenSummaryDto t in tokens)
                {
                    string st = t.IsRevoked ? "REVOKED" : "ACTIVE";
                    Console.WriteLine($"{t.Id}\t{st}\t{t.MaxCars}\t\t{t.TokenPrefix}…\t{t.Label}");
                }
                return 0;
            }

            if (sub == "revoke" && args.Length >= 3 && int.TryParse(args[2], out int id))
            {
                bool ok = await db.RevokeApiTokenAsync(id);
                Console.WriteLine(ok ? $"Revoked API token #{id}." : $"Token #{id} not found.");
                return ok ? 0 : 1;
            }
        }

        PrintUsage();
        return 1;
    }

    private static void PrintUsage()
    {
        Console.WriteLine($"""
            {ServerConstants.ProductName} v{ServerConstants.Version}
            Usage:
              DigitalConnectPlus.Server.exe                        (Runs server / Windows Service)
              DigitalConnectPlus.Server.exe config show            (Displays paths & active settings)
              DigitalConnectPlus.Server.exe token create <label> [--max-cars N]
              DigitalConnectPlus.Server.exe token list
              DigitalConnectPlus.Server.exe token revoke <id>
            """);
    }
}
