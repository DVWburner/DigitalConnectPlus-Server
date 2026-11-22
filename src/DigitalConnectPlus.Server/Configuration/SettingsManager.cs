using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DigitalConnectPlus.Server.Configuration;

public sealed class SettingsManager
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    private readonly object _sync = new();
    private ServerSettings _current;

    public string DataDirectory { get; }
    public string ConfigFilePath { get; }
    public string CertsDirectory { get; }
    public string AcmeDirectory { get; }
    public string LogsDirectory { get; }

    public event Action<ServerSettings>? SettingsChanged;

    public SettingsManager(string? customDataDirectory = null, ServerSettings? inMemoryOverride = null)
    {
        DataDirectory = ResolveDataDirectory(customDataDirectory);
        Directory.CreateDirectory(DataDirectory);

        string configDir = Path.Combine(DataDirectory, "config");
        Directory.CreateDirectory(configDir);
        ConfigFilePath = Path.Combine(configDir, "settings.json");

        CertsDirectory = Path.Combine(DataDirectory, "certs");
        Directory.CreateDirectory(CertsDirectory);

        AcmeDirectory = Path.Combine(DataDirectory, "acme");
        Directory.CreateDirectory(AcmeDirectory);

        LogsDirectory = Path.Combine(DataDirectory, "logs");
        Directory.CreateDirectory(LogsDirectory);

        if (inMemoryOverride != null)
        {
            _current = EnsureInitialized(inMemoryOverride, persistIfChanged: false);
        }
        else
        {
            _current = LoadFromDiskOrCreateDefault();
        }

        ApplyEnvironmentOverrides(_current);
    }

    public ServerSettings Current
    {
        get
        {
            lock (_sync)
            {
                return _current;
            }
        }
    }

    public string ResolveDatabasePath()
    {
        ServerSettings s = Current;
        if (!string.IsNullOrWhiteSpace(s.DatabasePath))
        {
            string? dir = Path.GetDirectoryName(Path.GetFullPath(s.DatabasePath));
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            return Path.GetFullPath(s.DatabasePath);
        }

        string dbDir = Path.Combine(DataDirectory, "data");
        Directory.CreateDirectory(dbDir);
        return Path.Combine(dbDir, "digitalconnect.db");
    }

    public void Save(ServerSettings updated)
    {
        EnsureInitialized(updated, persistIfChanged: false);
        string json = JsonSerializer.Serialize(updated, JsonOpts);

        string tempPath = ConfigFilePath + ".tmp";
        File.WriteAllText(tempPath, json, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(tempPath, ConfigFilePath, overwrite: true);

        lock (_sync)
        {
            _current = updated;
        }

        SettingsChanged?.Invoke(updated);
    }

    public ServerSettings ReloadFromDisk()
    {
        ServerSettings loaded = LoadFromDiskOrCreateDefault();
        ApplyEnvironmentOverrides(loaded);
        lock (_sync)
        {
            _current = loaded;
        }
        SettingsChanged?.Invoke(loaded);
        return loaded;
    }

    private ServerSettings LoadFromDiskOrCreateDefault()
    {
        if (File.Exists(ConfigFilePath))
        {
            try
            {
                string raw = File.ReadAllText(ConfigFilePath, Encoding.UTF8);
                ServerSettings? parsed = JsonSerializer.Deserialize<ServerSettings>(raw, JsonOpts);
                if (parsed != null)
                    return EnsureInitialized(parsed, persistIfChanged: true);
            }
            catch
            {
                // Keep corrupted file backed up before writing clean defaults
                string corruptBackup = ConfigFilePath + $".corrupt-{DateTime.UtcNow:yyyyMMddHHmmss}.bak";
                try { File.Copy(ConfigFilePath, corruptBackup, overwrite: true); } catch { }
            }
        }

        var fresh = new ServerSettings();
        return EnsureInitialized(fresh, persistIfChanged: true);
    }

    private ServerSettings EnsureInitialized(ServerSettings settings, bool persistIfChanged)
    {
        bool changed = false;

        if (string.IsNullOrWhiteSpace(settings.ServerSharedToken))
        {
            settings.ServerSharedToken = ServerSettings.GenerateSecureToken(32);
            changed = true;
        }

        if (settings.Port is < 1 or > 65535)
        {
            settings.Port = 8443;
            changed = true;
        }

        if (settings.HttpAcmePort is < 1 or > 65535)
        {
            settings.HttpAcmePort = 80;
            changed = true;
        }

        if (settings.MaxRequestBodyBytes < 16_384)
        {
            settings.MaxRequestBodyBytes = ServerConstants.DefaultMaxBodyBytes;
            changed = true;
        }

        if (persistIfChanged && changed)
        {
            string json = JsonSerializer.Serialize(settings, JsonOpts);
            File.WriteAllText(ConfigFilePath, json, new UTF8Encoding(false));
        }

        return settings;
    }

    private static void ApplyEnvironmentOverrides(ServerSettings s)
    {
        string? envAuth = Environment.GetEnvironmentVariable("AUTH_MODE");
        if (!string.IsNullOrWhiteSpace(envAuth))
            s.AuthMode = envAuth.Trim();

        string? envSharedToken = Environment.GetEnvironmentVariable("SERVER_SHARED_TOKEN");
        if (!string.IsNullOrWhiteSpace(envSharedToken))
            s.ServerSharedToken = envSharedToken.Trim();

        string? envPort = Environment.GetEnvironmentVariable("PORT");
        if (!string.IsNullOrWhiteSpace(envPort) && int.TryParse(envPort, out int p) && p is >= 1 and <= 65535)
            s.Port = p;

        string? envListen = Environment.GetEnvironmentVariable("LISTEN_INTERFACE");
        if (!string.IsNullOrWhiteSpace(envListen))
            s.ListenInterface = envListen.Trim();

        string? envTlsMode = Environment.GetEnvironmentVariable("TLS_MODE");
        if (!string.IsNullOrWhiteSpace(envTlsMode))
            s.TlsMode = envTlsMode.Trim();

        string? envDbPath = Environment.GetEnvironmentVariable("DB_PATH");
        if (!string.IsNullOrWhiteSpace(envDbPath))
            s.DatabasePath = envDbPath.Trim();

        string? envPublicUrl = Environment.GetEnvironmentVariable("PUBLIC_URL");
        if (envPublicUrl != null)
            s.PublicUrl = envPublicUrl.Trim();
    }

    public static string ResolveDataDirectory(string? customDataDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(customDataDirectory))
            return Path.GetFullPath(customDataDirectory);

        string? envDir = Environment.GetEnvironmentVariable("DCP_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(envDir))
            return Path.GetFullPath(envDir);

        if (OperatingSystem.IsWindows())
        {
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(commonAppData, "DigitalConnectPlus");
        }

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "data"));
    }

    public static string ProtectStringForLocalMachine(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return "";

        byte[] raw = Encoding.UTF8.GetBytes(plainText);
        if (OperatingSystem.IsWindows())
        {
            byte[] encrypted = ProtectedData.Protect(raw, optionalEntropy: null, DataProtectionScope.LocalMachine);
            return Convert.ToBase64String(encrypted);
        }

        return Convert.ToBase64String(raw);
    }

    public static string UnprotectStringFromLocalMachine(string protectedBase64, string plainFallback = "")
    {
        if (!string.IsNullOrEmpty(protectedBase64))
        {
            try
            {
                byte[] bytes = Convert.FromBase64String(protectedBase64);
                if (OperatingSystem.IsWindows())
                {
                    byte[] decrypted = ProtectedData.Unprotect(bytes, optionalEntropy: null, DataProtectionScope.LocalMachine);
                    return Encoding.UTF8.GetString(decrypted);
                }
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                // Fall back if moved across machines
            }
        }
        return plainFallback ?? "";
    }
}
