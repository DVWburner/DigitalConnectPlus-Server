using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.ServiceProcess;
using Microsoft.Win32;

namespace DigitalConnectPlus.Setup;

internal static class InstallerEngine
{
    public const string ProductName = "Digital Connect+ Server";
    public const string Version = "1.0.0";
    public const string ServiceName = "DigitalConnectPlusService";
    public const string UninstallKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\DigitalConnectPlusServer";
    public const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValueName = "DigitalConnectPlusTray";

    public static string DefaultInstallDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Digital Connect+ Server");

    public static string DataDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DigitalConnectPlus");

    public static (bool IsInstalled, string? InstalledVersion, string InstallDir) DetectExistingInstallation()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(UninstallKeyPath, writable: false);
            if (key != null)
            {
                string? loc = key.GetValue("InstallLocation") as string;
                string? ver = key.GetValue("DisplayVersion") as string;
                if (!string.IsNullOrWhiteSpace(loc) && Directory.Exists(loc))
                    return (true, ver, loc);
            }
        }
        catch { }

        if (Directory.Exists(DefaultInstallDir) &&
            File.Exists(Path.Combine(DefaultInstallDir, "DigitalConnectPlus.Server.exe")))
        {
            return (true, null, DefaultInstallDir);
        }

        return (false, null, DefaultInstallDir);
    }

    public static bool HasEmbeddedPayload()
    {
        using Stream? s = Assembly.GetExecutingAssembly().GetManifestResourceStream("DigitalConnectPlus.Payload.zip");
        return s != null;
    }

    public static async Task InstallOrUpgradeAsync(
        string installDir,
        bool startServiceAfterInstall,
        bool launchTrayAfterInstall,
        IProgress<string> log)
    {
        await Task.Run(() =>
        {
            using Stream? payloadStream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("DigitalConnectPlus.Payload.zip")
                ?? throw new InvalidOperationException("Embedded payload.zip not found in setup package. Build via build-installer.ps1.");

            var (existing, oldVer, _) = DetectExistingInstallation();
            log.Report(existing
                ? $"Detected existing installation{(oldVer != null ? $" (v{oldVer})" : "")}. Performing seamless in-place upgrade..."
                : $"Installing {ProductName} v{Version} to '{installDir}'...");

            // 1. Gracefully stop Windows Service & Tray app so binaries are unlocked
            log.Report("Stopping running Windows Service and Tray Monitor (if active)...");
            StopWindowsServiceAndWait();
            TerminateTrayAndServerProcessesInDir(installDir);

            // 2. Back up configuration & SQLite database prior to upgrade (never overwrite user data!)
            BackupExistingUserData(log);

            // 3. Extract self-contained binaries into installDir
            Directory.CreateDirectory(installDir);
            log.Report("Extracting self-contained .NET 10 Server & Tray binaries...");
            using (var archive = new ZipArchive(payloadStream, ZipArchiveMode.Read))
            {
                string fullInstallRoot = Path.GetFullPath(installDir) + Path.DirectorySeparatorChar;
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name))
                        continue;

                    string destPath = Path.GetFullPath(Path.Combine(installDir, entry.FullName));
                    if (!destPath.StartsWith(fullInstallRoot, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Blocked unsafe path in archive.");

                    Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                    entry.ExtractToFile(destPath, overwrite: true);
                }
            }

            // Copy Setup binary for future clean uninstallation
            string? selfExe = Environment.ProcessPath;
            string uninstallerPath = Path.Combine(installDir, "Uninstall", "DigitalConnectPlus-Setup.exe");
            if (!string.IsNullOrEmpty(selfExe) && File.Exists(selfExe))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(uninstallerPath)!);
                if (!string.Equals(Path.GetFullPath(selfExe), Path.GetFullPath(uninstallerPath), StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(selfExe, uninstallerPath, overwrite: true);
                }
            }

            // 4. Register / Update Windows Service + Auto-Recovery policy
            string serverExe = Path.Combine(installDir, "DigitalConnectPlus.Server.exe");
            string trayExe = Path.Combine(installDir, "DigitalConnectPlus.Tray.exe");

            log.Report("Registering Windows Service (DigitalConnectPlusService)...");
            RegisterOrUpdateService(serverExe);
            EnsureFirewallRuleForServerExe(serverExe, log);

            // 5. Register Tray Auto-Start, Start Menu Shortcut, and Windows Uninstall entry
            log.Report("Configuring Tray auto-start and Windows Installed Apps entry...");
            RegisterStartupAndUninstaller(installDir, trayExe, uninstallerPath);
            CreateStartMenuShortcut(trayExe, installDir);

            // 6. Start Windows Service
            if (startServiceAfterInstall)
            {
                log.Report("Starting Digital Connect+ Server Windows Service...");
                StartWindowsService();
            }

            // 7. Launch Tray Monitor in interactive session
            if (launchTrayAfterInstall && Environment.UserInteractive && File.Exists(trayExe))
            {
                log.Report("Launching System Tray Control Panel...");
                Process.Start(new ProcessStartInfo(trayExe, "--open")
                {
                    WorkingDirectory = installDir,
                    UseShellExecute = true
                });
            }

            log.Report("Complete! Digital Connect+ Server is installed and running.");
        });
    }

    public static async Task UninstallAsync(bool keepUserData, IProgress<string> log)
    {
        await Task.Run(() =>
        {
            var (_, _, installDir) = DetectExistingInstallation();

            log.Report("Stopping and removing Windows Service...");
            StopWindowsServiceAndWait();
            RunSc($"delete {ServiceName}");

            log.Report("Closing System Tray Monitor...");
            TerminateTrayAndServerProcessesInDir(installDir);

            try
            {
                const string ruleName = "Digital Connect+ Server (Inbound)";
                using Process? fw = Process.Start(new ProcessStartInfo("netsh.exe", $"advfirewall firewall delete rule name=\"{ruleName}\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
                fw?.WaitForExit(5000);
            }
            catch { }

            try
            {
                using RegistryKey? runKey = Registry.LocalMachine.OpenSubKey(RunKeyPath, writable: true);
                runKey?.DeleteValue(RunValueName, throwOnMissingValue: false);
            }
            catch { }

            try
            {
                Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath, throwOnMissingSubKey: false);
            }
            catch { }

            string shortcutPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
                "Digital Connect+ Server.lnk");
            try { if (File.Exists(shortcutPath)) File.Delete(shortcutPath); } catch { }

            if (Directory.Exists(installDir))
            {
                log.Report($"Removing binaries in '{installDir}'...");
                string? currentExe = Environment.ProcessPath;
                foreach (string file in Directory.EnumerateFiles(installDir, "*", SearchOption.AllDirectories))
                {
                    if (!string.IsNullOrEmpty(currentExe) &&
                        string.Equals(Path.GetFullPath(file), Path.GetFullPath(currentExe), StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    try { File.Delete(file); } catch { }
                }

                // Schedule deferred cleanup of directory if running uninstaller from inside installDir
                Process.Start(new ProcessStartInfo("cmd.exe", $"/c timeout /t 2 /nobreak >nul & rmdir /s /q \"{installDir}\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                });
            }

            if (!keepUserData && Directory.Exists(DataDirectory))
            {
                log.Report($"Removing data directory '{DataDirectory}'...");
                try { Directory.Delete(DataDirectory, recursive: true); } catch { }
            }

            log.Report("Uninstallation completed.");
        });
    }

    private static void BackupExistingUserData(IProgress<string> log)
    {
        try
        {
            string cfgFile = Path.Combine(DataDirectory, "config", "settings.json");
            string dbFile = Path.Combine(DataDirectory, "data", "digitalconnect.db");
            if (!File.Exists(cfgFile) && !File.Exists(dbFile))
                return;

            string backupFolder = Path.Combine(DataDirectory, "backups", $"pre-upgrade-{DateTime.UtcNow:yyyyMMdd-HHmmss}");
            Directory.CreateDirectory(backupFolder);

            if (File.Exists(cfgFile))
                File.Copy(cfgFile, Path.Combine(backupFolder, "settings.json"), overwrite: true);
            if (File.Exists(dbFile))
                File.Copy(dbFile, Path.Combine(backupFolder, "digitalconnect.db"), overwrite: true);

            log.Report($"Backed up existing settings & SQLite DB to '{backupFolder}'.");
        }
        catch { }
    }

    private static void StopWindowsServiceAndWait()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status is not ServiceControllerStatus.Stopped and not ServiceControllerStatus.StopPending)
            {
                sc.Stop();
            }
            sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(25));
        }
        catch
        {
            // Service does not exist yet
        }
    }

    private static void StartWindowsService()
    {
        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped)
        {
            sc.Start();
            sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(25));
        }
    }

    private static void TerminateTrayAndServerProcessesInDir(string installDir)
    {
        string normalizedRoot = Path.GetFullPath(installDir);
        foreach (string procName in new[] { "DigitalConnectPlus.Tray", "DigitalConnectPlus.Server" })
        {
            foreach (Process p in Process.GetProcessesByName(procName))
            {
                try
                {
                    string? path = p.MainModule?.FileName;
                    if (path == null || path.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        p.Kill(entireProcessTree: true);
                        p.WaitForExit(5000);
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        Thread.Sleep(400);
    }

    private static void RegisterOrUpdateService(string serverExePath)
    {
        bool exists = false;
        try
        {
            using var sc = new ServiceController(ServiceName);
            _ = sc.Status;
            exists = true;
        }
        catch { }

        string quotedBin = $"\\\"{serverExePath}\\\"";
        if (!exists)
        {
            RunSc($"create {ServiceName} binPath= \"{quotedBin}\" start= auto DisplayName= \"{ProductName}\"");
        }
        else
        {
            RunSc($"config {ServiceName} binPath= \"{quotedBin}\" start= auto DisplayName= \"{ProductName}\"");
        }

        RunSc($"description {ServiceName} \"Zero-Trust End-to-End Encrypted Relay Server for Gen5W Digital Control\"");
        RunSc($"failure {ServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000");
    }

    private static void RegisterStartupAndUninstaller(string installDir, string trayExe, string uninstallerExe)
    {
        using (RegistryKey runKey = Registry.LocalMachine.CreateSubKey(RunKeyPath, writable: true))
        {
            runKey.SetValue(RunValueName, $"\"{trayExe}\"");
        }

        using (RegistryKey unKey = Registry.LocalMachine.CreateSubKey(UninstallKeyPath, writable: true))
        {
            unKey.SetValue("DisplayName", ProductName);
            unKey.SetValue("DisplayVersion", Version);
            unKey.SetValue("Publisher", "Digital Connect+");
            unKey.SetValue("InstallLocation", installDir);
            unKey.SetValue("DisplayIcon", trayExe);
            unKey.SetValue("UninstallString", $"\"{uninstallerExe}\" /uninstall");
            unKey.SetValue("NoModify", 1, RegistryValueKind.DWord);
            unKey.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        }
    }

    private static void CreateStartMenuShortcut(string trayExe, string installDir)
    {
        try
        {
            string lnkPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
                "Digital Connect+ Server.lnk");

            string ps = $"$s=(New-Object -COM WScript.Shell).CreateShortcut('{lnkPath.Replace("'", "''")}');" +
                        $"$s.TargetPath='{trayExe.Replace("'", "''")}';" +
                        $"$s.Arguments='--open';" +
                        $"$s.WorkingDirectory='{installDir.Replace("'", "''")}';" +
                        $"$s.Description='Digital Connect+ Server Control Panel';" +
                        $"$s.Save();";

            using Process? p = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{ps}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
            p?.WaitForExit(5000);
        }
        catch { }
    }

    private static void EnsureFirewallRuleForServerExe(string serverExePath, IProgress<string> log)
    {
        try
        {
            const string ruleName = "Digital Connect+ Server (Inbound)";
            string args = $"/c netsh advfirewall firewall delete rule name=\"{ruleName}\" >nul 2>&1 & " +
                          $"netsh advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow program=\"{serverExePath}\" enable=yes profile=any";
            using Process? p = Process.Start(new ProcessStartInfo("cmd.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
            p?.WaitForExit(8000);
            log.Report($"Configured Windows Firewall inbound allow rule for {Path.GetFileName(serverExePath)}.");
        }
        catch { }
    }

    private static void RunSc(string arguments)
    {
        using Process? p = Process.Start(new ProcessStartInfo("sc.exe", arguments)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        });
        p?.WaitForExit(10_000);
    }
}
