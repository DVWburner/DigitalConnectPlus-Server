namespace DigitalConnectPlus.Setup;

internal sealed class SetupForm : Form
{
    private readonly bool _uninstallMode;
    private readonly TextBox _txtInstallDir = new();
    private readonly CheckBox _chkStartService = new();
    private readonly CheckBox _chkLaunchTray = new();
    private readonly CheckBox _chkKeepDataOnUninstall = new();
    private readonly ListBox _lstLog = new();
    private readonly Button _btnAction = new();
    private readonly Button _btnClose = new();

    public SetupForm(bool uninstallMode)
    {
        _uninstallMode = uninstallMode;
        var (isInstalled, oldVer, detectedDir) = InstallerEngine.DetectExistingInstallation();

        Text = uninstallMode
            ? "Uninstall Digital Connect+ Server"
            : isInstalled
                ? $"Upgrade Digital Connect+ Server (to v{InstallerEngine.Version})"
                : $"Install Digital Connect+ Server v{InstallerEngine.Version}";

        Size = new Size(640, 440);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        Font = new Font("Segoe UI", 9.5f);
        BackColor = Color.White;

        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 70,
            BackColor = Color.FromArgb(18, 26, 42),
            Padding = new Padding(18, 12, 18, 10)
        };
        header.Controls.Add(new Label
        {
            Text = "Digital Connect+ Server",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 14f, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(18, 10)
        });
        header.Controls.Add(new Label
        {
            Text = uninstallMode
                ? "Remove Digital Connect+ Server from this computer"
                : isInstalled
                    ? $"Update ready — your paired cars, database, and settings will be kept safely"
                    : "Runs automatically in the background with a taskbar icon for easy setup",
            ForeColor = Color.FromArgb(165, 210, 255),
            AutoSize = true,
            Location = new Point(20, 40)
        });

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18) };

        if (!uninstallMode)
        {
            var lblDir = new Label { Text = "Installation Folder:", AutoSize = true, Location = new Point(18, 14) };
            _txtInstallDir.Text = detectedDir;
            _txtInstallDir.Location = new Point(18, 36);
            _txtInstallDir.Width = 490;

            var btnBrowse = new Button { Text = "Browse...", Location = new Point(516, 34), Width = 86, Height = 27 };
            btnBrowse.Click += (_, _) =>
            {
                using var fbd = new FolderBrowserDialog { SelectedPath = _txtInstallDir.Text };
                if (fbd.ShowDialog(this) == DialogResult.OK)
                    _txtInstallDir.Text = fbd.SelectedPath;
            };

            _chkStartService.Text = "Start Digital Connect+ automatically in the background (Recommended)";
            _chkStartService.Checked = true;
            _chkStartService.AutoSize = true;
            _chkStartService.Location = new Point(18, 72);

            _chkLaunchTray.Text = "Open the Digital Connect+ dashboard when finished";
            _chkLaunchTray.Checked = true;
            _chkLaunchTray.AutoSize = true;
            _chkLaunchTray.Location = new Point(18, 98);

            body.Controls.AddRange([lblDir, _txtInstallDir, btnBrowse, _chkStartService, _chkLaunchTray]);
        }
        else
        {
            _chkKeepDataOnUninstall.Text = $"Keep SQLite database, certificates, and configuration in {InstallerEngine.DataDirectory}";
            _chkKeepDataOnUninstall.Checked = true;
            _chkKeepDataOnUninstall.AutoSize = true;
            _chkKeepDataOnUninstall.Location = new Point(18, 22);
            body.Controls.Add(_chkKeepDataOnUninstall);
        }

        _lstLog.Location = new Point(18, uninstallMode ? 60 : 132);
        _lstLog.Size = new Size(584, uninstallMode ? 205 : 135);
        _lstLog.Font = new Font("Consolas", 8.8f);
        body.Controls.Add(_lstLog);

        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 54,
            FlowDirection = FlowDirection.RightToLeft,
            BackColor = Color.FromArgb(238, 241, 247),
            Padding = new Padding(14, 10, 14, 10)
        };

        _btnClose.Text = "Close";
        _btnClose.Width = 100;
        _btnClose.Height = 32;
        _btnClose.Click += (_, _) => Close();

        _btnAction.Text = uninstallMode
            ? "Uninstall"
            : isInstalled ? "Upgrade Now" : "Install Now";
        _btnAction.Width = 155;
        _btnAction.Height = 32;
        _btnAction.BackColor = uninstallMode ? Color.FromArgb(180, 48, 48) : Color.FromArgb(25, 103, 210);
        _btnAction.ForeColor = Color.White;
        _btnAction.FlatStyle = FlatStyle.Flat;
        _btnAction.FlatAppearance.BorderSize = 0;
        _btnAction.Click += async (_, _) => await ExecuteSetupAsync();

        footer.Controls.Add(_btnClose);
        footer.Controls.Add(_btnAction);

        Controls.Add(body);
        Controls.Add(header);
        Controls.Add(footer);
    }

    private async Task ExecuteSetupAsync()
    {
        _btnAction.Enabled = false;
        var progress = new Progress<string>(msg =>
        {
            _lstLog.Items.Add(msg);
            _lstLog.TopIndex = _lstLog.Items.Count - 1;
        });

        try
        {
            if (_uninstallMode)
            {
                await InstallerEngine.UninstallAsync(_chkKeepDataOnUninstall.Checked, progress);
            }
            else
            {
                await InstallerEngine.InstallOrUpgradeAsync(
                    _txtInstallDir.Text.Trim(),
                    _chkStartService.Checked,
                    _chkLaunchTray.Checked,
                    progress);
            }

            _btnAction.Text = "Completed";
            MessageBox.Show(this,
                _uninstallMode
                    ? "Digital Connect+ Server has been uninstalled."
                    : "Digital Connect+ Server has been installed/updated successfully!\n\nRemember to open the Tray Control Panel and set your purchased domain URL.",
                InstallerEngine.ProductName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            _btnAction.Enabled = true;
            MessageBox.Show(this, $"Setup error: {ex.Message}", "Setup Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        bool uninstall = args.Any(a => a.Equals("/uninstall", StringComparison.OrdinalIgnoreCase) || a.Equals("--uninstall", StringComparison.OrdinalIgnoreCase));
        bool silent = args.Any(a => a.Equals("/silent", StringComparison.OrdinalIgnoreCase) || a.Equals("/S", StringComparison.OrdinalIgnoreCase) || a.Equals("--silent", StringComparison.OrdinalIgnoreCase));

        if (silent)
        {
            var progress = new Progress<string>(Console.WriteLine);
            if (uninstall)
            {
                InstallerEngine.UninstallAsync(keepUserData: true, progress).GetAwaiter().GetResult();
            }
            else
            {
                var (_, _, dir) = InstallerEngine.DetectExistingInstallation();
                InstallerEngine.InstallOrUpgradeAsync(dir, startServiceAfterInstall: true, launchTrayAfterInstall: false, progress)
                    .GetAwaiter().GetResult();
            }
            return 0;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new SetupForm(uninstall));
        return 0;
    }
}
