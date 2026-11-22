using System.Diagnostics;
using System.ServiceProcess;

namespace DigitalConnectPlus.Tray;

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _iconRunning;
    private readonly Icon _iconWarning;
    private readonly Icon _iconStopped;
    private readonly ToolStripMenuItem _mnuStatusHeader;
    private readonly System.Windows.Forms.Timer _trayTimer;
    private readonly EventWaitHandle _showWindowSignal;

    private ControlPanelForm? _controlPanel;

    public TrayApplicationContext(bool openWindowImmediately, EventWaitHandle showWindowSignal)
    {
        _showWindowSignal = showWindowSignal;

        _iconRunning = TrayIcons.CreateStatusIcon(Color.FromArgb(46, 204, 113));
        _iconWarning = TrayIcons.CreateStatusIcon(Color.FromArgb(241, 196, 15));
        _iconStopped = TrayIcons.CreateStatusIcon(Color.FromArgb(231, 76, 60));

        _mnuStatusHeader = new ToolStripMenuItem("Digital Connect+ Server (Checking...)") { Enabled = false };

        var menu = new ContextMenuStrip();
        menu.Items.Add(_mnuStatusHeader);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open Control Panel...", null, (_, _) => ShowControlPanel());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Start Service", null, async (_, _) => await AdminIpcClient.ControlWindowsServiceAsync("start"));
        menu.Items.Add("Stop Service", null, async (_, _) => await AdminIpcClient.ControlWindowsServiceAsync("stop"));
        menu.Items.Add("Restart Service", null, async (_, _) => await AdminIpcClient.ControlWindowsServiceAsync("restart"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open Data & Config Folder", null, (_, _) =>
        {
            string dir = AdminIpcClient.GetDataDirectory();
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit Tray Icon (Service Keeps Running)", null, (_, _) => ExitTray());

        _notifyIcon = new NotifyIcon
        {
            Icon = _iconWarning,
            Text = "Digital Connect+ Server",
            ContextMenuStrip = menu,
            Visible = true
        };
        _notifyIcon.DoubleClick += (_, _) => ShowControlPanel();

        // Listen for second-instance activation signal to pop open the Control Panel
        _ = Task.Run(() =>
        {
            while (true)
            {
                _showWindowSignal.WaitOne();
                if (_controlPanel is { IsDisposed: false })
                    _controlPanel.BeginInvoke(ShowControlPanel);
            }
        });

        _trayTimer = new System.Windows.Forms.Timer { Interval = 4000 };
        _trayTimer.Tick += async (_, _) => await PollTrayStateAsync();
        _trayTimer.Start();
        _ = PollTrayStateAsync();

        if (openWindowImmediately)
            ShowControlPanel();
    }

    private async Task PollTrayStateAsync()
    {
        TrayIpcResponse? ipc = await AdminIpcClient.SendAsync(new TrayIpcCommand { Action = "get_status" }, 900);
        var (svcInstalled, svcStatus) = AdminIpcClient.QueryServiceState();

        if (ipc is { Ok: true, Status: not null })
        {
            bool urlBlank = string.IsNullOrWhiteSpace(ipc.Status.PublicUrl);
            _notifyIcon.Icon = urlBlank ? _iconWarning : _iconRunning;
            _notifyIcon.Text = urlBlank
                ? "Digital Connect+ Server: Running (Set Domain)"
                : $"Digital Connect+ Server: Online ({ipc.Status.RequestsLastMinute} req/m)";
            _mnuStatusHeader.Text = $"Status: Online ({ipc.Status.RegisteredCarCount} cars, {ipc.Status.RequestsLastMinute} req/m)";
        }
        else
        {
            _notifyIcon.Icon = _iconStopped;
            string st = svcInstalled ? svcStatus?.ToString() ?? "Stopped" : "Service Not Installed";
            _notifyIcon.Text = $"Digital Connect+ Server: {st}";
            _mnuStatusHeader.Text = $"Status: {st}";
        }
    }

    public void ShowControlPanel()
    {
        if (_controlPanel == null || _controlPanel.IsDisposed)
            _controlPanel = new ControlPanelForm();

        if (!_controlPanel.Visible)
            _controlPanel.Show();

        if (_controlPanel.WindowState == FormWindowState.Minimized)
            _controlPanel.WindowState = FormWindowState.Normal;

        _controlPanel.BringToFront();
        _controlPanel.Activate();
    }

    private void ExitTray()
    {
        _trayTimer.Stop();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _iconRunning.Dispose();
        _iconWarning.Dispose();
        _iconStopped.Dispose();
        _controlPanel?.Dispose();
        Application.Exit();
    }
}

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        const string mutexName = @"Local\DigitalConnectPlus.Tray.SingleInstance";
        const string eventName = @"Local\DigitalConnectPlus.Tray.ShowControlPanel";

        using var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, eventName);
        using var mutex = new Mutex(true, mutexName, out bool createdNew);

        if (!createdNew)
        {
            // Another Tray instance is already running in this user session — pop open its Control Panel!
            showEvent.Set();
            return;
        }

        // Remove default template Form1 if present; run clean ApplicationContext
        ApplicationConfiguration.Initialize();
        bool openImmediately = args.Any(a => a.Equals("--open", StringComparison.OrdinalIgnoreCase));
        Application.Run(new TrayApplicationContext(openImmediately, showEvent));
    }
}
