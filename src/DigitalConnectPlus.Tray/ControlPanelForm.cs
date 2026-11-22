using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;

namespace DigitalConnectPlus.Tray;

internal sealed class ControlPanelForm : Form
{
    private sealed record AdapterChoice(string Value, string Label)
    {
        public override string ToString() => Label;
    }

    private readonly System.Windows.Forms.Timer _pollTimer;
    private TrayServerSettings _loadedSettings = new();
    private bool _settingsLoadedOnce;
    private bool _suppressModeEvents;

    private TabControl _tabs = null!;

    // Header & Setup Banner
    private readonly Label _lblServiceState = new();
    private readonly Panel _setupBanner = new();
    private readonly Label _lblBannerText = new();
    private readonly Button _btnTestConnection = new();
    private readonly Button _btnStartStopSvc = new();
    private readonly Button _btnRestartSvc = new();
    private readonly Button _btnElevate = new();

    // Tab 1: Overview
    private readonly TextBox _txtAppUrlDisplay = new();
    private readonly Panel _pnlAppTokenRow = new();
    private readonly TextBox _txtAppTokenDisplay = new();
    private readonly Label _valCars = new();
    private readonly Label _valActivePolls = new();
    private readonly Label _valQueued = new();
    private readonly Label _valReqMin = new();
    private readonly Label _valCertSummary = new();
    private readonly ListBox _lstEvents = new();

    // Tab 2: Connection & SSL (Guided!)
    private readonly TextBox _txtDomain = new();
    private readonly RadioButton _radLetsEncrypt = new();
    private readonly RadioButton _radReverseProxy = new();
    private readonly RadioButton _radExistingCert = new();

    // Mode Card A: Automatic Let's Encrypt
    private readonly Panel _cardLetsEncrypt = new();
    private readonly TextBox _txtLeEmail = new();
    private readonly NumericUpDown _numLeHttpsPort = new();
    private readonly Button _btnIssueLeNow = new();

    // Mode Card B: Behind Router / Reverse Proxy
    private readonly Panel _cardProxy = new();
    private readonly NumericUpDown _numProxyPort = new();
    private readonly ComboBox _cmbProxyProtocol = new();
    private readonly ComboBox _cmbProxyAdapter = new();

    // Mode Card C: Existing Windows / PFX Certificate
    private readonly Panel _cardExistingCert = new();
    private readonly RadioButton _radWinCertAuto = new();
    private readonly RadioButton _radWinCertPick = new();
    private readonly RadioButton _radPfxFile = new();
    private readonly TextBox _txtCertThumbprint = new();
    private readonly TextBox _txtPfxPath = new();
    private readonly TextBox _txtPfxPassword = new();
    private readonly NumericUpDown _numCertPort = new();
    private readonly ComboBox _cmbCertAdapter = new();

    // Tab 3: Access & Protection
    private readonly RadioButton _radAuthPersonalAuto = new();
    private readonly RadioButton _radAuthSharedKey = new();
    private readonly RadioButton _radAuthMultiUser = new();
    private readonly Panel _pnlSharedKeyCard = new();
    private readonly TextBox _txtSharedToken = new();
    private readonly Panel _pnlMultiUserCard = new();
    private readonly CheckBox _chkAllowPublicReg = new();
    private readonly NumericUpDown _numMaxCars = new();
    private readonly ListView _lstApiTokens = new();
    private readonly TextBox _txtNewTokenLabel = new();
    private readonly NumericUpDown _numRateCar = new();
    private readonly NumericUpDown _numRateIp = new();
    private readonly NumericUpDown _numMaxQueued = new();

    private readonly Label _lblFooterStatus = new();

    public ControlPanelForm()
    {
        Text = "Digital Connect+ Server";
        Size = new Size(880, 690);
        MinimumSize = new Size(840, 640);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9.5f);
        BackColor = Color.FromArgb(245, 247, 251);

        BuildLayout();

        _pollTimer = new System.Windows.Forms.Timer { Interval = 2500 };
        _pollTimer.Tick += async (_, _) => await RefreshLiveStatusAsync();

        Shown += async (_, _) =>
        {
            await LoadConfigurationIntoFormAsync();
            await RefreshLiveStatusAsync();
            await RefreshApiTokensAsync();
            _pollTimer.Start();
        };

        FormClosing += (_, e) =>
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                Hide();
            }
        };
    }

    private void BuildLayout()
    {
        // Top Header
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 68,
            BackColor = Color.FromArgb(18, 28, 45),
            Padding = new Padding(18, 10, 18, 10)
        };

        var lblTitle = new Label
        {
            Text = "Digital Connect+ Server",
            ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 14.5f, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(18, 9)
        };

        _lblServiceState.Text = "Checking server status...";
        _lblServiceState.ForeColor = Color.FromArgb(160, 215, 255);
        _lblServiceState.Font = new Font("Segoe UI", 9.5f);
        _lblServiceState.AutoSize = true;
        _lblServiceState.Location = new Point(20, 38);

        var headerBtns = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 8, 0, 0)
        };

        ConfigureHeaderButton(_btnElevate, "Unlock Admin", Color.FromArgb(150, 105, 25), 115);
        ConfigureHeaderButton(_btnTestConnection, "Test Connection", Color.FromArgb(32, 136, 78), 135);
        ConfigureHeaderButton(_btnStartStopSvc, "Stop Server", Color.FromArgb(165, 58, 58), 110);
        ConfigureHeaderButton(_btnRestartSvc, "Restart", Color.FromArgb(52, 98, 172), 90);

        _btnElevate.Visible = !AdminIpcClient.IsCurrentProcessAdmin();
        _btnElevate.Click += (_, _) => AdminIpcClient.RelaunchAsAdmin();
        _btnTestConnection.Click += async (_, _) => await RunConnectionSelfTestAsync();
        _btnStartStopSvc.Click += async (_, _) =>
        {
            string act = _btnStartStopSvc.Tag as string ?? "start";
            await RunServiceActionAsync(act);
        };
        _btnRestartSvc.Click += async (_, _) => await RunServiceActionAsync("restart");

        headerBtns.Controls.AddRange([_btnElevate, _btnTestConnection, _btnStartStopSvc, _btnRestartSvc]);
        header.Controls.Add(lblTitle);
        header.Controls.Add(_lblServiceState);
        header.Controls.Add(headerBtns);

        // Friendly Guided First-Time Setup Banner
        _setupBanner.Dock = DockStyle.Top;
        _setupBanner.Height = 38;
        _setupBanner.BackColor = Color.FromArgb(255, 244, 212);
        _setupBanner.Padding = new Padding(18, 0, 18, 0);
        _setupBanner.Visible = false;

        _lblBannerText.Dock = DockStyle.Fill;
        _lblBannerText.ForeColor = Color.FromArgb(115, 72, 0);
        _lblBannerText.TextAlign = ContentAlignment.MiddleLeft;
        _lblBannerText.Text = "Welcome! Step 1: Click 'Connection & SSL' below and enter the domain name you bought.";

        var btnGoSetup = new Button
        {
            Text = "Set Up Domain ->",
            Dock = DockStyle.Right,
            Width = 135,
            FlatStyle = FlatStyle.System
        };
        btnGoSetup.Click += (_, _) => _tabs.SelectedIndex = 1;
        _setupBanner.Controls.Add(_lblBannerText);
        _setupBanner.Controls.Add(btnGoSetup);

        // Bottom Save Bar
        var footer = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 56,
            BackColor = Color.FromArgb(234, 238, 246),
            Padding = new Padding(18, 10, 18, 10)
        };

        _lblFooterStatus.Text = "Changes take effect when you click Save Changes.";
        _lblFooterStatus.AutoSize = true;
        _lblFooterStatus.Location = new Point(18, 18);
        _lblFooterStatus.ForeColor = Color.FromArgb(55, 65, 82);

        var btnSave = new Button
        {
            Text = "Save Changes",
            Dock = DockStyle.Right,
            Width = 175,
            BackColor = Color.FromArgb(25, 103, 210),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI Semibold", 10f, FontStyle.Bold)
        };
        btnSave.FlatAppearance.BorderSize = 0;
        btnSave.Click += async (_, _) => await SaveConfigurationFromFormAsync();

        var btnOpenFolder = new Button
        {
            Text = "Open Data Folder",
            Dock = DockStyle.Right,
            Width = 135,
            FlatStyle = FlatStyle.System
        };
        btnOpenFolder.Click += (_, _) =>
        {
            string dir = AdminIpcClient.GetDataDirectory();
            Directory.CreateDirectory(dir);
            Process.Start(new ProcessStartInfo("explorer.exe", dir) { UseShellExecute = true });
        };

        footer.Controls.Add(_lblFooterStatus);
        footer.Controls.Add(btnOpenFolder);
        footer.Controls.Add(new Panel { Dock = DockStyle.Right, Width = 10 });
        footer.Controls.Add(btnSave);

        // 3 Clean, Approachable Tabs
        _tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Padding = new Point(16, 7),
            Font = new Font("Segoe UI Semibold", 9.8f)
        };
        _tabs.TabPages.Add(BuildOverviewTab());
        _tabs.TabPages.Add(BuildConnectionTab());
        _tabs.TabPages.Add(BuildAccessTab());

        Controls.Add(_tabs);
        Controls.Add(_setupBanner);
        Controls.Add(header);
        Controls.Add(footer);
    }

    // =========================================================================
    // TAB 1: OVERVIEW (Copy-Paste App Details + Simple Live Stats)
    // =========================================================================
    private TabPage BuildOverviewTab()
    {
        var page = new TabPage("Overview")
        {
            BackColor = Color.White,
            Padding = new Padding(18),
            Font = new Font("Segoe UI", 9.5f)
        };

        // Card 1: What to enter in the Phone & Car Apps!
        var appCard = new GroupBox
        {
            Text = "Phone & Car App Connection Info",
            Dock = DockStyle.Top,
            Height = 128,
            Padding = new Padding(14, 10, 14, 10)
        };

        var urlRow = new Panel { Dock = DockStyle.Top, Height = 36 };
        urlRow.Controls.Add(new Label
        {
            Text = "Server URL for App:",
            Location = new Point(2, 7),
            Width = 155,
            ForeColor = Color.FromArgb(55, 65, 85)
        });
        _txtAppUrlDisplay.ReadOnly = true;
        _txtAppUrlDisplay.Location = new Point(160, 4);
        _txtAppUrlDisplay.Width = 430;
        _txtAppUrlDisplay.BackColor = Color.FromArgb(245, 248, 252);
        var btnCopyUrl = new Button { Text = "Copy URL", Location = new Point(598, 3), Width = 105, Height = 28 };
        btnCopyUrl.Click += (_, _) =>
        {
            if (_txtAppUrlDisplay.Text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                Clipboard.SetText(_txtAppUrlDisplay.Text);
                _lblFooterStatus.Text = "Copied Server URL to clipboard!";
            }
            else
            {
                _tabs.SelectedIndex = 1;
            }
        };
        urlRow.Controls.AddRange([_txtAppUrlDisplay, btnCopyUrl]);

        _pnlAppTokenRow.Dock = DockStyle.Top;
        _pnlAppTokenRow.Height = 36;
        _pnlAppTokenRow.Visible = false;
        _pnlAppTokenRow.Controls.Add(new Label
        {
            Text = "Secret Access Key:",
            Location = new Point(2, 7),
            Width = 155,
            ForeColor = Color.FromArgb(55, 65, 85)
        });
        _txtAppTokenDisplay.ReadOnly = true;
        _txtAppTokenDisplay.Location = new Point(160, 4);
        _txtAppTokenDisplay.Width = 430;
        _txtAppTokenDisplay.BackColor = Color.FromArgb(245, 248, 252);
        var btnCopyTok = new Button { Text = "Copy Key", Location = new Point(598, 3), Width = 105, Height = 28 };
        btnCopyTok.Click += (_, _) =>
        {
            if (!string.IsNullOrEmpty(_txtAppTokenDisplay.Text))
            {
                Clipboard.SetText(_txtAppTokenDisplay.Text);
                _lblFooterStatus.Text = "Copied Secret Access Key to clipboard!";
            }
        };
        _pnlAppTokenRow.Controls.AddRange([_txtAppTokenDisplay, btnCopyTok]);

        _valCertSummary.Dock = DockStyle.Bottom;
        _valCertSummary.Height = 22;
        _valCertSummary.ForeColor = Color.FromArgb(80, 95, 115);
        _valCertSummary.Text = "SSL Status: Checking...";

        appCard.Controls.Add(_pnlAppTokenRow);
        appCard.Controls.Add(urlRow);
        appCard.Controls.Add(_valCertSummary);

        // Card 2: 4 Friendly Stat Tiles
        var statsGrid = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 92,
            ColumnCount = 4,
            RowCount = 1,
            Padding = new Padding(0, 8, 0, 8)
        };
        for (int i = 0; i < 4; i++)
            statsGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 25f));
        statsGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));

        statsGrid.Controls.Add(CreateMetricCard("Paired Cars", _valCars, "0"), 0, 0);
        statsGrid.Controls.Add(CreateMetricCard("Cars Connected Now", _valActivePolls, "0"), 1, 0);
        statsGrid.Controls.Add(CreateMetricCard("Waiting Commands", _valQueued, "0"), 2, 0);
        statsGrid.Controls.Add(CreateMetricCard("Requests / Minute", _valReqMin, "0"), 3, 0);

        // Card 3: Activity Feed
        var feedBox = new GroupBox
        {
            Text = "Recent Server Activity (All vehicle commands stay end-to-end encrypted)",
            Dock = DockStyle.Fill,
            Padding = new Padding(10)
        };
        _lstEvents.Dock = DockStyle.Fill;
        _lstEvents.Font = new Font("Consolas", 9f);
        _lstEvents.IntegralHeight = false;
        feedBox.Controls.Add(_lstEvents);

        page.Controls.Add(feedBox);
        page.Controls.Add(statsGrid);
        page.Controls.Add(appCard);
        return page;
    }

    // =========================================================================
    // TAB 2: CONNECTION & SSL (Guided Plain-English Setup)
    // =========================================================================
    private TabPage BuildConnectionTab()
    {
        var page = new TabPage("Connection & SSL")
        {
            BackColor = Color.White,
            Padding = new Padding(18),
            Font = new Font("Segoe UI", 9.5f),
            AutoScroll = true
        };

        // Step 1: Domain Name
        var step1 = new GroupBox
        {
            Text = "Step 1 — Your Domain Name",
            Dock = DockStyle.Top,
            Height = 92,
            Padding = new Padding(14, 10, 14, 8)
        };
        var lblDom = new Label
        {
            Text = "Web Address (Domain):",
            Location = new Point(14, 28),
            AutoSize = true
        };
        _txtDomain.PlaceholderText = "Example: remote.mydomain.com   (starts blank — enter the domain you bought)";
        _txtDomain.Location = new Point(175, 25);
        _txtDomain.Width = 540;
        var lblDomHint = new Label
        {
            Text = "Point your domain's DNS 'A' record to your internet IP (or Cloudflare) so your car and phone can find this server.",
            Location = new Point(175, 55),
            AutoSize = true,
            ForeColor = Color.FromArgb(95, 108, 128),
            Font = new Font("Segoe UI", 8.5f)
        };
        step1.Controls.AddRange([lblDom, _txtDomain, lblDomHint]);

        // Step 2: How is this computer connected?
        var step2 = new GroupBox
        {
            Text = "Step 2 — How is this computer connected to the internet?",
            Dock = DockStyle.Top,
            Height = 128,
            Padding = new Padding(14, 8, 14, 8)
        };

        _radLetsEncrypt.Text = "Automatic Free SSL with Let's Encrypt  (Easiest if you port-forward directly from your home/office router)";
        _radLetsEncrypt.AutoSize = true;
        _radLetsEncrypt.Location = new Point(16, 26);

        _radReverseProxy.Text = "Behind My Own Firewall / Reverse Proxy  (Cloudflare + Firewall, Nginx, Caddy, Apache, pfSense)";
        _radReverseProxy.AutoSize = true;
        _radReverseProxy.Location = new Point(16, 56);

        _radExistingCert.Text = "Use an Existing Certificate on Windows  (Windows Certificate Store, Certify The Web, win-acme, or .PFX file)";
        _radExistingCert.AutoSize = true;
        _radExistingCert.Location = new Point(16, 86);

        _radLetsEncrypt.CheckedChanged += (_, _) => UpdateConnectionModeCards();
        _radReverseProxy.CheckedChanged += (_, _) => UpdateConnectionModeCards();
        _radExistingCert.CheckedChanged += (_, _) => UpdateConnectionModeCards();

        step2.Controls.AddRange([_radLetsEncrypt, _radReverseProxy, _radExistingCert]);

        // --- Dynamic Card A: Let's Encrypt ---
        BuildLetsEncryptCard();

        // --- Dynamic Card B: Reverse Proxy / Firewall ---
        BuildReverseProxyCard();

        // --- Dynamic Card C: Existing Certificate ---
        BuildExistingCertCard();

        // Subtle Advanced Link at the bottom
        var bottomAdvPanel = new Panel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4, 8, 4, 0) };
        var lnkAdv = new LinkLabel
        {
            Text = "Advanced network options (IIS Port 443 sharing, custom proxy IPs)...",
            AutoSize = true,
            Location = new Point(4, 8)
        };
        lnkAdv.LinkClicked += (_, _) =>
        {
            using var dlg = new AdvancedNetworkDialog(_loadedSettings, BindHttpSysSslCert);
            if (dlg.ShowDialog(this) == DialogResult.OK)
                _lblFooterStatus.Text = "Updated advanced options. Click 'Save Changes' to apply.";
        };
        bottomAdvPanel.Controls.Add(lnkAdv);

        // Add in reverse DockStyle.Top order
        page.Controls.Add(bottomAdvPanel);
        page.Controls.Add(_cardExistingCert);
        page.Controls.Add(_cardProxy);
        page.Controls.Add(_cardLetsEncrypt);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 8 });
        page.Controls.Add(step2);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 8 });
        page.Controls.Add(step1);
        return page;
    }

    private void BuildLetsEncryptCard()
    {
        _cardLetsEncrypt.Dock = DockStyle.Top;
        _cardLetsEncrypt.Height = 165;
        _cardLetsEncrypt.BackColor = Color.FromArgb(244, 248, 254);
        _cardLetsEncrypt.Padding = new Padding(16);

        var lblInfo = new Label
        {
            Text = "Digital Connect+ will automatically get and renew a free Let's Encrypt certificate every 60 days.\n" +
                   "Router checklist: Forward TCP Port 80 and TCP Port 443 on your router to this Windows PC.",
            Location = new Point(16, 12),
            AutoSize = true,
            ForeColor = Color.FromArgb(40, 62, 96)
        };

        var lblEmail = new Label { Text = "Email for expiry alerts (optional):", Location = new Point(16, 66), AutoSize = true };
        _txtLeEmail.PlaceholderText = "you@example.com";
        _txtLeEmail.Location = new Point(235, 63);
        _txtLeEmail.Width = 310;

        var lblPort = new Label { Text = "HTTPS Port:", Location = new Point(16, 102), AutoSize = true };
        _numLeHttpsPort.Minimum = 1; _numLeHttpsPort.Maximum = 65535; _numLeHttpsPort.Value = 443;
        _numLeHttpsPort.Location = new Point(235, 99);
        _numLeHttpsPort.Width = 95;

        _btnIssueLeNow.Text = "Get / Renew Certificate Now";
        _btnIssueLeNow.Location = new Point(350, 96);
        _btnIssueLeNow.Width = 215;
        _btnIssueLeNow.Height = 30;
        _btnIssueLeNow.Click += async (_, _) => await TriggerLetsEncryptNowAsync();

        _cardLetsEncrypt.Controls.AddRange([lblInfo, lblEmail, _txtLeEmail, lblPort, _numLeHttpsPort, _btnIssueLeNow]);
    }

    private void BuildReverseProxyCard()
    {
        _cardProxy.Dock = DockStyle.Top;
        _cardProxy.Height = 175;
        _cardProxy.BackColor = Color.FromArgb(244, 248, 254);
        _cardProxy.Padding = new Padding(16);

        var lblInfo = new Label
        {
            Text = "Your gateway firewall or reverse proxy handles the public SSL certificate and forwards requests to this PC.",
            Location = new Point(16, 12),
            AutoSize = true,
            ForeColor = Color.FromArgb(40, 62, 96)
        };

        var lblPort = new Label { Text = "Port on this PC:", Location = new Point(16, 48), AutoSize = true };
        _numProxyPort.Minimum = 1; _numProxyPort.Maximum = 65535; _numProxyPort.Value = 8443;
        _numProxyPort.Location = new Point(220, 45);
        _numProxyPort.Width = 100;

        var lblProto = new Label { Text = "Traffic from your proxy:", Location = new Point(16, 84), AutoSize = true };
        _cmbProxyProtocol.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbProxyProtocol.Location = new Point(220, 81);
        _cmbProxyProtocol.Width = 460;
        _cmbProxyProtocol.Items.AddRange([
            "HTTPS — Encrypted internal link (proxy connects to https://this-pc:port)",
            "HTTP — Unencrypted local link (proxy connects to http://this-pc:port)"
        ]);

        var lblNic = new Label { Text = "Listen on network adapter:", Location = new Point(16, 120), AutoSize = true };
        _cmbProxyAdapter.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbProxyAdapter.Location = new Point(220, 117);
        _cmbProxyAdapter.Width = 460;
        PopulateAdapterChoices(_cmbProxyAdapter);

        _cardProxy.Controls.AddRange([lblInfo, lblPort, _numProxyPort, lblProto, _cmbProxyProtocol, lblNic, _cmbProxyAdapter]);
    }

    private void BuildExistingCertCard()
    {
        _cardExistingCert.Dock = DockStyle.Top;
        _cardExistingCert.Height = 215;
        _cardExistingCert.BackColor = Color.FromArgb(244, 248, 254);
        _cardExistingCert.Padding = new Padding(16);

        _radWinCertAuto.Text = "Automatically use the newest Windows certificate matching my domain name (great for Certify / win-acme)";
        _radWinCertAuto.AutoSize = true;
        _radWinCertAuto.Location = new Point(16, 14);

        _radWinCertPick.Text = "Pick a specific certificate from Windows:";
        _radWinCertPick.AutoSize = true;
        _radWinCertPick.Location = new Point(16, 46);

        _txtCertThumbprint.PlaceholderText = "Selected certificate ID";
        _txtCertThumbprint.Location = new Point(275, 44);
        _txtCertThumbprint.Width = 260;

        var btnPickWin = new Button { Text = "Choose Certificate...", Location = new Point(545, 42), Width = 155, Height = 27 };
        btnPickWin.Click += (_, _) =>
        {
            _radWinCertPick.Checked = true;
            using var dlg = new CertificatePickerDialog("LocalMachine", "My");
            if (dlg.ShowDialog(this) == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedThumbprint))
                _txtCertThumbprint.Text = dlg.SelectedThumbprint;
        };

        _radPfxFile.Text = "Use a .PFX certificate file:";
        _radPfxFile.AutoSize = true;
        _radPfxFile.Location = new Point(16, 80);

        _txtPfxPath.PlaceholderText = "C:\\path\\to\\certificate.pfx";
        _txtPfxPath.Location = new Point(210, 78);
        _txtPfxPath.Width = 240;

        var btnPickPfx = new Button { Text = "Browse...", Location = new Point(456, 76), Width = 85, Height = 27 };
        btnPickPfx.Click += (_, _) =>
        {
            _radPfxFile.Checked = true;
            using var ofd = new OpenFileDialog { Filter = "Certificate Files (*.pfx;*.p12)|*.pfx;*.p12|All Files (*.*)|*.*" };
            if (ofd.ShowDialog(this) == DialogResult.OK)
                _txtPfxPath.Text = ofd.FileName;
        };

        _txtPfxPassword.UseSystemPasswordChar = true;
        _txtPfxPassword.PlaceholderText = "PFX Password";
        _txtPfxPassword.Location = new Point(548, 78);
        _txtPfxPassword.Width = 152;

        var lblPort = new Label { Text = "HTTPS Port:", Location = new Point(16, 122), AutoSize = true };
        _numCertPort.Minimum = 1; _numCertPort.Maximum = 65535; _numCertPort.Value = 443;
        _numCertPort.Location = new Point(210, 119);
        _numCertPort.Width = 100;

        var lblNic = new Label { Text = "Listen on network adapter:", Location = new Point(16, 158), AutoSize = true };
        _cmbCertAdapter.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbCertAdapter.Location = new Point(210, 155);
        _cmbCertAdapter.Width = 490;
        PopulateAdapterChoices(_cmbCertAdapter);

        _cardExistingCert.Controls.AddRange([
            _radWinCertAuto, _radWinCertPick, _txtCertThumbprint, btnPickWin,
            _radPfxFile, _txtPfxPath, btnPickPfx, _txtPfxPassword,
            lblPort, _numCertPort, lblNic, _cmbCertAdapter
        ]);
    }

    // =========================================================================
    // TAB 3: ACCESS & PROTECTION (Simple Security Modes + Sensible Limits)
    // =========================================================================
    private TabPage BuildAccessTab()
    {
        var page = new TabPage("Access & Protection")
        {
            BackColor = Color.White,
            Padding = new Padding(18),
            Font = new Font("Segoe UI", 9.5f),
            AutoScroll = true
        };

        var modeBox = new GroupBox
        {
            Text = "Who is allowed to use this server?",
            Dock = DockStyle.Top,
            Height = 132,
            Padding = new Padding(14, 10, 14, 8)
        };

        _radAuthPersonalAuto.Text = "Personal Mode (Easiest) — Only phones paired over Bluetooth inside your car are accepted";
        _radAuthPersonalAuto.AutoSize = true;
        _radAuthPersonalAuto.Location = new Point(16, 26);

        _radAuthSharedKey.Text = "Personal Mode + Extra Secret Key — Also require a server password pasted into your app";
        _radAuthSharedKey.AutoSize = true;
        _radAuthSharedKey.Location = new Point(16, 58);

        _radAuthMultiUser.Text = "Community / Multi-User Mode — Separate user accounts or invite keys with per-user car limits";
        _radAuthMultiUser.AutoSize = true;
        _radAuthMultiUser.Location = new Point(16, 90);

        _radAuthPersonalAuto.CheckedChanged += (_, _) => UpdateAuthModeCards();
        _radAuthSharedKey.CheckedChanged += (_, _) => UpdateAuthModeCards();
        _radAuthMultiUser.CheckedChanged += (_, _) => UpdateAuthModeCards();

        modeBox.Controls.AddRange([_radAuthPersonalAuto, _radAuthSharedKey, _radAuthMultiUser]);

        // Dynamic Card: Shared Secret Key
        _pnlSharedKeyCard.Dock = DockStyle.Top;
        _pnlSharedKeyCard.Height = 76;
        _pnlSharedKeyCard.BackColor = Color.FromArgb(244, 248, 254);
        _pnlSharedKeyCard.Padding = new Padding(14);
        _pnlSharedKeyCard.Controls.Add(new Label
        {
            Text = "Paste this Secret Key into 'Optional Server Token' in your phone & car apps:",
            Location = new Point(14, 10),
            AutoSize = true
        });
        _txtSharedToken.Location = new Point(14, 34);
        _txtSharedToken.Width = 440;
        var btnCopyShared = new Button { Text = "Copy Key", Location = new Point(462, 32), Width = 95, Height = 28 };
        btnCopyShared.Click += (_, _) =>
        {
            if (!string.IsNullOrEmpty(_txtSharedToken.Text))
            {
                Clipboard.SetText(_txtSharedToken.Text);
                _lblFooterStatus.Text = "Copied Secret Key to clipboard!";
            }
        };
        var btnNewShared = new Button { Text = "Generate New Key", Location = new Point(564, 32), Width = 140, Height = 28 };
        btnNewShared.Click += (_, _) => _txtSharedToken.Text = AdminIpcClient.GenerateRandomToken();
        _pnlSharedKeyCard.Controls.AddRange([_txtSharedToken, btnCopyShared, btnNewShared]);

        // Dynamic Card: Multi-User Accounts & Invite Keys
        _pnlMultiUserCard.Dock = DockStyle.Top;
        _pnlMultiUserCard.Height = 215;
        _pnlMultiUserCard.BackColor = Color.FromArgb(244, 248, 254);
        _pnlMultiUserCard.Padding = new Padding(14);

        _chkAllowPublicReg.Text = "Allow users to create an account directly inside the app";
        _chkAllowPublicReg.AutoSize = true;
        _chkAllowPublicReg.Location = new Point(14, 12);

        var lblMaxCars = new Label { Text = "Max cars allowed per user:", Location = new Point(420, 14), AutoSize = true };
        _numMaxCars.Minimum = 1; _numMaxCars.Maximum = 500; _numMaxCars.Value = 5;
        _numMaxCars.Location = new Point(595, 11);
        _numMaxCars.Width = 75;

        _txtNewTokenLabel.PlaceholderText = "Friend or vehicle name (e.g. Alex's Ioniq 5)";
        _txtNewTokenLabel.Location = new Point(14, 44);
        _txtNewTokenLabel.Width = 280;

        var btnCreateInvite = new Button { Text = "Create Invite Key", Location = new Point(302, 42), Width = 135, Height = 28 };
        btnCreateInvite.Click += async (_, _) => await CreateApiTokenFromUiAsync();

        var btnRevokeInvite = new Button { Text = "Revoke Selected", Location = new Point(445, 42), Width = 130, Height = 28 };
        btnRevokeInvite.Click += async (_, _) => await RevokeSelectedTokenFromUiAsync();

        _lstApiTokens.Location = new Point(14, 78);
        _lstApiTokens.Size = new Size(760, 122);
        _lstApiTokens.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _lstApiTokens.View = View.Details;
        _lstApiTokens.FullRowSelect = true;
        _lstApiTokens.GridLines = true;
        _lstApiTokens.Columns.Add("ID", 50);
        _lstApiTokens.Columns.Add("Name / Label", 250);
        _lstApiTokens.Columns.Add("Key Preview", 160);
        _lstApiTokens.Columns.Add("Max Cars", 90);
        _lstApiTokens.Columns.Add("Status", 100);

        _pnlMultiUserCard.Controls.AddRange([
            _chkAllowPublicReg, lblMaxCars, _numMaxCars,
            _txtNewTokenLabel, btnCreateInvite, btnRevokeInvite, _lstApiTokens
        ]);

        // Traffic & Flood Protection Box
        var limitsBox = new GroupBox
        {
            Text = "Spam & Flood Protection Limits (Defaults work great for normal driving)",
            Dock = DockStyle.Top,
            Height = 96,
            Padding = new Padding(14, 12, 14, 10)
        };

        var flowLimits = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        _numRateCar.Minimum = 5; _numRateCar.Maximum = 50000; _numRateCar.Value = 40; _numRateCar.Width = 75;
        _numRateIp.Minimum = 5; _numRateIp.Maximum = 100000; _numRateIp.Value = 100; _numRateIp.Width = 80;
        _numMaxQueued.Minimum = 1; _numMaxQueued.Maximum = 200; _numMaxQueued.Value = 20; _numMaxQueued.Width = 70;

        flowLimits.Controls.AddRange([
            new Label { Text = "Max requests/min per Car:", AutoSize = true, Padding = new Padding(0, 6, 4, 0) },
            _numRateCar,
            new Label { Text = "    Max requests/min per IP:", AutoSize = true, Padding = new Padding(8, 6, 4, 0) },
            _numRateIp,
            new Label { Text = "    Max waiting commands:", AutoSize = true, Padding = new Padding(8, 6, 4, 0) },
            _numMaxQueued
        ]);
        limitsBox.Controls.Add(flowLimits);

        page.Controls.Add(limitsBox);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 8 });
        page.Controls.Add(_pnlMultiUserCard);
        page.Controls.Add(_pnlSharedKeyCard);
        page.Controls.Add(new Panel { Dock = DockStyle.Top, Height = 8 });
        page.Controls.Add(modeBox);
        return page;
    }

    private void UpdateConnectionModeCards()
    {
        if (_suppressModeEvents) return;
        _cardLetsEncrypt.Visible = _radLetsEncrypt.Checked;
        _cardProxy.Visible = _radReverseProxy.Checked;
        _cardExistingCert.Visible = _radExistingCert.Checked;
    }

    private void UpdateAuthModeCards()
    {
        if (_suppressModeEvents) return;
        _pnlSharedKeyCard.Visible = _radAuthSharedKey.Checked;
        _pnlMultiUserCard.Visible = _radAuthMultiUser.Checked;
    }

    private static void PopulateAdapterChoices(ComboBox cmb)
    {
        cmb.Items.Clear();
        cmb.Items.Add(new AdapterChoice("0.0.0.0", "All Network Adapters — 0.0.0.0 (Recommended)"));
        cmb.Items.Add(new AdapterChoice("127.0.0.1", "This Computer Only — 127.0.0.1 (Local Proxy on same PC)"));

        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (UnicastIPAddressInformation ua in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ua.Address))
                    {
                        string ip = ua.Address.ToString();
                        cmb.Items.Add(new AdapterChoice(ip, $"{ip}  ({nic.Name})"));
                    }
                }
            }
        }
        catch { }
        cmb.SelectedIndex = 0;
    }

    private static void SelectAdapterInCombo(ComboBox cmb, string? ipValue)
    {
        string target = string.IsNullOrWhiteSpace(ipValue) ? "0.0.0.0" : ipValue.Trim();
        for (int i = 0; i < cmb.Items.Count; i++)
        {
            if (cmb.Items[i] is AdapterChoice ch && string.Equals(ch.Value, target, StringComparison.OrdinalIgnoreCase))
            {
                cmb.SelectedIndex = i;
                return;
            }
        }
        int added = cmb.Items.Add(new AdapterChoice(target, target));
        cmb.SelectedIndex = added;
    }

    private static string GetSelectedAdapterValue(ComboBox cmb) =>
        (cmb.SelectedItem as AdapterChoice)?.Value ?? "0.0.0.0";

    private static string? DetectDefaultGatewayIp()
    {
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                foreach (GatewayIPAddressInformation gw in nic.GetIPProperties().GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(gw.Address))
                        return gw.Address.ToString();
                }
            }
        }
        catch { }
        return null;
    }

    public async Task RefreshLiveStatusAsync()
    {
        var (svcInstalled, svcStatus) = AdminIpcClient.QueryServiceState();
        TrayIpcResponse? ipc = await AdminIpcClient.SendAsync(new TrayIpcCommand { Action = "get_status" }, 1200);

        if (ipc is { Ok: true, Status: not null })
        {
            TrayLiveStatusDto st = ipc.Status;
            _lblServiceState.Text = $"Online & Running  •  v{st.Version}  •  Up {FormatUptime(st.UptimeSeconds)}";
            _lblServiceState.ForeColor = Color.FromArgb(120, 235, 165);

            _btnStartStopSvc.Text = "Stop Server";
            _btnStartStopSvc.BackColor = Color.FromArgb(165, 58, 58);
            _btnStartStopSvc.Tag = "stop";
            _btnStartStopSvc.Enabled = svcInstalled;

            _valCars.Text = st.RegisteredCarCount.ToString("N0");
            _valActivePolls.Text = st.ActiveLongPolls.ToString("N0");
            _valQueued.Text = st.QueuedCommandCount.ToString("N0");
            _valReqMin.Text = st.RequestsLastMinute.ToString("N0");

            string normalizedUrl = FormatDisplayPublicUrl(st.PublicUrl);
            _txtAppUrlDisplay.Text = string.IsNullOrEmpty(normalizedUrl)
                ? "Not set yet — click 'Connection & SSL' tab to enter your domain"
                : normalizedUrl;

            bool isSharedMode = string.Equals(st.AuthMode, "shared_token", StringComparison.OrdinalIgnoreCase);
            _pnlAppTokenRow.Visible = isSharedMode;
            if (isSharedMode)
                _txtAppTokenDisplay.Text = _loadedSettings.ServerSharedToken;

            _valCertSummary.Text = $"Listener: {st.ListenerSummary}   |   SSL: {st.CertificateStatus}";
            _setupBanner.Visible = string.IsNullOrEmpty(normalizedUrl);

            _lstEvents.BeginUpdate();
            _lstEvents.Items.Clear();
            foreach (string ev in st.RecentEvents)
                _lstEvents.Items.Add(ev);
            _lstEvents.EndUpdate();
        }
        else
        {
            string stateText = svcInstalled ? $"Server is {svcStatus}" : "Windows Service Not Installed";
            _lblServiceState.Text = stateText;
            _lblServiceState.ForeColor = Color.FromArgb(255, 170, 150);

            _btnStartStopSvc.Text = "Start Server";
            _btnStartStopSvc.BackColor = Color.FromArgb(32, 136, 78);
            _btnStartStopSvc.Tag = "start";
            _btnStartStopSvc.Enabled = svcInstalled;
        }

        _btnRestartSvc.Enabled = svcInstalled;
    }

    private async Task LoadConfigurationIntoFormAsync()
    {
        TrayIpcResponse? ipc = await AdminIpcClient.SendAsync(new TrayIpcCommand { Action = "get_settings" }, 1500);
        _loadedSettings = ipc is { Ok: true, Settings: not null }
            ? ipc.Settings
            : AdminIpcClient.LoadSettingsFallbackFromDisk();

        TrayServerSettings s = _loadedSettings;
        _suppressModeEvents = true;

        // Show clean domain without clutter, or empty if unconfigured
        _txtDomain.Text = CleanDomainForInput(s.PublicUrl);
        _txtLeEmail.Text = s.LetsEncryptEmail;

        string tls = (s.TlsMode ?? "WindowsCertStore").ToLowerInvariant();
        if (tls == "letsencrypt")
        {
            _radLetsEncrypt.Checked = true;
            _numLeHttpsPort.Value = Math.Clamp(s.Port, 1, 65535);
        }
        else if (tls is "selfsignedlocal" or "reverseproxyhttp")
        {
            _radReverseProxy.Checked = true;
            _numProxyPort.Value = Math.Clamp(s.Port, 1, 65535);
            _cmbProxyProtocol.SelectedIndex = tls == "reverseproxyhttp" ? 1 : 0;
            SelectAdapterInCombo(_cmbProxyAdapter, s.ListenInterface);
        }
        else
        {
            _radExistingCert.Checked = true;
            _numCertPort.Value = Math.Clamp(s.Port, 1, 65535);
            SelectAdapterInCombo(_cmbCertAdapter, s.ListenInterface);
            if (tls == "pfxfile")
                _radPfxFile.Checked = true;
            else if (!string.IsNullOrWhiteSpace(s.WindowsCertThumbprint))
                _radWinCertPick.Checked = true;
            else
                _radWinCertAuto.Checked = true;
        }

        if (_cmbProxyProtocol.SelectedIndex < 0) _cmbProxyProtocol.SelectedIndex = 0;
        if (!_radWinCertAuto.Checked && !_radWinCertPick.Checked && !_radPfxFile.Checked)
            _radWinCertAuto.Checked = true;

        _txtCertThumbprint.Text = s.WindowsCertThumbprint;
        _txtPfxPath.Text = s.PfxFilePath;
        _txtPfxPassword.Text = "";

        string auth = (s.AuthMode ?? "").ToLowerInvariant();
        if (auth is "shared_token" or "shared")
            _radAuthSharedKey.Checked = true;
        else if (auth is "accounts" or "account_plus_device_pop")
            _radAuthMultiUser.Checked = true;
        else
            _radAuthPersonalAuto.Checked = true;

        _txtSharedToken.Text = s.ServerSharedToken;
        _chkAllowPublicReg.Checked = s.AllowPublicAccountRegistration;
        _numMaxCars.Value = Math.Clamp(s.MaxCarsPerAccount, 1, 500);
        _numRateCar.Value = Math.Clamp(s.RateLimitPerCarPerMinute, 5, 50000);
        _numRateIp.Value = Math.Clamp(s.RateLimitPerIpPerMinute, 5, 100000);
        _numMaxQueued.Value = Math.Clamp(s.MaxQueuedCommandsPerCar, 1, 200);

        _suppressModeEvents = false;
        UpdateConnectionModeCards();
        UpdateAuthModeCards();
        _settingsLoadedOnce = true;
    }

    private async Task SaveConfigurationFromFormAsync()
    {
        if (!_settingsLoadedOnce) return;

        TrayServerSettings s = _loadedSettings;

        string rawDomain = _txtDomain.Text.Trim();
        if (string.IsNullOrEmpty(rawDomain))
        {
            s.PublicUrl = "";
        }
        else if (rawDomain.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                 rawDomain.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            s.PublicUrl = rawDomain.TrimEnd('/');
        }
        else
        {
            s.PublicUrl = "https://" + rawDomain.TrimEnd('/');
        }

        if (_radLetsEncrypt.Checked)
        {
            s.TlsMode = "LetsEncrypt";
            s.ListenInterface = "0.0.0.0";
            s.Port = (int)_numLeHttpsPort.Value;
            s.EnableHttpAcmeListener = true;
            s.HttpAcmePort = 80;
            s.LetsEncryptEmail = _txtLeEmail.Text.Trim();
            s.LetsEncryptAutoRenew = true;
            s.TrustForwardedHeaders = false;
        }
        else if (_radReverseProxy.Checked)
        {
            s.TlsMode = _cmbProxyProtocol.SelectedIndex == 1 ? "ReverseProxyHttp" : "SelfSignedLocal";
            s.Port = (int)_numProxyPort.Value;
            s.ListenInterface = GetSelectedAdapterValue(_cmbProxyAdapter);
            s.EnableHttpAcmeListener = false;
            s.TrustForwardedHeaders = true;

            // Automatically ensure default LAN gateway IP (e.g. 10.0.1.1) is trusted for client IP forwarding!
            string? gw = DetectDefaultGatewayIp();
            if (!string.IsNullOrEmpty(gw) && !s.TrustedProxyIps.Contains(gw, StringComparer.OrdinalIgnoreCase))
                s.TrustedProxyIps.Add(gw);
            if (!s.TrustedProxyIps.Contains("127.0.0.1"))
                s.TrustedProxyIps.Add("127.0.0.1");
            if (!s.TrustedProxyIps.Contains("::1"))
                s.TrustedProxyIps.Add("::1");
        }
        else
        {
            s.Port = (int)_numCertPort.Value;
            s.ListenInterface = GetSelectedAdapterValue(_cmbCertAdapter);
            s.EnableHttpAcmeListener = false;

            if (_radPfxFile.Checked)
            {
                s.TlsMode = "PfxFile";
                s.PfxFilePath = _txtPfxPath.Text.Trim();
                if (!string.IsNullOrEmpty(_txtPfxPassword.Text))
                {
                    s.PfxPasswordProtectedBase64 = AdminIpcClient.ProtectPasswordForLocalMachine(_txtPfxPassword.Text);
                    s.PfxPasswordPlain = "";
                    _txtPfxPassword.Text = "";
                }
            }
            else
            {
                s.TlsMode = "WindowsCertStore";
                s.WindowsCertStoreLocation = "LocalMachine";
                s.WindowsCertStoreName = "My";
                s.WindowsCertThumbprint = _radWinCertPick.Checked ? _txtCertThumbprint.Text.Replace(" ", "").Trim() : "";
                s.AutoMatchCertByPublicUrlHost = true;
            }
        }

        s.AuthMode = _radAuthSharedKey.Checked
            ? "shared_token"
            : _radAuthMultiUser.Checked
                ? "account_plus_device_pop"
                : "device_pop_only";

        s.ServerSharedToken = _txtSharedToken.Text.Trim();
        s.AllowPublicAccountRegistration = _chkAllowPublicReg.Checked;
        s.MaxCarsPerAccount = (int)_numMaxCars.Value;
        s.RateLimitPerCarPerMinute = (int)_numRateCar.Value;
        s.RateLimitPerIpPerMinute = (int)_numRateIp.Value;
        s.MaxQueuedCommandsPerCar = (int)_numMaxQueued.Value;

        TrayIpcResponse? resp = await AdminIpcClient.SendAsync(new TrayIpcCommand
        {
            Action = "save_settings",
            Settings = s
        }, 4000);

        if (resp != null)
        {
            if (!resp.Ok)
            {
                MessageBox.Show(this, resp.Message ?? "Unable to save settings.", "Save Settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _lblFooterStatus.Text = "Saved! Your server is updated.";
            if (resp.RequiresServiceRestart)
            {
                var (installed, _) = AdminIpcClient.QueryServiceState();
                if (installed)
                    await RunServiceActionAsync("restart");
            }
        }
        else
        {
            try
            {
                AdminIpcClient.SaveSettingsDirectToDisk(s);
                _lblFooterStatus.Text = "Saved settings to disk (start the server to go online).";
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Please click 'Unlock Admin' at the top right to save changes.\n\n({ex.Message})",
                    "Administrator Permission Needed", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        await RefreshLiveStatusAsync();
    }

    // =========================================================================
    // ONE-CLICK PLAIN-ENGLISH CONNECTION SELF-TEST!
    // =========================================================================
    private async Task RunConnectionSelfTestAsync()
    {
        _btnTestConnection.Enabled = false;
        _lblFooterStatus.Text = "Testing server connection...";
        var report = new System.Text.StringBuilder();

        try
        {
            // Check 1: Background Service
            TrayIpcResponse? ipc = await AdminIpcClient.SendAsync(new TrayIpcCommand { Action = "get_status" }, 2000);
            if (ipc is not { Ok: true, Status: not null })
            {
                MessageBox.Show(this,
                    "1. Background Server: NOT RUNNING\n\nClick 'Start Server' at the top right first, then test again.",
                    "Connection Test", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            report.AppendLine("✔ Step 1: Digital Connect+ background server is running.");

            // Check 2: Local Port Reachability
            TrayServerSettings s = _loadedSettings;
            string localIp = s.ListenInterface is "0.0.0.0" or "::" or "" ? "127.0.0.1" : s.ListenInterface;
            string localScheme = string.Equals(s.TlsMode, "ReverseProxyHttp", StringComparison.OrdinalIgnoreCase) ? "http" : "https";
            string localHealthUrl = $"{localScheme}://{localIp}:{s.Port}/api/v1/health";

            using var localHandler = new SocketsHttpHandler
            {
                SslOptions = { RemoteCertificateValidationCallback = (_, _, _, _) => true },
                ConnectTimeout = TimeSpan.FromSeconds(4)
            };
            using var localClient = new HttpClient(localHandler) { Timeout = TimeSpan.FromSeconds(5) };

            try
            {
                HttpResponseMessage localResp = await localClient.GetAsync(localHealthUrl);
                if (localResp.IsSuccessStatusCode)
                    report.AppendLine($"✔ Step 2: Local listener ({localHealthUrl}) responded OK.");
                else
                    report.AppendLine($"⚠ Step 2: Local listener returned HTTP {(int)localResp.StatusCode}.");
            }
            catch (Exception ex)
            {
                report.AppendLine($"✖ Step 2: Could not connect locally to {localHealthUrl} ({ex.Message}).");
            }

            // Check 3: Public Domain Reachability
            string publicUrl = FormatDisplayPublicUrl(ipc.Status.PublicUrl);
            if (string.IsNullOrEmpty(publicUrl))
            {
                report.AppendLine("\nℹ Step 3: You haven't entered your Domain Name yet.");
                report.AppendLine("   Open the 'Connection & SSL' tab and type the domain you bought.");
                MessageBox.Show(this, report.ToString(), "Connection Test Results", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string publicHealth = publicUrl.TrimEnd('/') + "/api/v1/health";
            using var pubClient = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
            try
            {
                HttpResponseMessage pubResp = await pubClient.GetAsync(publicHealth);
                string body = await pubResp.Content.ReadAsStringAsync();
                if (pubResp.IsSuccessStatusCode && body.Contains("gen5w-digital-control-relay", StringComparison.Ordinal))
                {
                    report.AppendLine($"✔ Step 3: Public URL ({publicUrl}) is LIVE and verified!");
                    report.AppendLine("\nEverything is working! Copy the Server URL on the Overview tab into your Gen5W Car & Phone apps.");
                    MessageBox.Show(this, report.ToString(), "Connection Test Passed!", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    report.AppendLine($"⚠ Step 3: {publicUrl} responded with HTTP {(int)pubResp.StatusCode}, which doesn't look like Digital Connect+ yet.");
                    report.AppendLine("   Check that your router / reverse proxy forwards this domain to port " + s.Port + " on this PC.");
                    MessageBox.Show(this, report.ToString(), "Connection Test — Check Router/Proxy", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                report.AppendLine($"✖ Step 3: Could not reach {publicUrl} from the internet yet ({ex.Message}).");
                report.AppendLine($"   Check your DNS record and make sure your router/firewall forwards traffic to this PC (port {s.Port}).");
                MessageBox.Show(this, report.ToString(), "Connection Test — Public URL Unreachable", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        finally
        {
            _btnTestConnection.Enabled = true;
            _lblFooterStatus.Text = "Connection test finished.";
        }
    }

    private async Task TriggerLetsEncryptNowAsync()
    {
        await SaveConfigurationFromFormAsync();
        _btnIssueLeNow.Enabled = false;
        _lblFooterStatus.Text = "Contacting Let's Encrypt to issue your free SSL certificate...";
        try
        {
            TrayIpcResponse? resp = await AdminIpcClient.SendAsync(
                new TrayIpcCommand { Action = "renew_letsencrypt" },
                timeoutMs: 95_000);

            if (resp == null)
            {
                MessageBox.Show(this, "Start the server first so Let's Encrypt can verify your domain.", "Let's Encrypt", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            MessageBox.Show(this, resp.Message ?? "Done.", "Let's Encrypt Certificate",
                MessageBoxButtons.OK, resp.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            _lblFooterStatus.Text = resp.Message ?? "";
            await RefreshLiveStatusAsync();
        }
        finally
        {
            _btnIssueLeNow.Enabled = true;
        }
    }

    private async Task RefreshApiTokensAsync()
    {
        TrayIpcResponse? resp = await AdminIpcClient.SendAsync(new TrayIpcCommand { Action = "list_tokens" }, 2000);
        if (resp?.ApiTokens == null) return;
        PopulateTokensList(resp.ApiTokens);
    }

    private async Task CreateApiTokenFromUiAsync()
    {
        string label = string.IsNullOrWhiteSpace(_txtNewTokenLabel.Text) ? "Invite Key" : _txtNewTokenLabel.Text.Trim();
        TrayIpcResponse? resp = await AdminIpcClient.SendAsync(new TrayIpcCommand
        {
            Action = "create_token",
            TokenLabel = label,
            MaxCars = (int)_numMaxCars.Value
        }, 3000);

        if (resp is { Ok: true, CreatedPlainToken: not null })
        {
            Clipboard.SetText(resp.CreatedPlainToken);
            _txtNewTokenLabel.Clear();
            if (resp.ApiTokens != null)
                PopulateTokensList(resp.ApiTokens);

            MessageBox.Show(this,
                $"Invite Key created and copied to clipboard:\n\n{resp.CreatedPlainToken}\n\nShare this key with the user — for security, it is only shown once.",
                "Invite Key Created", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            MessageBox.Show(this, resp?.Message ?? "Click 'Unlock Admin' at the top right to create invite keys.",
                "Create Invite Key", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task RevokeSelectedTokenFromUiAsync()
    {
        if (_lstApiTokens.SelectedItems.Count == 0) return;
        if (_lstApiTokens.SelectedItems[0].Tag is not int id) return;

        TrayIpcResponse? resp = await AdminIpcClient.SendAsync(new TrayIpcCommand
        {
            Action = "revoke_token",
            TokenId = id
        }, 3000);

        if (resp?.ApiTokens != null)
            PopulateTokensList(resp.ApiTokens);
    }

    private void PopulateTokensList(List<TrayApiTokenDto> tokens)
    {
        _lstApiTokens.BeginUpdate();
        _lstApiTokens.Items.Clear();
        foreach (TrayApiTokenDto t in tokens)
        {
            var item = new ListViewItem(t.Id.ToString()) { Tag = t.Id };
            item.SubItems.Add(t.Label);
            item.SubItems.Add(t.TokenPrefix + "…");
            item.SubItems.Add(t.MaxCars.ToString());
            item.SubItems.Add(t.IsRevoked ? "Revoked" : "Active");
            _lstApiTokens.Items.Add(item);
        }
        _lstApiTokens.EndUpdate();
    }

    private void BindHttpSysSslCert()
    {
        string thumb = _txtCertThumbprint.Text.Replace(" ", "").Trim();
        string host = CleanDomainForInput(_txtDomain.Text);

        if (string.IsNullOrEmpty(thumb) || string.IsNullOrEmpty(host))
        {
            MessageBox.Show(this, "Select a Windows Certificate and enter your Domain Name on 'Connection & SSL' first.",
                "IIS / HTTP.sys Certificate Binding", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        int port = _radExistingCert.Checked ? (int)_numCertPort.Value : 443;
        string appId = "{573EDD6F-ECF2-45BF-9165-AD01A780B8B2}";
        string cmdArgs = $"/c netsh http delete sslcert hostnameport={host}:{port} >nul 2>&1 & netsh http add sslcert hostnameport={host}:{port} certhash={thumb} certstorename=MY appid={appId}";

        try
        {
            using Process? p = Process.Start(new ProcessStartInfo("cmd.exe", cmdArgs)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden
            });
            p?.WaitForExit(8000);
            _lblFooterStatus.Text = $"Bound certificate for {host}:{port} in Windows HTTP.sys.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Binding canceled or failed: {ex.Message}", "Certificate Binding", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task RunServiceActionAsync(string action)
    {
        _lblFooterStatus.Text = $"Working ({action} server)...";
        var (_, msg) = await AdminIpcClient.ControlWindowsServiceAsync(action);
        _lblFooterStatus.Text = msg;
        await Task.Delay(600);
        await RefreshLiveStatusAsync();
    }

    private static string FormatDisplayPublicUrl(string? raw)
    {
        string trimmed = (raw ?? "").Trim().TrimEnd('/');
        if (string.IsNullOrEmpty(trimmed)) return "";
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return trimmed;
        return "https://" + trimmed;
    }

    private static string CleanDomainForInput(string? raw)
    {
        string trimmed = (raw ?? "").Trim();
        if (trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed["https://".Length..];
        else if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed["http://".Length..];
        return trimmed.TrimEnd('/');
    }

    private static void ConfigureHeaderButton(Button b, string text, Color bg, int width)
    {
        b.Text = text;
        b.Width = width;
        b.Height = 32;
        b.BackColor = bg;
        b.ForeColor = Color.White;
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 0;
        b.Margin = new Padding(6, 0, 0, 0);
    }

    private static Panel CreateMetricCard(string caption, Label valueLabel, string initial)
    {
        var card = new Panel
        {
            Dock = DockStyle.Fill,
            Margin = new Padding(4),
            BackColor = Color.FromArgb(242, 246, 252),
            Padding = new Padding(12, 8, 10, 6)
        };
        var lblCap = new Label
        {
            Text = caption,
            Dock = DockStyle.Top,
            Height = 20,
            ForeColor = Color.FromArgb(85, 98, 118),
            Font = new Font("Segoe UI", 8.8f)
        };
        valueLabel.Text = initial;
        valueLabel.Dock = DockStyle.Fill;
        valueLabel.Font = new Font("Segoe UI Semibold", 16f, FontStyle.Bold);
        valueLabel.ForeColor = Color.FromArgb(20, 32, 54);
        card.Controls.Add(valueLabel);
        card.Controls.Add(lblCap);
        return card;
    }

    private static string FormatUptime(long sec)
    {
        TimeSpan ts = TimeSpan.FromSeconds(sec);
        return ts.TotalDays >= 1
            ? $"{(int)ts.TotalDays}d {ts.Hours}h {ts.Minutes}m"
            : $"{ts.Hours}h {ts.Minutes}m {ts.Seconds}s";
    }
}
