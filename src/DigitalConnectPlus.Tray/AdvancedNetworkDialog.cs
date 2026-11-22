namespace DigitalConnectPlus.Tray;

/// <summary>
/// Keeps rare power-user options (IIS Port 443 sharing via Windows HTTP.sys, Custom Bind URL, Let's Encrypt Staging)
/// tucked out of the main UI so everyday users never have to see technical jargon.
/// </summary>
internal sealed class AdvancedNetworkDialog : Form
{
    private readonly CheckBox _chkShareIisPort443 = new();
    private readonly TextBox _txtCustomBindUrl = new();
    private readonly CheckBox _chkLeStaging = new();
    private readonly CheckBox _chkLeSyncWinStore = new();
    private readonly TextBox _txtTrustedProxies = new();

    public AdvancedNetworkDialog(TrayServerSettings current, Action onBindHttpSysCert)
    {
        Text = "Advanced Options (Optional)";
        Size = new Size(580, 380);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        Font = new Font("Segoe UI", 9.5f);
        BackColor = Color.White;

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(18) };

        var lblNote = new Label
        {
            Text = "Most users never need to change these settings.",
            ForeColor = Color.FromArgb(90, 102, 122),
            AutoSize = true,
            Location = new Point(18, 14)
        };

        _chkShareIisPort443.Text = "Share Port 443 directly with Microsoft IIS on this Windows Server (HTTP.sys mode)";
        _chkShareIisPort443.Checked = string.Equals(current.ListenerEngine, "HttpSys", StringComparison.OrdinalIgnoreCase);
        _chkShareIisPort443.AutoSize = true;
        _chkShareIisPort443.Location = new Point(18, 46);

        var btnHttpSysSsl = new Button
        {
            Text = "Register Certificate with Windows IIS/HTTP.sys...",
            Location = new Point(40, 74),
            Width = 320,
            Height = 28
        };
        btnHttpSysSsl.Click += (_, _) => onBindHttpSysCert();

        var lblBind = new Label
        {
            Text = "Restrict Host Header / Custom Bind URL (leave blank unless needed):",
            AutoSize = true,
            Location = new Point(18, 116)
        };
        _txtCustomBindUrl.Text = current.CustomBindUrl;
        _txtCustomBindUrl.PlaceholderText = "Leave blank (recommended)";
        _txtCustomBindUrl.Location = new Point(18, 138);
        _txtCustomBindUrl.Width = 520;

        var lblProxies = new Label
        {
            Text = "Trusted Router / Proxy IPs (comma-separated):",
            AutoSize = true,
            Location = new Point(18, 174)
        };
        _txtTrustedProxies.Text = string.Join(", ", current.TrustedProxyIps);
        _txtTrustedProxies.Location = new Point(18, 196);
        _txtTrustedProxies.Width = 520;

        _chkLeStaging.Text = "Use Let's Encrypt Test/Staging server (for certificate testing only)";
        _chkLeStaging.Checked = current.LetsEncryptUseStaging;
        _chkLeStaging.AutoSize = true;
        _chkLeStaging.Location = new Point(18, 234);

        _chkLeSyncWinStore.Text = "Also save Let's Encrypt certificates into Windows Certificate Manager";
        _chkLeSyncWinStore.Checked = current.LetsEncryptImportToWindowsStore;
        _chkLeSyncWinStore.AutoSize = true;
        _chkLeSyncWinStore.Location = new Point(18, 260);

        body.Controls.AddRange([
            lblNote, _chkShareIisPort443, btnHttpSysSsl,
            lblBind, _txtCustomBindUrl,
            lblProxies, _txtTrustedProxies,
            _chkLeStaging, _chkLeSyncWinStore
        ]);

        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 50,
            FlowDirection = FlowDirection.RightToLeft,
            BackColor = Color.FromArgb(240, 243, 248),
            Padding = new Padding(12, 8, 12, 8)
        };

        var btnCancel = new Button { Text = "Cancel", Width = 90, Height = 30, DialogResult = DialogResult.Cancel };
        var btnOk = new Button
        {
            Text = "Done",
            Width = 100,
            Height = 30,
            BackColor = Color.FromArgb(25, 103, 210),
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            DialogResult = DialogResult.OK
        };
        btnOk.FlatAppearance.BorderSize = 0;
        btnOk.Click += (_, _) =>
        {
            current.ListenerEngine = _chkShareIisPort443.Checked ? "HttpSys" : "Kestrel";
            current.CustomBindUrl = _txtCustomBindUrl.Text.Trim();
            current.LetsEncryptUseStaging = _chkLeStaging.Checked;
            current.LetsEncryptImportToWindowsStore = _chkLeSyncWinStore.Checked;
            current.TrustedProxyIps = _txtTrustedProxies.Text
                .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
        };

        footer.Controls.Add(btnCancel);
        footer.Controls.Add(btnOk);

        Controls.Add(body);
        Controls.Add(footer);
    }
}
