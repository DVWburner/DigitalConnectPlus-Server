using System.Security.Cryptography.X509Certificates;

namespace DigitalConnectPlus.Tray;

internal sealed class CertificatePickerDialog : Form
{
    private readonly ListView _list;
    private readonly Button _btnSelect;

    public string? SelectedThumbprint { get; private set; }
    public string? SelectedSubject { get; private set; }

    public CertificatePickerDialog(string storeLocation, string storeName)
    {
        Text = $"Select Certificate — Windows Store ({storeLocation}\\{storeName})";
        Size = new Size(780, 440);
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        Font = new Font("Segoe UI", 9.5f);

        var lblHint = new Label
        {
            Text = "Showing certificates with an accessible Private Key:",
            Dock = DockStyle.Top,
            Height = 32,
            Padding = new Padding(12, 8, 12, 0)
        };

        _list = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false,
            GridLines = true
        };
        _list.Columns.Add("Subject / Domain", 240);
        _list.Columns.Add("Issuer", 170);
        _list.Columns.Add("Expires (UTC)", 130);
        _list.Columns.Add("Thumbprint", 210);
        _list.DoubleClick += (_, _) => ConfirmSelection();

        var bottomPanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 50,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(10, 8, 10, 8)
        };

        var btnCancel = new Button { Text = "Cancel", Width = 95, Height = 32, DialogResult = DialogResult.Cancel };
        _btnSelect = new Button { Text = "Use Certificate", Width = 130, Height = 32, Enabled = false };
        _btnSelect.Click += (_, _) => ConfirmSelection();

        _list.SelectedIndexChanged += (_, _) => _btnSelect.Enabled = _list.SelectedItems.Count > 0;

        bottomPanel.Controls.Add(btnCancel);
        bottomPanel.Controls.Add(_btnSelect);

        Controls.Add(_list);
        Controls.Add(lblHint);
        Controls.Add(bottomPanel);

        LoadCertificates(storeLocation, storeName);
    }

    private void LoadCertificates(string storeLocation, string storeName)
    {
        try
        {
            StoreLocation loc = string.Equals(storeLocation, "CurrentUser", StringComparison.OrdinalIgnoreCase)
                ? StoreLocation.CurrentUser
                : StoreLocation.LocalMachine;

            using var store = new X509Store(string.IsNullOrWhiteSpace(storeName) ? "My" : storeName, loc);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            foreach (X509Certificate2 cert in store.Certificates.OrderByDescending(c => c.NotAfter))
            {
                if (!cert.HasPrivateKey)
                    continue;

                string dns = cert.GetNameInfo(X509NameType.SimpleName, false);
                var item = new ListViewItem(string.IsNullOrEmpty(dns) ? cert.Subject : dns);
                item.SubItems.Add(cert.GetNameInfo(X509NameType.SimpleName, true));
                item.SubItems.Add(cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm"));
                item.SubItems.Add(cert.Thumbprint);
                item.Tag = cert.Thumbprint;
                _list.Items.Add(item);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Unable to open certificate store: {ex.Message}", "Certificate Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ConfirmSelection()
    {
        if (_list.SelectedItems.Count == 0) return;
        ListViewItem sel = _list.SelectedItems[0];
        SelectedSubject = sel.Text;
        SelectedThumbprint = sel.Tag as string;
        DialogResult = DialogResult.OK;
        Close();
    }
}
