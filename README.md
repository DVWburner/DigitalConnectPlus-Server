# Digital Connect+ Server

> **Note:** This project was built with AI (Google Antigravity).

**Digital Connect+ Server** is a self-contained **.NET 10** Zero-Trust End-to-End Encrypted (E2EE) Relay Server for **Gen5W Digital Control** (in-car Android 4.4.2 head-unit daemon + Android & iOS companion apps).

It runs natively on Windows as a resilient **Windows Service** (`DigitalConnectPlusService`) paired with a **System Tray Control Panel** (`DigitalConnectPlus.Tray.exe`), backed by an embedded WAL-mode **SQLite** database (`%ProgramData%\DigitalConnectPlus\data\digitalconnect.db`) with zero external database dependencies.

---

## Key Highlights

- **100% Zero-Trust E2EE Blind Relay**:
  - Never stores or requests VINs or hardware serial numbers.
  - Verifies NIST P-256 (`secp256r1` / `prime256v1`) 91-byte X.509 SPKI DER public keys and ASN.1 DER `SHA256withECDSA` signatures across all **7 `GEN5W-*-V1|...` canonical strings**.
  - Enforces **Trust-On-First-Use (TOFU)** car key pinning, car-signed `PairingGrant` verification (`GEN5W-GRANT-V1`), ±90s clock-skew bounds, and 5-minute poll nonce replay protection.
  - Relays `e2ee` command envelopes and `encryptedTelemetry` blobs opaquely without ever decrypting or mutating signed fields.
- **Strict 5-Minute TTL, Instant Long-Polling, & Atomic Cancellation**:
  - Generation-numbered in-memory wait channels wake waiting `POST /api/v1/car/poll` requests (`waitSeconds` up to 15s) in milliseconds when `POST /api/v1/commands` arrives.
  - Enforces a strict 5-minute (`300s`) command timeout lazily on reads/polls/cancels and via a 15-second background sweeper (plus automatic pruning of >24h terminal commands and >10m nonces).
  - Supports instant signed command cancellation (`DELETE /api/v1/commands/{commandId}`) with `409 Conflict` if already executed or expired.
- **Blank Default Domain & Flexible Network Binding**:
  - `PublicUrl` and `CustomBindUrl` **start completely blank (`""`)** — enter whatever domain you purchased in the System Tray Control Panel.
  - Customize **Listening Interface / IP** (`0.0.0.0`, `::`, `127.0.0.1`, or any specific NIC IP), **Port**, and choose between **Kestrel** (direct socket listener) or **Windows `HTTP.sys`** (URL prefix binding capable of sharing port 443 alongside IIS).
- **Windows Certificate Store + Built-in Let's Encrypt Auto-Renewal**:
  - **Windows Certificate Store**: Pick directly from `LocalMachine\My`, `LocalMachine\WebHosting`, or `CurrentUser\My` by Thumbprint or automatic SAN/Hostname matching (auto-reloads certificates renewed by `win-acme` / `Certify The Web` with zero downtime).
  - **Built-in Let's Encrypt ACMEv2 Auto-Renew**: Native RFC 8555 ACMEv2 client (HTTP-01 challenge) automatically issues and renews NIST P-256 certificates with full ISRG intermediate chains 30 days before expiration.
  - **Gen5W Android 4.4.2 KitKat TLS Compatibility**: Explicitly serves `TLS 1.2` + `TLS 1.3` with `prime256v1` (`secp256r1`) & `secp384r1` curves, full intermediate chains, and **zero HTTP redirects** on `/api/v1/*`.
- **Single-File Distribution & Seamless In-Place Upgrades**:
  - Distribute `dist\DigitalConnectPlus-Setup.exe` — a single self-contained `.exe` (no pre-installed .NET runtime needed).
  - Running a newer `DigitalConnectPlus-Setup.exe` on top of an existing installation automatically stops the running service & tray app, backs up and preserves `%ProgramData%\DigitalConnectPlus\` (SQLite DB, certs, keys, `settings.json`), upgrades binaries in `C:\Program Files\Digital Connect+ Server\`, and restarts the service.

---

## Quick Start (Windows Installer & Upgrade)

1. Run **`dist\DigitalConnectPlus-Setup.exe`** (or run `DigitalConnectPlus-Setup.exe /silent` for unattended installation/upgrade).
2. The System Tray icon (**Digital Connect+ Server**) appears in the Windows taskbar notification area and opens the **Control Panel**:
   - **Network & URL Binding**: Enter the domain you bought into **Public Domain / URL** (starts blank), pick your **Listening Interface** and **Port**, and choose `Kestrel` or `HttpSys`.
   - **TLS & Let's Encrypt**: Select **Windows Certificate Store** (click *Browse Windows Cert Store...* or leave *Hostname Auto-Match* checked) or **Let's Encrypt Auto-Renew** (enable HTTP Challenge Port 80 if Let's Encrypt validates directly against this server, enter your email, and click *Issue / Renew Let's Encrypt Certificate Now*).
   - **Security, Auth & Quotas**: Select your `AUTH_MODE`:
     - `device_pop_only` (`open`): Personal Zero-Trust ECDSA PoP + Car PairingGrant (default).
     - `shared_token`: Require `Authorization: Bearer <ServerSharedToken>` + ECDSA PoP (click *Copy* to paste into your Gen5W phone & car app settings).
     - `account_plus_device_pop` (`accounts`): Multi-user accounts (`/api/v1/auth/register`, `/api/v1/auth/login`, `/api/v1/auth/me`) & static `dcp_...` API tokens with per-account car quotas.
3. Click **Save & Apply Configuration**.

---

## CLI Administration (Headless / Multi-User Tokens)

```powershell
# Show active paths and configuration
.\DigitalConnectPlus.Server.exe config show

# Issue, list, or revoke API tokens for AUTH_MODE=accounts / account_plus_device_pop
.\DigitalConnectPlus.Server.exe token create "Alice Ioniq 5" --max-cars 2
.\DigitalConnectPlus.Server.exe token list
.\DigitalConnectPlus.Server.exe token revoke 1
```

---

## Building & Running Automated Tests from Source

```powershell
# Run all 12 E2EE, ECDSA DER, Long-Poll, 5-Min TTL, Auth Mode, & TLS 1.2 Integration Tests
dotnet test .\DigitalConnectPlus.slnx -c Release

# Build dist\DigitalConnectPlus-Setup.exe and dist\DigitalConnectPlus-Portable-win-x64.zip
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```

Reverse-proxy & container examples (configured for Gen5W Android 4.4.2 TLS 1.2 + `prime256v1` compatibility) are located in [`deploy/`](deploy/).
