# ShadowBackup-Hunter & Exfil-Hunter

**Open-source ransomware early detection utilities for Windows and Linux**

Lightweight, silent first-line defense scripts that detect **ransomware recovery inhibition** (shadow copy / snapshot deletion) and **data exfiltration** before encryption begins. Built for security teams, SOC analysts, blue team defenders, and system administrators who need practical host-based detection without heavy agents.

**Keywords / Search terms:** ransomware detection, ransomware early warning, shadow copy deletion detection, VSS deletion monitor, Volume Shadow Copy Service ransomware, data exfiltration detection, outbound traffic anomaly detection, T1490 Inhibit System Recovery, pre-encryption ransomware indicators, Windows ransomware hunter, Linux ransomware detection script, backup deletion monitoring, DNS tunneling detection, silent security monitoring scripts, SOC automation scripts, blue team tools, MITRE ATT&CK T1490, ransomware canary alternative, host-based ransomware detection, PowerShell ransomware detection, Bash ransomware hunter.

---

## What These Tools Do

Ransomware operators almost always perform two critical steps **hours or days before encryption**:

1. **Destroy recovery options** – delete Volume Shadow Copies (Windows), LVM/Btrfs/ZFS snapshots (Linux), and backup catalogs so victims cannot restore for free.
2. **Exfiltrate data** – move large volumes of sensitive files to attacker-controlled infrastructure or consumer cloud services (double-extortion).

These utilities catch both behaviors early:

| Utility | Focus | Platform | Detection Layer |
|---------|-------|----------|-----------------|
| **ShadowBackup-Hunter** | Shadow-copy / snapshot / backup hunting | Windows + Linux | Layer 1 – Pre-encryption recovery kill |
| **Exfil-Hunter** | High outbound volume, external connections, DNS anomalies | Windows + Linux | Layer 2 – Data exfiltration (hours before encryption) |

Both scripts are designed for **silent operation**:
- No pop-ups, no interactive alerts, no desktop notifications
- Findings written only to log files
- Exit code `1` on high-confidence signals (ideal for SIEM, SOAR, cron, Task Scheduler, or EDR automation)
- Exit code `0` when clean

---

## Repository Contents

```
.
├── README.md                     # This file
├── .gitignore
├── ShadowBackup-Hunter.ps1       # Windows – Shadow Copy & Backup Hunting
├── shadow-backup-hunter.sh       # Linux  – Snapshot & Backup Hunting
├── Exfil-Hunter.ps1              # Windows – Data Exfiltration Detection
└── exfil-hunter.sh               # Linux  – Data Exfiltration Detection
```

---

## Installation

### Windows (PowerShell)

1. Download or clone the repository:
   ```powershell
   git clone https://github.com/YOUR_USERNAME/ShadowBackup-Hunter.git
   cd ShadowBackup-Hunter
   ```

2. (Optional but recommended) Unblock the scripts:
   ```powershell
   Unblock-File .\ShadowBackup-Hunter.ps1
   Unblock-File .\Exfil-Hunter.ps1
   ```

3. Run with elevated privileges (Administrator or SYSTEM) for full Event Log access.

4. Schedule via Task Scheduler (recommended every 5–15 minutes):
   - Program: `powershell.exe`
   - Arguments example:
     ```
     -NoProfile -ExecutionPolicy Bypass -File "C:\Path\To\ShadowBackup-Hunter.ps1"
     ```
   - Run whether user is logged on or not, highest privileges.

**Requirements:** Windows 10 / 11 or Windows Server 2016+, PowerShell 5.1+. Sysmon strongly recommended for richer process creation data.

### Linux (Bash)

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ShadowBackup-Hunter.git
   cd ShadowBackup-Hunter
   ```

2. Make scripts executable:
   ```bash
   chmod +x shadow-backup-hunter.sh exfil-hunter.sh
   ```

3. Copy to a system path (optional):
   ```bash
   sudo cp shadow-backup-hunter.sh exfil-hunter.sh /usr/local/bin/
   ```

4. Schedule with cron (example – every 10 minutes):
   ```bash
   sudo crontab -e
   # Add:
   */10 * * * * /usr/local/bin/shadow-backup-hunter.sh 15 >> /var/log/shadow-backup-hunter.log 2>&1
   */10 * * * * /usr/local/bin/exfil-hunter.sh >> /var/log/exfil-hunter.log 2>&1
   ```

**Requirements:** Bash 4+, root privileges recommended. `auditd` strongly recommended for higher-fidelity command detection. `ss` (iproute2) preferred over legacy `netstat`.

---

## Quick Usage

### ShadowBackup-Hunter (Layer 1 – Recovery Inhibition)

**Windows**
```powershell
.\ShadowBackup-Hunter.ps1                        # Default 60-minute lookback
.\ShadowBackup-Hunter.ps1 -LookbackMinutes 30    # Custom window
.\ShadowBackup-Hunter.ps1 -AlertOnly             # Only high-confidence hits
```

**Linux**
```bash
sudo ./shadow-backup-hunter.sh          # Default 60-minute lookback
sudo ./shadow-backup-hunter.sh 15       # 15-minute lookback
```

Detects: `vssadmin delete shadows`, WMI/CIM shadow copy deletion, `wbadmin delete catalog`, `bcdedit` recovery disablement, `ntdsutil`, stopped backup services, missing LVM/Btrfs/ZFS snapshots, and related indicators.

### Exfil-Hunter (Layer 2 – Data Exfiltration)

**Windows**
```powershell
.\Exfil-Hunter.ps1                                      # 30-second sample, silent
.\Exfil-Hunter.ps1 -SampleSeconds 60 -HighVolumeMBPerMin 300
```

**Linux**
```bash
sudo ./exfil-hunter.sh
SAMPLE_SECONDS=60 HIGH_VOLUME_MB_PER_MIN=300 sudo -E ./exfil-hunter.sh
```

Detects: outbound volume ≥ 500 MB/min (configurable), >5× baseline traffic, large numbers of external connections, DNS cache anomalies (long/deep domain names), elevated UDP activity (possible tunneling).

Logs are written to:
- Windows: `%ProgramData%\ExfilHunter\` and `%TEMP%\ShadowBackup-Hunter.log`
- Linux: `/var/log/exfil-hunter.log` and `/var/log/shadow-backup-hunter.log`

---

## Exit Codes (Automation-Friendly)

| Code | Meaning |
|------|---------|
| `0`  | No high-confidence activity detected |
| `1`  | High-confidence ransomware preparation or exfiltration signal |

Use these codes in SIEM rules, SOAR playbooks, EDR response actions, or simple monitoring wrappers to trigger isolation, tickets, or further investigation — without ever interrupting the end user.

---

## Why These Tools Matter

Traditional antivirus and many EDR solutions focus on the encryption phase. By the time files are being renamed with `.lockbit`, `.blackcat`, or similar extensions, the damage is largely done. The highest-leverage detection window is the **pre-encryption** phase when attackers:

- Delete Volume Shadow Copies and snapshots (MITRE ATT&CK **T1490 – Inhibit System Recovery**)
- Stage and exfiltrate data to rare or cloud destinations

These scripts give blue teams and defenders a lightweight, transparent, and auditable way to monitor exactly those behaviors on both Windows and Linux endpoints.

---

## Limitations & Best Practices

- These are **host-based hunters**, not full network detection & response (NDR) or EDR replacements.
- Combine with behavioral EDR, network monitoring, immutable off-host backups, and canary files for defense-in-depth.
- Tune thresholds and maintain allow-lists for known backup accounts and legitimate high-volume processes.
- On Windows, enable process creation auditing or deploy Sysmon for best results.
- On Linux, enable `auditd` with `execve` rules for the tools monitored by the snapshot hunter.

---

## Contributing & Feedback

Pull requests, detection rule improvements, additional platform support, and SIEM integration examples are welcome. Please open an issue for bugs or feature requests.

---

## Disclaimer

These scripts are provided for **defensive security research and legitimate protection purposes only**.  
Test thoroughly in non-production environments before wide deployment.  
The authors accept no liability for any damage, data loss, or operational impact resulting from their use.

---

**Detect the recovery kill and the exfiltration stage — before encryption starts.**

`ransomware detection` `shadow copy deletion` `VSS ransomware` `data exfiltration detection` `T1490` `pre-encryption detection` `Windows ransomware script` `Linux ransomware hunter` `blue team tools` `SOC automation` `silent host monitoring`
