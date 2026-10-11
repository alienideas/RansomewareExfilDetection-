# Early-Stage Indicators of Ransomware: What System Administrators Can Detect with PowerShell and Bash Before Encryption Begins

**A practical guide for blue-team defenders, SOC analysts, and system administrators**

Modern ransomware rarely starts with file encryption. By the time files are renamed with extensions such as `.lockbit`, `.blackcat`, or `.encrypted`, the attacker has usually spent hours or days preparing the environment. The most valuable detection window is therefore the **pre-encryption phase**.

This document describes the highest-leverage early-stage indicators that can be observed with lightweight, native scripts (PowerShell on Windows and Bash on Linux). No commercial EDR is required to begin monitoring these signals.

---

## Why Early Detection Matters

Ransomware operators follow a predictable sequence:

1. Gain initial access and elevate privileges  
2. Disable or impair recovery options (shadow copies, snapshots, backups)  
3. Steal credentials and move laterally  
4. Exfiltrate sensitive data (double extortion)  
5. Only then encrypt files  

Catching activity in stages 2–4 gives defenders a realistic chance to isolate systems, rotate credentials, and restore from clean backups before data becomes inaccessible.

Industry reporting consistently shows that the average breakout time continues to shrink, making automated or scheduled host-based checks essential.

---

## Layer 1 – Recovery Option Destruction (Highest Confidence)

Attackers almost always attempt to remove local recovery points so victims cannot restore for free. This is tracked as **MITRE ATT&CK T1490 – Inhibit System Recovery**.

### Windows Indicators

| Indicator | Typical Commands / Artifacts | Detection Approach |
|-----------|------------------------------|--------------------|
| Volume Shadow Copy deletion | `vssadmin delete shadows /all /quiet`, WMI/CIM `Win32_ShadowCopy.Delete()`, `wmic shadowcopy delete` | Process creation logs (Event ID 4688 or Sysmon ID 1) |
| Backup catalog deletion | `wbadmin delete catalog` | Same process creation monitoring |
| Recovery configuration disabled | `bcdedit /set recoveryenabled no`, `bcdedit /set bootstatuspolicy ignoreallfailures` | Command-line inspection |
| Shadow storage resized to force deletion | `vssadmin resize shadowstorage` | Command-line inspection |
| Backup or VSS services stopped | VSS, swprv, wbengine, Veeam, Acronis, etc. | Service status checks |

### Linux Indicators

| Indicator | Typical Commands / Artifacts | Detection Approach |
|-----------|------------------------------|--------------------|
| LVM snapshot removal | `lvremove`, suspicious `lvcreate --snapshot` | Process auditing or process list |
| Btrfs / ZFS snapshot destruction | `btrfs subvolume delete`, `zfs destroy` | Process auditing |
| Backup tool cleanup | Timeshift, Borg, Restic, rsnapshot deletion patterns | Command-line patterns |
| Missing or near-zero snapshots | Empty output from `lvs`, `btrfs subvolume list`, `zfs list -t snapshot` | Periodic inventory |

**Practical scripts:** `ShadowBackup-Hunter.ps1` (Windows) and `shadow-backup-hunter.sh` (Linux) implement these checks and write findings to log files only (silent operation).

---

## Layer 2 – Data Exfiltration Signals (Hours Before Encryption)

Many ransomware groups now steal data before encrypting it. Large outbound transfers or connections to unusual destinations are strong early warnings.

| Signal | Baseline Concept | Alert Threshold (starting point) | Notes |
|--------|------------------|----------------------------------|-------|
| Outbound data volume | Historical per-endpoint average | > 5× baseline **or** > 500 MB/min sustained | Ransomware exfiltration moves large volumes quickly |
| New or rare external destinations | Known business / IT destinations | Connections to IPs/domains never (or rarely) seen | Often C2 or staging infrastructure |
| Consumer cloud abuse | Normal sync traffic | Large transfers to Dropbox, Mega, Proton, public S3, etc. from non-IT endpoints | Common exfiltration channel |
| DNS anomalies | Normal query patterns | Extremely long domain names, very high query rate to a single domain | Possible DNS tunneling |

**Practical scripts:** `Exfil-Hunter.ps1` and `exfil-hunter.sh` sample outbound volume, enumerate external connections, and look for simple DNS anomalies. They operate silently and only log results.

---

## Layer 3 – Credential Access, Privilege Escalation & Defense Evasion

These activities usually occur early so the attacker can reach domain controllers, backup servers, and file shares.

### Common Observable Indicators

- Unusual process access to LSASS (Windows) or memory of privileged processes (Linux)  
- Creation of new services or scheduled tasks running as SYSTEM / root from unexpected parents  
- Disabling of security tools (EDR agents, antivirus services, auditd, firewall rules)  
- Off-hours interactive or service-account logons  
- Sudden appearance of credential-dumping utilities or living-off-the-land binaries used for dumping  

These signals have higher false-positive potential and are best correlated with the recovery-inhibition and exfiltration layers above.

---

## Recommended Monitoring Cadence for System Administrators

| Check | Frequency | Script / Method | Priority |
|-------|-----------|-----------------|----------|
| Shadow copy / snapshot status + recovery commands | Every 5–15 minutes | ShadowBackup-Hunter | Critical |
| Outbound volume + external connections | Every 5–15 minutes | Exfil-Hunter | High |
| Critical backup & security service status | Every 5–15 minutes | Simple service-state script | High |
| Process creation with known bad command-line patterns | Continuous (via SIEM) or frequent scheduled scan | Process-creation hunter | Medium-High |
| Canary / honeypot file access | Continuous | File-integrity or audit rules | Medium |

All scripts in this project are deliberately **silent**: they write only to log files and return an exit code (`0` = clean, `1` = high-confidence signal). This makes them suitable for Task Scheduler, cron, SIEM ingestion, or SOAR playbooks without interrupting users.

---

## Limitations and Realistic Expectations

- These are host-based indicators, not a complete detection platform.  
- Sophisticated attackers using fileless techniques, BYOVD, or living-off-the-land binaries may evade pure process monitoring.  
- Baseline tuning is required; legitimate backup jobs and administrative activity can trigger volume or snapshot-related signals.  
- Always combine host checks with network monitoring, immutable off-host backups, and tested recovery procedures.

The goal is not perfect prevention. The goal is to shorten the time between the attacker’s first recovery-inhibiting action and the defender’s response.

---

## How to Use the Accompanying Scripts

The repository contains ready-to-run utilities:

- `ShadowBackup-Hunter.ps1` / `shadow-backup-hunter.sh` – Layer 1 recovery-inhibition detection  
- `Exfil-Hunter.ps1` / `exfil-hunter.sh` – Layer 2 exfiltration detection  

See the main [README.md](../README.md) for installation, scheduling, and usage instructions.

---

## Further Reading & Standards

- MITRE ATT&CK: T1490 Inhibit System Recovery  
- CISA ransomware guidance on anomalous use of `vssadmin`, `wbadmin`, `bcdedit`, and related tools  
- Industry reporting on decreasing breakout times and the rise of double-extortion  

---

**Detect the preparation stage, not just the encryption stage.**

*This document is released for public defensive use. Contributions, additional detection ideas, and platform-specific improvements are welcome.*
