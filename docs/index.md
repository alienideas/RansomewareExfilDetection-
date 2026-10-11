# ShadowBackup-Hunter & Exfil-Hunter

**Open-source ransomware early detection utilities for Windows and Linux**

Silent, lightweight scripts that help system administrators and blue teams detect ransomware preparation **before encryption begins**.

---

## Quick Links

| Resource | Description |
|----------|-------------|
| **[Early-Stage Indicators of Ransomware](Early-Stage-Ransomware-Indicators.md)** | Full practical guide: what to look for with PowerShell and Bash before an attack reaches the encryption stage |
| [Main Project README](../README.md) | Installation, usage, scheduling, and script overview |
| [ShadowBackup-Hunter.ps1](../ShadowBackup-Hunter.ps1) | Windows – Shadow Copy & Backup Hunting |
| [shadow-backup-hunter.sh](../shadow-backup-hunter.sh) | Linux – Snapshot & Backup Hunting |
| [Exfil-Hunter.ps1](../Exfil-Hunter.ps1) | Windows – Data Exfiltration Detection |
| [exfil-hunter.sh](../exfil-hunter.sh) | Linux – Data Exfiltration Detection |

---

## What the tools detect

1. **Layer 1 – Recovery inhibition**  
   Deletion of Volume Shadow Copies, snapshots, and backup catalogs (MITRE ATT&CK T1490).

2. **Layer 2 – Data exfiltration**  
   High outbound volume, rare external destinations, and simple DNS anomalies that often appear hours before encryption.

Both sets of scripts run silently (log files only) and return clear exit codes for automation, SIEM, or SOAR integration.

---

## Getting started

See the [main README](../README.md) for installation instructions on Windows and Linux, recommended scheduling, and usage examples.

---

*Free and open for public defensive use.*
