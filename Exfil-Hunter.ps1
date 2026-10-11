# Exfil-Hunter.ps1
# Layer 2: Data Exfiltration Detection (silent monitoring)
# Windows 10 / 11 / Server 2016+
# Designed for scheduled / SIEM use — NO interactive alerts, NO pop-ups
# Logs findings only; exits with code 1 on high-confidence signals

[CmdletBinding()]
param(
    [int]$SampleSeconds = 30,                    # How long to sample outbound traffic
    [int]$HighVolumeMBPerMin = 500,              # Threshold: >500 MB/min is high-confidence
    [double]$VolumeMultiplier = 5.0,             # Or >5x recent baseline (if baseline exists)
    [string]$BaselineFile = "$env:ProgramData\ExfilHunter\baseline.json",
    [string]$LogPath = "$env:ProgramData\ExfilHunter\exfil-hunter.log",
    [string]$StatePath = "$env:ProgramData\ExfilHunter\state.json"
)

$ErrorActionPreference = "SilentlyContinue"
$HighConfidence = @()
$MediumConfidence = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Ensure directories exist
$dir = Split-Path $LogPath -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$timestamp] [$Level] $Message"
    # Silent: only write to log file, never Write-Host / MessageBox
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

Write-Log "=== Exfil-Hunter started (sample ${SampleSeconds}s) ==="

# -------------------------------------------------
# Helper: private / local address check
# -------------------------------------------------
function Test-PrivateIP {
    param([string]$IP)
    if ($IP -match '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1|fe80:|fc00:|fd)') { return $true }
    return $false
}

# -------------------------------------------------
# 1. Outbound data volume sampling
# -------------------------------------------------
$adapters = Get-NetAdapter -Physical | Where-Object Status -eq 'Up'
$bytesSentStart = 0
foreach ($a in $adapters) {
    $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
    if ($stats) { $bytesSentStart += $stats.SentBytes }
}

Start-Sleep -Seconds $SampleSeconds

$bytesSentEnd = 0
foreach ($a in $adapters) {
    $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
    if ($stats) { $bytesSentEnd += $stats.SentBytes }
}

$bytesSent = [math]::Max(0, $bytesSentEnd - $bytesSentStart)
$mbPerMin  = [math]::Round(($bytesSent / 1MB) * (60.0 / $SampleSeconds), 2)

Write-Log "Outbound volume sample: $mbPerMin MB/min over ${SampleSeconds}s"

if ($mbPerMin -ge $HighVolumeMBPerMin) {
    $HighConfidence += "High outbound volume: $mbPerMin MB/min (threshold $HighVolumeMBPerMin MB/min)"
}

# Simple baseline comparison (if previous run exists)
if (Test-Path $BaselineFile) {
    try {
        $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json
        if ($baseline.AvgMBPerMin -gt 0 -and $mbPerMin -gt ($baseline.AvgMBPerMin * $VolumeMultiplier)) {
            $HighConfidence += "Outbound volume ${mbPerMin} MB/min is >${VolumeMultiplier}x baseline ($($baseline.AvgMBPerMin) MB/min)"
        }
    } catch {}
}

# Update rolling baseline (very simple exponential moving average)
$newAvg = $mbPerMin
if (Test-Path $BaselineFile) {
    try {
        $old = (Get-Content $BaselineFile -Raw | ConvertFrom-Json).AvgMBPerMin
        $newAvg = [math]::Round(($old * 0.8) + ($mbPerMin * 0.2), 2)
    } catch {}
}
@{ AvgMBPerMin = $newAvg; Updated = $timestamp } | ConvertTo-Json | Set-Content $BaselineFile -Force

# -------------------------------------------------
# 2. Established outbound connections to external IPs
# -------------------------------------------------
$externalConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { -not (Test-PrivateIP $_.RemoteAddress) -and $_.RemoteAddress -ne '0.0.0.0' } |
    Select-Object RemoteAddress, RemotePort, OwningProcess, CreationTime

$uniqueRemoteIPs = $externalConnections | Select-Object -ExpandProperty RemoteAddress -Unique
Write-Log "External established connections: $($externalConnections.Count)  | Unique remote IPs: $($uniqueRemoteIPs.Count)"

# Cloud storage / common exfil destinations (by well-known ports + process context later)
$cloudPorts = @(443, 80, 22, 21, 8080, 8443)
$cloudLike = $externalConnections | Where-Object { $_.RemotePort -in $cloudPorts }

# Group by remote IP to find heavy talkers
$byIP = $externalConnections | Group-Object RemoteAddress | Sort-Object Count -Descending
foreach ($g in $byIP | Select-Object -First 10) {
    $procInfo = ""
    $sample = $g.Group | Select-Object -First 1
    try {
        $p = Get-Process -Id $sample.OwningProcess -ErrorAction SilentlyContinue
        if ($p) { $procInfo = " Process=$($p.ProcessName) Path=$($p.Path)" }
    } catch {}
    Write-Log "Remote $($g.Name) connections=$($g.Count)$procInfo"
}

# -------------------------------------------------
# 3. DNS Client cache anomalies (possible tunneling / staging)
# -------------------------------------------------
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
    $longNames = $dnsCache | Where-Object { $_.Entry.Length -gt 60 -or ($_.Entry -match '\.') -and ($_.Entry.Split('.').Count -gt 6) }
    if ($longNames) {
        $MediumConfidence += "DNS cache contains $($longNames.Count) unusually long or deep domain names (possible tunneling)"
        $longNames | Select-Object -First 5 | ForEach-Object {
            Write-Log "Long DNS entry: $($_.Entry)" "WARN"
        }
    }
} catch {}

# -------------------------------------------------
# 4. Known consumer cloud / file-share destinations (simple string match on reverse lookup if available)
# -------------------------------------------------
$suspectDomains = @('dropbox.com','mega.nz','mega.co.nz','proton.me','protonmail.com','transfer.sh','wetransfer.com','anonfiles','file.io','s3.amazonaws.com','storage.googleapis.com','blob.core.windows.net')
# We only log; full resolution would be expensive — rely on SIEM correlation or firewall logs for deeper analysis

# -------------------------------------------------
# Persist state for next run (last seen external IPs)
# -------------------------------------------------
$state = @{
    LastRun        = $timestamp
    LastMBPerMin   = $mbPerMin
    ExternalIPCount= $uniqueRemoteIPs.Count
    SampleIPs      = ($uniqueRemoteIPs | Select-Object -First 20)
}
$state | ConvertTo-Json | Set-Content $StatePath -Force

# -------------------------------------------------
# Final logging (silent)
# -------------------------------------------------
Write-Log "High-confidence signals: $($HighConfidence.Count)"
foreach ($h in $HighConfidence) { Write-Log $h "HIGH" }

Write-Log "Medium-confidence signals: $($MediumConfidence.Count)"
foreach ($m in $MediumConfidence) { Write-Log $m "WARN" }

if ($HighConfidence.Count -gt 0) {
    Write-Log "HIGH CONFIDENCE: Possible data exfiltration activity detected (silent mode — no user alert)" "HIGH"
    exit 1
} else {
    Write-Log "No high-confidence exfiltration signals in this sample."
    exit 0
}