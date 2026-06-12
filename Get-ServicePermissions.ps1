#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows service permissions for the current user.
    Reports services the user can start/stop/modify, and binaries the user can write to.

.PARAMETER ExportCsv
    Export results to a CSV file.

.PARAMETER CsvPath
    Path for CSV output. Defaults to ServiceAudit_<timestamp>.csv in current directory.

.EXAMPLE
    .\Get-ServicePermissions.ps1
    .\Get-ServicePermissions.ps1 -ExportCsv
    .\Get-ServicePermissions.ps1 -ExportCsv -CsvPath C:\Temp\audit.csv
#>
param(
    [switch]$ExportCsv,
    [string]$CsvPath = "ServiceAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Native service API ────────────────────────────────────────────────────────
# We call OpenService() directly instead of parsing SDDL.
#
# Why: WindowsIdentity.Groups returns ALL group SIDs including ones the kernel
# has marked SE_GROUP_USE_FOR_DENY_ONLY (e.g. BUILTIN\Administrators when UAC
# is active and the process is non-elevated). Those SIDs apply to Deny ACEs only,
# not Allow ACEs - so SDDL parsing incorrectly grants access the token can't
# actually exercise (WinDefend, etc.).
#
# OpenService() runs the real kernel access check against the caller's token, so
# it reflects UAC filtering, deny-only groups, and PPL-protected services correctly.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class SvcNative {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenSCManager(string machine, string database, uint access);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenService(IntPtr hSCM, string name, uint access);

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseServiceHandle(IntPtr h);

    public const uint SC_MANAGER_CONNECT    = 0x0001;
    public const uint SERVICE_START         = 0x0010;
    public const uint SERVICE_STOP          = 0x0020;
    public const uint SERVICE_CHANGE_CONFIG = 0x0002;
}
'@

$hSCM = [SvcNative]::OpenSCManager([NullString]::Value, [NullString]::Value, [SvcNative]::SC_MANAGER_CONNECT)
if ($hSCM -eq [IntPtr]::Zero) {
    Write-Warning "OpenSCManager failed (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Exiting."
    exit 1
}

# ── Current user identity (used for file-write ACL checks) ────────────────────
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$userSIDs = [System.Collections.Generic.HashSet[string]]::new()
[void]$userSIDs.Add($identity.User.Value)
foreach ($g in $identity.Groups) { [void]$userSIDs.Add($g.Value) }

# ── Service permission check via native API ───────────────────────────────────
function Get-ServicePermissions {
    param([string]$serviceName)

    $result = [PSCustomObject]@{ CanStart = $false; CanStop = $false; CanModify = $false }

    foreach ($entry in @(
        @{ Mask = [SvcNative]::SERVICE_START;         Key = 'CanStart'  }
        @{ Mask = [SvcNative]::SERVICE_STOP;          Key = 'CanStop'   }
        @{ Mask = [SvcNative]::SERVICE_CHANGE_CONFIG; Key = 'CanModify' }
    )) {
        $hSvc = [SvcNative]::OpenService($hSCM, $serviceName, $entry.Mask)
        if ($hSvc -ne [IntPtr]::Zero) {
            $result.($entry.Key) = $true
            [void][SvcNative]::CloseServiceHandle($hSvc)
        }
    }

    return $result
}

# ── Binary path resolution ────────────────────────────────────────────────────
function Get-ServiceBinaryInfo {
    param([string]$serviceName)

    $regBase   = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $imagePath = (Get-ItemProperty -Path $regBase -Name ImagePath).ImagePath
    if (-not $imagePath) { return $null }

    $expanded = [System.Environment]::ExpandEnvironmentVariables($imagePath.Trim())

    $exePath = $null
    if      ($expanded -match '^"([^"]+)"')                    { $exePath = $Matches[1] }
    elseif  ($expanded -match '^([A-Za-z]:\\[^\s"]+\.exe)')    { $exePath = $Matches[1] }
    elseif  ($expanded -match '^(\S+\.exe)')                   { $exePath = $Matches[1] }
    else                                                       { $exePath = ($expanded -split '\s+')[0] }

    $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)

    # svchost services: the real code is in a DLL, not the host EXE
    $isSvchost = ($exePath -match 'svchost\.exe')
    $dllPath   = $null
    if ($isSvchost) {
        $dllPath = (Get-ItemProperty -Path "$regBase\Parameters" -Name ServiceDll).ServiceDll
        if ($dllPath) { $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath) }
    }

    return [PSCustomObject]@{ ExePath = $exePath; DllPath = $dllPath; IsSvchost = $isSvchost }
}

# ── Binary write-access check ─────────────────────────────────────────────────
function Test-UserCanWrite {
    param([string]$filePath)

    if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) { return $false }
    try { $acl = Get-Acl -Path $filePath } catch { return $false }

    # Only check write-exclusive bits.
    # WriteData (0x2) is present in Write/Modify/FullControl but NOT in
    # ReadAndExecute/Read/Execute - so no false positives from run-only access.
    # AppendData (0x4), ChangePermissions (0x40000), TakeOwnership (0x80000) included
    # as they also enable overwriting or escalating to write.
    [long]$writeMask = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try   { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if (-not $userSIDs.Contains($sid)) { continue }
        if (([long][int]$ace.FileSystemRights -band $writeMask) -ne 0) { return $true }
    }
    return $false
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host @"

  ╔══════════════════════════════════════════════════════════╗
  ║        Windows Service Permission Auditor                ║
  ╚══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Host "  User     : " -NoNewline -ForegroundColor White
Write-Host $identity.Name  -ForegroundColor Yellow

Write-Host "  Is Admin : " -NoNewline -ForegroundColor White
if ($isAdmin) { Write-Host "YES (elevated - all admin-accessible services will appear)" -ForegroundColor Red }
else          { Write-Host "No  (non-elevated token - UAC-filtered results)"            -ForegroundColor Green }
Write-Host ""

# ── Scan ──────────────────────────────────────────────────────────────────────
$services = Get-Service | Sort-Object Name
$results  = [System.Collections.Generic.List[PSObject]]::new()
$total    = $services.Count
$i        = 0

foreach ($svc in $services) {
    $i++
    Write-Progress -Activity "Auditing $total services" `
                   -Status   "[$i/$total] $($svc.Name)" `
                   -PercentComplete ([int](($i / $total) * 100))

    $perms  = Get-ServicePermissions -ServiceName $svc.Name
    $binary = Get-ServiceBinaryInfo  -ServiceName $svc.Name

    $canWriteExe = $false
    $canWriteDll = $false

    if ($binary) {
        $canWriteExe = Test-UserCanWrite $binary.ExePath
        if ($binary.IsSvchost -and $binary.DllPath) {
            $canWriteDll = Test-UserCanWrite $binary.DllPath
        }
    }

    $interesting = $perms.CanStart -or $perms.CanStop -or $perms.CanModify `
                   -or $canWriteExe -or $canWriteDll
    if (-not $interesting) { continue }

    $risk = switch ($true) {
        { $canWriteExe -or $canWriteDll }      { 'CRITICAL'; break }
        { $perms.CanModify }                   { 'HIGH';     break }
        { $perms.CanStart -or $perms.CanStop } { 'MEDIUM';   break }
        default                                { 'LOW' }
    }

    $effectivePath = if ($binary -and $binary.IsSvchost -and $binary.DllPath) {
        $binary.DllPath
    } elseif ($binary) { $binary.ExePath } else { $null }

    $results.Add([PSCustomObject]@{
        Risk           = $risk
        ServiceName    = $svc.Name
        DisplayName    = $svc.DisplayName
        Status         = $svc.Status
        CanStart       = $perms.CanStart
        CanStop        = $perms.CanStop
        CanModify      = $perms.CanModify
        CanWriteBinary = ($canWriteExe -or $canWriteDll)
        IsSvchost      = if ($binary) { $binary.IsSvchost } else { $false }
        ExePath        = if ($binary) { $binary.ExePath }   else { $null }
        EffectivePath  = $effectivePath
    })
}

Write-Progress -Activity "Auditing services" -Completed
[void][SvcNative]::CloseServiceHandle($hSCM)

# ── Report ────────────────────────────────────────────────────────────────────
if ($results.Count -eq 0) {
    Write-Host "[+] No exploitable service permissions found for the current user." `
               -ForegroundColor Green
} else {
    $critical = @($results | Where-Object Risk -eq 'CRITICAL')
    $high     = @($results | Where-Object Risk -eq 'HIGH')
    $medium   = @($results | Where-Object Risk -eq 'MEDIUM')
    $low      = @($results | Where-Object Risk -eq 'LOW')

    $line = '─' * 68
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ("  FINDINGS: {0,3} service(s)   " -f $results.Count) -NoNewline
    Write-Host ("CRITICAL:{0,3}  " -f $critical.Count) -NoNewline -ForegroundColor Red
    Write-Host ("HIGH:{0,3}  "     -f $high.Count)     -NoNewline -ForegroundColor Yellow
    Write-Host ("MEDIUM:{0,3}  "   -f $medium.Count)   -NoNewline -ForegroundColor Cyan
    Write-Host ("LOW:{0,3}"        -f $low.Count)                  -ForegroundColor DarkCyan
    Write-Host $line -ForegroundColor DarkGray

    if ($critical) {
        Write-Host "`n[CRITICAL] Writable service binaries" -ForegroundColor Red
        Write-Host "  Replace the binary/DLL to gain code execution as the service account." `
                   -ForegroundColor DarkRed
        foreach ($r in $critical) {
            Write-Host ""
            Write-Host "  Service : $($r.ServiceName)  [$($r.Status)]" -ForegroundColor Red
            Write-Host "  Display : $($r.DisplayName)"  -ForegroundColor DarkRed
            if ($r.IsSvchost) {
                Write-Host "  Host EXE: $($r.ExePath)"                           -ForegroundColor DarkGray
                Write-Host "  DLL     : $($r.EffectivePath)  <-- WRITABLE"       -ForegroundColor Red
            } else {
                Write-Host "  Binary  : $($r.ExePath)  <-- WRITABLE"             -ForegroundColor Red
            }
            Write-Host ("  Perms   : Start={0}  Stop={1}  Modify={2}" -f `
                        $r.CanStart, $r.CanStop, $r.CanModify) -ForegroundColor DarkRed
        }
    }

    if ($high) {
        Write-Host "`n[HIGH] Services the user can reconfigure (SERVICE_CHANGE_CONFIG)" `
                   -ForegroundColor Yellow
        Write-Host "  Can redirect binPath to an arbitrary executable." -ForegroundColor DarkYellow
        $high | Format-Table -AutoSize @(
            @{N='Service';     E={$_.ServiceName};    W=28}
            @{N='Status';      E={$_.Status};          W=10}
            @{N='Start';       E={$_.CanStart}}
            @{N='Stop';        E={$_.CanStop}}
            @{N='BinWritable'; E={$_.CanWriteBinary}}
            @{N='Binary / DLL';E={$_.EffectivePath}}
        )
    }

    if ($medium) {
        Write-Host "`n[MEDIUM] Services the user can start or stop" -ForegroundColor Cyan
        $medium | Format-Table -AutoSize @(
            @{N='Service';     E={$_.ServiceName};  W=28}
            @{N='Status';      E={$_.Status};        W=10}
            @{N='Start';       E={$_.CanStart}}
            @{N='Stop';        E={$_.CanStop}}
            @{N='Binary / DLL';E={$_.EffectivePath}}
        )
    }

    if ($low) {
        Write-Host "`n[LOW] Other interesting entries" -ForegroundColor DarkCyan
        $low | Format-Table -AutoSize Risk, ServiceName, Status, CanStart, CanStop, CanModify, CanWriteBinary, EffectivePath
    }

    Write-Host "`n[*] Full results table:" -ForegroundColor White
    $riskOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
    $results |
        Sort-Object { $riskOrder[$_.Risk] }, ServiceName |
        Format-Table -AutoSize Risk, ServiceName, Status, CanStart, CanStop, CanModify, CanWriteBinary, EffectivePath
}

if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[*] Results exported to: $CsvPath" -ForegroundColor Green
}

Write-Host "Scan complete. $total services checked, $($results.Count) with interesting permissions.`n" `
           -ForegroundColor DarkGray
