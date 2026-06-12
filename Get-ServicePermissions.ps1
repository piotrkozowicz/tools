#Requires -Version 5.1
<#
.SYNOPSIS
    Audits Windows service permissions for the current user.
    Reports services the user can start/stop/modify, and binaries the user can write to.
    Verifies start/stop findings by actually attempting the operations and restoring state.

.PARAMETER ExportCsv
    Export results to a CSV file.

.PARAMETER CsvPath
    Path for CSV output. Defaults to ServiceAudit_<timestamp>.csv in current directory.

.PARAMETER SkipVerify
    Skip the live start/stop verification phase (faster, but may include false positives).

.EXAMPLE
    .\Get-ServicePermissions.ps1
    .\Get-ServicePermissions.ps1 -SkipVerify
    .\Get-ServicePermissions.ps1 -ExportCsv -CsvPath C:\Temp\audit.csv
#>
param(
    [switch]$ExportCsv,
    [string]$CsvPath = "ServiceAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$SkipVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ── Native service API ────────────────────────────────────────────────────────
# OpenService() is used for permission probing — it runs the real kernel access
# check against the caller's token, correctly reflecting UAC token filtering and
# deny-only group SIDs (which WindowsIdentity.Groups includes but SDDL parsing
# would wrongly treat as granting access).
# StartService / ControlService are used for live verification.
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

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(IntPtr hService, uint numArgs, IntPtr argVectors);

    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ControlService(IntPtr hService, uint control,
        ref SERVICE_STATUS status);

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS {
        public uint serviceType;
        public uint currentState;
        public uint controlsAccepted;
        public uint win32ExitCode;
        public uint serviceSpecificExitCode;
        public uint checkPoint;
        public uint waitHint;
    }

    public const uint SC_MANAGER_CONNECT    = 0x0001;
    public const uint SERVICE_START         = 0x0010;
    public const uint SERVICE_STOP          = 0x0020;
    public const uint SERVICE_CHANGE_CONFIG = 0x0002;
    public const uint SERVICE_CONTROL_STOP  = 0x00000001;
}
'@

$hSCM = [SvcNative]::OpenSCManager([NullString]::Value, [NullString]::Value, [SvcNative]::SC_MANAGER_CONNECT)
if ($hSCM -eq [IntPtr]::Zero) {
    Write-Warning "OpenSCManager failed (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Exiting."
    exit 1
}

# ── Current user identity (for file-write ACL checks) ─────────────────────────
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

$userSIDs = [System.Collections.Generic.HashSet[string]]::new()
[void]$userSIDs.Add($identity.User.Value)
foreach ($g in $identity.Groups) { [void]$userSIDs.Add($g.Value) }

# ── Service permission probe (OpenService access check) ───────────────────────
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

# ── Live start/stop verification ──────────────────────────────────────────────
# Attempts the actual operation against a running/stopped service and immediately
# restores the original state. Returns whether each operation actually succeeded.
#
# Safety rules:
#   Stop verification: only attempted on Running services; restores by starting.
#   Start verification: only attempted on Stopped services; restores by stopping.
#   If restore fails the service is left in the new state (logged to console).
function Confirm-StartStop {
    param(
        [string]$serviceName,
        [string]$status,       # current service status string
        [bool]$canStop,
        [bool]$canStart
    )

    $stopOk  = $null   # $null = not attempted
    $startOk = $null

    # ── Verify stop ────────────────────────────────────────────────────────────
    if ($canStop -and $status -eq 'Running') {
        $hSvc = [SvcNative]::OpenService($hSCM, $serviceName, [SvcNative]::SERVICE_STOP)
        if ($hSvc -ne [IntPtr]::Zero) {
            $svcStatus = New-Object SvcNative+SERVICE_STATUS
            $stopOk = [SvcNative]::ControlService($hSvc, [SvcNative]::SERVICE_CONTROL_STOP, [ref]$svcStatus)
            [void][SvcNative]::CloseServiceHandle($hSvc)

            if ($stopOk) {
                Start-Sleep -Milliseconds 1500
                $hRestore = [SvcNative]::OpenService($hSCM, $serviceName, [SvcNative]::SERVICE_START)
                if ($hRestore -ne [IntPtr]::Zero) {
                    [void][SvcNative]::StartService($hRestore, 0, [IntPtr]::Zero)
                    [void][SvcNative]::CloseServiceHandle($hRestore)
                } else {
                    Write-Warning "Stopped '$serviceName' for verification but could not restart it."
                }
            }
        } else {
            $stopOk = $false
        }
    }

    # ── Verify start ───────────────────────────────────────────────────────────
    if ($canStart -and $status -eq 'Stopped') {
        $hSvc = [SvcNative]::OpenService($hSCM, $serviceName, [SvcNative]::SERVICE_START)
        if ($hSvc -ne [IntPtr]::Zero) {
            $startOk = [SvcNative]::StartService($hSvc, 0, [IntPtr]::Zero)
            [void][SvcNative]::CloseServiceHandle($hSvc)

            if ($startOk) {
                Start-Sleep -Milliseconds 1500
                $hRestore = [SvcNative]::OpenService($hSCM, $serviceName, [SvcNative]::SERVICE_STOP)
                if ($hRestore -ne [IntPtr]::Zero) {
                    $svcStatus = New-Object SvcNative+SERVICE_STATUS
                    [void][SvcNative]::ControlService($hRestore, [SvcNative]::SERVICE_CONTROL_STOP, [ref]$svcStatus)
                    [void][SvcNative]::CloseServiceHandle($hRestore)
                } else {
                    Write-Warning "Started '$serviceName' for verification but could not stop it again."
                }
            }
        } else {
            $startOk = $false
        }
    }

    return [PSCustomObject]@{ StopConfirmed = $stopOk; StartConfirmed = $startOk }
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

    # WriteData (0x2) is present in Write/Modify/FullControl but NOT in
    # ReadAndExecute/Read/Execute - no false positives from run-only access.
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
if ($isAdmin) { Write-Host "YES (elevated)" -ForegroundColor Red }
else          { Write-Host "No"             -ForegroundColor Green }
Write-Host "  Verify   : " -NoNewline -ForegroundColor White
if ($SkipVerify) { Write-Host "Skipped (-SkipVerify)" -ForegroundColor DarkGray }
else             { Write-Host "Enabled  (will attempt live start/stop and restore)" -ForegroundColor Yellow }
Write-Host ""

# ── Phase 1: scan all services ────────────────────────────────────────────────
Write-Host "[1/2] Scanning permissions..." -ForegroundColor DarkGray
$services = Get-Service | Sort-Object Name
$results  = [System.Collections.Generic.List[PSObject]]::new()
$total    = $services.Count
$i        = 0

foreach ($svc in $services) {
    $i++
    Write-Progress -Activity "Phase 1/2 - Scanning $total services" `
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

    $effectivePath = if ($binary -and $binary.IsSvchost -and $binary.DllPath) {
        $binary.DllPath
    } elseif ($binary) { $binary.ExePath } else { $null }

    $results.Add([PSCustomObject]@{
        ServiceName    = $svc.Name
        DisplayName    = $svc.DisplayName
        Status         = $svc.Status
        CanStart       = $perms.CanStart
        CanStop        = $perms.CanStop
        CanModify      = $perms.CanModify
        CanWriteBinary = ($canWriteExe -or $canWriteDll)
        StopConfirmed  = $null
        StartConfirmed = $null
        IsSvchost      = if ($binary) { $binary.IsSvchost } else { $false }
        ExePath        = if ($binary) { $binary.ExePath }   else { $null }
        EffectivePath  = $effectivePath
    })
}

Write-Progress -Activity "Phase 1/2 - Scanning" -Completed
Write-Host "    Found $($results.Count) candidate service(s)." -ForegroundColor DarkGray

# ── Phase 2: live verification ────────────────────────────────────────────────
if (-not $SkipVerify) {
    $toVerify = @($results | Where-Object { $_.CanStart -or $_.CanStop })
    if ($toVerify.Count -gt 0) {
        Write-Host "[2/2] Verifying $($toVerify.Count) service(s) with live start/stop..." `
                   -ForegroundColor DarkGray
        $j = 0
        foreach ($r in $toVerify) {
            $j++
            Write-Progress -Activity "Phase 2/2 - Verifying" `
                           -Status   "[$j/$($toVerify.Count)] $($r.ServiceName)" `
                           -PercentComplete ([int](($j / $toVerify.Count) * 100))

            $v = Confirm-StartStop -serviceName $r.ServiceName `
                                   -status      $r.Status.ToString() `
                                   -canStop     $r.CanStop `
                                   -canStart    $r.CanStart
            $r.StopConfirmed  = $v.StopConfirmed
            $r.StartConfirmed = $v.StartConfirmed
        }
        Write-Progress -Activity "Phase 2/2 - Verifying" -Completed
    } else {
        Write-Host "[2/2] No Running/Stopped services to verify." -ForegroundColor DarkGray
    }
}

[void][SvcNative]::CloseServiceHandle($hSCM)

# ── Compute final risk (demote if verification disproved access) ──────────────
foreach ($r in $results) {
    # If verified and both start+stop failed, downgrade CanStart/CanStop
    if ($null -ne $r.StopConfirmed  -and -not $r.StopConfirmed)  { $r.CanStop  = $false }
    if ($null -ne $r.StartConfirmed -and -not $r.StartConfirmed) { $r.CanStart = $false }

    $riskValue = if     ($r.CanWriteBinary)              { 'CRITICAL' }
                 elseif ($r.CanModify)                   { 'HIGH'     }
                 elseif ($r.CanStart -or $r.CanStop)     { 'MEDIUM'   }
                 else                                    { 'LOW'      }
    $r | Add-Member -NotePropertyName Risk -NotePropertyValue $riskValue
}

# Drop entries that are no longer interesting after verification
$results = [System.Collections.Generic.List[PSObject]]($results | Where-Object {
    $_.CanStart -or $_.CanStop -or $_.CanModify -or $_.CanWriteBinary
})

# ── Report ────────────────────────────────────────────────────────────────────
if ($results.Count -eq 0) {
    Write-Host "[+] No exploitable service permissions confirmed for the current user." `
               -ForegroundColor Green
} else {
    $critical = @($results | Where-Object Risk -eq 'CRITICAL')
    $high     = @($results | Where-Object Risk -eq 'HIGH')
    $medium   = @($results | Where-Object Risk -eq 'MEDIUM')
    $low      = @($results | Where-Object Risk -eq 'LOW')

    $line = '─' * 68
    Write-Host $line -ForegroundColor DarkGray
    Write-Host ("  CONFIRMED: {0,3} service(s)   " -f $results.Count) -NoNewline
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
                Write-Host "  Host EXE: $($r.ExePath)"                       -ForegroundColor DarkGray
                Write-Host "  DLL     : $($r.EffectivePath)  <-- WRITABLE"   -ForegroundColor Red
            } else {
                Write-Host "  Binary  : $($r.ExePath)  <-- WRITABLE"         -ForegroundColor Red
            }
            Write-Host ("  Perms   : Start={0}  Stop={1}  Modify={2}" -f `
                        $r.CanStart, $r.CanStop, $r.CanModify) -ForegroundColor DarkRed
        }
    }

    if ($high) {
        Write-Host "`n[HIGH] Services the user can reconfigure" -ForegroundColor Yellow
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
        Write-Host "`n[MEDIUM] Services the user can start or stop (live verified)" -ForegroundColor Cyan
        $medium | Format-Table -AutoSize @(
            @{N='Service';       E={$_.ServiceName};    W=28}
            @{N='Status';        E={$_.Status};          W=10}
            @{N='Start';         E={$_.CanStart}}
            @{N='Stop';          E={$_.CanStop}}
            @{N='StopVerified';  E={if ($null -eq $_.StopConfirmed)  {'n/a'} else {$_.StopConfirmed}}}
            @{N='StartVerified'; E={if ($null -eq $_.StartConfirmed) {'n/a'} else {$_.StartConfirmed}}}
            @{N='Binary / DLL';  E={$_.EffectivePath}}
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
        Format-Table -AutoSize Risk, ServiceName, Status, CanStart, CanStop, CanModify, CanWriteBinary, StopConfirmed, StartConfirmed, EffectivePath
}

if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[*] Results exported to: $CsvPath" -ForegroundColor Green
}

Write-Host "Done. $total services scanned, $($results.Count) confirmed with exploitable permissions.`n" `
           -ForegroundColor DarkGray
