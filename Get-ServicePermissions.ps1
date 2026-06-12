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

# ── Current user identity ──────────────────────────────────────────────────────
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

# Build a set of all SIDs the user is a member of (own SID + all group SIDs)
$userSIDs = [System.Collections.Generic.HashSet[string]]::new()
[void]$userSIDs.Add($identity.User.Value)
foreach ($g in $identity.Groups) { [void]$userSIDs.Add($g.Value) }

# ── SDDL: well-known SID aliases ───────────────────────────────────────────────
# These appear in the 6th field of an ACE: (type;flags;rights;obj;iobj;SID)
$sddlSIDMap = @{
    'WD' = 'S-1-1-0'        # Everyone
    'AU' = 'S-1-5-11'       # Authenticated Users
    'IU' = 'S-1-5-4'        # Interactive Logon
    'SU' = 'S-1-5-6'        # Service
    'BA' = 'S-1-5-32-544'   # BUILTIN\Administrators
    'BU' = 'S-1-5-32-545'   # BUILTIN\Users
    'PU' = 'S-1-5-32-547'   # Power Users
    'SY' = 'S-1-5-18'       # Local System
    'LS' = 'S-1-5-19'       # Local Service
    'NS' = 'S-1-5-20'       # Network Service
    'CO' = 'S-1-3-0'        # Creator Owner
    'CG' = 'S-1-3-1'        # Creator Group
    'AN' = 'S-1-5-7'        # Anonymous
    'RD' = 'S-1-5-32-555'   # Remote Desktop Users
    'NO' = 'S-1-5-32-556'   # Network Configuration Operators
    'MU' = 'S-1-5-32-558'   # Performance Monitor Users
}

# ── SDDL: service-specific right codes → bitmasks ─────────────────────────────
# The 3rd field of an ACE is a concatenation of 2-char codes OR a hex value.
# Service-object specific codes (from winnt.h / sc SDDL documentation):
#   CC = SERVICE_QUERY_CONFIG    (0x0001)
#   DC = SERVICE_CHANGE_CONFIG   (0x0002)  ← "modify"
#   LC = SERVICE_QUERY_STATUS    (0x0004)
#   SW = SERVICE_ENUMERATE_DEPENDENTS (0x0008)
#   RP = SERVICE_START           (0x0010)  ← "start"
#   WP = SERVICE_STOP            (0x0020)  ← "stop"
#   DT = SERVICE_PAUSE_CONTINUE  (0x0040)
#   LO = SERVICE_INTERROGATE     (0x0080)
#   CR = SERVICE_USER_DEFINED_CONTROL (0x0100)
$serviceRightBits = @{
    'CC' = [long]0x0001
    'DC' = [long]0x0002
    'LC' = [long]0x0004
    'SW' = [long]0x0008
    'RP' = [long]0x0010
    'WP' = [long]0x0020
    'DT' = [long]0x0040
    'LO' = [long]0x0080
    'CR' = [long]0x0100
    'SD' = [long]0x00010000   # DELETE
    'RC' = [long]0x00020000   # READ_CONTROL
    'WD' = [long]0x00040000   # WRITE_DAC
    'WO' = [long]0x00080000   # WRITE_OWNER
    'GA' = [long]0x10000000   # GENERIC_ALL
    'GW' = [long]0x40000000   # GENERIC_WRITE
    'GR' = [long]0x20000000   # GENERIC_READ
}

function Resolve-SDDLSid {
    param([string]$sid)
    if ($sddlSIDMap.ContainsKey($sid)) { return $sddlSIDMap[$sid] }
    return $sid
}

function ConvertTo-ServiceRightsMask {
    param([string]$rightsStr)
    # Hex literal  (e.g.  0xf01ff)
    if ($rightsStr -match '^0[xX][0-9a-fA-F]+$') {
        return [Convert]::ToInt64($rightsStr, 16)
    }
    # Decimal literal
    if ($rightsStr -match '^\d+$') { return [long]$rightsStr }
    # Named codes — consume 2 chars at a time
    $mask = [long]0
    $i = 0
    while ($i -le ($rightsStr.Length - 2)) {
        $code = $rightsStr.Substring($i, 2)
        if ($serviceRightBits.ContainsKey($code)) {
            $mask = $mask -bor $serviceRightBits[$code]
            $i += 2
        } else {
            $i++
        }
    }
    return $mask
}

function Get-ServicePermissions {
    param([string]$serviceName)

    $result = [PSCustomObject]@{ CanStart = $false; CanStop = $false; CanModify = $false }

    $sddl = (& sc.exe sdshow $serviceName 2>$null) -join '' -replace '\s',''
    if (-not $sddl -or $sddl -notmatch 'D:') { return $result }

    # Parse every ACE in the string: (type;flags;rights;obj;iobj;sid)
    foreach ($m in [regex]::Matches($sddl, '\(([^)]+)\)')) {
        $parts = $m.Groups[1].Value -split ';'
        if ($parts.Count -lt 6) { continue }

        $aceType = $parts[0]   # A = Allow, D = Deny
        $rights  = $parts[2]
        $rawSid  = $parts[5]

        $sid = Resolve-SDDLSid $rawSid
        if (-not $userSIDs.Contains($sid)) { continue }

        $mask = ConvertTo-ServiceRightsMask $rights

        if ($aceType -eq 'A') {
            if ($mask -band 0x0010)      { $result.CanStart  = $true }   # SERVICE_START
            if ($mask -band 0x0020)      { $result.CanStop   = $true }   # SERVICE_STOP
            if ($mask -band 0x0002)      { $result.CanModify = $true }   # SERVICE_CHANGE_CONFIG
            if ($mask -band 0x10000000) {                                  # GENERIC_ALL
                $result.CanStart = $true; $result.CanStop = $true; $result.CanModify = $true
            }
            if ($mask -band 0x40000000) { $result.CanModify = $true }    # GENERIC_WRITE
        }
        # Deny ACEs would need priority handling for a full audit tool;
        # omitted here since we are listing what is reachable, not guaranteed safe.
    }
    return $result
}

function Get-ServiceBinaryInfo {
    param([string]$serviceName)

    $regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $imagePath = (Get-ItemProperty -Path $regBase -Name ImagePath).ImagePath
    if (-not $imagePath) { return $null }

    $expanded = [System.Environment]::ExpandEnvironmentVariables($imagePath.Trim())

    # Extract the executable — handle quoted paths, paths with arguments
    $exePath = $null
    if ($expanded -match '^"([^"]+)"')                          { $exePath = $Matches[1] }
    elseif ($expanded -match '^([A-Za-z]:\\[^\s"]+\.exe)')      { $exePath = $Matches[1] }
    elseif ($expanded -match '^(\S+\.exe)')                     { $exePath = $Matches[1] }
    else                                                        { $exePath = ($expanded -split '\s+')[0] }

    $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)

    # For svchost-hosted services the real code lives in a DLL
    $isSvchost  = ($exePath -match 'svchost\.exe')
    $dllPath    = $null
    if ($isSvchost) {
        $dllPath = (Get-ItemProperty -Path "$regBase\Parameters" -Name ServiceDll).ServiceDll
        if ($dllPath) {
            $dllPath = [System.Environment]::ExpandEnvironmentVariables($dllPath)
        }
    }

    return [PSCustomObject]@{
        ExePath    = $exePath
        DllPath    = $dllPath           # non-null only for svchost services
        IsSvchost  = $isSvchost
    }
}

function Test-UserCanWrite {
    param([string]$filePath)

    if (-not $filePath -or -not (Test-Path $filePath -PathType Leaf)) { return $false }

    try { $acl = Get-Acl -Path $filePath } catch { return $false }

    # Use only write-exclusive bits to avoid false positives from compound enum values.
    #
    # Root cause of false positives: Modify (0x301BF) and FullControl (0x1F01FF) both
    # include ExecuteFile (0x20), which is also present in ReadAndExecute (0x1200A9).
    # ORing those compound values into a mask makes ReadAndExecute match — incorrectly
    # flagging every system binary the user can merely run.
    #
    # WriteData (0x2) is the correct signal: present in Write/Modify/FullControl,
    # absent from ReadAndExecute, Read, and Execute.
    # AppendData (0x4): same pattern; alone can't overwrite content but included for accuracy.
    # ChangePermissions (0x40000) / TakeOwnership (0x80000): allow ACL manipulation → indirect write.
    [long]$writeMask = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        try   { $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { continue }
        if (-not $userSIDs.Contains($aceSid)) { continue }
        # Cast through [int] first to preserve sign, then widen to [long] for -band
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
if ($isAdmin) { Write-Host "YES (results may be less interesting)" -ForegroundColor Red }
else          { Write-Host "No"                                     -ForegroundColor Green }

Write-Host "  Group SIDs: $($userSIDs.Count - 1)" -ForegroundColor White
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

    $perms  = Get-ServicePermissions  -ServiceName $svc.Name
    $binary = Get-ServiceBinaryInfo   -ServiceName $svc.Name

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

    # Assign risk level
    $risk = switch ($true) {
        { $canWriteExe -or $canWriteDll } { 'CRITICAL'; break }
        { $perms.CanModify }              { 'HIGH';     break }
        { $perms.CanStart -or $perms.CanStop } { 'MEDIUM'; break }
        default                           { 'LOW' }
    }

    $effectivePath = if ($binary -and $binary.IsSvchost -and $binary.DllPath) {
        $binary.DllPath
    } elseif ($binary) {
        $binary.ExePath
    } else { $null }

    $results.Add([PSCustomObject]@{
        Risk           = $risk
        ServiceName    = $svc.Name
        DisplayName    = $svc.DisplayName
        Status         = $svc.Status
        CanStart       = $perms.CanStart
        CanStop        = $perms.CanStop
        CanModify      = $perms.CanModify  # SERVICE_CHANGE_CONFIG
        CanWriteBinary = ($canWriteExe -or $canWriteDll)
        IsSvchost      = if ($binary) { $binary.IsSvchost } else { $false }
        ExePath        = if ($binary) { $binary.ExePath }  else { $null }
        EffectivePath  = $effectivePath    # DLL for svchost, EXE otherwise
    })
}

Write-Progress -Activity "Auditing services" -Completed

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

    # ── CRITICAL ──────────────────────────────────────────────────────────────
    if ($critical) {
        Write-Host "`n[CRITICAL] Writable service binaries" -ForegroundColor Red
        Write-Host "  An attacker can replace the binary/DLL and gain code execution as" `
                   -ForegroundColor DarkRed
        Write-Host "  the service account on next service start." -ForegroundColor DarkRed
        foreach ($r in $critical) {
            Write-Host ""
            Write-Host "  Service : $($r.ServiceName)  [$($r.Status)]" -ForegroundColor Red
            Write-Host "  Display : $($r.DisplayName)"  -ForegroundColor DarkRed
            if ($r.IsSvchost) {
                Write-Host "  Host EXE: $($r.ExePath)"              -ForegroundColor DarkGray
                Write-Host "  DLL     : $($r.EffectivePath)  <-- WRITABLE" -ForegroundColor Red
            } else {
                Write-Host "  Binary  : $($r.ExePath)  <-- WRITABLE" -ForegroundColor Red
            }
            Write-Host "  Perms   : " -NoNewline -ForegroundColor DarkRed
            Write-Host ("Start={0}  Stop={1}  Modify={2}" -f $r.CanStart, $r.CanStop, $r.CanModify) `
                       -ForegroundColor DarkRed
        }
    }

    # ── HIGH ──────────────────────────────────────────────────────────────────
    if ($high) {
        Write-Host "`n[HIGH] Services the user can reconfigure (SERVICE_CHANGE_CONFIG)" `
                   -ForegroundColor Yellow
        Write-Host "  Can change binPath to an arbitrary executable." -ForegroundColor DarkYellow
        $high | Format-Table -AutoSize @(
            @{N='Service';    E={$_.ServiceName};   W=28}
            @{N='Status';     E={$_.Status};         W=10}
            @{N='Start';      E={$_.CanStart}}
            @{N='Stop';       E={$_.CanStop}}
            @{N='BinWritable';E={$_.CanWriteBinary}}
            @{N='Binary / DLL';E={$_.EffectivePath}}
        )
    }

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    if ($medium) {
        Write-Host "`n[MEDIUM] Services the user can start or stop" -ForegroundColor Cyan
        $medium | Format-Table -AutoSize @(
            @{N='Service';    E={$_.ServiceName};  W=28}
            @{N='Status';     E={$_.Status};        W=10}
            @{N='Start';      E={$_.CanStart}}
            @{N='Stop';       E={$_.CanStop}}
            @{N='Binary / DLL';E={$_.EffectivePath}}
        )
    }

    # ── LOW ───────────────────────────────────────────────────────────────────
    if ($low) {
        Write-Host "`n[LOW] Other interesting entries" -ForegroundColor DarkCyan
        $low | Format-Table -AutoSize Risk, ServiceName, Status, CanStart, CanStop, CanModify, CanWriteBinary, EffectivePath
    }

    # ── Full flat table ────────────────────────────────────────────────────────
    Write-Host "`n[*] Full results table:" -ForegroundColor White
    $results |
        Sort-Object @{E={
            switch ($_.Risk) { 'CRITICAL'{0} 'HIGH'{1} 'MEDIUM'{2} default{3} }
        }}, ServiceName |
        Format-Table -AutoSize Risk, ServiceName, Status, CanStart, CanStop, CanModify, CanWriteBinary, EffectivePath
}

# ── CSV export ────────────────────────────────────────────────────────────────
if ($ExportCsv) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "[*] Results exported to: $CsvPath" -ForegroundColor Green
}

Write-Host "Scan complete. $total services checked, $($results.Count) with interesting permissions.`n" `
           -ForegroundColor DarkGray
