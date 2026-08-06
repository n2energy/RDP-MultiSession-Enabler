<#
================================================================================
    RDP MULTI-SESSION ENABLER FOR WINDOWS
    Version: 6.5
    Author: RDP Multi-Session Team
    License: MIT
    Repository: https://github.com/malnwaihi/RDP-MultiSession-Enabler
================================================================================

.SYNOPSIS
    Enables multiple concurrent RDP sessions on Windows by patching termsrv.dll
    with persistence mechanisms to survive reboots.

.DESCRIPTION
    This script modifies termsrv.dll to bypass the single session limit,
    allowing multiple simultaneous RDP connections. Includes comprehensive
    validation, safety mechanisms, and persistence features to prevent
    Windows from restoring the original file after reboot.

    FEATURES:
    • Automatic OS detection and pattern matching
    • Built-in backup and restore functionality
    • SHA256 hash verification
    • Byte-level patch validation
    • System Restore Point integration
    • Windows File Protection bypass
    • Scheduled task for post-update recovery
    • Comprehensive error recovery
    • Full logging capability

.PARAMETER Patch
    Run the patching process non-interactively

.PARAMETER Restore
    Restore termsrv.dll from backup

.PARAMETER Check
    Check current status and compatibility

.PARAMETER Validate
    Perform full validation of current configuration

.PARAMETER Test
    Test multi-session capability

.PARAMETER Persist
    Add persistence mechanisms to survive reboots

.PARAMETER Force
    Skip confirmation prompts

.PARAMETER BackupPath
    Specify custom backup location

.PARAMETER NoPersistence
    Skip adding persistence mechanisms

.EXAMPLE
    .\RDP-MultiSession-Enabler.ps1 -Patch
    .\RDP-MultiSession-Enabler.ps1 -Restore
    .\RDP-MultiSession-Enabler.ps1 -Test
    .\RDP-MultiSession-Enabler.ps1 -Patch -Persist

.NOTES
    Requirements:  - PowerShell 5.1 or higher
                   - Administrator privileges
                   - 64-bit Windows

    Compatibility: - Windows 11 21H2, 22H2, 23H2, 24H2, 25H2
                   - Windows 10 (all versions)
                   - Windows 7 SP1 (64-bit)

    DISCLAIMER: This script modifies system files. Use at your own risk.
                Always create a backup before proceeding.

================================================================================
#>

#region Initial Setup
param(
    [switch]$Patch,
    [switch]$Restore,
    [switch]$Check,
    [switch]$Validate,
    [switch]$Test,
    [switch]$Persist,
    [switch]$Force,
    [switch]$NoPersistence,
    [string]$BackupPath = "$env:SystemRoot\System32\termsrv.dll.backup"
)

# Script metadata
$scriptInfo = @{
    version = "6.5"
    author = "RDP Multi-Session Team"
    url = "https://github.com/malnwaihi/RDP-MultiSession-Enabler"
}

# Color definitions - used in Write-Log function
$script:colors = @{
    Info = "Cyan"
    Success = "Green"
    Warning = "Yellow"
    Error = "Red"
    Header = "Magenta"
    Accent = "DarkCyan"
    Highlight = "White"
}

# File paths
$system32Path = "$env:SystemRoot\System32"
$termsrvPath = "$system32Path\termsrv.dll"
$termsrvPatched = "$system32Path\termsrv.dll.patched"  # Used in backup/restore operations
$termsrvBackupDir = "$env:SystemRoot\System32\termsrv_backup"
$logFile = "$env:TEMP\RDP-MultiSession-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$persistenceTaskName = "RDP-MultiSession-Persistence"
$persistenceScriptPath = "$env:SystemRoot\Temp\RDP-Persistence.ps1"
#endregion

#region Pattern Definitions
$patterns = @{
    # Windows 10/11 General Pattern (pre-24H2)
    General = @{
        Search = [regex]'39 81 3C 06 00 00 0F (?:[0-9A-F]{2} ){4}00'
        Replace = 'B8 00 01 00 00 89 81 38 06 00 00 90'
        Validation = @(
            @{ Offset = 0; Expected = 'B8' }
            @{ Offset = 1; Expected = '00' }
            @{ Offset = 2; Expected = '01' }
        )
        Description = "Windows 10/11 (pre-24H2)"
        BuildRange = @{ Min = 19041; Max = 22631 }
    }
    # Windows 11 24H2 Pattern
    Win11_24H2 = @{
        Search = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
        Replace = 'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
        Validation = @(
            @{ Offset = 0; Expected = 'B8' }
            @{ Offset = 1; Expected = '00' }
            @{ Offset = 2; Expected = '01' }
            @{ Offset = 12; Expected = 'EB' }
        )
        Description = "Windows 11 24H2"
        BuildRange = @{ Min = 26100; Max = 26100 }
    }
    # Windows 11 25H2 Pattern (Builds 26120-26299)
    Win11_25H2 = @{
        Search = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
        Replace = 'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
        Validation = @(
            @{ Offset = 0; Expected = 'B8' }
            @{ Offset = 1; Expected = '00' }
            @{ Offset = 2; Expected = '01' }
            @{ Offset = 12; Expected = 'EB' }
        )
        Description = "Windows 11 25H2"
        BuildRange = @{ Min = 26120; Max = 26299 }
    }
    # Windows 11 Future (26xxx+)
    Win11_Future = @{
        Search = [regex]'8B 81 38 06 00 00 39 81 3C 06 00 00 75'
        Replace = 'B8 00 01 00 00 89 81 38 06 00 00 90 EB'
        Validation = @(
            @{ Offset = 0; Expected = 'B8' }
            @{ Offset = 1; Expected = '00' }
            @{ Offset = 2; Expected = '01' }
            @{ Offset = 12; Expected = 'EB' }
        )
        Description = "Windows 11 Future Builds"
        BuildRange = @{ Min = 26300; Max = [int]::MaxValue }
        Warning = "Experimental support - Please report if this works!"
    }
    # Windows 7 Patterns
    Win7_64 = @{
        Search = [regex]'8B 87 38 06 00 00 39 87 3C 06 00 00 0F 84 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} 00'
        Replace = 'B8 00 01 00 00 90 89 87 38 06 00 00 90 90 90 90 90 90'
        Additional = @(
            @{ Search = '4C 24 60 BB 01 00 00 00'; Replace = '4C 24 60 BB 00 00 00 00' }
            @{ Search = '83 7C 24 50 00 74 18 48 8D'; Replace = '83 7C 24 50 00 EB 18 48 8D' }
        )
        Description = "Windows 7 SP1 (64-bit)"
        BuildRange = @{ Min = 7601; Max = 7601 }
    }
}
#endregion

#region Known DLL Compatibility Identities

$knownDllIdentities = @(
    @{
        Version = "10.0.26100.8115"
        SHA256 = "22BA956A6AE345D0909825B5C1D5BF94E90241A9BBC9D92118E31EF33D7FBED9"
        Status = "Unverified"
        Notes = "Windows 11 25H2 host build 26200.8894; existing Win11_25H2 candidate search signature was not present."
    }
)

#endregion

#region Visualization Functions

function Show-Header {
    Clear-Host
    Write-Host ""
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host "                          RDP MULTI-SESSION ENABLER v$($scriptInfo.version)" -ForegroundColor White
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host "  Enable multiple concurrent RDP sessions on any Windows edition" -ForegroundColor White
    Write-Host "  Safely patch termsrv.dll with automatic backup and restore" -ForegroundColor White
    Write-Host "  Includes persistence mechanisms to survive reboots" -ForegroundColor White
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host "  Author: $($scriptInfo.author)" -ForegroundColor Cyan
    Write-Host "  Repository: $($scriptInfo.url)" -ForegroundColor Cyan
    Write-Host "  ================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Title {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor DarkGray
    Write-Host " $Text" -ForegroundColor White
    Write-Host ("=" * 80) -ForegroundColor DarkGray
}

function Write-Success {
    param([string]$Text)
    Write-Host "  [OK] $Text" -ForegroundColor Green
}

function Write-Error {
    param([string]$Text)
    Write-Host "  [FAIL] $Text" -ForegroundColor Red
}

function Write-Warning {
    param([string]$Text)
    Write-Host "  [WARN] $Text" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Text)
    Write-Host "  [INFO] $Text" -ForegroundColor Cyan
}

function Write-ProgressBar {
    param(
        [string]$Activity,
        [int]$PercentComplete
    )
    
    $barLength = 50
    $filled = [math]::Floor($barLength * $PercentComplete / 100)
    $empty = $barLength - $filled
    
    $progressBar = "[" + ("#" * $filled) + ("." * $empty) + "]"
    
    Write-Host "  $Activity" -ForegroundColor Cyan
    Write-Host "  $progressBar $PercentComplete%" -ForegroundColor White
}

function Write-Table {
    param(
        [array]$Data,
        [string[]]$Properties,
        [string[]]$Headers
    )
    
    # Calculate column widths
    $colWidths = @()
    for ($i = 0; $i -lt $Properties.Count; $i++) {
        $maxLength = $Headers[$i].Length
        foreach ($item in $Data) {
            $value = $item."$($Properties[$i])"
            if ($value -and $value.Length -gt $maxLength) {
                $maxLength = [math]::Min($value.Length, 40)
            }
        }
        $colWidths += $maxLength + 2
    }
    
    # Create separator line
    $separator = "+"
    foreach ($width in $colWidths) {
        $separator += "-" * $width + "+"
    }
    
    # Create header row
    $headerRow = "|"
    for ($i = 0; $i -lt $Properties.Count; $i++) {
        $headerRow += " $($Headers[$i])".PadRight($colWidths[$i]) + "|"
    }
    
    # Create data rows
    $dataRows = @()
    foreach ($item in $Data) {
        $row = "|"
        for ($i = 0; $i -lt $Properties.Count; $i++) {
            $value = $item."$($Properties[$i])"
            if (-not $value) { $value = "" }
            $row += " $value".PadRight($colWidths[$i]) + "|"
        }
        $dataRows += $row
    }
    
    # Display the table
    Write-Host "  $separator" -ForegroundColor DarkGray
    Write-Host "  $headerRow" -ForegroundColor Yellow
    Write-Host "  $separator" -ForegroundColor DarkGray
    foreach ($row in $dataRows) {
        Write-Host "  $row" -ForegroundColor White
    }
    Write-Host "  $separator" -ForegroundColor DarkGray
}

#endregion

#region Core Functions

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Success $Message }
        "INFO" { Write-Info $Message }
        default { Write-Host "  $Message" }
    }
    
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    } catch {}
}

function Start-TranscriptLogging {
    try {
        Start-Transcript -Path $logFile -Append -ErrorAction SilentlyContinue
        Write-Info "Logging to: $logFile"
    } catch {}
}

function Stop-TranscriptLogging {
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}
}

function Test-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-SelfElevation {
    if (-not (Test-Administrator)) {
        Write-Warning "Requesting administrator privileges..."
        
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
        foreach ($key in $PSBoundParameters.Keys) {
            $arguments += " -$key"
            if ($PSBoundParameters[$key] -is [switch]) {
                # Switches don't need values
            } elseif ($PSBoundParameters[$key]) {
                $arguments += " `"$($PSBoundParameters[$key])`""
            }
        }
        
        try {
            Start-Process PowerShell.exe -Verb RunAs -ArgumentList $arguments
            exit 0
        } catch {
            Write-Error "Failed to elevate privileges. Please run as administrator manually."
            exit 1
        }
    }
}

function Get-OSInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    
    [PSCustomObject]@{
        Caption = $os.Caption
        Version = [version]$os.Version
        BuildNumber = [int]$os.BuildNumber
        UBR = $reg.UBR
        FullBuild = "$($os.BuildNumber).$($reg.UBR)"
        DisplayVersion = $reg.DisplayVersion
        DisplayVersionFull = if ($reg.DisplayVersion) { $reg.DisplayVersion } else { "Unknown" }
        EditionID = $reg.EditionID
        InstallationType = $reg.InstallationType
        Architecture = $os.OSArchitecture
        ProductType = $os.ProductType
        IsServer = ($cs.DomainRole -ge 4 -or $os.ProductType -ne 1)
        Is64Bit = $os.OSArchitecture -eq "64-bit"
        ReleaseId = $reg.ReleaseId
        CurrentBuild = $reg.CurrentBuild
    }
}

function Get-OSFriendlyName {
    $osInfo = Get-OSInfo
    
    if ($osInfo.IsServer) {
        switch ($osInfo.BuildNumber) {
            20348 { return "Windows Server 2022" }
            26100 { return "Windows Server 2025" }
            default { return "Windows Server" }
        }
    } else {
        # Windows 11 detection
        if ($osInfo.BuildNumber -ge 26120 -and $osInfo.BuildNumber -le 26299) {
            return "Windows 11 25H2"
        }
        elseif ($osInfo.BuildNumber -eq 26100) {
            return "Windows 11 24H2"
        }
        elseif ($osInfo.BuildNumber -ge 22621 -and $osInfo.BuildNumber -le 22631) {
            return "Windows 11 22H2/23H2"
        }
        elseif ($osInfo.BuildNumber -ge 22000 -and $osInfo.BuildNumber -lt 22621) {
            return "Windows 11 21H2"
        }
        # Windows 10 detection
        elseif ($osInfo.BuildNumber -ge 19041 -and $osInfo.BuildNumber -lt 22000) {
            return "Windows 10"
        }
        # Windows 7 detection
        elseif ($osInfo.BuildNumber -eq 7601) {
            return "Windows 7 SP1"
        }
        else {
            return "Unknown Windows Version"
        }
    }
}

function Get-ApplicablePattern {
    param(
        [switch]$Silent
    )
    
    $osInfo = Get-OSInfo
    $osName = Get-OSFriendlyName
    
    if (-not $Silent) {
        Write-Title "SYSTEM DETECTION"
        
        Write-Info "OS: $osName"
        Write-Info "Build: $($osInfo.FullBuild)"
        Write-Info "Architecture: $($osInfo.Architecture)"
        Write-Info "Edition: $($osInfo.EditionID)"
    }
    
    if ($osInfo.IsServer) {
        if (-not $Silent) {
            Write-Warning "Server edition detected - RDP multi-session is natively supported"
            Write-Warning "This script is intended for client editions only"
        }
        return $null
    }
    
    if (-not $osInfo.Is64Bit) {
        if (-not $Silent) {
            Write-Error "32-bit system detected - This script only supports 64-bit"
        }
        return $null
    }
    
    # Find matching pattern based on build number
    $matchingPattern = $null
    $patternName = $null
    
    foreach ($key in $patterns.Keys) {
        $pattern = $patterns[$key]
        if ($osInfo.BuildNumber -ge $pattern.BuildRange.Min -and $osInfo.BuildNumber -le $pattern.BuildRange.Max) {
            $matchingPattern = $pattern
            $patternName = $key
            break
        }
    }
    
    if ($matchingPattern) {
        if (-not $Silent) {
            Write-Info "Candidate pattern selected from OS build: $($matchingPattern.Description)"
            
            if ($matchingPattern.Warning) {
                Write-Warning $matchingPattern.Warning
            }
            
            if ($patternName -eq "Win11_25H2") {
                Write-Info "Windows 11 25H2 detected - using appropriate pattern"
                Write-Info "Build $($osInfo.BuildNumber) is a 25H2 build"
            }
            
            if ($patternName -eq "Win11_Future") {
                Write-Warning "Experimental pattern for future Windows builds"
                Write-Info "Please report if this works at: $($scriptInfo.url)"
            }
        }
        
        return $matchingPattern
    }
    
    if (-not $Silent) {
        Write-Error "No pattern available for this Windows version (Build $($osInfo.BuildNumber))"
        Write-Info "If this is a new Windows build, please report it at: $($scriptInfo.url)"
    }
    return $null
}

function Test-FileAccess {
    param([string]$Path)
    
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'None')
        $stream.Close()
        return $true
    } catch {
        return $false
    }
}

function Disable-WindowsFileProtection {
    Write-Title "DISABLING WINDOWS FILE PROTECTION"
    
    try {
        # Stop Windows Module Installer service
        $trustedInstaller = Get-Service -Name "TrustedInstaller" -ErrorAction SilentlyContinue
        if ($trustedInstaller -and $trustedInstaller.Status -eq "Running") {
            Write-Info "Stopping TrustedInstaller service..."
            Stop-Service -Name "TrustedInstaller" -Force -ErrorAction SilentlyContinue
            Write-Success "TrustedInstaller service stopped"
        }
        
        # Disable Windows File Protection via registry
        $sfcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try {
            $sfcValue = Get-ItemProperty -Path $sfcRegPath -Name "SFCDisable" -ErrorAction SilentlyContinue
            if (-not $sfcValue -or $sfcValue.SFCDisable -ne 1) {
                Write-Info "Disabling Windows File Protection via registry..."
                Set-ItemProperty -Path $sfcRegPath -Name "SFCDisable" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Success "Windows File Protection disabled in registry"
            }
        } catch {
            Write-Warning "Could not modify SFC registry setting: $_"
        }
        
        # Take ownership of important system files that might interfere
        $protectedFiles = @(
            "$env:SystemRoot\System32\catroot",
            "$env:SystemRoot\System32\catroot2",
            "$env:SystemRoot\System32\drivers\etc"
        )
        
        foreach ($file in $protectedFiles) {
            if (Test-Path $file) {
                & takeown.exe /F $file /R /D Y 2>&1 | Out-Null
                & icacls.exe $file /grant "Administrators:F" /T /Q 2>&1 | Out-Null
            }
        }
        
        # Disable Windows Update automatic driver updates
        $wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $wuRegPath)) {
            New-Item -Path $wuRegPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-ItemProperty -Path $wuRegPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $wuRegPath -Name "AUOptions" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
        
        Write-Success "Windows Update automatic updates disabled"
        
    } catch {
        Write-Warning "Failed to disable some protection mechanisms: $_"
    }
}

function Enable-WindowsFileProtection {
    Write-Title "RESTORING WINDOWS FILE PROTECTION"
    
    try {
        # Re-enable Windows File Protection via registry
        $sfcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        try {
            Remove-ItemProperty -Path $sfcRegPath -Name "SFCDisable" -ErrorAction SilentlyContinue
            Write-Success "Windows File Protection re-enabled in registry"
        } catch {
            Write-Warning "Could not restore SFC registry setting: $_"
        }
        
        # Re-enable Windows Update
        $wuRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Remove-ItemProperty -Path $wuRegPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $wuRegPath -Name "AUOptions" -ErrorAction SilentlyContinue
        
        Write-Success "Windows Update settings restored"
        
    } catch {
        Write-Warning "Failed to restore some protection mechanisms: $_"
    }
}

function Add-PersistenceMechanism {
    Write-Title "ADDING PERSISTENCE MECHANISMS"
    
    try {
        # Create backup directory for multiple copies
        if (-not (Test-Path $termsrvBackupDir)) {
            New-Item -Path $termsrvBackupDir -ItemType Directory -Force | Out-Null
            Write-Info "Created backup directory: $termsrvBackupDir"
        }
        
        # Create multiple backup copies in different locations
        $backupLocations = @(
            "$termsrvBackupDir\termsrv.dll.backup1",
            "$termsrvBackupDir\termsrv.dll.backup2",
            "$env:SystemRoot\System32\drivers\termsrv.dll.backup",
            "$env:ProgramData\termsrv.dll.backup"
        )
        
        foreach ($location in $backupLocations) {
            Copy-Item -Path $termsrvPath -Destination $location -Force -ErrorAction SilentlyContinue
            Write-Info "Created backup at: $location"
        }
        
        # Create persistence script
        $persistenceScript = @"
# RDP Multi-Session Persistence Script
# This script ensures the patched termsrv.dll survives reboots

`$termsrvPath = "$env:SystemRoot\System32\termsrv.dll"
`$backupLocations = @(
    "$termsrvBackupDir\termsrv.dll.backup1",
    "$termsrvBackupDir\termsrv.dll.backup2",
    "$env:SystemRoot\System32\drivers\termsrv.dll.backup",
    "$env:ProgramData\termsrv.dll.backup"
)

# Check if current termsrv.dll is patched
`$currentHash = Get-FileHash -Path `$termsrvPath -Algorithm SHA256
`$patchedHash = Get-FileHash -Path `$backupLocations[0] -Algorithm SHA256

if (`$currentHash.Hash -ne `$patchedHash.Hash) {
    Write-Host "RDP Multi-Session: Detected termsrv.dll change, restoring patch..."
    
    # Stop TermService
    Stop-Service -Name TermService -Force -ErrorAction SilentlyContinue
    
    # Try to restore from backups
    foreach (`$backup in `$backupLocations) {
        if (Test-Path `$backup) {
            try {
                # Take ownership
                & takeown.exe /F `$termsrvPath 2>&1 | Out-Null
                & icacls.exe `$termsrvPath /grant "Administrators:F" /Q 2>&1 | Out-Null
                
                # Copy backup
                Copy-Item -Path `$backup -Destination `$termsrvPath -Force -ErrorAction Stop
                Write-Host "Restored from backup: `$backup"
                break
            } catch {
                Write-Host "Failed to restore from `$backup"
            }
        }
    }
    
    # Start TermService
    Start-Service -Name TermService -ErrorAction SilentlyContinue
}
"@
        
        $persistenceScript | Out-File -FilePath $persistenceScriptPath -Encoding utf8 -Force
        Write-Success "Persistence script created at: $persistenceScriptPath"
        
        # Create scheduled task to run at startup and every hour
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$persistenceScriptPath`""
        $taskTrigger = @(
            (New-ScheduledTaskTrigger -AtStartup),
            (New-ScheduledTaskTrigger -Daily -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 365))
        )
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable $false
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Remove existing task if it exists
        Unregister-ScheduledTask -TaskName $persistenceTaskName -Confirm:$false -ErrorAction SilentlyContinue
        
        # Register new task
        Register-ScheduledTask -TaskName $persistenceTaskName `
            -Action $taskAction `
            -Trigger $taskTrigger `
            -Settings $taskSettings `
            -Principal $taskPrincipal `
            -Description "RDP Multi-Session Persistence - Ensures patched termsrv.dll survives reboots" `
            -Force
        
        Write-Success "Scheduled task created: $persistenceTaskName"
        
        # Add startup script to multiple locations for redundancy
        $startupLocations = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RDP-Persistence.ps1",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\RDP-Persistence.ps1"
        )
        
        foreach ($location in $startupLocations) {
            Copy-Item -Path $persistenceScriptPath -Destination $location -Force -ErrorAction SilentlyContinue
        }
        
        # Create a simple batch file for additional redundancy
        $batchContent = "@echo off`r`nPowerShell.exe -NoProfile -ExecutionPolicy Bypass -File `"$persistenceScriptPath`"`r`n"
        $batchContent | Out-File -FilePath "$env:SystemRoot\Temp\RDP-Persistence.cmd" -Encoding ascii -Force
        
        # Add to run registry key
        $runRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $runRegPath -Name "RDP-MultiSession-Persistence" -Value "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File `"$persistenceScriptPath`"" -Force
        
        Write-Success "Added to registry Run key"
        
        # Disable Windows Defender real-time monitoring for termsrv.dll
        try {
            Add-MpPreference -ExclusionPath $termsrvPath -ErrorAction SilentlyContinue
            Add-MpPreference -ExclusionPath $termsrvBackupDir -ErrorAction SilentlyContinue
            Write-Success "Added Windows Defender exclusions"
        } catch {
            Write-Warning "Could not add Windows Defender exclusions"
        }
        
        Write-Success "Persistence mechanisms added successfully!"
        
    } catch {
        Write-Error "Failed to add persistence mechanisms: $_"
    }
}

function Remove-PersistenceMechanism {
    Write-Title "REMOVING PERSISTENCE MECHANISMS"
    
    try {
        # Remove scheduled task
        Unregister-ScheduledTask -TaskName $persistenceTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Success "Scheduled task removed"
        
        # Remove from registry
        $runRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Remove-ItemProperty -Path $runRegPath -Name "RDP-MultiSession-Persistence" -ErrorAction SilentlyContinue
        Write-Success "Registry entry removed"
        
        # Remove startup scripts
        $startupLocations = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\RDP-Persistence.ps1",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\RDP-Persistence.ps1",
            "$env:SystemRoot\Temp\RDP-Persistence.ps1",
            "$env:SystemRoot\Temp\RDP-Persistence.cmd"
        )
        
        foreach ($location in $startupLocations) {
            if (Test-Path $location) {
                Remove-Item -Path $location -Force -ErrorAction SilentlyContinue
            }
        }
        
        Write-Success "Startup scripts removed"
        
        # Remove Windows Defender exclusions
        try {
            Remove-MpPreference -ExclusionPath $termsrvPath -ErrorAction SilentlyContinue
            Remove-MpPreference -ExclusionPath $termsrvBackupDir -ErrorAction SilentlyContinue
        } catch {}
        
    } catch {
        Write-Warning "Failed to remove some persistence mechanisms: $_"
    }
}

function Stop-TermServiceWithTimeout {
    Write-Title "SERVICE CONTROL"
    Write-Info "Stopping Remote Desktop Services..."
    
    try {
        $service = Get-Service -Name TermService -ErrorAction Stop
        if ($service.Status -eq "Stopped") {
            Write-Success "Service already stopped"
            return $true
        }
        
        Stop-Service -Name TermService -Force -ErrorAction Stop
        
        $timeout = 30
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            Start-Sleep -Seconds 1
            $elapsed++
            $service.Refresh()
            Write-ProgressBar -Activity "Waiting for service to stop" -PercentComplete (($elapsed / $timeout) * 100)
            if ($service.Status -eq "Stopped") {
                Write-Success "Service stopped successfully"
                return $true
            }
        }
        
        Write-Error "Timeout waiting for service to stop"
        return $false
    } catch {
        Write-Error "Failed to stop service: $_"
        return $false
    }
}

function Start-TermServiceWithTimeout {
    Write-Info "Starting Remote Desktop Services..."
    
    try {
        $service = Get-Service -Name TermService -ErrorAction Stop
        
        Start-Service -Name TermService -ErrorAction Stop
        
        $timeout = 30
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            Start-Sleep -Seconds 1
            $elapsed++
            $service.Refresh()
            Write-ProgressBar -Activity "Waiting for service to start" -PercentComplete (($elapsed / $timeout) * 100)
            if ($service.Status -eq "Running") {
                Write-Success "Service started successfully"
                return $true
            }
        }
        
        Write-Error "Timeout waiting for service to start"
        return $false
    } catch {
        Write-Error "Failed to start service: $_"
        return $false
    }
}

function Set-FilePermissions {
    param(
        [string]$Path,
        [switch]$TakeOwnership,
        [System.Security.AccessControl.FileSecurity]$OriginalAcl
    )
    
    try {
        if ($TakeOwnership) {
            Write-Info "Taking ownership of file..."
            
            $takeownResult = & takeown.exe /F $Path 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Error "takeown failed: $takeownResult"
                return $false
            }
            
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $icaclsResult = & icacls.exe $Path /grant "${currentUser}:F" /Q 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Error "icacls failed: $icaclsResult"
                return $false
            }
            
            & icacls.exe $Path /grant "SYSTEM:F" /Q 2>&1 | Out-Null
            & icacls.exe $Path /grant "Administrators:F" /Q 2>&1 | Out-Null
            & icacls.exe $Path /grant "Everyone:R" /Q 2>&1 | Out-Null
            
            Write-Success "Ownership and permissions updated"
            return $true
        }
        
        if ($OriginalAcl) {
            Write-Info "Restoring original permissions..."
            try {
                Set-Acl -Path $Path -AclObject $OriginalAcl -ErrorAction Stop
                Write-Success "Permissions restored"
                return $true
            } catch {
                Write-Warning "Failed to restore permissions: $_"
                return $false
            }
        }
        
        return $true
    } catch {
        Write-Error "Permission operation failed: $_"
        return $false
    }
}

function Backup-TermServiceDll {
    param([string]$BackupPath)
    
    Write-Title "BACKUP OPERATION"
    Write-Info "Creating backup of termsrv.dll..."
    
    try {
        if (Test-Path $BackupPath) {
            $backupInfo = Get-Item $BackupPath
            Write-Warning "Backup already exists at: $BackupPath"
            Write-Info "Created: $($backupInfo.CreationTime)"
            
            if (-not $Force) {
                $response = Read-Host "  Overwrite existing backup? (y/N)"
                if ($response -notmatch '^[Yy]') {
                    Write-Warning "Backup cancelled"
                    return $false
                }
            }
        }
        
        Copy-Item -Path $termsrvPath -Destination $BackupPath -Force -ErrorAction Stop
        Write-Success "Backup created successfully at: $BackupPath"
        
        Write-Info "Verifying backup integrity..."
        $originalHash = Get-FileHash $termsrvPath -Algorithm SHA256
        $backupHash = Get-FileHash $BackupPath -Algorithm SHA256
        if ($originalHash.Hash -eq $backupHash.Hash) {
            Write-Success "Backup verified (hash match)"
            return $true
        } else {
            Write-Error "Backup verification failed - hash mismatch"
            return $false
        }
    } catch {
        Write-Error "Failed to create backup: $_"
        return $false
    }
}

function Find-PatternInDll {
    param(
        [byte[]]$FileBytes,
        [string]$SearchPattern
    )
    
    $patternBytes = $SearchPattern -split ' ' | ForEach-Object { [Convert]::ToByte($_, 16) }
    
    for ($i = 0; $i -le $FileBytes.Length - $patternBytes.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $patternBytes.Length; $j++) {
            if ($FileBytes[$i + $j] -ne $patternBytes[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $i
        }
    }
    return -1
}

function Find-PatternWithRegex {
    param(
        [string]$DllAsText,
        [regex]$Pattern
    )
    
    $match = $Pattern.Match($DllAsText)
    if ($match.Success) {
        return $match.Value, $match.Index
    }
    return $null, -1
}

function Test-IsPatched {
    param(
        [string]$DllPath,
        $Pattern
    )
    
    $bytes = [System.IO.File]::ReadAllBytes($DllPath)
    $replacementOffset = Find-PatternInDll -FileBytes $bytes -SearchPattern $Pattern.Replace
    return ($null -ne $replacementOffset -and $replacementOffset -ne -1)
}

function Test-PatchValidity {
    param(
        [string]$DllPath,
        $Pattern
    )
    
    $bytes = [System.IO.File]::ReadAllBytes($DllPath)
    $replacementOffset = Find-PatternInDll -FileBytes $bytes -SearchPattern $Pattern.Replace
    
    if ($null -eq $replacementOffset -or $replacementOffset -eq -1) {
        return $false
    }
    
    $allValid = $true
    foreach ($byteCheck in $Pattern.Validation) {
        $actualByte = $bytes[$replacementOffset + $byteCheck.Offset].ToString("X2")
        if ($actualByte -ne $byteCheck.Expected) {
            Write-Warning "Validation failed at offset +$($byteCheck.Offset): Expected $($byteCheck.Expected), got $actualByte"
            $allValid = $false
        }
    }
    
    return $allValid
}

function Test-TermsrvPatchPreflight {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DllPath,

        [Parameter(Mandatory = $true)]
        $Pattern
    )

    Write-Title "TERMSRV.DLL SAFETY PREFLIGHT"

    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
        Write-Error "termsrv.dll was not found at: $DllPath"
        return $false
    }

    try {
        # ---------------------------------------------------------------------
        # Establish the exact file identity before doing anything invasive.
        # ---------------------------------------------------------------------
        $dllItem = Get-Item -LiteralPath $DllPath -ErrorAction Stop

        $versionSource = $dllItem.VersionInfo.ProductVersion
        if ([string]::IsNullOrWhiteSpace($versionSource)) {
            $versionSource = $dllItem.VersionInfo.FileVersion
        }

        $versionMatch = [regex]::Match(
            [string]$versionSource,
            '\d+\.\d+\.\d+\.\d+'
        )

        if (-not $versionMatch.Success) {
            Write-Error "Could not determine a four-part termsrv.dll version."
            return $false
        }

        $dllVersion = $versionMatch.Value

        $initialHash = (
            Get-FileHash -LiteralPath $DllPath -Algorithm SHA256 -ErrorAction Stop
        ).Hash.ToUpperInvariant()

        if ($initialHash -notmatch '^[0-9A-F]{64}$') {
            Write-Error "termsrv.dll SHA256 value is invalid."
            return $false
        }

        Write-Info "termsrv.dll version: $dllVersion"
        Write-Info "termsrv.dll SHA256:  $initialHash"

        $knownIdentity = $knownDllIdentities |
            Where-Object {
                $_.Version -eq $dllVersion -and
                $_.SHA256 -eq $initialHash
            } |
            Select-Object -First 1

        if ($null -ne $knownIdentity) {
            Write-Warning "Known DLL identity detected"
            Write-Info "Compatibility status: $($knownIdentity.Status)"
            Write-Info "Identity notes: $($knownIdentity.Notes)"
        } else {
            Write-Info "DLL identity is not currently listed in the repository compatibility identity table."
        }

        # ---------------------------------------------------------------------
        # Require an intact Microsoft-signed binary.
        # ---------------------------------------------------------------------
        $auth = Get-AuthenticodeSignature -LiteralPath $DllPath -ErrorAction Stop

        if ($auth.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
            Write-Error "Authenticode validation failed: $($auth.Status)"
            return $false
        }

        if ($null -eq $auth.SignerCertificate) {
            Write-Error "No signing certificate was returned for termsrv.dll."
            return $false
        }

        $signerSubject = [string]$auth.SignerCertificate.Subject
        Write-Info "Signer: $signerSubject"

        if ($signerSubject -notmatch '(?i)Microsoft') {
            Write-Error "termsrv.dll is validly signed, but not by Microsoft."
            return $false
        }

        Write-Success "Microsoft Authenticode signature is valid"

        # ---------------------------------------------------------------------
        # Check the EXISTING selected pattern before TermService is stopped,
        # ACLs are changed, or Windows protection/update settings are touched.
        #
        # No replacement/bypass patterns are introduced here.
        # ---------------------------------------------------------------------
        $dllBytes = [System.IO.File]::ReadAllBytes($DllPath)
        $dllAsText = ($dllBytes | ForEach-Object {
            $_.ToString('X2')
        }) -join ' '

        $matchCount = 0

        if ($Pattern.Search -is [regex]) {
            $matches = $Pattern.Search.Matches($dllAsText)
            $matchCount = $matches.Count
        }
        else {
            $literalPattern = [regex]::Escape([string]$Pattern.Search)
            $matches = [regex]::Matches($dllAsText, $literalPattern)
            $matchCount = $matches.Count
        }

        Write-Info "Selected signature matches: $matchCount"

        if ($matchCount -eq 0) {
            $osInfo = Get-OSInfo

            Write-Title "COMPATIBILITY DIAGNOSTICS"

            Write-Info "OS build:          $($osInfo.FullBuild)"
            Write-Info "OS display version: $($osInfo.DisplayVersionFull)"
            Write-Info "DLL version:       $dllVersion"
            Write-Info "DLL SHA256:        $initialHash"
            Write-Info "Candidate pattern: $($Pattern.Description)"
            Write-Info "Candidate range:   $($Pattern.BuildRange.Min)-$($Pattern.BuildRange.Max)"
            Write-Info "Signature matches: $matchCount"

            Write-Warning "Diagnosis: the OS build selected this candidate pattern, but the installed termsrv.dll does not contain its expected search signature."
            Write-Warning "The current repository compatibility rule is therefore too broad for this DLL revision."

            if ($null -ne $knownIdentity) {
                Write-Warning "This exact DLL version/hash is already recorded as: $($knownIdentity.Status)"
                Write-Info "Recorded notes: $($knownIdentity.Notes)"
            } else {
                Write-Warning "This DLL identity has not previously been classified by this repository."
            }

            Write-Warning "No compatible binary-level signature has been verified for this DLL identity."

            Write-Error "Compatibility has NOT been verified for this DLL revision."
            Write-Error "No services, ACLs, or Windows protection/update settings were changed."

            return $false
        }

        if ($matchCount -ne 1) {
            Write-Error "Selected patch signature is ambiguous ($matchCount matches)."
            Write-Error "Refusing to continue."
            return $false
        }

        Write-Success "Selected patch signature exists exactly once"

        # ---------------------------------------------------------------------
        # Re-hash after inspection to ensure the file did not change during
        # preflight.
        # ---------------------------------------------------------------------
        $finalHash = (
            Get-FileHash -LiteralPath $DllPath -Algorithm SHA256 -ErrorAction Stop
        ).Hash.ToUpperInvariant()

        if ($finalHash -ne $initialHash) {
            Write-Error "termsrv.dll changed while preflight validation was running."
            Write-Error "Initial SHA256: $initialHash"
            Write-Error "Final SHA256:   $finalHash"
            return $false
        }

        Write-Success "termsrv.dll identity remained stable during preflight"
        Write-Success "Safety preflight passed"

        return $true
    }
    catch {
        Write-Error "termsrv.dll safety preflight failed: $_"
        return $false
    }
}
function Invoke-PatchApplication {
    param(
        $Pattern,
        [string]$BackupPath
    )
    
    Write-Title "PATCHING PROCESS"
    
    if (-not (Test-Path $termsrvPath)) {
        Write-Error "termsrv.dll not found!"
        return $false
    }
    
    if ((Test-IsPatched -DllPath $termsrvPath -Pattern $Pattern) -and -not $Force) {
        Write-Warning "System appears to be already patched!"
        $response = Read-Host "  Do you want to re-patch anyway? (y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-Info "Patching cancelled"
            return $false
        }
    }
    
    # Fail closed before stopping services, changing ACLs, or modifying
    # Windows protection/update settings.
    if (-not (Test-TermsrvPatchPreflight -DllPath $termsrvPath -Pattern $Pattern)) {
        Write-Error "Safety preflight failed. No invasive changes have been made."
        return $false
    }

    # Disable Windows File Protection
    Disable-WindowsFileProtection
    
    # Stop service
    if (-not (Stop-TermServiceWithTimeout)) {
        Write-Error "Failed to stop TermService. Cannot proceed."
        Enable-WindowsFileProtection
        return $false
    }
    
    $originalAcl = Get-Acl -Path $termsrvPath -ErrorAction SilentlyContinue
    
    if (-not (Set-FilePermissions -Path $termsrvPath -TakeOwnership)) {
        Write-Error "Failed to gain necessary permissions. Aborting."
        Start-TermServiceWithTimeout
        Enable-WindowsFileProtection
        return $false
    }
    
    try {
        # Create backup
        if (-not (Backup-TermServiceDll -BackupPath $BackupPath)) {
            Write-Error "Backup failed. Aborting patch."
            Set-FilePermissions -Path $termsrvPath -OriginalAcl $originalAcl
            Start-TermServiceWithTimeout
            Enable-WindowsFileProtection
            return $false
        }
        
        # Read DLL
        Write-Info "Reading termsrv.dll..."
        $dllBytes = [System.IO.File]::ReadAllBytes($termsrvPath)
        $originalHash = Get-FileHash $termsrvPath -Algorithm SHA256
        Write-Info "Original hash: $($originalHash.Hash)"
        
        $dllAsText = ($dllBytes | ForEach-Object { $_.ToString('X2') }) -join ' '
        
        Write-Info "Searching for patch pattern..."
        
        if ($Pattern.Search -is [regex]) {
            $matchValue, $matchIndex = Find-PatternWithRegex -DllAsText $dllAsText -Pattern $Pattern.Search
            if ($matchValue) {
                Write-Success "Pattern found with regex at index $matchIndex"
                $dllAsTextReplaced = $dllAsText -replace $Pattern.Search, $Pattern.Replace
            } else {
                Write-Error "Pattern not found!"
                throw "Pattern not found"
            }
        } else {
            $patternOffset = Find-PatternInDll -FileBytes $dllBytes -SearchPattern $Pattern.Search
            if ($null -eq $patternOffset -or $patternOffset -eq -1) {
                Write-Error "Pattern not found!"
                throw "Pattern not found"
            }
            Write-Success "Pattern found at offset: 0x$($patternOffset.ToString('X'))"
            
            $replacementBytes = $Pattern.Replace -split ' ' | ForEach-Object { [Convert]::ToByte($_, 16) }
            for ($i = 0; $i -lt $replacementBytes.Length; $i++) {
                $dllBytes[$patternOffset + $i] = $replacementBytes[$i]
            }
        }
        
        if ($Pattern.Additional) {
            foreach ($addPattern in $Pattern.Additional) {
                $dllAsText = ($dllBytes | ForEach-Object { $_.ToString('X2') }) -join ' '
                $dllAsText = $dllAsText -replace $addPattern.Search, $addPattern.Replace
                $dllBytes = -split $dllAsText | ForEach-Object { [Convert]::ToByte($_, 16) }
            }
        } elseif ($dllAsTextReplaced) {
            $dllBytes = -split $dllAsTextReplaced | ForEach-Object { [Convert]::ToByte($_, 16) }
        }
        
        Write-Info "Writing patched file..."
        [System.IO.File]::WriteAllBytes($termsrvPath, $dllBytes)
        
        $patchedHash = Get-FileHash $termsrvPath -Algorithm SHA256
        Write-Info "Patched hash: $($patchedHash.Hash)"
        
        if ($originalHash.Hash -eq $patchedHash.Hash) {
            Write-Warning "Hash unchanged - patch may not have been applied!"
        }
        
        Write-Info "Validating patch..."
        if (Test-PatchValidity -DllPath $termsrvPath -Pattern $Pattern) {
            Write-Success "Byte-level validation passed"
        } else {
            Write-Error "Byte-level validation failed"
            throw "Validation failed"
        }
        
        Write-Info "Comparing with backup..."
        if (Test-BinaryEquality -File1 $termsrvPath -File2 $BackupPath) {
            Write-Error "Patched file is identical to backup!"
            throw "Patch not applied"
        } else {
            Write-Success "Files are different - patch applied"
        }
        
        # Add persistence mechanisms if requested
        if ($Persist -and -not $NoPersistence) {
            Add-PersistenceMechanism
        }
        
        Set-FilePermissions -Path $termsrvPath -OriginalAcl $originalAcl
        
        # Re-enable Windows File Protection
        Enable-WindowsFileProtection
        
        if (-not (Start-TermServiceWithTimeout)) {
            Write-Error "Service failed to start after patching!"
            Write-Warning "Attempting automatic restore from backup..."
            
            if (Test-Path $BackupPath) {
                Copy-Item -Path $BackupPath -Destination $termsrvPath -Force
                Start-TermServiceWithTimeout
            }
            return $false
        }
        
        Write-Title "PATCH COMPLETED"
        Write-Success "Multi-session RDP has been enabled successfully!"
        
        if ($Persist -and -not $NoPersistence) {
            Write-Success "Persistence mechanisms have been added!"
            Write-Info "  The patch will now survive reboots and Windows updates"
        } else {
            Write-Warning "Persistence was NOT added. The patch may not survive reboots."
            Write-Info "  Run with -Persist parameter to add persistence: .\RDP-MultiSession-Enabler.ps1 -Patch -Persist"
        }
        
        Write-Title "IMPORTANT NOTES"
        Write-Warning "Windows updates may still overwrite this patch"
        Write-Warning "If patch is lost, run the script again with -Persist"
        Write-Info "Backup saved at: $BackupPath"
        
        $osInfo = Get-OSInfo
        if ($osInfo.BuildNumber -ge 26120 -and $osInfo.BuildNumber -le 26299) {
            Write-Title "25H2 BUILD NOTES"
            Write-Info "Windows 11 25H2 detected (Build $($osInfo.BuildNumber))"
            Write-Info "Using 25H2 pattern - please report if you encounter any issues"
        }
        
        return $true
        
    } catch {
        Write-Error "Patching failed: $_"
        
        # Attempt to restore from backup
        if (Test-Path $BackupPath) {
            Write-Warning "Attempting to restore from backup..."
            Copy-Item -Path $BackupPath -Destination $termsrvPath -Force -ErrorAction SilentlyContinue
        }
        
        Set-FilePermissions -Path $termsrvPath -OriginalAcl $originalAcl
        Enable-WindowsFileProtection
        Start-TermServiceWithTimeout
        
        return $false
    }
}

function Test-BinaryEquality {
    param([string]$File1, [string]$File2)
    
    try {
        $hash1 = Get-FileHash $File1 -Algorithm SHA256
        $hash2 = Get-FileHash $File2 -Algorithm SHA256
        return ($hash1.Hash -eq $hash2.Hash)
    } catch {
        return $false
    }
}

function Restore-TermServiceDll {
    param([string]$BackupPath)
    
    Write-Title "RESTORE OPERATION"
    
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup file not found at: $BackupPath"
        return $false
    }
    
    # Remove persistence mechanisms
    Remove-PersistenceMechanism
    
    if (-not (Stop-TermServiceWithTimeout)) {
        Write-Error "Failed to stop service for restore"
        return $false
    }
    
    $originalAcl = Get-Acl -Path $termsrvPath -ErrorAction SilentlyContinue
    
    if (-not (Set-FilePermissions -Path $termsrvPath -TakeOwnership)) {
        Write-Error "Failed to take ownership for restore"
        Start-TermServiceWithTimeout
        return $false
    }
    
    try {
        Copy-Item -Path $BackupPath -Destination $termsrvPath -Force -ErrorAction Stop
        Write-Success "Restore completed successfully"
        
        $restoredHash = Get-FileHash $termsrvPath -Algorithm SHA256
        $backupHash = Get-FileHash $BackupPath -Algorithm SHA256
        if ($restoredHash.Hash -eq $backupHash.Hash) {
            Write-Success "Restore verified (hash match)"
        } else {
            Write-Error "Restore verification failed!"
        }
        
        Set-FilePermissions -Path $termsrvPath -OriginalAcl $originalAcl
        Start-TermServiceWithTimeout
        
        Write-Success "Original termsrv.dll restored successfully!"
        Write-Info "All persistence mechanisms have been removed"
        
        return $true
    } catch {
        Write-Error "Failed to restore: $_"
        Set-FilePermissions -Path $termsrvPath -OriginalAcl $originalAcl
        Start-TermServiceWithTimeout
        return $false
    }
}

function Show-Disclaimer {
    Write-Host ""
    Write-Host "  ================================================================================" -ForegroundColor Yellow
    Write-Host "                           DISCLAIMER" -ForegroundColor Yellow
    Write-Host "  ================================================================================" -ForegroundColor Yellow
    Write-Host "  This script modifies critical system files (termsrv.dll) to enable" -ForegroundColor Yellow
    Write-Host "  multiple concurrent RDP sessions. By using this script, you acknowledge" -ForegroundColor Yellow
    Write-Host "  and accept the following:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  • This may violate Microsoft Windows licensing terms for client editions" -ForegroundColor Yellow
    Write-Host "  • Windows updates may overwrite the patched file" -ForegroundColor Yellow
    Write-Host "  • Antivirus software may flag this script" -ForegroundColor Yellow
    Write-Host "  • Use at your own risk - the authors assume no liability" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  A system restore point and backup are strongly recommended." -ForegroundColor Yellow
    Write-Host "  Use the -Persist parameter to make the patch survive reboots." -ForegroundColor Yellow
    Write-Host "  ================================================================================" -ForegroundColor Yellow
    Write-Host ""
}

function Show-Menu {
    Clear-Host
    Show-Header
    Show-Disclaimer
    
    $osInfo = Get-OSInfo
    $osName = Get-OSFriendlyName
    $serviceStatus = (Get-Service -Name TermService -ErrorAction SilentlyContinue).Status
    $pattern = Get-ApplicablePattern -Silent
    $isPatched = if ($pattern) { Test-IsPatched -DllPath $termsrvPath -Pattern $pattern } else { $false }
    $hasPersistence = ($null -ne (Get-ScheduledTask -TaskName $persistenceTaskName -ErrorAction SilentlyContinue))
    
    $statusSymbol = switch ($serviceStatus) {
        "Running" { "[RUNNING]" }
        "Stopped" { "[STOPPED]" }
        default { "[UNKNOWN]" }
    }
    
    $patchStatus = if ($isPatched) { "[PATCHED]" } else { "[NOT PATCHED]" }
    $persistStatus = if ($hasPersistence) { "[ACTIVE]" } else { "[INACTIVE]" }
    
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  | SYSTEM INFORMATION                                                             |" -ForegroundColor White
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ("  |  OS:           {0,-70} |" -f $osName) -ForegroundColor White
    Write-Host ("  |  Build:        {0,-70} |" -f "$($osInfo.FullBuild) [$($osInfo.Architecture)]") -ForegroundColor White
    Write-Host ("  |  Edition:      {0,-70} |" -f $osInfo.EditionID) -ForegroundColor White
    Write-Host ("  |  TermService:  {0,-71} |" -f $statusSymbol) -ForegroundColor $(if($serviceStatus -eq "Running"){"Green"}else{"Yellow"})
    Write-Host ("  |  Patch Status: {0,-70} |" -f $patchStatus) -ForegroundColor $(if($isPatched){"Green"}else{"Yellow"})
    Write-Host ("  |  Persistence:  {0,-70} |" -f $persistStatus) -ForegroundColor $(if($hasPersistence){"Green"}else{"Yellow"})
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  | AVAILABLE OPTIONS                                                               |" -ForegroundColor White
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |                                                                                 |" -ForegroundColor DarkGray
    Write-Host "  |  [1]  Check System Compatibility                                                |" -ForegroundColor White
    Write-Host "  |  [2]  Validate Current Configuration                                            |" -ForegroundColor White
    Write-Host "  |  [3]  Patch termsrv.dll (Enable Multi-Session)                                  |" -ForegroundColor White
    Write-Host "  |  [4]  Patch with Persistence (Survives Reboots)                                 |" -ForegroundColor White
    Write-Host "  |  [5]  Restore from Backup                                                       |" -ForegroundColor White
    Write-Host "  |  [6]  Create System Restore Point                                               |" -ForegroundColor White
    Write-Host "  |  [7]  Show Active RDP Sessions                                                  |" -ForegroundColor White
    Write-Host "  |  [8]  Test Multi-Session (Full Validation)                                      |" -ForegroundColor White
    Write-Host "  |  [9]  Exit                                                                      |" -ForegroundColor White
    Write-Host "  |                                                                                 |" -ForegroundColor DarkGray
    Write-Host "  +--------------------------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host -NoNewline "  Select an option [1-9]: " -ForegroundColor Yellow
}

function Test-SystemCompatibility {
    Write-Title "COMPATIBILITY CHECK"

    $pattern = Get-ApplicablePattern
    if ($null -eq $pattern) {
        return $false
    }

    Write-Info "Candidate pattern: $($pattern.Description)"

    if (Test-Path $termsrvPath) {
        $fileInfo = Get-Item $termsrvPath
        Write-Success "termsrv.dll found: $($fileInfo.Length) bytes"

        if (Test-FileAccess $termsrvPath) {
            Write-Success "File is accessible"
        } else {
            Write-Warning "File may be locked by another process"
        }
    } else {
        Write-Error "termsrv.dll NOT found!"
        return $false
    }

    Write-Info "Running non-invasive termsrv.dll compatibility preflight..."

    if (-not (Test-TermsrvPatchPreflight -DllPath $termsrvPath -Pattern $pattern)) {
        Write-Warning "System compatibility check FAILED."
        Write-Warning "The selected candidate pattern is not verified for the installed termsrv.dll."
        return $false
    }

    Write-Success "System compatibility check PASSED."
    return $true
}
function Test-CurrentConfiguration {
    Write-Title "CONFIGURATION VALIDATION"
    
    $pattern = Get-ApplicablePattern
    if ($null -eq $pattern) {
        return
    }
    
    $configData = @()
    
    if (Test-IsPatched -DllPath $termsrvPath -Pattern $pattern) {
        $patchStatus = "[PATCHED]"
        $patchValid = if (Test-PatchValidity -DllPath $termsrvPath -Pattern $pattern) { "[VALID]" } else { "[INVALID]" }
    } else {
        $patchStatus = "[NOT PATCHED]"
        $patchValid = "[-]"
    }
    
    $configData += [PSCustomObject]@{
        Component = "termsrv.dll"
        Status = $patchStatus
        Details = $patchValid
    }
    
    try {
        $rdpAllowed = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections
        $rdpStatus = if ($rdpAllowed.fDenyTSConnections -eq 0) { "[ENABLED]" } else { "[DISABLED]" }
    } catch {
        $rdpStatus = "[UNKNOWN]"
    }
    
    $configData += [PSCustomObject]@{
        Component = "RDP Connections"
        Status = $rdpStatus
        Details = ""
    }
    
    try {
        $firewallRule = Get-NetFirewallRule -DisplayName "Remote Desktop*" -ErrorAction SilentlyContinue | Where-Object {$_.Enabled -eq $true}
        $fwStatus = if ($null -ne $firewallRule) { "[ENABLED]" } else { "[DISABLED]" }
    } catch {
        $fwStatus = "[UNKNOWN]"
    }
    
    $configData += [PSCustomObject]@{
        Component = "Firewall Rule"
        Status = $fwStatus
        Details = ""
    }
    
    $backupStatus = if (Test-Path $BackupPath) { "[EXISTS]" } else { "[NOT FOUND]" }
    $configData += [PSCustomObject]@{
        Component = "Backup"
        Status = $backupStatus
        Details = ""
    }
    
    $hasPersistence = ($null -ne (Get-ScheduledTask -TaskName $persistenceTaskName -ErrorAction SilentlyContinue))
    $persistStatus = if ($hasPersistence) { "[ACTIVE]" } else { "[INACTIVE]" }
    $configData += [PSCustomObject]@{
        Component = "Persistence"
        Status = $persistStatus
        Details = ""
    }
    
    Write-Table -Data $configData -Properties @("Component", "Status", "Details") -Headers @("Component", "Status", "Details")
}

function Test-MultiSessionCapability {
    Write-Title "MULTI-SESSION TEST"
    
    $issues = @()
    $warnings = @()
    $testResults = @()
    
    $service = Get-Service -Name TermService -ErrorAction SilentlyContinue
    if ($null -eq $service -or $service.Status -ne "Running") {
        $issues += "Remote Desktop Services is not running"
        $testResults += [PSCustomObject]@{
            Test = "TermService Status"
            Result = "[FAIL]"
            Details = "Not Running"
        }
    } else {
        $testResults += [PSCustomObject]@{
            Test = "TermService Status"
            Result = "[PASS]"
            Details = "Running"
        }
    }
    
    try {
        $rdpAllowed = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -ErrorAction Stop
        if ($rdpAllowed.fDenyTSConnections -eq 0) {
            $testResults += [PSCustomObject]@{
                Test = "RDP Connections"
                Result = "[PASS]"
                Details = "Enabled"
            }
        } else {
            $issues += "RDP connections are disabled in registry"
            $testResults += [PSCustomObject]@{
                Test = "RDP Connections"
                Result = "[FAIL]"
                Details = "Disabled"
            }
        }
    } catch {
        $warnings += "Could not read RDP registry setting"
        $testResults += [PSCustomObject]@{
            Test = "RDP Connections"
            Result = "[WARN]"
            Details = "Unknown"
        }
    }
    
    $pattern = Get-ApplicablePattern
    if ($pattern) {
        if (Test-IsPatched -DllPath $termsrvPath -Pattern $pattern) {
            if (Test-PatchValidity -DllPath $termsrvPath -Pattern $pattern) {
                $testResults += [PSCustomObject]@{
                    Test = "termsrv.dll Patch"
                    Result = "[PASS]"
                    Details = "Patched & Validated"
                }
            } else {
                $issues += "termsrv.dll is patched but validation failed"
                $testResults += [PSCustomObject]@{
                    Test = "termsrv.dll Patch"
                    Result = "[FAIL]"
                    Details = "Validation Failed"
                }
            }
        } else {
            $issues += "termsrv.dll is not patched"
            $testResults += [PSCustomObject]@{
                Test = "termsrv.dll Patch"
                Result = "[FAIL]"
                Details = "Not Patched"
            }
        }
    }
    
    # Check persistence
    $hasPersistence = ($null -ne (Get-ScheduledTask -TaskName $persistenceTaskName -ErrorAction SilentlyContinue))
    if ($hasPersistence) {
        $testResults += [PSCustomObject]@{
            Test = "Persistence"
            Result = "[PASS]"
            Details = "Active"
        }
    } else {
        $warnings += "Persistence not active - patch may not survive reboots"
        $testResults += [PSCustomObject]@{
            Test = "Persistence"
            Result = "[WARN]"
            Details = "Inactive"
        }
    }
    
    Write-Table -Data $testResults -Properties @("Test", "Result", "Details") -Headers @("Test", "Result", "Details")
    
    Write-Host ""
    if ($issues.Count -eq 0) {
        Write-Success "ALL TESTS PASSED! Multi-session is ready."
        Write-Host ""
        Write-Info "Next steps:"
        Write-Info "  1. Connect from another computer using RDP"
        Write-Info "  2. While connected, try connecting from a third computer"
        Write-Info "  3. Both connections should be successful"
        Write-Info "  4. Use option 7 to monitor active sessions"
        return $true
    } else {
        Write-Error "TESTS FAILED! Issues found:"
        foreach ($issue in $issues) {
            Write-Error "  • $issue"
        }
        if ($warnings.Count -gt 0) {
            Write-Warning "Warnings:"
            foreach ($warning in $warnings) {
                Write-Warning "  • $warning"
            }
        }
        return $false
    }
}

function New-SystemRestorePoint {
    Write-Title "SYSTEM RESTORE"
    Write-Info "Creating System Restore Point..."

    try {
        $description = "Pre-RDP Multi-Session Patch $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

        $beforePoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        $beforeMaxSequence = -1

        if ($beforePoints.Count -gt 0) {
            $beforeMaxSequence = [int64]((
                $beforePoints |
                Measure-Object -Property SequenceNumber -Maximum
            ).Maximum)
        }

        $checkpointWarnings = @()

        Checkpoint-Computer `
            -Description $description `
            -RestorePointType MODIFY_SETTINGS `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue `
            -WarningVariable checkpointWarnings

        $afterPoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)

        $newPoint = $afterPoints |
            Where-Object { [int64]$_.SequenceNumber -gt $beforeMaxSequence } |
            Sort-Object SequenceNumber -Descending |
            Select-Object -First 1

        if ($null -eq $newPoint) {
            Write-Warning "System Restore Point was not created."

            foreach ($warningMessage in $checkpointWarnings) {
                Write-Warning ([string]$warningMessage)
            }

            if ($checkpointWarnings.Count -eq 0) {
                Write-Warning "Checkpoint-Computer returned without an error, but no new restore point could be verified."
            }

            return $false
        }

        Write-Success "System Restore Point created successfully"
        Write-Info "Description: $($newPoint.Description)"
        Write-Info "Sequence number: $($newPoint.SequenceNumber)"
        return $true
    } catch {
        Write-Warning "Failed to create System Restore Point: $_"
        Write-Info "Check Windows System Protection configuration and available restore-point storage."
        return $false
    }
}
function Get-RDPSessions {
    Write-Title "ACTIVE SESSIONS"
    
    try {
        $sessions = & query session /server:localhost 2>$null
        if ($sessions) {
            $sessionLines = $sessions -split "`r`n"
            $sessionData = @()
            
            foreach ($line in $sessionLines[1..$($sessionLines.Count-1)]) {
                if ($line.Trim() -ne "") {
                    $parts = $line -split '\s+', 4
                    if ($parts.Count -ge 4) {
                        $sessionData += [PSCustomObject]@{
                            Session = $parts[0]
                            Username = $parts[1]
                            ID = $parts[2]
                            State = $parts[3]
                            Type = if ($line -match "rdp-tcp") { "RDP" } elseif ($line -match "console") { "Console" } else { "Other" }
                        }
                    }
                }
            }
            
            if ($sessionData.Count -gt 0) {
                Write-Table -Data $sessionData -Properties @("Session", "Username", "ID", "State", "Type") -Headers @("Session", "Username", "ID", "State", "Type")
                
                $rdpCount = ($sessionData | Where-Object {$_.Type -eq "RDP"} | Measure-Object).Count
                $consoleCount = ($sessionData | Where-Object {$_.Type -eq "Console"} | Measure-Object).Count
                $activeCount = ($sessionData | Where-Object {$_.State -eq "Active"} | Measure-Object).Count
                
                Write-Host ""
                Write-Info "Summary: $rdpCount RDP | $consoleCount Console | $activeCount Active"
            } else {
                Write-Info "No active sessions found"
            }
        } else {
            Write-Info "No active sessions found"
        }
    } catch {
        Write-Error "Failed to query sessions: $_"
    }
}

#endregion

#region Main Execution

Start-TranscriptLogging

Clear-Host
Show-Header
Show-Disclaimer

if (-not ($Check -or $Validate -or $Test)) {
    Set-SelfElevation
}

if ($Check) {
    $null = Test-SystemCompatibility
    Stop-TranscriptLogging
    exit 0
}

if ($Validate) {
    Test-CurrentConfiguration
    Stop-TranscriptLogging
    exit 0
}

if ($Test) {
    Test-MultiSessionCapability
    Stop-TranscriptLogging
    exit 0
}

if ($Patch) {
    Write-Host ""
    Write-Info "Running in PATCH mode..."
    
    $pattern = Get-ApplicablePattern
    if ($pattern) {
        if (-not $Force) {
            $response = Read-Host "`n  Do you want to create a System Restore Point first? (Y/n)"
            if ($response -ne 'n' -and $response -ne 'N') {
                $null = New-SystemRestorePoint
            }
        }
        
        $result = Invoke-PatchApplication -Pattern $pattern -BackupPath $BackupPath
    } else {
        $result = $false
    }
    
    Stop-TranscriptLogging
    exit $(if($result){0}else{1})
}

if ($Restore) {
    Write-Host ""
    Write-Info "Running in RESTORE mode..."
    $result = Restore-TermServiceDll -BackupPath $BackupPath
    
    Stop-TranscriptLogging
    exit $(if($result){0}else{1})
}

do {
    Show-Menu
    $choice = Read-Host
    
    switch ($choice) {
        "1" { 
            $null = Test-SystemCompatibility
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            Test-CurrentConfiguration
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" {
            $pattern = Get-ApplicablePattern
            if ($pattern) {
                if (-not $Force) {
                    $response = Read-Host "`n  Do you want to create a System Restore Point first? (Y/n)"
                    if ($response -ne 'n' -and $response -ne 'N') {
                        $null = New-SystemRestorePoint
                    }
                }
                $null = Invoke-PatchApplication -Pattern $pattern -BackupPath $BackupPath
            }
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "4" {
            $pattern = Get-ApplicablePattern
            if ($pattern) {
                if (-not $Force) {
                    $response = Read-Host "`n  Do you want to create a System Restore Point first? (Y/n)"
                    if ($response -ne 'n' -and $response -ne 'N') {
                        $null = New-SystemRestorePoint
                    }
                }
                $null = Invoke-PatchApplication -Pattern $pattern -BackupPath $BackupPath -Persist
            }
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "5" {
            Restore-TermServiceDll -BackupPath $BackupPath
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "6" {
            $null = New-SystemRestorePoint
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "7" {
            Get-RDPSessions
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "8" {
            Test-MultiSessionCapability
            Write-Host "`n  Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "9" {
            Write-Info "Exiting..."
            break
        }
        default {
            Write-Error "Invalid option. Please try again."
            Start-Sleep -Seconds 2
        }
    }
} while ($choice -ne "9")

Stop-TranscriptLogging
exit 0

#endregion