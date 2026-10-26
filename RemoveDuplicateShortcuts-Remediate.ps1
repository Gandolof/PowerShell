# Remove duplicate desktop shortcuts - Intune Remediation
# Supports Swedish, English, Danish, Norwegian, Finnish, German
# Exit 0 = Success
# Exit 1 = Remediation error
#
# Author: Björn Hedenström / Xperta AB
#

$ErrorActionPreference = 'Stop'
$CopyPattern = '(?:\s+-\s+(?:kopia|copy|kopi|kopio|kopie)(?:\s+\(\d+\))?|\s+\(\d+\))$'
$LogDirectory = Join-Path $env:LOCALAPPDATA 'COMPANY'
$LogPath = Join-Path $LogDirectory 'DuplicateDesktopShortcuts.log'

# Create directory if it does not exist
if (-not (Test-Path -LiteralPath $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force -ErrorAction Stop |
        Out-Null
}
$script:LogEnabled = $false

# Initialise logging once. Failure to access the IME log directory must not block cleanup.
try {
    $LogDirectory = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force -ErrorAction Stop | Out-Null
    }
    Add-Content -LiteralPath $LogPath -Value ("[{0}] [INFO] ----- Remediation started -----" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding UTF8 -ErrorAction Stop
    $script:LogEnabled = $true
}
catch {
    Write-Output "WARNING: Cannot write log at '$LogPath': $($_.Exception.Message). Remediation will continue."
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $Line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $Line
    if ($script:LogEnabled) {
        try {
            Add-Content -LiteralPath $LogPath -Value $Line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            $script:LogEnabled = $false
            Write-Output "WARNING: Log write failed: $($_.Exception.Message). Continuing without file logging."
        }
    }
}

function Get-OriginalName {
    param([string]$BaseName)
    $Name = $BaseName
    while ($Name -match $CopyPattern) {
        $Name = $Name -replace $CopyPattern, ''
    }
    return $Name
}

$Removed = 0
$Errors = 0
$Skipped = 0

try {
    Write-Log "Run account: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    $DesktopPaths = @(
        [Environment]::GetFolderPath('DesktopDirectory')
        [Environment]::GetFolderPath('CommonDesktopDirectory')
    ) | Where-Object {
        $_ -and (Test-Path -LiteralPath $_ -PathType Container)
    } | Select-Object -Unique

    foreach ($DesktopPath in $DesktopPaths) {
        Write-Log "Scanning: $DesktopPath"
        try {
            $Shortcuts = @(
                Get-ChildItem -LiteralPath $DesktopPath -File -ErrorAction Stop |
                    Where-Object { $_.Extension -in '.lnk', '.url' }
            )
            foreach ($Shortcut in $Shortcuts) {
                $OriginalBaseName = Get-OriginalName $Shortcut.BaseName
                if ($OriginalBaseName -ceq $Shortcut.BaseName) { continue }

                $OriginalPath = Join-Path $DesktopPath ($OriginalBaseName + $Shortcut.Extension)
                if (-not (Test-Path -LiteralPath $OriginalPath -PathType Leaf)) {
                    Write-Log "Skipped (original missing): $($Shortcut.FullName); expected $OriginalPath" 'INFO'
                    $Skipped++
                    continue
                }

                try {
                    Remove-Item -LiteralPath $Shortcut.FullName -Force -ErrorAction Stop
                    Write-Log "Removed: $($Shortcut.FullName); preserved original: $OriginalPath"
                    $Removed++
                }
                catch {
                    Write-Log "Removal failed: $($Shortcut.FullName): $($_.Exception.Message)" 'ERROR'
                    $Errors++
                }
            }
        }
        catch {
            Write-Log "Scan failed: ${DesktopPath}: $($_.Exception.Message)" 'ERROR'
            $Errors++
        }
    }

    Write-Log "Completed. Removed: $Removed. Skipped (missing originals): $Skipped. Errors: $Errors."
    Write-Log '----- Remediation finished -----'
    if ($Errors -gt 0) { exit 1 }
    exit 0
}
catch {
    Write-Log "Remediation error: $($_.Exception.Message)" 'ERROR'
    exit 1
}
