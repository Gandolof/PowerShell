# Microsoft 365 Apps - Detection
#
# Checks the latest 5 user-context Click-to-Run log files.
#
# Exit 0 = Remediation not started
# Exit 1 = Remediation started

$ComputerName = $env:COMPUTERNAME
$LogFolder    = $env:TEMP

$NumberOfLogsToCheck = 5

$BaseFolder = Join-Path $env:LOCALAPPDATA "COMPANY"
$LogFile    = Join-Path $BaseFolder "M365AppsUpdateRemediation.log"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

if (-not (Test-Path $BaseFolder)) {
    New-Item -Path $BaseFolder -ItemType Directory -Force | Out-Null
}

function Write-DetectionResult {

    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    $Line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] $Message"

    Add-Content `
        -Path $LogFile `
        -Value $Line `
        -Encoding UTF8 `
        -ErrorAction SilentlyContinue

    Write-Output $Message
}

# ------------------------------------------------------------
# Get latest Click-to-Run logs
# ------------------------------------------------------------

$RecentLogs = Get-ChildItem `
    -Path $LogFolder `
    -Filter "$ComputerName-*.log" `
    -File `
    -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First $NumberOfLogsToCheck

if (-not $RecentLogs) {

    Write-DetectionResult "Remediation not started."
    exit 0
}

# ------------------------------------------------------------
# Find ProcessKillerShutdown events
# ------------------------------------------------------------

$ShutdownEvents = @()

foreach ($Log in $RecentLogs) {

    try {

        $LogMatches = Select-String `
            -Path $Log.FullName `
            -Pattern 'Office\.ClickToRun\.ProcessKillerShutdown' `
            -ErrorAction Stop

        foreach ($Match in $LogMatches) {

            $Timestamp = $Log.LastWriteTime

            if (
                $Match.Line -match
                '^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\.\d+)'
            ) {
                try {
                    $Timestamp = [datetime]::Parse($Matches[1])
                }
                catch {
                }
            }

            $ShutdownEvents += [PSCustomObject]@{
                Timestamp = $Timestamp
                Line      = $Match.Line
            }
        }
    }
    catch {
    }
}

if (-not $ShutdownEvents) {

    Write-DetectionResult "Remediation not started."
    exit 0
}

# ------------------------------------------------------------
# Inspect only newest shutdown event
# ------------------------------------------------------------

$Line = (
    $ShutdownEvents |
    Sort-Object Timestamp -Descending |
    Select-Object -First 1
).Line

$BlockedByOffice =
    ($Line -match 'Office\.ClickToRun\.ProcessKillerShutdown') -and
    ($Line -match '"Data\.ErrorMessage"\s*:\s*"Shutdown failed"') -and
    ($Line -match '"Data\.VetoingApps"\s*:\s*"[^"]+"') -and
    ($Line -match '"Data\.VetoCause"\s*:\s*1') -and
    ($Line -match '"Data\.IgnoreVeto"\s*:\s*"False"') -and
    ($Line -match '"Data\.AppsAfterFailedShutdown"\s*:\s*"[^"]+"') -and
    ($Line -match '"Data\.RMShutdownReturn"\s*:\s*351')

# ------------------------------------------------------------
# Result
# ------------------------------------------------------------

if ($BlockedByOffice) {

    Write-DetectionResult "Remediation started."
    exit 1
}

Write-DetectionResult "Remediation not started."
exit 0