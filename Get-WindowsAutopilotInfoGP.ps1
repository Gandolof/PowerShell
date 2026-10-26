<#
.SYNOPSIS
    Collect Windows Autopilot hardware information and save it to a central share.

.DESCRIPTION
    Intended to run as a Computer Startup Script through Group Policy.

    Collects:
      - Computer name
      - Serial number
      - Manufacturer
      - Model
      - Windows Product ID
      - Windows Autopilot hardware hash
      - Logged-on user
      - Collection timestamp

    Creates:
      1. An Autopilot-compatible CSV per device
      2. A separate inventory CSV per device
      3. A local log file

.NOTES
    The central share must allow the computer accounts / Domain Computers
    to create files.

    Example:
      \\SERVER\AutopilotCollection$
#>

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

$CentralShare = "\\SERVER\AutopilotCollection$"

$AutopilotFolder = Join-Path $CentralShare "Autopilot"
$InventoryFolder = Join-Path $CentralShare "Inventory"

$LocalLogFolder = "C:\ProgramData\AutopilotCollection"
$LocalLogFile   = Join-Path $LocalLogFolder "AutopilotCollection.log"

# -------------------------------------------------------------------
# Logging function
# -------------------------------------------------------------------

function Write-Log {
    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","WARNING","ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "$Timestamp [$Level] $Message"

    try {
        Add-Content -Path $LocalLogFile -Value $Line -Encoding UTF8
    }
    catch {
        # Ignore logging errors
    }
}

# -------------------------------------------------------------------
# Prepare local logging
# -------------------------------------------------------------------

try {
    if (-not (Test-Path $LocalLogFolder)) {
        New-Item -Path $LocalLogFolder -ItemType Directory -Force | Out-Null
    }
}
catch {
    exit 1
}

Write-Log "Starting Autopilot hardware collection."

# -------------------------------------------------------------------
# Check central share
# -------------------------------------------------------------------

try {
    if (-not (Test-Path $CentralShare)) {
        Write-Log "Central share $CentralShare is unavailable." "ERROR"
        exit 1
    }

    foreach ($Folder in @($AutopilotFolder, $InventoryFolder)) {
        if (-not (Test-Path $Folder)) {
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
        }
    }
}
catch {
    Write-Log "Unable to access or create folders on central share. $($_.Exception.Message)" "ERROR"
    exit 1
}

# -------------------------------------------------------------------
# Gather device information
# -------------------------------------------------------------------

try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $BIOS           = Get-CimInstance -ClassName Win32_BIOS
    $OS             = Get-CimInstance -ClassName Win32_OperatingSystem

    $ComputerName = $env:COMPUTERNAME
    $SerialNumber = $BIOS.SerialNumber.Trim()
    $Manufacturer = $ComputerSystem.Manufacturer.Trim()
    $Model        = $ComputerSystem.Model.Trim()
    $LoggedOnUser = $ComputerSystem.UserName

    Write-Log "Device: $ComputerName"
    Write-Log "Serial number: $SerialNumber"
    Write-Log "Manufacturer: $Manufacturer"
    Write-Log "Model: $Model"
}
catch {
    Write-Log "Unable to collect standard device information. $($_.Exception.Message)" "ERROR"
    exit 1
}

# -------------------------------------------------------------------
# Get Windows Product ID
# -------------------------------------------------------------------

$ProductID = ""

try {
    $ProductID = (Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
        -Name ProductId `
        -ErrorAction Stop).ProductId
}
catch {
    Write-Log "Windows Product ID could not be retrieved." "WARNING"
}

# -------------------------------------------------------------------
# Get Windows Autopilot hardware hash
# -------------------------------------------------------------------

try {

    $DevDetail = Get-CimInstance `
        -Namespace "root/cimv2/mdm/dmmap" `
        -ClassName "MDM_DevDetail_Ext01" `
        -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
        -ErrorAction Stop

    $HardwareHash = $DevDetail.DeviceHardwareData

    if ([string]::IsNullOrWhiteSpace($HardwareHash)) {
        throw "DeviceHardwareData was empty."
    }

    Write-Log "Successfully retrieved Autopilot hardware hash."
}
catch {
    Write-Log "Unable to retrieve Autopilot hardware hash. $($_.Exception.Message)" "ERROR"
    exit 1
}

# -------------------------------------------------------------------
# Clean serial number for filename
# -------------------------------------------------------------------

$SafeSerial = $SerialNumber -replace '[\\/:*?"<>|]', '_'

if ([string]::IsNullOrWhiteSpace($SafeSerial)) {
    $SafeSerial = $ComputerName
}

# -------------------------------------------------------------------
# Autopilot CSV
#
# IMPORTANT:
# Keep this file limited to Microsoft's supported Autopilot columns.
# -------------------------------------------------------------------

$AutopilotFile = Join-Path `
    $AutopilotFolder `
    "$SafeSerial.csv"

$AutopilotData = [PSCustomObject]@{
    "Device Serial Number" = $SerialNumber
    "Windows Product ID"   = $ProductID
    "Hardware Hash"        = $HardwareHash
    "Group Tag"            = ""
    "Assigned User"        = ""
}

try {
    $AutopilotData |
        Export-Csv `
            -Path $AutopilotFile `
            -NoTypeInformation `
            -Encoding ASCII `
            -Force

    Write-Log "Autopilot CSV written to $AutopilotFile"
}
catch {
    Write-Log "Unable to write Autopilot CSV. $($_.Exception.Message)" "ERROR"
    exit 1
}

# -------------------------------------------------------------------
# Inventory CSV
# -------------------------------------------------------------------

$InventoryFile = Join-Path `
    $InventoryFolder `
    "$SafeSerial.csv"

$InventoryData = [PSCustomObject]@{
    ComputerName   = $ComputerName
    SerialNumber   = $SerialNumber
    Manufacturer   = $Manufacturer
    Model          = $Model
    ProductID      = $ProductID
    LoggedOnUser   = $LoggedOnUser
    WindowsVersion = $OS.Caption
    OSBuild        = $OS.BuildNumber
    Collected      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

try {
    $InventoryData |
        Export-Csv `
            -Path $InventoryFile `
            -NoTypeInformation `
            -Encoding UTF8 `
            -Force

    Write-Log "Inventory CSV written to $InventoryFile"
}
catch {
    Write-Log "Unable to write inventory CSV. $($_.Exception.Message)" "ERROR"
    exit 1
}

Write-Log "Autopilot hardware collection completed successfully."

exit 0
