<#
.SYNOPSIS
    Detects specified applications installed on the system.

.DESCRIPTION
    This script checks for the presence of specified applications, including AppX provisioned packages, AppX packages, and Win32 applications.
    It logs the detection results and returns a status code indicating whether any of the specified applications were found.

.PARAMETER
    None.

.EXAMPLE
    .\XCS-RemoveUnwantedApps-Detect.ps1

.NOTES
    Author: Björn Hedenström
    Company: Xperta AB
    Date: 2023-10-10
    Version: 0.6

.REVISIONS
    2023-10-10: Initial version.
    2023-11-25: Updated to include additional app names.
    2023-12-01: Updated to include detection of Win32 apps.
    2023-12-02: Updated to return a status code indicating whether any apps were found.

#>

# Define an array of app names to check
$appNames = @(
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.GamingApp",
    "Microsoft.Getstarted",
    "Microsoft.GetHelp",
    "Microsoft.Messaging",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.Windows.Photos",
    "Microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameCallableUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "MicrosoftTeams",
    "Mozilla Firefox"
)

# Initialize a variable to track if any apps are found
$appsFound = $false

# Function to check if an AppX Provisioned Package is installed
function Is-AppXProvisionedPackageInstalled {
    param (
        [string]$appName
    )
    $package = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }
    return $package -ne $null
}

# Function to check if an AppX Package is installed
function Is-AppXPackageInstalled {
    param (
        [string]$appName
    )
    $apps = Get-AppxPackage -AllUsers -Name $appName -ErrorAction SilentlyContinue
    $uniqueApps = $apps | Select-Object -Unique
    return $uniqueApps -ne $null
}

# Function to check if a Win32 App is installed
function Is-Win32AppInstalled {
    param (
        [string]$appName
    )
    $appPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Ensure the registry provider is loaded
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }

    $userSIDs = Get-ChildItem -Path "HKU:\" | Select-Object -ExpandProperty PSChildName

    foreach ($userSID in $userSIDs) {
        $appPaths += "HKU:\$userSID\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    foreach ($path in $appPaths) {
        $apps = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $appName }
        if ($apps) {
            return $true
        }
    }
    return $false
}

# Loop through the array of app names
foreach ($appName in $appNames) {
    if (Is-AppXProvisionedPackageInstalled -appName $appName) {
        Write-Output "Detected AppX Provisioned Package: $appName"
        $appsFound = $true
    } elseif (Is-AppXPackageInstalled -appName $appName) {
        Write-Output "Detected AppX Package: $appName"
        $appsFound = $true
    } elseif (Is-Win32AppInstalled -appName $appName) {
        Write-Output "Detected Win32 App: $appName"
        $appsFound = $true
    } else {
        Write-Output "App not found: $appName"
    }
}

# Return 1 if any apps were found, otherwise return 0
if ($appsFound) {
    exit 1
} else {
    exit 0
}