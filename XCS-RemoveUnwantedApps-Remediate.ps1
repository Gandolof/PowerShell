<#
.SYNOPSIS
    Remediates specified unwanted applications by uninstalling them from the system.

.DESCRIPTION
    This script checks for the presence of specified unwanted applications, including AppX provisioned packages, AppX packages, and Win32 applications.
    If any of the specified applications are found, the script attempts to uninstall them.

.PARAMETER
    None.

.EXAMPLE
    .\XCS-RemoveUnwantedApps-Remediate.ps1

.NOTES
    Author: Björn Hedenström
    Company: Xperta AB
    Date: 2023-10-10
    Version: 0.8

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

# Set debug mode
$DebugMode = $false

# Set timeout for uninstall operations (in seconds)
$UninstallTimeout = 90

# Function to log events
function Log-Event {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Output $logMessage
    Add-Content -Path "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\RemoveUnwantedApps.log" -Value $logMessage
}

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

# Function to uninstall an AppX Provisioned Package
function Uninstall-AppXProvisionedPackage {
    param (
        [string]$appName
    )
    $package = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appName }
    if ($package) {
        if ($DebugMode) {
            Log-Event "DEBUG: Would uninstall provisioned package: $appName"
        } else {
            Log-Event "Executing: Remove-AppxProvisionedPackage -Online -PackageName $($package.PackageName) -ErrorAction Stop"
            $output = Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop 2>&1
            Log-Event "Output: $output"
            Log-Event "Uninstalled provisioned package: $appName"
        }
    }
}

# Function to uninstall an AppX Package
function Uninstall-AppxPackage {
    param (
        [string]$appName
    )
    if ($DebugMode) {
        Log-Event "DEBUG: Would uninstall AppX Package: $appName"
    } else {
        Log-Event "Executing: Get-AppxPackage -Name $appName | Remove-AppxPackage -AllUsers -ErrorAction Stop"
        $output = Get-AppxPackage -Name $appName | Remove-AppxPackage -AllUsers -ErrorAction Stop 2>&1
        Log-Event "Output: $output"
        Log-Event "Uninstalled AppX Package: $appName"
    }
}

# Function to uninstall a Win32 App
function Uninstall-Win32App {
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
            foreach ($app in $apps) {
                if ($app.PSChildName -match '^\{[0-9a-fA-F\-]+\}$') {
                    # If the path is a GUID, use msiexec
                    if ($DebugMode) {
                        Log-Event "DEBUG: Would uninstall Win32 app using msiexec: $appName"
                    } else {
                        Log-Event "Found Win32 app to uninstall: $appName"
                        Log-Event "Executing: Start-Process -FilePath msiexec.exe -ArgumentList /x $($app.PSChildName) /quiet /norestart -Wait"
                        $job = Start-Job -ScriptBlock {
                            param ($app)
                            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($app.PSChildName) /quiet /norestart" -Wait
                        } -ArgumentList $app
                        if (Wait-Job -Job $job -Timeout $UninstallTimeout) {
                            $output = Receive-Job -Job $job
                            Log-Event "Output: $output"
                            Log-Event "Uninstalled Win32 app: $appName"
                        } else {
                            Log-Event "Uninstall of Win32 app $appName timed out."
                            Stop-Job -Job $job
                        }
                    }
                } elseif ($app.QuietUninstallString) {
                    # If QuietUninstallString is available, use it
                    if ($DebugMode) {
                        Log-Event "DEBUG: Would uninstall Win32 app using QuietUninstallString: $appName"
                    } else {
                        Log-Event "Found Win32 app to uninstall: $appName"
                        Log-Event "Executing: Start-Process -FilePath cmd.exe -ArgumentList /c $($app.QuietUninstallString) -Wait"
                        $job = Start-Job -ScriptBlock {
                            param ($app)
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($app.QuietUninstallString)" -Wait
                        } -ArgumentList $app
                        if (Wait-Job -Job $job -Timeout $UninstallTimeout) {
                            $output = Receive-Job -Job $job
                            Log-Event "Output: $output"
                            Log-Event "Uninstalled Win32 app: $appName"
                        } else {
                            Log-Event "Uninstall of Win32 app $appName timed out."
                            Stop-Job -Job $job
                        }
                    }
                } else {
                    Log-Event "Unable to uninstall Win32 app: $appName. QuietUninstallString not found."
                }
            }
        }
    }
}

# Loop through the array of app names
foreach ($appName in $appNames) {
    if (Is-AppXProvisionedPackageInstalled -appName $appName) {
        Uninstall-AppXProvisionedPackage -appName $appName
    } elseif (Is-AppXPackageInstalled -appName $appName) {
        Uninstall-AppxPackage -appName $appName
    } elseif (Is-Win32AppInstalled -appName $appName) {
        Uninstall-Win32App -appName $appName
    } else {
        Log-Event "App not found: $appName"
    }
}