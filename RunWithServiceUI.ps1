<#
.SYNOPSIS
    Runs Deploy-Application.exe with or without ServiceUI based on the logon status of the computer.

.DESCRIPTION
    This script is used to run Deploy-Application.exe with or without ServiceUI based on the logon status of the computer.

.PARAMETER
    Mode
        Specifies the mode of the script. Valid values are "Install" and "Uninstall".

.EXAMPLE
    powershell.exe -executionpolicy bypass -file ".\RunWithServiceUI.ps1" -Mode Install
    powershell.exe -executionpolicy bypass -file ".\RunWithServiceUI.ps1" -Mode Uninstall

.NOTES
    Author: Björn Hedenström
    Company: Xperta AB
    Date: 2023-12-06
    Version: 0.8 (Not tested in production)

#>

param (
    [string]$Mode
)

# Define the log file path
$logFilePath = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\RunWithServiceUI.log"

# Logging function
function Write-Log {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Add-Content -Path $logFilePath -Value $logMessage
}

# Function to get logon status
function GetLogonStatus {
    try {
        $user = $null
        $user = Get-WmiObject -Class win32_computersystem | select -ExpandProperty username -ErrorAction Stop
        if (!($user)) { 
            return "System" # Not logged on
        }
    } catch { 
        return "System" # Not logged on
    }
    try {
        if ((Get-Process logonui -ErrorAction Stop) -and ($user)) { 
            return "User" # Workstation locked
        }
    } catch { 
        if ($user) { 
            return "User" # Computer In Use
        }
    }
}

# Main script execution
$State = GetLogonStatus
Write-Log "Logon status: $State"

if ($State -eq "User") {
    try {
        Write-Log "User logged in, running with ServiceUI"
        Write-Output "User logged in, running with ServiceUI"
        if ($Mode -eq "Install") {
            .\ServiceUI.exe -Process:explorer.exe Deploy-Application.exe install
        } elseif ($Mode -eq "Uninstall") {
            .\ServiceUI.exe -Process:explorer.exe Deploy-Application.exe uninstall
        } else {
            Write-Log "Invalid mode specified: $Mode"
            Write-Output "Invalid mode specified: $Mode"
            exit 1
        }
        Write-Log "ServiceUI executed successfully"
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log "Error running ServiceUI: $ErrorMessage"
        Write-Output $ErrorMessage
    }
} else {
    try {
        Write-Log "No user logged in, running without ServiceUI"
        Write-Output "No user logged in, running without ServiceUI"
        if ($Mode -eq "Install") {
            Start-Process Deploy-Application.exe -Wait -ArgumentList 'install'
        } elseif ($Mode -eq "Uninstall") {
            Start-Process Deploy-Application.exe -Wait -ArgumentList 'uninstall'
        } else {
            Write-Log "Invalid mode specified: $Mode"
            Write-Output "Invalid mode specified: $Mode"
            exit 1
        }
        Write-Log "Deploy-Application executed successfully"
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Log "Error running Deploy-Application: $ErrorMessage"
        Write-Output $ErrorMessage
    }
}