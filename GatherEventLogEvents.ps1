<#
.SYNOPSIS
    Gathers event log events related to WDAC policy set to audit mode.

.DESCRIPTION
    This script retrieves event log events related to WDAC policy set to audit mode from the
    Microsoft-Windows-CodeIntegrity/Operational and Microsoft-Windows-AppLocker/MSI and Script logs.
    It parses the event data and exports the relevant fields to a CSV file for further analysis.

.PARAMETER
    None.

.EXAMPLE
    .\XCS-RemoveUnwantedApps-Detect.ps1

.NOTES
    Author: Björn Hedenström
    Company: Xperta AB
    Date: 2023-11-25
    Version: 0.8

#>

# Define parameters
$hostname = $env:COMPUTERNAME
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$directoryPath = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs"
$logFilePath = "$directoryPath\$hostname`_Events_Log_$timestamp.txt"
$outputPath = "$directoryPath\$hostname`_Events_$timestamp.csv"
$errorLogPath = "$directoryPath\$hostname`_Events_ErrorLog_$timestamp.txt"
$numberOfEvents = 500
$errorOccurred = $false

# Ensure the directory exists
if (-not (Test-Path -Path $directoryPath)) {
    New-Item -Path $directoryPath -ItemType Directory | Out-Null
}

# Create the log files
New-Item -Path $logFilePath -ItemType File -Force | Out-Null

# Function to parse event data XML and extract required fields
function Parse-EventData {
    param (
        [xml]$eventDataXml
    )

    try {
        $dataItems = $eventDataXml.Event.EventData.Data
        if (-not $dataItems) {
            throw "EventData is null or empty."
        }

        $fileName = if ($dataItems[1]) { [System.IO.Path]::GetFileName($dataItems[1].'#text') } else { $null }
        $filePath = if ($dataItems[1]) { [System.IO.Path]::GetDirectoryName($dataItems[1].'#text') } else { $null }
        $processName = if ($dataItems[3]) { [System.IO.Path]::GetFileName($dataItems[3].'#text') } else { $null }
        $processPath = if ($dataItems[3]) { [System.IO.Path]::GetDirectoryName($dataItems[3].'#text') } else { $null }
        $requestedPolicy = if ($dataItems[4]) { $dataItems[4].'#text' } else { $null }
        $validatedPolicy = if ($dataItems[5]) { $dataItems[5].'#text' } else { $null }
        $status = if ($dataItems[6]) { $dataItems[6].'#text' } else { $null }
        $eventId = $eventDataXml.Event.System.EventID

        return [PSCustomObject]@{
            Computer = $hostname
            EventID = $eventId
            FileName = $fileName
            FilePath = $filePath
            ProcessName = $processName
            ProcessPath = $processPath
            RequestedPolicy = $requestedPolicy
            ValidatedPolicy = $validatedPolicy
            Status = $status
        }
    } catch {
        Write-Error "Failed to parse event data: $_"
        if (-not $errorOccurred) {
            New-Item -Path $errorLogPath -ItemType File -Force | Out-Null
            $errorOccurred = $true
        }
        $eventDataXml.OuterXml | Out-File -FilePath $errorLogPath -Append
        return $null
    }
}

# Initialize the CSV file with headers
"Computer,EventID,FileName,FilePath,ProcessName,ProcessPath,RequestedPolicy,ValidatedPolicy,Status" | Out-File -FilePath $outputPath

$allEvents = @()
$allEvents += Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-CodeIntegrity/Operational"; Id=3076} -MaxEvents $numberOfEvents
$allEvents += Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-AppLocker/MSI and Script"; Id=8028} -MaxEvents $numberOfEvents
# $allEvents += Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-AppLocker/EXE and DLL"; Id=8028} -MaxEvents $numberOfEvents

foreach ($event in $allEvents) {
    try {
        $eventDataXml = [xml]$event.ToXml()
        $eventDataXml.OuterXml | Out-File -FilePath $logFilePath -Append
        Write-Output "Processing event: $($eventDataXml.Event.System.EventID)" | Out-File -FilePath $logFilePath -Append
        Write-Output "EventData: $($eventDataXml.Event.EventData.OuterXml)" | Out-File -FilePath $logFilePath -Append
        $parsedData = Parse-EventData -eventDataXml $eventDataXml
        if ($parsedData) {
            $parsedData | Export-Csv -Path $outputPath -Append -NoTypeInformation
        } else {
            Write-Error "Parsed data is null for event: $($eventDataXml.Event.System.EventID)"
        }
    } catch {
        Write-Error "Failed to process event: $_"
        if (-not $errorOccurred) {
            New-Item -Path $errorLogPath -ItemType File -Force | Out-Null
            $errorOccurred = $true
        }
        $event.ToXml() | Out-File -FilePath $errorLogPath -Append
    }
}