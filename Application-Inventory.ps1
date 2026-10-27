# Requires Microsoft.Graph.Authentication and an authenticated Graph session.
# Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All"
# Report schema: https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports#appinvrawdata-report
# InstallScope, Architecture and UninstallString are not available in this report.

[CmdletBinding()]
param(
    [ValidateRange(1, 3600)]
    [int]$PollIntervalSeconds = 10,

    [ValidateRange(1, 360)]
    [int]$MaxPollAttempts = 30,

    [string]$OutputPath = (Join-Path $PSScriptRoot 'DiscoveredApps-Grouped.csv')
)

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw 'Install Microsoft.Graph.Authentication before running this script.'
}
if (-not (Get-MgContext -ErrorAction Stop)) {
    throw 'Connect first using Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All".'
}

$Body = @{
    reportName = "AppInvRawData"
    filter     = ""
    select     = @(
        "ApplicationName",
        "ApplicationVersion",
        "ApplicationPublisher",
        "Platform",
        "DeviceId"
    )
    format     = "csv"
} | ConvertTo-Json

$ExportUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
Write-Host "Submitting export job to Microsoft Graph..." -ForegroundColor Yellow
$Job = Invoke-MgGraphRequest -Method POST -Uri $ExportUri -Body $Body -ContentType "application/json" -ErrorAction Stop

$JobId = $Job.id
if ([string]::IsNullOrWhiteSpace($JobId)) {
    throw 'Microsoft Graph did not return a job ID.'
}
$StatusUri = "$ExportUri/$([uri]::EscapeDataString($JobId))"
Write-Host "Export job started. ID: $JobId" -ForegroundColor Green

for ($Attempt = 1; $Attempt -le $MaxPollAttempts; $Attempt++) {
    $Check = Invoke-MgGraphRequest -Method GET -Uri $StatusUri -ErrorAction Stop

    if ($Check.status -eq "completed") {
        if ([string]::IsNullOrWhiteSpace($Check.url)) {
            throw "Export job $JobId completed but did not provide a download URL."
        }
        $ZipPath = [System.IO.Path]::GetTempFileName()
        $Archive = $null
        try {
            Invoke-WebRequest -Uri $Check.url -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
            $Archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
            $CsvEntries = @($Archive.Entries | Where-Object { $_.FullName -like '*.csv' })
            if ($CsvEntries.Count -eq 0) {
                throw 'The export archive does not contain a CSV file.'
            }
            $Rows = @(foreach ($Entry in $CsvEntries) {
                $Reader = [System.IO.StreamReader]::new($Entry.Open())
                try {
                    $Reader.ReadToEnd() | ConvertFrom-Csv -ErrorAction Stop
                } finally {
                    $Reader.Dispose()
                }
            })

            if ($Rows.Count -eq 0) {
                throw 'The report contains no applications. No CSV file was written.'
            }
            foreach ($Row in $Rows) {
                if (-not $Row.PSObject.Properties['ApplicationName'] -or
                    -not $Row.PSObject.Properties['ApplicationVersion'] -or
                    -not $Row.PSObject.Properties['Platform'] -or
                    [string]::IsNullOrWhiteSpace($Row.DeviceId)) {
                    throw 'The CSV file is missing ApplicationName, ApplicationVersion, Platform, or a valid DeviceId.'
                }
            }

            # Keep platforms separate and count each device once across all versions.
            $Rows | Group-Object ApplicationName, Platform | Sort-Object Name | ForEach-Object {
                [pscustomobject]@{
                    ApplicationName = $_.Group[0].ApplicationName
                    ApplicationVersion = ($_.Group.ApplicationVersion | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ','
                    ApplicationPublisher = ($_.Group.ApplicationPublisher | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ','
                    Platform = $_.Group[0].Platform
                    DeviceCount = @($_.Group.DeviceId | Sort-Object -Unique).Count
                }
            } | ForEach-Object {
                # Reserve semicolons exclusively for column delimiters, including in source values.
                foreach ($Property in $_.PSObject.Properties) {
                    $Property.Value = ([string]$Property.Value).Replace(';', ',')
                }
                $_
            } | Export-Csv -LiteralPath $OutputPath -Delimiter ';' -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

            Write-Host "`nDone! The inventory, with one row per application and platform, was saved to: $OutputPath" -ForegroundColor Green
        } finally {
            if ($null -ne $Archive) { $Archive.Dispose() }
            Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
        }
        return
    }
    if ($Check.status -eq "failed") {
        throw "Export job $JobId failed."
    }

    Write-Host "Microsoft Graph is still processing the job. Status: $($Check.status)" -ForegroundColor Yellow
    if ($Attempt -lt $MaxPollAttempts) {
        Start-Sleep -Seconds $PollIntervalSeconds
    }
}

Write-Warning "Export job $JobId did not complete after $MaxPollAttempts status checks."
Write-Host "Run the command below later to retrieve the download URL:"
Write-Host "Invoke-MgGraphRequest -Method GET -Uri `"$StatusUri`" -ErrorAction Stop" -ForegroundColor Gray
