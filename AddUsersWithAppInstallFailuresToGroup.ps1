
# Add users with failed Intune app installations to Entra group

$AppId   = "[AppID here]"
$GroupId = "[GroupID here]"

# Maximum new users to add (0 = all)
$MaxUsersToAdd = 5

$ErrorActionPreference = "Stop"

Connect-MgGraph -Scopes @(
    "DeviceManagementApps.Read.All",
    "User.Read.All",
    "GroupMember.ReadWrite.All"
)

# Get existing group members
$Existing = @(
    Get-MgGroupMember -GroupId $GroupId -All |
        ForEach-Object { $_.Id }
)

# Retrieve User Install Status report
$Uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getUserInstallStatusReport"
$Failures = @()
$Skip = 0
$PageSize = 200
$SessionId = $null

do {
    $Body = @{
        filter  = "(ApplicationId eq '$AppId')"
        select  = @("UserId", "UserName", "UserPrincipalName", "FailedCount")
        skip    = $Skip
        top     = $PageSize
        orderBy = @()
    }

    if ($SessionId) {
        $Body.sessionId = $SessionId
    }

    $TempFile = Join-Path ([IO.Path]::GetTempPath()) (
        "IntuneReport-$([guid]::NewGuid().ToString('N')).json"
    )

    try {
        Invoke-MgGraphRequest -Method POST -Uri $Uri `
            -Body ($Body | ConvertTo-Json -Depth 5) `
            -ContentType "application/json" `
            -OutputFilePath $TempFile | Out-Null

        $Report = Get-Content $TempFile -Raw -Encoding UTF8 |
            ConvertFrom-Json
    }
    finally {
        Remove-Item $TempFile -Force -ErrorAction SilentlyContinue
    }

    if (-not $Report.Schema -or $null -eq $Report.Values) {
        throw "Invalid report response. No users have been added."
    }

    $Columns = @($Report.Schema | ForEach-Object { $_.Column })

    foreach ($Row in $Report.Values) {
        $Entry = @{}

        for ($i = 0; $i -lt $Columns.Count; $i++) {
            $Entry[$Columns[$i]] = $Row[$i]
        }

        if ([int]$Entry.FailedCount -gt 0 -and
            ($Entry.UserId -or $Entry.UserPrincipalName)) {

            $Failures += [PSCustomObject]@{
                UserId            = $Entry.UserId
                UserPrincipalName = $Entry.UserPrincipalName
                FailedCount       = [int]$Entry.FailedCount
            }
        }
    }

    $Skip += @($Report.Values).Count
    $SessionId = $Report.SessionId

    if ($Skip -lt [int]$Report.TotalRowCount -and
        @($Report.Values).Count -eq 0) {
        throw "Report pagination returned no rows before completion."
    }

} while ($Skip -lt [int]$Report.TotalRowCount)

$Failures = @($Failures |
    Sort-Object UserPrincipalName, UserId -Unique)

Write-Host "`nUsers with installation failures: $($Failures.Count)"
Write-Host "Maximum new users to add: $MaxUsersToAdd`n"

$Added = 0
$Eligible = 0
$ExistingCount = 0

foreach ($Entry in $Failures) {
    $UPN = $Entry.UserPrincipalName
    $LookupId = if ($Entry.UserId) {
        $Entry.UserId
    } else {
        $UPN
    }

    # Skip existing members without counting toward the limit
    if ($Entry.UserId -and $Entry.UserId -in $Existing) {
        Write-Host "SKIPPED (existing): $UPN" -ForegroundColor Cyan
        $ExistingCount++
        continue
    }

    try {
        $User = Get-MgUser -UserId $LookupId

        # Check group membership
        if ($User.Id -in $Existing) {
            Write-Host "SKIPPED (existing): $UPN" -ForegroundColor Cyan
            $ExistingCount++
            continue
        }

        $Eligible++

        # Print remaining users even after limit is reached
        if ($MaxUsersToAdd -gt 0 -and $Added -ge $MaxUsersToAdd) {
            Write-Host "SKIPPED (limit):    $UPN" -ForegroundColor Yellow
            continue
        }

        # Add user to group
        New-MgGroupMemberByRef -GroupId $GroupId -BodyParameter @{
            "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($User.Id)"
        }

        $Existing += $User.Id
        $Added++

        Write-Host "ADDED ($Added):         $UPN" -ForegroundColor Green
    }
    catch {
        Write-Warning "FAILED: $UPN - $_"
    }
}

Write-Host "`n----------------------------------------"
Write-Host "Total users with failures:   $($Failures.Count)"
Write-Host "Already in group:            $ExistingCount"
Write-Host "Eligible new users:          $Eligible"
Write-Host "New group members added:     $Added"
Write-Host "Skipped due to limit:        $([Math]::Max(0, $Eligible - $Added))"
Write-Host "----------------------------------------"
