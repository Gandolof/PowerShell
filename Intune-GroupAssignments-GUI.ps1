
#requires -Version 5.1
# Ensure UTF-8 encoding
[Console]::InputEncoding  = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

<#
.SYNOPSIS
  Read-only GUI to find direct Intune assignments for one Entra ID group.
.NOTES
  Run in Windows PowerShell 5.1 (STA). Requires Microsoft.Graph.Authentication.
  Queries selected Microsoft Graph beta Intune endpoints. API contracts can change.
  This reports explicit group targeting only; it does not calculate effective policy via
  All Users/All Devices, nesting, filters, policy sets or user/device membership.
#>

if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core' -and $env:OS -ne 'Windows_NT') {
    throw 'This GUI requires Windows.'
}
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    throw 'Run with Windows PowerShell in STA mode: powershell.exe -STA -File .\Intune-GroupAssignments-GUI.ps1'
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Intune Group Assignment Explorer" Height="730" Width="1160" MinWidth="850" MinHeight="520" WindowStartupLocation="CenterScreen" Background="#F5F7FA" FontFamily="Segoe UI">
 <DockPanel Margin="20">
  <StackPanel DockPanel.Dock="Top">
   <TextBlock Text="Intune Group Assignment Explorer" FontSize="25" FontWeight="SemiBold" Foreground="#14273F"/>
   <TextBlock Text="Search explicit assignments to an Entra ID group across Intune apps, configurations, compliance, and scripts." Foreground="#536477" Margin="0,5,0,14"/>
   <Grid Margin="0,0,0,12">
    <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <TextBlock Grid.Column="0" Text="Group name or object ID" VerticalAlignment="Center" Margin="0,0,12,0" FontWeight="SemiBold"/>
    <TextBox Grid.Column="1" Name="GroupInput" Height="34" Padding="9,6" VerticalContentAlignment="Center" ToolTip="Exact group display name or Entra object ID"/>
    <Button Grid.Column="2" Name="SearchButton" Content="Find assignments" Padding="20,7" Margin="10,0,0,0" Background="#176BC1" Foreground="White" BorderThickness="0" FontWeight="SemiBold"/>
    <Button Grid.Column="3" Name="ExportButton" Content="Export CSV" Padding="16,7" Margin="8,0,0,0" IsEnabled="False"/>
   </Grid>
   <CheckBox Name="RetainResults" Content="Retain results between searches (append to current results)" Margin="0,0,0,10" VerticalAlignment="Center" ToolTip="When checked, additional group searches keep previous results. Uncheck to replace the results on the next search."/>
   <Grid Margin="0,0,0,8">
    <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
    <ProgressBar Grid.Column="0" Name="SearchProgress" Height="18" Minimum="0" Maximum="100" Value="0"/>
    <TextBlock Grid.Column="1" Name="ProgressText" Text="Ready" VerticalAlignment="Center" Margin="12,0,0,0" MinWidth="80"/>
   </Grid>
   <TextBlock Name="StatusText" Text="Connect to Graph and enter a group name to begin." Foreground="#536477" TextWrapping="Wrap" Margin="0,0,0,8"/>
   <TextBlock Name="GroupText" FontWeight="SemiBold" Foreground="#14273F" Margin="0,0,0,8"/>
   <Grid Margin="0,0,0,10"><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
     <TextBox Grid.Column="0" Name="FilterInput" Height="30" Padding="8,4" ToolTip="Filter displayed results"/>
     <TextBlock Grid.Column="1" Name="CountText" VerticalAlignment="Center" Margin="12,0,0,0"/>
   </Grid>
  </StackPanel>
  <Grid>
   <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="100"/></Grid.RowDefinitions>
   <DataGrid Grid.Row="0" Name="ResultsGrid" AutoGenerateColumns="False" IsReadOnly="True" CanUserAddRows="False" CanUserDeleteRows="False" SelectionMode="Extended" GridLinesVisibility="Horizontal" AlternatingRowBackground="#EEF3F9" HeadersVisibility="Column" EnableRowVirtualization="True">
    <DataGrid.Columns>
     <DataGridTextColumn Header="Group" Binding="{Binding GroupName}" Width="175"/>
     <DataGridTextColumn Header="Workload" Binding="{Binding Workload}" Width="175"/>
     <DataGridTextColumn Header="Policy / App" Binding="{Binding Name}" Width="*"/>
     <DataGridTextColumn Header="Assignment" Binding="{Binding Assignment}" Width="110"/>
     <DataGridTextColumn Header="Intent" Binding="{Binding Intent}" Width="95"/>
     <DataGridTextColumn Header="Platform / Type" Binding="{Binding Platform}" Width="155"/>
     <DataGridTextColumn Header="Filter" Binding="{Binding Filter}" Width="150"/>
    </DataGrid.Columns>
   </DataGrid>
   <TextBlock Grid.Row="1" Text="Query warnings (failures mean the report may be incomplete):" FontWeight="SemiBold" Margin="0,12,0,5"/>
   <TextBox Grid.Row="2" Name="WarningsText" Text="None" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Padding="7" Background="White"/>
  </Grid>
 </DockPanel>
</Window>
'@
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$ui = @{}
foreach ($name in @('GroupInput','SearchButton','ExportButton','StatusText','GroupText','FilterInput','CountText','ResultsGrid','WarningsText','SearchProgress','ProgressText','RetainResults')) { $ui[$name] = $window.FindName($name) }
$script:rows = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$ui.ResultsGrid.ItemsSource = $script:rows
$script:allRows = @()
$script:warnings = [System.Collections.Generic.List[string]]::new()
$script:working = $false

$script:workerCode = @'
param([string]$InputText, [hashtable]$State)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
function Get-ErrorDescription($e) {
    $message = [string]$e.Exception.Message
    if ($message.Length -gt 360) { $message = $message.Substring(0,360) + '...' }
    return $message
}
function Invoke-GraphPages([string]$uri) {
    $items = [System.Collections.Generic.List[object]]::new()
    while ($uri) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        foreach ($v in @($response.value)) { if ($null -ne $v) { [void]$items.Add($v) } }
        $uri = $response['@odata.nextLink']
    }
    return $items.ToArray()
}
function Get-AssignmentPath([string]$basePath, $item) {
    if ($basePath -ne 'deviceAppManagement/managedAppPolicies') { return $basePath }
    $kind = [string]$item['@odata.type']
    # Default app protection is a fallback policy without group assignments.
    if ($kind -eq '#microsoft.graph.defaultManagedAppProtection') { return '__SKIP_DEFAULT_APP_PROTECTION__' }
    switch -Regex ($kind) {
        'iosManagedAppProtection$' { return 'deviceAppManagement/iosManagedAppProtections' }
        'androidManagedAppProtection$' { return 'deviceAppManagement/androidManagedAppProtections' }
        'windowsManagedAppProtection$' { return 'deviceAppManagement/windowsManagedAppProtections' }
        'mdmWindowsInformationProtectionPolicy$' { return 'deviceAppManagement/mdmWindowsInformationProtectionPolicies' }
        'windowsInformationProtectionPolicy$' { return 'deviceAppManagement/windowsInformationProtectionPolicies' }
        default { return $null }
    }
}
function Find-Group([string]$groupText) {
    # Built-in Intune targets are not Entra ID groups.
    if ($groupText.Trim() -ieq 'All Users') {
        return @{ id = '(built-in target)'; displayName = 'All Users'; assignmentTargetType = '#microsoft.graph.allLicensedUsersAssignmentTarget' }
    }
    if ($groupText.Trim() -ieq 'All Devices') {
        return @{ id = '(built-in target)'; displayName = 'All Devices'; assignmentTargetType = '#microsoft.graph.allDevicesAssignmentTarget' }
    }
    if ($groupText -match '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') {
        return Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$groupText`?`$select=id,displayName" -ErrorAction Stop
    }
    $escaped = $groupText.Replace("'", "''")
    $encoded = [uri]::EscapeDataString("displayName eq '$escaped'")
    $matches = @(Invoke-GraphPages "https://graph.microsoft.com/v1.0/groups?`$filter=$encoded&`$select=id,displayName&`$top=999")
    if ($matches.Count -eq 0) { throw "No Entra ID group found with the exact name '$groupText'." }
    if ($matches.Count -gt 1) { throw "Multiple Entra ID groups have this name. Enter the object ID: $($matches.id -join ', ')" }
    return $matches[0]
}
$targets = @(
    @{Label='Settings Catalog'; Path='deviceManagement/configurationPolicies'},
    @{Label='Device configurations'; Path='deviceManagement/deviceConfigurations'},
    @{Label='Compliance policies'; Path='deviceManagement/deviceCompliancePolicies'},
    @{Label='Administrative Templates'; Path='deviceManagement/groupPolicyConfigurations'},
    @{Label='Endpoint Security intents'; Path='deviceManagement/intents'},
    @{Label='PowerShell scripts'; Path='deviceManagement/deviceManagementScripts'},
    @{Label='macOS shell scripts'; Path='deviceManagement/deviceShellScripts'},
    @{Label='macOS custom attributes'; Path='deviceManagement/deviceCustomAttributeShellScripts'},
    @{Label='Remediations'; Path='deviceManagement/deviceHealthScripts'},
    @{Label='Compliance scripts'; Path='deviceManagement/deviceComplianceScripts'},
    @{Label='Applications'; Path='deviceAppManagement/mobileApps'},
    @{Label='App configuration'; Path='deviceAppManagement/mobileAppConfigurations'},
    @{Label='Managed app configuration'; Path='deviceAppManagement/targetedManagedAppConfigurations'},
    @{Label='Managed app protection'; Path='deviceAppManagement/managedAppPolicies'},
    @{Label='Enrollment configurations'; Path='deviceManagement/deviceEnrollmentConfigurations'}
)
try {
    $State.Message = 'Resolving group...'
    $group = Find-Group $InputText
    $State.GroupName = [string]$group.displayName
    $State.GroupId = [string]$group.id
    $State.Total = $targets.Count
    for ($i=0; $i -lt $targets.Count; $i++) {
        $targetConfig = $targets[$i]
        $label = [string]$targetConfig.Label
        $basePath = [string]$targetConfig.Path
        $State.Step = $i
        $State.Message = "Searching $label ($($i+1)/$($targets.Count))..."
        try { $objects = @(Invoke-GraphPages "https://graph.microsoft.com/beta/$basePath`?`$top=100") }
        catch {
            $State.Warnings.Enqueue("$label list: $(Get-ErrorDescription $_)")
            $State.Step = $i+1
            continue
        }
        foreach ($item in $objects) {
            $name = [string]$item.displayName
            if (-not $name) { $name = [string]$item.name }
            if (-not $name) { $name = [string]$item.id }
            $id = [string]$item.id
            $State.Message = "Searching $label ($($i+1)/$($targets.Count)): $name"
            $assignmentPath = Get-AssignmentPath $basePath $item
            if ($assignmentPath -eq '__SKIP_DEFAULT_APP_PROTECTION__') { continue }
            if (-not $assignmentPath) {
                $State.Warnings.Enqueue("$label / $name : Unrecognized policy type '$($item['@odata.type'])'; cannot select an assignment endpoint.")
                continue
            }
            $assignments = @()
            try { $assignments = @(Invoke-GraphPages "https://graph.microsoft.com/beta/$assignmentPath/$id/assignments") }
            catch {
                $requestError = Get-ErrorDescription $_
                # Some tenants return HTTP 400 for the macOS shell script assignments navigation.
                # Reading the script resource with $expand=assignments can still expose them.
                if ($label -eq 'macOS shell scripts' -or $label -eq 'macOS custom attributes') {
                    try {
                        $detail = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/$basePath/$id`?`$expand=assignments" -ErrorAction Stop
                        if ($null -ne $detail.assignments) { $assignments = @($detail.assignments) }
                        elseif ($null -ne $detail.groupAssignments) { $assignments = @($detail.groupAssignments) }
                        else { throw 'The expanded response did not contain an assignments collection.' }
                    } catch {
                        $State.Warnings.Enqueue("$label / $name assignments: initial request: $requestError; fallback: $(Get-ErrorDescription $_)")
                        continue
                    }
                } else {
                    $State.Warnings.Enqueue("$label / $name assignments: $requestError")
                    continue
                }
            }
            foreach ($assignment in $assignments) {
                $assignmentTarget = $assignment.target
                if (-not $assignmentTarget -and $assignment.targetGroupId) { $assignmentTarget = @{ groupId = $assignment.targetGroupId } }
                if (-not $assignmentTarget) { continue }
                $targetId = [string]$assignmentTarget.groupId
                if (-not $targetId) { $targetId = [string]$assignmentTarget.entraObjectId }
                if (-not $targetId) { $targetId = [string]$assignment.targetGroupId }
                if ($group.assignmentTargetType) {
                    if ([string]$assignmentTarget['@odata.type'] -ine [string]$group.assignmentTargetType) { continue }
                } elseif ($targetId -ine $group.id) { continue }
                $relation = if ([string]$assignmentTarget['@odata.type'] -match 'exclusionGroupAssignmentTarget') { 'Excluded' } else { 'Included' }
                $intent = [string]$assignment.intent
                if ($label -eq 'Remediations' -and $null -ne $assignment.runRemediationScript) {
                    $intent = if ($assignment.runRemediationScript) { 'Remediate' } else { 'Detect only' }
                }
                if (-not $intent) { $intent = 'Apply' }
                $filter = ''
                if ($assignmentTarget.deviceAndAppManagementAssignmentFilterId) {
                    $filter = "$($assignmentTarget.deviceAndAppManagementAssignmentFilterType): $($assignmentTarget.deviceAndAppManagementAssignmentFilterId)"
                }
                $platform = [string]$item['@odata.type'] -replace '^#?microsoft\.graph\.', ''
                if (-not $platform) { $platform = [string]$item.platforms }
                if (-not $platform) { $platform = [string]$item.templateReference.templateFamily }
                $State.Rows.Enqueue([pscustomobject]@{
                    Workload=$label; Name=$name; Assignment=$relation; Intent=$intent;
                    Platform=$platform; Filter=$filter; ObjectId=$id; GroupId=[string]$group.id; GroupName=[string]$group.displayName
                })
            }
        }
        $State.Step = $i+1
    }
    $State.Message = 'Search complete.'
} catch {
    $State.Error = Get-ErrorDescription $_
} finally {
    $State.Done = $true
}
'@

function Update-Status([string]$value) { $ui.StatusText.Text = $value }
function Get-ErrorDescription($errorRecord) {
    $message = [string]$errorRecord.Exception.Message
    if ($message.Length -gt 360) { $message = $message.Substring(0,360) + '...' }
    return $message
}
function Refresh-Grid {
    $search = $ui.FilterInput.Text.Trim()
    $script:rows.Clear()
    foreach ($item in $script:allRows) {
        if (-not $search -or ((@($item.GroupName,$item.Workload,$item.Name,$item.Assignment,$item.Intent,$item.Platform,$item.Filter) -join ' ') -like "*$search*")) { [void]$script:rows.Add($item) }
    }
    $ui.CountText.Text = "$($script:rows.Count) shown / $($script:allRows.Count) found"
}

$ui.FilterInput.Add_TextChanged({ Refresh-Grid })
# Run Graph queries on a separate runspace; poll thread-safe progress from the WPF dispatcher.
$script:progressTimer = [System.Windows.Threading.DispatcherTimer]::new()
$script:progressTimer.Interval = [TimeSpan]::FromMilliseconds(180)
$script:progressTimer.Add_Tick({
    if (-not $script:working) { return }
    $state = $script:state
    $item = $null
    while ($state.Rows.TryDequeue([ref]$item)) {
        $script:allRows += $item
        if (-not $ui.FilterInput.Text.Trim() -or ((@($item.GroupName,$item.Workload,$item.Name,$item.Assignment,$item.Intent,$item.Platform,$item.Filter) -join ' ') -like "*$($ui.FilterInput.Text.Trim())*")) { [void]$script:rows.Add($item) }
        $item = $null
    }
    $warning = $null
    while ($state.Warnings.TryDequeue([ref]$warning)) {
        [void]$script:warnings.Add([string]$warning)
        $warning = $null
    }
    $ui.SearchProgress.Maximum = [Math]::Max(1, [int]$state.Total)
    $ui.SearchProgress.Value = [Math]::Min([int]$state.Step, [int]$ui.SearchProgress.Maximum)
    $ui.ProgressText.Text = "$($state.Step) / $($state.Total) workloads"
    $ui.StatusText.Text = [string]$state.Message
    if ($state.GroupId -and $ui.GroupText.Text -ne "Group: $($state.GroupName)     ID: $($state.GroupId)") {
        $ui.GroupText.Text = "Group: $($state.GroupName)     ID: $($state.GroupId)"
    }
    $ui.CountText.Text = "$($script:rows.Count) shown / $($script:allRows.Count) found"
    if ($state.Done -or $script:handle.IsCompleted) {
        $script:progressTimer.Stop()
        try { $null = $script:pipeline.EndInvoke($script:handle) }
        catch { if (-not $state.Error) { $state.Error = Get-ErrorDescription $_ } }
        $script:pipeline.Dispose()
        $script:runspace.Dispose()
        $script:allRows = @($script:allRows | Sort-Object GroupName,Workload,Name,Assignment)
        Refresh-Grid
        $ui.WarningsText.Text = if ($script:warnings.Count) { $script:warnings -join [Environment]::NewLine } else { 'None' }
        if ($state.Error) {
            Update-Status "Search failed: $($state.Error)"
            [void][System.Windows.MessageBox]::Show([string]$state.Error,'Search failed','OK','Error')
        } else {
            $ui.SearchProgress.Value = $ui.SearchProgress.Maximum
            $ui.ProgressText.Text = 'Complete'
            Update-Status "Complete: $($script:allRows.Count) direct group assignments found; $($script:warnings.Count) query warnings."
            $ui.ExportButton.IsEnabled = $true
        }
        $script:working = $false
        $ui.SearchButton.IsEnabled = $true
    }
})
$ui.SearchButton.Add_Click({
    if ($script:working) { return }
    $inputText = $ui.GroupInput.Text.Trim()
    if (-not $inputText) { [void][System.Windows.MessageBox]::Show('Enter a group name or object ID.','Group required'); return }
    $script:working = $true
    $ui.SearchButton.IsEnabled = $false
    $ui.ExportButton.IsEnabled = $false
    if (-not $ui.RetainResults.IsChecked) {
        $script:allRows = @()
        $script:rows.Clear()
        $script:warnings.Clear()
        $ui.WarningsText.Text = 'None'
    }
    $ui.GroupText.Text = ''
    $ui.SearchProgress.Value = 0
    $ui.ProgressText.Text = 'Starting...'
    try {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            throw 'Required module is missing. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
        }
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        $scopes = @('Group.Read.All','DeviceManagementConfiguration.Read.All','DeviceManagementApps.Read.All','DeviceManagementScripts.Read.All','DeviceManagementServiceConfig.Read.All')
        $ctx = Get-MgContext
        $missing = @($scopes | Where-Object { -not $ctx -or $_ -notin $ctx.Scopes })
        if ($missing.Count -gt 0) {
            Update-Status 'Signing in to Microsoft Graph...'
            Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop | Out-Null
        }
        $script:state = [hashtable]::Synchronized(@{
            Step=0; Total=15; Message='Starting background query...'; Done=$false;
            GroupName=''; GroupId=''; Error='';
            Rows=[System.Collections.Concurrent.ConcurrentQueue[object]]::new();
            Warnings=[System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        })
        $script:runspace = [runspacefactory]::CreateRunspace()
        $script:runspace.Open()
        $script:pipeline = [powershell]::Create()
        $script:pipeline.Runspace = $script:runspace
        [void]$script:pipeline.AddScript($script:workerCode).AddArgument($inputText).AddArgument($script:state)
        $script:handle = $script:pipeline.BeginInvoke()
        $script:progressTimer.Start()
    } catch {
        Update-Status "Error: $(Get-ErrorDescription $_)"
        [void][System.Windows.MessageBox]::Show((Get-ErrorDescription $_),'Search failed','OK','Error')
        $script:working = $false
        $ui.SearchButton.IsEnabled = $true
    }
})
$ui.ExportButton.Add_Click({
    $dialog = [Microsoft.Win32.SaveFileDialog]::new()
    $dialog.Filter = 'CSV files (*.csv)|*.csv'
    $dialog.FileName = 'Intune-GroupAssignments.csv'
    if ($dialog.ShowDialog($window)) {
        try {
            $script:allRows | Select-Object GroupName,Workload,Name,Assignment,Intent,Platform,Filter,ObjectId,GroupId | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
            Update-Status "Exported $($script:allRows.Count) rows to $($dialog.FileName)"
        } catch { [System.Windows.MessageBox]::Show((Get-ErrorDescription $_),'Export failed','OK','Error') | Out-Null }
    }
})
[void]$window.ShowDialog()
