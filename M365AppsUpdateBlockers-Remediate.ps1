# Microsoft 365 Apps - Remediation
#
# Run in logged-on user context.
#
# FIRST PROCEED:
# - Outlook / Teams / OneNote / communication apps are closed automatically.
# - Word / Excel / PowerPoint / Visio / Project / Publisher:
#       Try Office COM.
#
#       Word / Excel / PowerPoint:
#           Saved=True -> safe to close
#           Saved=False + reliably read AutoSaveOn=True -> safe to close
#           Otherwise -> leave open
#
#       Visio / Project / Publisher:
#           Saved=True -> safe to close
#           Otherwise -> leave open
#
# SECOND PROCEED:
# - User has already been instructed to save work.
# - COM is retried.
# - Any protected Office apps still running receive a normal WM_CLOSE
#   through their visible top-level windows.
#
# Logging:
# %LOCALAPPDATA%\COMPANY\M365AppsUpdateRemediation.log

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore

$Title = "Microsoft 365 Apps update required"

# ============================================================
# Office ROT helper
#
# Excel:
# Microsoft documents sending WM_USER + 18 to Excel's XLMAIN
# window to force registration in the Running Object Table.
#
# Word:
# Microsoft documents that Office applications register in the
# ROT after their top-level window loses focus.
# ============================================================

$OfficeRotHelperSource = @'
using System;
using System.Runtime.InteropServices;

public static class OfficeRotHelper
{
    private const uint WM_USER = 0x0400;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SendMessage(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        IntPtr lParam
    );

    public static void RegisterExcelInROT(IntPtr hWnd)
    {
        SendMessage(
            hWnd,
            WM_USER + 18,
            IntPtr.Zero,
            IntPtr.Zero
        );
    }
}
'@

try {

    Add-Type `
        -TypeDefinition $OfficeRotHelperSource `
        -Language CSharp `
        -ErrorAction Stop
}
catch {

    if (
        -not (
            "OfficeRotHelper" -as [type]
        )
    ) {
        throw
    }
}

# ============================================================
# Window close helper
# ============================================================

$WindowCloseHelperSource = @'
using System;
using System.Runtime.InteropServices;

public static class WindowCloseHelper
{
    private const uint WM_CLOSE = 0x0010;

    private delegate bool EnumWindowsProc(
        IntPtr hWnd,
        IntPtr lParam
    );

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(
        EnumWindowsProc lpEnumFunc,
        IntPtr lParam
    );

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(
        IntPtr hWnd,
        out uint lpdwProcessId
    );

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(
        IntPtr hWnd
    );

    [DllImport("user32.dll")]
    private static extern bool PostMessage(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        IntPtr lParam
    );

    public static int CloseVisibleWindowsForProcess(
        int processId
    )
    {
        int count = 0;

        EnumWindows(
            delegate(IntPtr hWnd, IntPtr lParam)
            {
                uint windowProcessId;

                GetWindowThreadProcessId(
                    hWnd,
                    out windowProcessId
                );

                if (
                    windowProcessId == processId &&
                    IsWindowVisible(hWnd)
                )
                {
                    if (
                        PostMessage(
                            hWnd,
                            WM_CLOSE,
                            IntPtr.Zero,
                            IntPtr.Zero
                        )
                    )
                    {
                        count++;
                    }
                }

                return true;
            },
            IntPtr.Zero
        );

        return count;
    }
}
'@

try {

    Add-Type `
        -TypeDefinition $WindowCloseHelperSource `
        -Language CSharp `
        -ErrorAction Stop
}
catch {

    if (
        -not (
            "WindowCloseHelper" -as [type]
        )
    ) {
        throw
    }
}

# ============================================================
# Paths
# ============================================================

$BaseFolder =
    Join-Path `
        $env:LOCALAPPDATA `
        "COMPANY"

$StateFolder =
    Join-Path `
        $BaseFolder `
        "M365AppsUpdate"

$StateFile =
    Join-Path `
        $StateFolder `
        "RemediationStarted.txt"

$LogFile =
    Join-Path `
        $BaseFolder `
        "M365AppsUpdateRemediation.log"

try {

    if (-not (Test-Path $BaseFolder)) {

        New-Item `
            -Path $BaseFolder `
            -ItemType Directory `
            -Force |
            Out-Null
    }
}
catch {
}

# ============================================================
# Logging
# ============================================================

function Write-Log {

    param (
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet(
            "INFO",
            "WARNING",
            "ERROR"
        )]
        [string]$Level = "INFO"
    )

    $Timestamp =
        Get-Date `
            -Format "yyyy-MM-dd HH:mm:ss"

    $Line =
        "$Timestamp [$Level] $Message"

    Write-Host $Line

    try {

        Add-Content `
            -Path $LogFile `
            -Value $Line `
            -Encoding UTF8 `
            -ErrorAction Stop
    }
    catch {
    }
}

Write-Log "============================================================"
Write-Log "Microsoft 365 Apps remediation started."
Write-Log "User: $env:USERNAME"
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "Log file: $LogFile"

# Diagnostic information

Write-Log "PowerShell PID: $PID"
Write-Log "PowerShell 64-bit: $([Environment]::Is64BitProcess)"
Write-Log "OS 64-bit: $([Environment]::Is64BitOperatingSystem)"
Write-Log "PowerShell Session ID: $((Get-Process -Id $PID).SessionId)"

foreach ($Name in @("WINWORD","EXCEL","POWERPNT","OUTLOOK")) {

    Get-Process `
        -Name $Name `
        -ErrorAction SilentlyContinue |
        ForEach-Object {

            $_.Refresh()

            Write-Log "$Name PID=$($_.Id) SessionId=$($_.SessionId) MainWindowHandle=$($_.MainWindowHandle) MainWindowTitle='$($_.MainWindowTitle)'"
        }
}

# ============================================================
# Protected applications
# ============================================================

$ProtectedApplications = [ordered]@{

    "WINWORD"  = "Microsoft Word"
    "EXCEL"    = "Microsoft Excel"
    "POWERPNT" = "Microsoft PowerPoint"
    "MSACCESS" = "Microsoft Access"
    "MSPUB"    = "Microsoft Publisher"
    "VISIO"    = "Microsoft Visio"
    "WINPROJ"  = "Microsoft Project"
}

# ============================================================
# Office COM applications
# ============================================================

$OfficeComApplications = [ordered]@{

    "WINWORD"  = "Word.Application"
    "EXCEL"    = "Excel.Application"
    "POWERPNT" = "PowerPoint.Application"
    "MSPUB"    = "Publisher.Application"
    "VISIO"    = "Visio.Application"
    "WINPROJ"  = "MSProject.Application"
}

# ============================================================
# Applications always closed automatically
# ============================================================

$AutoCloseProcesses = @(

    "OUTLOOK",
    "olk",

    "ONENOTE",
    "ONENOTEM",
    "ONENOTEIM",

    "Teams",
    "ms-teams",
    "ms-teamsupdate",
    "msteams_autostarter",

    "lync",
    "communicator",
    "skype"
)

# ============================================================
# Background/helper processes
# ============================================================

$BackgroundProcesses = @(

    "msoadfsb",
    "msoasb",
    "ucmapi",
    "lynchtmlconv",
    "msosync",
    "namecontrolserver",
    "perfboost",
    "groove",
    "msoia",
    "officebackgroundtaskhandler",
    "sdxhelper",
    "ai",
    "aimgr",
    "operfmon",
    "filecoauth"
)

# ============================================================
# Get protected applications currently running
# ============================================================

function Get-RunningProtectedApplications {

    $Running = @()

    foreach (
        $ProcessName in
        $ProtectedApplications.Keys
    ) {

        $Processes =
            Get-Process `
                -Name $ProcessName `
                -ErrorAction SilentlyContinue

        if ($Processes) {

            $Running +=
                [PSCustomObject]@{

                    ProcessName =
                        $ProcessName

                    DisplayName =
                        $ProtectedApplications[$ProcessName]
                }
        }
    }

    return $Running |
        Sort-Object `
            DisplayName,
            ProcessName `
            -Unique
}

# ============================================================
# Send normal WM_CLOSE
# ============================================================

function Request-WindowClose {

    param (
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process
    )

    try {

        $WindowCount =
            [WindowCloseHelper]::CloseVisibleWindowsForProcess(
                $Process.Id
            )

        if ($WindowCount -gt 0) {

            Write-Log `
                "Sent WM_CLOSE to $WindowCount visible window(s) for $($Process.ProcessName) PID $($Process.Id)."

            return $true
        }

        Write-Log `
            "No visible top-level windows found for $($Process.ProcessName) PID $($Process.Id)." `
            "WARNING"

        return $false
    }
    catch {

        Write-Log `
            "WM_CLOSE failed for $($Process.ProcessName) PID $($Process.Id): $($_.Exception.Message)" `
            "WARNING"

        return $false
    }
}

# ============================================================
# Always-close applications
# ============================================================

function Stop-AutoCloseApps {

    Write-Log `
        "Checking automatically closed applications."

    foreach (
        $ProcessName in
        $AutoCloseProcesses
    ) {

        $Processes =
            @(
                Get-Process `
                    -Name $ProcessName `
                    -ErrorAction SilentlyContinue
            )

        foreach ($Process in $Processes) {

            try {

                Write-Log `
                    "Stopping auto-close process $($Process.ProcessName) PID $($Process.Id)."

                Stop-Process `
                    -Id $Process.Id `
                    -Force `
                    -ErrorAction Stop

                Write-Log `
                    "Stopped auto-close process $($Process.ProcessName) PID $($Process.Id)."
            }
            catch {

                Write-Log `
                    "Could not force-stop auto-close process $($Process.ProcessName) PID $($Process.Id): $($_.Exception.Message). Trying WM_CLOSE." `
                    "WARNING"

                [void](
                    Request-WindowClose `
                        -Process $Process
                )
            }
        }
    }
}

# ============================================================
# Obtain Office COM object
#
# THIS IS THE NEW PART.
#
# Excel:
# - Explicitly asks Excel to register in ROT using WM_USER+18.
#
# Word:
# - Temporarily gives focus to a tiny off-screen WPF window.
# - This makes Word lose focus while GetActiveObject is attempted.
#
# Other Office apps:
# - Normal GetActiveObject.
# ============================================================

function Get-OfficeActiveObject {

    param (
        [Parameter(Mandatory)]
        [string]$ProcessName,

        [Parameter(Mandatory)]
        [string]$ProgId
    )

    $FocusWindow = $null

    try {

        # ----------------------------------------------------
        # Excel ROT registration
        # ----------------------------------------------------

        if ($ProcessName -eq "EXCEL") {

            $ExcelProcesses =
                @(
                    Get-Process `
                        -Name "EXCEL" `
                        -ErrorAction SilentlyContinue
                )

            foreach ($ExcelProcess in $ExcelProcesses) {

                try {

                    $ExcelProcess.Refresh()

                    $Hwnd =
                        [IntPtr]$ExcelProcess.MainWindowHandle

                    if ($Hwnd -ne [IntPtr]::Zero) {

                        Write-Log `
                            "Requesting Excel ROT registration for PID $($ExcelProcess.Id), HWND $Hwnd using WM_USER+18."

                        [OfficeRotHelper]::RegisterExcelInROT(
                            $Hwnd
                        )

                        Write-Log `
                            "Excel ROT registration message sent to PID $($ExcelProcess.Id)."
                    }
                    else {

                        Write-Log `
                            "Excel PID $($ExcelProcess.Id) has no MainWindowHandle; ROT registration message cannot be sent." `
                            "WARNING"
                    }
                }
                catch {

                    Write-Log `
                        "Could not request Excel ROT registration for PID $($ExcelProcess.Id): $($_.Exception.Message)" `
                        "WARNING"
                }
            }

            Start-Sleep `
                -Milliseconds 750
        }

        # ----------------------------------------------------
        # Word focus-loss ROT registration
        # ----------------------------------------------------

        if ($ProcessName -eq "WINWORD") {

            Write-Log `
                "Creating temporary focus window to make Word lose focus and register in the ROT."

            try {

                $FocusWindow =
                    New-Object System.Windows.Window

                $FocusWindow.Width =
                    1

                $FocusWindow.Height =
                    1

                $FocusWindow.Left =
                    -32000

                $FocusWindow.Top =
                    -32000

                $FocusWindow.ShowInTaskbar =
                    $false

                $FocusWindow.WindowStyle =
                    "None"

                $FocusWindow.ResizeMode =
                    "NoResize"

                $FocusWindow.Topmost =
                    $true

                $FocusWindow.Show()

                [void]$FocusWindow.Activate()

                Start-Sleep `
                    -Milliseconds 750

                Write-Log `
                    "Temporary focus window activated; Word should now have lost focus."
            }
            catch {

                Write-Log `
                    "Could not create Word focus-loss window: $($_.Exception.Message)" `
                    "WARNING"
            }
        }

        # ----------------------------------------------------
        # Get COM object from ROT
        # ----------------------------------------------------

        Write-Log `
            "Calling GetActiveObject('$ProgId')."

        $Application =
            [Runtime.InteropServices.Marshal]::GetActiveObject(
                $ProgId
            )

        Write-Log `
            "GetActiveObject succeeded for $ProcessName."

        return $Application
    }
    finally {

        if ($null -ne $FocusWindow) {

            try {

                $FocusWindow.Close()

                Write-Log `
                    "Temporary Word focus window closed."
            }
            catch {
            }
        }
    }
}

# ============================================================
# Saved / AutoSave test
#
# MUST return only Boolean.
# ============================================================

function Test-OfficeApplicationSafeToQuit {

    param (
        [Parameter(Mandatory)]
        [string]$ProcessName,

        [Parameter(Mandatory)]
        $Application
    )

    try {

        switch ($ProcessName) {

            # ------------------------------------------------
            # Word
            # ------------------------------------------------

            "WINWORD" {

                foreach (
                    $Document in
                    $Application.Documents
                ) {

                    $Saved =
                        [bool]$Document.Saved

                    Write-Log `
                        "Word document '$($Document.Name)': Saved=$Saved"

                    if ($Saved) {

                        continue
                    }

                    $AutoSaveReadSucceeded =
                        $false

                    $AutoSaveOn =
                        $false

                    try {

                        $AutoSaveOn =
                            [bool]$Document.AutoSaveOn

                        $AutoSaveReadSucceeded =
                            $true

                        Write-Log `
                            "Word document '$($Document.Name)': AutoSaveOn=$AutoSaveOn (property read succeeded)."
                    }
                    catch {

                        Write-Log `
                            "Word document '$($Document.Name)': Could not reliably read AutoSaveOn: $($_.Exception.Message)" `
                            "WARNING"
                    }

                    if (
                        $AutoSaveReadSucceeded -and
                        $AutoSaveOn
                    ) {

                        Write-Log `
                            "Word document '$($Document.Name)' reports Saved=False, but AutoSaveOn=True. Treating document as safe to close."

                        continue
                    }

                    Write-Log `
                        "Word document '$($Document.Name)' is not confirmed safe to close." `
                        "WARNING"

                    return $false
                }

                return $true
            }

            # ------------------------------------------------
            # Excel
            # ------------------------------------------------

            "EXCEL" {

                foreach (
                    $Workbook in
                    $Application.Workbooks
                ) {

                    $Saved =
                        [bool]$Workbook.Saved

                    Write-Log `
                        "Excel workbook '$($Workbook.Name)': Saved=$Saved"

                    if ($Saved) {

                        continue
                    }

                    $AutoSaveReadSucceeded =
                        $false

                    $AutoSaveOn =
                        $false

                    try {

                        $AutoSaveOn =
                            [bool]$Workbook.AutoSaveOn

                        $AutoSaveReadSucceeded =
                            $true

                        Write-Log `
                            "Excel workbook '$($Workbook.Name)': AutoSaveOn=$AutoSaveOn (property read succeeded)."
                    }
                    catch {

                        Write-Log `
                            "Excel workbook '$($Workbook.Name)': Could not reliably read AutoSaveOn: $($_.Exception.Message)" `
                            "WARNING"
                    }

                    if (
                        $AutoSaveReadSucceeded -and
                        $AutoSaveOn
                    ) {

                        Write-Log `
                            "Excel workbook '$($Workbook.Name)' reports Saved=False, but AutoSaveOn=True. Treating workbook as safe to close."

                        continue
                    }

                    Write-Log `
                        "Excel workbook '$($Workbook.Name)' is not confirmed safe to close." `
                        "WARNING"

                    return $false
                }

                return $true
            }

            # ------------------------------------------------
            # PowerPoint
            # ------------------------------------------------

            "POWERPNT" {

                foreach (
                    $Presentation in
                    $Application.Presentations
                ) {

                    $Saved =
                        (
                            [int]$Presentation.Saved `
                            -eq -1
                        )

                    Write-Log `
                        "PowerPoint presentation '$($Presentation.Name)': Saved=$Saved"

                    if ($Saved) {

                        continue
                    }

                    $AutoSaveReadSucceeded =
                        $false

                    $AutoSaveOn =
                        $false

                    try {

                        $AutoSaveOn =
                            [bool]$Presentation.AutoSaveOn

                        $AutoSaveReadSucceeded =
                            $true

                        Write-Log `
                            "PowerPoint presentation '$($Presentation.Name)': AutoSaveOn=$AutoSaveOn (property read succeeded)."
                    }
                    catch {

                        Write-Log `
                            "PowerPoint presentation '$($Presentation.Name)': Could not reliably read AutoSaveOn: $($_.Exception.Message)" `
                            "WARNING"
                    }

                    if (
                        $AutoSaveReadSucceeded -and
                        $AutoSaveOn
                    ) {

                        Write-Log `
                            "PowerPoint presentation '$($Presentation.Name)' reports Saved=False, but AutoSaveOn=True. Treating presentation as safe to close."

                        continue
                    }

                    Write-Log `
                        "PowerPoint presentation '$($Presentation.Name)' is not confirmed safe to close." `
                        "WARNING"

                    return $false
                }

                return $true
            }

            # ------------------------------------------------
            # Visio
            # ------------------------------------------------

            "VISIO" {

                foreach (
                    $Document in
                    $Application.Documents
                ) {

                    $Saved =
                        [bool]$Document.Saved

                    Write-Log `
                        "Visio document '$($Document.Name)': Saved=$Saved"

                    if (-not $Saved) {

                        Write-Log `
                            "Visio document '$($Document.Name)' contains unsaved changes." `
                            "WARNING"

                        return $false
                    }
                }

                return $true
            }

            # ------------------------------------------------
            # Project
            # ------------------------------------------------

            "WINPROJ" {

                foreach (
                    $Project in
                    $Application.Projects
                ) {

                    $Saved =
                        [bool]$Project.Saved

                    Write-Log `
                        "Project '$($Project.Name)': Saved=$Saved"

                    if (-not $Saved) {

                        Write-Log `
                            "Project '$($Project.Name)' contains unsaved changes." `
                            "WARNING"

                        return $false
                    }
                }

                return $true
            }

            # ------------------------------------------------
            # Publisher
            # ------------------------------------------------

            "MSPUB" {

                foreach (
                    $Document in
                    $Application.Documents
                ) {

                    $Saved =
                        [bool]$Document.Saved

                    Write-Log `
                        "Publisher document '$($Document.Name)': Saved=$Saved"

                    if (-not $Saved) {

                        Write-Log `
                            "Publisher document '$($Document.Name)' contains unsaved changes." `
                            "WARNING"

                        return $false
                    }
                }

                return $true
            }

            default {

                return $false
            }
        }
    }
    catch {

        Write-Log `
            "Could not determine saved state for $ProcessName`: $($_.Exception.Message)" `
            "WARNING"

        return $false
    }
}

# ============================================================
# Safe Office COM close
# ============================================================

function Invoke-SafeOfficeComQuit {

    Write-Log `
        "Starting safe Office COM Quit checks."

    foreach (
        $ProcessName in
        $OfficeComApplications.Keys
    ) {

        $Processes =
            @(
                Get-Process `
                    -Name $ProcessName `
                    -ErrorAction SilentlyContinue
            )

        if ($Processes.Count -eq 0) {

            continue
        }

        $ProgId =
            $OfficeComApplications[$ProcessName]

        $Application =
            $null

        try {

            Write-Log `
                "Connecting to $ProcessName using COM ProgID '$ProgId'."

            $Application =
                Get-OfficeActiveObject `
                    -ProcessName $ProcessName `
                    -ProgId $ProgId

            Write-Log `
                "COM connection obtained for $ProcessName."

            [bool]$SafeToQuit =
                Test-OfficeApplicationSafeToQuit `
                    -ProcessName $ProcessName `
                    -Application $Application

            Write-Log `
                "$ProcessName SafeToQuit result: $SafeToQuit"

            if (-not $SafeToQuit) {

                Write-Log `
                    "$ProcessName will remain open because unsaved work exists or state could not be verified." `
                    "WARNING"

                continue
            }

            Write-Log `
                "$ProcessName is confirmed safe to close."

            $Application.Quit()

            Write-Log `
                "COM Quit requested successfully for $ProcessName."
        }
        catch {

            Write-Log `
                "COM access/close failed for $ProcessName using '$ProgId': $($_.Exception.Message). Application will remain open for the user prompt." `
                "WARNING"
        }
        finally {

            if ($null -ne $Application) {

                try {

                    if (
                        [Runtime.InteropServices.Marshal]::IsComObject(
                            $Application
                        )
                    ) {

                        [void][Runtime.InteropServices.Marshal]::ReleaseComObject(
                            $Application
                        )
                    }
                }
                catch {
                }
            }

            $Application =
                $null
        }
    }

    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}

# ============================================================
# Second-stage protected application close
# ============================================================

function Invoke-SecondStageProtectedClose {

    Write-Log `
        "Starting second-stage protected application close."

    Invoke-SafeOfficeComQuit

    Start-Sleep `
        -Seconds 2

    $RunningApplications =
        @(
            Get-RunningProtectedApplications
        )

    foreach (
        $Application in
        $RunningApplications
    ) {

        $Processes =
            @(
                Get-Process `
                    -Name $Application.ProcessName `
                    -ErrorAction SilentlyContinue
            )

        foreach ($Process in $Processes) {

            Write-Log `
                "Protected application $($Application.DisplayName) is still running. Sending normal WM_CLOSE to PID $($Process.Id)."

            [void](
                Request-WindowClose `
                    -Process $Process
            )
        }
    }
}

# ============================================================
# Initial dialog
# ============================================================

function Show-InitialDialog {

    Write-Log `
        "Showing initial user prompt."

    $Window =
        New-Object System.Windows.Window

    $Window.Title =
        $Title

    $Window.Width =
        640

    $Window.Height =
        500

    $Window.MinWidth =
        640

    $Window.MinHeight =
        500

    $Window.WindowStartupLocation =
        "CenterScreen"

    $Window.ResizeMode =
        "NoResize"

    $Window.Topmost =
        $true

    $Grid =
        New-Object System.Windows.Controls.Grid

    $Grid.Margin =
        "26"

    $ContentRow =
        New-Object System.Windows.Controls.RowDefinition

    $ContentRow.Height =
        New-Object System.Windows.GridLength(
            1,
            [System.Windows.GridUnitType]::Star
        )

    $ButtonRow =
        New-Object System.Windows.Controls.RowDefinition

    $ButtonRow.Height =
        [System.Windows.GridLength]::Auto

    $Grid.RowDefinitions.Add(
        $ContentRow
    )

    $Grid.RowDefinitions.Add(
        $ButtonRow
    )

    $ContentPanel =
        New-Object System.Windows.Controls.StackPanel

    $Headline =
        New-Object System.Windows.Controls.TextBlock

    $Headline.Text =
        "Microsoft 365 Apps need to complete an update"

    $Headline.FontSize =
        20

    $Headline.FontWeight =
        "Bold"

    $Headline.Margin =
        "0,0,0,24"

    $null =
        $ContentPanel.Children.Add(
            $Headline
        )

    $Paragraph1 =
        New-Object System.Windows.Controls.TextBlock

    $Paragraph1.TextWrapping =
        "Wrap"

    $Paragraph1.FontSize =
        14

    $Paragraph1.LineHeight =
        22

    $Paragraph1.Margin =
        "0,0,0,22"

    $Paragraph1.Text = @"
Microsoft 365 Apps need to close running Office applications before the update can continue.
"@

    $null =
        $ContentPanel.Children.Add(
            $Paragraph1
        )

    $Paragraph2 =
        New-Object System.Windows.Controls.TextBlock

    $Paragraph2.TextWrapping =
        "Wrap"

    $Paragraph2.FontSize =
        14

    $Paragraph2.LineHeight =
        22

    $Paragraph2.Margin =
        "0,0,0,22"

    $BoldSave =
        New-Object System.Windows.Documents.Bold

    $BoldSave.Inlines.Add(
        (
            New-Object System.Windows.Documents.Run(
                "Please save your work before continuing."
            )
        )
    )

    $Paragraph2.Inlines.Add(
        $BoldSave
    )

    $null =
        $ContentPanel.Children.Add(
            $Paragraph2
        )

    $Paragraph3 =
        New-Object System.Windows.Controls.TextBlock

    $Paragraph3.TextWrapping =
        "Wrap"

    $Paragraph3.FontSize =
        14

    $Paragraph3.LineHeight =
        22

    $Paragraph3.Margin =
        "0,0,0,22"

    $Paragraph3.Text = @"
When you click "Proceed", Microsoft 365 will attempt to close applications that are safe to close. Applications containing unsaved work will remain open so that you can save them.
"@

    $null =
        $ContentPanel.Children.Add(
            $Paragraph3
        )

    $Paragraph4 =
        New-Object System.Windows.Controls.TextBlock

    $Paragraph4.TextWrapping =
        "Wrap"

    $Paragraph4.FontSize =
        14

    $Paragraph4.LineHeight =
        22

    $Paragraph4.Text = @"
If you are not ready, click "Postpone". You will be prompted again during the next scheduled check.
"@

    $null =
        $ContentPanel.Children.Add(
            $Paragraph4
        )

    [System.Windows.Controls.Grid]::SetRow(
        $ContentPanel,
        0
    )

    $null =
        $Grid.Children.Add(
            $ContentPanel
        )

    $ButtonPanel =
        New-Object System.Windows.Controls.StackPanel

    $ButtonPanel.Orientation =
        "Horizontal"

    $ButtonPanel.HorizontalAlignment =
        "Right"

    $ButtonPanel.Margin =
        "0,24,0,0"

    $PostponeButton =
        New-Object System.Windows.Controls.Button

    $PostponeButton.Content =
        "Postpone"

    $PostponeButton.Width =
        120

    $PostponeButton.Height =
        38

    $PostponeButton.Margin =
        "0,0,12,0"

    $PostponeButton.IsCancel =
        $true

    $ProceedButton =
        New-Object System.Windows.Controls.Button

    $ProceedButton.Content =
        "Proceed"

    $ProceedButton.Width =
        120

    $ProceedButton.Height =
        38

    $ProceedButton.IsDefault =
        $true

    $null =
        $ButtonPanel.Children.Add(
            $PostponeButton
        )

    $null =
        $ButtonPanel.Children.Add(
            $ProceedButton
        )

    [System.Windows.Controls.Grid]::SetRow(
        $ButtonPanel,
        1
    )

    $null =
        $Grid.Children.Add(
            $ButtonPanel
        )

    $Window.Content =
        $Grid

    $Script:DialogResult =
        "Postpone"

    $PostponeButton.Add_Click({

        $Script:DialogResult =
            "Postpone"

        $Window.Close()
    })

    $ProceedButton.Add_Click({

        $Script:DialogResult =
            "Proceed"

        $Window.Close()
    })

    $null =
        $Window.ShowDialog()

    Write-Log `
        "Initial prompt result: $Script:DialogResult"

    return $Script:DialogResult
}

# ============================================================
# Remaining applications dialog
# ============================================================

function Show-RemainingAppsDialog {

    param (
        [Parameter(Mandatory)]
        [array]$RunningApplications
    )

    $Names =
        $RunningApplications.DisplayName |
        Sort-Object -Unique

    Write-Log `
        "Showing remaining-applications prompt for: $($Names -join ', ')"

    $Window =
        New-Object System.Windows.Window

    $Window.Title =
        $Title

    $Window.Width =
        640

    $Window.Height =
        500

    $Window.MinWidth =
        640

    $Window.MinHeight =
        500

    $Window.WindowStartupLocation =
        "CenterScreen"

    $Window.ResizeMode =
        "NoResize"

    $Window.Topmost =
        $true

    $Grid =
        New-Object System.Windows.Controls.Grid

    $Grid.Margin =
        "26"

    $ContentRow =
        New-Object System.Windows.Controls.RowDefinition

    $ContentRow.Height =
        New-Object System.Windows.GridLength(
            1,
            [System.Windows.GridUnitType]::Star
        )

    $ButtonRow =
        New-Object System.Windows.Controls.RowDefinition

    $ButtonRow.Height =
        [System.Windows.GridLength]::Auto

    $Grid.RowDefinitions.Add(
        $ContentRow
    )

    $Grid.RowDefinitions.Add(
        $ButtonRow
    )

    $ContentPanel =
        New-Object System.Windows.Controls.StackPanel

    $Headline =
        New-Object System.Windows.Controls.TextBlock

    $Headline.Text =
        "Microsoft 365 applications are still open"

    $Headline.FontSize =
        20

    $Headline.FontWeight =
        "Bold"

    $Headline.Margin =
        "0,0,0,20"

    $null =
        $ContentPanel.Children.Add(
            $Headline
        )

    $Intro =
        New-Object System.Windows.Controls.TextBlock

    $Intro.TextWrapping =
        "Wrap"

    $Intro.FontSize =
        14

    $Intro.LineHeight =
        22

    $Intro.Margin =
        "0,0,0,16"

    $Intro.Text = @"
The following applications could not be closed automatically:
"@

    $null =
        $ContentPanel.Children.Add(
            $Intro
        )

    $AppBorder =
        New-Object System.Windows.Controls.Border

    $AppBorder.BorderBrush =
        [System.Windows.Media.Brushes]::LightGray

    $AppBorder.BorderThickness =
        "1"

    $AppBorder.Padding =
        "14"

    $AppBorder.Margin =
        "0,0,0,20"

    $AppPanel =
        New-Object System.Windows.Controls.StackPanel

    foreach (
        $Application in
        (
            $RunningApplications |
            Sort-Object DisplayName -Unique
        )
    ) {

        $AppText =
            New-Object System.Windows.Controls.TextBlock

        $AppText.Text =
            $Application.DisplayName

        $AppText.FontSize =
            14

        $AppText.FontWeight =
            "Bold"

        $AppText.Margin =
            "0,3,0,3"

        $null =
            $AppPanel.Children.Add(
                $AppText
            )
    }

    $AppBorder.Child =
        $AppPanel

    $null =
        $ContentPanel.Children.Add(
            $AppBorder
        )

    $Warning =
        New-Object System.Windows.Controls.TextBlock

    $Warning.TextWrapping =
        "Wrap"

    $Warning.FontSize =
        14

    $Warning.LineHeight =
        22

    $Warning.Margin =
        "0,0,0,18"

    $BoldWarning =
        New-Object System.Windows.Documents.Bold

    $BoldWarning.Inlines.Add(
        (
            New-Object System.Windows.Documents.Run(
                "Please save your work and close the applications listed above manually."
            )
        )
    )

    $Warning.Inlines.Add(
        $BoldWarning
    )

    $null =
        $ContentPanel.Children.Add(
            $Warning
        )

    $Explanation =
        New-Object System.Windows.Controls.TextBlock

    $Explanation.TextWrapping =
        "Wrap"

    $Explanation.FontSize =
        14

    $Explanation.LineHeight =
        22

    $Explanation.Text = @"
When your work has been saved, click "Proceed" to continue.

If you are not ready, click "Postpone". You will be prompted again during the next scheduled check.
"@

    $null =
        $ContentPanel.Children.Add(
            $Explanation
        )

    [System.Windows.Controls.Grid]::SetRow(
        $ContentPanel,
        0
    )

    $null =
        $Grid.Children.Add(
            $ContentPanel
        )

    $ButtonPanel =
        New-Object System.Windows.Controls.StackPanel

    $ButtonPanel.Orientation =
        "Horizontal"

    $ButtonPanel.HorizontalAlignment =
        "Right"

    $ButtonPanel.Margin =
        "0,24,0,0"

    $PostponeButton =
        New-Object System.Windows.Controls.Button

    $PostponeButton.Content =
        "Postpone"

    $PostponeButton.Width =
        120

    $PostponeButton.Height =
        38

    $PostponeButton.Margin =
        "0,0,12,0"

    $PostponeButton.IsCancel =
        $true

    $ProceedButton =
        New-Object System.Windows.Controls.Button

    $ProceedButton.Content =
        "Proceed"

    $ProceedButton.Width =
        120

    $ProceedButton.Height =
        38

    $ProceedButton.IsDefault =
        $true

    $null =
        $ButtonPanel.Children.Add(
            $PostponeButton
        )

    $null =
        $ButtonPanel.Children.Add(
            $ProceedButton
        )

    [System.Windows.Controls.Grid]::SetRow(
        $ButtonPanel,
        1
    )

    $null =
        $Grid.Children.Add(
            $ButtonPanel
        )

    $Window.Content =
        $Grid

    $Script:DialogResult =
        "Postpone"

    $PostponeButton.Add_Click({

        $Script:DialogResult =
            "Postpone"

        $Window.Close()
    })

    $ProceedButton.Add_Click({

        $Script:DialogResult =
            "Proceed"

        $Window.Close()
    })

    $null =
        $Window.ShowDialog()

    Write-Log `
        "Remaining-applications prompt result: $Script:DialogResult"

    return $Script:DialogResult
}

# ============================================================
# Initial prompt
# ============================================================

$Result =
    Show-InitialDialog

if ($Result -eq "Postpone") {

    Write-Log `
        "User postponed Microsoft 365 Apps servicing."

    exit 0
}

Write-Log `
    "User chose Proceed on initial prompt."

# ============================================================
# First shutdown attempt
# ============================================================

Stop-AutoCloseApps

Invoke-SafeOfficeComQuit

Write-Log `
    "Waiting 5 seconds after safe Office close attempt."

Start-Sleep `
    -Seconds 5

# ============================================================
# Remaining protected applications
# ============================================================

while ($true) {

    $RunningApplications =
        @(
            Get-RunningProtectedApplications
        )

    if (
        $RunningApplications.Count `
        -eq 0
    ) {

        Write-Log `
            "No protected Microsoft 365 applications remain open."

        break
    }

    $ApplicationNames =
        $RunningApplications.DisplayName |
        Sort-Object -Unique

    Write-Log `
        "Protected applications still running: $($ApplicationNames -join ', ')"

    $Result =
        Show-RemainingAppsDialog `
            -RunningApplications $RunningApplications

    if (
        $Result `
        -eq "Postpone"
    ) {

        Write-Log `
            "User postponed Microsoft 365 Apps servicing."

        exit 0
    }

    Write-Log `
        "User chose Proceed on remaining-applications prompt."

    Stop-AutoCloseApps

    Invoke-SecondStageProtectedClose

    Write-Log `
        "Waiting 5 seconds before checking protected applications again."

    Start-Sleep `
        -Seconds 5
}

# ============================================================
# Final auto-close cleanup
# ============================================================

Stop-AutoCloseApps

# ============================================================
# Stop Office helper processes
# ============================================================

Write-Log `
    "Stopping Office background/helper processes."

foreach (
    $ProcessName in
    $BackgroundProcesses
) {

    $Processes =
        Get-Process `
            -Name $ProcessName `
            -ErrorAction SilentlyContinue

    foreach ($Process in $Processes) {

        try {

            Write-Log `
                "Stopping background process $($Process.ProcessName) PID $($Process.Id)."

            Stop-Process `
                -Id $Process.Id `
                -Force `
                -ErrorAction Stop

            Write-Log `
                "Stopped background process $($Process.ProcessName) PID $($Process.Id)."
        }
        catch {

            Write-Log `
                "Could not stop background process $($Process.ProcessName) PID $($Process.Id): $($_.Exception.Message)" `
                "WARNING"
        }
    }
}

Start-Sleep `
    -Seconds 3

# ============================================================
# Final protected-app check
# ============================================================

while ($true) {

    $RunningApplications =
        @(
            Get-RunningProtectedApplications
        )

    if (
        $RunningApplications.Count `
        -eq 0
    ) {

        Write-Log `
            "Final protected-application check passed."

        break
    }

    $ApplicationNames =
        $RunningApplications.DisplayName |
        Sort-Object -Unique

    Write-Log `
        "Protected application reopened or remained active: $($ApplicationNames -join ', ')" `
        "WARNING"

    $Result =
        Show-RemainingAppsDialog `
            -RunningApplications $RunningApplications

    if (
        $Result `
        -eq "Postpone"
    ) {

        Write-Log `
            "User postponed during final protected-application check."

        exit 0
    }

    Stop-AutoCloseApps

    Invoke-SecondStageProtectedClose

    Start-Sleep `
        -Seconds 5
}

# ============================================================
# Final auto-close pass
# ============================================================

Stop-AutoCloseApps

Start-Sleep `
    -Seconds 2

# ============================================================
# Locate Click-to-Run
# ============================================================

Write-Log `
    "Locating OfficeC2RClient.exe."

$C2RPaths = @(

    "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe",

    "${env:ProgramFiles(x86)}\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
)

$C2RClient =
    $C2RPaths |
    Where-Object {

        $_ -and
        (Test-Path $_)
    } |
    Select-Object `
        -First 1

if (-not $C2RClient) {

    Write-Log `
        "OfficeC2RClient.exe not found." `
        "ERROR"

    [System.Windows.MessageBox]::Show(
        "Microsoft Office Click-to-Run could not be found.`n`nPlease contact IT.",
        $Title,
        "OK",
        "Error"
    )

    exit 1
}

Write-Log `
    "OfficeC2RClient.exe found: $C2RClient"

# ============================================================
# Create cooldown marker
# ============================================================

try {

    if (
        -not (
            Test-Path $StateFolder
        )
    ) {

        New-Item `
            -Path $StateFolder `
            -ItemType Directory `
            -Force |
            Out-Null

        Write-Log `
            "Created state folder: $StateFolder"
    }

    (Get-Date).ToString("o") |
        Set-Content `
            -Path $StateFile `
            -Encoding UTF8 `
            -Force

    Write-Log `
        "Created remediation cooldown marker: $StateFile"
}
catch {

    Write-Log `
        "Could not create remediation cooldown marker: $($_.Exception.Message)" `
        "WARNING"
}

# ============================================================
# Start Click-to-Run servicing
# ============================================================

try {

    Write-Log `
        "Starting Microsoft 365 Apps Click-to-Run servicing with /update user."

    Start-Process `
        -FilePath $C2RClient `
        -ArgumentList "/update user" `
        -WindowStyle Hidden `
        -ErrorAction Stop

    Write-Log `
        "OfficeC2RClient.exe started successfully."
}
catch {

    Write-Log `
        "Failed to start OfficeC2RClient.exe: $($_.Exception.Message)" `
        "ERROR"

    Remove-Item `
        -Path $StateFile `
        -Force `
        -ErrorAction SilentlyContinue

    [System.Windows.MessageBox]::Show(
        "The Microsoft 365 Apps update could not be started.`n`nPlease contact IT.",
        $Title,
        "OK",
        "Error"
    )

    exit 1
}

# ============================================================
# Confirmation
# ============================================================

[System.Windows.MessageBox]::Show(
    "The Microsoft 365 Apps update has been started.`n`nPlease wait a few minutes before reopening Outlook, Word, Excel, Teams or other Microsoft 365 applications.",
    $Title,
    "OK",
    "Information"
)

Write-Log `
    "Microsoft 365 Apps servicing initiated successfully."

Write-Log `
    "Remediation completed."

Write-Log `
    "============================================================"

exit 0