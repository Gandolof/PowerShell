# This script creates a Windows Form with buttons to run specified executables.
# Each button corresponds to an executable defined in the $executables array.
# The buttons are arranged in a grid with two buttons per row.
# The form size is dynamically adjusted to fit all buttons.

Add-Type -AssemblyName System.Windows.Forms

# Define the executables
$executables = @(
    "c:\Windows\System32\notepad.exe",
    "c:\Windows\System32\notepad.exe",
    "c:\Windows\System32\notepad.exe",
    "c:\Windows\System32\cmd.exe",
    "c:\Windows\System32\cmd.exe",
    "c:\Windows\System32\cmd.exe",
    "c:\Windows\System32\regedt32.exe"
)

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Run As System"
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false

# Create buttons for each executable
$buttonWidth = 120
$buttonHeight = 30
$padding = 10
$buttonsPerRow = 2
$yPos = $padding
$xPos = $padding

for ($i = 0; $i -lt $executables.Length; $i++) {
    $exe = $executables[$i]
    $button = New-Object System.Windows.Forms.Button
    $button.Text = [System.IO.Path]::GetFileNameWithoutExtension($exe)
    $button.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
    $button.Location = New-Object System.Drawing.Point($xPos, $yPos)
    $button.Tag = $exe
    $button.Add_Click({
        param ($sender, $eventArgs)
        Start-Process $sender.Tag
    })
    $form.Controls.Add($button)

    if (($i + 1) % $buttonsPerRow -eq 0) {
        $xPos = $padding
        $yPos += $buttonHeight + $padding
    } else {
        $xPos += $buttonWidth + $padding
    }
}

# Adjust form size to fit all buttons
$form.Width = ($buttonWidth + $padding) * $buttonsPerRow + $padding + 15
$form.Height = $yPos + $buttonHeight + $padding * 3 + 20

# Show the form
$form.Add_Shown({ $form.Activate() })
[void] $form.ShowDialog()