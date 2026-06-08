<#
.SYNOPSIS
    WinForms GUI client for the CSV ticket server. Set/change the server IP,
    connect, and list / add / edit findings over the network.

.DESCRIPTION
    The Server IP field at the top is editable, so you can repoint the client at
    a different server anytime. Each action opens a TCP connection to that
    IP:port, sends one command, and shows the response. Tickets are stored as
    CSV on the server; the client receives CSV text and parses it with
    ConvertFrom-Csv. No file share or mount required — pure network.

    Run on Windows (WinForms requires Windows). Start TicketServer.ps1 first.

.EXAMPLE
    .\TicketClientGUI.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# The sender's machine name — attached automatically to every ticket this
# client submits, so the server records who reported each finding.
$script:MyHostname = $env:COMPUTERNAME
if (-not $script:MyHostname) { $script:MyHostname = [System.Net.Dns]::GetHostName() }

# Send one command line to the server, return the (decoded) response string.
function Send-TicketCommand {
    param([string]$ServerIp, [int]$ServerPort, [string]$Command, [int]$TimeoutMs = 4000)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect($ServerIp, $ServerPort, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            throw "Connection to $ServerIp`:$ServerPort timed out."
        }
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $writer = [System.IO.StreamWriter]::new($stream); $writer.AutoFlush = $true
        $reader = [System.IO.StreamReader]::new($stream)
        $writer.WriteLine($Command)
        $response = $reader.ReadLine()
        if ($null -ne $response) { $response = $response -replace "`u{241E}", "`n" }
        return $response
    }
    finally { $client.Close() }
}

# --- form ------------------------------------------------------------------
$form = [System.Windows.Forms.Form]::new()
$form.Text = "Threat Hunt Tickets (CSV)"
$form.Size = [System.Drawing.Size]::new(820, 660)
$form.StartPosition = "CenterScreen"

$lblIp = [System.Windows.Forms.Label]::new()
$lblIp.Text = "Server IP:"; $lblIp.Location = [System.Drawing.Point]::new(12,15); $lblIp.AutoSize = $true
$form.Controls.Add($lblIp)

$txtIp = [System.Windows.Forms.TextBox]::new()
$txtIp.Location = [System.Drawing.Point]::new(75,12); $txtIp.Size = [System.Drawing.Size]::new(140,22)
$txtIp.Text = "127.0.0.1"      # <-- change to the server machine's IP
$form.Controls.Add($txtIp)

$lblPort = [System.Windows.Forms.Label]::new()
$lblPort.Text = "Port:"; $lblPort.Location = [System.Drawing.Point]::new(225,15); $lblPort.AutoSize = $true
$form.Controls.Add($lblPort)

$txtPort = [System.Windows.Forms.TextBox]::new()
$txtPort.Location = [System.Drawing.Point]::new(265,12); $txtPort.Size = [System.Drawing.Size]::new(60,22)
$txtPort.Text = "9000"
$form.Controls.Add($txtPort)

$btnConnect = [System.Windows.Forms.Button]::new()
$btnConnect.Text = "Test connection"; $btnConnect.Location = [System.Drawing.Point]::new(335,11); $btnConnect.Size = [System.Drawing.Size]::new(120,24)
$form.Controls.Add($btnConnect)

$lblStatus = [System.Windows.Forms.Label]::new()
$lblStatus.Text = "Not connected"; $lblStatus.Location = [System.Drawing.Point]::new(465,15); $lblStatus.AutoSize = $true
$lblStatus.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblStatus)

$grid = [System.Windows.Forms.ListView]::new()
$grid.Location = [System.Drawing.Point]::new(12,50); $grid.Size = [System.Drawing.Size]::new(780,300)
$grid.View = "Details"; $grid.FullRowSelect = $true; $grid.GridLines = $true; $grid.MultiSelect = $false
[void]$grid.Columns.Add("Id",40)
[void]$grid.Columns.Add("Date",115)
[void]$grid.Columns.Add("Host",90)
[void]$grid.Columns.Add("IP",100)
[void]$grid.Columns.Add("Port",50)
[void]$grid.Columns.Add("Severity",70)
[void]$grid.Columns.Add("Status",70)
[void]$grid.Columns.Add("Title",155)
$form.Controls.Add($grid)

$y = 365
$lblNewIp = [System.Windows.Forms.Label]::new(); $lblNewIp.Text = "IP:"; $lblNewIp.Location = [System.Drawing.Point]::new(12,$y+3); $lblNewIp.AutoSize = $true; $form.Controls.Add($lblNewIp)
$txtNewIp = [System.Windows.Forms.TextBox]::new(); $txtNewIp.Location = [System.Drawing.Point]::new(40,$y); $txtNewIp.Size = [System.Drawing.Size]::new(110,22); $form.Controls.Add($txtNewIp)

$lblPortF = [System.Windows.Forms.Label]::new(); $lblPortF.Text = "Port:"; $lblPortF.Location = [System.Drawing.Point]::new(158,$y+3); $lblPortF.AutoSize = $true; $form.Controls.Add($lblPortF)
$txtNewPort = [System.Windows.Forms.TextBox]::new(); $txtNewPort.Location = [System.Drawing.Point]::new(195,$y); $txtNewPort.Size = [System.Drawing.Size]::new(60,22); $form.Controls.Add($txtNewPort)

$lblSev = [System.Windows.Forms.Label]::new(); $lblSev.Text = "Severity:"; $lblSev.Location = [System.Drawing.Point]::new(265,$y+3); $lblSev.AutoSize = $true; $form.Controls.Add($lblSev)
$cmbSev = [System.Windows.Forms.ComboBox]::new(); $cmbSev.Location = [System.Drawing.Point]::new(320,$y); $cmbSev.Size = [System.Drawing.Size]::new(85,22); $cmbSev.DropDownStyle = "DropDownList"
[void]$cmbSev.Items.AddRange(@("info","low","medium","high","critical")); $cmbSev.SelectedIndex = 2; $form.Controls.Add($cmbSev)

$lblTitle = [System.Windows.Forms.Label]::new(); $lblTitle.Text = "Title:"; $lblTitle.Location = [System.Drawing.Point]::new(412,$y+3); $lblTitle.AutoSize = $true; $form.Controls.Add($lblTitle)
$txtTitle = [System.Windows.Forms.TextBox]::new(); $txtTitle.Location = [System.Drawing.Point]::new(450,$y); $txtTitle.Size = [System.Drawing.Size]::new(340,22); $form.Controls.Add($txtTitle)

# Multi-line, scrollable, resizable description box.
$dy = $y + 30
$lblDesc = [System.Windows.Forms.Label]::new(); $lblDesc.Text = "Description:"; $lblDesc.Location = [System.Drawing.Point]::new(12,$dy+3); $lblDesc.AutoSize = $true; $form.Controls.Add($lblDesc)
$txtDesc = [System.Windows.Forms.TextBox]::new()
$txtDesc.Location = [System.Drawing.Point]::new(90,$dy)
$txtDesc.Size = [System.Drawing.Size]::new(700,70)
$txtDesc.Multiline = $true
$txtDesc.ScrollBars = "Vertical"
$txtDesc.AcceptsReturn = $true          # Enter makes a new line instead of submitting
$txtDesc.WordWrap = $true
$form.Controls.Add($txtDesc)

# Show which hostname will be attached to tickets this client sends.
$lblHost = [System.Windows.Forms.Label]::new()
$lblHost.Text = "Submitting as host: $script:MyHostname"
$lblHost.Location = [System.Drawing.Point]::new(12,$dy+78)
$lblHost.AutoSize = $true
$lblHost.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblHost)

$by = $dy + 100
$btnRefresh = [System.Windows.Forms.Button]::new(); $btnRefresh.Text = "Refresh list"; $btnRefresh.Location = [System.Drawing.Point]::new(12,$by); $btnRefresh.Size = [System.Drawing.Size]::new(100,28); $form.Controls.Add($btnRefresh)
$btnAdd = [System.Windows.Forms.Button]::new(); $btnAdd.Text = "Add ticket"; $btnAdd.Location = [System.Drawing.Point]::new(118,$by); $btnAdd.Size = [System.Drawing.Size]::new(100,28); $form.Controls.Add($btnAdd)

# Status control: pick open / assigned / closed, then apply to the selected row.
$cmbStatus = [System.Windows.Forms.ComboBox]::new()
$cmbStatus.Location = [System.Drawing.Point]::new(224,$by+3); $cmbStatus.Size = [System.Drawing.Size]::new(100,22); $cmbStatus.DropDownStyle = "DropDownList"
[void]$cmbStatus.Items.AddRange(@("open","assigned","closed")); $cmbStatus.SelectedIndex = 0
$form.Controls.Add($cmbStatus)
$btnSetStatus = [System.Windows.Forms.Button]::new(); $btnSetStatus.Text = "Set status on selected"; $btnSetStatus.Location = [System.Drawing.Point]::new(330,$by); $btnSetStatus.Size = [System.Drawing.Size]::new(160,28); $form.Controls.Add($btnSetStatus)

$btnApply = [System.Windows.Forms.Button]::new(); $btnApply.Text = "Apply edits to selected"; $btnApply.Location = [System.Drawing.Point]::new(496,$by); $btnApply.Size = [System.Drawing.Size]::new(170,28); $form.Controls.Add($btnApply)

$log = [System.Windows.Forms.TextBox]::new(); $log.Location = [System.Drawing.Point]::new(12,$by+40); $log.Size = [System.Drawing.Size]::new(780,60)
$log.Multiline = $true; $log.ScrollBars = "Vertical"; $log.ReadOnly = $true; $form.Controls.Add($log)
function Write-Log([string]$m) { $log.AppendText((Get-Date).ToString("HH:mm:ss") + "  " + $m + "`r`n") }

function Get-Conn { return @{ Ip = $txtIp.Text.Trim(); Port = [int]$txtPort.Text.Trim() } }

$btnConnect.Add_Click({
    try {
        $c = Get-Conn
        $r = Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "PING"
        if ($r -eq "PONG") { $lblStatus.Text = "Connected"; $lblStatus.ForeColor = [System.Drawing.Color]::Green; Write-Log "Connected to $($c.Ip):$($c.Port)" }
        else { $lblStatus.Text = "Unexpected reply"; $lblStatus.ForeColor = [System.Drawing.Color]::DarkOrange; Write-Log "Reply: $r" }
    } catch { $lblStatus.Text = "Failed"; $lblStatus.ForeColor = [System.Drawing.Color]::Red; Write-Log "Connect failed: $_" }
})

function Refresh-List {
    try {
        $c = Get-Conn
        $r = Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "LIST"
        $grid.Items.Clear()
        if ($r -and $r.StartsWith("CSV|")) {
            $csvText = $r.Substring(4)
            # Parse the CSV the server sent. ConvertFrom-Csv reads the header row
            # and gives objects with .Id .Date .Host .IP .Port .Severity .Status .Title .Description
            # In-field newlines (e.g. in Description) arrive as U+2400 so they
            # don't get confused with the breaks between records; restore them.
            $rows = $csvText | ConvertFrom-Csv
            foreach ($row in @($rows)) {
                if (-not $row.Id) { continue }
                $desc = [string]$row.Description -replace "`u{2400}", "`r`n"
                $item = [System.Windows.Forms.ListViewItem]::new([string]$row.Id)
                [void]$item.SubItems.Add([string]$row.Date)
                [void]$item.SubItems.Add([string]$row.Host)
                [void]$item.SubItems.Add([string]$row.IP)
                [void]$item.SubItems.Add([string]$row.Port)
                [void]$item.SubItems.Add([string]$row.Severity)
                [void]$item.SubItems.Add([string]$row.Status)
                [void]$item.SubItems.Add([string]$row.Title)
                # Stash the (possibly multi-line) description on the item's Tag so
                # row-select can show it without needing a visible column.
                $item.Tag = $desc
                [void]$grid.Items.Add($item)
            }
        }
        Write-Log "List refreshed ($($grid.Items.Count) tickets)"
    } catch { Write-Log "Refresh failed: $_" }
}

$btnRefresh.Add_Click({ Refresh-List })

$btnAdd.Add_Click({
    try {
        $c = Get-Conn
        # Encode any newlines in the description so the whole command stays one
        # protocol line. The server stores it; the placeholder is decoded for display.
        $descEncoded = $txtDesc.Text -replace "`r`n", "`u{241E}" -replace "`n", "`u{241E}" -replace "`r", "`u{241E}"
        $cmd = "ADD`t$script:MyHostname`t$($txtNewIp.Text.Trim())`t$($txtNewPort.Text.Trim())`t$($cmbSev.SelectedItem)`t$($txtTitle.Text.Trim())`t$descEncoded"
        $r = Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command $cmd
        Write-Log "Add -> $r"; Refresh-List
    } catch { Write-Log "Add failed: $_" }
})

$btnSetStatus.Add_Click({
    if ($grid.SelectedItems.Count -eq 0) { Write-Log "Select a ticket first."; return }
    try {
        $c = Get-Conn; $id = $grid.SelectedItems[0].Text
        $newStatus = $cmbStatus.SelectedItem
        $r = Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`tstatus`t$newStatus"
        Write-Log "Status #$id -> $newStatus  ($r)"; Refresh-List
    } catch { Write-Log "Set status failed: $_" }
})

$btnApply.Add_Click({
    if ($grid.SelectedItems.Count -eq 0) { Write-Log "Select a ticket first."; return }
    try {
        $c = Get-Conn; $id = $grid.SelectedItems[0].Text
        if ($txtNewIp.Text.Trim()) { [void](Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`tip`t$($txtNewIp.Text.Trim())") }
        if ($txtNewPort.Text.Trim()) { [void](Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`tport`t$($txtNewPort.Text.Trim())") }
        if ($cmbSev.SelectedItem)  { [void](Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`tsev`t$($cmbSev.SelectedItem)") }
        if ($txtTitle.Text.Trim()) { [void](Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`ttitle`t$($txtTitle.Text.Trim())") }
        if ($txtDesc.Text.Trim())  {
            $de = $txtDesc.Text -replace "`r`n", "`u{241E}" -replace "`n", "`u{241E}" -replace "`r", "`u{241E}"
            [void](Send-TicketCommand -ServerIp $c.Ip -ServerPort $c.Port -Command "EDIT`t$id`tdesc`t$de")
        }
        Write-Log "Applied edits to #$id"; Refresh-List
    } catch { Write-Log "Edit failed: $_" }
})

$grid.Add_SelectedIndexChanged({
    if ($grid.SelectedItems.Count -gt 0) {
        $it = $grid.SelectedItems[0]
        $txtNewIp.Text = $it.SubItems[3].Text
        $txtNewPort.Text = $it.SubItems[4].Text
        $sev = $it.SubItems[5].Text
        if ($cmbSev.Items.Contains($sev)) { $cmbSev.SelectedItem = $sev }
        # Status is column index 6; preselect it in the status dropdown.
        $st = $it.SubItems[6].Text
        if ($cmbStatus.Items.Contains($st)) { $cmbStatus.SelectedItem = $st }
        $txtTitle.Text = $it.SubItems[7].Text
        # Description was stashed on the item's Tag (it has no visible column).
        if ($null -ne $it.Tag) { $txtDesc.Text = [string]$it.Tag } else { $txtDesc.Text = "" }
    }
})

[void]$form.ShowDialog()
