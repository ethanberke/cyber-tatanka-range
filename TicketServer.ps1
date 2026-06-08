<#
.SYNOPSIS
    Central ticket server. ONE machine runs this; it owns the CSV file and
    listens on a TCP port. GUI clients connect to this machine's IP to list,
    add, and edit tickets over the network.

.DESCRIPTION
    Findings tracker for threat hunting. Each ticket is one finding tied to an
    IP address. Storage is a single CSV file on THIS machine, read and written
    with PowerShell's native Import-Csv / Export-Csv. The server serializes all
    access with an in-process lock, so multiple clients are safe.

    CSV columns:
        Id, Date, IP, Severity, Status, Title

    The CSV opens directly in Excel and is easy to back up, diff, or hand off.

.PARAMETER ListenAddress
    Interface to bind. 0.0.0.0 = all interfaces (reachable by other machines).
    127.0.0.1 = local only (testing).

.PARAMETER Port
    TCP port to listen on. Clients must use the same port.

.PARAMETER CsvPath
    Path to the ticket CSV file on this machine.

.EXAMPLE
    .\TicketServer.ps1 -ListenAddress 0.0.0.0 -Port 9000 -CsvPath C:\hunt\tickets.csv
#>
[CmdletBinding()]
param(
    [string]$ListenAddress = "0.0.0.0",
    [int]$Port = 9000,
    [string]$CsvPath = "$env:USERPROFILE\tickets.csv"
)

$script:CsvPath = $CsvPath
$script:Lock    = [System.Object]::new()

# Column order is fixed and used everywhere we write the CSV.
$script:Columns = @("Id","Date","Host","IP","Port","Severity","Status","Title","Description")

# Create the CSV with a header row on first run.
if (-not (Test-Path $script:CsvPath)) {
    ($script:Columns -join ",") | Set-Content -LiteralPath $script:CsvPath -Encoding UTF8
}

# --- CSV helpers -----------------------------------------------------------

# Load all tickets as objects. Returns an array (possibly empty).
function Get-Tickets {
    if (-not (Test-Path $script:CsvPath)) { return @() }
    $rows = Import-Csv -LiteralPath $script:CsvPath
    if ($null -eq $rows) { return @() }
    return @($rows)
}

# Write the full ticket set back to CSV. Export-Csv handles quoting/escaping
# of commas, quotes, and other CSV-special characters automatically — which is
# the main reason CSV is nicer here than the old hand-rolled delimited format.
function Save-Tickets($tickets) {
    if (@($tickets).Count -eq 0) {
        ($script:Columns -join ",") | Set-Content -LiteralPath $script:CsvPath -Encoding UTF8
        return
    }
    $tickets |
        Select-Object $script:Columns |
        Export-Csv -LiteralPath $script:CsvPath -NoTypeInformation -Encoding UTF8
}

function Get-NextId {
    $tickets = Get-Tickets
    $max = 0
    foreach ($t in $tickets) {
        $n = 0
        if ([int]::TryParse($t.Id, [ref]$n) -and $n -gt $max) { $max = $n }
    }
    return $max + 1
}

# Serialize tickets back into a single protocol line for transport. We send
# real CSV text (header + rows) so the client can parse it with ConvertFrom-Csv.
function Tickets-ToCsvText($tickets) {
    if (@($tickets).Count -eq 0) { return ($script:Columns -join ",") }
    # ConvertTo-Csv produces one array element per record, with multi-line field
    # values (like Description) already wrapped in quotes and containing real
    # newlines. We must distinguish those in-field newlines from the breaks
    # *between* records before flattening to a single transport line.
    # In-field newlines -> U+2400 (will be restored to newlines by the client).
    $csv = $tickets | Select-Object $script:Columns | ConvertTo-Csv -NoTypeInformation
    $protected = $csv | ForEach-Object { $_ -replace "`r`n", "`u{2400}" -replace "`n", "`u{2400}" -replace "`r", "`u{2400}" }
    # Join records with newline; the outer transport encoder turns THESE into
    # the record separator U+241E. Two different placeholders keep them separate.
    return ($protected -join "`n")
}

# --- command handlers ------------------------------------------------------
function Invoke-TicketCommand([string]$request) {
    # Protocol: "VERB<TAB>arg1<TAB>arg2<TAB>..."
    $parts = $request -split "`t"
    $verb  = $parts[0].ToUpper()

    [System.Threading.Monitor]::Enter($script:Lock)
    try {
        switch ($verb) {

            "LIST" {
                $filterIp = if ($parts.Count -ge 2) { $parts[1] } else { "" }
                $tickets = Get-Tickets
                if ($filterIp) {
                    $tickets = @($tickets | Where-Object { $_.IP -eq $filterIp })
                }
                # Return CSV text (header + rows) for the client to parse.
                return "CSV|" + (Tickets-ToCsvText $tickets)
            }

            "ADD" {
                # ADD <host> <ip> <port> <severity> <title> <description>
                # Host = the sending analyst's machine name (filled in by the
                # client automatically). Port and Description are optional.
                $host_ = $parts[1]
                $ip    = $parts[2]
                $port  = $parts[3]
                $sev   = $parts[4]
                $title = $parts[5]
                $desc  = if ($parts.Count -ge 7) { $parts[6] } else { "" }
                # Client encodes newlines in the description as U+241E so the
                # command travels as one line; restore real newlines for storage.
                $desc  = $desc -replace "`u{241E}", "`r`n"
                if (-not $ip -or -not $sev -or -not $title) { return "ERR|need ip, severity, title" }

                $tickets = @(Get-Tickets)
                $new = [PSCustomObject]@{
                    Id          = (Get-NextId)
                    Date        = (Get-Date).ToString("yyyy-MM-dd HH:mm")
                    Host        = $host_
                    IP          = $ip
                    Port        = $port
                    Severity    = $sev
                    Status      = "open"
                    Title       = $title
                    Description = $desc
                }
                $tickets += $new
                Save-Tickets $tickets
                return "OK|added #$($new.Id)"
            }

            "EDIT" {
                # EDIT <id> <field> <newvalue>   field = host|ip|port|sev|status|title|desc
                $eid   = $parts[1]
                $field = $parts[2].ToLower()
                $val   = $parts[3]
                # Description edits arrive with newlines encoded as U+241E; decode.
                if ($field -eq "desc") { $val = $val -replace "`u{241E}", "`r`n" }

                $tickets = @(Get-Tickets)
                $found = $false
                foreach ($t in $tickets) {
                    if ($t.Id -eq $eid) {
                        $found = $true
                        switch ($field) {
                            "host"   { $t.Host = $val }
                            "ip"     { $t.IP = $val }
                            "port"   { $t.Port = $val }
                            "sev"    { $t.Severity = $val }
                            "status" { $t.Status = $val }
                            "title"  { $t.Title = $val }
                            "desc"   { $t.Description = $val }
                            default  { return "ERR|unknown field '$field'" }
                        }
                    }
                }
                if (-not $found) { return "ERR|no ticket #$eid" }
                Save-Tickets $tickets
                return "OK|edited #$eid"
            }

            "PING" { return "PONG" }

            default { return "ERR|unknown verb '$verb'" }
        }
    }
    finally {
        [System.Threading.Monitor]::Exit($script:Lock)
    }
}

# --- TCP listen loop -------------------------------------------------------
$endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($ListenAddress), $Port)
$listener = [System.Net.Sockets.TcpListener]::new($endpoint)
$listener.Start()
Write-Host "Ticket server listening on $ListenAddress`:$Port"
Write-Host "CSV store: $script:CsvPath"
Write-Host "Press Ctrl+C to stop."

# Make Ctrl+C set a flag and break the loop cleanly instead of hard-killing the
# process. TreatControlCAsInput lets us read the keypress ourselves so we can
# shut the listener down and print a confirmation message.
[Console]::TreatControlCAsInput = $true
$stop = $false

try {
    while (-not $stop) {

        # 1) Check for a Ctrl+C keypress without blocking.
        while ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            if (($key.Modifiers -band [ConsoleModifiers]::Control) -and ($key.Key -eq 'C')) {
                $stop = $true
                break
            }
        }
        if ($stop) { break }

        # 2) If no client is waiting, sleep briefly and loop again. This is what
        #    makes Ctrl+C work — we never block forever on Accept anymore.
        if (-not $listener.Pending()) {
            Start-Sleep -Milliseconds 200
            continue
        }

        # 3) A client is waiting — accept and handle it.
        $client = $listener.AcceptTcpClient()
        try {
            $stream = $client.GetStream()
            $reader = [System.IO.StreamReader]::new($stream)
            $writer = [System.IO.StreamWriter]::new($stream)
            $writer.AutoFlush = $true

            $request = $reader.ReadLine()
            if ($null -ne $request) {
                $response = Invoke-TicketCommand $request
                # Encode newlines so the whole multi-line CSV response is one
                # protocol line on the wire; client decodes it back.
                $writer.WriteLine(($response -replace "`r","" -replace "`n","`u{241E}"))
            }
        }
        catch { Write-Host "Client error: $_" }
        finally { $client.Close() }
    }
}
finally {
    $listener.Stop()
    [Console]::TreatControlCAsInput = $false
    Write-Host ""
    Write-Host "Server stopped. No longer listening on $ListenAddress`:$Port."
}
