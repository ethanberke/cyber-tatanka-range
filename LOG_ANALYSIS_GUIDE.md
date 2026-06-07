# Log Analysis Guide — Focused Checks for Logins, Ports, Services, Resources

**Purpose**: Practical, hands-on checks for common investigative questions: who logged in, what ports/services are in use, what processes/services started, and where resources spiked. Designed for manual analysis when centralized tools are limited.

---

## Table of Contents

- [What each log/source shows (high level)](#what-each-logsource-shows-high-level)
- [Authentication & logins](#authentication--logins)
- [Ports, listening services, and connections](#ports-listening-services-and-connections)
- [Processes, services, and persistence](#processes-services-and-persistence)
- [Resource spikes (CPU, memory, disk, I/O)](#resource-spikes-cpu-memory-disk-io)
- [File system changes and persistence locations](#file-system-changes-and-persistence-locations)
- [Practical search patterns and examples (quick copy-paste)](#practical-search-patterns-and-examples-quick-copy-paste)
- [Quick checklists (first 10 minutes)](#quick-checklists-first-10-minutes)
- [Sysmon (Windows) — description and Sysmon queries](#sysmon-windows--description-and-sysmon-queries)
- [Notes & next steps](#notes--next-steps)
- [Resources & Tools (concise)](#resources--tools-concise)


## What each log/source shows (high level)

- **Authentication logs**: User logins, failed/successful authentication, sudo/privilege use. (Linux: /var/log/auth.log or /var/log/secure; Windows: Security log)
- **SSH / Remote access**: Remote session origins, key vs password auth, session open/close. (Linux: auth.log, journalctl -u sshd)
- **System logs / kernel**: Kernel messages, OOM events, hardware/network errors. (Linux: /var/log/syslog, /var/log/messages, dmesg; Windows: System log)
- **Service logs**: Service start/stop, errors, configuration changes. (systemd: journalctl -u <svc>; app logs: /var/log/nginx/access.log)
- **Network logs / firewall**: Open/blocked ports, connection attempts, source/destination IPs. (iptables/ufw logs, firewall logs, NetFlow/Syslog from network devices)
- **Process & endpoint telemetry**: Process creation, command lines, parent/child relationships. (Sysmon EventID 1, auditd on Linux if enabled)
- **Performance / resource metrics**: CPU/memory/disk spikes, I/O saturation, OOM kills. (top, sar, iostat, Performance Monitor on Windows)

---

## Authentication & logins

**Linux** — Quick searches (simple, easy-to-read)

Show the most recent failed SSH password attempts (raw lines):
```bash
grep "Failed password" /var/log/auth.log | tail -n 50
```

Count failed attempts by source IP (extract IPv4 addresses) and show top sources:
```bash
grep "Failed password" /var/log/auth.log | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head
```

Show recent successful logins (raw lines):
```bash
grep "Accepted" /var/log/auth.log | tail -n 50
```

Show session open entries for users:
```bash
grep "session opened for user" /var/log/auth.log | tail -n 50
```

Show session close entries for users:
```bash
grep "session closed for user" /var/log/auth.log | tail -n 50
```

Show recent interactive logins summary:
```bash
last -a | head -n 30
```

If `auditd` is enabled, use it for structured login events:
```bash
ausearch -m USER_LOGIN --start recent
```

**Windows** — Event IDs and sample PowerShell

Show recent successful logons (Event ID 4624):
```powershell
Get-EventLog -LogName Security -Newest 100 | Where-Object {$_.EventID -eq 4624} | Select TimeGenerated,Message
```

Show recent failed logons (Event ID 4625):
```powershell
Get-EventLog -LogName Security -Newest 200 | Where-Object {$_.EventID -eq 4625} | Select TimeGenerated,Message
```

Show recent new user creation or privilege events (common IDs):
```powershell
Get-EventLog -LogName Security -Newest 200 | Where-Object {$_.EventID -in 4720,4722,4672} | Select TimeGenerated,Message
```

Tips: look for multiple failed logins followed by a success, unusual logon types (RDP when not used), or source IPs outside normal ranges.


Windows GUI checks (Authentication & logins):

- Event Viewer: Open `Event Viewer` → `Windows Logs` → `Security`. Right-click → `Filter Current Log...` and enter Event IDs `4624,4625,4720,4672` and set time range.
- To see RDP sessions: open Command Prompt and run `qwinsta` (lists session IDs and users).
- To correlate RDP sockets: run `netstat -ano | findstr :3389` then map PID to process with `tasklist /FI "PID eq <PID>"`.

---

---

## Ports, listening services, and connections

- **Check current listeners and their binaries (important to tie ports to processes)**
Show listening TCP/UDP ports and owning process:
```bash
ss -tulpen | head -n 120
```

Alternate view (netstat):
```bash
netstat -tulnp
```

Map sockets to binaries (lsof):
```bash
sudo lsof -i -P -n | grep LISTEN
```

- **Find processes with network activity**
Show established TCP connections with process info:
```bash
ss -tnp | head -n 40
```

Show listening ports and owning processes:
```bash
ss -tulpen | head -n 40
```

Map established sockets to binaries with lsof:
```bash
sudo lsof -i -P -n | grep ESTABLISHED | head -n 40
```


Windows checks (Ports & connections):

```powershell
# Classic: list established TCP connections (shows PID)
netstat -ano | findstr ESTABLISHED

# Map a PID to a process name (replace <PID>)
tasklist /FI "PID eq <PID>"

# PowerShell alternative to show connections
Get-NetTCPConnection -State Established | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
```

GUI tools:

- Resource Monitor → Network tab: shows listening ports, established connections, and process names.
- TCPView (Sysinternals): GUI listing of TCP/UDP endpoints with process names and remote addresses.
- Windows Firewall with Advanced Security → Monitoring for active rules and connections.

---

- **Service-specific logs**
Check a systemd service journal for errors and recent starts (sshd):
```bash
journalctl -u sshd --since "2 hours ago"
```

Show recent nginx errors:
```bash
journalctl -u nginx --since "1 day ago" -p err | tail -n 100
```

Show top client IPs from nginx access log (recent):
```bash
tail -n 200 /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 20
```

Windows equivalent (Service logs / Web server events):

Open Event Viewer → Windows Logs → Application/System to view service and application errors. To list recent service-related events via PowerShell:
```powershell
Get-EventLog -LogName System -Newest 200 | Where-Object {$_.EventID -in 7036,7034,7040} | Select TimeGenerated,Message
```

To check a Windows service status (replace `<ServiceName>`):
```powershell
Get-Service -Name <ServiceName>
```

- **Firewall and connection logs**
Show UFW log lines (recent):
```bash
grep UFW /var/log/syslog | tail -n 200
```

Show iptables log entries (if configured):
```bash
grep "IN=" /var/log/messages | tail -n 200
```

Capture packets for 15 seconds for a specific host/port:
```bash
sudo timeout 15 tcpdump -n -i any host 192.0.2.5 and port 22 -w /tmp/suspect.pcap
```

Windows equivalent (Firewall logs & packet capture):

To view Windows Firewall events in the GUI: open `Windows Firewall with Advanced Security` → `Monitoring`. For detailed events, open Event Viewer and navigate to `Applications and Services Logs` → `Microsoft` → `Windows` → `Windows Firewall with Advanced Security` → `Firewall`.

List basic firewall rules via PowerShell:
```powershell
Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled
```

Start a network trace on Windows (admin) and stop after investigation:
```powershell
netsh trace start capture=yes tracefile=c:\temp\nettrace.etl
```
```powershell
netsh trace stop
```

For GUI packet capture, use Wireshark; for connection listings use TCPView (Sysinternals).

---

## Processes, services, and persistence

- **Identify recently started services and new unit files**
Show recently started services (last 6 hours):
```bash
journalctl --since "6 hours ago" | egrep "Starting|Started" | tail -n 50
```

List unit files changed in the last 7 days:
```bash
find /etc/systemd/system /lib/systemd/system -type f -mtime -7 -ls | head -n 50
```

Show recent package installs (apt/dpkg example):
```bash
grep "install " /var/log/dpkg.log | tail -n 50
```

Show recent apt history entries:
```bash
grep "Installed: " /var/log/apt/history.log | tail -n 50
```

- **Processes spawning unusual children or commands**
Show top CPU consumers:
```bash
ps aux --sort=-%cpu | head -n 15
```

Show top memory consumers:
```bash
ps aux --sort=-%mem | head -n 15
```

Find PIDs for a suspicious process name (replace `suspicious_binary`):
```bash
pgrep -fl suspicious_binary
```

Show the process tree for a PID (replace `<PID>`):
```bash
pstree -ps <PID>
```

- **Windows** — service and process checks
Show new service install events (Event ID 7045):
```powershell
Get-EventLog -LogName System -Newest 200 | Where-Object {$_.EventID -eq 7045} | Select TimeGenerated,Message
```

Show recent process creation events (Event ID 4688):
```powershell
Get-EventLog -LogName Security -Newest 200 | Where-Object {$_.EventID -eq 4688} | Select TimeGenerated,Message
```


Windows GUI & tips (Processes & services):

- Task Manager: `Details` and `Processes` tabs for CPU/memory usage and to view the command line column (View → Select Columns → check "Command Line").
- Process Explorer (Sysinternals): shows parent-child relationships, command line, loaded DLLs, and network activity per process.
- Services.msc and Event Viewer (System/Application) to check service start/stop events; filter for Event ID `7045` (new services) and `7036` (service state changes).
- Check Task Scheduler for suspicious scheduled tasks: `Task Scheduler` → `Task Scheduler Library` and sort by `Last Run Time`.

PowerShell quick checks (simple):

List running services (short):
```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name,DisplayName
```

List scheduled tasks (short):
```powershell
Get-ScheduledTask | Select TaskName,State
```

---

---

## Resource spikes (CPU, memory, disk, I/O)

- **Linux quick diagnostics**
Instant snapshot (top):
```bash
top -b -n1 | head -40
```

Short vmstat samples (5 iterations):
```bash
vmstat 1 5
```

Short iostat samples:
```bash
iostat -x 1 5
```

Look for OOM events in kernel logs:
```bash
dmesg | egrep -i "oom|out of memory" -n
```

Or via the journal:
```bash
journalctl -k | egrep -i "oom|out of memory"
```

Check for high disk write activity (iotop must be installed):
```bash
iotop -b -o -n 5
```


**Windows quick diagnostics (simple)**
- Open Task Manager → `Processes` to see top CPU and memory consumers.
- Open Resource Monitor → `CPU` / `Memory` / `Disk` tabs for per-process details.

PowerShell quick checks (easy):

Top 10 processes by CPU:
```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id,ProcessName,CPU
```

Quick CPU/Memory snapshot:
```powershell
Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes' -MaxSamples 3 -SampleInterval 1
```

---

---

## File system changes and persistence locations

- **Common persistence places to audit quickly**
  - `/etc/cron.*`, `crontab -l` (Linux cron jobs)
  - `/etc/rc.local`, systemd timers in `/etc/systemd/system` and `~/.config/systemd/user`
  - `~/.ssh/authorized_keys` for unexpected keys
  - Scheduled Tasks / Services / Run keys (Windows)

Windows persistence GUI & commands:

- Autoruns (Sysinternals): GUI to enumerate Run keys, scheduled tasks, services, drivers, and browser helper objects.
- Registry: check `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for unexpected entries.
- Task Scheduler: GUI as noted above; PowerShell `Get-ScheduledTask` to list tasks.


PowerShell example: find recently modified files in Program Files (change path as needed)
```powershell
# Show files modified in the last 7 days under Program Files
Get-ChildItem 'C:\Program Files' -Recurse -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
  Select-Object FullName,LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 50
```

---

- **Search for recently modified files under root-owned areas**
```bash
# Find files modified in the last 7 days in common config areas
find /etc /usr/local /opt -type f -mtime -7 -ls | head -n 50

# Find files (excluding /proc) modified in the last 2 days, limit output
find / -path /proc -prune -o -type f -mtime -2 -size -100M -ls | head -n 50
```

---

## Practical search patterns and examples (quick copy-paste)

- Linux: failed logins by IP
```bash
grep "Failed password" /var/log/auth.log | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head
```

Windows: failed logons (simple, raw view)
```powershell
# Show recent failed logons (Event ID 4625) - raw messages for manual inspection
Get-EventLog -LogName Security -Newest 500 | Where-Object {$_.EventID -eq 4625} | Select TimeGenerated,Message
```

- Linux: successful SSH public-key logins
```bash
 # Show recent successful SSH publickey authentications (raw lines)
 grep "Accepted publickey" /var/log/auth.log | tail -n 50
```

- Windows: RDP logons in last 24 hours (LogonType 10)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddHours(-24)} | 
  Where-Object { ($_.Properties[8].Value) -eq 10 } | Select TimeCreated, @{n='Account';e={$_.Properties[5].Value}}, Message
```

---

## Quick checklists (first 10 minutes)

- **If suspicious login:**
  - Check `/var/log/auth.log` or Security log for failed → successful sequences
  - `last`, `w`, `who` to find active sessions
  - `ss -tnp`/`netstat -tunap` to locate remote endpoints

- **Windows equivalent for suspicious login:**
  - In Event Viewer, filter Security log Event IDs `4625,4624` and group by `Account Name` and network address in details.
  - `qwinsta` / `query user` to list active RDP sessions.
  - `netstat -ano` to find remote endpoints and map PIDs to processes via Task Manager or `Get-Process`.

- **If unexpected open port / service:**
  - `ss -tulpen` and `sudo lsof -i` to find the binary
  - `journalctl -u <service>` and service logs for recent restarts or errors
  - Check package manager logs for recent installs

- **If resources spiking:**
  - `top`, `vmstat`, `iostat`, `iotop` to identify hot processes
  - `dmesg`/`journalctl -k` for OOM/kernel messages

- **If resources spiking (Windows):**
  - Use Task Manager/Resource Monitor to identify top CPU, Memory, and Disk consumers.
  - Run `Get-Counter` or use `perfmon` to capture counters; check System and Application event logs for OOM or disk errors.

---

## Notes & next steps

- When possible, capture logs to an external location before making changes.
- Use `tcpdump` or live packet capture for short, targeted captures when network IoCs are suspected.
- Consider enabling `auditd` and `Sysmon` in preparation for deeper investigations.

---

## Sysmon (Windows) — description and Sysmon queries

Sysmon (System Monitor) is a lightweight Windows service (part of Sysinternals) that provides detailed endpoint telemetry beyond standard Windows Event Logs. It records process creation (with command lines), network connections, file creation times, driver/load events, and more when configured. Deploying Sysmon with a good config dramatically improves visibility for C2, lateral movement, and living-off-the-land activity.

Quick deployment notes:
- Install Sysmon from Microsoft Sysinternals and use a curated config (enable ProcessCreate, NetworkConnect, FileCreate, CreateRemoteThread, and ImageLoaded where feasible).
- Ensure `Include` rules capture `CommandLine`, `ParentImage`, and `User` fields; forward the `Microsoft-Windows-Sysmon/Operational` channel to your collector if possible.

Example detection queries (PowerShell / Event Log)
```powershell
# Recent process creations (Sysmon Event ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddHours(-24)} |
  Select TimeCreated, @{n='Message';e={$_.Message}} | Out-String -Width 4096

# Network connections recorded by Sysmon (Event ID 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3; StartTime=(Get-Date).AddHours(-24)} | Select TimeCreated, Message

# Detect suspicious parent-child combos (example: regsvr32 -> powershell or rundll32 spawning curl)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=(Get-Date).AddDays(-7)} |
  Where-Object {$_.Message -match 'ParentImage:.*(regsvr32|rundll32|wmic)'} | Select TimeCreated, Message

# Find processes making outbound connections to unusual ports
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3; StartTime=(Get-Date).AddDays(-1)} |
  Where-Object {$_.Message -match ':[0-9]{4,5}'} | Select TimeCreated, Message
```

Detection tips:
- Look for rare parent-child chains (eg, Office app spawning cmd/powershell).
- Correlate Sysmon EventID 3 (network) with DNS logs and firewall logs for external destinations.
- Search for repeated short-interval network connections from the same host (possible beacons).

If you want, I can add a recommended Sysmon XML config snippet and a small set of Sigma rules or Splunk/SIEM queries to detect common C2 patterns.

---

## Resources & Tools (concise)

- **Linux:** `grep`, `awk`, `sed`, `ss`, `lsof`, `journalctl`, `auditd`, `top`, `iotop`, `iostat`, `tcpdump`
- **Windows:** Event Viewer, `Get-WinEvent`, `Get-EventLog`, Sysmon, PowerShell
- **Forensic:** `volatility` (memory), `tcpdump`/Wireshark (network)

