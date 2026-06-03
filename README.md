# **Range Topics**

## Table of Contents
- [Common Ports](#common-ports)
- [Linux Commands](#linux-commands)
- [Nmap](#nmap)
- [PowerShell Commands](#powershell-commands)
- [Sysinternals](#sysinternals)
- [Security Onion](#security-onion)
- [Splunk](#splunk)
- [pfSense](#pfsense)
- [QRadar](#qradar)
- [Triage Steps](#triage-steps)
  - [Quick Triage Checklist](#quick-triage-checklist)
 
# Common Ports

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| SSH | 22 | TCP | Remote Linux/Unix administration |
| Telnet | 23 | TCP | Legacy remote access, usually insecure |
| DNS | 53 | UDP/TCP | Name resolution |
| DHCP server | 67 | UDP | Server listens for client requests |
| DHCP client | 68 | UDP | Client receives DHCP responses |
| TFTP | 69 | UDP | Simple file transfer |
| HTTP | 80 | TCP | Web traffic |
| SNMP manager | 161 | UDP | Network monitoring queries |
| SNMP traps | 162 | UDP | Network monitoring alerts |
| HTTPS | 443 | TCP | Encrypted web traffic |
| SMB | 445 | TCP | Windows file sharing |
| Syslog | 514 | UDP/TCP | System and network logging |
| PostgreSQL | 5432 | TCP | PostgreSQL database |
| HTTP Proxy | 8080 | TCP | Common proxy or alternate web port |
| MongoDB | 27017 | TCP | MongoDB database |


# Linux Commands

### Creating/Reading/Deleting Files
```bash
cat file.txt        # Print an entire file
less file.txt       # View a file page by page
head file.txt       # Show the first lines
tail file.txt       # Show the last lines
tail -f app.log     # Follow new log output live
lsblk               # Shows available drive partitions/mount points
cat file.txt | grep "Hello World"  # Searches based on keywords
```


### grep

Search log for matching keywords
```bash
# Case-insensitive search for 'error' in a file
grep -i "error" /var/log/syslog

# Recursive search for 'main' in current directory
grep -r "main" .

# Show 3 lines of context around matches
grep -C 3 "error" application.log

# Search for multiple patterns
grep -E "error|warning" /var/log/syslog

# Count occurrences
grep -c "failed" /var/log/auth.log   
```

### ps aux

- Displays all running processes on the system

| USER | PID | %CPU | %MEM | VSZ | RSS | TTY | STAT | START | TIME | COMMAND |
|------|-----|-----|-----|-----|-----|-----|------|-------|------|------|
| root | 1 | 0.0 | 0.1 | 168000 | 12000 | ? | Ss | 08:00 | 0:01 | /sbin/init |
| www-data | 522 | 0.2 | 0.5 | 250000 | 50000 | ? | S | 08:01 | 0:05 | apache2 |
| ethan | 1254 | 5.1 | 1.2 | 800000 | 95000 | pts/0 | Sl | 09:15 | 1:32 | python3 app.py |

### ps aux definitions

| Column | Description |
|----------|-------------|
| USER | User that owns the process |
| PID | Unique Process ID |
| %CPU | Percentage of CPU currently being used |
| %MEM | Percentage of system memory (RAM) being used |
| VSZ | Virtual memory size allocated to the process (KB) |
| RSS | Physical memory currently used by the process (KB) |
| TTY | Terminal associated with the process (`?` = no terminal) |
| STAT | Current process state (Running, Sleeping, Zombie, etc.) |
| START | Time or date the process started |
| TIME | Total CPU time consumed since process start |
| COMMAND | Command and arguments used to launch the process |

### Common STAT Values

| Value | Meaning |
|---------|---------|
| D | Uninterruptible sleep (usually disk I/O) |
| l | Multi-threaded process |
| R | Running |
| s | Session leader |
| S | Sleeping (waiting for an event) |
| T | Stopped |
| Z | Zombie (terminated but not cleaned up) |
| + | Running in foreground process group |

## Daemons

A **daemon** is a background process that runs continuously and provides a service to the operating system or users.

Unlike normal programs, daemons typically:

- Start automatically at boot
- Run without user interaction
- Listen for requests or perform scheduled tasks
- Often have names ending in `d` (daemon)

### Common Linux Daemons

| Daemon | Purpose |
|----------|----------|
| `sshd` | SSH remote access |
| `httpd` / `apache2` | Apache web server |
| `nginx` | Nginx web server |
| `named` | DNS server |
| `crond` / `cron` | Scheduled tasks |
| `rsyslogd` | System logging |
| `systemd` | Service manager |
| `mysqld` | MySQL database |
| `postgres` | PostgreSQL database |
| `dockerd` | Docker service |

### Permissions

```bash
chmod 755 script.sh
```

Avoid using `chmod 777` unless you specifically need everyone to read, write, and execute the file.

|Number| Description|
|------|------------|
|4| gives Read (r) privileges to a file|
|2| gives Write (w) privileges to a file|
|1| gives execute (x) privileges to a file|

|Combination Number| Description|
|------|------------|
| 7 | all permissions|
| 6 | Read/Write|
| 5 | read/execute|
| 3 | write/execute|

|Owner | Group | Others (Standard Users)| Permission Type |
|------|-------|------------------------|     ------      |
| 7    | 7     | 7                      | Everyone has permission to Read/Write/Execute |
| 7    | 1     | 1                      | Only owner can read/write/execute, everyone else can only execute |
| 7    | 6    | 1                      | Owner has rwx, group has rw, other has execute

### Pipes

A pipe sends the output of one command into another command.

```bash
ls -la | less
```

### tail
```bash
tail -n 50 /var/log/syslog # Returns the last 50 lines from a log
```

### wc - (word count)
```bash
wc file.txt # Counts lines, words, and characters
wc -l file.txt # Counts how many lines are in a file
```

# Nmap

Nmap is a network scanning tool used to discover hosts, identify open ports, detect services, and gather basic operating system information.

Use Nmap only on systems you own, manage, or have permission to test.

## Installing Nmap

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap -y
```

### macOS
```bash
brew install nmap
```

### Windows

Download the Windows installer from the official Nmap site:

```text
https://nmap.org/download.html
```

After installing, open PowerShell or Command Prompt and verify it works:

```powershell
nmap --version
```

## Basic Nmap Syntax

```bash
nmap [scan options] [target]
```

Targets can be:

```bash
nmap 192.168.1.10          # Scan one host
nmap 192.168.1.0/24        # Scan a subnet
nmap 192.168.1.10-50       # Scan a range of IP addresses
nmap example.com           # Scan a hostname
```

## Finding Live Hosts

Use a ping sweep to find hosts that are online without doing a full port scan.

```bash
nmap -sn 192.168.1.0/24
```

Useful when you first enter a network and need to identify active systems.

## Basic Port Scan

Scan the most common 1,000 TCP ports on a host:

```bash
nmap 192.168.1.10
```

Example output:

```text
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

### Reading Port States

| State | Meaning |
|-------|---------|
| open | A service is listening on the port |
| closed | The host responded, but nothing is listening on the port |
| filtered | Nmap cannot tell because a firewall or filter may be blocking traffic |

## Scan Specific Ports

```bash
nmap -p <port number> <ip address>
nmap -p 22,80,443 192.168.1.10
```

Scan a port range:

```bash
nmap -p 1-1000 192.168.1.10
```

## Common Nmap Options

| Option | Purpose |
|--------|---------|
| `-sn` | Host discovery only, no port scan |
| `-p` | Choose specific ports |
| `-p-` | Scan all TCP ports |
| `-sV` | Detect service versions |
| `-O` | Attempt operating system detection |
| `-A` | Aggressive scan with extra detection |
| `-sU` | UDP scan |
| `-T4` | Faster timing, commonly used on stable networks |
| `-oN` | Save normal output to a file |
| `-oX` | Save XML output to a file |
| `-iL` | Read targets from a file |

## Save Scan Results

Save normal output:

```bash
nmap -sV 192.168.1.10 -oN scan-results.txt
```

Save XML output for importing into other tools:

```bash
nmap -sV 192.168.1.10 -oX scan-results.xml
```

## Scan Multiple Targets from a File

Create a file named `targets.txt`:

```text
192.168.1.10
192.168.1.11
192.168.1.12
```

Run:

```bash
nmap -sV -iL targets.txt -oN subnet-scan.txt
```

## Practical Walkthrough

### 1. Identify Your Network

On Linux:

```bash
ip addr
```

On Windows:

```powershell
ipconfig
```

Look for your local IP address and subnet. For example, if your IP is `192.168.1.25`, your local network is commonly `192.168.1.0/24`.

### 2. Find Live Hosts

```bash
nmap -sn 192.168.1.0/24
```

Write down the hosts that respond.

### 3. Scan One Host for Common Ports

```bash
nmap 192.168.1.10
```

Look for open ports and compare them against what you expect the system to run.

### 4. Identify Services

```bash
nmap -sV 192.168.1.10
```

Check whether service names and versions make sense for that host.

### 5. Scan All TCP Ports if Needed

```bash
nmap -p- 192.168.1.10
```

If you find unusual ports, scan them with version detection:

```bash
nmap -sV -p 8080,8443,3389 192.168.1.10
```

### 6. Save Evidence

```bash
nmap -sV 192.168.1.10 -oN 192.168.1.10-nmap.txt
```

Keep scan results with your notes so you can compare changes over time.

## Example Network Engineer Workflow

```bash
nmap -sn 10.10.10.0/24
nmap -sV -p 22,53,80,443,445,3389 10.10.10.25 -oN host-scan.txt
nmap -p- 10.10.10.25 -oN host-all-tcp-ports.txt
sudo nmap -sU --top-ports 20 10.10.10.25 -oN host-common-udp.txt
```

Use this workflow to:

- Confirm a host is online
- Check expected management ports
- Find unexpected TCP services
- Check common UDP services
- Save results for documentation or troubleshooting


# PowerShell Commands

### Creating/Reading/Deleting Files

```powershell
Get-Content file.txt                    # Print an entire file
Get-Content file.txt | more             # View a file page by page
Get-Content file.txt -Head 10           # Show the first lines
Get-Content file.txt -Tail 10           # Show the last lines
Get-Content app.log -Wait               # Follow new log output live
Get-Volume                              # Shows available drives and mount points
Get-Content file.txt | Select-String "Hello World"  # Search based on keywords
```

### Select-String (PowerShell Equivalent of grep)

Search logs for matching keywords.

```powershell
# Case-insensitive search for 'error' in a file
Select-String -Path C:\Logs\app.log -Pattern "error"

# Recursive search for 'main' in current directory
Get-ChildItem -Recurse | Select-String "main"

# Show matching lines with context
Select-String -Path application.log -Pattern "error" -Context 3

# Search for multiple patterns
Select-String -Path application.log -Pattern "error","warning"

# Count occurrences
(Select-String -Path security.log -Pattern "failed").Count
```

### Get-Process (PowerShell Equivalent of ps aux)

Displays all running processes on the system.

```powershell
Get-Process
```

Detailed view:

```powershell
Get-Process | Select-Object `
Name,
Id,
CPU,
WorkingSet,
StartTime
```

Sort by CPU:

```powershell
Get-Process | Sort-Object CPU -Descending
```

Sort by Memory:

```powershell
Get-Process | Sort-Object WorkingSet -Descending
```

### Common Get-Process Properties

| Property | Description |
|-----------|-------------|
| Name | Process name |
| Id | Process ID (PID) |
| CPU | Total CPU time consumed |
| WorkingSet | Physical memory (RAM) in use |
| VirtualMemorySize | Virtual memory allocated |
| StartTime | Time process started |
| Path | Executable location |
| Company | Software vendor |
| Description | Process description |

### Example

```powershell
Get-Process | Select Name,Id,CPU,WorkingSet
```

| Name | Id | CPU | WorkingSet |
|------|----|-----|------------|
| svchost | 1024 | 15.3 | 55000000 |
| chrome | 2345 | 42.7 | 325000000 |
| powershell | 5678 | 1.1 | 85000000 |

---

### Permissions

View ACL permissions:

```powershell
Get-Acl file.txt
```

Grant Full Control:

```powershell
icacls file.txt /grant User:F
```

| Permission | Description |
|------------|-------------|
| F | Full Control |
| M | Modify |
| RX | Read and Execute |
| R | Read |
| W | Write |

View permissions recursively:

```powershell
Get-ChildItem . -Recurse | Get-Acl
```

---

### Pipes

A pipe sends the output of one command into another command.

```powershell
Get-ChildItem | Out-Host -Paging
```

Example:

```powershell
Get-Process | Sort-Object CPU -Descending
```

---

### Tail

Show the last 50 lines of a log file.

```powershell
Get-Content application.log -Tail 50
```

Follow log updates live.

```powershell
Get-Content application.log -Wait
```

Show last 50 lines and continue watching.

```powershell
Get-Content application.log -Tail 50 -Wait
```

---

### Measure-Object (PowerShell Equivalent of wc)

Count lines:

```powershell
(Get-Content file.txt | Measure-Object -Line).Lines
```

Count words:

```powershell
(Get-Content file.txt | Measure-Object -Word).Words
```

Count characters:

```powershell
(Get-Content file.txt | Measure-Object -Character).Characters
```

Count files in a directory:

```powershell
(Get-ChildItem).Count
```

# Sysinternals

https://live.sysinternals.com/


Sysinternals is a suite of advanced Windows system utilities developed by Microsoft. These tools provide deep visibility into operating system processes, services, drivers, network connections, registry activity, and other low-level system components that are not easily accessible through standard Windows administration tools.

## Common Sysinternals Tools

| Tool | Purpose |
|--------|---------|
| Autoruns | Identifies programs configured to run automatically at startup |
| Handle | Identifies which processes have files or resources open |
| Process Explorer | Advanced process monitoring and analysis |
| Process Monitor (Procmon) | Real-time monitoring of file, registry, process, and network activity |
| PsExec | Executes commands remotely on Windows systems |
| RAMMap | Examines memory usage and allocation |
| RootkitRevealer | Detects signs of user-mode or kernel-mode rootkits |
| Sigcheck | Verifies digital signatures and analyzes files |
| TCPView | Displays active network connections and listening ports |


# Security Onion

https://docs.securityonion.net/en/3/main/getting-started/

Security Onion is a defensive monitoring platform used for network security monitoring, log collection, alerting, and investigation.

Common places to look:

- Alerts
- Hunt
- Dashboards
- PCAP
- Cases

Example detection logic:

```txt
title: External Host Connection To Internal Server
id: 8d9b3e5a-1111-4444-9999-external-internal
status: experimental
description: Detects an external source IP connecting to an internal enterprise server.
author: example
logsource:
  category: network_connection
detection:
  selection:
    destination.ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  filter_internal_source:
    source.ip|cidr:
      - '10.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection and not filter_internal_source
fields:
  - source.ip
  - destination.ip
  - destination.port
  - network.transport
  - event.dataset
falsepositives:
  - VPN concentrators
  - NAT gateways
  - trusted partner IPs
level: medium
```

# Splunk

https://www.splunk.com/en_us/blog/learn/splunk-cheat-sheet-query-spl-regex-commands.html

Splunk is used to search, analyze, alert on, and visualize machine data such as logs, firewall events, authentication events, and application activity.

Common actions:

- Search logs with SPL
- Build alerts
- Create dashboards
- Extract fields
- Investigate events by host, user, IP address, or time range

### Alert - Determine how often to check and how to alert

```spl
index=network sourcetype=firewall
dest_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
NOT src_ip IN ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
action=allowed
| stats count by src_ip dest_ip dest_port action
| where count > 0
```

### Dashboard - Count how many times log occurs

```spl
index=app sourcetype=application_logs "User login failed"
| stats count AS failed_login_message_count
```

### Dashboard - Extract value using regex

```spl
index=app sourcetype=application_logs "User login failed"
| rex "user=(?<username>\w+)"
| stats count AS failures by username
| sort - failures
```


# pfSense

https://docs.netgate.com/pfsense/en/latest/index.html

pfSense is a firewall and router platform used for traffic filtering, NAT, VPNs, DHCP, DNS, and basic network services.

Common places to look:

- Dashboard
- Interfaces
- Firewall
- Services
- Diagnostics
- Status
- System

### Checking Logs
```txt
Status → System Logs → Firewall

Block
SRC: 203.0.113.25 #External IP attempting to connect to 10.1.1.50 internal IP using RDP
DST: 10.1.1.50
PORT: 3389
PROTO: TCP

Status → System Logs → Firewall

203.0.113.25
```

### Blocking an IP

```txt
Firewall → Rules → WAN

Action: Block
Source: 203.0.113.25
Destination: Any
```

# QRadar

https://www.ibm.com/docs/en/qsip/7.4.0?topic=SS42VS_7.4/com.ibm.qradar.doc/c_qradar_pdfs.htm


https://www.ibm.com/docs/en/SS42VS_7.4/pdf/b_qradar_gs_guide.pdf

QRadar is a SIEM used to collect events and flows, correlate activity, generate offenses, and support investigations.

Common places to look:

- Offenses
- Log Activity
- Network Activity
- Assets
- Rules
- Reports

Basic investigation flow:

```text
1. Open the offense.
2. Review source IPs, destination IPs, users, and event names.
3. Pivot into Log Activity or Network Activity.
4. Check the timeline and magnitude.
5. Determine whether the activity is expected or suspicious.
6. Document findings and escalate or contain if needed.
```


# Triage Steps

## Quick Triage Checklist

### Linux

```bash
hostname
ip a
who
ss -tunap
ss -tulpn
ps aux --sort=-%cpu | head
last
tail -50 /var/log/auth.log
systemctl list-units --type=service
```

### Windows

```powershell
hostname
ipconfig
whoami
netstat -ano
tasklist
Get-Service
Get-WinEvent -LogName Security -MaxEvents 50
Get-WinEvent -LogName System -MaxEvents 50
```

---

### Quick Triage Flow

```text
1. Identify the affected host.
2. Determine the affected service.
3. Find active connections and remote IPs.
4. Identify listening ports.
5. Map ports to processes.
6. Review user activity.
7. Review authentication and system logs.
8. Determine whether activity is expected.
9. Contain malicious activity.
10. Document findings and actions taken.
```

---

## 1. Identify the Problem

### Questions to Answer

```text
What host is affected?
What service is affected?
What time did the issue start?
What IPs are involved?
What user account is involved?
```

---

## 2. Identify Host Information

### Linux (RHEL/Ubuntu)

```bash
hostname
ip a
whoami
date
```

### Windows

```powershell
hostname
whoami
ipconfig
Get-Date
```

---

## 3. Identify Active Connections

### Linux

Show active connections:

```bash
ss -tunap
```

Older systems:

```bash
netstat -tunap
```

Look for:

```text
ESTABLISHED connections
Unexpected external IPs
Unknown listening services
```

### Windows

```powershell
netstat -ano
```

Find process owning connection:

```powershell
tasklist | findstr <PID>
```

Example:

```powershell
tasklist | findstr 1234
```

Look for:

```text
External IPs
Suspicious ports
Unknown processes
```

---

## 4. Identify Open Ports

### Linux

```bash
ss -tulpn
```

or

```bash
netstat -tulpn
```

Example output:

```text
TCP 0.0.0.0:22
TCP 0.0.0.0:80
TCP 0.0.0.0:443
```

Questions:

```text
Should this port be open?
Should this service be running?
```

### Windows

```powershell
netstat -ano | findstr LISTENING
```

Match PID to process:

```powershell
tasklist | findstr <PID>
```

---

## 5. Identify Running Processes

### Linux

```bash
ps aux
```

Sort by CPU:

```bash
ps aux --sort=-%cpu | head
```

Sort by Memory:

```bash
ps aux --sort=-%mem | head
```

### Windows

```powershell
tasklist
```

Detailed view:

```powershell
Get-Process
```

---

## 6. Check User Activity

### Linux

Current users:

```bash
who
w
```

Login history:

```bash
last
```

Failed logins (Ubuntu):

```bash
grep "Failed" /var/log/auth.log
```

Failed logins (RHEL):

```bash
grep "Failed" /var/log/secure
```

### Windows

Failed logins:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
```

Recent security events:

```powershell
Get-WinEvent -LogName Security -MaxEvents 50
```

---

## 7. Check Logs

### Linux

Authentication:

```text
/var/log/auth.log
```

System:

```text
/var/log/syslog
```

Live monitoring:

```bash
tail -f /var/log/syslog
```

### Windows

Open Event Viewer:

```powershell
eventvwr.msc
```

Security Logs:

```powershell
Get-WinEvent -LogName Security -MaxEvents 50
```

System Logs:

```powershell
Get-WinEvent -LogName System -MaxEvents 50
```

Application Logs:

```powershell
Get-WinEvent -LogName Application -MaxEvents 50
```

---

## 8. Check Services

### Linux

List services:

```bash
systemctl list-units --type=service
```

Check a specific service:

```bash
systemctl status <service>
```

Examples:

```bash
systemctl status nginx
systemctl status apache2
systemctl status sshd
```

### Windows

List services:

```powershell
Get-Service
```

Running services only:

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
```

---

## 9. Determine Scope

```text
What IP connected?
What port was used?
What process owns the port?
What user executed the process?
What logs show activity?
Is the activity expected?
```

---

## 10. Contain If Malicious

### Linux

Kill process:

```bash
kill <PID>
```

Stop service:

```bash
systemctl stop <service>
```

Block IP:

```bash
iptables -A INPUT -s <IP> -j DROP
```

### Windows

Kill process:

```powershell
taskkill /PID <PID> /F
```

Block IP:

```powershell
New-NetFirewallRule `
-DisplayName "Block Bad IP" `
-Direction Inbound `
-RemoteAddress <IP> `
-Action Block
```

---

### Common Windows Security Event IDs

| Event ID | Description |
|-----------|------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials |
| 4672 | Privileged logon |
| 4688 | Process creation |
| 4697 | Service installed |
| 4720 | User account created |
| 4728 | Added to privileged group |
| 4732 | Added to local Administrators |
| 4740 | Account locked out |
| 7045 | Service created |
