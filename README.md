# **Range Topics**

## Table of Contents
- [Common Ports](#common-ports)
- [Linux Commands](#linux-commands)
- [Security Onion](#security-onion)
- [Splunk](#splunk)
- [Palo Alto](#palo-alto)
- [PfSense](#pfsense)
- [Triage Steps](#triage-steps)
- [Quick Triage Checklist](#quick-triage-checklist)
 
# Common Ports

- SSH: 22 TCP
- Telnet: 23 TCP
- DNS: 53 UDP
- DHCP server listen: 67 UDP
- DHCP client receive: 68 UDP
- TFTP: 69 UDP
- HTTP: 80 TCP
- SNMP manager: 161 UDP
- SNMP traps: 162 UDP
- HTTPS: 443 TCP
- SMB: 445 TCP
- PostgreSQL: 5432
- HTTP Proxy: 8080
- MongoDB: 27017


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

| USER | PID | %CPU | %MEM | VSZ | RSS | TTY | STAT | START | TIME | COMMAND
|------|-----|-----|-----|-----|-----|-----|------|-------|------|------|
| root | 1 | 0.0 | 0.1 | 168000 | 12000 | ? | Ss | 08:00 | 0:01 |sbin/init |
|www-data | 522 | 0.2 | 0.5 | 250000 | 50000 | ? | S | 08:01 | 0:05 | apache2 |
|ethan | 1254 | 5.1 | 1.2 | 800000 | 95000 | pts/0 | Sl | 09:15 | 1:32 python3 | app.py |

## ps aux Columns

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
| R | Running |
| S | Sleeping (waiting for an event) |
| D | Uninterruptible sleep (usually disk I/O) |
| T | Stopped |
| Z | Zombie (terminated but not cleaned up) |
| s | Session leader |
| l | Multi-threaded process |
| + | Running in foreground process group |

### Example

```text
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      1024  0.1  0.3 168000 12000 ?        Ss   08:00   0:01 sshd
apache    2048  1.2  1.5 450000 60000 ?        Sl   08:05   0:10 httpd
```

- `sshd` is owned by `root`
- PID is `1024`
- State `Ss` = Sleeping + Session Leader
- Started at `08:00`
- Has consumed `0:01` of CPU time


### Permissions

```bash
chmod 777 file.txt 
```
|Number| Description|
|------|------------|
|4| gives Write privileges to a file|
|2| gives Read privileges to a file|
|1| gives execute privileges to a file|

|Combination Number| Description|
|------|------------|
| 7 | all permissions|
| 6 | Read/Write|
| 5 | write/execute|
| 3 | read/execute|

|Owner | Group | Others (Standard Users)| Permission Type |
|------|-------|------------------------|     ------      |
| 7    | 7     | 7                      | Everyone has permission to Read/Write/Execute |
| 7    | 1     | 1                      | Only file only can read/write/execute, everyone else can only execute |
| 7    | 6    | 1                      | Owner has rwx, group has rw, other has execute

### Pipes

A pipe sends the output of one command into another command.

```bash
ls -la | less
```

### tail
```bash
tail -n 50 #Returns the last specified lines in a log, in this case 50
```

### wc - (word count)
```bash
wc # counts how many words are returned
wc - l #counts how many lines are returned
```

# Security Onion

https://docs.securityonion.net/en/3/main/getting-started/

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

# Palo Alto

https://www.paloguard.com/documentation.asp

- Monitor
- Policies
- Objects
- Network

### View Traffic

```txt
Monitor → Logs → Traffic

Source: 10.1.1.100
Destination: 8.8.8.8
Application: dns
Action: allow
Rule: Internal-DNS
```
# PfSense

https://docs.netgate.com/pfsense/en/latest/index.html

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

### Threat Logs

```txt
Monitor → Logs → Threat

Threat Name:
ET MALWARE Emotet C2

Action:
reset-both
```


# Triage Steps

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

## Windows

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

---

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
