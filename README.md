# **Range Topics**

## Table of Contents
- [Common Ports](#common-ports)
- [Linux Commands](#linux-commands)
- [Security Onion](#security-onion)
- [Splunk](#splunk)
- [Palo Alto](#palo-alto)
- [PfSense](#pfsense)


 
# Common Ports

- SSH: 22 TCP
- Telnet: 23 TCP
- SMB: 445 TCP
- DNS: 53 UDP
- SNMP traps: 162 UDP
- SNMP manager: 161 UDP
- DHCP server listen: 67 UDP
- DHCP client receive: 68 UDP
- TFTP: 69 UDP
- HTTP: 80 TCP
- HTTPS: 443 TCP
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

### Permissions

```bash
chmod 777 file.txt 
```

4 gives Write privileges to a file
2 gives Read privileges to a file
1 gives execute privileges to a file

7 - all permissions
6 - Read/Write
5 - write/execute
3 - read/execute

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