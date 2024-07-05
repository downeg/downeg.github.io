---
layout: default
title:  "File Transfer Protocol (FTP)"
date:   2024-05-07 09:00:00 +0000
categories: ftp recon reconnaissance 
---

# File Transfer Protocol (FTP) reconnaissance

## Introduction

File Transfer Protocol (FTP) is one of the oldest protocols still in use today for transferring files over the Internet. Despite its age, it is still prevalent in many networks, often due to legacy systems or specific operational requirements. However, its age also means it can be rife with vulnerabilities if not properly secured. This blog post investigates the FTP protocol, and discusses performing reconnaissance on FTP services to identify potential vulnerabilities that can be exploited by attackers.

FTP is a standard network protocol used to transfer files between a client and a server on a computer network. Established in the 1970s, FTP has evolved but retains its basic functionality and design, making it both a powerful tool for file transfers and a potential security risk if not properly managed.

FTP operates on a client-server model, where the client initiates a connection to the server to upload or download files. This process involves two key types of connections: ***control*** and ***data***.

>**Control Connection:** This connection is established over port 21 and is used for sending commands from the client to the server and receiving responses. This includes authentication commands (e.g., USER and PASS), navigation commands (e.g., CWD for changing directories), and file operation commands (e.g., STOR for storing a file on the server).
>
>**Data Connection:** This connection is used for the actual transfer of files and can operate in two modes: active and passive.

FTP can be run in two modes depending on firewall restictions: ***active*** and ***passive***.

**Active Mode FTP:** In active mode, the client opens a random port above 1023 and informs the server of this port. The server then initiates the data connection back to the client's specified port from its port 20. This mode can be problematic if the client is behind a firewall or NAT (Network Address Translation) that blocks incoming connections.

>* **Advantages:** Simple to configure on the server side as the server initiates the data connection.
>* **Disadvantages:** More complex for clients behind firewalls/NAT, as these typically block incoming connections.

**Passive Mode FTP:** In passive mode, the server opens a random port above 1023 and informs the client. The client then initiates the data connection to this port. Passive mode is more firewall-friendly as it allows the client to initiate both control and data connections.

>* **Advantages:** Easier for clients behind firewalls/NAT as the client initiates both connections, reducing issues with blocked ports.
>* **Disadvantages:** Requires additional configuration on the server to manage the range of ports used for passive connections, which must be open and forwarded through the firewall.

## Key FTP Commands

FTP uses a set of standardized commands for communication between the client and the server. Some of the most common commands include:

* **USER**: Specifies the username for authentication.
* **PASS**: Specifies the password for authentication.
* **LIST**: Lists files and directories in the current directory.
* **RETR**: Retrieves (downloads) a file from the server.
* **STOR**: Stores (uploads) a file to the server.
* **DELE**: Deletes a file from the server.
* **CWD**: Changes the working directory.
* **PWD**: Prints the working directory.

These commands are transmitted in plain text, which presents significant security risks, as they can be intercepted by attackers.

## Common FTP Software

Several FTP server and client software are widely used:
*FTP Servers:*
* **vsftpd**: A secure, fast, and stable FTP server for Unix-like systems.
* **ProFTPD**: Highly configurable and designed for Unix-like systems, with a modular design.
* **FileZilla Server**: A popular open-source FTP server for Windows.

*FTP Clients:*
* **FileZilla**: A free and open-source FTP client supporting multiple platforms.
* **WinSCP**: A free SFTP, SCP, and FTP client for Windows.
* **Cyberduck**: A versatile client supporting FTP, SFTP, and various cloud storage services, available for macOS and Windows.

## Security Concerns

FTP's design, which predates modern security practices, leads to several security concerns:

*   **Plain Text Transmission:** Both control commands and data are sent in plain text, making FTP susceptible to eavesdropping and credential interception.
*   **Authentication and Access Control:** Weak or misconfigured authentication mechanisms can lead to unauthorized access. Anonymous login, if not properly restricted, can expose sensitive information.
*   **Brute Force Attacks:** Weak password policies can lead to successful brute force attacks, especially if the FTP server is exposed to the internet.
*   **Data Integrity:** FTP does not provide mechanisms for ensuring the integrity of transferred data. Malicious actors could modify files during transmission without detection.
*   **Port Vulnerabilities:** FTP's use of multiple ports (21 for control, 20 for data in active mode) can complicate firewall configurations and potentially expose servers to attack if not properly secured. The nature of active mode requires open ports on the client side, which can conflict with firewall policies. Passive mode requires open ports on the server side, which also introduces security considerations.
*   **Protocol Limitations:** FTP lacks modern security features like encryption, mutual authentication, and integrity verification, which are standard in more secure file transfer protocols like SFTP (SSH File Transfer Protocol) and FTPS (FTP over SSL/TLS).

## Performing Reconnaissance

Reconnaissance is the first and most crucial phase in a penetration test or security assessment. This phase involves gathering as much information as possible about the target system to identify potential vulnerabilities. When focusing on FTP, the reconnaissance phase can be broken down into several key steps:

### 1. Scanning for FTP Services
The initial step in reconnaissance is to identify hosts running FTP services. This can be done using network scanning tools like Nmap, which is widely used for network discovery and security auditing.
Using Nmap to Scan for FTP services:
```bash
nmap -p 21 -sV <target-IP-range>
```

*   ```-p 21``` : Specifies to scan port 21, the default port for FTP.
*   ```-sV``` : Attempts to determine the version of the service running on the specified port.

Example:
```bash
nmap -p 21 -sV 192.168.1.0/24
```

This command will scan all hosts in the 192.168.1.0/24 subnet for an FTP service on port 21 and attempt to identify the version of the FTP service running. Nmap will provide output indicating which hosts have port 21 open and the version of the FTP service. Look for banners or service versions that might indicate outdated or vulnerable software.

### 2. Banner Grabbing

FTP services often reveal valuable information in their banners. You can manually connect to an FTP server using tools like Telnet or Netcat to capture the banner:
```bash
telnet <target-IP> 21
nc -p 21 <target-ip>
```

Or, you can use Nmap's built-in script for banner grabbing:
```bash
nmap -p 21 --script=banner <target-IP>
```
### 3. Enumerating Users

Anonymous access or default credentials can be a significant vulnerability. Try logging in with the username anonymous and any password. Many FTP servers allow this by default:
```bash
ftp <&lt>target-IP>
```
Use anonymous as the username and any email address as the password.

### 4. Identifying Vulnerabilities

Once you have basic information about the FTP service, use vulnerability databases and tools to identify known vulnerabilities. Searchsploit from Exploit-DB can be very useful:

```bash
searchsploit ftp <service-version>
```

### 5. Using Automated Tools

Automated tools can help streamline the reconnaissance process. It is important to be aware that automated tools can be detected by network defenders through unusual User-Agent strings or behaviors that deviate from normal traffic patterns. Additionally, the high volume of packets sent by these tools during scanning and enumeration can trigger intrusion detection systems (IDS) and raise red flags with network monitoring tools. Two popular automated tools that can be used to fingerprint FTP servers are Nikto and Metasploit.

Nikto is included in Kali Linux and can be run on the default FTP port as follows:
```bash
nikto -host <target-IP> -p 21
```

Metasploit can be used for a more in-depth analysis and exploitation:
```bash
msfconsole |use auxiliary/scanner/ftp/ftp_version
set RHOSTS <target-IP>
run
```
Nmap can be run against the target(s) with the default scripts and Nmap Scripting Engine scripts included with the command. The NSE scripts include scripts for brute forcing, so may take a long time to complete and are very noisy on the wire:
```bash
```nmap -p 21 -sV -sC --script==ftp* <target-IP-range>
```
## Performing Reconnaissance with TLS/SSL

Performing reconassaince on an FTP server that uses SSL/TLS encryption involves identifying the specific characteristics of the SSL/TLS implementation to gather information about the server. This process includes analyzing the server's SSL/TLS certificate, the supported ciphers, and the protocol versions. Here's how you can do it:
### 1. Using Nmap with SSL/TLS Scripts

Nmap has several built-in scripts that can help fingerprint SSL/TLS implementations on FTP servers.
```bash
nmap --script ssl-cert -p 21 <target-IP>
```

This script retrieves and displays the SSL/TLS certificate details, such as the issuer, subject, validity period, and any associated metadata. This information can help identify the software and version of the FTP server.
```bash
nmap --script ssl-enum-ciphers -p 21 <target-IP>
```

This script enumerates the supported cipher suites and protocols (e.g., SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3) used by the FTP server. The specific combination of supported ciphers and protocols can provide clues about the underlying server software and version.

### 2. Using SSLyze

SSLyze is a powerful tool specifically designed to analyze SSL/TLS configurations.
```bash
sslyze --regular <target-IP>:21
```

SSLyze performs a thorough analysis of the SSL/TLS configuration, including certificate details, supported protocols, cipher suites, and potential vulnerabilities (e.g., Heartbleed, POODLE).

### 3. Manual Analysis with OpenSSL

OpenSSL can be used to manually connect to the FTP server and retrieve SSL/TLS information.

Retrieving SSL/TLS Certificate:
```bash
openssl s_client -connect <target-IP>:21 -starttls ftp
```

This command initiates a connection to the FTP server and starts an SSL/TLS handshake. The output includes detailed information about the server's SSL/TLS certificate.

Listing Supported Cipher Suites:
```bash
openssl s_client -connect <target-IP>:21 -starttls ftp -cipher 'ALL'
```

This command attempts to connect using different cipher suites to determine which ones are supported by the server.

### 4. Analyzing Server Responses

In addition to using tools, analyzing the server's responses during the SSL/TLS handshake can provide valuable fingerprinting information. Differences in response times, specific error messages, and the order of offered cipher suites can all hint at the server software and version.