---
layout: default
title:  "Server Message Block(SMB)"
date:   2024-06-12 09:00:00 +0000
categories: smb recon reconnaissance 
---

# Server Message Block(SMB) reconnaissance

> ### Introduction

{: style="text-align: justify" }
The Server Message Block (SMB) protocol is a cornerstone of network communications within many enterprise environments. It allows applications to read and write to files and request services from server programs in a networked environment. While SMB facilitates essential functions like file sharing, printer sharing, and communication between network devices, it also presents a significant attack surface if not properly secured. This blog post delves into the reconnaissance techniques for SMB and highlights common vulnerabilities that can be exploited by malicious actors.

{: style="text-align: justify" }
SMB is a network file sharing protocol primarily used for providing shared access to files, printers, and serial ports. The protocol has undergone significant evolution since its inception, resulting in various versions, each with distinct features, improvements, and security enhancements. 

> ### SMB Versions

{: style="text-align: justify" }
**SMBv1** was introduced in 1983 by IBM, and later adopted and modified by Microsoft. It's primary use was to provide basic functionality for file sharing, printer sharing and network browsing. SMBv1, however, does not support encryption, making data transmitted over the network susceptible to interception. The use of null sessions allowed unauthenticated access to certain resources, facilitating information gathering by attackers. A critical vulnerability, known as EternalBlue (***MS17-010***), developed by the NSA was leaked to bad actors and used in wide reaching ransomware atttacks such as WannaCry as it allowed remote code execution on unpatched systems. Due to its inherent vulnerabilities and lack of modern security features, SMBv1 should be disabled on all systems.

{: style="text-align: justify" }
**SMBv2** was introduced with Windows Vista and Windows Server 2008 with enhanced performance and security for file sharing and network communication. A reduced command/response overhead, improved performance and scalability. Multiple requests could be sent through pipelining mechanisms, which improved performance over high latency links. SMBv2 also included support for larger reads, increasing the efficiency of data transfers, and improved the resilience of temporary network disruptions through the use of durable file handles. SMBv2 supports stronger authentication mechanisms compared to SMBv1. While significantly more secure than SMBv1, SMBv2 can still be susceptible to attacks if not properly configured and patched. Issues like man-in-the-middle attacks can occur if message signing is not enforced. Message signing is a security feature implemented in the SMB protocol to ensure the integrity and authenticity of the data being exchanged between clients and servers. When SMB message signing is enabled, each message exchanged between an SMB client and server is signed with a digital signature. This signature is a cryptographic hash generated from the message contents and a shared secret, typically derived from the session key established during the authentication process. The recipient can then verify the signature to ensure that the message has not been altered in transit.

{: style="text-align: justify" }
**SMBv3** was introduced with Windows 8 and Windows Server 2012 and provides secure, high-performance file sharing and network services. SMB3 supports end-to-end AES-128 encryption, providing robust protection to data in transit against eavesdropping. Secure negotiation ensures that clients and servers negotiate the highest level of security supported. Modern authentication protocols are in use to ensure secure access to network resources. Further enhancements in read/write operations and the use of multiple network connections simultaneously for increased throughput and redundancy result is greater performance, scalability and the overall efficiency of the protocol over older versions. Even with the advanced security features, improper configuration of SMBv3 can lead to vulnerabilities. For example, disabling encryption can expose data to interception. Interoperability with older SMB versions can introduce security risks if not managed properly. A downgrade attack is a type of cyberattack where an attacker forces a communication protocol to fall back to an older, less secure version, thereby exploiting known vulnerabilities in the older version. In the context of SMB, a downgrade attack against an SMBv3 resource could potentially force the protocol to revert to SMBv2 or even SMBv1, making it susceptible to a variety of attacks that have been mitigated in later versions.

> ### SMB Network Ports

{: style="text-align: justify" }
The SMB protocol utilizes specific network ports to facilitate communication between clients and servers within a network. It operates mainly over ports 139 and 445.

{: style="text-align: justify" }
TCP/UDP port ```139``` is used by older implementations of SMB (primarily SMBv1) that rely on the NetBIOS over TCP/IP (NBT) protocol for network communication. Due to its association with the older SMBv1 protocol and NetBIOS, port ```139``` is often seen as a legacy port that can pose security risks if left open and unmonitored. Modern networks should consider disabling SMBv1 and the use of ```port 139``` where possible. Where port ```139``` is in use to provide NBT communication, TCP/UDP ports ```137``` and ```138``` may also be seen open. Port ```137``` is used for the NetBIOS Name Service (NBNS), which handles name registration and resolution in a NetBIOS network. Port ```138``` is used for the NetBIOS Datagram Service, which supports connectionless communication for tasks such as sending broadcast messages within a network. Like port ```139```, ```137``` and ```138``` are associated with legacy NetBIOS services and can be vectors for attacks. These ports are often unnecessary in modern networks and should be disabled unless specifically required for compatibility reasons.

{: style="text-align: justify" }
TCP/UDP port ```445``` is the primary port used by SMB versions 2 and 3, as well as modern implementations of SMBv1, for direct access over TCP/IP without the need for the NetBIOS layer. Port ```445``` enables direct hosting of SMB over TCP, allowing faster and more efficient communication by bypassing the NetBIOS layer. This port is essential for modern Windows operating systems and other platforms that implement SMB over TCP/IP. Since it is a common target for attacks such as WannaCry ransomware (which exploits the EternalBlue vulnerability), port```445``` should be carefully monitored and protected.

> ### Common SMB Software

{: style="text-align: justify" }
There are several common SMB software implementations and tools used across various operating systems and network environments. These tools facilitate file sharing, printer sharing, and other network services using the SMB protocol. Here are some notable examples of SMB software:

***Server Software***

* **Samba**: Samba is one of the most widely used open-source implementations of the SMB/CIFS protocol suite for Unix/Linux systems. It allows Unix-like operating systems to share files and printers with Windows clients.
* **Windows Server**: Microsoft's Windows Server operating system includes built-in support for SMB, allowing Windows-based servers to offer file and print services to clients using the SMB protocol.
* **FreeNAS / TrueNAS**: FreeNAS and its successor TrueNAS are open-source network-attached storage (NAS) operating systems based on FreeBSD. They support SMB among other protocols to provide file sharing capabilities.

***Client Software***

* **Windows File Explorer**: Built-in to Windows operating systems, File Explorer (previously known as Windows Explorer) supports accessing and managing files and folders on SMB shares.
* **macOS Finder**: The default file manager in macOS, Finder supports accessing shared folders and printers on SMB servers.
* **Linux Clients (e.g., Nautilus, Dolphin, Thunar)**: Various Linux desktop environments include file managers that support browsing and accessing SMB shares.
* **Linux CLI**: The mount command in Linux is used to attach (mount) file systems and devices to the Linux file system hierarchy. The basic syntax is as follows:

```bash 
sudo mount -t cifs //server/share /mnt/point -o options
```

> ### Performing Reconnaissance

{: style="text-align: justify" }
Before exploiting any vulnerabilities, attackers typically engage in reconnaissance to gather information about the target system's SMB implementation. Here are some common reconnaissance techniques:

#### 1. Scanning for SMB Services

{: style="text-align: justify" }
The first step in reconnaissance involves identifying hosts that are running SMB services. This can be accomplished using network scanning tools such as Nmap or Masscan, which are extensively utilized for network discovery and security audits.

Using Nmap to Scan for FTP services:

```bash 
nmap -p 139,445 -sV <target IP>
```

* ```-p 139,445``` : Specifies to scan ports 139 and 445, the default ports for SMB.
* ```-sV``` : Attempts to determine the version of the service running on the specified port.

Example:

```bash
nmap -p 139,445 -sV 192.168.1.0/24
```

{: style="text-align: justify" }
This command will scan all hosts in the 192.168.1.0/24 subnet for the SMB service and attempt to identify the version of the FTP service running. Nmap will provide output indicating which hosts have ports 139 and/or 445 open and the version of the SMB service found. Look for banners or service versions that might indicate outdated or vulnerable software.

{: style="text-align: justify" }
Tools such as Netcat and Telnet can also be used to connect directly to the SMB ports in an effort to test if the port is open and interact with the port dorectly.

#### 2. Enumerating Shares:

{: style="text-align: justify" }
SMB enumeration is a critical phase in penetration testing and security assessments, aiming to gather detailed information about SMB services and shares on a network. This process helps identify potential vulnerabilities and misconfigurations that could be exploited by attackers.

{: style="text-align: justify" }
**enum4linux** is a powerful open-source tool designed specifically for enumerating information from SMB shares and servers. It performs a series of queries and requests against SMB services to extract valuable data such as user names, shares, policies, and more. By leveraging enum4linux, penetration testers can quickly gather essential information about the target network's SMB configuration without requiring extensive manual effort. The tool's automated approach simplifies the enumeration process, providing structured results that aid in identifying potential entry points for further exploitation.

```bash 
smbclient -L \\<target IP>
```

{: style="text-align: justify" }
**rpcclient** is another command-line utility included in the Samba suite, widely used for interacting with SMB servers via Remote Procedure Call (RPC). It allows penetration testers to establish interactive sessions with SMB servers to query information, enumerate users and shares, and execute commands. rpcclient supports a variety of RPC services exposed by SMB, enabling testers to gather detailed insights into the server's configuration, user accounts, and potentially sensitive data. Its versatility and direct interaction with SMB services make rpcclient invaluable during the enumeration phase, facilitating thorough reconnaissance and vulnerability assessment.

| **Query** | **Description** |
| ------- | ------- |
| ```srvinfo``` | Server information. |
| ```enumdomains``` | Enumerate all domains that are deployed in the network. |
| ```querydominfo``` | Provides domain, server, and user information of deployed domains. |
| ```netshareenumall``` | Enumerates all available shares. |
| ```netsharegetinfo``` | Provides information about a specific share. |
| ```enumdomusers``` | Enumerates all domain users. |
| ```queryuser``` | Provides information about a specific user. |

{: style="text-align: justify" }
**Metasploit**, a renowned framework for penetration testing and exploitation, includes modules specifically designed for SMB enumeration and exploitation. Leveraging Metasploit's robust capabilities, testers can automate and streamline the process of identifying SMB vulnerabilities and misconfigurations. Metasploit modules for SMB enumeration can conduct comprehensive scans, exploit known weaknesses like SMB vulnerabilities, and escalate privileges by leveraging identified vulnerabilities. Its integration with a vast database of exploits and payloads empowers testers to perform advanced SMB enumeration and subsequent exploitation with efficiency and precision, making it a cornerstone tool in penetration testing engagements.
