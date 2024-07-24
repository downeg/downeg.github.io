---
layout: default
title:  "Case Study: Mirai Botnet"
date:   2023-11-10 09:00:00 +0000
categories: mirai botnet malware university assignment
---

# Case Study: Mirai Botnet 

---
University assignment Autumn 2023

---

> #### Executive Summary.

{: style="text-align: justify" }
In September 2016 a simple piece of malware highlighted the prevalence of one of the oldest vulnerabilities in technology: the default password. The Mirai botnet was responsible for some of the biggest Distributed Denial of Service (DDoS) attacks of its time.

{: style="text-align: justify" }
Powered by an army of simple Internet of Things (IoT) devices, this botnet could bring the most popular websites in the world to a halt. Initially created as an extortion tool to leverage protection money from owners of Minecraft servers, the Mirai botnet quickly mutated after its source code was made public.

{: style="text-align: justify" }
Mirai spread by scanning the Internet for IoT devices that could be accessed using the default credentials set at the time of manufacture. At its peak in November 2016 Mirai had infected over 600,000 IoT devices. Victims of DDoS attacks made by Mirai include Amazon, Netflix and PayPal.

{: style="text-align: justify" }
The Mirai botnet continues to evolve in 2023 and can now exploit specific code vulnerabilities to gain a foothold on devices to infect them and expand its botnet.

> #### Introduction.

{: style="text-align: justify" }
In 2016 three teenagers developed a piece of malware that was destined to be responsible for some of the largest Distributed Denial of Service attacks (DDoS) of the time. Motivated by money and operating a protection racket to protect Minecraft servers against DDoS attacks, Paras Jha, Josiah White and Dalton Norman wrote the Mirai botnet.

{: style="text-align: justify" }
Mirai (the Japanese word for "future") took advantage of known default passwords on Internet of Things (IoT) devices such as IP security cameras, DVD recorders and consumer grade home-routers which were connected to the Internet using default Telnet TCP ports 23 and 2323. Whist engaged in a botnet war with another group of teenagers known as VDoS, the Mirai botnet came to prominence in September 2016 when a DDoS attack was launched against the "Krebs On Security" website, a blog run by an independent journalist who specialises in cyber-crime. Previous victims of the Mirai botnet in the same month include OVH, one a European hosting provider popularly used to host Minecraft servers.

{: style="text-align: justify" }
On 30th September 2016 Paras Jha released the source code for Mirai on the Hack Forums web site.  This was possibly an attempt to avoid responsibility for the DDoS attacks. If the code was found on a user’s computer, then the claim can be made that it was downloaded from the Internet. Also, the more users there are of a piece of malware, the easier it is for threat actors to hide.

{: style="text-align: justify" }
On 21st October 2016 a Mirai attack targeted the popular DNS provider DYN. This resulted in many large popular websites being unavailable as name resolution to these domains was affected by the DDoS attack. The list of over 1200 websites web sites affected include Amazon, Netflix, PayPal and Twitter.

{: style="text-align: justify" }
Shortly afterwards on the 26th November 2016 an altered version of Mirai infected over 900,000 routers belonging to Deutche Telekom leaving almost 1 million users offline. Rather than being a targeted DDoS attack on the company, this was a botched attempt to add the routers to a botnet but a bug in the code caused the routers to fail.

> #### How did it work?

{: style="text-align: justify" }
A threat actor would configure a Command and Control (C2) server and manually infect the first device. The first bot would enter a scanning phase searching for hosts that can be infected. TCP SYN probes are sent to ports 23 and 2323 of pseudo randomly generated IP addresses on the Internet ```antonakakis.pdf```. The bot did not attempt to probe any bogon\martian IP ranges and also excluded IP ranges owned by General Electric, Hewlett-Packard and The US Department of Defence.

IMAGE MISSING
IP address generation function showing how certain subnets are passed over. Screenshot from [Mirai-Source-Code] (https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c#L674)

{: style="text-align: justify" }
If any of the scanned IP addresses responded to the TCP SYN packet, Mirai would attempt a dictionary attack on the open Telnet port using a selection of credentials randomly picked from a hardcoded list of username/password pairs.

IMAGE MISSING
Sample of hardcoded default passwords used in dictionary attack. Screenshot from [Mirai-Source-Code] (https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c#L123)

{: style="text-align: justify" }
After a successful login, the victim device’s IP and associated credentials would be sent to a separate Scan Receiver service which in turn would dispatch the task of infecting the victim device to a Loader service. The Loader would log into the IoT device and check the device Operating System. If a suitable OS was found then it would install the malware. The newly infected IoT device would then register itself on the threat actor owned C2 server. The infected IoT device will then begin its own scanning to infect new devices and is ready to receive further instructions from the C2 server. The threat actor can then use the C2 server to launch large scale DDoS attacks by having all the bots in the botnet send a flood of traffic to a specific host or service at once. The target host/service gets overwhelmed by all the traffic and is unable to serve legitimate requests resulting in a denial of service to users.

> #### Why is the attack classified as it is?

{: style="text-align: justify" }
Mirai is classified as a self-propagating worm. NIST defines a worm as "a computer program that can run independently, can propagate a complete working version of itself onto other hosts on a network, and may consume computer resources destructively." One of Mirai's primary goals is to scan the Internet for other devices that can be infected with a copy of its code. It is self-propagating as it does not require any user intervention to spread. Once a Mirai bot has identified the IP and user credentials for a vulnerable device on the internet it will send these details back to its C2 server (the Report Server) so that the newly discovered device can be automatically infected.

{: style="text-align: justify" }
Mirai is also classified as a bot. A bot is a software program that performs automated, repetitive, pre-defined tasks. In the case of malware bots these repetitive tasks can include the sending of spam and phishing emails, and engaging in DDoS attacks. Bots can also be used as part of a network of distributed proxies used to anonymise cyber-criminal activities .

> #### Have there been any variants of the attack and are they different and/or more dangerous?

{: style="text-align: justify" }
Mirai has been evolving since the source code was released in September 2016. One early variant caused an internet outage for almost a million people in Germany as it tried to infect routers belonging to German ISP Deutche Telekom. Later variants are becoming more advanced and are no longer using just default credentials and Telnet port. A variant known as Wicked scanned ports 8080, 8443, 80, and 81 used known exploits to infect Netgear routers. 

{: style="text-align: justify" }
The uses for Mirai based botnets is also changing. OMG is a variant which includes code that allows it to be set up as a proxy server on vulnerable IoT devices. These proxy devices can be used by cyber-criminals to anonymize their nefarious activities online.

> #### How could Firewalls have been implemented or better utilized to deter the attack?

{: style="text-align: justify" }
All IoT devices that were infected were directly connected to the Internet. If these devices had been on an internal network protected by a firewall they would not have been infected. Device management ports such as Telnet, SSH and HTTP(S) should be protected by limiting or preventing access to the management interface from the Internet. If access to these management ports from the public Internet is an absolute requirement, then the firewall should be configured with a whitelist of IP addresses that are allowed to access the IoT device. The service port number should be changed to a non-default port. Since the operating systems on IoT devices is limited and changing the default management port may not be possible, port knocking could be implemented to disguise the fact that the default port is open. In port knocking, a correct sequence of port "knocks" (connection attempts) is required before the firewall will allow the connection through to the open default port of the protected device. The original Mirai botnet did not have the ability to penetrate port knocking as it only scanned default ports.

> #### What Defence in Depth techniques were in use? Could the security architecture have been improved to minimise or stop the attack?

{: style="text-align: justify" }
IoT devices differ from typical server/PC endpoints in that they usually run a very stripped-down OS and cannot have any third-party anti-virus, anti-malware or Endpoint Detection and Response software installed on them. This limits Defence in Depth techniques to what is available on the network. IoT devices can be separated from the public Internet using firewalls. The use of Network intrusion Detection Systems (NIDS) on the IoT network can then work to identify any malicious looking behaviour such as port scanning and dictionary attacks on the login interfaces of IoT devices and can analyse network packets for the known signatures of the Mirai malware before they land on the target IoT device. 

> #### What recommendations would you make to ensure a more secure network which would limit the effects of the attack in the future? What lessons can be learnt?

{: style="text-align: justify" }
Management services for IoT devices such as SSH and Telnet should never be accessible from the public Internet. These devices should be treated as inherently insecure and should be protected with compensating controls such as firewalls and network segregation. Default credentials, both the username and password, should be changed whenever possible. Automatic updates should be configured, especially on those devices such as consumer grade routers that need to be connected to the Internet.

> #### Conclusion.

{: style="text-align: justify" }
The original Mirai botnet was successful as very little importance was put on the security of IoT devices. Ports open to the public Internet and the use of default passwords made these devices ripe for attack. The OWASP Project ranked weak, guessable or hardcoded passwords as the number one vulnerability in IoT devices in 2018. Default accounts and their passwords still make the latest OWASP Top Ten list (September 2021) being ranked the fifth most common security risk in webbased applications. With the increasing popularity in 5G networks there will be more and more IoT devices being connected to the Internet. Securing these devices from the ground up with encrypted communications be default and unique passwords being set at manufacturing will be vital for securing the future.

> #### References.

* [THE STRANGE STORY OF THE TEENS BEHIND THE MIRAI BOTNET](https://spectrum.ieee.org/mirai-botnet)
* [IoT Botnet Forensics: A Comprehensive Digital Forensic Case Study on Mirai Botnet Servers](https://www.sciencedirect.com/science/article/pii/S2666281720300214)
* [Inside the infamous Mirai IoT Botnet: A Retrospective Analysis](https://blog.cloudflare.com/inside-mirai-the-infamous-iot-botnet-aretrospective-analysis/)
* [IZ1H9 Campaign Enhances Its Arsenal with Scores of Exploits](https://www.fortinet.com/blog/threat-research/Iz1h9-campaign-enhancesarsenal-with-scores-of-exploits)
* [New Mirai Variant Found Spreading like Wildfire](https://www.trendmicro.com/vinfo/gb/security/news/internet-of-things/new-miraivariant-found-spreading-like-wildfire)
* [Failed Mirai botnet attack causes internet outage for 900,000 Germans](https://www.siliconrepublic.com/enterprise/miraibotnet-deutsche-telekom)
* [Mirai-Source-Code](https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/scanner.c)
* [NIST COMPUTER SECURITY RESOURCE CENTER Online Glossary](https://csrc.nist.gov/glossary/term/worm)
* [What are bots? – Definition and Explanation](https://usa.kaspersky.com/resource-center/definitions/what-are-bots)
* [Massive 400,000 proxy botnet built with stealthy malware infections](https://www.bleepingcomputer.com/news/security/massive-400-000-proxy-botnet-built-with-stealthy-malware-infections/)
* [A Wicked Family of Bots](https://www.fortinet.com/blog/threat-research/a-wicked-family-of-bots)
* [OMG: Mirai-based Bot Turns IoT Devices into Proxy Servers](https://www.fortinet.com/blog/threat-research/omg--mirai-basedbot-turns-iot-devices-into-proxy-servers)
* [IoT Devices as Proxies for Cybercrime](https://krebsonsecurity.com/2016/10/iot-devices-as-proxies-for-cybercrime/)
* [Port knocking](https://wiki.archlinux.org/title/Port_knocking)
* [OWASP Internet of Things (IoT) Project](https://wiki.owasp.org/index.php/OWASP_Internet_of_Things_Project)
* [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
