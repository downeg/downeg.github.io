---
layout: default
title:  "Case Study: SolarWinds Hack of 2020."
date:   2023-11-10 09:00:00 +0000
categories: solarwinds malware university assignment
---

# Case Study: SolarWinds Hack of 2020.

---
University assignment Autumn 2023

---

> #### Executive Summary.

{: style="text-align: justify" }
The SolarWinds Attack 2020, known as SUNBURST, was a supply chain cyber-attack where a backdoor was inserted into the SolarWinds Orion platform to allow the subsequent install of remote access tools. Supply chain attacks "allow the adversary to utilize implants or other vulnerabilities inserted prior to installation in order to infiltrate data, or manipulate information technology". In the SolarWinds attack threat actors gained access to the SolarWinds internal network and a malicious tool was deployed into the build environment to inject a backdoor into the SolarWinds Orion Platform. With the backdoor being injected before the build cycle the compiled binary (including the backdoor) was digitally signed by SolarWinds ensuring that it was trusted by customer's using the infected build to perform updates.

{: style="text-align: justify" }
News of the attack reached the public on 13th December 2020 when cybersecurity FireEye released information on the malware. FireEye, themselves a customer of SolarWinds, detected the malware while investigating a breach on their own network where proprietary software had been exfiltrated by the threat actors. Over 18,000 organisations had been affected globally including the U.S. Department of Homeland Security.

> #### Introduction.

{: style="text-align: justify" }
On 8th December 2020 cybersecurity firm FireEye (now part of STG Trellix) revealed that its network had been compromised and that proprietary red-team assessment tools which the company developed had been stolen. On 13th December 2020 FireEye announced that their investigation had "discovered a supply chain attack trojanizing SolarWinds Orion business software updates in order to distribute malware". They named this malware SUNBURST.

{: style="text-align: justify" }
The SolarWinds Orion Platform is a suite of enterprise network management software products that include network, server and application performance and resource monitoring. Orion modules provide statistics on a wide range of vendor products. To allow the Orion modules to monitor this wide range of third-party systems and appliances it is common for the software to be configured with elevated privileges that may not be required by typical software installs. This made the SolarWinds software a valuable target for adversarial attacks.

{: style="text-align: justify" }
The attack on SolarWinds was twofold. Firstly, the threat actors gained access to the SolarWinds network. This allowed them to infiltrate the software development environment and install malware (dubbed SUNSPOT) into the build cycle that would inject a backdoor into a Dynamic-Link library (DLL) used by the Orion Platform. This backdoor (dubbed SUNBURST) was injected into the source code before the build process, ensuring that the final package (including the backdoor) would be digitally signed by the SolarWinds Certificate Authority. The result of this is that the update bundle containing the infected DLL would be trusted by customers and that the DLL would run on the Windows operating system with elevated privileges as the OS would trust the digitally signed code.

{: style="text-align: justify" }
The second part of the attack occurs after the infected Orion upgrade package was published. Any Orion servers that were upgraded using the infected upgrade package were susceptible to the malware's actions. After a short period of dormancy, the infected DLL would reach out to Command and Control (C2) servers that were under the control of the threat actors to exfiltrate some reconnaissance data about the install’s environment and network,  and then download another piece of malware given the name TEARDROP.

> #### How did it work?

{: style="text-align: justify" }
While it is not known (or made public) how the threat actor gained access to the SolarWinds build environment, their actions once on the build server have been publicised. Even in this first step of the supply chain attack the threat actors prioritized operational security to avoid revealing their presence.

{: style="text-align: justify" }
SUNSPOT, as the injector malware was known, was identified on disk with the seemingly benign filename of taskhostsvc.exe. When executed it would make use of a mutex to ensure it was the only instance of the malware running on the system. SUNSPOT would monitor the server for running MsBuild.exe processes, which is part of Microsoft Visual Studio development tools. If MsBuild.exe is detected then SUNSPOT would check to see if the Orion software is being compiled, and if so, would hijack the build process to inject the backdoor code SUNBURST. Since the SUNBURST code was injected as source code before the actual compilation this guaranteed that the final package containing the backdoor was digitally signed as authentic software from SolarWinds.

{: style="text-align: justify" }
After installation on a target network SUNBURST will perform several detection evasion checks, including checking the names of running processes, file write timestamps and Active Directory (AD) domains before reaching out to the C2 server for instructions.

{: style="text-align: justify" }
The process names that are checked were stored within the malware in encrypted format to prevent detection by static analysis tools. FireEye brute forced all the encrypted service names which the malware checks. In this list, available at https://github.com/mandiant/sunburst_countermeasures/blob/main/fnv1a_xor_hashes.txt , we can see services such as dnspy, radare2 (both well-known tools for malware dynamic analysis) and vboxservice (tools used by Oracle Virtual Box). This is evidence that the malware was designed to check if it was running in a virtual environment and to evade forensic tools. The malware had the ability to disable antivirus services on next boot by configuring the Windows registry.

{: style="text-align: justify" }
The malware also checks the timestamp of its install and would only continue execution if the time since the install is greater than 12-14 days. This is an effort to remain stealthy and not raise alarm bells if the malware’s behaviour is detected immediately after the Orion upgrade. Lastly, the malware will confirm it has Internet access by ensuring it can resolve the DNS name ```api[.]solarwinds[.]com```.

{: style="text-align: justify" }
If all these checks pass and the malware continues execution it will then use a Domain Generation Algorithm (DGA) to create obfuscated subdomains of the threat actor controlled domain ```avsvmcloud[.]com```. Encoded into these domain names is information about the network in which the infected host resides. These partially randomly generated domain names are then sent to the C2 server acting as an authoritative DNS server to be resolved. The threat actor can gain information about the infected host network through the encoded data in the domain name. The C2 server will then respond with a specially crafted DNS response which contains the instruction for the malware.

{: style="text-align: justify" }
If the C2 server responds with a DNS A record, the resolved address is checked against a hard-coded list of IP address blocks. SUNBURST will then either terminate, sleep or perform further actions based on what IP address was received in the DNS A record. Microsoft used this functionality as a kill-switch once the malware was detected by working with GoDaddy to set up DNS servers that would respond to DNS requests for any subdomain of ```avsvmcloud[.]com``` with IP addresses within the hard-coded blocks that instructed the malware to terminate so that it never executed again.

{: style="text-align: justify" }
The C2 server may also respond with a DNS CNAME response. If a DNS CNAME response is received the malware will use this returned IP for HTTP(S) communication. It is within this HTTP(S) communication that second stage malware is downloaded and installed in the form of a VBScript and a customized Cobalt Strike DLL dubbed TEARDROP. Cobalt Strike is a commercial threat emulation and adversary simulation software which is designed to be used by red-teams and penetration testers. It is so successful in its task that illegal copies are commonly used by threat actors to gain lateral movement through victim networks after initial penetration.

{: style="text-align: justify" }
The patience and determination of the threat actor was seen again in the deployment of the second stage malware as each instance of TEARDROP was customised to the end target's environment, and path and filenames for the second stage malwares were never duplicated to prevent an indicators of compromise list from being shared among targets if the malware was to be discovered.

{: style="text-align: justify" }
The loading of TEARDROP into memory was separated from the SUNBURST malware and was used to perform further infections and lateral movement through the network. SUNBURST was kept hidden so that it could be used for re-infection if TEARDROP or any other downloaded malwares were discovered.

> #### How as it detected?

{: style="text-align: justify" }
Effects of the attack were detected by cybersecurity company FireEye who disclosed on 8th December 2020 that their network had been breached and that proprietary tools had been stolen. It was not immediately known how the threat actors had compromised the FireEye network, but it was determined that the attack was carried out by a "highly sophisticated cyber threat actor, one whose discipline, operational security, and techniques lead us to believe it was a state-sponsored attack"

{: style="text-align: justify" }
Through an investigation with Microsoft the root cause of the FireEye breach was discovered to be the infected DLL which was part of the signed SolarWinds Orion Platform build.

> #### Why is the attack classified as it is?

{: style="text-align: justify" }
This attack is classified as a supply chain attack as the vendor of the software (SolarWinds) was not the end target of the threat actors’ campaign. It was customers of SolarWinds whose networks have the SolarWinds Orion Platform installed that were the final targets for the threat actors. The malware was injected into an upstream vendor's product (the SolarWinds Orion Platform) so that it could be used to compromise multiple downstream customer networks.

{: style="text-align: justify" }
The malware itself can be classified as a trojan backdoor remote access tool. It is a trojan because it is hidden inside a piece of software that the customer installs willingly in their environment while unaware of the backdoor hidden inside the digitally signed upgrade package. The NIST Glossary defines a trojan as "A computer program that appears to have a useful function, but also has a hidden and potentially malicious function that evades security mechanisms, sometimes by exploiting legitimate authorizations of a system entity that invokes the program." This definition describes the SUNBURST malware perfectly.

{: style="text-align: justify" }
It can be classed as a backdoor as it allows access directly into the target's environment without having to break through any further firewalls, authenticated systems or intrusion prevention systems. NIST Special Publication 800-83 defines a backdoor as "A malicious program that listens for commands on a certain Transmission Control Protocol (TCP) or User Datagram Protocol (UDP) port" SUNBURST used DNS and HTTP(S) traffic to communicate with its C2 servers to perform actions on the infected hosts.

{: style="text-align: justify" }
The malware can be classified as a remote access tool (RAT) as it can receive commands from the C2 server and perform actions such as creating and deleting files, modifying registry settings and exfiltrating certain network related information encoded within DNS lookups.

> #### Have there been any variants of the attack and are they different and/or more dangerous?

{: style="text-align: justify" }
The SolarWinds hack is widely regarded as one of the most sophisticated cyber-attacks in history. SolarWinds itself was a valuable target as it is a provider of software to a large number of companies, including government agencies, around the world. Other software companies with such a wide portfolio of customers and with similar processes for software development environments may find themselves the focus of an attack where the end-target is the downstream customer. These supply chain attacks are meticulously planned and are generally executed by well-funded threat actors, such as the nation sponsored advanced persistent threat (APT) groups. It is highly likely that there are a number of these supply chain attacks in progress at the moment. With the patience and skill of the adversary it is practically impossible to detect these implanted vulnerabilities until the threat actor does something to reveal themselves. In the case of the SolarWinds supply chain attack it was the exfiltration of tools from a cybersecurity company which raised the alarm.

> #### How could Firewalls have been implemented or better utilized to deter the attack?

{: style="text-align: justify" }
The SUNBURST backdoor used DNS (UDP port 53) and HTTP(S) (TCP ports 80 and 443) to communicate with the C2 servers. The SolarWinds Orion platform does not require Internet access to function. Firewalls could have been configured to deny any Internet access from the Orion server to the Internet. Without the ability to contact the C2 servers the backdoor would not have been able to download the second stage malwares. In a letter to US senator Ron Wyden dated 3rd June 2021, when asked if "firewalls in front of the servers running SolarWinds Orion" configured to block outgoing connections to the Internet could have prevented the attack, acting director of the Cybersecurity and Infrastructure Security Agency (CISA) Brandon Wales explicitly states "CISA agrees that a firewall blocking all outgoing connections to the internet would have neutralized the malware."

> #### What Defence in Depth techniques were in use? Could the security architecture have been improved to minimize or stop the attack?

{: style="text-align: justify" }
Defence in Depth is a multi-layered security strategy. Defence in Depth techniques that would have helped contain the malware include application whitelisting and Endpoint Detection and Response software installed on the Orion servers.

{: style="text-align: justify" }
Microsoft AppLocker can control which applications (including which executable files, scripts and Dynamic-Link Libraries) can run on a system. While the infected SolarWinds DLL may have been whitelisted and allowed to run, the customised Cobalt Strike DLLs (and VBScript used to load it) that were downloaded as the second stage malware would not match any Allow Rules in AppLocker and may not have been allowed to run. This would help to mitigate further infection and lateral movement within the victim network. An advanced technique used by the threat actor was to use the Windows rundll32.exe command to load the Cobalt Strike DLL into memory in an attempt to evade detection, however this still required the execution of the downloaded VBScript.

{: style="text-align: justify" }
Endpoint Detection and Response (EDR) software is a threat monitoring application that is installed on "endpoint" computers. These endpoints can be servers or user PCs. Endpoint detection continually monitors the system looking for any suspicious behaviour that may be an indication of malicious activity. While EDR may not have prevented the installation of the digitally signed backdoor, there are claims that the reconnaissance activities of the malware such as LDAP lookups for domain enumeration could have been detected and alerted on by EDR monitoring.

> #### What recommendations would you make to ensure a more secure network which would limit the effects of this attack in the future? What lessons can be learnt?

{: style="text-align: justify" }
Blocking all HTTP(S) traffic to the Internet from sensitive internal servers such as the SolarWinds Orion server could have prevented the spread of second stage malware on infected Orion servers. Threat actors often used unencrypted HTTP traffic to communicate with their C2 servers as it is difficult for a threat actor to get a TLS certificate signed by a legitimate Certificate Authority. Any unencrypted traffic going out of a corporate network from protected servers should not be trusted and should be blocked. The use of TSL and certificates is on the rise with malware authors. Malware can be hosted on legitimate HTTPS content delivery sites such as Discord or in the Google Cloud. If Internet access is an absolute requirement on the server being protected, then the use of Next Generation Firewalls using deep packet inspection firewalls with SSL inspection should be mandatory. If a threat actor is using a compromised legitimate certificate to send traffic over HTTPS then the traffic would be blocked as soon as that certificate is added to Certificate Revocation Lists by Certificate Authorities.

{: style="text-align: justify" }
Since one of the checks done by the malware was to only execute if the DNS name api.solarwinds.com resolved, preventing the Orion server the ability to contact external name servers, and the use of split-horizon DNS servers, may have stopped the malware in its tracks. If the malware could not make that initial name resolution of subdomains of avsvmcloud[.]com then it would not have received instructions from the C2 server to install the second stage malware.

> #### Conclusion.

{: style="text-align: justify" }
The severity and complexity of the SolarWinds hack and the patience and stealth of the threat actor has taught us that nation state cyber-warfare is highly motivated and highly funded with expert knowledge being used for nefarious purposes. Effectively combatting similar attacks in the future will require an industry-wide approach as well as public-private partnerships that leverage the skills, insight, knowledge, and resources of all constituents.

> #### References.

* [NIST COMPUTER SECURITY RESOURCE CENTER Online Glossary](https://csrc.nist.gov/glossary/term/supply_chain_attack)
* [Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor](https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwindssupply-chain-compromises-with-sunburst-backdoor)
* [Why the SolarWinds Orion Platform?](https://www.solarwinds.com/orion-platform)
* [SUNSPOT: An Implant in the Build Process](https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/)
* [SUNBURST Additional Technical Details](https://www.mandiant.com/resources/blog/sunburst-additional-technical-details)
* [mandiant/sunburst_countermeasures](https://github.com/mandiant/sunburst_countermeasures/blob/main/fnv1a_xor_hashes.txt)
* [FireEye, Microsoft create kill switch for SolarWinds backdoor](https://www.bleepingcomputer.com/news/security/fireeyemicrosoft-create-kill-switch-for-solarwinds-backdoor/)
* [Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop](https://www.microsoft.com/enus/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activationfrom-sunburst-to-teardrop-and-raindrop/)
* [Software for Adversary Simulations and Red Team Operations](https://www.cobaltstrike.com/)
* [UNITED STATES SECURITIES AND EXCHANGE COMMISSION](https://www.sec.gov/Archives/edgar/data/1370880/000137088020000037/feye20201208.htm)
* [NIST COMPUTER SECURITY RESOURCE CENTER Online Glossary](https://csrc.nist.gov/glossary/term/trojan_horse)
* [Guide to Malware Incident Prevention and Handling for Desktops and Laptops](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-83r1.pdf)
* [SolarWinds Platform Product Features Affected by Internet Access](https://support.solarwinds.com/SuccessCenter/s/article/OrionPlatform-Product-Features-Affected-by-Internet-Access?language=en_US)
* [U.S. Department of Homeland Security CISA](https://s3.documentcloud.org/documents/20969575/wyden_response_signed.pdf)
* [Microsoft AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/applicationcontrol/windows-defender-application-control/applocker/applocker-overview)
* [How SES Complete Can Protect Against Sophisticated Attacks Such As Sunburst](https://symantec-enterprise-blogs.security.com/expert-perspectives/how-ses-complete-can-protect-against-sophisticated-attacks-such-sunburst)
* [Nearly half of malware now use TLS to conceal communications](https://news.sophos.com/en-us/2021/04/21/nearly-half-ofmalware-now-use-tls-to-conceal-communications/)

