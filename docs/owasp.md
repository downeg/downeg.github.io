---
layout: default
title:  "OWASP Top Ten Case Study"
date:   2024-03-17 09:00:00 +0000
categories: owasp web vulnerability university assignment
---

# OWASP Top Ten Case Study (University assignment)

## Executive Summary:
Nick Espinosa, a well-respected cybersecurity expert, created his five cyber security laws to promote an awareness of the risks in cybersecurity which will always be present irrespective of the technology. Nick's law number one states: "If there is a vulnerability, it will be exploited - No-Exceptions". Web sites are the face of the Internet and are one of the most easily accessible attack vectors for threat actors. Sites can be scanned and gently probed by patient attackers until a vulnerability is found. Once found, the vulnerability will then be exploited so that the attacker can gain access to information they are not authorised to have, or to gain a foothold on the webserver itself and perform lateral movement through the network, or to gain persistence by uploading a reverse-shell. It might seem surprising, but most of these vulnerabilities in websites can easily be mitigated through some diligence and a knowledge of security during the software development lifecycle. The Open Worldwide Application Security Project (OWASP) is a foundation dedicated to making organisations and web developers aware of the most critical security risks to their applications. The OWASP achieves this through a community driven effort to scan websites and map vulnerabilities found in the MITRE Common Weakness Enumeration list. The community then comes to a broad consensus about the most critical security risks to web applications and publishes these as the OWASP Top Ten. By being aware of the OWASP Top Ten and following the advice provided by the foundation about how to prevent these vulnerabilities an organisation can improve the security of their websites and network applications from the ground up. Attention to security from the design stage of software development and application deployment will prevent data breaches by reducing the attack surface available to threat actors.

## Introduction:
The Open Worldwide Application Security Project (OWASP) is a non-profit organisation who provideinformation and free tools in the area of web security, application security and vulnerability assessment. Founded in 2001, the OWASP published their first "Top Ten" list of security vulnerabilities for web sites in 2003. Since then, the "Top Ten" list has been updated several times to reflect the ten most common attack vectors of the time. The most recent update was in 2021. The OWASP also provides free tools such as the Zed Attack Proxy (OWASP ZAP), which is a fully featured and open-source alternative to PortSwigger's BURP Suite. This tool can be used to scan web sites for vulnerabilities and to act as a proxy server to manipulate HTTP(S) traffic when penetration testing web applications. On August 1st, 2023, the developers of ZAP announced that the ZAP project would move to the newly created Software Security Project (SSP) foundation. As of writing, ZAP continues to be the top listed Dynamic Application Security Testing (DAST) tool on the OWASP free Open-Source application security tools list. 

Other free resources provided by the OWASP include the OWASP Juice Shop and the WebGoat broken web applications which are available as Docker containers. These containers contain several intentionally vulnerably web applications which can be used for training, observing web attacks and for testing new tools. In this case study the following vulnerabilities listed in the OWASP Top Ten 2021 will be examined: ```A01:2021-Broken Access Control```, ```A03:2021 – Injection``` and ```A10:2021 – Server-Side Request Forgery (SSRF)```.

## A01:2021-Broken Access Control
### What is the attack?

Broken Access Control is a type of application security vulnerability that occurs when a web application allows users to perform actions or access data they shouldn't be able to access. In most cases of broken access control, this is due to insufficient enforcement of permissions or inadequate authentication and authorization mechanisms [10]. Attackers can exploit this vulnerability to gain unauthorized access to functionalities, data, or resources.

### How does the attack work?
An example of how Broken Access Control works is through Insecure Direct Object Reference (IDOR). IDOR arises when an application uses user-supplied input to access objects directly. Consider a web application that allows users to view their personal profile information after logging in. Each user has a unique identifier associated with their account, such as a user ID. This user ID is included in the URL of a HTTP(S) GET request (e.g., https://example.com/profile?user_id=123) and is directly used to query a back-end database. Without sufficient session management, authentication and authorisation mechanisms in place an attacker could exploit this by simply changing the value of the user_id parameter in the URL to gain unauthorised access to another user's profile information.

### Explain why the attack is classified as it is and why it differs from other types of the same attack?
IDOR is classified as broken access control because it focuses specifically on flaws in access control mechanisms rather than exploiting vulnerabilities in cryptography, code execution or data manipulation.

### What vulnerability does the attack typically exploit?
Insecure Direct Object Reference attacks exploit vulnerabilities in access control mechanisms, including insufficient or ineffective authentication, authorization and session management.

### What is an example that occurred in practice?
One recent example of where an IDOR vulnerability had a very large impact was the First American Financial Corp. breach in 2019. First American's website had an IDOR vulnerability, and this exposed more than 885 million files including customer's personally identifiable information. Even though no customer data was exploited, First American were fined nearly $500,000 by the Securities and Exchange Commission (SEC) for violating cybersecurity laws by failing to implement and maintain effective governance and classification, access controls and identity management, and risk assessment policies and procedures.

### What APT would use such an attack and what TTPs are associated?
Within the MITRE ATT&CK framework, Insecure Direct Object References (IDOR) are categorized under the tactics of Initial Access (TA0001) and Discovery (TA0007). An example of IDOR being used as a technique is Account Discovery (T1087). In an Initial Access tactic (TA0001), IDOR can be used by attackers to gain their initial foothold into a target system or network. By exploiting flaws in access controls attackers can directly access sensitive objects or resources without proper authentication or authorization. This unauthorized access can provide them with a foothold to further exploit vulnerabilities or escalate privileges within the target environment.

As a Discovery tactic (TA007), IDOR can be leveraged by attackers to gather information about the target environment. By exploiting IDOR, attackers can discover and enumerate sensitive objects or resources that are not intended to be publicly accessible. This reconnaissance phase allows attackers to identify potential targets for further exploitation and gain a better understanding of the target environment's architecture and data flow.

IDOR can also facilitate Account Discovery (T1087) by allowing attackers to obtain sensitive information or credentials belonging to other users. In scanning a web application vulnerable to IDOR, an attacker may be able to access user profiles or account information of other users. This could expose usernames, email addresses, or the ability to change passwords. These credentials can then be leveraged by attackers for unauthorized access to additional systems or services. 

An Advanced Persistent Threat (APT) group such as APT28 (Fancy Bear) could utilize Insecure Direct Object Reference and Broken Access Control to perform reconnaissance on targets, or to escalate privileges within compromised systems.

### Attack Detection: How can log files be used to detect the selected vulnerability?
#### What log setup should be in place to enable detection?
Log files can be instrumental in detecting Broken Access Control vulnerabilities by monitoring and analysing events related to authentication, authorization, and access control. In the case of IDOR these attacks can be identified on both Linux and Windows systems by monitoring and alerting on the system's webserver logs. On Linux the webserver logs could be either Apache logs or NGINX logs depending on the type of webserver installed. In a Windows environment the logs to monitor would be the Internet Information Services (IIS) logs.

All these logs can be forwarded to a central Security Information and Event Monitoring (SIEM) solution such as Splunk. A Universal Forwarder can be configured to forward individual webserver logs. The SIEM can be configured to format the log information into easy to view tables and charts. There are specialised plugins available for Splunk, such as the Apache add-on, the NGINX add-on for Linux, or the Microsoft IIS add-on, which allows a Splunk administrator to collect website activity data in the log file format specific to each OS installation, and allow the data to be easily searched in Splunk.

Alerts can be set up in the SIEM to automatically inform if certain patterns are detected in the logs. In the case of IDOR these patterns might look like HTTP(S) requests that involve sequential or predictable changes to resource identifiers (e g., incrementing numeric IDs in URLs) if an attacker is scanning a web application, repeated requests for URLs that are typically restricted or not intended for public access, or continuous failed attempts to access restricted resources.

#### What are the keywords to search for?
Webserver logs may not explicitly label entries as "IDOR", but monitoring and analysing webserver logs for patterns can help to detect and investigate potential instances of IDOR exploitation. On Linux the default location for the Apache webserver logs is ```/var/log/apache2/```. An example of Apache logs showing an attempted IDOR scan is shown in the following screenshot.

IMAGE MISSING
Example of a possible IDOR as seen in the raw Apache webserver access.log

In Microsoft IIS logs the ```cs-uri-query``` field contains the query part of the requested URL path. These fields can be viewed in the Windows Event Viewer. These webserver logs can be monitored by a SIEM for requests targeting sensitive or restricted data, or multiple requests in quick succession which manipulate the parameter(s) in the URL. Searching for repeated HTTP(S) status codes of ```403 Forbidden``` or ```404 Not Found``` may indicate attempts to access resources without proper authorisation.

#### What logs and/or Event IDs should you search for?
On Windows IIS servers the default location for the logs is ```C:\inetpub\logs\LogFiles\W3SVC1```. The screenshot belowshows an example environment where a Splunk Universal Forwarder was installed on a Windows Server 2022 Internet Information Services 10 webserver to forward the IIS log to a Splunk server. A sample IDOR attack was simulated by sending sequential requests to ```http://webserver/profile?user_id=#``` where ```#``` was a number representing the ```user_id```. In Splunk this attack could be viewed by selecting the forwarded IIS webserver log as the source, specifying the URL path we are interested in and searching for the ```iis_status="404.0"``` (file or directory not found) HTTP responses. Note the user agent of ```curl 8.5.0``` and the repeated requests with a different user_id. This suspicious behaviour could indicate a threat actor probing a URL for an Insecure Direct Object Reference vulnerability.

IMAGE MISSING
Example of a possible IDOR as seen through Splunk monitoring Windows IIS logs.

The Linux, webserver logs can be forwarded to a Splunk server and monitored in a similar manner. They can also be searched in the raw logs on the webserver itself. Tools such as grep and awk can be used to pull out the interesting information from the logs. We can search for the URI we are investigating and focus the search results on ```404 Not Found``` type responses using the command: ```grep "profile" /var/log/apache2/access.log* | grep " 404 "```.

IMAGE MISSING
Using grep to review the raw logs on a Linux Apache webserver.

#### What is the audit trail that can be used to detect the attack?
The audit trail for investigating broken access control will start with the webserver logs. If information about specific users is compromised, for example a list of valid usernames was enumerated via an IDOR attack, then OS Security logs could be checked for any successful or unsuccessful login attempts by those same user accounts. This would provide information on how much access to other systems a threat actor has. A password spraying attack against a system around the same time the valid usernames were enumerated would indicate an attacker has network access to that system. Firewall logs could be checked to make sure that the correct access controls are in place to protect internal servers.

#### How are the logs used to investigate and act against the attack?
The IP address of the attacker will be recorded in the Windows IIS log and the Linux Apache/NGINX logs. When an alert is triggered for an attempted IDOR attack, the IP address responsible for the requests can be automatically blocked at the firewall to mitigate further probing attempts. Geolocation services may provide insight into the origin of the attack, although the threat actor might obfuscate their true location using VPN or TOR services. The chronological sequence of the attack is also documented in the logs, enabling investigators to establish a timeline of events. Additionally, logs should be examined for any other anomalies occurring concurrently with the detected IDOR attack. 

The targeted URI is also captured in the logs. This information can be forwarded to developers for code scrutiny to identify and address any potential vulnerabilities that may lead to unauthorized access. User accounts subjected to probing can undergo verification to ensure no unauthorized access occurred. Any accounts suspected of compromise can be promptly disabled or suspended pending further investigation into potential malicious activity.

#### How can frameworks help this process?
The NIST Cybersecurity Framework serves as a valuable resource for developing a robust and comprehensive log collection and monitoring strategy. Within the Asset Management category of the Identify function, organizations can systematically enumerate all webservers, databases, and application servers, ensuring that their logs are enabled and integrated as essential data sources within a centralized SIEM system. Diligent care in encompassing all critical assets of the organization within the logging strategy guarantees the availability of log data for ongoing monitoring and storage, adhering to the timeframes mandated by governing bodies for future investigative purposes.

#### How are the logs used to learn how to prevent repeat attacks in the future?
A penetration test can be performed on any websites or applications accessible via the Internet, or on web applications housing sensitive data. The results of such tests may uncover instances where confidential information, including user credentials, personal data, or proprietary information, is susceptible to unauthorized access or inadvertent exposure. Organizations can then address these data exposure risks by implementing robust access control measures to safeguard sensitive data from exploitation through Insecure Direct Object Reference (IDOR) vulnerabilities. The log data generated during the penetration test can be analysed to establish rules and alerts within a SIEM system. This proactive approach to testing, log generation and log analysis enables organizations to swiftly detect and respond to similar IDOR attacks in the future.

#### Any recommendations of using logs against the chosen attack?
Some recommendations for using logs to track IDOR attacks would be to develop a comprehensive logging strategy that covers all relevant systems, including webservers, databases and authentication mechanisms. Have a centralised location where logs from different systems can be sent, for example a Security Information and Event Management (SIEM) system. Ensure that all the systems forwarding logs to the SIEM are configured to the same time using Network Time Protocol. If the times do not synchronise for logs from different systems, then it is far more difficult to correlate information from different logs during a security event. Conduct regular reviews and audits of webserver log data, and user accounts that have permissions to use the webserver. Audit the user accounts to ensure they do not have too much access and access to resources is granted using the principle of least privilege.

## A03:2021-Injection
### What is the attack?
Injection attacks can occur when an attacker has control over an input field which is used for data processing, and the input is not validated, filtered or sanitized by the application. Injection attacks can occur in many forms, such as SQL Injection where SQL queries can be modified in such a manner that the injected command is run by the backend DBMS, or as Remote Command Injections like the ShellShock vulnerability where BASH commands could be injected into a user-controlled request header in HTTP(S) requests to a web server. Cross Site Scripting (XSS) was a category of its own in the 2017 OWASP Top Ten but has been rolled into the A03:2021-Injection category in the 2021 list. This section for Injection vulnerabilities will concentrate on XSS.

### How does the attack work?
There are two main types of XSS attack, Reflected XXS and Stored XXS. A third type of XSS called DOM XSS is less common. Reflected XSS is a type of injection attack where malicious scripts are injected as parameters into the URL of dynamically generated web pages. These scripts are then reflected back to the user by the web application and execute in the context of the user's browser, allowing attackers to steal session cookies, sensitive data, or even take control of user sessions.

In stored XSS attacks, the malicious script is permanently stored on the server, typically within the application's database or filesystem. A common method for an attacker to upload the malicious scripts is through comment forms, message boards, or anywhere a file can be uploaded. Once injected, the malicious script remains on the server and is executed on any client’s browser when they visit the infected site.

### Explain why the attack is classified as it is and why it differs from other types of the same attack?
XSS attacks fall under the category of injection attacks due to their method of injecting malicious scripts or payloads into the URL or user-controlled input fields of webpages. The term "injection" refers to the unauthorized insertion of data or code into an application with the intent of altering its behaviour or compromising its security.

### What vulnerability does the attack typically exploit?
XSS attacks exploit the absence of adequate input validation and sanitization mechanisms in web applications. Input validation refers to the process of ensuring that user-supplied data meets certain criteria, such as format, length, or range, before it is accepted by the application. Sanitization involves removing or encoding potentially malicious characters or scripts from user input to prevent them from being interpreted and executed by the application.

### What is an example that occurred in practice?
The 2018 attack on British Airways was a significant cybersecurity incident that compromised the personal and financial information of approximately 380,000 customers who made bookings or changes to their flights on the airline's website and mobile app between August and September 2018. This Stored XSS attack involved the injection of malicious JavaScript code onto the payment page of British Airways' website. The attackers, believed to be associated with the Magecart threat actor group, exploited a vulnerability in the airline's web application to inject a skimming script, which was designed to capture payment card details entered by customers during the checkout process.

### What APT would use such an attack and what TTPs are associated?
The MITRE ATT&CK framework outlines tactics associated with Cross-Site Scripting (XSS), including Execution (TA0002) and Persistence (TA0003). One technique commonly employed to inject XSS code is Exploiting Public-Facing Applications (T1190). The primary objective behind injecting XSS code into a URL or a file hosted on a web server is to execute that code within a client's browser, aligning with the MITRE Execution tactic. Once executed, the malicious code can perform various nefarious actions, such as data theft, privilege escalation, or initiating a reverse shell on the target's machine.

Stored XSS attacks entail injecting code directly into files stored within a web server's filesystem. These compromised files are subsequently served to clients browsing the site, exemplifying the Persistence tactic. By embedding malicious code into files, adversaries ensure a broad reach for execution.

Moreover, these files may also be included in backups of web server directories, enhancing the persistence of the attack beyond routine disaster recovery procedures.

Both reflected and stored XSS attacks capitalize on vulnerabilities present in public-facing applications and websites, where end users have the ability to manipulate input data that is subsequently processed or stored by the web server. These vulnerabilities often stem from inadequate verification or sanitization of user input, or potentially from misconfigurations within the web server that permit unauthorized modification of files in the document root. This exploitation aligns with the MITRE technique of exploiting public-facing applications.

APT32, a threat group based in Vietnam, is recognized for their utilization of JavaScript payloads injected into victims' systems as part of their extensive range of techniques.

### Attack Detection: How can log files be used to detect the selected vulnerability?
#### What log setup should be in place to enable detection?
Linux-based Apache webservers commonly utilize access logs (e.g., ```/var/log/apache2/varaccess.log```) and error logs (e.g., ```/var/log/apache2/error.log```) to record HTTP requests and server errors. These logs serve as valuable resources for detecting potential Cross-Site Scripting (XSS) attacks by flagging suspicious patterns such as unexpected query strings, abnormal user-agent strings, or encoded payloads indicative of XSS exploitation.

Linux web server logs can be accessed directly in their raw format within the server's filesystem. Alternatively, they can be forwarded to a Security Information and Event Management (SIEM) system for streamlined searching and automated alerting based on predefined rules. By centralizing these logs, organizations gain the ability to efficiently monitor and respond to XSS threats across their Linux web server infrastructure.

On Windows IIS servers, the default web server log files are located in ```C:\inetpub\logs\LogFiles\W3SVC1```. These logs, formatted as text files, can be viewed using standard text editors such as Notepad. However, for enhanced visibility and analysis capabilities, it is advantageous to forward these logs to a centralized SIEM platform. This enables comprehensive log analysis, facilitates the creation of reports, and simplifies the detection of XSS anomalies across Windows-based web servers.

By aggregating log files from multiple webservers, database servers, and application servers into a single centralized log management system such as Splunk, organizations can exponentially improve their ability to detect and respond to XSS attacks. The SIEM system can be intelligently configured to automatically monitor these logs, promptly identify any deviations from normal behaviour, and issue alerts based on user-defined rules. This proactive approach to log management and monitoring significantly enhances an organization's security posture against XSS threats. 

#### What are the keywords to search for?
XSS is a broad vulnerability category and has an immensely large number of attack vectors. Not all of the attack vectors can be caught in logs, however there are some keywords and phrases that might be written to the webserver logs which would indicate an attempted XSS attack. In reflected XSS attacks the injected script is part of the URL. Both Windows IIS and Linux webserver logs keep track of requested URLs. HTML tags such as ```<script>```, ```<img>``` and ```<iframe>``` would not typically be expected as part of a URL. We can search the webserver log files for instances where requested URL contain these keywords.

IMAGE MISSING
An example searching Windows IIS log files for any URL that includes the keyword script that may indicate a possible reflected XSS attempt.

#### What logs and/or Event IDs should you search for?
Stored XSS attacks inject the malicious code into to the files served by the webserver. In Windows Server we can enable a feature known as ```Audit object access``` in the Local Security Policy or by using Group Policy. We can then enable auditing of the wwwroot directory so that any modifications of logs are written to the Windows Security Event logs. By forwarding the Security Event Logs to our SIEM we can then search, report and alert on any time the monitored files are modified. The event code that is generated when a file is modified in a monitored directory is ```EventCode=4663```.

IMAGE MISSING
Enabling the logging of file auditing to the Windows Security Event log.

#### What is the audit trail that can be used to detect the attack?
When creating an audit trail to investigate XSS attacks, the webserver log files can be used to discover the IP address of the threat actor. Geolocation services can be utilised to check where the attack may be originating. In Reflected XSS attacks the injected code can sometimes be retrievable from the URL written to the webserver logs. Even if a basic encoding scheme such as Base64 is used to attempt to obfuscate the payload, this can be easily reversed to get the content of the injected code.

File system logs around the same time as the attack can be correlated to find any files within the webserver document directories have been modified with injected malicious code using the ```EventCode 4663```. Searching for any files within the IIS document root directory which had changes made to them during a suspected XSS attack.

#### How are the logs used to investigate and act against the attack?
During the investigation of an XSS attack, various sections in the web server logs offer valuable insights. In the case of a victim falling prey to a reflected XSS attack, examining the "referrer" request header can reveal the origin of the infected link clicked by the user. This information can be instrumental in tracking down the source of the infected URLs and subsequently removing them to prevent further victimization. 

Conversely, in the event of a successful stored XSS attack where malicious code is written to files on the web server, incorporating these filesystem modifications into audit logs provides a crucial time frame for cross-referencing with other web server logs. This aids in pinpointing the occurrence of the attack and enables security teams to conduct thorough investigations and remediation efforts effectively.

#### How can frameworks help this process?
The NIST Cybersecurity Framework's Detect function proves invaluable in mitigating the impact of an XSS attack. If malicious code manages to infiltrate a web server's file system undetected, it may persist for extended periods, as evidenced by the 2018 British Airways incident, which affected 380,000 customers over the course of a month. Establishing comprehensive logging and monitoring protocols capable of swiftly identifying ongoing XSS attacks and issuing immediate alerts during injection attempts can spare organizations the arduous task of manually sifting through voluminous logs post-incident. Proactive detection not only enhances response efficacy but also minimizes potential damages incurred.

#### How are the logs used to learn how to prevent repeat attacks in the future?
Proactive logging can be generated by fuzzing any URL or web page where user input is solicited, a process often integrated into targeted penetration tests of websites or web applications. Tools like ```Nikto``` facilitate vulnerability scans against these web assets. Once penetration tests and scans conclude, the ensuing webserver logs can be meticulously scrutinized to assess the data written to them. Should the logs prove insufficient, enabling additional debug logging becomes imperative. These logs serve as a blueprint for constructing a profile of potential XSS attack vectors against the site. Subsequently, SIEM systems can be finely tuned to deliver specific alerts and reports based on the observed log patterns indicative of XSS attacks.

#### Any recommendations of using logs against the chosen attack?
XSS attacks can be mitigated with some careful planning in the real-time collection of webserver logs into a SIEM, and alerting on any detected anholonomies in the monitored logs that match the profile of known XSS attacks. Once again, making sure that all systems being monitored have their clocks synchronised is important if an incident spanning many different systems is to be investigated. Enabling auditing on the files is recommended so that any unexpected changes to files can be alerted on (i.e., changes made to files within a webserver document root outside of any web-developer's work times).

## A10:2021-Server-Side Request Forgery
### What is the attack?
Server-Side Request Forgery (SSRF) is a web application vulnerability which enables threat actors to manipulate a webserver's outgoing requests, potentially resulting in unauthorized access to internal systems or sensitive data. Exploiting SSRF involves tricking the server into sending requests to unintended destinations, typically achieved by providing malicious input through URL parameters or API requests.

### How does the attack work?
SSRF works by exploiting web applications or services that make HTTP requests to external resources without proper validation or authorization checks. A threat actor can target an application that supports data imports from URLs or allows them to read data from URLs. The attacker will manipulate the URL being retrieved by the webserver, either by replacing them with new ones or by tampering with URL path traversal. Since the server may have different access rights to other internal servers, the attackers may be able to gain access to data and services that were not meant to be exposed – including HTTP-enabled databases and server configuration data.

### Explain why the attack is classified as it is and why it differs from other types of the same attack?
SSRF involves manipulating a server into making requests to unintended destinations. These requests are initiated from the server side rather than the client side. This makes it different from other types of attacks such as Insecure Direct Object References (IDOR) which typically originate from the client side, or reflected XXS attacks which originate from the client side and whose payload is executed in the clientside browser.

### What vulnerability does the attack typically exploit?
SSRF attacks take advantage of inadequate input validation and security measures surrounding userprovided URLs. When a webserver accepts and processes user-input without thorough validation, it becomes susceptible to SSRF attacks. This vulnerability enables attackers to trick the webserver into making requests to unintended destinations, potentially resulting in unauthorized access to internal systems, data theft, or service interruption.

### What is an example that occurred in practice?
In the 2019 Capital One breach, SSRF was exploited by the attacker to gain unauthorized access to sensitive data stored on Capital One's cloud infrastructure. The breach involved a misconfigured web application firewall (WAF) on a web application hosted on Amazon Web Services (AWS). The attacker was able to exploit SSRF to trick the WAF into using its service account into retrieving data from S3 buckets which the WAF account should not have had permissions to access. The attacker was able to exfiltrate large amounts of confidential information, including personal data of millions of Capital One customers and credit card application data.

### Attack Detection: How can log files be used to detect the selected vulnerability?
#### What log setup should be in place to enable detection?
#### Similar to the previous attacks, the main source of logs will be the webserver logs.
#### What are the keywords to search for?
#### What logs and/or Event IDs should you search for?
#### What is the audit trail that can be used to detect the attack?
#### How are the logs used to investigate and act against the attack?
#### How can frameworks help this process?
#### How are the logs used to learn how to prevent repeat attacks in the future?
### Any recommendations of using logs against the chosen attack? 

## What are some techniques (attacker tricks) which can be used to evade log analysis attack detection?
Threat actors may want to evade log analysis detection for several reasons, including achieving persistence and avoiding detection from incident response teams. By evading log analysis detection threat actors can prolong their access to compromised systems or networks without being discovered by security teams. This allows them time to continue their attack through lateral movement, exfiltrating sensitive data, or planting other forms of malware in the network. By avoiding the writing of known patterns to log files which may be monitored, threat actors can avoid triggering security alerts which would result in a security incident response. If their attack patterns became known through log file analysis, then it would be easier for defenders on the cyber security teams to fingerprint the pattern and alert on the same type of attack in the future. 

When access control mechanisms can be broken through an IDOR vulnerability the threat actor does not need to make any changes to the site, the information is already available through the vulnerability. The main goal for the attacker is to retrieve as much of the sensitive information as they can without alerting the owner of the website to the vulnerability. The best way to do this is to limit the frequency in which HTTP(S) requests are made. By being patient, the malicious requests blend in with legitimate user traffic to avoid raising suspicion. By sending requests infrequently and at random intervals, threat actors mimic the natural variability in user behaviour, making it challenging for security monitoring tools to identify anomalous patterns. It is hypothesised that this "low-and-slow" type of attack was used against First American in their 2019 data breach.

In the following example an alert was created in Splunk to trigger when a webpage hosted on a Windows IIS server was being probed to check for an IDOR vulnerability. The alert would trigger if more than 20 requests to the /profile page responded with a ```404 HTTP response``` (i.e., the attacker was attempting to access the page using many different user_id values that did not exist). This type of alert would easily be avoided if the threat actor limited their probing to less than 20 requests per minute. This type of evasion technique is platform agnostic, so would work the same if the logs being monitored were on a Linux based webserver.

IMAGE MISSING
Example alert in Splunk to trigger an event when there are more than 20 HTTP 404 responses to a webpage.

Obfuscating malicious code serves as a common tactic employed to circumvent log detection in XSS attacks. In reflected XSS scenarios the payload is inserted into the URL which is then sent to the webserver. Since this URL is logged by the webserver, identifying XXS keywords like ```script``` or ```img``` within the URL becomes feasible. We can pull these keywords from the webserver logs and use a SIEM to alert on their occurrence. For instance, in our previous example utilizing Splunk for XSS detection we highlighted instances of the "script" keyword within processed URLs from our webserver logs. Using obfuscation, attackers can easily evade such detection mechanisms by encoding their payloads using Base64. By doing so, not only do they create a more convincing URL for exploitation (e.g., phishing campaigns), but they may also bypass input sanitization filters and totally defeat our keyword-based webserver log monitoring and alerting systems.

## How can we detect these evasion techniques?
Detecting "low-and-slow" attacks, where threat actors deliberately conduct their malicious activities at a slow pace, presents a unique challenge in log analysis. Instead of relying solely on frequency or volume, analysis should prioritize identifying patterns of anomalies. This includes observing irregularities such as unusually long intervals between requests or inconsistent timing between consecutive requests originating from the same IP address. Additionally, paying attention to the User-Agent is crucial as it can provide valuable insights. Despite the lower volume of requests, a suspicious User-Agent could reveal the use of uncommon browsers or scanning tools, serving as a red flag for potential malicious activity.

If obfuscation is used to circumvent the detection of easily identifiable keywords in log files, the resulting strings typically exhibit high entropy, signifying a degree of randomness. To identify such obfuscated strings, a Splunk plugin called ```URL Toolbox``` can be leveraged to compute the Shannon Entropy score, which is a metric measuring the randomness within a string. Elevated Shannon Entropy scores within specific URL segments may indicate encoded strings and potentially signify attempts to obfuscate userprovided input. This plugin can be applied for Windows IIS logs, or to Linux Apache webserver logs as long as they are configured as data sources to Splunk.

## Recommendations and conclusion:
In conclusion, log analysis and event monitoring plays a pivotal role in detecting the vulnerabilities listed in the OWASP Top Ten. By diligently monitoring and analysing logs, security teams can uncover indicators of compromise, identify potential security threats, and mitigate risks before they escalate into full-blown incidents.

It is recommended that an organisation develop a comprehensive logging strategy that aligns with the NIST CSF framework. Key components such as webservers, database servers and applications can be identified and have their logs forwarded to a centralised SIEM. The centralised SIEM system can then protect the logs in case a threat actor tries to destroy evidence on a compromised host. Real time monitoring can be implemented in the SIEM to detect potential attacks and alerting can improve response time to potential security incidents.

Proactively threat hunting activities can be run to search for indicators of compromise and advanced threats within log data. The resulting logs of these activities, as well as penetration tests, can be used for continuous improvement of the logging strategies.

By making log analysis a fundamental component of their cybersecurity strategy organizations can improve their capacity to identify and address vulnerabilities, safeguard critical assets, and effectively defend against cyber threats.

## References:
* [5 Cyber Security Laws We All Need To Know] (https://www.think-cloud.co.uk/blog/5-cyber-security-laws-we-all-need-to-know/)
* [The Five Laws Of Cybersecurity] (https://www.forbes.com/sites/forbestechcouncil/2018/01/19/the-five-laws-of-cybersecurity/)
* [CWE VIEW: Weaknesses in OWASP Top Ten (2021)] (https://cwe.mitre.org/data/definitions/1344.html)
* [About the OWASP Foundation] (https://owasp.org/about/)
* [The OWASP Top Ten] (https://www.owasptopten.org/)
* [Top 10 Web Application Security Risks] (https://owasp.org/www-projecttop-ten/)
* [Free for Open Source Application Security Tools] (https://owasp.org/wwwcommunity/Free_for_Open_Source_Application_Security_Tools)
* [ZAP is Joining the Software Security Project] (https://www.zaproxy.org/blog/2023-08-01-zap-is-joining-the-software-security-project/)
* [Vulnerability Scanning Tools] (https://owasp.org/wwwcommunity/Vulnerability_Scanning_Tools)
* [A01:2021 – Broken Access Control] (https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [Insecure direct object references] (https://portswigger.net/websecurity/access-control/idor)
* [Insecure Direct Object Reference – Prevention and Detection of IDOR] (https://www.socinvestigation.com/insecure-direct-object-reference-prevention-anddetection-of-idor/)
* [Biggest Data Breaches in US History] (https://www.upguard.com/blog/biggest-data-breaches-us)
* [First American fined $1M by NYDFS over 2019 cybersecurity breach] (https://www.complianceweek.com/regulatory-enforcement/first-american-fined-1m-bynydfs-over-2019-cybersecurity-breach/33938.article)
* [Initial Access] (https://attack.mitre.org/tactics/TA0001/)
* [Discovery] (https://attack.mitre.org/tactics/TA0007/)
* [Account Discovery] (https://attack.mitre.org/techniques/T1087/)
* [APT28] (https://attack.mitre.org/groups/G0007/)
* [Splunk Add-on for Apache Web Server] (https://docs.splunk.com/Documentation/AddOns/released/ApacheWebServer/About)
* [Splunk Add-on for NGINX] (https://docs.splunk.com/Documentation/AddOns/released/NGINX/About)
* [Splunk Add-on for Microsoft IIS] (https://docs.splunk.com/Documentation/AddOns/released/MSIIS/About)
* [ID.AM-2 Software platforms and applications within the organization are inventoried] (https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/id-am/id-am-2/)
* [Welcome to the home of the Network Time Protocol (NTP) Project.] (http://www.ntp.org/)
* [What is the principle of least privilege?] (https://www.cloudflare.com/learning/access-management/principle-of-least-privilege/)
* [A03:2021 – Injection] (https://owasp.org/Top10/A03_2021-Injection/)
* [Apache mod_cgi - 'Shellshock' Remote Command Injection] (https://www.exploit-db.com/exploits/34900)
* [3 Types of Cross-Site Scripting (XSS) Attacks] (https://www.trendmicro.com/en_sg/devops/23/e/cross-site-scripting-xss-attacks.html)
* [Cross Site Scripting] (https://owasp.org/www-community/attacks/xss/)
* [Definition cross-site scripting (XSS)] (https://www.techtarget.com/searchsecurity/definition/cross-site-scripting)
* [Cross-Site Scripting] (https://www.synopsys.com/glossary/what-iscross-site-scripting.html)
* [CWE-20: Improper Input Validation] (https://cwe.mitre.org/data/definitions/20.html)
* [Cross Site Scripting Prevention Cheat Sheet] (https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
* [XSS Attack: 3 Real Life Attacks and Code Examples] (https://brightsec.com/blog/xss-attack/#real-life-examples)
* [British Airways data theft demonstrates need for cross-site scripting restrictions] (https://www.techrepublic.com/article/british-airways-data-theftdemonstrates-need-for-cross-site-scripting-restrictions/)
* [Execution] (https://attack.mitre.org/tactics/TA0002/)
* [Persistence] (https://attack.mitre.org/tactics/TA0003/)
* [Exploit Public-Facing Application] (https://attack.mitre.org/techniques/T1190/)
* [APT32] (https://attack.mitre.org/groups/G0050/)
* [Cross-Site Scripting (XSS) Attacks & How To Prevent Them] (https://www.splunk.com/en_us/blog/learn/cross-site-scripting-xss-attacks.html)
* [NIST CSF core functions: Detect] (https://www.infosecinstitute.com/resources/nist-csf/nist-csf-core-functions-detect/)
* [Web Server Scanning With Nikto – A Beginner's Guide] (https://www.freecodecamp.org/news/an-introduction-to-web-server-scanning-with-nikto/)
* [Server-side request forgery] (https://portswigger.net/websecurity/ssrf)
* [Server-Side Request Forgery] (https://www.imperva.com/learn/application-security/server-side-request-forgery-ssrf/)
* [USA v PAIGE A. THOMPSON] (https://www.justice.gov/usao-wdwa/press-release/file/1188626/download)
* [Preventing The Capital One Breach] (https://ejj.io/blog/capital-one)
* [What We Can Learn from the Capital One Hack] (https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/)
* [First American Financial Corp. Leaked Hundreds of Millions of Title Insurance Records] (https://krebsonsecurity.com/2019/05/first-american-financial-corpleaked-hundreds-of-millions-of-title-insurance-records/)
* [Understanding The First American Financial Data Leak] (https://www.forbes.com/sites/ajdellinger/2019/05/26/understanding-the-first-americanfinancial-data-leak-how-did-it-happen-and-what-does-it-mean/)
* [XSS Filter Evasion Cheat Sheet] (https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
* [URL Toolbox] (https://apps.splunk.com/app/2734/)
