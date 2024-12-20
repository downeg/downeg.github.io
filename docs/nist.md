---
layout: default
title:  "Case Study: NIST (Cybersecurity Standards & Risks)"
date:   2023-10-09 09:00:00 +0000
categories: nist ransomware phishing university assignment
---

# Case Study: NIST (Cybersecurity Standards & Risks)

---
University assignment Autumn 2023

---

> ### Introduction.

{: style="text-align: justify" }
The use-case company is a software developer named GoodSoftware. It is a US based medium sized company with over 1000 employees and about $40 million in annual revenue. They have a single site in four countries: the US, Ireland, the Netherlands, and New Zealand. Each site has a marketing department, a sales department and a billing department. The software development is done in the US and Ireland offices. There is a dedicated cyber-security team based in the Irish office. Most of GoodSoftware’s business communication is via phone and email. New customers are found through the GoodSoftware website, email campaigns and the company’s well-respected name. In a recent risk management initiative, the biggest business risks to GoodSoftware were determined to be the loss of their intellectual property and a loss of customers by having a bad reputation in protecting against cyber threats.

{: style="text-align: justify" }
With GoodSoftware’s reliance on email, the first most significant cyber risk was determined to be phishing. Microsoft Exchange email servers and the Microsoft Office Outlook mail client are used by GoodSoftware. Email from the company is sent using the domain name goodsoftware.com. Cloud technologies are not currently used. All development work and customer relations management (CRM) data are stored on premises. With all data being kept on-prem the second most significant cyber risk to GoodSoftware was determined to be a complete loss of access to its data through a ransomware attack.

> ### Identify and describe two significant inherent cybersecurity risks faced by your use-case organisation, based on the strategic risk environment the usecase/real organisation operates within.
> ### With reference to the NIST Cybersecurity Framework, identify which Function, Category and Sub-Category the two identified cybersecurity risks align with.

{: style="text-align: justify" }
Email is one of the most important assets in GoodSoftware as most customer communications, including marketing, sales and billing, are done through email. In this paper we will focus on email as a method of communication rather than on the data retention policies on email that may be required for legal purposes. A major risk to the GoodSoftware’s email infrastructure is phishing.

{: style="text-align: justify" }
NIST defines phishing as "*A technique for attempting to acquire sensitive data, such as bank account numbers, through a fraudulent solicitation in email or on a web site, in which the perpetrator masquerades as a legitimate business or reputable person*". Phishing offers an attack vector for malware into the company’s internal network, and GoodSoftware’s customers could be targeted in a spear phishing campaign for fraudulent invoicing or credential theft. GoodSoftware has mail servers in all four of its global sites. Email is used by all employees in each of the four sites. The first task in protecting email is to identify all the mail server assets. This would fall under the ***NIST CSF Identify function***, where ***Asset Management subcategory 3 (ID.AM-3)*** requires that "*Organizational communication and data flows are mapped*". Knowing where business email originates and proving the integrity of emails originating from GoodSoftware will prevent threat actors from impersonating GoodSoftware in spear phishing campaigns against its customers. If customers were to fall victim to targeted campaigns that appeared to originate from the GoodSoftware, then the company would lose respect and market share and be unable to retain customers or generate new revenue.

{: style="text-align: justify" }
GoodSoftware employees could also be targeted by phishing campaigns and a lack of training and understanding of the risks of phishing could open the company up to malware infections. The ***NIST CSF Protect function, Awareness and Training subcategory 1 (PR.AT-1)*** states that "*All users are informed and trained*". Having alert and aware employees will help to mitigate the influence of phishing campaigns on them and reduce the attack surface for threat actors trying to gain unauthorized access to GoodSoftware’s internal network.

{: style="text-align: justify" }
Ransomware attacks will typically exploit vulnerabilities in software to propagate through the network once the initial breach has occurred. The 2016 ransomware SamSam exploited a vulnerability in Red Hat's JBoss Enterprise Application Platform to infect systems. The WannaCrypt crypto-worm of 2017 made use of the known vulnerability in Microsoft Windows' network communication protocol Server Message Block (SMB) to replicate through an infected network. It is an essential security stance that regular vulnerability scans are performed on all GoodSoftware’s hardware and software assets and that all vulnerabilities are patched. This aligns with the NIST CSF Detect function, ***Security Continuous Monitoring subcategory 8 (DE.CM-8)*** which states "*Vulnerability scans are performed*". Paying ransomware may be illegal. The 2021 Office of Foreign Assets Control (OFAC) advisory on risks for facilitating ransomware payments states "*Companies that facilitate ransomware payments to cyber actors on behalf of victims, including financial institutions, cyber insurance firms, and companies involved in digital forensics and incident response, not only encourage future ransomware payment demands but also may risk violating OFAC regulations*". Therefore, it is important that data recovery is possible if a ransomware attack is conducted on the GoodSoftware network. Data should be backed up regularly and fully protected and recoverable post-attack without the need to pay out any ransom to the threat actors. ***NIST CSF Protect function, Information Protection Process and Procedures subcategory 4 (PR.IP-4)*** recommends that "*backups of information are conducted, maintained, and tested*".

> ### Develop a suitable Inherent Likelihood Risk Matrix and an Inherent Impact Risk Matrix for the use-case organisation, using practical measures that are relevant to your use-case organisation’s strategic risk environment. 
> ### Briefly describe why these measures are relevant for this use-case organisation. Calculate the Inherent Risk Score for each of the two cybersecurity risks.

IMAGE MISSING

{: style="text-align: justify" }
Phishing received an inherent likelihood of 5 as it is a constant threat. With phishing being the easiest initial attack vector for threat actors to deploy malware or steal credentials we must give this as a high inherent impact rating. The company may still be able to function depending on the type of phishing attack it fell victim to, so an inherent impact rating of 4 is given. This results in an inherent risk score of 20 out of 25.

{: style="text-align: justify" }
Ransomware attacks are increasing year upon year. There is not a single company connected to the Internet who are not a prospective target to the cyber-criminals who operate in ransomware. The likelihood of a ransomware attack is 5 as it is a constant threat. GoodSoftware is a software company and if access to the library of intellectual property were to be encrypted in a ransomware attack, then the company would be unable to function, and the entire business would collapse. The inherent impact of a ransomware attack is given the maximum value of 5, giving a maximum inherent risk score of 25.

> ### Using the NIST Cybersecurity Framework, identify two relevant internal controls (Control Statements) for each of the cybersecurity risks identified in Part 1 above.
> ### Describe how the implementation of the chosen internal controls will impact the Inherent Risk Scores calculated in Part 2 above.

{: style="text-align: justify" }
A control to put into place to secure the integrity of outgoing emails and reducing threat actor's ability to masquerade as GoodSoftware would be to implement SPF, DKIM and DMARC. 

{: style="text-align: justify" }
*Sender Policy Framework (SPF)* provides a mechanism by which transferring or receiving mail servers can check if the mail server sending emails for a certain domain name is authorized to do so.. This is achieved by an organisation (GoodSoftware) identifying its authorised mail servers during the mapping of business communications (***NIST CSF ID.AM-3***) and providing DNS TXT records for the IP addresses of each server identified. When a customer’s mail server receives an email from the ```goodsoftware[.]com`` domain it can perform a lookup on the domain name and confirm if it matches one of GoodSoftware’s authorised IP addresses. The use of SPF will imbue confidence in customers that all business-related emails originate from GoodSoftware servers.

{: style="text-align: justify" }
*DomainKeys Identified Mail (DKIM)* leverages the Public Key Infrastructure (PKI) to digitally sign any outgoing emails from an organisation. The receiving mail server can then validate the email as legitimate by checking the certificate against the sender's public key. All emails sent from a GoodSoftware mail server should be digitally signed.

{: style="text-align: justify" }
DMARC, which stands for *Domain-based Message Authentication, Reporting & Conformance*, is an email authentication, policy, and reporting protocol which verifies email senders by building on SPF and DKIM. With SPF and DKIM implemented, GoodSoftware can publish DMARC policies via DNS to recommend to receiving mail servers what to do if a DMARC check fails. Customers can configure their mail servers to either quarantine or reject any emails received from the goodsoftware.com domain name that contain invalid DMARC signatures. This will instil a sense of confidence in customers when responding to emails that they are not being targeted by phishing attacks which impersonate GoodSoftware’s domain.

{: style="text-align: justify" }
A control to put in place to protect GoodSoftware employees against phishing is to conduct yearly mandatory training on cyber-security which promotes the awareness of how phishing campaigns work (NIST CSF PR.AT-1). Outlook has a *Phishing Alert Button (PAB)* which can be used by employees to highlight any emails that they consider suspicious. On reporting an email using the PAB it is quarantined until it is checked manually by the cyber security team. If there is no issue found with the email it is delivered back to the employee. Quarterly testing can be carried out by the cyber security team where simulated phishing emails are sent to employees to check if they will report the email correctly using the Outlook PAB, or if they fall 'victim' to the email. Any employees that fail the test will need to go through the mandatory training again.

IMAGE MISSING

Example of the Outlook Phish Alert Button [original](https://helpdesk.tcsedsystem.edu/hc/en-us/articles/4412725474967-What-is-the-Phish-Alert-Button-and-how-do-I-use-it)

{: style="text-align: justify" }
A control for mitigating exposure to known vulnerabilities is to develop a policy to regularly scan all assets that connect to the network (***NIST CSF DE.CM-8***) and implement maintenance schedules for patching any vulnerabilities found. The assets to be scanned include all servers, desktops, laptops and mobile devices belonging to the company. Firmwares of routers, wireless access points and other network devices should also be scanned regularly. The *Common Vulnerability Scoring System (CVSS)* can be used to evaluate and rank discovered vulnerabilities so that appropriate timelines can be set out for patching while maintaining the maximum uptime and availability of resources.

{: style="text-align: justify" }
A control to guarantee access to business data during and after a successful ransomware attack is to implement regular backups (***NIST CSF PR.IP-4***). The backups should be verified and tested to confirm the integrity of the data. Two objectives to consider when planning the backup strategy are the *Recovery Time Objective (RTO)* and *Recovery Point Objective (RPO)*. RPO is the amount of data loss a business can afford in terms of time or in terms of information. Servers that contain customer data and intellectual policy will have a much shorter RPO than employee devices such as laptops and mobile phones so will need to be backed up more often. The RTO is the time that it takes to bring the entire application stack to the last good state. Again, business critical servers will need to have a much shorter RTO than end user devices as development servers or CRM applications being unavailable for extended periods will halt GoodSoftware's ability to do business. The use of air-gapped immutable backup vaults should be used to protect the backups from being encrypted by ransomware attacks. The control effectiveness score is given a quantitative value which is a number between 0.0 and 1.0. An effectiveness of 0.0 means that the control absolutely and completely mitigates the risk. An effectiveness of 1.0 means that the controls in place are completely ineffective. After multiplying the inherent risk score by the control effectiveness score for the implemented controls we get the final residual risk.

IMAGE MISSING

{: style="text-align: justify" }
Phishing mitigation through asset management and the training and raised awareness of employees is given an effectiveness score of 0.4. This may not seem like the controls are very effective, however this value is based on the fact that it is impossible to control human behaviour. No matter how much we try to defend against phishing it always depends on the end user and how they respond on the day the phishing email arrives. Even with a medium effectiveness score of 0.4 this still brings the residual risk score down to a tolerable 8 out of 25.

{: style="text-align: justify" }
With stricter control possible over strategies to reduce the attack surface through patch management and the protection of data through a resilient backup strategy an effectiveness score of 0.2 can be applied to the controls in place to protect GoodSoftware from ransomware attacks. Bringing the residual risk score down to an acceptable 5 out of 25 is justification for the expenses that may arise from purchasing additional hardware or software licenses required to implement the vulnerability scans and backup vaulting.

> ### Identify and describe a relevant cybersecurity risk metric for each of the cybersecurity risks identified in Part 1 above. 
> ### Describe how the cybersecurity risk metrics can be used to manage the identified risks you identified.

{: style="text-align: justify" }
Metrics such as click-through rates, reporting rates, and overall user awareness levels can provide valuable feedback for phishing tests. Monitoring these metrics during phishing simulations will inform the cyber-security on the effectiveness of the training program, and on how vigilant employees are about reporting phishing emails. Repeat offenders who constantly fail the phishing test can be given additional customised training. Feedback from individuals as to why they clicked through on the phishing link can help to improve future training.

{: style="text-align: justify" }
Vulnerability scanning reports can provide valuable metrics as to how well system updating and patching is being performed on GoodSoftware’s hardware and software assets. Regular scanning will make sure that the mean time to repair for discovered vulnerabilities is being kept within the acceptable timeframes set out by the cyber-security team. Any assets which are continuously reporting positive for a known vulnerability will need to have some compensating controls put in place to prevent infection with ransomware. Vulnerability scanning may not be able to prevent zero-day vulnerabilities, but it can show how quickly and effectively known vulnerabilities are patched in the environment.

> ### References.

* [NIST Computer Security Resource Centre Glossary: Phishing](https://csrc.nist.gov/glossary/term/phishing)
* [ID.AM-3: Organizational communication and data flows are mapped](https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/idam/id-am-3/)
* [PR.AT-1: All users are informed and trained](https://csf.tools/reference/nist-cybersecurity-framework/v1-1/pr/pr-at/pr-at-1/)
* [Is my JBoss / EAP Server Vulnerable to Samas Ransomware?](https://access.redhat.com/solutions/2205341)
* [WannaCrypt ransomware worm targets out-of-date systems](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacryptransomware-worm-targets-out-of-date-systems/)
* [DE.CM-8: Vulnerability scans are performed](https://csf.tools/reference/nist-cybersecurity-framework/v1-1/de/de-cm/de-cm-8/)
* [OFAC Updated Advisory on Potential Sanctions Risks for Facilitating Ransomware Payments](https://ofac.treasury.gov/media/912981/download?inline)
* [PR.IP-4: Backups of information are conducted, maintained, and tested](https://csf.tools/reference/nist-cybersecurity-framework/v1-1/pr/prip/pr-ip-4/)
* [Verizon 2023 Data Breach Investigations Report Summary of Findings](https://www.verizon.com/business/resources/reports/dbir/2023/summary-offindings/)
* [DKIM](https://www.mailhardener.com/kb/dkim)
* [Announcing New DMARC Policy Handling Defaults for Enhanced Email Security](https://techcommunity.microsoft.com/t5/exchange-teamblogannouncing-new-dmarc-policy-handling-defaults-for-enhanced-email/bc-p/3928975)
* [Use DMARC to validate email](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/emailauthentication-dmarc-configure?view=o365-worldwide)
* [Enable the Microsoft Report Message or the Report Phishing add-ins](https://learn.microsoft.com/en-us/microsoft365/security/office-365-securitysubmissions-users-report-message-add-inconfigure?view=o365-worldwide)
* [What is Common Vulnerability Scoring System (CVSS)](https://www.sans.org/blog/what-is-cvss/)
* [RPO and RTO management](https://infohub.delltechnologies.com/l/dell-validated-design-for-retail-edge-withdeep-north-design-guide/rpo-and-rto-management/)
* [Dell Cyber Resilience Data Protection](https://www.dell.com/enie/dt/data-protection/cyber-recovery-solution.htm)
* [Key Metrics For Measuring Security Awareness Training](https://www.metacompliance.com/blog/cyber-security-awareness/measuring-securityawareness-training)
