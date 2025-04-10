# Penetration Testing with Kali & Metasploit

![image](https://github.com/user-attachments/assets/ca1e8881-ac5b-43db-8589-2ab757bf4530)

## 📖 Table of Contents

- [Introduction](#introduction)
- [Tools Used](#tools-used)
- [Network Scanning](#network-scanning)  
  - [Exercise 1.1: NMAP Network Scanning](#exercise-11-nmap-network-scanning)  
  - [Exercise 1.2: Scan Automation using Legion](#exercise-12-scan-automation-using-legion)  
- [Task 2 - Exploiting the Unreal IRC Server](#task-2---exploiting-the-unreal-irc-server)  
  - [Exercise 2.1: Exploiting UnrealIRCd](#exercise-21-exploiting-unrealircd)  
  - [Exercise 2.2: Start HTTP Webservice](#exercise-22-start-http-webservice)  
- [Task 3 - Gaining Root Access](#task-3---gaining-root-access)  
  - [Exercise 3.1: Identify and Acquire Kernel Vulnerability](#exercise-31-identify-and-acquire-kernel-vulnerability)  
- [Task 4 - Cracking the Passwords](#task-4---cracking-the-passwords)  
  - [Exercise 4.1: Acquire the Passwords](#exercise-41-acquire-the-passwords)  
  - [Exercise 4.2: Deciphering the Password](#exercise-42-deciphering-the-password)  
- [Task 5 - Login into Ubuntu Metasploit](#task-5---login-into-ubuntu-metasploit)  
- [Task 6 - Mapping to ATT&CK](#task-6---mapping-to-attck)  
  - [Definition](#definition)  
  - [Tactics, Techniques, and Sub-Techniques](#tactics-techniques-and-sub-techniques)  
- [Task 7 - ATT&CK Technique Countermeasure](#task-7---attck-technique-countermeasure)  
  - [ATT&CK Matrix](#attck-matrix)  
- [Conclusion](#conclusion)  
- [References](#references)  

  ---

## Introduction

In today’s interconnected world, computer and cloud security are paramount for organizations striving to safeguard their operations. Cloud service providers and their corporate clients must proactively prepare to counter cyberthreats before they strike and ensure resilience against a diverse range of malicious activities to maintain a competitive edge. While cloud-based solutions offer compelling cost-saving benefits, they also introduce challenges related to scalability, privacy, and security. These concerns contribute to hesitation and complexities surrounding their widespread adoption.

This report will focus on penetration testing using both Kali and Metasploit. The goal is to complete each assigned task given. I will be focusing on the following:


-	Network Scanning
- Exploiting the unreal IRC Server
- Gaining root access
- Cracking the passwords
- Logging into ubuntu Metasploit
- Mapping to Att&ck
- Att&ck Technique Countermeasures 

All of these labs were completed on Oracle Box Virtual Machines which will demonstrate all my work I completed. 

---

### Tools Used

- Kali Linux (for penetration testing and running Nmap, Legion, and Metasploit)
- Metasploit (for exploiting vulnerabilities and gaining access to target systems)
- Nmap (for network scanning and service enumeration)
- Legion (for automated scanning and vulnerability assessment)
- Unreal IRCd (target application for exploitation testing)
- Oracle VirtualBox (for virtualizing the lab environment with Ubuntu and Windows VMs)
- Ubuntu VM (for hosting Metasploit and conducting penetration testing tasks)
- Windows VM (for additional network scanning and testing)

---

#### Lab Enviornment

![Image](https://github.com/user-attachments/assets/7bb13030-d9dd-4f9d-94d5-2b7eea21f424)

### Network Scanning

Task 1.1: NMAP Network Scanning 
Exercise: Carry out a ping sweep and list the network addresses discovered

ANS: nmap -sn 10.0.2.0/24

![Image](https://github.com/user-attachments/assets/c1f64df5-a6a3-4efa-920f-8e29a56b3d49)

Exercise: Carry out a TCP SYN scan to determine system ports on Ubuntu VM. Use -Pn to avoid host discovery phase. Show the list of ports for each VM.

ANS: sudo nmap -Pn -PS 192.168.43.252

![Image](https://github.com/user-attachments/assets/2d0ca4bd-fb33-4279-8973-c626042eb829)

Exercise: Repeat but this time use the -p option to explicity indicate the ports. Use -p 1-65535. highlight any differences between the two scans.

Answer: sudo nmap -Pn -PS -p1-65535 192.168.43.252

![Image](https://github.com/user-attachments/assets/709032a2-881a-4258-ad02-de2ea612f450)

From the second scan carried out, the major difference with the previous scan has to do with the addition of two newly discovered ports, 3500(rtmp-port) and 6697(ircs-u).

Exercise: Carry out a service OS discovery on both machines and list the results.

ANS:  For Linux VM: sudo nmap -O -sV 192.168.43.252

![Image](https://github.com/user-attachments/assets/58894bfc-1a1f-4a93-9cce-1c6bda735b40)

For Windows VM: sudo nmap -O -sV 192.168.43.81

![Image](https://github.com/user-attachments/assets/65b8ccd0-f230-47f6-b4fd-0921e3d5fe91)

![Image](https://github.com/user-attachments/assets/8c5b9d30-2d74-4193-bb8c-e0fd6f8ad0b6)

---

Exercise 1.2: Scan automation using Legion
Start a scan on the Ubuntu host 

ANS:

![Image](https://github.com/user-attachments/assets/ecc5aca1-47f6-4546-a337-e0fb0b398023)

Exercie: Show the list of ports and services:

ANS:

![Image](https://github.com/user-attachments/assets/ccb4043f-034b-4820-b026-d403fe58ac49)

Exercise: Show the screenshot for port 80

ANS: 

![Image](https://github.com/user-attachments/assets/dcae5957-8efb-476b-b73a-f5aa4a33fdd6)

Exercise: Run the nikto tool on port 80. Click on the service window in Legion, select http and select port 80 in right hand window, right click to display options. Select run nikto! Select Tools windows in Legion and select nikto to see results of scan). Indicate three vulnerabilities indicated by nikto on port 80 - refer to OSVDB number report. Include the OSVDB number where appropriate.

ANS:

![Image](https://github.com/user-attachments/assets/d2433851-b429-4d9c-acb3-a2c3b918a151)

![Image](https://github.com/user-attachments/assets/3913d9ac-5d1e-4f65-ad9b-7eb1b4faa7a1)

![Image](https://github.com/user-attachments/assets/7aaf41e5-ee30-4c8e-95cb-9a6489caecbb)

![Image](https://github.com/user-attachments/assets/fc322709-113d-48c8-ad11-ebe375c91d1b)

Exercise. Grab the screenshot for port 3500 

ANS:

![Image](https://github.com/user-attachments/assets/39be7bed-884c-493f-93ad-86fd5f83e860)

Task 2 Exploiting the Unreal IRC server
Exercise 2.1: Exploiting  UnrealIRCd - Give a short descripton of IRC and Unreal IRCd server

### Internet Relay Chat (IRC)
Internet Relay Chat (IRC) is a protocol for real-time text messaging over the internet, enabling communication between users on connected computers. IRC operates on a client-server model and is primarily used for group discussions in chat rooms called "channels," though it also supports private messaging, data transmission, and various server/client commands. Users connect to IRC servers using an IRC client or web interface, joining channels to discuss shared interests. 

### Unreal IRCd Server
UnrealIRCd is an open-source IRC server software, known for its advanced features and flexibility. It highlights its focus on modularity, with a highly configurable setup that includes features like SSL support, cloaking (to hide user IP addresses), advanced anti-flood and anti-spam systems, swear filtering, and module support for extending functionality. UnrealIRCd, specifically version 3.2.8.1 in this assignment, runs on port 6697 and is designed to host IRC channels, making it a popular choice for communities needing a robust and secure IRC server. 

Exercise: Indicate the Unreal IRCd version and the port it is open on.

ANS:

Version: 3.2.8.1

Port: 6697 

Exercise: Search for UnrealIRCD exploits in exploit-db. Use searchsploit and the exploit-db.com website. Show the results via a screenshot. Identify which exploit is likely to be most useful.

ANS:

![Image](https://github.com/user-attachments/assets/2ff3da0d-7af3-4962-84d9-3cab3e8fd96f)

Exercise: Open Metasploit using msfconscole or choose from the Kali application menu

ANS:

![Image](https://github.com/user-attachments/assets/1a35c9a2-0bce-4a56-b140-42ddb257094b)

Exercise: Search for UnrealIRDc exploits and select the one to use. Identify the CVE number and indicate the CVSS scoree for this vulnerability.

ANS:

CVSS score: 7.5

CVE number: CVE-2010-2075

![Image](https://github.com/user-attachments/assets/4279fc8b-dae5-4cd3-b16b-f36fde7fb6cb)

![Image](https://github.com/user-attachments/assets/a03084b3-4d6e-4dc8-a548-1be998c3fe96)

![Image](https://github.com/user-attachments/assets/0e36976b-4bb9-473b-82b6-c1e20681127c)

Exercise: Show and configure the options (Ihost/rhost/rport) (using Kali and Ubuntu host info)

ANS:

![Image](https://github.com/user-attachments/assets/0e36976b-4bb9-473b-82b6-c1e20681127c)

Exercise: Select payload 5 - cmd/unix/reversE

ANS:

![Image](https://github.com/user-attachments/assets/8607cdf0-e083-473b-90a0-144c2bdc391a)

Exercise: Run the exploit - you show now have gained remore access. Give the 'whoami' and 'ls' commands to show evidence of access. Provide a screensot showing exploit trace execution.

ANS: 

![Image](https://github.com/user-attachments/assets/109b4ea7-f3bd-4ccc-84c4-631937ca5223)

![Image](https://github.com/user-attachments/assets/cd01f464-b7d3-47f2-8e7b-4e57e93142c8)

Exercise 2.2 - Start HTTP webservice 

Exercise 2.2.1: In a seperate shell start the SimpleHTTPServer in directory /root/Downloads. Use python -m SimpleHTTServer

ANS:

![Image](https://github.com/user-attachments/assets/06eaa1e6-c989-480c-ac4a-58817d57821f)

---

## Gaining Root Access

Exercise 3.1 - Identify the Linux distribution (cat /etc/issue) and the kernel version (uname -a). Is the kernel 32 or 64 bit?

ANS:

The kernel is 64-bit

![Image](https://github.com/user-attachments/assets/b872e796-db81-4d70-b270-18d7428152f7)

Exercise 3.2 - Use searchsploit to look for any kernel exploit(s) found and indicate which will be used. Show the kernel version number. Show the exploit(s) via a screenshot. Give a short description of the vulnerability using the associated exploit-db information. Indicate the CVE number and the CVSS score.

ANS:

CVE number: CVE-2010-2075

CVSS score: 7.5 

![Image](https://github.com/user-attachments/assets/5cd083e9-ad60-47af-bc89-6f9ed081fe91)

![Image](https://github.com/user-attachments/assets/439c8eb6-cf42-4099-ace6-c5b487f26a36)

Exercise 3.3 - Copy the vulnerability C file to the /root directory and transfer the vulnerability file to Ubuntu using wget

ANS: 

![Image](https://github.com/user-attachments/assets/9733de53-fc16-4089-ab2f-a2d5cc0a5d4c)

Exercise 3.5 You should now have a root shell #. Use whoami to confirm root access. Show the entire sequence via a screen shot.

ANS:

![Image](https://github.com/user-attachments/assets/6487ba6e-127c-4566-9cba-e665c753f6e6)

---

## Exercise 4 - Acquire Passwords

Exercise 4.1: Copy the password file (/etc/passwd) and the shadow file (/etc/shadow) to the /root home directory. Transfer both files to the Kali server. 

This can be done either by: 

a. Starting the SimpleHTTPServer on Ubuntu VM and exercising wget from the Kali VM. To do this you will first need to add a rule to the iptables to make the SimpleHTTPServer visible to Kali (e.g., add the default port 5000 iptables -I INPUT -p tcp --dport 5000 -j ACCEPT -I is recommended rather than -A as the rule may be added after a default drop rule otherwise. 

b. Transferring the files to the /var/www/html directory, and fetching via browser from Kali VM. There are a couple of complications to be sorted here including setting appropriate file permissions to enable the shadow file to be read via browser. Accessing these files via a browser will require selecting and copying the text from the browser and pasting to a text file. This can be done using an editor such as vim or the nano editor in the Kali. 

c. It should also be possible to transfer the files using nc/ncat - though I have not tried this. 

Clearly show the steps taken via a screen shot.

ANS:

![Image](https://github.com/user-attachments/assets/9b8ebc9e-8373-4a93-b01f-4a5f207c5d77)

![Image](https://github.com/user-attachments/assets/30e98ecb-4d47-445a-857d-48534cbda1f4)

Exercise 4.2 - Deciphering the password

Exercise 4.2.1 - 
1. Move both files (passwd, shadow) to your home directory if not already done so.
2. Do unshadow passwd shadow > cracked
3. You can now run the john the ripper as john --single cracked or alternatively john --wordlist=/usr/share/john/password.lst cracked
4. This will now attempt to crack the Ubuntu passwords. In fact only one password will be cracked for user vagrant

ANS:

![Image](https://github.com/user-attachments/assets/7bef8562-01b2-4942-912e-dcf64c3191fc)

![Image](https://github.com/user-attachments/assets/f56183fb-fc50-4e67-a07d-7e7e707f2a3e)

---

## Task 5 - Login via Ubuntu Metasploit

Exercise 5.1 - You should now have the password for the 'vagrant' user.

1. Login and show the home shell

ANS:

Username: vagrant Password: notavagrant

![Image](https://github.com/user-attachments/assets/00f2854a-dd10-4205-bc9f-97ed9f0ba7ae)

Exercise 5.2 - List the files & directories and show - use a screenshot.

ANS:

Files and directories in the “vagrant” home directory
37292.c, 37293, 47170.c, chocobo_root, ofs, VBoxGuestAdditions.iso

![Image](https://github.com/user-attachments/assets/c8ee511e-be48-4540-95c5-14fa10cb8277)

---


## Task 6 - Mapping to ATT&CK

MITRE ATT&CK is a guideline for classifying and describing cyberattacks and intrusions with a focus on TTPs (Tactics, Techniques and Procedures) and thereby the top of the Pyramid of Pain.

![Image](https://github.com/user-attachments/assets/9de0ad02-9fbd-43fa-854f-dae267425d75)

TTPs can in turn be translated to attacker behaviours. Meaning: what does an attacker do to achieve its goal (e.g. steal money or intellectual property). In more detail TTPs can be explained the following way.

Tactics: the adversary’s technical goals.

Techniques: how the goals are achieved.

Procedures: specific technique implementation.

Attackers can exploit organisational networks through various methods, including session hijacking, SQL injection, and other sophisticated techniques. As a Security Analyst, I recognize that adversaries are growing increasingly adept in their attack strategies. Organisations must remain vigilant and proactive, as even a single oversight can lead to substantial damage,

## 🛡️ MITRE ATT&CK TTPs for Penetration Testing Assignment

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1595      | Active Scanning                  | Network scanning using Nmap and Legion to identify live hosts, ports, and services.             | Detects reconnaissance efforts targeting network infrastructure and services.   |
| T1190      | Exploit Public-Facing Application| Exploiting Unreal IRCd server vulnerability on port 6697.                                       | Identifies exploitation attempts on externally accessible applications.         |
| T1203      | Exploitation for Client Execution| Executing exploit code against Unreal IRCd to gain initial access.                             | Reveals execution of malicious code to compromise a target system.              |
| T1068      | Exploitation for Privilege Escalation | Using a kernel exploit to gain root access on the target system.                            | Detects privilege escalation attempts via kernel vulnerabilities.               |
| T1110      | Brute Force                      | Cracking passwords to extract credentials from the target system.                              | Identifies password cracking efforts to uncover valid credentials.              |
| T1078      | Valid Accounts                   | Logging into Ubuntu Metasploit using provided credentials.                                      | Monitors use of legitimate credentials for potential unauthorized access.       |

The MITRE ATT&CK framework is a powerful tool for understanding adversary tactics and techniques, but it also serves as a foundation for developing effective countermeasures to bolster organizational defenses. By mapping threats to the ATT&CK matrix, security teams can identify specific techniques such as session hijacking (T1563) or SQL injection (T1190) and implement targeted mitigations, such as enforcing multi-factor authentication, sanitizing database inputs, or deploying intrusion detection systems to monitor for suspicious activity. For instance, to counter reconnaissance techniques (TA0043) like active scanning (T1595), organisations can use network segmentation and firewall rules to limit exposure of internal services, as well as deploy deception technologies like honeypots to detect and mislead attackers. Additionally, adopting a threat-informed defense strategy. It allows teams to simulate adversary behaviors, test their defenses, and refine incident response plans, ensuring resilience against evolving cyber threats. This proactive approach transforms ATT&CK from a knowledge base into a practical guide for strengthening security postures.

ATT&CK Matrix for Enterprise

Source: https://attack.mitre.org/

![Image](https://github.com/user-attachments/assets/deadb775-444a-435f-a4bb-aaad16aa535a)


---

# Conclusion

This penetration testing assignment, leveraging Kali Linux and Metasploit, has been instrumental in deepening my expertise in cybersecurity. By successfully completing a series of rigorous tasks such as Network Scanning, Exploiting the Unreal IRC Server, Gaining Root Access, Cracking Passwords, Logging into Ubuntu Metasploit, Mapping to MITRE ATT&CK, and Identifying ATT&CK Technique Countermeasures has allowed me to significantly expanded my technical skill set and practical understanding of offensive security. 

In spite of encountering numerous challenges, such as the complexities of password cracking, I persevered, gaining valuable insights into the critical role of robust security practices in organizations. This process underscored the importance of identifying vulnerabilities, like weak passwords, to assess an organization’s security posture—a key takeaway for any aspiring penetration tester. 

Additionally, utilising Metasploit and applying ATT&CK frameworks has equipped me with essential tools and methodologies to excel in the IT security industry. 
