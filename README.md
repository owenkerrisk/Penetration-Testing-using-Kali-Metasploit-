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

This report will focus on penetration testing using both Kali and Metasploit. The goal is to complete each assigned task given. I will be focusing on the following;
•	Network Scanning
•	Exploiting the unreal IRC Server
•	Gaining root access
•	Cracking the passwords
•	Logging into ubuntu Metasploit
•	Mapping to Att&ck
•	Att&ck Technique Countermeasures 

All of these labs were completed on Oracle Box Virtual Machines which will demonstrate all my work I completed. 

### Tools Used

- Kali Linux (for penetration testing and running Nmap, Legion, and Metasploit)
- Metasploit (for exploiting vulnerabilities and gaining access to target systems)
- Nmap (for network scanning and service enumeration)
- Legion (for automated scanning and vulnerability assessment)
- Unreal IRCd (target application for exploitation testing)
- Oracle VirtualBox (for virtualizing the lab environment with Ubuntu and Windows VMs)
- Ubuntu VM (for hosting Metasploit and conducting penetration testing tasks)
- Windows VM (for additional network scanning and testing)

### Network Scanning

Task 1.1: NMAP Network Scanning 
Exercise: Carry out a ping sweep and list the network addresses discovered

ANS: nmap -sn 10.0.2.0/24

![Image](https://github.com/user-attachments/assets/99defb5d-21a4-4931-9d28-feebd0543225)

Exercise: Carry out a TCP SYN scan to determine system ports on Ubuntu VM. Use -Pn to avoid host discovery phase. Show the list of ports for each VM.

ANS: sudo nmap -Pn -PS 192.168.43.252

![Image](https://github.com/user-attachments/assets/5dafabb2-5d41-484a-8104-ffe07176d92f)

Exercise: Repeat but this time use the -p option to explicity indicate the ports. Use -p 1-65535. highlight any differences between the two scans.

Answer: sudo nmap -Pn -PS -p1-65535 192.168.43.252

![Image](https://github.com/user-attachments/assets/542e706a-81c6-49f4-8afd-2956dc86ec37)

From the second scan carried out, the major difference with the previous scan has to do with the addition of two newly discovered ports, 3500(rtmp-port) and 6697(ircs-u).

Exercise: Carry out a service OS discovery on both machines and list the results.

ANS:  For Linux VM: sudo nmap -O -sV 192.168.43.252

![Image](https://github.com/user-attachments/assets/bd2a364f-fdb8-43f6-b026-da7564aa78f5)

For Windows VM: sudo nmap -O -sV 192.168.43.81

![image](https://github.com/user-attachments/assets/6c3084f2-4ac4-4795-a243-639ba5d361fa)

![image](https://github.com/user-attachments/assets/4489b35c-254a-4333-af88-435c4af224e0)

Exercise 1.2: Scan automation using Legion

Start a scan on the Ubuntu host 
ANS:
![image](https://github.com/user-attachments/assets/85933205-b187-4673-8306-e7629ebc12d3)

Exercies: Show the list of ports and services:
ANS:
![image](https://github.com/user-attachments/assets/a4e0ba50-c1c9-4fdb-bba9-62a8df90a89c)

Exercise: Show the screenshot for port 80

ANS: 
![image](https://github.com/user-attachments/assets/c9ce68d4-700e-4538-8de4-350181720042)

Exercise: Run the nikto tool on port 80. Click on the service window in Legion, select http and select port 80 in right hand window, right click to display options. Select run nikto! Select Tools windows in Legion and select nikto to see results of scan). Indicate three vulnerabilities indicated by nikto on port 80 - refer to OSVDB number report. Include the OSVDB number where appropriate.

ANS:
![image](https://github.com/user-attachments/assets/39375400-4245-4b91-871f-89bf936d105e)
![image](https://github.com/user-attachments/assets/af3eebd4-5e99-4186-8e57-2610ff8778ee)
![image](https://github.com/user-attachments/assets/75ffd492-d25a-4766-8f16-5501eaa49c4b)
![image](https://github.com/user-attachments/assets/1c534740-239f-45b2-95aa-5719268fe5a9)

5. Grab the screenshot for port 3500 
ANS:
![image](https://github.com/user-attachments/assets/e0d82d70-ce77-423d-b830-8855587b1c1d)

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
![image](https://github.com/user-attachments/assets/eb3ecdf4-0ade-4655-82a6-feda34dc1f0d)

Exercise: Open Metasploit using msfconscole or choose from the Kali application menu

ANS:

![image](https://github.com/user-attachments/assets/895ea962-d72d-4a22-a998-5dca58a71ead)

Exercise: Search for UnrealIRDc exploits and select the one to use. Identify the CVE number and indicate the CVSS scoree for this vulnerability.

ANS:
CVSS score: 7.5

CVE number: CVE-2010-2075

![image](https://github.com/user-attachments/assets/0707b203-bd9b-4f12-89e8-4c0c0b75eefe)
![image](https://github.com/user-attachments/assets/c3fbe399-3ef3-4562-b27a-7e4f8019652e)
![image](https://github.com/user-attachments/assets/39e6f7d4-f4fc-4da2-a97f-5fb44ddcac1a)

Exercise: Show and configure the options (Ihost/rhost/rport) (using Kali and Ubuntu host info)

ANS:

![image](https://github.com/user-attachments/assets/3c419738-202a-46ca-b833-e6d78c44b035)

Exercise: Select payload 5 - cmd/unix/reverse
![image](https://github.com/user-attachments/assets/40c0fd9e-6a4e-41f5-95d5-389e84619e17)

Exercise: Run the exploit - you show now have gained remore access. Give the 'whoami' and 'ls' commands to show evidence of access. Provide a screensot showing exploit trace execution.

ANS: 
![image](https://github.com/user-attachments/assets/ed8c84b1-79e3-4370-a290-f0fdc6628ec3)
![image](https://github.com/user-attachments/assets/c6939e26-656d-4bed-a5a8-e1e996d457a7)








 







ANS:
 
 


 
 


4.	Grab the screenshot for port 3500. 
ANS:

 








Task 2 Exploiting the Unreal IRC server
![image](https://github.com/user-attachments/assets/12fdd32a-d630-40ac-b391-ae2febed927a)



## Network Diagram

[![NetworkDiagram-ActiveDirectoryProject drawio](https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/f44ce545-f677-4006-8a65-b447b6d2978f)](https://imgur.com/ib3A0G1)

## Setting up Splunk server and Forwarders

### Setting Static IP Address and Default Route:

- Configured a static IP address for the Splunk server and defined a default route with the gateway 192.168.10.10.
```sudo nano /etc/netplan/00-installer-config.yaml```

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/99ee31d7-40c0-4739-8581-c6d72613b066" alt="Splunk server running in Oracle VirtualBox" width="635" />

Apply the changes:
```sudo netplan apply```

### Install Splunk Enterprise:

- Installed Splunk Enterprise on the Splunk server and configure it to start at boot.

```tsoc@splunk:/opt/splunk/bin$ sudo ./splunk enable boot-start -user splunk```

### Setting Up Splunk Forwarder:
Installed and configured Splunk Forwarder on ADDC01 and target-PC (Windows 10) to send data to the Splunk server as a receiving indexer.

![2024-06-28 22_10_10-ADDC01  Running  - Oracle VM VirtualBox](https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/54bdd7fe-3954-4c2e-8613-6ec049293241)

### Installing Sysmon:

Installed Sysmon to enhance event logging capabilities.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/306160cf-69bd-4322-b2ee-50dbd73b66eb" width="700" />

### Configuring Inputs for Splunk Forwarder:

Created an inputs.conf file in C:\Program Files\SplunkUniversalForwarder\etc\system\local on ADDC01 and target-PC, configuring settings as per.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/7b973c10-11a6-4620-949e-bc233cf55736" width="700" />
<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/dc816365-9ca2-4435-af25-8d3e7e35aece" width="700" />

### Restarting Splunk Forwarder Service:

Restarted the Splunk Forwarder service on ADDC01 and set to log on as local system account.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/4aa87cdf-4e3e-49a8-a2fe-a0eae7de8f4f" width="700" />

### Connecting to Splunk Web Interface:

Accessed the Splunk server's web interface at port 8000, then created an index named endpoint as specified in the inputs.conf file. I repeated this process for both ADDC01 and target-PC to ensure the Splunk server receives events from both sources.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/fa26209e-7ad2-4136-a5f5-7ec7fba9c232" width="700" />

---

## Setting up Active Directory and provisioning users

Install Active Directory Domain Services on ADDC01

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/80c01684-787a-4639-8f61-a3a8ab7270a7" width="700" />

Promote ADDC01 to Domain Controller

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/39653cdf-11f8-4527-ac06-588629e50e05" width="700" />

I joined target_PC to the domain and tinkered around with users, groups and permissions. I used this script from Josh Madakor's video to create around 1000 users.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/64f8e66c-9404-40de-bb38-5e15b0b4d69a" width="700" />
<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/5501aaa0-120e-4540-8630-00087fb0f77d" width="700" />

---

## Performing a Brute force attack on target_PC and reviewing events via Splunk

I used crowbar to launch a brute force dictionary attack on target_PC from the Kali Linux machine. I had enabled RDP on target_PC beforehand so this attack would be feasable.

![2024-06-29 22_33_32-kali-linux-2024 1-virtualbox-amd64  Running  - Oracle VM VirtualBox](https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/bc6e4d08-5653-45e0-a549-00d88246d945)

After running the attack, we can see that Splunk recorded 42 events with event code 4265, which indicates failed login attempts. This corresponds to the 22 passwords in the wordlist I used for the attack, which was run twice.

Among these, there are two events with event code 4264, representing successful login attempts. This outcome is expected since one of the passwords in the wordlist was of course correct.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/2d796524-390b-449e-86cc-615b9cad0b3a" width="700" />
<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/643611dd-b8e9-41d4-9784-60ffa72060ae" width="600" />

Here we can see that the attack indeed came from the Kali machine at 192.168.10.250

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/2770fcbd-b06a-4ba2-8b40-10d6a2ca347f" width="600" />

---

## Installing Atomic Red Team, Performing a Test, and Reviewing Events in Splunk

Atomic Red Team is an open-source project that offers a collection of tests to simulate cyberattacks based on the MITRE ATT&CK framework.

Before installing Atomic Red Team (ATR) on target_PC, I excluded the C: drive (where ATR will be installed) from Microsoft Defender Anti-Virus scans. Note: This exclusion is not recommended for normal circumstances.

To allow PowerShell scripts to run without restrictions for the current user, I used the command:
```Set-ExecutionPolicy Bypass -Scope CurrentUser```

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/3df29cb5-77f4-4d34-8db9-e112b23f2c04" width="800" />
<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/69ef5c78-2b1e-4ac4-82d3-2b66eef8e699" width="700" />

Next, I installed ATR using the following commands:

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/853de60c-1d63-4a9b-b9a1-43e50401b827" width="800" />

Now we can view all the tests available in Atomic Red Team. Each test is named after the corresponding MITRE ATT&CK technique. For example, I ran the T1136.001 test, which corresponds to the "Create Account: Local Account" persistence technique in MITRE ATT&CK.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/189a3b58-e48d-426a-bfca-9e2ad1da5d1e" width="700" />
<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/febce88b-103b-4330-ba3a-80458c62cd0d" width="500" />

Running the test created a user called NewLocalUser, added it to the local administrators group, and finally deleted the user.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/9426fff8-1b57-4ae5-8d69-5aa5f1b00959" width="700" />

We see these events in Splunk.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/d9d4a3d4-a2ca-4542-bda1-e31a7db4472a" width="700" />

Here are the corresponding event codes:
- 4798: A user's local group membership was enumerated.
- 4738: A user account was changed.
- 4720: A user account was created.
- 4722: A user account was enabled.
- 4724: An attempt was made to reset an account's password.
- 4726: A user account was deleted.

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/06f90944-7158-4630-b824-e3f742759c78" width="700" />

Below is the final event showing "NewLocalUser" being deleted

<img src="https://github.com/PaulMiguelSec/Active-Directory-Lab/assets/174075754/feb94ab2-9222-4a1a-99b4-020f09bfda07" width="700" />

---

# 🛡️ MITRE ATT&CK TTPs for Penetration Testing Assignment

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1595      | Active Scanning                  | Network scanning using Nmap and Legion to identify live hosts, ports, and services (Task 1).             | Detects reconnaissance efforts targeting network infrastructure and services.   |
| T1190      | Exploit Public-Facing Application| Exploiting Unreal IRCd server vulnerability on port 6697 (Task 2).                                       | Identifies exploitation attempts on externally accessible applications.         |
| T1203      | Exploitation for Client Execution| Executing exploit code against Unreal IRCd to gain initial access (Task 2).                             | Reveals execution of malicious code to compromise a target system.              |
| T1068      | Exploitation for Privilege Escalation | Using a kernel exploit to gain root access on the target system (Task 3).                            | Detects privilege escalation attempts via kernel vulnerabilities.               |
| T1110      | Brute Force                      | Cracking passwords to extract credentials from the target system (Task 4).                              | Identifies password cracking efforts to uncover valid credentials.              |
| T1078      | Valid Accounts                   | Logging into Ubuntu Metasploit using provided credentials (Task 5).                                      | Monitors use of legitimate credentials for potential unauthorized access.       |

# Conclusion

This lab has been a fantastic learning experience for me. I've set up Splunk Enterprise on Ubuntu, deployed Splunk forwarders, performed tests with Atomic Red Team, and analyzed results in Splunk following the MITRE ATT&CK framework. I also used Kali Linux to simulate a brute force attack and reviewed the outcome in Splunk.

Through setting all this up, I've sharpened my skills in virtualization with VirtualBox, general Windows and Linux processes and learned the essentials of setting up Active Directory on Windows Server.

I'm excited to keep building on this lab. My next steps include creating Splunk alerts, tweaking group policies, and just generally tinkering around in the domain environment. There's always more to learn, and I'm looking forward to it!
