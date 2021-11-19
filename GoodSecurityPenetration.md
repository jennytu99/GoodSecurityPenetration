### High-Level Summary 
GoodSecurity was tasked with performing an internal penetration test on GoodCorp’s CEO, Hans Gruber. An internal penetration test is a dedicated attack against internally connected systems. The goal of this test is to perform attacks similar to those of a hacker and attempt to infiltrate Hans’ computer to determine if it is at risk. GoodSecurity’s overall objective was to exploit any vulnerable software, find a secret recipe file on Hans’ computer, and report the findings back to GoodCorp. 
The internal penetration test found several alarming vulnerabilities on Hans’ computer: When performing the attacks, GoodSecurity was able to gain access to his machine and find the secret recipe file by exploiting two programs with major vulnerabilities. The details of the attack are below. 
 
### Findings 
## Machine IP: 192.168.0.20 
## Hostname: DVWA10 
## Vulnerability Exploited: CVE-2004-1561, Icecast 2.0.1 
CVE’s other known as Common Vulnerability Exposures are a list of entries—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities. CVE Entries are used in numerous cybersecurity products and services from around the world, including the U.S. National Vulnerability Database (NVD). 1 
 
### Vulnerability Explanation: 
Icecast is a streaming server, which can stream audio (and video) to listeners/viewers. Due to this specific Icecast version 2.0.1 that is being used on CEO Hans’ machine, it runs on an open port 8000. Port 8000 is commonly used for online radio streams; however, it can also be used as an alternate HTTP port. Because of the HTTP port alternative, it allows attackers to execute arbitrary code via an HTTP request with a large number of headers. Which creates a buffer overflow, and enables remote control of the system and ease of attackers to run commands as administrator. Buffer overflow attacks are when a program attempts to put more data in a buffer than it can hold or when a program attempts to put data in a memory area past a buffer. In this case, a buffer is a sequential section of memory allocated to contain anything from a character string to an array of integers. Writing outside the bounds of a block of allocated memory can corrupt data, crash the program, or cause the execution of malicious code and further install a root-kit which will enable attackers to access the machine at any time while going unnoticed.  
 
## Severity: HIGH, CVSS Score 7.5/10 

  
According to CVSS v2.0 Ratings, CVE-2004-1561, Icecast 2.0.1 vulnerability scores a 7.5 out of 10. The Common Vulnerability Scoring System (CVSS) is an open framework for communicating the characteristics and severity of software vulnerabilities.2 
 
This vulnerability will not only affect Hans Gruber, it will also severely impact GoodCorp’s confidentiality, integrity, and availability. There is a considerable number of possibilities but not limited to the following: 
Informational disclosures such as Personal Identification Information (PII), access and risk of modification to sensitive company data. 
Modification and downloading of internal system files   
Performance and availability of services interruptions 
 
### Tools used During Test: 
Testing Platform: Kali Linux 
NMAP for port scanning 
SearchSploit 
Metasploit: Msfconsole, Meterpreter 
 
## Proof of Concept: 
Below are the steps that were taken to exploit Icecast v2.01 and can be easily replicated: 
 
For this assessment, Kali was used as the penetration testing box. Since the target machine’s IP was provided, an NMAP scan was done to reveal open ports on IP 192.168.0.20. Refer to Figure 1  
 
Figure 1 – Open port information gathering, reveals open ports 
 
With the knowledge of the open ports, I can narrow down specific Icecast exploits by using Searchsploit.   
 
    Run searchsploit Icecast 
 
To reveal available Icecast exploits in the terminal of Kali, Figure 2 
 

Figure 2 - List of available Icecast exploits 
 
 
With the available exploits in hand, I can now create a payload using Metasploit. First, in the Kali terminal: 
 
    Run msfconsole  
    Type search Icecast in the terminal 
 
This will display the available exploits, shown in Figure 3.  
 
    Type Use exploit/windows/http/icecast_header 
 
Figure 3 – Once in the msfconsole, searching for Icecast will display the available modules 
 
Before executing the exploit the payload, the RHOST, remote host, is set to IP 192.168.0.20, as shown in Figure4.  
 
 
Figure 4 – Setting RHOSTS to 192.168.0.20 
 
    Type exploit or run 
 
 
Figure 5 – Using the Icecast exploit module 
 

Once the payload has successfully run and a Meterpreter session has open, it is now possible to search, view, and manipulate system files on CEO Hans Gruber’s machine. The Meterpreter session allows for a shell to open, and I am able to search for a file named secretfile.txt and also download the secret recipe from Hans’ machine. Seen in Figure 6,7.
Further enumeration of the operating system was possible as seen in Figure 8. 
 
Figure 6 - Searching for secrefile.txt
 
Figure 7 – Download secret recipe file from the target machine 
 
Figure 8 – Enumerating system information through the Meterpreter session 
 
Recommendations 

##### IMMEDIATELY:  
Patch and update Icecast to the latest version available 
Closing port 8000 
Put up a IDS or IPS & antivirus software that is kept up to date 
Do not run Icecast or any application as system administrator. Local administrator account should be used for administration purposes. 
 
OPTIONAL: 
Not using Icecast as a service in general at GoodCorp.  
Rebuild from the OS up to eradicate all possible exploits 

