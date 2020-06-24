# TAC-BOX ToolKit

This repo and guide will remain a open repo/document for continuous improvement, and will be used to 
assist with learning and competing in CTF challenges to improve our cyber skillset.

## Tool Kit:
    
## Operating System:
        
### Parrot Security OS:

The Operating System we will be using for hacking/red teaming/pentesting is [Parrot Security OS](https://www.parrotsec.org/download/)
and can be downloaded at https://download.parrot.sh/parrot/iso/4.9.1/Parrot-security-4.9.1_x64.iso. 
The download link provides the standard .iso image that will be installed on your hypervisor (VirtualBox, 
VM Ware Player, VM Ware Workstation) of choice. Here are the [System Requirements](https://www.parrotsec.org/docs/info/system-requirements/),
and [The installation process through the installer](https://www.parrotsec.org/docs/getting-started/install-debian/). Also, this walks you through [Installing ParrotOS in Virtual Box](https://ojoiszy.com/install-parrot-security-os-virtualbox/) and [Installing ParrotOS in VMWare](https://www.hackercoolmagazine.com/install-parrot-security-os-vmware/).
There is a Parrot Security OVA (Open Virtual Appliance) virtual machine image. However, through personal experience 
this tends to be broken/built for a specific hypervisor. Once the .iso has been downloaded and installed on your hypervisor 
you will need to install either VirtualBox Guest Additions or open-vm-tools.

**Installing VirtualBox Guest Additions on ParrotSecOS:**

1.	On the Virtual Machine menu bar, select Devices > Insert Guest Additions CD image…
2.	Login as root by using sudo su, and enter your current user password
3.	Enter the CDROM directory by using ```cd /media/cdrom0/``` (if there isn’t anything in this directory, 
open places > home, on the left side under devices click VBOX_GAs_#.#.#, close the window, then continue)
4.	Make a directory to move these files to with ```sudo mkdir /opt/vbox_ga```
5.	Copy the Guest Additions file to “/opt/vbox_ga” directory with ```cp -r * /opt/vbox_ga```
6.	Enter the “/opt/vbox_ga” directory with ```cd /opt/vbox_ga```
7.	Give the permission for execute “+x” to “VBoxLinuxAdditions.run” by using ```sudo chmod +x VBoxLinuxAdditions.run```
8.	Execute “VBoxLinuxAdditions.run” with ```sudo  ./VBoxLinuxAdditions.run```
9.	After installation completed, reboot the virtual machine with ```sudo reboot```

**Installing VMWare Open-VM-Tools on ParrotSecOS:**

1.	```sudo apt-get update```
2.	```sudo apt-get install open-vm-tools-desktop``` (if this throws an error use sudo apt-get install open-vm-tools)
3.	After installation completed, reboot the virtual machine with ```sudo reboot```

### SANS SIFT Workstation:

The Operating System we will be using for forensics is the SANS SIFT Worksation and can be downloaded at 
https://digital-forensics.sans.org/community/download-sift-kit/3.0. The download link provides the standard
.ova image that will be imported on your hypervisor (VirtualBox, VM Ware Player, VM Ware Workstation) of choice. 

**Importing a .ova into VitrualBox:**

1.	On the VirtualBox menu bar, select File > Import Appliance
2.	A new window will popup asking for the location of the .ova file. 
3.	Click the folder/arrow icon on the right of the input box and select SIFT-Workstation.ova
4.	The next window will be “Appliance Settings”, change these to meet your needs.
5.	The click the “Import” button at the bottom right of the window.

**Importing a .ova into VMWare:**

1.	In Workstation Player, select File > Open a Virtual Machine. 
2.	Browse to the .ova file and click Open. 
3.	Type a name for the virtual machine, type or browse to the directory for the virtual machine files and click Import. 
4.	If the import fails, click Retry to try again, or click Cancel to cancel the import. 
5.	Once Imported click on the virtual machine name to open it.
6.	Then click “Edit virtual machine settings” and change these to meet your needs.

**Once the .ova has been downloaded and imported into your hypervisor you will need to install either VirtualBox Guest Additions or open-vm-tools.** 

**Installing VirtualBox Guest Additions on ParrotSecOS:**

1.	On the Virtual Machine menu bar, select Devices > Insert Guest Additions CD image…
2.	Login as root by using sudo su, and enter your current user password
3.	Enter the CDROM directory by using cd /media/cdrom0/ (if there isn’t anything in this directory, 
open places > home, on the left side under devices click VBOX_GAs_#.#.#, close the window, then continue)
4.	Make a directory to move these files to with sudo mkdir /opt/vbox_ga
5.	Copy the Guest Additions file to “/opt/vbox_ga” directory with ```cp -r * /opt/vbox_ga```
6.	Enter the “/opt/vbox_ga” directory with ```cd /opt/vbox_ga```
7.	Give the permission for execute “+x” to “VBoxLinuxAdditions.run” by using ```sudo chmod +x VBoxLinuxAdditions.run```
8.	Execute “VBoxLinuxAdditions.run” with ```sudo  ./VBoxLinuxAdditions.run```
9.	After installation completed, reboot the virtual machine with ```sudo reboot```

**Installing VMWare Open-VM-Tools on ParrotSecOS:**

1.	```sudo apt-get update```
2.	```sudo apt-get install open-vm-tools-desktop``` (if this throws an error use sudo apt-get install open-vm-tools)
3.	After installation completed, reboot the virtual machine with ```sudo reboot```

# Additional Tools:

**LinEnum** – BASH shell script for linux enumeration - https://github.com/rebootuser/LinEnum

**PowerShell Empire** -  post-exploitation agent / C2 framework using powershell - https://www.powershellempire.com/

**Skiptracer** -  CLI OSINT Tool (Gives you a place to start when you have very little information.) - https://github.com/xillwillx/skiptracer

**OpenVAS** – vulnerability scanner - https://www.ceos3c.com/hacking/install-openvas-parrotsec/

**Nessus** – Vulnerability Scanner (Free version but limited) - https://www.tenable.com/products/nessus/nessus-essentials

**Veil-Evasion** - Veil-Evasion is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. - https://github.com/Veil-Framework/Veil-Evasion

**Crack Station** – online hash cracker that supports LM, NTLM, md2, md4, md5, md5(md5_hex), md5-half, sha1, sha224, sha256, sha384, sha512, ripeMD160, whirlpool, MySQL 4.1+ (sha1(sha1_bin)), QubesV3.1BackupDefaults (also pretty fast) - https://crackstation.net/

**CyberChef** – Open Source Data Analysis Tool - https://gchq.github.io/CyberChef/

**CVE Details** – vulnerability research (used for information gathering and assists with exploitation) - https://www.cvedetails.com/

**ExploitDB / searchsploit** - vulnerability research (can be installed on ParrotSecOS using ```sudo apt-get install exploitdb```, syntax is ```searchsploit “search criteria”```(used for information gathering and assists with exploitation))  - https://www.exploit-db.com/

 
## Additional Resources:

### Guides and Info:

**CTF Cheat Sheet** - https://raw.githubusercontent.com/175ME1/CTF-Guide/master/cheat%20sheets/CTF-CheatSheet?token=ANFE4SFYP2LQWBZEFQWSHZK66EEXY

**Basic Dot Files** - https://github.com/175ME1/CTF-Guide/tree/master/dotfiles

https://pequalsnp-team.github.io/cheatsheet/writing-good-writeup

https://ryankozak.com/how-i-do-my-ctf-writeups/

https://apsdehal.in/awesome-ctf/

https://ctfs.github.io/resources/

https://www.hoppersroppers.org/courseCTF.html

https://trailofbits.github.io/ctf/

https://github.com/zardus/ctf-tools

https://captf.com/practice-ctf/

https://www.reddit.com/r/securityCTF/


## CTF Legend

## URL                              |   Abbreviation

https://tryhackme.com               |   (THM)

https://cryptohack.org/             |   (CPH)

https://nationalcyberleague.org/    |   (NCL)

https://picoctf.com/                |   (pico)

https://www.hackthebox.eu/          |   (HTB)

## CTF Schedule:

## Dates            |    CTF
                    
June 21 - 27        |   [Learn Linux (THM) ](https://tryhackme.com/room/zthlinux)        

June 28 - July 4    |   [RP: NMAP (THM)](https://tryhackme.com/room/rpnmap)

July 5 - 11         |   [Basic Pentesting (THM)](https://tryhackme.com/room/basicpentestingjt) **Note:** Use the CTF Cheat Cheet (Additional Resources > Guides > CTF CheatSheet) to help with the additional tools needed for this CTF.

July 16 - 17        |   [SANS CTF (SANS)](https://www.sans.org/blog/and-now-for-something-awesome-sans-launches-new-series-of-worldwide-capture-the-flag-cyber-events/) **Note:** SANS Community CTF -  Free SANS Account Needed - Registration opens July 13 (Use the link)

On Your Own         |   [Introductory Researching (THM)](https://tryhackme.com/room/introtoresearch)

On Your Own         |   [Google Dorking (THM)](https://tryhackme.com/room/googledorking)

On Your Own         |   [Shodan.io (THM)](https://tryhackme.com/room/shodan)

On Your Own         |   [OhSint (THM)](https://tryhackme.com/room/ohsint)

On Your Own         |   [BP: Networking (THM)](https://tryhackme.com/room/bpnetworking)

On Your Own         |   [Networking Services (THM)](https://tryhackme.com/room/networkservices)

On Your Own         |   [The Find Command (THM)](https://tryhackme.com/room/thefindcommand)

## CTF Challenges:

## General 

### Linux

Learn Linux (THM)

Linux Challenges (THM)

### Toolbox

RP: NMAP (THM)

RP: Metasploit (THM)

Hydra (THM)

Learn Burp Suite (THM)

RP: Nessus (THM)

BP: Splunk (THM)

BP: Volatility (THM)

RP: Sublist3r (THM)

CC: Ghidra (THM)

CC: Radare2 (THM)

Toolbox: Vim (THM)

Wireshark 0x01 (THM)

The Find Command (THM)

### Information Gathering

Introductory Researching (THM)

Google Dorking (THM)

Shodan.io (THM)

OhSint (THM)

### Network

Introductory Networking (THM)

BP: Networking (THM)

Networking Services (THM)

### Scripting

Scripting (THM)

Intro to Python (THM)

## OCO

Blue (THM)

RP: Web Scanning (THM)

Cross Site Scripting (THM)

WebAppSec 101 (THM)

CC: Pentesting (THM)

Wifi Hacking 101 (THM)

Phishing: HiddenEye (THM)

Vulnversity (THM)

Basic Pentesting (THM)

Common Linux Privesc (THM)

Android Hacking 101 (THM)

Crack the Hash (THM)

Attacktive Directory (THM)

Custom Wordlists (THM)

Web Fundamentals (THM)

## DCO

Easy Steganography (THM)

Basic Steganography (THM)

CC: Steganography (THM)

Wireshark CTFs (THM)

MAL: Malware Introductory (THM)

Basic Malware RE (THM)

MAL: Strings (THM)

MAL: REMnux (THM)

Investigating Windows (THM)

## Other CTF Sites:

http://ctf.infosecinstitute.com/

https://legitbs.net/

https://picoctf.com/

http://ghostintheshellcode.com/

https://www.rootcon.org/

https://hsctf.com/

https://ictf.cs.ucsb.edu/

http://smashthestack.org/

https://microcorruption.com/login

https://def.camp/competitions/defcamp-capture-the-flag-d-ctf-2019-at-the-hacking-village/

https://ctf2019.hitcon.org/

https://ctftime.org/

https://www.vulnhub.com/

https://ctf.redpwn.net/
