http://scx020c07c.blogspot.com/2012/09/exploitation-windows-xp-using.html

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


```
ippoeug@kali:~$ sudo nmap -p 445 --script=vuln 10.10.10.4 -v -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 22:48 +08
NSE: Loaded 105 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 22:48
Completed NSE at 22:48, 10.00s elapsed
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:48
Completed Parallel DNS resolution of 1 host. at 22:48, 0.03s elapsed
Initiating SYN Stealth Scan at 22:48
Scanning 10.10.10.4 [1 port]
Discovered open port 445/tcp on 10.10.10.4
Completed SYN Stealth Scan at 22:48, 0.04s elapsed (1 total ports)
NSE: Script scanning 10.10.10.4.
Initiating NSE at 22:48
Completed NSE at 22:49, 14.03s elapsed
Initiating NSE at 22:49
Completed NSE at 22:49, 0.00s elapsed
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
