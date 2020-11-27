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
