# References
1. [Grandpa Writeup (x.com)]()
2. [Grandpa Writeup (x.com)]()

# Summary
### 1. NMAP

### 2. X

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
