# Summary
### 1. NMAP

https://or10nlabs.tech/hackthebox-optimum/
https://www.rapid7.com/db/modules/exploit/windows/http/rejetto_hfs_exec/
https://www.jdksec.com/hack-the-box/optimum

# Attack
## 1. NMAP
Business as usual.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.8 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 13:54 +08
...
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
...
```
Wow, only Port 80, a HttpFileServer is open.

Let's see another vulnerability NMAP script.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.8 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 14:01 +08
...
PORT   STATE SERVICE
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
|       http://capec.mitre.org/data/definitions/274.html
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|_      http://www.mkit.com.ar/labs/htexploit/
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  BID:49303  CVE:CVE-2011-3192
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://seclists.org/fulldisclosure/2011/Aug/175
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://www.tenable.com/plugins/nessus/55976
...
```
Wow, a couple of vulnerabilities it seems. but mainly for DoS. Let's take a quick look at `http-method-tamper` links and try something.
```
hippoeug@kali:~$ nmap -p 80 --script http-methods 10.10.10.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-03 14:37 +08
...
PORT   STATE SERVICE
80/tcp open  http
| http-methods: 
|_  Supported Methods: GET HEAD POST
```
Hmm, nothing interesting AFAIK. Testing another..
```
hippoeug@kali:~$ nc 10.10.10.8 80

```
No response from netcat attempt.

Let's KIV those and move on to a little more enumeration.

## 2. Enumeration: Searchsploit & Dirbuster
Let's run some searchsploit and see what we get.
```
hippoeug@kali:~$ searchsploit httpfileserver
Exploits: No Results
Shellcodes: No Results
```
No results, next.

What about `httpd 2.3`?
```
hippoeug@kali:~$ searchsploit httpd 2.3
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenBSD HTTPd < 6.0 - Memory Exhaustion Denial of Service                                                                           | openbsd/dos/41278.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Ah, DoS, not very useful. Next.

What about the header `HFS 2.3`?
```
hippoeug@kali:~$ searchsploit hfs 2.3
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                         | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                      | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                 | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                 | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                            | windows/webapps/34852.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Wow, looks like quite a few things!

Let's see Dirbuster!
```
hippoeug@kali:~$ dirbuster
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Jan 03, 2021 2:17:11 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
Jan 03, 2021 2:17:11 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
ERROR: http://10.10.10.8:80/home.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/2005.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/sitemap.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/archives.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/support.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/keygen.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/index/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/04.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/crack/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/archive.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Dir found: / - 200
ERROR: http://10.10.10.8:80/register.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:12 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r45,c3,p1451) contains a '/' character before the closing '>', which is ignored because tags of this name cannot be empty-element tags
ERROR: http://10.10.10.8:80/new/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/press.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/media.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/16.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/sitemap/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/docs.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:12 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag at (r9,c5,p361) missing required end tag - invalid nested start tag encountered before end tag
ERROR: http://10.10.10.8:80/08/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/22.php - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
ERROR: http://10.10.10.8:80/articles/ - IOException The server 10.10.10.8 failed to respond with a valid HTTP response
Jan 03, 2021 2:17:16 PM org.apache.commons.httpclient.HttpMethodBase readResponseBody
INFO: Response content length is not known
```
What's this! Content length not known?!

## 3. 
