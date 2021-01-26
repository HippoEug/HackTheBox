# References
1. [Bank Writeup (x.com)]()
2. [Bank Writeup (x.com)]()

# Summary
### 1. NMAP

### 2. Enumeration

# Attack
## 1. NMAP
This machine sounds fun. Let's go.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.29 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-26 22:42 +08
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain?
80/tcp open  http    Apache/2.4.7 (Ubuntu)
|_http-server-header: Apache/2.4.7 (Ubuntu)                                                                                                                           
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Ooh, a Linux machine. SSH, mystery port, and HTTP!

Let's do the obligatory vuln script too.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.29 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-26 22:44 +08
...
PORT   STATE SERVICE
22/tcp open  ssh
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
53/tcp open  domain
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
...
```

### 2. Enumeration
Let's visit the webpage. Navigating to `http://10.10.10.29:80` on our browser, we see the Apache2 Ubuntu Default Page.

We can do Dirbuster if we do not find anything else. Time to find exploits!
```
searchsploit apache 2.4.7
```
