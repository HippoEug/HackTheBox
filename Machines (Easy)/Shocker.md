# Summary
### 1. NMAP
x

### 2. Port 80 HTTP Enumeration
x

### 3. Privilege Escalation
x

# Attack
## 1. NMAP
Damn, it's been long since I did a new HTB. Let's begin.
```
hippoeug@kali:~$ nmap 10.129.1.175 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 22:12 +08
...
Scanning 10.129.1.175 [1000 ports]
Discovered open port 80/tcp on 10.129.1.175
Increasing send delay for 10.129.1.175 from 0 to 5 due to max_successful_tryno increase to 4
Discovered open port 2222/tcp on 10.129.1.175
...
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)                                                                                                        
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
2 ports, not much to enumerate, nice.

And a quick vulnerability script.
```
hippoeug@kali:~$ nmap --script vuln 10.129.1.175 -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 22:14 +08
...
Scanning 10.129.1.175 [1000 ports]
Discovered open port 80/tcp on 10.129.1.175
Increasing send delay for 10.129.1.175 from 0 to 5 due to 13 out of 43 dropped probes since last increase.
Discovered open port 2222/tcp on 10.129.1.175
...
PORT     STATE SERVICE
80/tcp   open  http
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
2222/tcp open  EtherNetIP-1
...
```
Nothing from this.

## 2. Port 80 HTTP Enumeration
Let's do a quick visit to `http://10.129.1.175`.

![Port80](https://user-images.githubusercontent.com/21957042/116421006-0f83d180-a871-11eb-94d0-0c8e2ef62494.png)

Hmm, nothing much on this page. Surely there must be more things here. Let's look at Gobuster.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.1.175" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.1.175
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/04/28 22:24:40 Starting gobuster
===============================================================
/server-status (Status: 403)
===============================================================
2021/04/28 22:36:09 Finished
===============================================================
hippoeug@kali:~$ 
```
What?! Only `/server-status`? Nevertheless, let's take a look at it.

![ServerStatus](https://user-images.githubusercontent.com/21957042/116423255-1a3f6600-a873-11eb-9acd-62ea260ef40b.png)

Forbidden. Hmm. 

As it turns out, our Gobuster did not append a slash at the back of the directory searches.

EXPLAIN HERE.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.1.175:80" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -f
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.1.175:80
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Add Slash:      true
[+] Timeout:        10s
===============================================================
2021/04/29 07:10:08 Starting gobuster
===============================================================
/cgi-bin/ (Status: 403)
/icons/ (Status: 403)
/server-status/ (Status: 403)
===============================================================
2021/04/29 07:21:40 Finished
===============================================================
hippoeug@kali:~$ 
```
