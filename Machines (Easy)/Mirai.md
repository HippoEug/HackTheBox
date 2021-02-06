# References
1. [Mirai Writeup (medium.com)](https://medium.com/@fularam.prajapati/hack-the-box-mirai-walkthrough-writeup-oscp-ca574732f0bf)

# Summary
### 1. NMAP

### 2. Port 80 HTTP Enumeration

# Attack
## 1. NMAP
Insert TEXT.. ?
```
hippoeug@kali:~$ nmap --script vuln 10.129.92.103 -sC -sV -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-06 18:06 +08
...
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
53/tcp   open  domain  dnsmasq 2.76
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    lighttpd 1.4.35
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: lighttpd/1.4.35
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
|   cpe:/a:lighttpd:lighttpd:1.4.35: 
|       CVE-2019-11072  7.5     https://vulners.com/cve/CVE-2019-11072
|       CVE-2018-19052  5.0     https://vulners.com/cve/CVE-2018-19052
|_      CVE-2015-3200   5.0     https://vulners.com/cve/CVE-2015-3200
1075/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Ha! How does combining both my old NMAP command lines together look? Anyways, 4 ports are opened. Port 22 SSH, Port 53 DNS, Port 80 HTTP, and Port 1075 UPNP.

Googling "UPNP", we see that it stands for "Universal Plug and Play". UPNP is a set of networking protocols that permits networked devices, such as personal computers, printers, Internet gateways, Wi-Fi access points and mobile devices to seamlessly discover each other's presence on the network and establish functional network services.

## 2. Port 80 HTTP Enumeration
Visiting `http://10.129.92.103:80`, the page loads successfully but it is just a blank white screen. Thinking it might be similar to [Bank](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Bank.md) exercise, we add it to our `/etc/hosts` file.
```
hippoeug@kali:~$ sudo nano /etc/hosts
[sudo] password for hippoeug: 
  GNU nano 4.9.3                                                                 /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.92.103 mirai.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
Visiting `http://mirai.htb` now, the page loads but we get an error message.
```
Website Blocked
Access to the following site has been blocked:
mirai.htb
If you have an ongoing use for this website, please ask the owner of the Pi-hole in your network to have it whitelisted.
This page is blocked because it is explicitly contained within the following block list(s):
Go back Whitelist this page Close window
Generated Sat 10:10 AM, Feb 06 by Pi-hole v3.1.4
```
At least this is progress! 

Time for some GoBuster!
```
hippoeug@kali:~$ gobuster dir -u "http://mirai.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://mirai.htb
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/06 18:37:59 Starting gobuster
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://mirai.htb/bc6ce6e8-e7f1-4d73-a4ac-a817a2ba5835 => 200. To force processing of Wildcard responses, specify the '--wildcard' switch
```
This didn't work. Weird. Let's not use the domain name, but the IP itself.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.92.103" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.92.103
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/06 18:44:36 Starting gobuster
===============================================================
/admin (Status: 301)
/versions (Status: 200)
===============================================================
2021/02/06 18:54:14 Finished
===============================================================
```
Interesting, two directories, `/admin` & `/versions`.

Let's visit `http://10.129.92.103/admin` first.
```
```
Next to `http://10.129.92.103/versions`.
