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
hippoeug@kali:~$ gobuster dir -u "https://10.10.10.7:10000" -w /usr/share/wordlists/dirbuster/directory-lis
...
Error: error on running goubster: unable to connect to https://10.10.10.7:10000/: invalid certificate: x509: cannot validate certificate for 10.10.10.7 because it doesn't contain any IP SANs
...
hippoeug@kali:~$ gobuster dir -u "https://10.10.10.7" -w /usr/share/wordlists/dirbuster/directory-lis
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

We try both Metasploit modules, [first being `use exploit/unix/webapp/webmin_upload_exec`](https://www.rapid7.com/db/modules/exploit/unix/webapp/webmin_upload_exec/) of `Webmin Upload Authenticated RCE`, and [second being `use exploit/linux/http/webmin_packageup_rce`](https://www.rapid7.com/db/modules/exploit/linux/http/webmin_packageup_rce/) of `Webmin Package Updates Remote Command Execution`. However, both modules required credentials to the Webmin, USERNAME & PASSWORD.

To go down this path, we must get the some credentials.
