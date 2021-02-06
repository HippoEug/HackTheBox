# References
1. [Block Writeup (x.com)]()

# Summary
### 1. NMAP

### 2. Enumeration on Port 80 HTTP

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
```
BlockyCraft
Under Construction!

Posts
Posted on July 2, 2017
Welcome to BlockyCraft!
Welcome everyone. The site and server are still under construction so don’t expect too much right now!
We are currently developing a wiki system for the server and a core plugin to track player stats and stuff. Lots of great stuff planned for the future 🙂

Search...

Recent Posts
    Welcome to BlockyCraft!
Recent Comments
Archives
    July 2017
Categories
    Uncategorized
Meta
    Log in
    Entries RSS
    Comments RSS
    WordPress.org

Proudly powered by WordPress
```
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
```
http://10.129.1.53/wiki/
-> Under Construction
Please check back later! We will start publishing wiki articles after we have finished the main server plugin!
The new core plugin will store your playtime and other information in our database, so you can see your own stats!

http://10.129.1.53/wp-content/
-> 

http://10.129.1.53/wp-content/uploads/
-> Index of /wp-content/uploads
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[DIR]	2017/	2017-07-02 19:43 	- 	 
Apache/2.4.18 (Ubuntu) Server at 10.129.1.53 Port 80

http://10.129.1.53/plugins/
-> files
    .jarBlockyCore.jar 883 Bytes
    .jargriefprevention-1.11.2-3.1.1.298.jar 520 KB
    
http://10.129.1.53/wp-includes/
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
[ ]	class-phpmailer.php	2017-01-11 01:23 	143K	 
[ ]	class-pop3.php	2016-10-31 06:28 	20K	 
[ ]	class-requests.php	2016-10-05 03:24 	29K	 
[ ]	class-simplepie.php	2016-06-06 03:24 	87K	 
[ ]	class-smtp.php	2017-01-11 01:23 	39K	 
[ ]	class-snoopy.php	2016-07-06 12:40 	37K	 
[ ]	class-walker-category-dropdown.php	2016-03-22 17:22 	2.1K	 
[ ]	class-walker-category.php	2016-05-22 18:50 	6.6K	 
[ ]	class-walker-comment.php	2016-08-23 23:33 	11K	 
[ ]	class-walker-nav-menu.php	2017-05-14 03:38 	8.2K	 
[ ]	class-walker-page-dropdown.php	2016-05-22 18:50 	2.3K	 
[ ]	class-walker-page.php	2017-05-01 23:32 	6.7K	 
[ ]	class-wp-admin-bar.php	2016-11-05 16:28 	16K	 
[ ]	class-wp-ajax-response.php	2016-08-23 14:33 	4.9K	 
[ ]	class-wp-comment-query.php	2016-12-07 15:52 	41K	 
[ ]	class-wp-comment.php	2017-01-26 16:53 	9.2K	 
[ ]	class-wp-customize-control.php	2017-05-19 20:25 	22K	 
[ ]	class-wp-customize-manager.php	2017-05-19 20:25 	146K	 
[ ]	class-wp-customize-nav-menus.php	2017-01-26 03:47 	48K	 
[ ]	class-wp-customize-panel.php	2017-04-07 19:27 	9.7K	 
[ ]	class-wp-customize-section.php	2016-10-19 18:15 	9.9K	 
[ ]	class-wp-customize-setting.php	2017-05-19 20:25 	28K	 
[ ]	class-wp-customize-widgets.php	2017-04-07 19:27 	66K	 
[ ]	class-wp-dependency.php	2016-08-26 18:06 	1.6K	 
[ ]	class-wp-editor.php	2017-05-31 22:04 	59K	 
[ ]	class-wp-embed.php	2016-08-26 09:53 	12K	 
[ ]	class-wp-error.php	2016-08-26 09:58 	4.6K	 
[ ]	class-wp-feed-cache-transient.php	2016-08-25 18:18 	2.6K	 
[ ]	class-wp-feed-cache.php	2016-08-25 18:18 	764 	 
[ ]	class-wp-hook.php	2016-12-02 07:10 	14K	 
[ ]	class-wp-http-cookie.php	2016-07-27 15:32 	6.4K	 
[ ]	class-wp-http-curl.php	2016-05-22 18:15 	11K	 
[ ]	class-wp-http-encoding.php	2016-06-10 04:50 	6.3K	 
[ ]	class-wp-http-ixr-client.php	2016-05-22 18:15 	3.2K	 
[ ]	class-wp-http-proxy.php	2016-05-22 18:15 	5.8K	 
[ ]	class-wp-http-requests-hooks.php	2017-02-17 05:06 	1.8K	 
[ ]	class-wp-http-requests-response.php	2016-10-05 03:51 	4.4K	 
[ ]	class-wp-http-response.php	2016-08-22 21:28 	3.0K	 
[ ]	class-wp-http-streams.php	2016-05-22 18:15 	15K	 
[ ]	class-wp-image-editor-gd.php	2016-07-08 14:37 	13K	 
[ ]	class-wp-image-editor-imagick.php	2017-02-27 04:22 	21K	 
[ ]	class-wp-image-editor.php	2016-08-20 23:36 	12K	 
[ ]	class-wp-list-util.php	2016-10-25 21:26 	6.3K	 
[ ]	class-wp-locale-switcher.php	2016-11-21 16:07 	5.0K	 
[ ]	class-wp-locale.php	2017-01-06 22:11 	14K	 
[ ]	class-wp-matchesmapregex.php	2016-08-26 18:11 	1.9K	 
[ ]	class-wp-meta-query.php	2016-10-10 06:38 	22K	 
[ ]	class-wp-metadata-lazyloader.php	2016-05-23 18:54 	5.4K	 
[ ]	class-wp-network-query.php	2016-10-21 02:54 	17K	 
[ ]	class-wp-network.php	2017-02-22 10:42 	10K	 
[ ]	class-wp-oembed-controller.php	2017-05-11 18:18 	5.2K	 
[ ]	class-wp-post-type.php	2017-03-18 15:17 	19K	 
[ ]	class-wp-post.php	2017-01-26 16:53 	5.7K	 
[ ]	class-wp-query.php	2017-02-23 10:30 	120K	 
[ ]	class-wp-rewrite.php	2016-10-07 19:44 	59K	 
[ ]	class-wp-role.php	2016-05-22 18:15 	2.7K	 
[ ]	class-wp-roles.php	2016-11-02 05:55 	6.4K	 
[ ]	class-wp-session-tokens.php	2017-01-04 13:22 	7.4K	 
[ ]	class-wp-simplepie-file.php	2016-08-25 18:18 	2.2K	 
[ ]	class-wp-simplepie-sanitize-kses.php	2016-08-25 18:18 	1.8K	 
[ ]	class-wp-site-query.php	2017-03-27 19:48 	23K	 
[ ]	class-wp-site.php	2017-04-19 18:52 	7.5K	 
[ ]	class-wp-tax-query.php	2017-01-02 19:40 	19K	 
[ ]	class-wp-taxonomy.php	2017-03-18 15:25 	10K	 
[ ]	class-wp-term-query.php	2017-03-16 02:04 	32K	 
[ ]	class-wp-term.php	2017-01-26 16:53 	5.3K	 
[ ]	class-wp-text-diff-renderer-inline.php	2016-08-25 17:37 	712 	 
[ ]	class-wp-text-diff-renderer-table.php	2016-08-25 17:37 	14K	 
[ ]	class-wp-theme.php	2017-03-18 03:54 	47K	 
[ ]	class-wp-user-meta-session-tokens.php	2016-08-25 17:44 	3.0K	 
[ ]	class-wp-user-query.php	2017-01-16 23:24 	29K	 
[ ]	class-wp-user.php	2017-01-06 22:09 	19K	 
[ ]	class-wp-walker.php	2017-01-06 22:14 	12K	 
[ ]	class-wp-widget-factory.php	2016-07-20 16:57 	3.8K	 
[ ]	class-wp-widget.php	2016-10-31 06:28 	18K	 
[ ]	class-wp-xmlrpc-server.php	2017-05-16 08:46 	195K	 
[ ]	class-wp.php	2016-10-25 20:48 	24K	 
[ ]	class.wp-dependencies.php	2016-08-26 18:06 	11K	 
[ ]	class.wp-scripts.php	2016-07-06 12:40 	14K	 
[ ]	class.wp-styles.php	2016-05-22 18:50 	9.9K	 
[ ]	comment-template.php	2017-05-14 03:50 	85K	 
[ ]	comment.php	2017-05-14 04:20 	100K	 
[ ]	compat.php	2016-08-10 16:10 	17K	 
[ ]	cron.php	2016-08-26 09:22 	16K	 
[DIR]	css/	2017-06-08 14:29 	- 	 
[DIR]	customize/	2017-06-08 14:29 	- 	 
[ ]	date.php	2017-01-04 13:26 	35K	 
[ ]	default-constants.php	2017-03-23 19:01 	9.2K	 
[ ]	default-filters.php	2017-05-18 14:34 	25K	 
[ ]	default-widgets.php	2017-05-11 21:11 	2.0K	 
[ ]	deprecated.php	2017-01-10 22:09 	109K	 
[ ]	embed-template.php	2016-07-06 12:40 	344 	 
[ ]	embed.php	2017-03-06 11:42 	43K	 
[ ]	feed-atom-comments.php	2016-12-16 06:39 	5.2K	 
[ ]	feed-atom.php	2016-12-16 06:39 	3.0K	 
[ ]	feed-rdf.php	2016-10-25 20:48 	2.6K	 
[ ]	feed-rss.php	2016-10-25 20:48 	1.2K	 
[ ]	feed-rss2-comments.php	2016-12-16 06:39 	4.0K	 
[ ]	feed-rss2.php	2016-12-16 06:42 	3.7K	 
[ ]	feed.php	2017-01-05 03:06 	19K	 
[DIR]	fonts/	2017-06-08 14:29 	- 	 
[ ]	formatting.php	2017-05-29 03:21 	186K	 
[ ]	functions.php	2017-04-09 22:44 	171K	 
[ ]	functions.wp-scripts.php	2016-10-18 20:05 	11K	 
[ ]	functions.wp-styles.php	2016-09-04 04:09 	7.9K	 
[ ]	general-template.php	2017-05-25 07:18 	123K	 
[ ]	http.php	2017-03-17 19:02 	22K	 
[DIR]	images/	2017-06-08 14:29 	- 	 
[DIR]	js/	2017-06-08 14:29 	- 	 
[ ]	kses.php	2017-05-11 19:23 	49K	 
[ ]	l10n.php	2017-04-01 14:26 	42K	 
[ ]	link-template.php	2016-12-27 09:28 	132K	 
[ ]	load.php	2017-05-11 19:54 	32K	 
[ ]	locale.php	2016-12-03 04:16 	141 	 
[ ]	media-template.php	2017-05-11 21:11 	45K	 
[ ]	media.php	2017-05-26 23:10 	135K	 
[ ]	meta.php	2017-05-10 06:10 	37K	 
[ ]	ms-blogs.php	2017-03-30 04:36 	37K	 
[ ]	ms-default-constants.php	2016-10-19 04:47 	4.6K	 
[ ]	ms-default-filters.php	2017-05-09 17:15 	4.5K	 
[ ]	ms-deprecated.php	2017-04-05 02:18 	14K	 
[ ]	ms-files.php	2016-09-27 20:05 	2.6K	 
[ ]	ms-functions.php	2017-05-10 23:22 	81K	 
[ ]	ms-load.php	2016-10-26 03:39 	19K	 
[ ]	ms-settings.php	2016-08-31 16:31 	3.3K	 
[ ]	nav-menu-template.php	2017-05-12 20:35 	20K	 
[ ]	nav-menu.php	2017-05-16 05:37 	32K	 
[ ]	option.php	2017-05-10 06:10 	63K	 
[ ]	pluggable-deprecated.php	2016-07-06 12:40 	6.1K	 
[ ]	pluggable.php	2017-05-07 16:54 	86K	 
[ ]	plugin.php	2016-09-12 01:50 	31K	 
[DIR]	pomo/	2017-06-08 14:29 	- 	 
[ ]	post-formats.php	2015-08-25 20:28 	6.8K	 
[ ]	post-template.php	2017-04-06 18:01 	57K	 
[ ]	post-thumbnail-template.php	2016-06-29 17:28 	7.9K	 
[ ]	post.php	2017-04-22 14:17 	207K	 
[ ]	query.php	2017-02-23 10:30 	23K	 
[DIR]	random_compat/	2017-06-08 14:29 	- 	 
[ ]	registration-functions.php	2016-07-06 12:40 	178 	 
[ ]	registration.php	2016-07-06 12:40 	178 	 
[ ]	rest-api.php	2017-05-25 18:02 	35K	 
[DIR]	rest-api/	2017-06-08 14:29 	- 	 
[ ]	revision.php	2016-11-09 23:00 	21K	 
[ ]	rewrite.php	2016-05-23 19:02 	17K	 
[ ]	rss-functions.php	2016-07-06 12:40 	191 	 
[ ]	rss.php	2016-10-31 06:28 	23K	 
[ ]	script-loader.php	2017-06-01 09:49 	68K	 
[ ]	session.php	2016-12-03 03:51 	242 	 
[ ]	shortcodes.php	2017-01-03 04:00 	20K	 
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

http://10.129.1.53/javascript/
-> Forbidden
You don't have permission to access /javascript/ on this server.
Apache/2.4.18 (Ubuntu) Server at 10.129.1.53 Port 80

http://10.129.1.53/wp-admin/
http://10.129.1.53/wp-login.php?redirect_to=http%3A%2F%2F10.129.1.53%2Fwp-admin%2F&reauth=1
-> Wordpress Login

http://10.129.1.53/phpmyadmin/
-> phpMyAdmin
Welcome to phpMyAdmin
Language
Log inDocumentation
Username:
Password:

http://10.129.1.53/server-status
-> Forbidden
You don't have permission to access /server-status on this server.
Apache/2.4.18 (Ubuntu) Server at 10.129.1.53 Port 80
```
That is quite a lot of things to go through. 
