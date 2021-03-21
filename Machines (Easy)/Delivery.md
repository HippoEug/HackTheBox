# References
1. [Delivery Writeup (drt.sh)](https://drt.sh/posts/htb-delivery/)

# Summary
### 1. NMAP

### 2. Port 80 HTTP Enumeration

### 3. X

# Attack
## 1. NMAP
Once upon a time...
```
hippoeug@kali:~$ nmap --script vuln 10.129.116.248 -sC -sV -Pn -v
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-21 12:00 +08
...
Scanning 10.129.116.248 [1000 ports]
Discovered open port 22/tcp on 10.129.116.248
Discovered open port 80/tcp on 10.129.116.248
...
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.9p1: 
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19    *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    *EXPLOIT*
|       EDB-ID:46516    5.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111
|       CVE-2019-16905  4.4     https://vulners.com/cve/CVE-2019-16905
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       EDB-ID:46193    0.0     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|_      1337DAY-ID-32009        0.0     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
80/tcp open  http    nginx 1.14.2
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.116.248
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.116.248:80/
|     Form id: demo-name
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /error/: Potentially interesting folder
|_http-server-header: nginx/1.14.2
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://www.tenable.com/plugins/nessus/55976
|       https://seclists.org/fulldisclosure/2011/Aug/175
|_      https://www.securityfocus.com/bid/49303
| vulners: 
|   nginx 1.14.2: 
|       CVE-2019-9513   7.8     https://vulners.com/cve/CVE-2019-9513
|       CVE-2019-9511   7.8     https://vulners.com/cve/CVE-2019-9511
|       CVE-2019-9516   6.8     https://vulners.com/cve/CVE-2019-9516
|_      CVE-2018-16845  5.8     https://vulners.com/cve/CVE-2018-16845
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

## 2. Port 80 HTTP Enumeration
Let's visit `10.129.116.248` first.
```
Delivery

The best place to get all your email related support
For an account check out our helpdesk

    Contact Us

© Untitled. Design: HTML5 UP.
```
Click on `helpdesk` redirects to `http://helpdesk.delivery.htb/`, which shows `Server Not Found` error.

Moving on, we click on `Contact Us` button.
```
Contact Us

For unregistered users, please use our HelpDesk to get in touch with our team. 
Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server.
```
Once again, clicking on `helpdesk` redirects to `http://helpdesk.delivery.htb/`, which shows `Server Not Found` error.

But we are also able to click on `MatterMost server`, which brings us to `http://delivery.htb:8065/`, which also shows `Server Not Found` error.

No sweat, easy fix as we seen on many machines now. Let's just add to our `/etc/hosts` file.
```
hippoeug@kali:~$ sudo nano /etc/hosts
[sudo] password for hippoeug: 
  GNU nano 5.4                                                                  /etc/hosts *
127.0.0.1       localhost
127.0.1.1       kali
10.129.116.248 delivery.htb      
10.129.116.248 helpdesk.delivery.htb 

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
With this added, we can now visit the 2 sites.

Visiting `http://helpdesk.delivery.htb/` first.
```
Guest User | Sign In

delivery

    Support Center Home Open a New Ticket Check Ticket Status 

Open a New Ticket

Check Ticket Status
Welcome to the Support Center

In order to streamline support requests and better serve you, we utilize a support ticket system. 
Every support request is assigned a unique ticket number which you can use to track the progress and responses online. 
For your reference we provide complete archives and history of all your support requests. 
A valid email address is required to submit a ticket.

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
Interesting, we are able to sign in or be a guest user, and then open a new ticket and check the ticket status after. 

We can see this Ticket Support system uses is powered by osTicket. Let's do a quick Searchsploit.
```
hippoeug@kali:~$ searchsploit osticket
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                      |  Path
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
osTicket - 'l.php?url' Arbitrary Site Redirect                                                                                      | php/webapps/38161.txt
osTicket - 'tickets.php?status' Cross-Site Scripting                                                                                | php/webapps/38162.txt
osTicket 1.10 - SQL Injection (PoC)                                                                                                 | php/webapps/42660.txt
osTicket 1.10.1 - Arbitrary File Upload                                                                                             | windows/webapps/45169.txt
osTicket 1.11 - Cross-Site Scripting / Local File Inclusion                                                                         | php/webapps/46753.txt
osTicket 1.12 - Formula Injection                                                                                                   | php/webapps/47225.txt
osTicket 1.12 - Persistent Cross-Site Scripting                                                                                     | php/webapps/47226.txt
osTicket 1.12 - Persistent Cross-Site Scripting via File Upload                                                                     | php/webapps/47224.txt
osTicket 1.14.1 - 'Saved Search' Persistent Cross-Site Scripting                                                                    | php/webapps/48525.txt
osTicket 1.14.1 - 'Ticket Queue' Persistent Cross-Site Scripting                                                                    | php/webapps/48524.txt
osTicket 1.14.1 - Persistent Authenticated Cross-Site Scripting                                                                     | php/webapps/48413.txt
osTicket 1.14.2 - SSRF                                                                                                              | php/webapps/49441.txt
osTicket 1.2/1.3 - 'view.php?inc' Arbitrary Local File Inclusion                                                                    | php/webapps/25926.txt
osTicket 1.2/1.3 - Multiple Input Validation / Remote Code Injection Vulnerabilities                                                | php/webapps/25590.txt
osTicket 1.2/1.3 Support Cards - 'view.php' Cross-Site Scripting                                                                    | php/webapps/29298.txt
osTicket 1.6 RC4 - Admin Login Blind SQL Injection                                                                                  | php/webapps/9032.txt
osTicket 1.6 RC5 - Multiple Vulnerabilities                                                                                         | php/webapps/11380.txt
osTicket 1.9.14 - 'X-Forwarded-For' Cross-Site Scripting                                                                            | php/webapps/40826.py
osTicket 1.x - 'Open_form.php' Remote File Inclusion                                                                                | php/webapps/27928.txt
osTicket STS 1.2 - Attachment Remote Command Execution                                                                              | php/webapps/24225.php
------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
However, we don't see any version numbers whatsoever from page source, so we don't have a clear target. Let's KIV this, we can try some of these exploits if we are stuck in the end.

Visiting `http://delivery.htb:8065/`, we get redirected to `http://delivery.htb:8065/login`.
```
Mattermost
All team communication in one place, searchable and accessible anywhere
Don't have an account? Create one now.
I forgot my password.
Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
Ah, a Mattermost login page. I've used Mattermost in my training before, it's just like another internal Discord server. We also do a quick Searchsploit.
```
hippoeug@kali:~$ searchsploit mattermost
Exploits: No Results
Shellcodes: No Results
```

Finally, if we don't see anything interesting we will Dirbuster this site.

## 3. Port 80 Helpdesk Enumeration
As we've seen earlier, let's revisit `http://helpdesk.delivery.htb/`.
```
Support Center Home Open a New Ticket Check Ticket Status 

Open a New Ticket
Check Ticket Status

Welcome to the Support Center

In order to streamline support requests and better serve you, we utilize a support ticket system. 
Every support request is assigned a unique ticket number which you can use to track the progress and responses online. 
For your reference we provide complete archives and history of all your support requests. 
A valid email address is required to submit a ticket.
```
Hmm, a valid email address is required to submit a ticket. Let's try submitting a ticket anyhow.
```
Open a New Ticket
Please fill in the form below to open a new ticket.

Contact Information
Email Address: alibaba@pizza.com
Full Name: Ali Baba
Phone Number: 98987676
Ext: 65
Help Topic: Contact Us

Ticket Details
Please Describe Your Issue

Issue Summary:
My pizza is not boneless
Read the title

Drop files here or choose them
linpeas.sh313kB

CAPTCHA Text: 	   Enter the text shown on the image: 6CD18
 

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
Filled this up, and it's interesting we can upload a file. Potentially, we could upload a reverse shell or something. Let's Create Ticket.
```
Support Center Home Open a New Ticket Check Ticket Status 

Support ticket request created

Ali Baba, 
You may check the status of your ticket, by navigating to the Check Status page using ticket id: 4009396.
If you want to add more information to your ticket, just email 4009396@delivery.htb.

Thanks,
Support Team

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
