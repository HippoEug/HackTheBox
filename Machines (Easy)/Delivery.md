# References
1. [Delivery Writeup (drt.sh)](https://drt.sh/posts/htb-delivery/)
2. [Delivery Writeup (medium.com)](https://psychovik.medium.com/htb-delivery-walk-through-a2cdd4e3f9cb)
3. [Delivery Writeup (dylanpoelstra.nl)](https://dylanpoelstra.nl/delivery.html)

# Summary
### 1. NMAP

### 2. Port 80 HTTP Enumeration

### 3. Port 80 Helpdesk Enumeration

### 4. Port 8065 MatterMost Enumeration

### 5. Discovering MatterMost

### 6. SSH with Credentials

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
Okay cool, Linux machine running Port 22 SSH and Port 80 HTTP. Lots of other stuff which we're just gonna ignore for now.

## 2. Port 80 HTTP Enumeration
Let's visit `10.129.116.248` first.

![10 129 123 240](https://user-images.githubusercontent.com/21957042/113474520-09cde280-94a3-11eb-80f0-27be3d5d401e.png)

Clicking on `helpdesk` redirects to `http://helpdesk.delivery.htb/`, which shows `Server Not Found` error.

Moving on, we click on `Contact Us` button.

![Contact Us](https://user-images.githubusercontent.com/21957042/113474525-0b97a600-94a3-11eb-8afe-b9a99974cd2f.png)

Once again, clicking on `helpdesk` redirects to `http://helpdesk.delivery.htb/`, which shows `Server Not Found` error. But we are also able to click on `MatterMost server`, which brings us to `http://delivery.htb:8065/`, which also shows `Server Not Found` error. At least now we know there's Port 8065 also, which NMAP did not get to scan.

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

![helpdesk delivery htb](https://user-images.githubusercontent.com/21957042/113474526-0cc8d300-94a3-11eb-93ff-091d198b85f5.png)

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

![Mattermost](https://user-images.githubusercontent.com/21957042/113477915-085ae500-94b8-11eb-82ca-0cb6dd6361fb.png)

Ah, turns out Port 8065 is running MatterMost, and we are on the login page. I've used MatterMost in my training before, it's just like another internal Discord server. We also do a quick Searchsploit.
```
hippoeug@kali:~$ searchsploit mattermost
Exploits: No Results
Shellcodes: No Results
```

Finally, if we don't see anything interesting we will Dirbuster this site.

## 3. Port 80 Helpdesk Enumeration
As we've seen earlier, let's revisit `http://helpdesk.delivery.htb/`.

![Support Center](https://user-images.githubusercontent.com/21957042/113477917-08f37b80-94b8-11eb-8207-4c46c8f1ead8.png)

Hmm, a valid email address is required to submit a ticket. Let's try submitting a ticket anyhow.

![OpenTicket](https://user-images.githubusercontent.com/21957042/113477916-08f37b80-94b8-11eb-8cbf-4ebd0df1f202.png)

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

![Ticket Created](https://user-images.githubusercontent.com/21957042/113478281-8a4c0d80-94ba-11eb-8d05-35906ce074ee.png)

Cool! We got a email now, `40314246@delivery.htb` and our ticket id is `4031424`.

What can we do now? Maybe we can check the status of our ticket we just created.

![Access Denied](https://user-images.githubusercontent.com/21957042/113478278-87e9b380-94ba-11eb-8922-d4da78fce25d.png)

Entering the Email Address we just got as well as a Ticket Number, we got an error `Access denied`. Hmm.

As it turns out, those were the wrong credentials. We needed to enter our original Email Address used in the ticket, which was `alibaba@pizza.com`. We will fix this issue below.

## 4. Port 8065 MatterMost Enumeration
Let's move on first. From the Contact Us botton earlier, we see the interesting message.
```
Contact Us

For unregistered users, please use our HelpDesk to get in touch with our team. 
Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server.
```
With the `@delivery.htb` email address, we would be able to access the MatterMost server, theoretically.

We cannot sign in, because we do not have a MatterMost account.

![No Password](https://user-images.githubusercontent.com/21957042/113478280-89b37700-94ba-11eb-9cb7-5eba24867f6f.png)

We don't have a password.

Let's create an account then.

![Create Account](https://user-images.githubusercontent.com/21957042/113478279-891ae080-94ba-11eb-9ee2-76782ff26bc0.png)

```
Mattermost
All team communication in one place, searchable and accessible anywhere

Let's create your account
Already have an account? Click here to sign in.

What's your email address?: 4031424@delivery.htb
Valid email required for sign-up
Choose your username: delivery
You can use lowercase letters, numbers, periods, dashes, and underscores.
Choose your password: Delivery69!

By proceeding to create your account and use Mattermost, you agree to our Terms of Service and Privacy Policy. If you do not agree, you cannot use Mattermost.

Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
And finally a verification email.

![Verificiation Email](https://user-images.githubusercontent.com/21957042/113478282-8ae4a400-94ba-11eb-8831-c1592992c835.png)

How are we going to access the email `40314246@delivery.htb` to verify?

## 5. Discovering MatterMost
Here is where I got stuck again and had to get some clues. Quoting my reference from drt.sh (link above), "This is very common of ticketing systems. Allowing the customer to reply directly to an email, and it will show up in the Customer Service Portal.". There, we need to go to the Customer Service Portal, which is we can find in the `Check Ticket Status` page.

We go back to checking the status of our ticket we created. This time, we use our original `@pizza.com` email address, not the `@delivery.htb` one that was provided. That was why our first attempt did not work.

![View Ticket](https://user-images.githubusercontent.com/21957042/113479299-d306c500-94c0-11eb-9f5a-075a9f5fa747.png)

Let's click `View Ticket`, and see what we get.

![View Ticket 2](https://user-images.githubusercontent.com/21957042/113479301-d306c500-94c0-11eb-8b48-9812065abd32.png)

Fantastic! Now all we do is go to the verification link `http://delivery.htb:8065/do_verify_email?token=sowizixm4iuikchfpddpu45pm7f4yqe3k8m3nj4r8iixjp3or7f3d4g7b8swqzx5&email=4031424%40delivery.htb`.

Let's create an account.

![Mattermost](https://user-images.githubusercontent.com/21957042/113479296-d1d59800-94c0-11eb-97ff-5c884d942be4.png)

Okay, great. Few more buttons to click.

![Teams Join](https://user-images.githubusercontent.com/21957042/113479298-d26e2e80-94c0-11eb-8834-cd3e8eeb6313.png)

Let's join Internal team.

We can read the chat.

![Chat Messages](https://user-images.githubusercontent.com/21957042/113479295-d13d0180-94c0-11eb-8b1b-ac5bc0552b18.png)

Interesting.. user `root` mentioned credentials, `Credentials to the server are maildeliverer:Youve_G0t_Mail!`. So username `maildeliverer` and password `Youve_G0t_Mail!`?

Extra information which isn't required, the Support Center Ticket System login page `http://helpdesk.delivery.htb/login.php` has an option for `I'm an agent - sign in here`.
Using the credentials username `maildeliverer` and password `Youve_G0t_Mail!` on the osTicket Log In page at `helpdesk.delivery.htb/scp/login.php`, were able to sign in successfully.

Under the dashboard, we see a total of 7 Open tickets, and one of which is the ticket which we created, `My pizza is not boneless`.

![AdminProfile](https://user-images.githubusercontent.com/21957042/113479294-d0a46b00-94c0-11eb-8954-eeb3eec81a8f.png)
![7Tickets](https://user-images.githubusercontent.com/21957042/113479291-cf733e00-94c0-11eb-80c7-e464b98bfd82.png)

Going through each of these tickets, we find various Mattermost verification email links.
```
http://delivery.htb:8065/do_verify_email?token=a5k53o185tdu7pb93gfgwr9umfsn1fcsn5xwwzibpez8hr8khj3sruguxjogqpcm&email=7466068%40delivery.htb
http://delivery.htb:8065/do_verify_email?token=yu1wegyh8ua7ehk3a1eg56bmd471c6nwo3qy5hkarow6y5kp97x6iw6oodoko37w&email=9122359%40delivery.htb
http://delivery.htb:8065/do_verify_email?token=8mj7g7ey59a9wrgfxd9a1jfnoqa7rezbeexhgc4mywckeeze77ibb179qeisigjd&email=4120849%40delivery.htb
http://delivery.htb:8065/do_verify_email?token=sxjww9mxbokgr1fqu63iqitkiodimputhe9gi6zmhn7mhd3tyksub4zxiiukdef9&email=5056505%40delivery.htb
```
However, these links are all expired with the message `The invite link was invalid. Please speak with your Administrator to receive an invitation.`.

Additionally, we take a look around this admin page, and under settings we see the version `System Settings and Preferences — osTicket (v1.15.1)`.

## 6. SSH with Credentials
With credentials username `maildeliverer` and password `Youve_G0t_Mail!`, we were not able to access Mattermost or an existing View Ticket Thread. That only leaves us with SSH.
```
hippoeug@kali:~$ ssh maildeliverer@10.129.116.248
The authenticity of host '10.129.116.248 (10.129.116.248)' can't be established.
ECDSA key fingerprint is SHA256:LKngIDlEjP2k8M7IAUkAoFgY/MbVVbMqvrFA6CUrHoM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.116.248' (ECDSA) to the list of known hosts.
maildeliverer@10.129.116.248's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Jan  5 06:09:50 2021 from 10.10.14.5
maildeliverer@Delivery:~$ 
```
And indeed, into the system. We can get flags now.
```
maildeliverer@Delivery:~$ pwd
/home/maildeliverer
maildeliverer@Delivery:~$ ls
user.txt
maildeliverer@Delivery:~$ cat user.txt
dd0d904a2962b49b64e5360dc90dd766
```
Let's see if we got root access.
```
maildeliverer@Delivery:~$ id
uid=1000(maildeliverer) gid=1000(maildeliverer) groups=1000(maildeliverer)

maildeliverer@Delivery:~$ sudo -i
[sudo] password for maildeliverer: 
maildeliverer is not in the sudoers file.  This incident will be reported.

maildeliverer@Delivery:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for maildeliverer: 
Sorry, user maildeliverer may not run sudo on Delivery.
```
Unfortunately not.

## 7. Privilege Escalation Enumeration
Let's do some enumeration.
```
maildeliverer@Delivery:~$ uname -a
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64 GNU/Linux
```
And the SUID configuration which we've seen in other previous boxes.
```
maildeliverer@Delivery:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/chfn
/usr/bin/mount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/umount
/usr/bin/fusermount
```
Nothing out of the ordinary.

What about services?
```
maildeliverer@Delivery:~$ systemctl --type=service --state=running
UNIT                      LOAD   ACTIVE SUB     DESCRIPTION                                                 
avahi-daemon.service      loaded active running Avahi mDNS/DNS-SD Stack                                     
cron.service              loaded active running Regular background program processing daemon                
cups-browsed.service      loaded active running Make remote CUPS printers available locally                 
cups.service              loaded active running CUPS Scheduler                                              
dbus.service              loaded active running D-Bus System Message Bus                                    
getty@tty1.service        loaded active running Getty on tty1                                               
mariadb.service           loaded active running MariaDB 10.3.27 database server                             
mattermost.service        loaded active running Mattermost                                                  
nginx.service             loaded active running A high performance web server and a reverse proxy server    
open-vm-tools.service     loaded active running Service for virtual machines hosted on VMware               
php7.3-fpm.service        loaded active running The PHP 7.3 FastCGI Process Manager                         
rsyslog.service           loaded active running System Logging Service                                      
ssh.service               loaded active running OpenBSD Secure Shell server                                 
systemd-journald.service  loaded active running Journal Service                                             
systemd-logind.service    loaded active running Login Service                                               
systemd-timesyncd.service loaded active running Network Time Synchronization                                
systemd-udevd.service     loaded active running udev Kernel Device Manager                                  
user@1000.service         loaded active running User Manager for UID 1000                                   
vgauth.service            loaded active running Authentication service for virtual machines hosted on VMware
```
The `mattermost.service` is interesting, but it is expected as we have seen the Mattermost running. Another interesting one is the `MariaDB 10.3.27 database server`.

What about scheduled tasks? Maybe we can take advantage of something here potentially.
```
maildeliverer@Delivery:~$ crontab -l
no crontab for maildeliverer
```
Nevermind.
