# References
1. [Delivery Writeup (drt.sh)](https://drt.sh/posts/htb-delivery/)

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
```
Delivery

The best place to get all your email related support
For an account check out our helpdesk

    Contact Us

© Untitled. Design: HTML5 UP.
```
Clicking on `helpdesk` redirects to `http://helpdesk.delivery.htb/`, which shows `Server Not Found` error.

Moving on, we click on `Contact Us` button.
```
Contact Us

For unregistered users, please use our HelpDesk to get in touch with our team. 
Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server.
```
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
Ah, turns out Port 8065 is running MatterMost, and we are on the login page. I've used MatterMost in my training before, it's just like another internal Discord server. We also do a quick Searchsploit.
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
Cool! We got a email now, `4009396@delivery.htb` and our ticket id is `4009396`.

What can we do now? Maybe we can check the status of our ticket we just created.
```
Check Ticket Status

Please provide your email address and a ticket number. This will sign you in to view your ticket.
Email Address: 4009396@delivery.htb
Ticket Number: 4009396

Have an account with us? Sign In or register for an account to access all your tickets.

If this is your first time contacting us or you've lost the ticket number, please open a new ticket

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
Entering the Email Address we just got as well as a Ticket Number, we got an error `Access denied`. Hmm.

## 4. Port 8065 MatterMost Enumeration
Let's move on first. From the Contact Us botton earlier, we see the interesting message.
```
Contact Us

For unregistered users, please use our HelpDesk to get in touch with our team. 
Once you have an @delivery.htb email address, you'll be able to have access to our MatterMost server.
```
With the `@delivery.htb` email address, we would be able to access the MatterMost server, theoretically.

We cannot sign in, because we do not have a MatterMost account.
```
Mattermost
All team communication in one place, searchable and accessible anywhere

Email or Username: 4009396@delivery.htb
Password:

Don't have an account? Create one now.
I forgot my password.

Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
We don't have a password.

Let's create an account then.
```
Mattermost
All team communication in one place, searchable and accessible anywhere

Let's create your account
Already have an account? Click here to sign in.

What's your email address?: 4009396@delivery.htb
Valid email required for sign-up
Choose your username: delivery
You can use lowercase letters, numbers, periods, dashes, and underscores.
Choose your password: Delivery69!

By proceeding to create your account and use Mattermost, you agree to our Terms of Service and Privacy Policy. If you do not agree, you cannot use Mattermost.

Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
And finally a verification email.
```
Back
Mattermost: You are almost done

Please verify your email address. Check your inbox for an email.
Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
How are we going to access the email `4009396@delivery.htb` to verify?

## 5. Discovering MatterMost
Here is where I got stuck again and had to get some clues. Quoting my reference from drt.sh (link above), "This is very common of ticketing systems. Allowing the customer to reply directly to an email, and it will show up in the Customer Service Portal.". There, we need to go to the Customer Service Portal, which is we can find in the `Check Ticket Status` page.

We go back to checking the status of our ticket we created. This time, we use our original `@pizza.com` email address, not the `@delivery.htb` one that was provided. That was why our first attempt did not work.
```
Check Ticket Status

Please provide your email address and a ticket number. This will sign you in to view your ticket.
Email Address: alibaba@pizza.com
Ticket Number: 4009396

Have an account with us? Sign In or register for an account to access all your tickets.

If this is your first time contacting us or you've lost the ticket number, please open a new ticket

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
Let's click `View Ticket`, and see what we get.
```
Looking for your other tickets?
Sign In or register for an account for the best experience on our help desk.

My pizza is not boneless #4009396
Print Edit
Basic Ticket Information
Ticket Status: 	Open
Department: 	Support
Create Date: 	3/21/21 2:56 AM
	
User Information
Name: 	Ali Baba
Email: 	alibaba@pizza.com
Phone: 	98987676 x65

Avatar
Ali Baba posted 3/21/21 2:56 AM
---- Registration Successful ---- Please activate your email by going to: 
http://delivery.htb:8065/do_verify_email?token=pgct5wqwt7ki7ffsh4fdo8pr9dqtfzmsriwkkqyym93icdpan5pxnqx5odm6ggca&email=4009396%40delivery.htb )
--------------------- You can sign in from: --------------------- 
Mattermost lets you share messages and files from your PC or phone, with instant search and archiving. 
For the best experience, download the apps for PC, Mac, iOS and Android from: https://mattermost.com/download/#mattermostApps ( https://mattermost.com/download/#mattermostApps

linpeas.sh312.5 kb
Created by AvatarAli Baba 3/21/21 2:56 AM
Post a Reply

To best assist you, we request that you be specific and detailed * 

Drop files here or choose them

Copyright © 2021 delivery - All rights reserved.
Helpdesk software - powered by osTicket
```
Fantastic! Now all we do is go to the verification link `http://delivery.htb:8065/do_verify_email?token=pgct5wqwt7ki7ffsh4fdo8pr9dqtfzmsriwkkqyym93icdpan5pxnqx5odm6ggca&email=4009396%40delivery.htb`.

Let's create an account.
```
Mattermost
All team communication in one place, searchable and accessible anywhere

Email Verified
Email or Username: 4009396@delivery.htb
Password: Delivery69!

Don't have an account? Create one now.
I forgot my password.

Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
Okay, great. Few more buttons to click.
```
Preview Mode: Email notifications have not been configured.
Back

Mattermost
All team communication in one place, searchable and accessible anywhere

Teams you can join:
Internal
Create a team

Mattermost
© 2015-2021 Mattermost, Inc.AboutPrivacyTermsHelp
```
Let's join Internal team.

We can read the chat.
```
Beginning of Internal

Welcome to Internal!
Post messages here that you want everyone to see. Everyone automatically becomes a permanent member of this channel when they join the team.

December 26, 2020
System
10:25 PM
@root joined the team.

System
10:28 PM
@root updated the channel display name from: Town Square to: Internal

root
10:29 PM
@developers Please update theme to the OSTicket before we go live.  Credentials to the server are maildeliverer:Youve_G0t_Mail! 
Also please create a program to help us stop re-using the same passwords everywhere.... Especially those that are a variant of "PleaseSubscribe!"

root
11:58 PM
PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases.

Today
System
3:23 PM
You joined the team.
```
Interesting.. user `root` mentioned credentials, `Credentials to the server are maildeliverer:Youve_G0t_Mail!`. So username `maildeliverer` and password `Youve_G0t_Mail!`?

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

## 7. Privilege Escalation
